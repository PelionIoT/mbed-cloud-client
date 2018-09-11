// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_FEATURE_RESUME_ENGINE) && (ARM_UC_FEATURE_RESUME_ENGINE == 1)

#include "update-client-common/arm_uc_common.h"
#include "update-client-resume-engine/arm_uc_resume.h"

// RESUMPTION MANAGEMENT.
// ----------------------

// Developer-facing defines allow easier testing of parameterised resume.
// If not available, it becomes extremely difficult to detect exactly when the resume
//   functionality is taking place, or to set values outside of the assumed 'reasonable'
//   range (which can't predict all use cases), which hampers assessment of the settings.
// This can be set in the mbed_app.json file, or here in the source.
// This fills in the values from mbed_app.json if specified non-default.
// Values are checked for sanity unless overridden for easier testing during development.

#if defined(MBED_CONF_UPDATE_CLIENT_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE)\
    && (MBED_CONF_UPDATE_CLIENT_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE)
// Text messages will be printed to output to give live feedback for test.
#define ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE 1
#endif

// Exponentiation factor tries to balance speed with power considerations.
// Resume is intended to be reasonably aggressive to start but backs off quickly too.
#define RESUME_EXPONENTIATION_FACTOR_LIMIT  1024
#if defined(MBED_CONF_UPDATE_CLIENT_RESUME_EXPONENTIATION_FACTOR)
#define RESUME_EXPONENTIATION_FACTOR        MBED_CONF_UPDATE_CLIENT_RESUME_EXPONENTIATION_FACTOR
#else
#define RESUME_EXPONENTIATION_FACTOR        ARM_UC_RESUME_DEFAULT_EXPONENTIATION_FACTOR
#endif

// Delay parameters have minimum and maximum values.
// In general the minimum is a hard limit, because going too low will interfere with the algorithm,
//   given that there are various phases which need to coordinate.
// The maximum delays have no hard limits, but issue a warning if they seem unreasonably long,
//   which is intended to catch errors like extra zeroes in the #defined values.

// Initial delay between resume-servicing attempts.
#if defined(MBED_CONF_UPDATE_CLIENT_RESUME_INITIAL_DELAY_SECS)
#define RESUME_INITIAL_DELAY_MSECS          ((MBED_CONF_UPDATE_CLIENT_RESUME_INITIAL_DELAY_SECS)*1000)
#else
#define RESUME_INITIAL_DELAY_MSECS          ((ARM_UC_RESUME_DEFAULT_INITIAL_DELAY_SECS)*1000)
#endif

// Greatest delay between resume-servicing attempts.
#if defined(MBED_CONF_UPDATE_CLIENT_RESUME_MAXIMUM_DELAY_SECS)
#define RESUME_MAXIMUM_DELAY_MSECS          ((MBED_CONF_UPDATE_CLIENT_RESUME_MAXIMUM_DELAY_SECS)*1000)
#else
#define RESUME_MAXIMUM_DELAY_MSECS          ((ARM_UC_RESUME_DEFAULT_MAXIMUM_DELAY_SECS)*1000)
#endif

// Stop resume-servicing attempts after this period has elapsed.
// Max activity time is limited to 30 because of 32-bit limitation of 49 days in msecs.
#define RESUME_MAXIMUM_ACTIVITY_TIME_MSECS_LIMIT    (30*24*60*60*1000UL)

#if defined(MBED_CONF_UPDATE_CLIENT_RESUME_MAXIMUM_ACTIVITY_TIME_SECS)
#define RESUME_MAXIMUM_ACTIVITY_TIME_MSECS  ((MBED_CONF_UPDATE_CLIENT_RESUME_MAXIMUM_ACTIVITY_TIME_SECS)*1000)
#else
#define RESUME_MAXIMUM_ACTIVITY_TIME_MSECS  ((ARM_UC_RESUME_DEFAULT_MAXIMUM_DOWNLOAD_TIME_SECS)*1000)
#endif

// Interval events, disabled by default.
#define RESUME_INITIAL_INTERVAL_DELAY_MSECS   0
#define RESUME_INITIAL_INTERVAL_COUNT         0

// Const struct to refill the settings with default startup settings if needed.
arm_uc_resume_t const resume_default_init = {
    .exponentiation_factor = RESUME_EXPONENTIATION_FACTOR,
    .attempt_initial_delay = RESUME_INITIAL_DELAY_MSECS,
    .attempt_max_delay = RESUME_MAXIMUM_DELAY_MSECS,
    .activity_max_time = RESUME_MAXIMUM_ACTIVITY_TIME_MSECS,
    .interval_delay = RESUME_INITIAL_INTERVAL_DELAY_MSECS,
    .interval_count = RESUME_INITIAL_INTERVAL_COUNT,

    .on_resume_interval_p = NULL,
    .on_resume_attempt_p = NULL,
    .on_resume_terminate_p = NULL,
    .on_resume_error_p = NULL
};

// FORWARD DECLARATIONS.
// ---------------------

static void check_resume_activity(void const *a_data_p);
static void do_check_resume_activity(uint32_t unused);
arm_uc_error_t arm_uc_resume_end_monitoring(arm_uc_resume_t *a_resume_p);

// TIMER MANAGEMENT.
// -----------------

// Synchronize actual timer state and timer-state variable here.
// Timer_is_running should not be modified at any other point in the code.

/**
 * @brief Keep timer_is_running flag in sync with actual timer state.
 * @details Actual access to the timer_is_running field is isolated to one location.
 * @param a_resume_p Pointer to the active resume structure.
 * @param an_is_running_f Flag to indicate new state of timer.
 */
static inline void update_state_resume_timer(arm_uc_resume_t *a_resume_p, bool an_is_running_f)
{
    if (a_resume_p != NULL) {
        a_resume_p->timer_is_running = an_is_running_f;
    }
}

/**
 * @brief Create a new resume timer for use with a resume structure.
 * @param a_resume_p Pointer to the active resume structure.
 */
static palStatus_t create_resume_timer(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    if (a_resume_p == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    update_state_resume_timer(a_resume_p, false);
    palStatus_t status = pal_osTimerCreate(check_resume_activity, a_resume_p, palOsTimerOnce, &a_resume_p->timer_id);
    if (status == PAL_SUCCESS) {
        UC_RESUME_TRACE("success: resume-timer %" PRIx32 " created", (uint32_t)a_resume_p->timer_id);
    } else {
        UC_RESUME_TRACE("error: resume-timer %" PRIx32 " could not create new timer %" PRIx32,
                        (uint32_t)a_resume_p->timer_id, (uint32_t)status);
    }
    return status;
}

/**
 * @brief Stop the timer in a resume structure.
 * @param a_resume_p Pointer to the active resume structure.
 */
static palStatus_t stop_resume_timer(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    if (a_resume_p == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    palStatus_t status = PAL_SUCCESS;
    // this should not be called if the timer is already stopped.
    if (!a_resume_p->timer_is_running) {
        UC_RESUME_TRACE("warning: resume-timer is already stopped.");
    } else {
        status = pal_osTimerStop((palTimerID_t)(a_resume_p->timer_id));
        update_state_resume_timer(a_resume_p, false);
        if (status != PAL_SUCCESS) {
            UC_RESUME_TRACE("error: resume-timer %" PRIx32 " could not stop %" PRIx32,
                            (uint32_t)a_resume_p->timer_id, (uint32_t)status);
        }
    }
    return status;
}

/**
 * @brief Start the timer in a resume structure.
 * @param a_resume_p Pointer to the active resume structure.
 */
static palStatus_t start_resume_timer(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    if (a_resume_p == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    palStatus_t status = PAL_SUCCESS;
    // this should not be called if the timer is already running.
    // but if so, needs to be stopped then restarted with new delay.
    if (a_resume_p->timer_is_running) {
        UC_RESUME_TRACE("warning: resume-timer is already running.");
        stop_resume_timer(a_resume_p);
    }
    // now start the timer with the new delay value.
    status = pal_osTimerStart((palTimerID_t)(a_resume_p->timer_id), a_resume_p->actual_delay);
    update_state_resume_timer(a_resume_p, status == PAL_SUCCESS);
    if (status != PAL_SUCCESS) {
        UC_RESUME_TRACE("error: resume-timer %" PRIx32 " could not start %" PRIx32,
                        (uint32_t)a_resume_p->timer_id, (uint32_t)status);
    }
    return status;
}

// UTILITY FUNCTIONS.
// ------------------

/**
 * @brief Make a call to the requested handler.
 * @param a_resume_p Pointer to the active resume structure.
 */
static void invoke_resume_handler(arm_uc_resume_t *a_resume_p, on_resume_cb_t a_handler_p, char *a_text_p)
{
    if (a_resume_p == NULL) {
        UC_RESUME_TRACE("error: %s resume-pointer is null!", a_text_p);
    } else if (a_handler_p != NULL) {
        UC_RESUME_TRACE("calling on-%s handler", a_text_p);
        a_handler_p(a_resume_p->context_p);
    } else {
        UC_RESUME_TRACE("error: %s handler-vector is null!", a_text_p);
    }
}
/**
 * @brief Reset values per every new resume-attempt.
 * @param a_resume_p Pointer to the active resume structure.
 */
static void reset_on_attempt_values(arm_uc_resume_t *a_resume_p)
{
    if (a_resume_p != NULL) {
        a_resume_p->num_intervals = 0;
        a_resume_p->sum_attempt_period = 0;
        a_resume_p->sum_interval_delays = 0;
    }
}
/**
 * @brief Reset values per every new resume-cycle.
 * @param a_resume_p Pointer to the active resume structure.
 */
static void reset_on_cycle_values(arm_uc_resume_t *a_resume_p)
{
    if (a_resume_p != NULL) {
        a_resume_p->num_attempts = 0;
        a_resume_p->sum_total_period = 0;
    }
}

// DELAY CALCULATIONS.
// -------------------

// Utility functions to simplify caller code.
static void set_below(uint32_t *a_value_p, uint32_t a_high)
{
    if (*a_value_p > a_high) {
        *a_value_p = a_high;
    }
}
static void set_between(uint32_t *a_value_p, uint32_t a_low, uint32_t a_high)
{
    if (*a_value_p > a_high) {
        *a_value_p = a_high;
    } else if (*a_value_p < a_low) {
        *a_value_p = a_low;
    }
}

// @brief Calculate an interval randomised around the given value.
// @details Get a 25% (+-12.5%) randomisation of the base interval value,
//          calculated by multiplying it by a 0-maxuint random factor,
//          and add/subtract it to the base by adding with offset.
//          Picking these values because they are reasonable but quick to calculate.
// @param an_interval The base interval around which to randomise.
// @return Interval +/- some random part of one-eighth of the interval.
#define RANGE_FRACTION_DIV 4
#define BOUND_FRACTION_DIV 8
static uint32_t randomised_interval(uint32_t an_interval)
{
    // Calculate range for max amount of wiggle allowed in both directions total.
    uint32_t range = an_interval / RANGE_FRACTION_DIV;
    // Calculate bound for max allowed wiggle *either* above or below the interval.
    uint32_t bound = an_interval / BOUND_FRACTION_DIV;
    // Actual wiggle for this attempt.
    // Calculated by multiplying max allowed wiggle by a fraction of rand()/RAND_MAX.
    // Use (RAND_MAX+1) if is power-of-two and not zero
#if (((RAND_MAX+1) & RAND_MAX) == 0) && ((RAND_MAX+1) != 0)
    uint32_t wiggle = ((long long) rand() * range) / ((unsigned) RAND_MAX + 1);
#else
    uint32_t wiggle = ((long long)rand() * range) / ((unsigned)RAND_MAX);
#endif
    return an_interval - bound + wiggle;
}

/**
 * @brief Calculate values for next attempt of a resume cycle.
 * @details This calculates the time until this current resume attempt is scheduled to
 *            time out, ignoring the possibility of interval events before then.
 * @param a_resume_p Pointer to the active resume structure.
 * @param an_expected_delay The expected delay prior to jitter and limit adjustment.
 */
static void calc_next_attempt_jittered_delay(arm_uc_resume_t *a_resume_p, uint32_t an_expected_delay)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ", %" PRIu32 ")", __func__, (uint32_t)a_resume_p, (uint32_t)an_expected_delay);
    if (a_resume_p == NULL) {
        UC_RESUME_TRACE(".. %s exiting with NULL resume-pointer", __func__);
        return;
    }
    // Clear admin values keeping track of progress through this attempt.
    reset_on_attempt_values(a_resume_p);

    // Get the correct interval times set up.
    // Ensure they are within range of maximum and minimum allowed.
    a_resume_p->expected_delay = an_expected_delay;
    set_between(&a_resume_p->expected_delay, a_resume_p->attempt_initial_delay, a_resume_p->attempt_max_delay);
    // Set jittered delay, which is randomised, bounded by max and min times.
    a_resume_p->jitter_delay = randomised_interval(a_resume_p->expected_delay);
    set_below(&a_resume_p->jitter_delay, a_resume_p->activity_max_time - a_resume_p->sum_total_period);
    set_between(&a_resume_p->jitter_delay, a_resume_p->attempt_initial_delay, a_resume_p->attempt_max_delay);
    a_resume_p->saved_jitter_delay = a_resume_p->jitter_delay;

    UC_RESUME_TRACE(".. %s: jitter delay %" PRIu32 " msecs", __func__, a_resume_p->jitter_delay);
}

/**
 * @brief Calculate values for first attempt of a new resume cycle.
 * @details This calculates the time until this current resume attempt is scheduled to
 *            time out, ignoring the possibility of interval events before then.
 * @param a_resume_p Pointer to the active resume structure.
 */
static void calc_initial_attempt_jittered_delay(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);

    reset_on_cycle_values(a_resume_p);
    calc_next_attempt_jittered_delay(a_resume_p, a_resume_p->attempt_initial_delay);
}

/**
 * @brief Calculate *actual* values for jittered delay taking intervals into account.
 * @details This is the value to which the timer will be set, and will possibly be different
 *            than the jittered delay, which is the time to the next resume attempt, and
 *            does not take into account the need for any interval events before that.
 *            For this reason, the actual timeout calculation will first track all necessary
 *            interval events, and after these have been completed, or would overrun the
 *            jittered resume-attempt timeout, it returns the jittered timeout.
 * @param a_resume_p Pointer to the active resume structure.
 */
static void calc_next_actual_delay(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    if (a_resume_p == NULL) {
        return;
    }
    // Calculate the period to the next timer event.
    uint32_t interval = a_resume_p->interval_delay;
    if ((interval != 0)
            && (a_resume_p->num_intervals < a_resume_p->interval_count)
            && ((a_resume_p->sum_interval_delays + interval) < a_resume_p->jitter_delay)) {
        a_resume_p->sum_interval_delays += interval;
        a_resume_p->actual_delay = interval;
    } else {
        a_resume_p->actual_delay = a_resume_p->jitter_delay - a_resume_p->sum_interval_delays;
    }
    UC_RESUME_TRACE(".. %s: actual delay %" PRIu32 " msecs", __func__, a_resume_p->actual_delay);
}

// CHECKING OF RESUME EVENTS.
// --------------------------

/**
 * @brief Post callback to avoid running from timer callback context
 * @param a_data_p Pointer to the active resume structure.
 */
static void check_resume_activity(void const *a_data_p)
{
//    UC_RESUME_TRACE( ">> %s (%" PRIx32 ")", __func__, a_data_p);

    arm_uc_resume_t *resume_p = (arm_uc_resume_t *) a_data_p;
    if (resume_p == NULL) {
        UC_RESUME_TRACE("resume-struct pointer is null in check_resume_activity!");
    } else {
        // Keep the timer and timer-state variable synched - it stops on firing (once-off).
        update_state_resume_timer(resume_p, false);
        // Only invoke the checks if the resume engine hasn't been disabled.
        if (resume_p->currently_resuming) {
            // If it doesn't install, run an error-specific callback.
            // Can't do something specific-to-resume, because user needs are different.
            ARM_UC_PostCallback(NULL, do_check_resume_activity, (uint32_t) a_data_p);
        }
    }
}

/**
 * @brief Evaluate resume probe - kill, install a new idle probe, or initiate a new operation.
 * @param a_param Parameter to be passed to callback, is pointer to resume struct.
 */
static void do_check_resume_activity(uint32_t a_param)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, a_param);

    arm_uc_resume_t *a_resume_p = (arm_uc_resume_t *) a_param;
    if (a_resume_p == NULL) {
        UC_RESUME_TRACE("resume-struct pointer is null in do_check_resume_activity!");
    } else {
        // Update summed periods, total and per attempt.
        a_resume_p->sum_total_period += a_resume_p->actual_delay;
        a_resume_p->sum_attempt_period += a_resume_p->actual_delay;

        // Identify the current state of affairs for the resume probe.
        if (!a_resume_p->currently_resuming) {
            // Must have been terminated *after* the timer had posted the callback.
            // Just ignore this and let the thread die naturally.
#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
            UC_QA_TRACE("\nResume inactive.\n");
#endif
        } else if (a_resume_p->sum_total_period >= a_resume_p->activity_max_time) {
            UC_RESUME_TRACE("resume max-activity-time reached - %" PRIu32 " secs",
                            a_resume_p->activity_max_time / 1000);
            // Past the maximum time we should keep trying, so just let it die.
            a_resume_p->currently_resuming = false;
            // Make the callback and let handler take care of it.
            invoke_resume_handler(a_resume_p, a_resume_p->on_resume_terminate_p, "resume-terminate");

#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
            puts("\nMaximum resume activity time reached.\n");
#endif
        } else if (a_resume_p->sum_attempt_period >= a_resume_p->jitter_delay) {
            UC_RESUME_TRACE("resume-attempt period reached - %" PRIu32 " secs",
                            a_resume_p->expected_delay / 1000);
            UC_RESUME_TRACE("resume attempted after total %" PRIu32 " secs",
                            a_resume_p->sum_total_period / 1000);

            // Let the source know this will be a resume attempt (there is some setup involved),
            //   put the state machine in a suitable state, and then initiate the process.
            // Need to reset the various timers and carry on.
            ++a_resume_p->num_attempts;
            calc_next_attempt_jittered_delay(a_resume_p,
                                             a_resume_p->expected_delay * a_resume_p->exponentiation_factor);
            calc_next_actual_delay(a_resume_p);

            invoke_resume_handler(a_resume_p, a_resume_p->on_resume_attempt_p, "resume-attempt");
            start_resume_timer(a_resume_p);

#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
            // Resume is running, is not deferred, internal limit has not been reached.
            //   and the hub is currently in the idle state, so we need to try again.
            // But first we need to enqueue the next resume check.
            // If it isn't deferred or cancelled in the meantime,
            //   it will take action when it fires.
            UC_QA_TRACE("\nResume being attempted now, next in %" PRIi32 ".%" PRIu32 "(~%" PRIi32 ")\n",
                        a_resume_p->jitter_delay / 1000,
                        (a_resume_p->jitter_delay % 1000) / 100,
                        a_resume_p->expected_delay / 1000);
#endif
        } else {
            // This must be an interval event.
            UC_RESUME_TRACE("resume interval period reached - %" PRIu32 " msecs (at %" PRIu32 " of %" PRIu32 ")",
                            a_resume_p->interval_delay, a_resume_p->sum_attempt_period, a_resume_p->jitter_delay);
            ++a_resume_p->num_intervals;
            calc_next_actual_delay(a_resume_p);

            if (a_resume_p->num_intervals <= a_resume_p->interval_count) {
                invoke_resume_handler(a_resume_p, a_resume_p->on_resume_interval_p, "resume-interval");
            }
            start_resume_timer(a_resume_p);
        }
    }
    UC_RESUME_TRACE(".. %s", __func__);
}

// INIT, START, RESYNCH, END.
// --------------------------
#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
static bool has_displayed_resume_settings = false;
#endif

/**
 * @brief Check a client resume-struct with values to be used for resuming.
 * @param a_resume_p A pointer to the struct holding the values to be checked.
 */
arm_uc_error_t arm_uc_resume_check_settings(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (a_resume_p == NULL) {
        ARM_UC_SET_ERROR(result, ERR_NULL_PTR);
        UC_RESUME_ERR_MSG("%s failed: null for resume-struct", __func__);
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        // Check that the new values satisfy the constraints.
        // There are no constraints on intervals, they just won't be called if out of range.
        if ((a_resume_p->exponentiation_factor == 0)
                || (a_resume_p->exponentiation_factor > RESUME_EXPONENTIATION_FACTOR_LIMIT)
                || (a_resume_p->attempt_initial_delay == 0)
                || (a_resume_p->attempt_initial_delay > a_resume_p->attempt_max_delay)
                || (a_resume_p->attempt_max_delay == 0)
                || (a_resume_p->attempt_max_delay > a_resume_p->activity_max_time)
                || (a_resume_p->activity_max_time == 0)
                || (a_resume_p->activity_max_time > RESUME_MAXIMUM_ACTIVITY_TIME_MSECS_LIMIT)) {
            ARM_UC_SET_ERROR(result, ERR_INVALID_PARAMETER);
            UC_RESUME_ERR_MSG("%s failed: invalid resume settings", __func__);
        }
    }
#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
    if (!has_displayed_resume_settings) {
        if (ARM_UC_IS_ERROR(result)) {
            UC_QA_ERR_MSG("Resume settings invalid - checking failed.\r\n");
        }
    }
#endif
    UC_RESUME_TRACE(".. %s %" PRIx32, __func__, (uint32_t)result.code);
    return result;
}

/**
 * @brief Initialize a client resume-struct with values to be used for resuming.
 * @param a_resume_p A pointer to the struct to be initialized with values.
 * @param an_exponentiation_factor The factor by which a previous delay is multiplied to get next.
 * @param an_attempt_initial_delay The smallest allowed gap between successive attempts.
 * @param an_attempt_max_delay The largest allowed gap between successive attempts.
 * @param an_activity_max_time The largest *total* allowed period for full cycle of activity.
 * @param an_interval_delay The gap between regular interval events until next.
 * @param an_interval_count The number of interval events to allow per resume attempt.
 * @param an_on_interval_cb The callback to be invoked on an interval event.
 * @param an_on_attempt_cb The callback to be invoked on an attempt event.
 * @param an_on_termination_cb The callback to be invoked on a termination event.
 * @param an_on_error_cb The callback to be invoked on an error event (runs in ISR context!).
 */
arm_uc_error_t arm_uc_resume_initialize(
    arm_uc_resume_t *a_resume_p,
    uint32_t an_exponentiation_factor,
    uint32_t an_attempt_initial_delay,
    uint32_t an_attempt_max_delay,
    uint32_t an_activity_max_time,
    uint32_t an_interval_delay,
    uint32_t an_interval_count,
    on_resume_cb_t an_on_interval_cb,
    on_resume_cb_t an_on_attempt_cb,
    on_resume_cb_t an_on_termination_cb,
    on_resume_cb_t an_on_error_cb,
    void *a_context_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (a_resume_p == NULL) {
        ARM_UC_SET_ERROR(result, ERR_NULL_PTR);
        UC_RESUME_ERR_MSG("%s failed: null for resume-struct", __func__);
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        a_resume_p->exponentiation_factor = an_exponentiation_factor;
        a_resume_p->attempt_initial_delay = an_attempt_initial_delay;
        a_resume_p->attempt_max_delay = an_attempt_max_delay;
        a_resume_p->activity_max_time = an_activity_max_time;
        a_resume_p->interval_delay = an_interval_delay;
        a_resume_p->interval_count = an_interval_count;
        a_resume_p->on_resume_interval_p = an_on_interval_cb;
        a_resume_p->on_resume_attempt_p = an_on_attempt_cb;
        a_resume_p->on_resume_terminate_p = an_on_termination_cb;
        a_resume_p->on_resume_error_p = an_on_error_cb;
        a_resume_p->context_p = a_context_p;

        result = arm_uc_resume_check_settings(a_resume_p);
    }
#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
    if (!has_displayed_resume_settings) {
        UC_QA_TRACE("Resume settings\r\n"
                    "exponentiation factor: %" PRIu32
                    ", initial delay: %" PRIu32
                    ", maximum delay: %" PRIu32
                    ", maximum activity time: %" PRIu32
                    ", interval delay: %" PRIu32
                    ", interval count: %" PRIu32 "\r\n",
                    an_exponentiation_factor,
                    an_attempt_initial_delay, an_attempt_max_delay, an_activity_max_time,
                    an_interval_delay, an_interval_count);
        if (ARM_UC_IS_ERROR(result)) {
            UC_QA_ERR_MSG("Resume settings invalid - copying failed.\r\n");
        }
        has_displayed_resume_settings = true;
    }
#endif
    UC_RESUME_TRACE(".. %s %" PRIx32, __func__, (uint32_t)result.code);
    return result;
}

/**
 * @brief Start off a new resume monitor, including initialisation.
 * @details Initialise a supplied resume-struct with suitable values as passed in,
 *            then initiate the process of monitoring for resume purposes.
 * @param a_resume_p Pointer to the active resume structure.
 * @param a_resume_init_p Pointer to the initial values for active resume structure.
 */
arm_uc_error_t arm_uc_resume_start_monitoring(
    arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (a_resume_p == NULL) {
        ARM_UC_SET_ERROR(result, ERR_NULL_PTR);
        UC_RESUME_TRACE("%s failed: null for resume-struct", __func__);
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        // A new resume must first abort an ongoing resume-nudge attempt.
        if (a_resume_p->currently_resuming) {
            result = arm_uc_resume_end_monitoring(a_resume_p);
            if (ARM_UC_IS_ERROR(result)) {
                UC_RESUME_TRACE("%s failed: could not end existing resume", __func__);
            }
        }
    }
    // Set up the starting conditions for a full new resume cycle.
    // Note that this assumes a brand new cycle, all the counters & timers are reset.
    if (ARM_UC_IS_NOT_ERROR(result)) {
        result = arm_uc_resume_check_settings(a_resume_p);
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        // If the timer hasn't even been created yet, do it now.
        if (a_resume_p->timer_id == 0) {
            palStatus_t pal_status = create_resume_timer(a_resume_p);
            if (pal_status != PAL_SUCCESS) {
                ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
            }
        }
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        a_resume_p->currently_resuming = true;
        calc_initial_attempt_jittered_delay(a_resume_p);
        calc_next_actual_delay(a_resume_p);

        // Enable a timed callback for the next check, wait for it.
        palStatus_t pal_status = start_resume_timer(a_resume_p);
        if (pal_status != PAL_SUCCESS) {
            ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
            UC_RESUME_TRACE("%s failed: could not start timer, error %"
                            PRIx32 " id %" PRIu32 " delay %" PRIu32,
                            __func__, (uint32_t)pal_status, (uint32_t)a_resume_p->timer_id, a_resume_p->actual_delay);
        }
#if ARM_UC_RESUME_ATTEMPT_TEST_MESSAGES_ENABLE
        UC_QA_TRACE("\nResume starting now, in %" PRIi32 ".%" PRIu32 "(~%" PRIi32 ")\n",
                    a_resume_p->jitter_delay / 1000,
                    (a_resume_p->jitter_delay % 1000) / 100,
                    a_resume_p->expected_delay / 1000);
#endif
    }
    UC_RESUME_TRACE(".. %s %" PRIx32, __func__, (uint32_t)result.code);
    return result;
}

/**
 * @brief Notify resume probe that recent valid activity has taken place.
 * @details Reset the resume engine such that timing begins again from now.
 * @param a_resume_p Pointer to the active resume structure.
 */

arm_uc_error_t arm_uc_resume_resynch_monitoring(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);

    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (a_resume_p == NULL) {
        UC_RESUME_TRACE("resume-resynch failed: null-pointer");
        ARM_UC_SET_ERROR(result, ERR_NULL_PTR);
    } else if (a_resume_p->timer_id == 0) {
        UC_RESUME_TRACE("resume-resynch failed: timer-id == 0");
        ARM_UC_SET_ERROR(result, ERR_INVALID_PARAMETER);
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        palStatus_t pal_status = stop_resume_timer(a_resume_p);
        if (pal_status != PAL_SUCCESS) {
            UC_RESUME_TRACE("resume-resynch failed: could not stop timer, error %" PRIx32, (uint32_t)pal_status);
        }
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        // Clear attempts control values and restore the prior jitter delay.
        // Jittered delay is kept the same as it was before the reset.
        reset_on_attempt_values(a_resume_p);
        reset_on_cycle_values(a_resume_p);
        a_resume_p->jitter_delay = a_resume_p->saved_jitter_delay;
        calc_next_actual_delay(a_resume_p);

        palStatus_t pal_status = start_resume_timer(a_resume_p);
        if (pal_status != PAL_SUCCESS) {
            ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
            UC_RESUME_TRACE("resume-resynch failed: could not start timer, error %"
                            PRIx32 " id %" PRIx32 " delay %" PRIu32,
                            (uint32_t)pal_status, (uint32_t)a_resume_p->timer_id, a_resume_p->actual_delay);
        }
    }
    UC_RESUME_TRACE("next check in %" PRIu32 ".%3" PRIu32 " secs",
                    a_resume_p->actual_delay / 1000, a_resume_p->actual_delay % 1000);
    UC_RESUME_TRACE(".. %s %" PRIx32, __func__, (uint32_t)result.code);
    return result;
}

/**
 * @brief Notify resume probe that full firmware download has completed.
 * @details Halt the resume engine running on this resume-struct.
 * @param a_resume_p Pointer to the active resume structure.
 */
arm_uc_error_t arm_uc_resume_end_monitoring(arm_uc_resume_t *a_resume_p)
{
    UC_RESUME_TRACE(">> %s (%" PRIx32 ")", __func__, (uint32_t)a_resume_p);

    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (a_resume_p == NULL) {
        ARM_UC_SET_ERROR(result, ERR_NULL_PTR);
    }
    if (ARM_UC_IS_NOT_ERROR(result)) {
        a_resume_p->currently_resuming = false;
        if (a_resume_p->timer_id != 0) {
            if (stop_resume_timer(a_resume_p) != PAL_SUCCESS) {
                UC_RESUME_TRACE("resume-end failed: could not stop timer");
            }
        }
    }
    UC_RESUME_TRACE(".. %s %" PRIx32, __func__, (uint32_t)result.code);
    return result;
}

#endif // ARM_UC_FEATURE_RESUME_ENGINE
