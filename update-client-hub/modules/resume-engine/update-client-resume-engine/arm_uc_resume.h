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

#ifndef ARM_RESUME_H
#define ARM_RESUME_H

#ifdef __cplusplus
extern "C" {
#endif

#include "update-client-common/arm_uc_common.h"
#include "pal.h"
#include <inttypes.h>

// RESUME MANAGEMENT.
// ------------------
/*
 * From the resume-engine perspective:
 *
 * This is an engine for allowing clients to hand off the responsibility of
 *   managing the timing portion of time-bounded and potentially resumable
 *   operations. A resumable operation is one which is able to fail temporarily,
 *   but retains enough state to continue later, typically after taking recovery
 *   actions to return to a state enabling continuation. Resumable operations are
 *   a mechanism to implement reliable operations in an unreliable environment.
 *
 * The resume engine supplies three callbacks - attempt, interval and terminate -
 *   which allows the client module to handle events appropriately.
 *   - Attempt callbacks are called repeatedly after some specified delay from
 *   the beginning of an attempt cycle, typically with exponentially increasing delays.
 *   An attempt cycle is the period from the start of an attempt to its end.
 *   - Interval callbacks are called at the *beginning* of every attempt cycle,
 *   (including the zeroth one, which occurs at the very start of an operation)
 *   up to some number of events specified by the client (possibly zero).
 *   An interval cycle is the period from the start of an interval to the next one.
 *   - The terminate callback is called after some specified delay from start,
 *   and calling it indicates that the resume is no longer active.
 *   An activity cycle is the period from the start of the resume monitor until
 *   it ends, either with an on-terminate event, or by the client-module
 *   ending it explicitly.
 *
 * Resynching is the process of clearing out the existing state of a resume, and
 *   restarting the whole process of intervals, attempts etc.
 *
 * From the client-module perspective:
 *
 * Resuming is handled by starting off what is effectively a parallel monitor
 *   whenever a new activity request is begun. The monitor is a timer which invokes
 *   client-supplied callbacks whenever the appropriate timer conditions are
 *   reached. The role of the resume engine is to supply the logic for a timer
 *   and callback structure that the client-module fills with suitable values to
 *   fulfil the needs it has.
 *
 * On expiry of the timer, the resume engine will invoke a callback so that the client
 *   module can take whatever action it deems necessary. The appropriate callback is
 *   selected based on the event type to which the timer was set to fire.
 *
 * If an operation completes, the resume-instance is transparently suspended by
 *   stopping the timer at the request of the client-module.
 *
 * There are three possible resume-event types, and one resume-error-event type.
 *
 * The error event is only invoked if the resume engine is unable to install a callback
 *   handler on behalf of the client, and signifies that the client can no longer
 *   assume its behaviour is being monitored by the resume engine.
 *
 * The first event type is the on-terminate event. This occurs when all events
 *   that have taken place up to now have not resulted in the resume cycle being
 *   completed with a call to arm_uc_resume_end_monitoring(). At this point, the
 *   user-specified callback on_resume_terminate_p is invoked, so that the client module
 *   can take whatever action it feels is suitable. The on-terminate event is intended
 *   to reflect the need to eventually call a halt to resume engine actions as by this
 *   point it is assumed that the activity can never be successfully completed by any
 *   actions the resume engine is capable of inducing the client to undertake.
 *
 * The second event type is the on-attempt event. This is an exponentially scaled
 *   timeout that is intended to reflect a balance between the need for repeated
 *   attempts to recover by the client module, and the need not to blindly continue
 *   repeating the same old actions over and over again, at the same pace. The on-attempt
 *   timeout is exponentially scaled to allow faster initial attempts, and then to
 *   slow down and be less aggressive with resources in its continued attempts. Once the
 *   summed attempts have reached the max-activity-timeout time, the resume cycle will
 *   be terminated with an on-terminate event.
 *
 * The last event type is an on-interval event. This is at a fixed (non-random) delay,
 *   and will occur either as many times as specified in the initialization structure,
 *   or indefinitely (until it threatens to overrun the current attempt timeout time).
 *   This is intended to provide support for repetitive algorithmic actions that are
 *   not well served by the exponential attempt timer, for example, simple retries
 *   with delays at the start of every attempt.
 *
 * If an activity completes, the thread is transparently suspended. The client-module
 *   must inform the resume-engine that this is so with a call to arm_uc_resume_end_monitoring().
 *
 *     *           |                         |                                                     |   *
 *     | | | |     | | | |                   |                                                     |   |
 *     -------------------------------------------------------------------------------------------------
 *     S I I I     A I I I                   A I I I                                               A I F
 *       1 2 3     2 1 2 3                   3 1 2 3                                               4 1
 *
 *     ^                                                                                               ^
 *     start                                                                                           finish
 *
 *
 *     [----------][------------------------][----------------------------------------------------][---]
 *       initial     initial * exponent        (initial * exponent) * exponent                      remainder
 *
 *      - - -
 *      interval gaps * number of intervals
 *
 *
 */
// vectored activity-condition handlers to allow individual callbacks and unit-test mocking.
typedef void (*on_resume_cb_t)(void *a_context_p);

// storage cache for the current activity-probe state.
typedef struct {
    // configuration.
    uint32_t exponentiation_factor; // factor by which previous attempt period is multiplied to get next.
    uint32_t attempt_initial_delay; // smallest allowed time period between successive attempts.
    uint32_t attempt_max_delay;     // largest allowed time period between successive attempts.
    uint32_t activity_max_time;     // largest *total* allowed time period for full cycle of activity.
    uint32_t interval_delay;        // time period between regular interval events until next.
    uint32_t interval_count;        // number of interval events to allow per resume attempt.

    // callbacks.
    on_resume_cb_t on_resume_interval_p;    // callback on regular interval.
    on_resume_cb_t on_resume_attempt_p;     // callback on resume attempt.
    on_resume_cb_t on_resume_terminate_p;   // callback on terminate (exceeded time limit).
    on_resume_cb_t on_resume_error_p;       // callback on resume engine error.

    // per-instance context.
    void *context_p;                // the client context instance.

    // behaviour support.
    palTimerID_t timer_id;          // resume-monitor timer.
    bool timer_is_running;          // keep track of timer run-state.

    bool currently_resuming;        // activity in progress, resume-probe is active.
    uint32_t num_attempts;          // number of resume attempts without a resynch.
    uint32_t num_intervals;         // number of interval events so far in this attempt.

    uint32_t expected_delay;        // period of the current attempt cycle.
    uint32_t jitter_delay;          // current expected-delay, allowing for randomization.
    uint32_t saved_jitter_delay;    // saved jitter delay for restoring after a resynch.
    uint32_t actual_delay;          // current timer period, allowing for intervals.
    uint32_t sum_interval_delays;   // summed interval delays from start of attempt.
    uint32_t sum_attempt_period;    // summed period of current attempt cycle.
    uint32_t sum_total_period;      // summed total period of full operation since last resynch.
} arm_uc_resume_t;

// Developer-facing #defines allow easier testing of parameterised resume.
// If not available, it becomes extremely difficult to detect exactly when the resume
//   functionality is taking place, or to set values outside of the assumed 'reasonable'
//   range (which can't predict all use cases), which hampers assessment of the settings.

// Print very high priority messages about resume activity for debugging.
// Also, disable checks on resume initialization values.
// Normally compiler errors out if checks enabled and out of permissible range.
#define ARM_UC_RESUME_DEFAULT_ATTEMPT_TEST_MESSAGES_ENABLE  0

// !do not modify or delete these definitions!
// default configuration values for HTTP resume functionality.
// to modify from default values, declare as below but without _DEFAULT
//   eg. ARM_UC_HTTP_RESUME_EXPONENTIATION_FACTOR   3

#define ARM_UC_RESUME_DEFAULT_EXPONENTIATION_FACTOR         2
#define ARM_UC_RESUME_DEFAULT_INITIAL_DELAY_SECS            30
#define ARM_UC_RESUME_DEFAULT_MAXIMUM_DELAY_SECS            (60*60)
#define ARM_UC_RESUME_DEFAULT_MAXIMUM_DOWNLOAD_TIME_SECS    (7*24*60*60)

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
 * @param a_context_p The client instance address.
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
    void *a_context_p);

/**
 * @brief Check a client resume-struct with values to be used for resuming.
 * @param a_resume_p A pointer to the struct holding the values to be checked.
 */
arm_uc_error_t arm_uc_resume_check_settings(arm_uc_resume_t *a_resume_p);

/**
 * @brief Start off a new resume monitor, including initialisation if needed.
 * @details Initialise a supplied resume-struct with suitable values as passed in,
 *            then initiate the process of monitoring for resume purposes.
 * @param a_resume_p Pointer to the active resume structure.
 * @param a_resume_init_p Pointer to the initial values for active resume structure.
 */
arm_uc_error_t arm_uc_resume_start_monitoring(arm_uc_resume_t *a_resume_p);

/**
 * @brief Notify resume probe that recent valid activity has taken place.
 * @details Reset the resume engine such that timing begins again from now.
 * @param a_resume_p Pointer to the active resume structure.
 */
arm_uc_error_t arm_uc_resume_resynch_monitoring(arm_uc_resume_t *a_resume_p);

/**
 * @brief Notify resume probe that full firmware download has completed.
 * @details Halt the resume engine running on this resume-struct.
 * @param a_resume_p Pointer to the active resume structure.
 */
arm_uc_error_t arm_uc_resume_end_monitoring(arm_uc_resume_t *a_resume_p);

#ifdef __cplusplus
}
#endif

#endif
