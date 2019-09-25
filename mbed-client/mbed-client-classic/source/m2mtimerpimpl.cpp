/*
 * Copyright (c) 2015-2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed-client-classic/m2mtimerpimpl.h"
#include "mbed-client/m2mtimerobserver.h"

#include "eventOS_event_timer.h"
#include "eventOS_scheduler.h"

#include <assert.h>
#include <string.h>


#define MBED_CLIENT_TIMER_TASKLET_INIT_EVENT 0 // Tasklet init occurs always when generating a tasklet
#define MBED_CLIENT_TIMER_EVENT 10

int8_t M2MTimerPimpl::_tasklet_id = -1;

extern "C" void tasklet_func(arm_event_s *event)
{
    // skip the init event as there will be a timer event after
    if (event->event_type == MBED_CLIENT_TIMER_EVENT) {

        M2MTimerPimpl* timer = (M2MTimerPimpl*)event->data_ptr;
        assert(timer);
        timer->handle_timer_event(*event);
    }
}

void M2MTimerPimpl::handle_timer_event(const arm_event_s &event)
{
    // Clear the reference to timer event which is now received and handled.
    // This avoids the useless work from canceling a event if the timer is restarted
    // and also lets the assertions verify the object state correctly.
    _timer_event = NULL;

    if (get_still_left_time() > 0) {
        start_still_left_timer();
    } else {
        timer_expired();
    }
}

M2MTimerPimpl::M2MTimerPimpl(M2MTimerObserver& observer)
: _observer(observer),
  _interval(0),
  _intermediate_interval(0),
  _total_interval(0),
  _still_left(0),
  _timer_event(NULL),
  _type(M2MTimerObserver::Notdefined),
  _status(0),
  _dtls_type(false),
  _single_shot(true)
{
    eventOS_scheduler_mutex_wait();

    if (_tasklet_id < 0) {
        _tasklet_id = eventOS_event_handler_create(tasklet_func, MBED_CLIENT_TIMER_TASKLET_INIT_EVENT);
        assert(_tasklet_id >= 0);
    }

    eventOS_scheduler_mutex_release();
}

M2MTimerPimpl::~M2MTimerPimpl()
{
    // cancel the timer request, if any is pending
    cancel();

    // there is no turning back, event os does not have eventOS_event_handler_delete() or similar,
    // so the tasklet is lost forever.
}

void M2MTimerPimpl::start_timer(uint64_t interval,
                                M2MTimerObserver::Type type,
                                bool single_shot)
{
    _dtls_type = false;
    _intermediate_interval = 0;
    _total_interval = 0;
    _status = 0;
    _single_shot = single_shot;
    _interval = interval;
    _type = type;
    _still_left = 0;
    start();
}

void M2MTimerPimpl::start_dtls_timer(uint64_t intermediate_interval, uint64_t total_interval, M2MTimerObserver::Type type)
{
    _dtls_type = true;
    _intermediate_interval = intermediate_interval;
    _total_interval = total_interval;
    _interval = _intermediate_interval;
    _status = 0;
    _single_shot = false;
    _type = type;
    start();
}

void M2MTimerPimpl::start()
{
    // Cancel ongoing events before creating a new one.
    // Otherwise it can happen that there are multiple events running at the same time.
    cancel();

    int32_t wait_time;

    if (_interval > INT32_MAX) {
        _still_left = _interval - INT32_MAX;
        wait_time = INT32_MAX;
    } else {
        wait_time = _interval;
    }

    request_event_in(wait_time);
}

void M2MTimerPimpl::request_event_in(int32_t delay_ms)
{
    // init struct to zero to avoid hassle when new fields are added to it
    arm_event_t event = { 0 };

    event.receiver = _tasklet_id;
    event.sender = _tasklet_id;
    event.event_type = MBED_CLIENT_TIMER_EVENT;
    event.data_ptr = this;
    event.priority = ARM_LIB_MED_PRIORITY_EVENT;

    // check first, that there is no timer event still pending
    assert(_timer_event == NULL);

    const uint32_t delay_ticks = eventOS_event_timer_ms_to_ticks(delay_ms);

    _timer_event = eventOS_event_timer_request_in(&event, delay_ticks);

    // The timer request may fail only if the system is out of pre-allocated
    // timers and it can not allocate more.
    // If application requires large number of timers, the
    // MBED_CLIENT_EVENT_LOOP_SIZE needs to be at least 1 KiB.
    assert(_timer_event != NULL);
}

void M2MTimerPimpl::cancel()
{
    // NULL event is ok to cancel
    eventOS_cancel(_timer_event);

    _timer_event = NULL;
}

void M2MTimerPimpl::stop_timer()
{
    _interval = 0;
    _single_shot = true;
    _still_left = 0;
    cancel();
}

void M2MTimerPimpl::timer_expired()
{
    _status++;

    // The code is  expecting that the expiration has happened 0, 1 or more times,
    // and we also need to check for overflow as the _status is stored in 2 bits slot.
    if (_status > 2) {
        _status = 2;
    }

    _observer.timer_expired(_type);

    if ((!_dtls_type) && (!_single_shot)) {
        // start next round of periodic timer
        start();
    } else if ((_dtls_type) && (!is_total_interval_passed())) {
        // if only the intermediate time has passed, we need still wait up to total time
        _interval = _total_interval - _intermediate_interval;
        start();
    }
}

bool M2MTimerPimpl::is_intermediate_interval_passed() const
{
    if (_status > 0) {
        return true;
    }
    return false;
}

bool M2MTimerPimpl::is_total_interval_passed() const
{
    if (_status > 1) {
        return true;
    }
    return false;
}

uint64_t M2MTimerPimpl::get_still_left_time() const
{
   return _still_left;
}

void M2MTimerPimpl::start_still_left_timer()
{
    if (_still_left > 0) {

        int32_t wait_time;

        if (_still_left > INT32_MAX) {
            _still_left = _still_left - INT32_MAX;
            wait_time = INT32_MAX;
        } else {
            wait_time = _still_left;
            _still_left = 0;
        }

        request_event_in(wait_time);

    } else {
        _observer.timer_expired(_type);
        if (!_single_shot) {
            start_timer(_interval, _type, _single_shot);
        }
    }
}
