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

#include "ns_event_loop.h"

#include "pal.h"
#include "ns_trace.h"

#include "eventOS_scheduler.h"

#include <assert.h>


#define TRACE_GROUP "evlp"

static void event_loop_thread(const void *arg);

static palThreadID_t event_thread_id = 0;
static palMutexID_t event_mutex_id = 0;
static palSemaphoreID_t event_start_sema_id = 0;
static palSemaphoreID_t event_signal_sema_id = 0;
static palSemaphoreID_t event_stop_sema_id = 0;
static volatile bool event_stop_loop;

void eventOS_scheduler_mutex_wait(void)
{
    palStatus_t status;
    status = pal_osMutexWait(event_mutex_id, UINT32_MAX);
    assert(PAL_SUCCESS == status);
}

void eventOS_scheduler_mutex_release(void)
{
    palStatus_t status;
    status = pal_osMutexRelease(event_mutex_id);
    assert(PAL_SUCCESS == status);
}

void eventOS_scheduler_signal(void)
{
    palStatus_t status;
    status = pal_osSemaphoreRelease(event_signal_sema_id);
    assert(PAL_SUCCESS == status);
}

void eventOS_scheduler_idle(void)
{
    int32_t counters = 0;
    palStatus_t status;

    eventOS_scheduler_mutex_release();

    status = pal_osSemaphoreWait(event_signal_sema_id, UINT32_MAX, &counters);
    assert(PAL_SUCCESS == status);

    eventOS_scheduler_mutex_wait();
}

static void event_loop_thread(const void *arg)
{
    int32_t counters = 0;
    palStatus_t status;

    tr_debug("event_loop_thread create");

    event_stop_loop = false;

    status = pal_osSemaphoreWait(event_start_sema_id, UINT32_MAX, &counters);
    assert(PAL_SUCCESS == status);

    // TODO: Delete start semaphore?
    eventOS_scheduler_mutex_wait();
    tr_debug("event_loop_thread loop start");

    // A stoppable version of eventOS_scheduler_run(void)
    while (event_stop_loop == false) {
        if (!eventOS_scheduler_dispatch_event()) {
            eventOS_scheduler_idle();
        }
    }
    tr_debug("event_loop_thread loop end");

    // cleanup the scheduler timer resources which are not needed anymore
    eventOS_scheduler_timer_stop();

    // signal the ns_event_loop_thread_stop() that it can continue 
    status = pal_osSemaphoreRelease(event_stop_sema_id);
    assert(PAL_SUCCESS == status);
}

void ns_event_loop_thread_create(void)
{
    int32_t counters = 0;
    palStatus_t status;

    status = pal_osSemaphoreCreate(1, &event_start_sema_id);
    assert(PAL_SUCCESS == status);

    status = pal_osSemaphoreWait(event_start_sema_id, UINT32_MAX, &counters);
    assert(PAL_SUCCESS == status);

    status = pal_osSemaphoreCreate(0, &event_stop_sema_id);
    assert(PAL_SUCCESS == status);

    status = pal_osSemaphoreCreate(1, &event_signal_sema_id);
    assert(PAL_SUCCESS == status);

    status = pal_osMutexCreate(&event_mutex_id);
    assert(PAL_SUCCESS == status);

    status = pal_osThreadCreateWithAlloc(event_loop_thread, NULL, PAL_osPriorityNormal, MBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE, NULL, &event_thread_id);
    assert(PAL_SUCCESS == status);
}

void ns_event_loop_thread_start(void)
{
    palStatus_t status;
    status = pal_osSemaphoreRelease(event_start_sema_id);
    assert(PAL_SUCCESS == status);
}

void ns_event_loop_thread_stop(void)
{
    palStatus_t status;

    // request loop to stop
    event_stop_loop = true;

    // Ping the even loop at least once more so it will notice the flag and
    // hopefully end the loop soon.
    eventOS_scheduler_signal();

    // wait until the event loop has been stopped and the thread is shutting down.
    // Note: the PAL API does not have any better means to join with a thread termination. 
    status = pal_osSemaphoreWait(event_stop_sema_id, UINT32_MAX, NULL);
    assert(PAL_SUCCESS == status);

    pal_osSemaphoreDelete(&event_start_sema_id);
    pal_osSemaphoreDelete(&event_stop_sema_id);
}
