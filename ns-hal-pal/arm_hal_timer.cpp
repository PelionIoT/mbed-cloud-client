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

// Include before mbed.h to properly get UINT*_C()
#include "ns_types.h"

#include "pal.h"
#include "pal_rtos.h"

#include "platform/arm_hal_timer.h"
#include "platform/arm_hal_interrupt.h"

#include <assert.h>

// Low precision platform tick timer variables
static void (*tick_timer_callback)(void);
static palTimerID_t tick_timer_id;
#define TICK_TIMER_ID   1

void timer_callback(void const *funcArgument)
{
    (void)funcArgument;
    if (tick_timer_callback != NULL) {
        tick_timer_callback();
    }
}

#ifdef MBED_CONF_NANOSTACK_EVENTLOOP_EXCLUDE_HIGHRES_TIMER
extern "C" int8_t ns_timer_sleep(void);
#endif

// static method for creating the timer, called implicitly by platform_tick_timer_register if
// timer was not enabled already
static void tick_timer_create(void)
{
    palStatus_t status;
    status = pal_init();
    assert(PAL_SUCCESS == status);
    status = pal_osTimerCreate(timer_callback, NULL, palOsTimerPeriodic, &tick_timer_id);
    assert(PAL_SUCCESS == status);
    
}

// Low precision platform tick timer
int8_t platform_tick_timer_register(void (*tick_timer_cb_handler)(void))
{
    if (tick_timer_id == 0) {
        tick_timer_create();
    }
    tick_timer_callback = tick_timer_cb_handler;
    return TICK_TIMER_ID;
}

int8_t platform_tick_timer_start(uint32_t period_ms)
{
    int8_t retval = -1;
    if ((tick_timer_id != 0) && (PAL_SUCCESS == pal_osTimerStart(tick_timer_id, period_ms))) {
        retval = 0;
    }
    return retval;
}

int8_t platform_tick_timer_stop(void)
{
    int8_t retval = -1;
    if ((tick_timer_id != 0) && (PAL_SUCCESS == pal_osTimerStop(tick_timer_id))) {
        retval = 0;
    }

    // release PAL side resources
    pal_osTimerDelete(&tick_timer_id);
    pal_destroy();

    return retval;
}


