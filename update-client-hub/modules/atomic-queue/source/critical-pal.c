// ----------------------------------------------------------------------------
// Copyright 2015-2017 ARM Ltd.
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

#if defined(ATOMIC_QUEUE_USE_PAL) && !defined(TARGET_LIKE_MBED)

#include <stdint.h>
#include <assert.h>
#include <unistd.h>

#include "pal.h"
// Module include
#include "aq_critical.h"

static palMutexID_t mutex = NULLPTR;
static volatile unsigned irq_nesting_depth = 0;

void aq_critical_section_enter() {
    if (mutex == NULLPTR) {
        palStatus_t rc = pal_osMutexCreate(&mutex);
        assert(rc == PAL_SUCCESS);
    }
    if (++irq_nesting_depth > 1) {
        return;
    }
    palStatus_t rc = pal_osMutexWait(mutex, PAL_RTOS_WAIT_FOREVER);
    assert(rc == PAL_SUCCESS);
}

void aq_critical_section_exit() {
    assert(irq_nesting_depth > 0);
    if (--irq_nesting_depth == 0) {
        palStatus_t rc = pal_osMutexRelease(mutex);
        assert(rc == PAL_SUCCESS);
    }
}

#endif // defined(ATOMIC_QUEUE_USE_PAL)
