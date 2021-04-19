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

/**
 * Use critical implementation below when explicitly defined.
 */
#if defined(ATOMIC_QUEUE_USE_PAL)

#include <stdint.h>
#include <assert.h>

#include "pal.h"
// Module include
#include "aq_critical.h"

static palMutexID_t mutex = NULLPTR;

void aq_critical_section_enter(void)
{
    if (mutex == NULLPTR) {
        palStatus_t rc = pal_osMutexCreate(&mutex);
        assert(rc == PAL_SUCCESS);
    }

    palStatus_t rc = pal_osMutexWait(mutex, PAL_RTOS_WAIT_FOREVER);
    assert(rc == PAL_SUCCESS);
}

void aq_critical_section_exit(void)
{
    palStatus_t rc = pal_osMutexRelease(mutex);
    assert(rc == PAL_SUCCESS);
}

#endif // defined(ATOMIC_QUEUE_USE_PAL)
