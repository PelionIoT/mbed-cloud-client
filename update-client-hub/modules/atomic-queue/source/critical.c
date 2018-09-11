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

// This critical section implementation is generic for mbed OS targets,
// except Nordic ones
#if defined(TARGET_LIKE_MBED) && !defined(TARGET_NORDIC)

#include <stdint.h>                  // uint32_t, UINT32_MAX
#include <stddef.h>                  // NULL

#if defined(YOTTA_CFG_MBED_OS)
#include "cmsis-core/core_generic.h" //__disable_irq, __enable_irq
#else
#include "cmsis.h"
#endif

#include <assert.h>

// Module include
#include "aq_critical.h"

static volatile uint32_t interruptEnableCounter = 0;
static volatile uint32_t critical_primask = 0;

void aq_critical_section_enter()
{
    uint32_t primask;
#if defined(__CORTEX_A9)
    primask = __get_CPSR(); // get the current interrupt enabled state
#else
    primask = __get_PRIMASK(); // get the current interrupt enabled state
#endif
    __disable_irq();

    // Save the interrupt enabled state as it was prior to any nested critical section lock use
    if (!interruptEnableCounter) {
#if defined(__CORTEX_A9)
        critical_primask = primask & 0x80;
#else
        critical_primask = primask & 0x1;
#endif
    }
#if 0
    /* If the interruptEnableCounter overflows or we are in a nested critical section and interrupts
       are enabled, then something has gone badly wrong thus assert an error.
    */

    /* FIXME: This assertion needs to be commented out for the moment, as it
     *        triggers a fault when uVisor is enabled. For more information on
     *        the fault please checkout ARMmbed/mbed-drivers#176. */

    assert(interruptEnableCounter < UINT32_MAX);
    if (interruptEnableCounter > 0) {
        assert(primask & 0x1);
    }
#endif

    if (interruptEnableCounter < UINT32_MAX) {
        interruptEnableCounter++;
    }
}

void aq_critical_section_exit(void)
{
    // If critical_section_enter has not previously been called, do nothing
    if (interruptEnableCounter) {
#if 0
        /* FIXME: This assertion needs to be commented out for the moment, as it
         *        triggers a fault when uVisor is enabled. For more information
         *        on the fault please checkout ARMmbed/mbed-drivers#176. */

        uint32_t primask;
#if defined(__CORTEX_A9)
        primask = __get_CPSR(); // get the current interrupt enabled state
#else
        primask = __get_PRIMASK(); // get the current interrupt enabled state
#endif
        assert(primask & 0x1); // Interrupts must be disabled on invoking an exit from a critical section
#endif

        interruptEnableCounter--;


        /* Only re-enable interrupts if we are exiting the last of the nested critical sections and
           interrupts were enabled on entry to the first critical section.
        */
        if (!interruptEnableCounter && !critical_primask) {
            __enable_irq();
        }
    }
}

#endif // defined(TARGET_LIKE_MBED) && !defined(TARGET_NORDIC)
