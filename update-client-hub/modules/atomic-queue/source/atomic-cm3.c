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

#include "atomic.h"

#if defined(TARGET_LIKE_MBED)
#include "cmsis.h"
#endif

#if defined(__CORTEX_M) && (__CORTEX_M >= 0x03)

#define STATIC_ASSERT(STATIC_ASSERT_FAILED,MSG)\
    switch(0){\
        case 0:case (STATIC_ASSERT_FAILED): \
        break;}

#include <stddef.h>
#include <stdint.h>

int aq_atomic_cas_deref_uintptr(uintptr_t* volatile * ptrAddr,
                            uintptr_t** currentPtrValue,
                            uintptr_t expectedDerefValue,
                            uintptr_t* newPtrValue,
                            uintptr_t valueOffset)
{
    STATIC_ASSERT(sizeof(uintptr_t) == sizeof(uint32_t), Error: Pointer size mismatch)
    uint32_t *current;
    current = (uint32_t *)__LDREXW((volatile uint32_t *)ptrAddr);
    if (currentPtrValue != NULL) {
        *currentPtrValue = (uintptr_t *)current;
    }
    if (current == NULL) {
        return AQ_ATOMIC_CAS_DEREF_NULLPTR;
    } else if ( *(uint32_t *)((uintptr_t)current + valueOffset) != expectedDerefValue) {
        return AQ_ATOMIC_CAS_DEREF_VALUE;
    } else if(__STREXW((uint32_t)newPtrValue, (volatile uint32_t *)ptrAddr)) {
        return AQ_ATOMIC_CAS_DEREF_INTERUPTED;
    } else {
        return AQ_ATOMIC_CAS_DEREF_SUCCESS;
    }
}
#endif

