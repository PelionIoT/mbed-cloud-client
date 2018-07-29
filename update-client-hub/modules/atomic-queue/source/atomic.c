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

#include <stddef.h>
#include "atomic.h"
#include "aq_critical.h"

#if defined(TARGET_LIKE_MBED)
#include "cmsis.h"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M < 0x03)

int aq_atomic_cas_deref_uintptr(uintptr_t* volatile * ptrAddr,
                            uintptr_t** currentPtrValue,
                            uintptr_t expectedDerefValue,
                            uintptr_t* newPtrValue,
                            uintptr_t valueOffset)
{
    int rc;
    aq_critical_section_enter();
    uintptr_t *current = *ptrAddr;
    if (currentPtrValue != NULL) {
        *currentPtrValue = current;
    }
    if (current == NULL) {
        rc = AQ_ATOMIC_CAS_DEREF_NULLPTR;
    } else if ( *(uintptr_t *)((uintptr_t)current + valueOffset) != expectedDerefValue) {
        rc = AQ_ATOMIC_CAS_DEREF_VALUE;
    } else {
        *ptrAddr = newPtrValue;
        rc = AQ_ATOMIC_CAS_DEREF_SUCCESS;
    }
    aq_critical_section_exit();
    return rc;
}
#endif


#if defined(__GNUC__) && (!defined(__CORTEX_M) || (__CORTEX_M >= 0x03)) && (!defined(__MICROLIB))
int aq_atomic_cas_uintptr(uintptr_t *ptr, uintptr_t oldval, uintptr_t newval) {
    return __sync_bool_compare_and_swap(ptr, oldval, newval);
}

int32_t aq_atomic_inc_int32(int32_t *ptr, int32_t inc) {
    return __sync_add_and_fetch(ptr, inc);
}
#else
int aq_atomic_cas_uintptr(uintptr_t *ptr, uintptr_t oldval, uintptr_t newval)
{
    int rc;
    aq_critical_section_enter();
    if (*ptr == oldval) {
        rc = 1;
        *ptr = newval;
    } else {
        rc = 0;
    }
    aq_critical_section_exit();
    return rc;
}
int32_t aq_atomic_inc_int32(int32_t *ptr, int32_t inc) {
    int32_t ret;
    aq_critical_section_enter();
    ret = *ptr + inc;
    *ptr = ret;
    aq_critical_section_exit();
    return ret;
}
#endif
