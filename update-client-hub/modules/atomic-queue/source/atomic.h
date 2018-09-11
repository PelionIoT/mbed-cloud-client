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

#ifndef ATOMIC_QUEUE_ATOMIC_H
#define ATOMIC_QUEUE_ATOMIC_H
#include <stdint.h>



#ifdef __cplusplus
extern "C" {
#endif

enum {
    AQ_ATOMIC_CAS_DEREF_SUCCESS = 0,
    AQ_ATOMIC_CAS_DEREF_NULLPTR,
    AQ_ATOMIC_CAS_DEREF_VALUE,
    AQ_ATOMIC_CAS_DEREF_INTERUPTED,
};

/**
 * @brief Atomically compares the value of a dereferenced pointer, replacing the pointer on success.
 * @detail aq_atomic_cas_deref_uintptr provides a mechanism to atomically change a pointer based on a value contained
 *     in the structure referenced by the pointer. This is done in the following sequence of operations:
 *
 *     1. Load the value of `*ptrAddr`
 *     2. Optionally store the current value of `*ptrAddr`
 *     3. Check that the pointer is valid: `*ptrAddr != NULL`
 *     4. Check the value of the referenced location: `*(*ptrAddr + valueOffset) == expectedDerefValue` (casts omitted)
 *     5. If 3 and 4 succeeded, store newPtrValue: `*ptrAddr = newPtrValue` (NOTE: in non-blocking implementations, this step can fail)
 *     6. Return a status code based on the results of 3, 4, 5.
 *
 * @param[in,out] ptrAddr            The address of the pointer to manipulate
 * @param[out]    currentPtrValue    A pointer to a container for the current value of *ptrAddr
 * @param[in]     expectedDerefValue This is the value that is expected at *(uintptr_t *)((uintptr_t)*ptrAddr + valueOffset)
 * @param[in]     newPtrValue        The value to store to *ptrAddr if the comparison is successful
 * @param[in]     valueOffset        The offset of the target value from *ptrAddr
 *
 * @retval AQ_ATOMIC_CAS_DEREF_SUCCESS    The compare and set has succeeded
 * @retval AQ_ATOMIC_CAS_DEREF_NULLPTR    `*ptrAddr` was `NULL`
 * @retval AQ_ATOMIC_CAS_DEREF_VALUE      The value test failed (*(*ptrAddr + valueOffset) != expectedDerefValue`)
 * @retval AQ_ATOMIC_CAS_DEREF_INTERUPTED Another context modified `*ptrAddr`
 */
int aq_atomic_cas_deref_uintptr(uintptr_t *volatile *ptrAddr,
                                uintptr_t **currentPtrValue,
                                uintptr_t expectedDerefValue,
                                uintptr_t *newPtrValue,
                                uintptr_t valueOffset);

#ifdef __cplusplus
} // extern "C"
#endif
#endif // ATOMIC_QUEUE_ATOMIC_H
