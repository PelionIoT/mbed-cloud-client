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

#ifndef __ATOMIC_QUEUE_H__
#define __ATOMIC_QUEUE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if defined(ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK) && ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK == 0
#undef ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK
#else
#undef ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK
#define ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK
#endif

#ifndef ATOMIC_QUEUE_CUSTOM_ELEMENT
struct atomic_queue_element {
    struct atomic_queue_element * volatile next;
#ifdef ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK
    uintptr_t lock;
#endif
    void * data;
};
#endif

struct atomic_queue {
    struct atomic_queue_element * volatile tail;
};

enum aq_failure_codes {
    ATOMIC_QUEUE_SUCCESS = 0,
    ATOMIC_QUEUE_NULL_QUEUE,
    ATOMIC_QUEUE_DUPLICATE_ELEMENT,
};

/**
 * \brief Add an element to the tail of the queue
 *
 * Since the queue only maintains a tail pointer, this simply inserts the new element before the tail pointer
 *
 * @param[in,out] q the queue structure to operate on
 * @param[in] e The element to add to the queue
 */
int aq_push_tail(struct atomic_queue * q, struct atomic_queue_element * e);
/**
 * \brief Get an element from the head of the queue
 *
 * This function iterates over the queue and removes an element from the head when it finds the head. This is slower
 * than maintaining a head pointer, but it is necessary to ensure that a pop is completely atomic.
 *
 * @param[in,out] q The queue to pop from
 * @return The popped element or NULL if the queue was empty
 */
struct atomic_queue_element * aq_pop_head(struct atomic_queue * q);
/**
 * Check if there are any elements in the queue
 *
 * Note that there is no guarantee that a queue which is not empty when this API is called will not be become empty
 * before aq_pop_head is called
 *
 * @retval non-zero when the queue is empty
 * @retval 0 when the queue is not empty
 */
int aq_empty(struct atomic_queue * q);
/**
 * Iterates over the queue and counts the elements in the queue
 *
 * The value returned by this function may be invalid by the time it returns. Do not depend on this value except in
 * a critical section.
 *
 * @return the number of elements in the queue
 */
unsigned aq_count(struct atomic_queue * q);

/**
 * Initialize an atomic queue element.
 *
 * WARNING: Only call this function one time per element, or it may result in undefined behaviour.
 *
 * @param[in] element Element to initialize
 */
void aq_initialize_element(struct atomic_queue_element* e);

#ifdef __cplusplus
}
#endif

#endif // __ATOMIC_QUEUE_H__
