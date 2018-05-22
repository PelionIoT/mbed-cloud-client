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
 * @file atomic-queue.h
 * @brief A linked-list queue based on atomic access
 * @details This queue is designed explicitly for use in contexts where atomic
 * access is desirable. Using an atomic queue comes with three major benefits:
 *
 * 1. This allows the queue to be used in contexts where some RTOS primitives
 *    (mutexes) cannot be used, such as interrupt context.
 * 2. On many platforms, critical sections are very expensive, while atomics
 *    are not. Thus, there is a significant performance benefit to using atomic
 *    primitives wherever possible.
 * 3. Atomic operations have the least effect on all other execution contexts
 *    on the device. Critical sections have performance and responsiveness side
 *    effects. Mutexes can disrupt the execution of other threads. Atomics do 
 *    not affect the execution of other contexts and are immune to priority
 *    inversion.
 * 
 * In short, the atomics are the most cooperative way of building a queue.
 * 
 * Theory of Operation:
 * The queue is intended to be multi-writer/multi-reader. Multi-writer
 * semantics have been fully validated, but multi-reader semantics still
 * require additional validation. It is recommended that the atomic queue be
 * treated as multi-writer/single-reader until this validation is complete.
 * 
 * Assumptions:
 * The queue MUST own all memory currently in the queue. Any modification
 * to a queue element that is already enqueued can result in undefined
 * behaviour.
 * Because of this, the queue expects queue elements to be pool-allocated prior
 * to insertion and freed after extraction.
 * 
 * To mitigate the possibility of a double-insert, the queue elements are
 * populated with a "lock" field. This is used to indicate when the element is
 * in use, to ensure that a parallel thread of execution cannot accidentally
 * reuse an element that has already been inserted.
 * 
 * *NB:* Element locks are unnecessary when the atomic queue is used
 * exclusively with pool allocated queue elements.
 * 
 * Queue Organization:
 * The queue is a singly linked list. The list pointer is the tail pointer of
 * the queue. The tail pointer points to the last element in the queue. To find
 * the head of the queue, the dequeue mechanism traverses the list, starting at
 * the tail of the queue until it finds the last list element, which is the
 * head of the queue. Each queue element contains:
 * * Next pointer
 * * Lock element
 * * Data (void* by default, custom element possible)
 * 
 * Element Insertion:
 * To insert an element:
 * Do: 
 * * Read the tail pointer (load exclusive).
 * * Write the tail pointer into the next pointer of the new element.
 * * Write the tail pointer with the address of the new element 
 *   (store exclusive).
 * Until the store is successful.
 * 
 * If a different thread of higher priority executed between the read and the
 * last write, it will cause the new element to have the wrong next pointer.
 * This is why the load-exclusive and store-exclusive are used. These are ARMv7
 * instructions that allow a given thread of execution to recognize whether it
 * has been interrupted. If another thread has set the exclusive bit, then the
 * store will fail.
 * 
 * Element Extraction:
 * Extracting an element is much more complex than element insertion due to the
 * need to traverse the queue.
 * 
 * 1. Read the tail pointer
 * 2. If the tail pointer is NULL, return NULL.
 * 3. Set the current element to the tail pointer.
 * 4. Read the current element's next pointer (load exclusive).
 * 5. If the next pointer was NULL, start over (go to 1.)
 * 6. Load the next element.
 * 7. Check the value of the next element's next pointer
 * 8. If it is non-NULL, set the current element pointer to the next element and go to 4.
 * 9. Otherwise, set the current element's next pointer to NULL (store exclusive).
 * 10. Return the next element.
 * 
 * There is the potential for another thread of execution to interrupt the
 * search for the head of the queue. This should cause the dequeue mechanism to
 * find a NULL next pointer in the current element. However, this may depend on
 * other circumstances in the system, which might break the behaviour of the
 * queue. Until this is fully analyzed, the queue should be treated as single-
 * reader/multi-writer.
 */

#ifndef __ATOMIC_QUEUE_H__
#define __ATOMIC_QUEUE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


#ifndef ATOMIC_QUEUE_CUSTOM_ELEMENT
struct atomic_queue_element {
    struct atomic_queue_element * volatile next;
    uintptr_t lock;
    void * data;
};
#endif

struct atomic_queue {
    struct atomic_queue_element * volatile tail;
};

enum aq_failure_codes {
    ATOMIC_QUEUE_SUCCESS = 0,
    ATOMIC_QUEUE_NULL_QUEUE,
    ATOMIC_QUEUE_NULL_ELEMENT,
    ATOMIC_QUEUE_DUPLICATE_ELEMENT,
    
};

/**
 * \brief Add an element to the tail of the queue
 *
 * Since the queue only maintains a tail pointer, this simply inserts the new element before the tail pointer
 *
 * Element Insertion:
 * To insert an element:
 * Do: 
 * * Read the tail pointer (load exclusive).
 * * Write the tail pointer into the next pointer of the new element.
 * * Write the tail pointer with the address of the new element 
 *   (store exclusive).
 * Until the store is successful.
 *
 * If a different thread of higher priority executed between the read and the
 * last write, it will cause the new element to have the wrong next pointer.
 * This is why the load-exclusive and store-exclusive are used. These are ARMv7
 * instructions that allow a given thread of execution to recognize whether it
 * has been interrupted. If another thread has set the exclusive bit, then the
 * store will fail. 
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
 * Element Extraction:
 * Extracting an element is much more complex than element insertion due to the
 * need to traverse the queue.
 * 
 * 1. Read the tail pointer
 * 2. If the tail pointer is NULL, return NULL.
 * 3. Set the current element to the tail pointer.
 * 4. Read the current element's next pointer (load exclusive).
 * 5. If the next pointer was NULL, start over (go to 1.)
 * 6. Load the next element.
 * 7. Check the value of the next element's next pointer
 * 8. If it is non-NULL, set the current element pointer to the next element and go to 4.
 * 9. Otherwise, set the current element's next pointer to NULL (store exclusive).
 * 10. Return the next element.
 * 
 * There is the potential for another thread of execution to interrupt the
 * search for the head of the queue. This should cause the dequeue mechanism to
 * find a NULL next pointer in the current element. However, this may depend on
 * other circumstances in the system, which might break the behaviour of the
 * queue. Until this is fully analyzed, the queue should be treated as single-
 * reader/multi-writer.
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

/**
 * Take an element (this acquires the element lock)
 * 
 * @param[in] element Element to take
 */
int aq_element_take(struct atomic_queue_element * e);

/**
 * Release an element (this releases the element lock)
 * 
 * @param[in] element Element to release
 */
int aq_element_release(struct atomic_queue_element * e);

/**
 * Atomic Compare and Set
 * 
 * Take a pointer to a uintptr_t, compare its current value to oldval. If it is
 * as expected, try to write newval to the pointer target. Fail if interrupted.
 * 
 * @param[in,out] ptr A pointer to the target of the atomic compare and set
 * @param[in]     oldval A value to compare with the target of ptr.
 * @param[in]     newval A new value to store to the target of ptr.
 * @retval 1 if newval was stored
 * @retval 0 if oldval did not match *ptr, or if the store was interrupted.
 */
int aq_atomic_cas_uintptr(uintptr_t *ptr, uintptr_t oldval, uintptr_t newval);

/**
 * Atomic increment
 * 
 * Increment the value pointed to by ptr and increment it by inc atomically
 * This is just a passthrough to __sync_add_and_fetch on platforms where it
 * is supported.
 * 
 * @param[in,out] ptr A pointer to the target of the increment
 * @param[in]     inc A value by which to increment *ptr
 * @return the new value of *ptr
 */
int32_t aq_atomic_inc_int32(int32_t *ptr, int32_t inc);


#ifdef __cplusplus
}
#endif

#endif // __ATOMIC_QUEUE_H__
