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

#ifndef ARM_UPDATE_SCHEDULER_H
#define ARM_UPDATE_SCHEDULER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @file arm_uc_scheduler.h
 * @brief A simple, atomic event queue for embedded systems
 *
 * @details This is a simple scheduler useful for collecting events from
 * different threads and interrupt context so they can be executed from the
 * same thread/context.
 *
 * This can reduce the calldepth, ensure functions are executed from the same
 * thread, and provide a method for breaking out of interrupt context.
 *
 * Callbacks are executed FIFO.
 *
 * The notification handler should be used for processing the queue whenever it
 * is non-empty.
 *
 * This event queue uses an underlying atomic queue implementation
 * to provide atomicity guaranties without Critical Section primitives on
 * Cortex-M3 or later platforms. Linux and Cortex-M0 require a Critical Section
 * due to the lack of exclusive access primitives. See the atomic-queue
 * documentation for more detail on atomic access.
 *
 * An atomic queue has been used for three reasons:
 * 1. This allows the queue to be used in contexts where some RTOS primitives
 *    (mutexes) cannot be used, such as interrupt context.
 * 2. On many platforms, critical sections are very expensive, while atomics
 *    are not. Thus, there is a significant performance benefit to using atomic
 *    primitives wherever possible.
 * 3. Atomic operations have the least effect on all other execution contexts
 *    on the device. Critical sections have performance and responsiveness side
 *    effects. Mutexes can disrupt the execution of other threads. Atomics do
 *    not affect the execution of other contexts and are immune to priority
 *    inversion
 *
 * In short, the atomic queue is the most cooperative way of building an event
 * queue.
 *
 * This queue does, however have three major drawbacks:
 * 1. There is no way to directly cancel a callback. This is because the atomic
 *    queue has no way to remove an element from the middle of the queue. It
 *    can only be removed from the head of the queue.
 * 2. There is no way to prioritize one callback over another in the same
 *    queue. This is because there is no way to insert a callback into the
 *    middle of the queue. It can only be added at the end.
 * 3. The queue is entirely dependent on correct memory ownership, but it
 *    allocates no memory. The queue must own the callbacks while they are in
 *    the queue and any manipulation of that storage could break the behaviour
 *    of the queue.
 *
 * To compensate for 1., a callback author can provide a cancellation flag for
 * their callback that is checked on entry, but this may not know if it was
 * successful. The implementation of callback cancellation is beyond the scope
 * of this document.
 *
 * To compensate for 2., a prioritized event queue could be constructed from
 * two or more atomic queues. Since an event queue only takes a single pointer
 * of dedicated storage, this is can be used with a small number of priorities.
 * The implementation of a prioritized event queue is beyond the scope of this
 * document.
 *
 * In typical (non-atomic) structures, the solution for 3. is to allocate a
 * new callback storage block from the heap on each call. This would ensure
 * that the queue owns the block. However, this is not possible from an
 * interrupt context. Therefore, the queue uses a pool allocator instead.
 * However, pool allocators can run out of elements very easily. To ensure
 * that a particular callback can be scheduled, it is possible to give the
 * callback a statically allocated block instead. However, this introduces a
 * new failure mode: what happens if the block is already in use?
 *
 * To compensate for this failure mode, a per-element lock is provided in every
 * atomic queue element. The lock must be taken before ANY content of the
 * element is modified, including setting the callback and parameter. The lock
 * must only be released after the contents of the element have been copied
 * out.
 *
 * Because both statically allocated blocks and pool allocated blocks are
 * available, the user of the event queue is presented with a choice: Use a
 * statically allocated callback element, or use a pool allocated callback
 * element. Each option is better for different use-cases. When it is only
 * semantically possible for one callback from a given block of code to be in
 * flight at a time, it is more reliable for the callback to be statically
 * allocated. When it's possible for more than one callback from the same block
 * of code to be in flight at a time, then the pool allocator is a better
 * choice. Notwithstanding this distinction, if the scheduler fails to acquire
 * a lock on a statically allocated element, it will allocate a pool element
 * instead.
 *
 * To reduce API complexity, the callback queue mechanism works as below:
 *
 * When a callback is posted, the scheduler attempts to acquire the lock.
 * If either the callback storage is NULL or the lock cannot be acquired, the
 * scheduler pool-allocates a callback. If that fails, the scheduler uses a
 * dedicated error callback to notify the system that pool allocation has
 * failed, since this is a critical error.
 *
 * This event queue is composed of two major parts:
 * * The mechanism to post a callback (ARM_UC_PostCallback)
 * * The mechanism to process a callback
 *
 * When posting a callback, the scheduler first takes the lock on the supplied
 * callback structure, or pool-allocates a new one and then takes the lock. The
 * supplied event handler and event parameter are then placed into the supplied
 * (or pool-allocated) callback structure. The callback structure is then
 * placed in the event queue for later execution. If the queue was empty prior
 * to queuing this element, then the notification handler is invoked.
 *
 * **NOTE:** this means that the notification handler MUST be safe to execute
 * in IRQ context.
 *
 * When the queue is processed, callbacks are extracted in FIFO order. The
 * scheduler can be run in one of two modes:
 * * Consume the whole queue (ARM_UC_ProcessQueue)
 * * Consume single event (ARM_UC_ProcessSingleCallback)
 *
 * Both of these operations execute the same process:
 * 1. An element is dequeued from the atomic-queue
 * 2. The contents of the element are extracted
 * 3. The element is unlocked
 * 4. If the element was pool-allocated, it is freed
 * 5. The callback is executed with the supplied parameter
 *
 * Finally, ARM_UC_ProcessQueue goes back to 1, while
 * ARM_UC_ProcessSingleCallback returns true if there are still callbacks in
 * the queue, false otherwise.
 *
 * Callback Pool:
 * The callback pool is configured using a system define:
 *     ARM_UC_SCHEDULER_STORAGE_POOL_SIZE
 * To set the size of the pool, override this define in your build system. To
 * disable the pool, set this define to 0.
 *
 * To assist with callback pool debugging, an API is provided to calculate the
 * high watermark of the pool: ARM_UC_SchedulerGetHighWatermark(). This can be
 * compared to ARM_UC_SCHEDULER_STORAGE_POOL_SIZE to determine how many
 * elements were left at maximum usage.
 */

/**
 * Use custom struct for the lockfree queue.
 * Struct contains function pointer callback and uint32_t parameter.
 */
#define ATOMIC_QUEUE_CUSTOM_ELEMENT

/* A queue element can store two different callback types: with and without context */
typedef void (*arm_uc_no_context_callback_t)(uintptr_t);
typedef void (*arm_uc_context_callback_t)(void *, uintptr_t);
struct lockfree_queue_element {
    struct lockfree_queue_element *volatile next;
    uintptr_t lock;
    void *callback;
    uintptr_t parameter;
};

#include "atomic-queue/atomic-queue.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lockfree_queue_element arm_uc_callback_t;

/**
 * @brief Add function to be executed to the queue.
 * @details The caller is responsible for managing the memory for each element
 *          in the queue, i.e., allocating enough struct lockfree_queue_element
 *          to hold the number of outstanding callbacks in the queue.
 *
 * @param storage Pointer to struct lockfree_queue_element.
 * @param callback Function pointer to function being scheduled to run later.
 * @param parameter uintptr_t value to be passed as parameter to the callback function.
 * @return True when the callback was successfully scheduled.
 */
bool ARM_UC_PostCallback(arm_uc_callback_t *storage, arm_uc_no_context_callback_t callback, uintptr_t parameter);

/**
 * @brief Add function to be executed to the queue and associate a context with it.
 * @details The caller is responsible for managing the memory for each element
 *          in the queue, i.e., allocating enough struct lockfree_queue_element
 *          to hold the number of outstanding callbacks in the queue.
 *
 * @param storage Pointer to struct lockfree_queue_element.
 * @param[in] ctx The callback context. If a context is not needed, use ATOMIC_QUEUE_NO_CONTEXT.
 *                If a context is needed, pass a non-NULL pointer.
 * @param callback Function pointer to function being scheduled to run later.
 * @param parameter uintptr_t value to be passed as parameter to the callback function.
 * @return True when the callback was successfully scheduled.
 */
bool ARM_UC_PostCallbackCtx(arm_uc_callback_t *storage, void *ctx, arm_uc_context_callback_t callback, uintptr_t parameter);

/**
 * @brief Schedule an error callback.
 * @details The error callback has priority over the other callbacks: as long as
 *          an error callback was posted using this function, it'll be dispatched before
 *          all the other callbacks in the queue. The storage for the error callback is
 *          internal to the scheduler. A single error callback can be scheduled at a time.
 *
 * @param[in] ctx The callback context. If a context is not needed, use ATOMIC_QUEUE_NO_CONTEXT.
 *                If a context is needed, pass a non-NULL pointer.
 * @param callback Function pointer to the error callback.
 * @param parameter uintptr_t value to be passed as parameter to the callback function.
 * @return True when the callback was successfully scheduled.
 */
bool ARM_UC_PostErrorCallbackCtx(void *_ctx, arm_uc_context_callback_t _callback, uintptr_t _parameter);

/**
 * @brief Calling this function processes all callbacks in the queue.
 */
void ARM_UC_ProcessQueue(void);

/**
 * @brief Calling this function processes a single callback in the queue.
 * @details The return value indicates whether there are more callbacks
 *          in the queue that needs handling.
 * @return True when there are more callbacks in the queue, false otherwise.
 */
bool ARM_UC_ProcessSingleCallback(void);

/**
 * @brief Register callback function for when callbacks are added to an empty queue.
 * @details This function is called at least once (maybe more) when callbacks are
 *          added to an empty queue. Useful for scheduling when the queue needs
 *          to be processed.
 * @param handler Function pointer to function to be called when elements are
 *        added to an empty queue.
 */
void ARM_UC_AddNotificationHandler(void (*handler)(void));

/**
 * @brief Initialize the scheduler.
 * @details This function primarily initializes the pool allocator for
 * callbacks. It should be called prior to using the scheduler at all.
 */
void ARM_UC_SchedulerInit(void);

/**
 * @brief Set the handler for scheduler errors.
 * @details This will be called in normal scheduler context when the pool runs
 * out of available callbacks.
 *
 * @param[in] handler The function to call (thread context) when there is a
 *                    scheduler error.
 */
void ARM_UC_SetSchedulerErrorHandler(void(*handler)(uint32_t));

/**
 * @brief Get the maximum usage of the callback pool.
 * @details Uses the high watermark of the callback pool to indicate the
 * worst-case callback usage.
 *
 * @return the maximum number of callbacks that have been allocated from the
 * pool at one time.
 */
uint32_t ARM_UC_SchedulerGetHighWatermark(void);

/**
 * @brief Get the current number of queued callbacks
 * @details This is a function for running tests. The value returned by this
 * function cannot be relied upon in any system that is not exclusively
 * single-threaded, since any parallel thread or any interrupt could modify the
 * count.
 *
 * @return The number of callbacks currently queued in the scheduler.
 */
int32_t ARM_UC_SchedulerGetQueuedCount(void);

/**
 * @brief Remove all pending callbacks in the scheduler's queue
 */
void ARM_UC_DrainCallbackQueue(void);

#ifdef __cplusplus
}
#endif

#endif // ARM_UPDATE_SCHEDULER_H
