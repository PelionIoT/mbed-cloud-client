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
 * Simple scheduler useful for collecting events from different threads and
 * interrupt context so they can be executed from the same thread/context.
 *
 * This can reduce the calldepth, ensure functions are executed from the same
 * thread, and provide a method for breaking out of interrupt context.
 *
 * Callbacks are executed FIFO.
 *
 * The notification handler should be used for processing the queue whenever it
 * is non-empty.
 */

/**
 * Use custom struct for the lockfree queue.
 * Struct contains function pointer callback and uint32_t parameter.
 */
#define ATOMIC_QUEUE_CUSTOM_ELEMENT

struct lockfree_queue_element {
    struct lockfree_queue_element * volatile next;
    uintptr_t lock;
    void (*callback)(uint32_t);
    uint32_t parameter;
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
 * @param parameter uint32_t value to be passed as parameter to the callback function.
 * @return True when the callback was successfully scheduled.
 */
bool ARM_UC_PostCallback(arm_uc_callback_t* storage, void (*callback)(uint32_t), uint32_t parameter);

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

#ifdef __cplusplus
}
#endif

#endif // ARM_UPDATE_SCHEDULER_H
