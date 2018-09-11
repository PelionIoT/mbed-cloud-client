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

#include "update-client-common/arm_uc_config.h"
#include "update-client-common/arm_uc_scheduler.h"
#include "update-client-common/arm_uc_trace.h"
#include "update-client-common/arm_uc_error.h"

#include "atomic-queue/atomic-queue.h"

static struct atomic_queue arm_uc_queue = { 0 };
static void (*arm_uc_notificationHandler)(void) = NULL;
static volatile int32_t arm_uc_queue_counter = 0;

int32_t ARM_UC_SchedulerGetQueuedCount(void)
{
    return arm_uc_queue_counter;
}

#if ARM_UC_SCHEDULER_STORAGE_POOL_SIZE
/* Define the scheduler's callback pool storage.
 * The scheduler will allocate out of this pool whenever it encounters a
 * callback that is already locked or a callback that is NULL.
 */
static arm_uc_callback_t callback_pool_storage[ARM_UC_SCHEDULER_STORAGE_POOL_SIZE];
static arm_uc_callback_t *callback_pool_root;
#endif

static void (*scheduler_error_cb)(uint32_t parameter);
static arm_uc_callback_t callback_pool_exhausted_error_callback = {0};
static arm_uc_callback_t callback_failed_take_error_callback = {0};

#define POOL_WATERMARK 0xABABABAB

void ARM_UC_SchedulerInit(void)
{
#if ARM_UC_SCHEDULER_STORAGE_POOL_SIZE
    /* Initialize the storage pool */
    callback_pool_root = callback_pool_storage;
    for (size_t i = 0; i < ARM_UC_SCHEDULER_STORAGE_POOL_SIZE - 1; i++) {
        callback_pool_storage[i].next = &callback_pool_storage[i + 1];
        /* watermark pool elements by setting the lock to POOL_WATERMARK.
         * This allows checking of the maximum number of concurrent allocations.
         */
        callback_pool_storage[i].lock = POOL_WATERMARK;
    }
    callback_pool_storage[ARM_UC_SCHEDULER_STORAGE_POOL_SIZE - 1].next = NULL;
    callback_pool_storage[ARM_UC_SCHEDULER_STORAGE_POOL_SIZE - 1].lock = POOL_WATERMARK;
#endif
    memset(&callback_pool_exhausted_error_callback, 0, sizeof(arm_uc_callback_t));
    memset(&callback_failed_take_error_callback, 0, sizeof(arm_uc_callback_t));
}

/**
 * @brief Allocate a block from the pool
 * @details Gets a non-null block from the callback pool.
 *
 * Theory of operation:
 * * callback_pool_alloc starts by fetching the current value of the pool's
 *   root. This value should be the next free item in the pool.
 * * If the value is NULL, then there are no elements left in the pool, so
 *   callback_pool_alloc returns NULL.
 * * callback_pool_alloc tries to take this element by replacing the root
 *   node with the following element. If replacement fails, callback_pool_alloc
 *   tries the whole process again. This is repeated until allocation succeeds
 *   or the root pointer is NULL.
 *
 * @retval NULL the no element was available to allocate
 * @retval non-NULL An allocated element
 */
static arm_uc_callback_t *callback_pool_alloc()
{
    while (true) {
        arm_uc_callback_t *prev_free = callback_pool_root;
        if (NULL == prev_free) {
            return NULL;
        }
        arm_uc_callback_t *new_free = prev_free->next;

        if (aq_atomic_cas_uintptr((uintptr_t *)&callback_pool_root, (uintptr_t)prev_free, (uintptr_t)new_free)) {
            return prev_free;
        }
    }
}

/**
 * @brief Check if the pool owns a block
 * @detail callback_pool_owns() checks whether the pointer supplied exists
 * within the callback_pool_storage array. If it does, that means that the pool
 * should own the block.
 *
 * @param[in] e the element to evaluate for pool ownership
 *
 * @retval 1 the pool owns the callback
 * @retval 0 the pool does not own the callback
 */

static int callback_pool_owns(arm_uc_callback_t *e)
{
    int isGreater = e >= callback_pool_storage;
    int isLesser = (uintptr_t)e < ((uintptr_t)callback_pool_storage + sizeof(callback_pool_storage));
    return isGreater && isLesser;
}

/**
 * @brief Free a block owned by the pool.
 * @details Checks whether the supplied callback is owned by the pool and frees
 * it if so. Performs no operation for a callback that is not owned by the pool.
 *
 * @param[in] e the element to free
 */
static void callback_pool_free(arm_uc_callback_t *e)
{
    UC_SDLR_TRACE("%s (%p)", __PRETTY_FUNCTION__, e);
    if (callback_pool_owns(e)) {
        while (true) {
            arm_uc_callback_t *prev_free = callback_pool_root;

            e->next = prev_free;
            UC_SDLR_TRACE("%s inserting r:%p p:%p, e:%p, ", __PRETTY_FUNCTION__, callback_pool_root, prev_free, e);
            if (aq_atomic_cas_uintptr((uintptr_t *)&callback_pool_root, (uintptr_t)prev_free, (uintptr_t)e)) {
                break;
            }
            UC_SDLR_TRACE("%s inserting failed", __PRETTY_FUNCTION__);
        }
    }
}

uint32_t ARM_UC_SchedulerGetHighWatermark(void)
{
    uint32_t i;
    for (i = 0; i < ARM_UC_SCHEDULER_STORAGE_POOL_SIZE; i++) {
        if (callback_pool_storage[i].lock == POOL_WATERMARK) {
            break;
        }
    }
    return i;
}


void ARM_UC_AddNotificationHandler(void (*handler)(void))
{
    arm_uc_notificationHandler = handler;
}

void ARM_UC_SetSchedulerErrorHandler(void(*handler)(uint32_t))
{
    scheduler_error_cb = handler;
}

bool ARM_UC_PostCallback(arm_uc_callback_t *_storage,
                         void (*_callback)(uint32_t),
                         uint32_t _parameter)
{
    bool success = true;
    UC_SDLR_TRACE("%s Scheduling %p(%lu) with %p", __PRETTY_FUNCTION__, _callback, _parameter, _storage);

    if (_callback == NULL) {
        return false;
    }

    if (_storage) {
        int result = aq_element_take((void *) _storage);
        if (result != ATOMIC_QUEUE_SUCCESS) {

// NOTE: This may be useful for detecting double-allocation of callbacks on mbed-os too
#if defined(TARGET_IS_PC_LINUX)
            /* On Linux, issue an error message if the callback was not added
               to the queue. This is dangerous in mbed-os, since writing to the
               console from an interrupt context might crash the program. */
            UC_SDLR_TRACE("ARM_UC_PostCallback failed to acquire lock on: %p %p; allocating a temporary callback",
                          _storage,
                          _callback);

#endif
            _storage = NULL;
        }
    }
    if (_storage == NULL) {
        _storage = callback_pool_alloc();
        if (_storage == NULL) {
            success = false;
            /* Handle a failed alloc */

#ifdef TARGET_IS_PC_LINUX
            /* On Linux, issue an error message if the callback was not added
               to the queue. This is dangerous in mbed-os, since writing to the
               console from an interrupt context might crash the program. */
            UC_SDLR_ERR_MSG("Failed to allocate a callback block");
#endif
            if (scheduler_error_cb) {
                _storage = &callback_pool_exhausted_error_callback;
                int result = aq_element_take((void *) _storage);
                if (result == ATOMIC_QUEUE_SUCCESS) {
                    _parameter = ARM_UC_EQ_ERR_POOL_EXHAUSTED;
                    _callback = scheduler_error_cb;
                } else {
                    _storage = NULL;
                }
            }
        } else {
            /* This thread is guaranteed to exclusively own _storage here */
            aq_initialize_element((void *) _storage);
            int result = aq_element_take((void *) _storage);
            if (result != ATOMIC_QUEUE_SUCCESS) {
                success = false;
                /* This should be impossible */
                UC_SDLR_ERR_MSG("Failed to take an allocated a callback block... this should be impossible...");
                if (scheduler_error_cb) {
                    _storage = &callback_failed_take_error_callback;
                    int result = aq_element_take((void *) _storage);
                    if (result == ATOMIC_QUEUE_SUCCESS) {
                        _parameter = ARM_UC_EQ_ERR_FAILED_TAKE;
                        _callback = scheduler_error_cb;
                    } else {
                        _storage = NULL;
                    }
                }
            }
        }
    }
    if (_storage) {
        /* populate callback struct */
        _storage->callback = _callback;
        _storage->parameter = _parameter;

        UC_SDLR_TRACE("%s Queueing %p(%lu) in %p", __PRETTY_FUNCTION__, _callback, _parameter, _storage);

        /* push struct to atomic queue */
        int result = aq_push_tail(&arm_uc_queue, (void *) _storage);

        if (result == ATOMIC_QUEUE_SUCCESS) {
            UC_SDLR_TRACE("%s Scheduling success!", __PRETTY_FUNCTION__);

            /*  The queue is processed by removing an element first and then
                decrementing the queue counter. This continues until the counter
                reaches 0 (process single callback) or the queue is empty
                (process queue).

                If the counter is greater than zero at this point, there should
                already be a notification in progress, so no new notification
                is required.

                If the counter is zero at this point, there is one element in
                the queue, and incrementing the counter will return 1 and which
                triggers a notification.

                Because the scheduler could run at any time and consume queue
                elements, it's possible for the scheduler to remove the queue
                element before the counter is incremented.

                Therefore, If the queue is empty at this point, the counter is
                -1 and incrementing the counter will return 0. This does not
                trigger a notification, which is correct since the queue is
                empty.
            */
            int32_t count = aq_atomic_inc_int32((int32_t *) &arm_uc_queue_counter, 1);

            /* if notification handler is set, check if this is the first
            insertion
            */
            if ((arm_uc_notificationHandler) && (count == 1)) {
                UC_SDLR_TRACE("%s Invoking notify!", __PRETTY_FUNCTION__);

                /* disable: UC_SDLR_TRACE("notify nanostack scheduler"); */
                arm_uc_notificationHandler();
            }
        } else {
            success = false;
        }
    }

    return success;
}

void ARM_UC_ProcessQueue(void)
{
    arm_uc_callback_t *element = (arm_uc_callback_t *) aq_pop_head(&arm_uc_queue);

    while (element != NULL) {
        UC_SDLR_TRACE("%s Invoking %p(%lu)", __PRETTY_FUNCTION__, element->callback, element->parameter);
        /* Store the callback locally */
        void (*callback)(uint32_t) = element->callback;
        /* Store the parameter locally */
        uint32_t parameter = element->parameter;
        /* Release the lock on the element */
        UC_SDLR_TRACE("%s Releasing %p", __PRETTY_FUNCTION__, element);
        aq_element_release((void *) element);
        /* Free the element if it was pool allocated */
        UC_SDLR_TRACE("%s Freeing %p", __PRETTY_FUNCTION__, element);
        callback_pool_free((void *) element);

        /* execute callback */
        callback(parameter);

        /*  decrement element counter after executing the callback.
            otherwise further callbacks posted inside this callback could
            trigger notifications eventhough we are still processing the queue.
        */
        int32_t count = aq_atomic_inc_int32((int32_t *) &arm_uc_queue_counter, -1);

        if (count > 0) {
            /* get next element */
            element = (arm_uc_callback_t *) aq_pop_head(&arm_uc_queue);
        } else {
            element = NULL;
        }
    }
}

bool ARM_UC_ProcessSingleCallback(void)
{
    /* elements in queue */
    int32_t count = 0;

    /* get first element */
    arm_uc_callback_t *element = (arm_uc_callback_t *) aq_pop_head(&arm_uc_queue);

    if (element != NULL) {
        UC_SDLR_TRACE("%s Invoking %p(%lu)", __PRETTY_FUNCTION__, element->callback, element->parameter);
        /* Store the callback locally */
        void (*callback)(uint32_t) = element->callback;
        /* Store the parameter locally */
        uint32_t parameter = element->parameter;
        /* Release the lock on the element */
        UC_SDLR_TRACE("%s Releasing %p", __PRETTY_FUNCTION__, element);
        aq_element_release((void *) element);
        /* Free the element if it was pool allocated */
        UC_SDLR_TRACE("%s Freeing %p", __PRETTY_FUNCTION__, element);
        callback_pool_free((void *) element);

        /* execute callback */
        callback(parameter);

        UC_SDLR_TRACE("%s Decrementing callback counter", __PRETTY_FUNCTION__);

        /*  decrement element counter after executing the callback.
            otherwise further callbacks posted inside this callback could
            trigger notifications eventhough we are still processing the queue.

            when this function returns false, the counter is 0 and there are
            either 1 or 0 elements in the queue. if there is 1 element in
            the queue, it means the counter hasn't been incremented yet, and
            incrmenting it will return 1, which will trigger a notification.
        */
        count = aq_atomic_inc_int32((int32_t *) &arm_uc_queue_counter, -1);
    }

    return (count > 0);
}
