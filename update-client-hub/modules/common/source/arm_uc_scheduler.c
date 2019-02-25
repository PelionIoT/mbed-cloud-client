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
static volatile uintptr_t callbacks_pending = 0;

int32_t ARM_UC_SchedulerGetQueuedCount(void)
{
    return aq_count(&arm_uc_queue);
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

/* Single element used for queuing errors */
static arm_uc_callback_t plugin_error_callback = {0};
static volatile uintptr_t plugin_error_pending = 0;

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
    memset(&plugin_error_callback, 0, sizeof(arm_uc_callback_t));
    callbacks_pending = 0;
    plugin_error_pending = 0;
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

bool ARM_UC_PostCallbackCtx(arm_uc_callback_t *_storage,
                            void *_ctx,
                            arm_uc_context_callback_t _callback,
                            uintptr_t _parameter)
{
    bool success = true;
    UC_SDLR_TRACE("%s Scheduling %p(%lu) with %p (context %p)", __PRETTY_FUNCTION__, _callback, _parameter, _storage, _ctx);

    if (_callback == NULL || _ctx == NULL) {
        return false;
    }

    if (_storage) {
        int result = aq_element_take((void *) _storage, _ctx);
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
                int result = aq_element_take((void *) _storage, ATOMIC_QUEUE_NO_CONTEXT);
                if (result == ATOMIC_QUEUE_SUCCESS) {
                    _parameter = ARM_UC_EQ_ERR_POOL_EXHAUSTED;
                    _callback = (arm_uc_context_callback_t)scheduler_error_cb;
                } else {
                    _storage = NULL;
                }
            }
        } else {
            /* This thread is guaranteed to exclusively own _storage here */
            aq_initialize_element((void *) _storage);
            int result = aq_element_take((void *) _storage, _ctx);
            if (result != ATOMIC_QUEUE_SUCCESS) {
                success = false;
                /* This should be impossible */
                UC_SDLR_ERR_MSG("Failed to take an allocated a callback block... this should be impossible...");
                if (scheduler_error_cb) {
                    _storage = &callback_failed_take_error_callback;
                    int result = aq_element_take((void *) _storage, ATOMIC_QUEUE_NO_CONTEXT);
                    if (result == ATOMIC_QUEUE_SUCCESS) {
                        _parameter = ARM_UC_EQ_ERR_FAILED_TAKE;
                        _callback = (arm_uc_context_callback_t)scheduler_error_cb;
                    } else {
                        _storage = NULL;
                    }
                }
            }
        }
    }
    if (_storage) {
        /* populate callback struct */
        _storage->callback = (void*)_callback;
        _storage->parameter = _parameter;

        UC_SDLR_TRACE("%s Queueing %p(%lu) in %p", __PRETTY_FUNCTION__, _callback, _parameter, _storage);

        /* push struct to atomic queue */
        int result = aq_push_tail(&arm_uc_queue, (void *) _storage);

        if (result == ATOMIC_QUEUE_SUCCESS) {
            UC_SDLR_TRACE("%s Scheduling success!", __PRETTY_FUNCTION__);

            /* if notification handler is set, check if this is the first
             * insertion.
             * Try to set callbacks_pending to 1.
             * Fail if already 1 (there are other callbacks pending)
             * If successful, notify.
             */
            if (arm_uc_notificationHandler) {
                while (callbacks_pending == 0 && arm_uc_queue.tail != NULL) {
                    // Remove volatile qualifier from callbacks_pending
                    int cas_result = aq_atomic_cas_uintptr((uintptr_t *)&callbacks_pending, 0, 1);
                    if (cas_result) {
                        UC_SDLR_TRACE("%s Invoking notify!", __PRETTY_FUNCTION__);

                        /* disable: UC_SDLR_TRACE("notify nanostack scheduler"); */
                        arm_uc_notificationHandler();
                    }
                }
            }
        } else {
            success = false;
        }
    }

    return success;
}

bool ARM_UC_PostCallback(arm_uc_callback_t *_storage,
                         arm_uc_no_context_callback_t _callback,
                         uintptr_t _parameter)
{
    return ARM_UC_PostCallbackCtx(_storage, ATOMIC_QUEUE_NO_CONTEXT, (arm_uc_context_callback_t)_callback, _parameter);
}

bool ARM_UC_PostErrorCallbackCtx(void *_ctx, arm_uc_context_callback_t _callback, uintptr_t _parameter)
{
    UC_SDLR_TRACE("%s Scheduling error callback %p with parameter %lu and context %p", __PRETTY_FUNCTION__, _callback, _parameter, _ctx);

    if (_callback == NULL || _ctx == NULL) {
        return false;
    }

    /* Take ownership of error callback */
    int result = aq_element_take((void *)&plugin_error_callback, _ctx);
    if (result != ATOMIC_QUEUE_SUCCESS) {
        UC_SDLR_ERR_MSG("ARM_UC_PostErrorCallback failed to acquire lock on error callback");
        return false;
    }

    /* populate callback struct */
    plugin_error_callback.callback = (void*)_callback;
    plugin_error_callback.parameter = _parameter;

    plugin_error_pending = 1;
    return true;
}

/**
 * @brief Clear the callbacks_pending flag.
 * @details This function attempts to clear the callbacks_pending flag. This
 * operation can fail if:
 * * the flag has already been cleared
 * * the operation is interrupted
 * * the queue is not empty
 *
 * The return from this function indicates whether or not the scheduler should
 * continue processing callbacks. This is used to prevent duplicate
 * notifications. This could be a simple flag, but that would introduce several
 * race conditions. By using atomic Compare And Swap, we are able to detect and
 * correct those race conditions.
 *
 * Operation:
 * Case 1
 * If the callbacks_pending flag is clear AND the queue is empty, there is
 * nothing to do and the scheduler should stop processing callbacks.
 *
 * Case 2
 * If the callbacks_pending flag is set AND the queue is not empty, there is
 * nothing to do and the scheduler should continue processing callbacks.
 *
 * Case 3
 * If the callbacks_pending flag is clear AND the queue is not empty, then the
 * callbacks pending flag must be set to 1. If this operation is successful,
 * then the scheduler should continue processing callbacks. If the CAS fails,
 * then the scheduler must perform all checks and try again.
 *
 * Case 4
 * If the callbacks_pending flag is set AND the queue is empty, then the
 * callbacks_pending flag must be cleared. Atomic CAS opens an atomic context,
 * checks that the callbacks_pending flag is still set, then sets it to 0.
 * Atomic CAS will fail if either callbacks_pending is 0 OR if the CAS is
 * interrupted by another atomic operation. If the CAS succeeds and flag is
 * cleared then the scheduler must check if the queue is empty, since a new post
 * could have happened after callbacks_pending was stored to cbp_local. If the
 * CAS fails, then the scheduler must perform all checks and try again.
 *
 * @return false if the scheduler should stop processing callbacks or true if
 *         the scheduler should continue processing callbacks.
 */
static bool try_clear_callbacks_pending() {
    bool run_again = true;
    bool cleared_flag = false;
    while (true) {
        /* Preserve local copies of callbacks_pending and queue_empty */
        uintptr_t cbp_local = callbacks_pending;
        bool queue_empty = arm_uc_queue.tail == NULL;
        /* Case 1 */
        /* Flag clear, no elements queued. Nothing to do */
        if (!cbp_local && queue_empty) {
            run_again = false;
            break;
        }
        /* Case 2 */
        /* Flag is set and elements are queued. Nothing to do */
        if (cbp_local && !queue_empty) {
            /* Do not indicate a "run again" condition if the flag was
             * previously cleared
             */
            run_again = !cleared_flag;
            break;
        }
        /* Case 3 */
        /* Flag not set, elements queued. Set flag. */
        if (!cbp_local && !queue_empty) {
            int cas_result = aq_atomic_cas_uintptr((uintptr_t*)&callbacks_pending, cbp_local, 1);
            /* on success, exit and continue scheduling */
            if (cas_result) {
                run_again = true;
                break;
            }
        }
        /* Case 4 */
        /* Flag set, no elements queued. Clear flag */
        if (cbp_local && queue_empty) {
            int cas_result = aq_atomic_cas_uintptr((uintptr_t*)&callbacks_pending, cbp_local, 0);
            if (cas_result) {
                /* If the flag returns to true, then Case 2 should not set
                 * run_again, since this would cause a duplicate notification.
                 */
                cleared_flag = true;
            }
            /* If the result is success, then the scheduler must check for
             * (!cbp_local && !queue_empty). If the result is failure, then the
             * scheduler must try again.
             */
        }
    }
    return run_again;
}

void ARM_UC_ProcessQueue(void)
{
    arm_uc_callback_t *element = NULL;

    while (true) {
        element = NULL;
        /* Always consider the error callback first */
        if (plugin_error_pending) {
            /* Clear the read lock */
            plugin_error_pending = 0;
            element = &plugin_error_callback;
        }
        /* If the error callback isn't taken, get an element from the queue */
        else if (callbacks_pending){
            element = (arm_uc_callback_t *) aq_pop_head(&arm_uc_queue);
        }
        /* If the queue is empty */
        if (element == NULL) {
            /* Try to shut down queue processing */
            if (! try_clear_callbacks_pending()) {
                break;
            }
        }

        UC_SDLR_TRACE("%s Invoking %p(%lu)", __PRETTY_FUNCTION__, element->callback, element->parameter);
        /* Store the callback locally */
        void *callback = element->callback;
        /* Store the parameter locally */
        uint32_t parameter = element->parameter;

        /* Release the lock on the element */
        UC_SDLR_TRACE("%s Releasing %p", __PRETTY_FUNCTION__, element);
        void *ctx;
        aq_element_release((void *) element, &ctx);
        /* Free the element if it was pool allocated */
        UC_SDLR_TRACE("%s Freeing %p", __PRETTY_FUNCTION__, element);
        callback_pool_free((void *) element);

        /* execute callback */
        if (ctx == ATOMIC_QUEUE_NO_CONTEXT) {
            ((arm_uc_no_context_callback_t)callback)(parameter);
        } else {
            ((arm_uc_context_callback_t)callback)(ctx, parameter);
        }
    }
}

bool ARM_UC_ProcessSingleCallback(void)
{
    bool call_again = true;
    /* always check the error callback first */
    arm_uc_callback_t *element = NULL;
    /* Always consider the error callback first */
    if (plugin_error_pending) {
        /* Clear the read lock */
        plugin_error_pending = 0;
        element = &plugin_error_callback;
    }
    /* If the error callback isn't taken, get an element from the queue */
    else {
        element = (arm_uc_callback_t *) aq_pop_head(&arm_uc_queue);
        /* If the queue is empty */
        if (element == NULL) {
            /* Try to shut down queue processing */
            call_again = try_clear_callbacks_pending();
        }
    }

    if (element != NULL) {
        UC_SDLR_TRACE("%s Invoking %p(%lu)", __PRETTY_FUNCTION__, element->callback, element->parameter);
        /* Store the callback locally */
        void *callback =  element->callback;
        /* Store the parameter locally */
        uintptr_t parameter = element->parameter;
        /* Release the lock on the element */
        UC_SDLR_TRACE("%s Releasing %p", __PRETTY_FUNCTION__, element);
        void *ctx;
        aq_element_release((void *) element, &ctx);
        /* Free the element if it was pool allocated */
        UC_SDLR_TRACE("%s Freeing %p", __PRETTY_FUNCTION__, element);
        callback_pool_free((void *) element);

        /* execute callback */
        if (ctx == ATOMIC_QUEUE_NO_CONTEXT) {
            ((arm_uc_no_context_callback_t)callback)(parameter);
        } else {
            ((arm_uc_context_callback_t)callback)(ctx, parameter);
        }

        /* Try to shut down queue processing */
        call_again = try_clear_callbacks_pending();
    }

    return call_again || plugin_error_pending;
}
