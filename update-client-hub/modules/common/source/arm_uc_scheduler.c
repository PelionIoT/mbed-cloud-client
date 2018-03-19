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

#include "update-client-common/arm_uc_common.h"

#include "pal.h"

static struct atomic_queue arm_uc_queue = { 0 };
static void (*arm_uc_notificationHandler)(void) = NULL;
static int32_t arm_uc_queue_counter = 0;

void ARM_UC_AddNotificationHandler(void (*handler)(void))
{
    arm_uc_notificationHandler = handler;
}

bool ARM_UC_PostCallback(arm_uc_callback_t* _storage,
                         void (*_callback)(uint32_t),
                         uint32_t _parameter)
{
    bool success = false;

    if (_storage)
    {
        /* push struct to atomic queue */
        int result = aq_push_tail(&arm_uc_queue, (void *) _storage);

        if (result == ATOMIC_QUEUE_SUCCESS)
        {
            /* populate callback struct */
            /* WARNING: This is a dangerous pattern. The atomic queue should own
               all memory referenced by the storage element.
               
               This only works when ARM_UC_ProcessQueue and 
               ARM_UC_ProcessSingleCallback are guaranteed to be called only from
               lower priority than ARM_UC_PostCallback. In the update client,
               this is expected to be true, but it cannot be assumed to be true in
               all environments. This requires further rework, possibly including
               a critical section in ARM_UC_PostCallback, or a "taken" flag on the
               callback storage.
             */               
            _storage->callback = _callback;
            _storage->parameter = _parameter;

            success = true;

            /*  The queue is processed by removing an element first and then
                decrementing the queue counter. This continues until the counter
                reaches 0 (process single callback) or the queue is empty
                (process queue).

                If the counter is zero at this point, there is one element in
                the queue, and incrementing the counter will return 1 and which
                triggers a notification.

                If the queue is empty at this point, the counter is -1 and
                incrementing the counter will return 0. This does not trigger
                a notification, which is correct since the queue is empty.
            */
            int32_t count = pal_osAtomicIncrement(&arm_uc_queue_counter, 1);

            /* if notification handler is set, check if this is the first
            insertion
            */
            if ((arm_uc_notificationHandler) && (count == 1))
            {
                /* disable: UC_COMM_TRACE("notify nanostack scheduler"); */
                arm_uc_notificationHandler();
            }
        }
/* disable when not debugging */
#if 0
        else
        {
            UC_COMM_ERR_MSG("failed to add callback to queue: %p %p",
                            _storage,
                            _callback);
        }
#endif
    }

    return success;
}

void ARM_UC_ProcessQueue(void)
{
    arm_uc_callback_t* element = (arm_uc_callback_t*) aq_pop_head(&arm_uc_queue);

    while (element != NULL)
    {
        /* execute callback */
        element->callback(element->parameter);

        /*  decrement element counter after executing the callback.
            otherwise further callbacks posted inside this callback could
            trigger notifications eventhough we are still processing the queue.
        */
        pal_osAtomicIncrement(&arm_uc_queue_counter, -1);

        /* get next element */
        element = (arm_uc_callback_t*) aq_pop_head(&arm_uc_queue);
    }
}

bool ARM_UC_ProcessSingleCallback(void)
{
    /* elements in queue */
    int32_t count = 0;

    /* get first element */
    arm_uc_callback_t* element = (arm_uc_callback_t*) aq_pop_head(&arm_uc_queue);

    if (element != NULL)
    {
        /* execute callback */
        element->callback(element->parameter);

        /*  decrement element counter after executing the callback.
            otherwise further callbacks posted inside this callback could
            trigger notifications eventhough we are still processing the queue.

            when this function returns false, the counter is 0 and there are
            either 1 or 0 elements in the queue. if there is 1 element in
            the queue, it means the counter hasn't been incremented yet, and
            incrmenting it will return 1, which will trigger a notification.
        */
        count = pal_osAtomicIncrement(&arm_uc_queue_counter, -1);
    }

    return (count > 0);
}
