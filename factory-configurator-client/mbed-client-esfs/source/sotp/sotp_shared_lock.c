/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



// ----------------------------------------------------------- Includes -----------------------------------------------------------


#include "sotp_shared_lock.h"
#include "mbed-trace/mbed_trace.h"
#include "pal.h"
#include <string.h>
#include <stdlib.h>

// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define TRACE_GROUP                     "sotp"

#define PR_ERR tr_err
#define PR_INFO tr_info
#define PR_DEBUG tr_debug

#define MEDITATE_TIME_MS 100

#ifdef SOTP_THREAD_SAFE
typedef struct {
    int32_t      ctr;
    // Use semaphore and not mutex, as mutexes don't behave well when trying
    // to delete them while taken (which may happen in our tests).
    palSemaphoreID_t sem;
} shared_lock_priv_t;
#endif
// -------------------------------------------------- Local Functions Declaration ----------------------------------------------------


// -------------------------------------------------- Functions Implementation ----------------------------------------------------
// Create a shared lock.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_create(sotp_shared_lock_t *sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv;
    lock_priv = (shared_lock_priv_t *) malloc(sizeof(shared_lock_priv_t));

    if (!lock_priv) {
        PR_ERR("sotp_sh_lock_create: Out of memory\n");
        return SOTP_SHL_NO_MEM;
    }

    lock_priv->ctr = 0;

    if (pal_osSemaphoreCreate(1, &(lock_priv->sem)) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_shared_lock: PAL error\n");
        free(lock_priv);
        return SOTP_SHL_PAL_ERR;
    }

    *sh_lock = (sotp_shared_lock_t) lock_priv;
#endif
    return SOTP_SHL_SUCCESS;
}

// Destroy a shared lock.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_destroy(sotp_shared_lock_t sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv = (shared_lock_priv_t *) sh_lock;

    if (!sh_lock) {
        PR_ERR("sotp_sh_lock_destroy: NULL parameter\n");
        return SOTP_SHL_NULL_PTR;
    }

    // Semaphore may be taken, so deleting it would fail. Try releasing (without checking return code).
    pal_osSemaphoreRelease(lock_priv->sem);

    if (pal_osSemaphoreDelete(&(lock_priv->sem)) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_destroy: PAL error\n");
        return SOTP_SHL_PAL_ERR;
    }

    free(lock_priv);
#endif
    return SOTP_SHL_SUCCESS;
}

// Lock a shared-lock in a shared manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_shared_lock(sotp_shared_lock_t sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv = (shared_lock_priv_t *) sh_lock;
    int32_t ctrs;

    if (!sh_lock)
        return SOTP_SHL_NULL_PTR;

    if (pal_osSemaphoreWait(lock_priv->sem, PAL_RTOS_WAIT_FOREVER, &ctrs) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_shared_lock: PAL error\n");
        return SOTP_SHL_PAL_ERR;
    }

    pal_osAtomicIncrement(&lock_priv->ctr, 1);

    if (pal_osSemaphoreRelease(lock_priv->sem) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_shared_lock: PAL error\n");
        return SOTP_SHL_PAL_ERR;
    }
#endif
    return SOTP_SHL_SUCCESS;
}

// Release a shared-lock in a shared manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_shared_release(sotp_shared_lock_t sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv = (shared_lock_priv_t *) sh_lock;
    int32_t val;

    if (!sh_lock) {
        PR_ERR("sotp_sh_lock_shared_release: NULL parameter\n");
        return SOTP_SHL_NULL_PTR;
    }

    val = pal_osAtomicIncrement(&lock_priv->ctr, -1);
    if (val < 0) {
        PR_ERR("sotp_sh_lock_shared_release: Misuse (released more than locked)\n");
        return SOTP_SHL_MISUSE;
    }

#endif
    return SOTP_SHL_SUCCESS;
}

// Lock a shared-lock in an exclusive manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_exclusive_lock(sotp_shared_lock_t sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv = (shared_lock_priv_t *) sh_lock;
    int32_t ctrs;

    if (!sh_lock) {
        PR_ERR("sotp_sh_lock_exclusive_lock: NULL parameter\n");
        return SOTP_SHL_NULL_PTR;
    }

    if (pal_osSemaphoreWait(lock_priv->sem, PAL_RTOS_WAIT_FOREVER, &ctrs) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_exclusive_lock: PAL error\n");
        return SOTP_SHL_PAL_ERR;
    }

    while(lock_priv->ctr)
        pal_osDelay(MEDITATE_TIME_MS);

#endif
    return SOTP_SHL_SUCCESS;
}

// Release a shared-lock in an exclusive manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_exclusive_release(sotp_shared_lock_t sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv = (shared_lock_priv_t *) sh_lock;

    if (!sh_lock) {
        PR_ERR("sotp_sh_lock_exclusive_release: NULL parameter\n");
        return SOTP_SHL_NULL_PTR;
    }

    if (pal_osSemaphoreRelease(lock_priv->sem) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_exclusive_release: PAL error\n");
        return SOTP_SHL_PAL_ERR;
    }

#endif
    return SOTP_SHL_SUCCESS;
}

// Promote a shared-lock from shared mode to exclusive mode.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_promote(sotp_shared_lock_t sh_lock)
{
#ifdef SOTP_THREAD_SAFE
    shared_lock_priv_t *lock_priv = (shared_lock_priv_t *) sh_lock;
    int32_t ctrs;

    if (!sh_lock) {
        PR_ERR("sotp_sh_lock_promote: NULL parameter\n");
        return SOTP_SHL_NULL_PTR;
    }

    if (pal_osSemaphoreWait(lock_priv->sem, PAL_RTOS_WAIT_FOREVER, &ctrs) != PAL_SUCCESS) {
        PR_ERR("sotp_sh_lock_promote: PAL error\n");
        return SOTP_SHL_PAL_ERR;
    }

    while(lock_priv->ctr > 1)
        pal_osDelay(MEDITATE_TIME_MS);

    if (lock_priv->ctr != 1) {
        PR_ERR("sotp_sh_lock_promote: Misuse (promoted when not locked)\n");
        return SOTP_SHL_MISUSE;
    }

    pal_osAtomicIncrement(&lock_priv->ctr, -1);

#endif
    return SOTP_SHL_SUCCESS;
}

