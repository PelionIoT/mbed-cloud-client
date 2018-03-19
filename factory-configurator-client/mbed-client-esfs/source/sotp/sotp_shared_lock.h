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



#ifndef __SOTP_SHARED_LOCK_H
#define __SOTP_SHARED_LOCK_H

#include <stdint.h>
#include "pal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SOTP_SHL_SUCCESS            = 0,
    SOTP_SHL_INVALID_ARG        = 1,
    SOTP_SHL_NULL_PTR           = 2,
    SOTP_SHL_NO_MEM             = 3,
    SOTP_SHL_PAL_ERR            = 4,
    SOTP_SHL_MISUSE             = 5,
    SOTP_SHL_ERROR_MAXVAL       = 0xFFFF
} sotp_sh_lock_result_e;

typedef uintptr_t sotp_shared_lock_t;

// Create a shared lock.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_create(sotp_shared_lock_t *sh_lock);

// Destroy a shared lock.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_destroy(sotp_shared_lock_t sh_lock);

// Lock a shared-lock in a shared manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_shared_lock(sotp_shared_lock_t sh_lock);

// Release a shared-lock in a shared manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_shared_release(sotp_shared_lock_t sh_lock);

// Lock a shared-lock in an exclusive manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_exclusive_lock(sotp_shared_lock_t sh_lock);

// Release a shared-lock in an exclusive manner.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_exclusive_release(sotp_shared_lock_t sh_lock);

// Promote a shared-lock from shared mode to exclusive mode.
// Parameters :
// sh_lock    - [OUT]  lock handle.
// Return     : SOTP_SHL_SUCCESS on success. Error code otherwise.
sotp_sh_lock_result_e sotp_sh_lock_promote(sotp_shared_lock_t sh_lock);


#ifdef __cplusplus
}
#endif

#endif
