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

#ifndef ARM_UC_PRE_SHARED_KEY_H
#define ARM_UC_PRE_SHARED_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "update-client-common/arm_uc_common.h"

#include <stdint.h>

typedef enum {
    ARM_UC_PSK_GET_DONE,
    ARM_UC_PSK_GET_ERROR
} arm_uc_psk_event_t;

/**
 * @brief Register event handler.
 *
 * @param callback Event handler to signal result.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_Initialize(void (*callback)(uint32_t));

/**
 * @brief Set pointer to pre-shared-key with the given size.
 *
 * @param key Pointer to pre-shared-key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_SetKey(const uint8_t* key, uint16_t bits);

/**
 * @brief Get pointer to pre-shared-key with the given size.
 * @details This call will generate an event upon completion because the key
 *          pointing to might have to be loaded from asynchronous storage.
 *
 *          If the event is ARM_UC_PSK_GET_DONE, key will point to a valid
 *          pre-shared-key, which memory is handled internally.
 *
 * @param key Pointer-pointer to the shared key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_GetKey(const uint8_t** key, uint16_t bits);

#ifdef __cplusplus
}
#endif

#endif // ARM_UC_PRE_SHARED_KEY_H
