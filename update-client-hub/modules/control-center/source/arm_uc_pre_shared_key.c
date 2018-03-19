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

#include "update-client-control-center/arm_uc_pre_shared_key.h"

/* Pointer to the pre-shared-key. Module only supports 1 key at a time. */
static const uint8_t* arm_uc_psk_key = NULL;
static uint16_t arm_uc_psk_size = 0;

/**
 * @brief Register event handler.
 *
 * @param callback Event handler to signal result.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_Initialize(void (*callback)(uint32_t))
{
    return (arm_uc_error_t){ ERR_NONE};
}

/**
 * @brief Set pointer to pre-shared-key with the given size.
 *
 * @param key Pointer to pre-shared-key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_SetKey(const uint8_t* key, uint16_t bits)
{
    arm_uc_psk_key = key;
    arm_uc_psk_size = bits;

    return (arm_uc_error_t){ ERR_NONE};
}

/**
 * @brief Get pointer to pre-shared-key with the given size.
 *
 * @param key Pointer-pointer to the shared key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_GetKey(const uint8_t** key, uint16_t bits)
{
    arm_uc_error_t retval = (arm_uc_error_t){ ERR_INVALID_PARAMETER };

    if (key && (bits == arm_uc_psk_size))
    {
        /* set return value */
        retval = (arm_uc_error_t){ ERR_NONE };

        /* assign PSK pointer */
        *key = arm_uc_psk_key;
    }

    return retval;
}
