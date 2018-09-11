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
#include "update-client-control-center/arm_uc_pre_shared_key.h"

#if defined(ARM_UC_FEATURE_PSK_STORE_NVSTORE) && (ARM_UC_FEATURE_PSK_STORE_NVSTORE==1)


#include "CloudClientStorage.h"

#define DEFAULT_PSK_SIZE 128
#define DEFAULT_PSK_SIZE_IN_BYTES (128/8)

/* Pointer to the pre-shared-key. Module only supports 1 key at a time. */
static uint16_t arm_uc_psk_size = DEFAULT_PSK_SIZE;
static uint8_t pskbuffer[DEFAULT_PSK_SIZE_IN_BYTES] = { 0 };

/**
 * @brief Set pointer to pre-shared-key with the given size.
 *
 * @param key Pointer to pre-shared-key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_SetSecret(const uint8_t *key, uint16_t bits)
{
    // Do not support currently, you should provision to nvstore blob into image
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    return result;
}

/**
 * @brief Get pointer to pre-shared-key with the given size.
 *
 * @param key Pointer-pointer to the shared key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_GetSecret(const uint8_t **key, uint16_t bits)
{
    arm_uc_error_t retval = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (key && (bits == arm_uc_psk_size)) {
        size_t value_length = 0;
        memset(pskbuffer, 0, DEFAULT_PSK_SIZE_IN_BYTES);

        ccs_status_e ccs_status = get_config_parameter(UPDATE_PSK_SECRET,
                                                       pskbuffer,
                                                       arm_uc_psk_size,
                                                       &value_length);
        if (ccs_status == CCS_STATUS_KEY_DOESNT_EXIST) {
            retval.code = ARM_UC_DI_ERR_NOT_FOUND;
        }

        if (ccs_status == CCS_STATUS_SUCCESS) {
            retval.code = ERR_NONE;

            *key = pskbuffer;

        }
        /* set return value */
        retval = (arm_uc_error_t) { ERR_NONE };

    }

    return retval;
}

#elif defined(ARM_UC_FEATURE_PSK_STORE_RAW) && (ARM_UC_FEATURE_PSK_STORE_RAW==1)

// Below is runtime memory-based volatile solution without NVSTORE
/* Pointer to the pre-shared-key. Module only supports 1 key at a time. */
static const uint8_t *arm_uc_psk_key = NULL;
static uint16_t arm_uc_psk_size = 0;

/**
 * @brief Set pointer to pre-shared-key with the given size.
 *
 * @param key Pointer to pre-shared-key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_SetSecret(const uint8_t *key, uint16_t bits)
{
    arm_uc_psk_key = key;
    arm_uc_psk_size = bits;

    return (arm_uc_error_t) { ERR_NONE};
}

/**
 * @brief Get pointer to pre-shared-key with the given size.
 *
 * @param key Pointer-pointer to the shared key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_PreSharedKey_GetSecret(const uint8_t **key, uint16_t bits)
{
    arm_uc_error_t retval = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (key && (bits == arm_uc_psk_size)) {
        /* set return value */
        retval = (arm_uc_error_t) { ERR_NONE };

        /* assign PSK pointer */
        *key = arm_uc_psk_key;
    }

    return retval;
}

#endif /* ARM_UC_FEATURE_PSK_STORE_NVSTORE/RAW */
