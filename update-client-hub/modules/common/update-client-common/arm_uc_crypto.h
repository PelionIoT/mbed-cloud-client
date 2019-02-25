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

#ifndef ARM_UPDATE_CRYPTO_H
#define ARM_UPDATE_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include "arm_uc_error.h"
#include "arm_uc_types.h"
#include "arm_uc_config.h"

#if defined(ARM_UC_FEATURE_CRYPTO_PAL) && (ARM_UC_FEATURE_CRYPTO_PAL == 1)
#include "pal.h"
#ifndef palMDHandle_t
#include "pal_Crypto.h"
#endif

typedef palMDHandle_t arm_uc_mdHandle_t;
typedef palMDType_t arm_uc_mdType_t;
typedef struct arm_uc_cipherHandle_t {
    palAesHandle_t aes_context;
    uint8_t *aes_iv;
} arm_uc_cipherHandle_t;

#define ARM_UC_CU_SHA256 PAL_SHA256

#elif defined(ARM_UC_FEATURE_CRYPTO_MBEDTLS) && (ARM_UC_FEATURE_CRYPTO_MBEDTLS == 1) // ARM_UC_FEATURE_CRYPTO_PAL

#include "mbedtls/md_internal.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#if ARM_UC_FEATURE_MANIFEST_PUBKEY
#include "mbedtls/x509_crt.h"
#endif
#include "mbedtls/cipher.h"
typedef mbedtls_md_context_t arm_uc_mdHandle_t;
typedef mbedtls_md_type_t arm_uc_mdType_t;
typedef struct arm_uc_cipherHandle_t {
    mbedtls_aes_context aes_context;
    uint8_t  aes_partial[MBEDTLS_MAX_BLOCK_LENGTH];
    uint8_t *aes_iv;
    size_t   aes_nc_off;
} arm_uc_cipherHandle_t;

#define ARM_UC_CU_SHA256 MBEDTLS_MD_SHA256

#else // ARM_UC_FEATURE_CRYPTO_PAL

#error Either ARM_UC_FEATURE_CRYPTO_PAL or ARM_UC_FEATURE_CRYPTO_MBEDTLS must be defined.

#endif // ARM_UC_FEATURE_CRYPTO_PAL

arm_uc_error_t ARM_UC_cryptoHashSetup(arm_uc_mdHandle_t *h, arm_uc_mdType_t mdType);
arm_uc_error_t ARM_UC_cryptoHashUpdate(arm_uc_mdHandle_t *h, arm_uc_buffer_t *input);
arm_uc_error_t ARM_UC_cryptoHashFinish(arm_uc_mdHandle_t *h, arm_uc_buffer_t *output);
arm_uc_error_t ARM_UC_cryptoDecryptSetup(arm_uc_cipherHandle_t *h, arm_uc_buffer_t *key, arm_uc_buffer_t *iv,
                                         int32_t bits);
arm_uc_error_t ARM_UC_cryptoDecryptUpdate(arm_uc_cipherHandle_t *h, const uint8_t *input_ptr, uint32_t input_size,
                                          arm_uc_buffer_t *output);
arm_uc_error_t ARM_UC_cryptoDecryptFinish(arm_uc_cipherHandle_t *h, arm_uc_buffer_t *output);

/**
 * @brief Calculate HAMC-SHA256
 *
 * @param key    buffer struct containing the hmac key
 * @param input  buffer struct containing the input data
 * @param output buffer struct to cotain output HMAC, it is safe to use the same buffer
 *               as input to save memory. The size member of the struct will be set on success.
 *
 * @return ERR_NONE on success, error code on failure.
 */
arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key, arm_uc_buffer_t *input, arm_uc_buffer_t *output);

#ifdef __cplusplus
}
#endif

#endif // ARM_UPDATE_CRYPTO_H
