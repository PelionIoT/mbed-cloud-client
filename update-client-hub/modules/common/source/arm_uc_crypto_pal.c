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
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_crypto.h"

#include <string.h>

#if defined(ARM_UC_FEATURE_CRYPTO_PAL) && (ARM_UC_FEATURE_CRYPTO_PAL == 1)
#include "pal.h"
#include "sotp.h"
#ifndef palMDHandle_t
#include "pal_plat_rot.h"
#else
#include "mbedtls/md.h"
#endif

arm_uc_error_t ARM_UC_cryptoHashSetup(arm_uc_mdHandle_t *hDigest, arm_uc_mdType_t mdType)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };
    if (hDigest) {
        palStatus_t rc = pal_mdInit(hDigest, mdType);
        if (rc == PAL_SUCCESS) {
            result.code = ERR_NONE;
        }
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoHashUpdate(arm_uc_mdHandle_t *hDigest, arm_uc_buffer_t *input)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };
    if (hDigest && input) {
        palStatus_t rc = pal_mdUpdate(*hDigest, input->ptr, input->size);
        if (rc == PAL_SUCCESS) {
            result = (arm_uc_error_t) { ERR_NONE };
        }
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoHashFinish(arm_uc_mdHandle_t *hDigest, arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    // TODO: validate buffer size? I guess we just hope for the best!
    if (hDigest && output && output->size_max >= 256 / 8) { // FIXME:PAL does not provide a method to extract this
        palStatus_t rc = pal_mdFinal(*hDigest, output->ptr);

        if (rc == PAL_SUCCESS) {
            result = (arm_uc_error_t) { ERR_NONE };
            output->size = 256 / 8; // FIXME:PAL does not provide a method to extract this
        }
    }
    if (hDigest) {
        palStatus_t rc = pal_mdFree(hDigest);
        if (rc != PAL_SUCCESS && result.error == ERR_NONE) {
            result.module = TWO_CC('P', 'A');
            result.error  = rc;
        }
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptSetup(arm_uc_cipherHandle_t *hCipher, arm_uc_buffer_t *key, arm_uc_buffer_t *iv,
                                         int32_t aesKeySize)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (key && key->ptr && iv && iv->ptr) {
        palStatus_t rc = 1;

        switch (aesKeySize) {
            case 128:
            case 256: {
                rc = pal_initAes(&hCipher->aes_context);
                /* NOTE: From the mbedtls documentation:
                 * Due to the nature of CTR you should use the same key schedule for
                 * both encryption and decryption. So a context initialized with
                 * mbedtls_aes_setkey_enc() for both MBEDTLS_AES_ENCRYPT and MBEDTLS_AES_DECRYPT.
                 */
                if (rc == PAL_SUCCESS) {
                    rc = pal_setAesKey(hCipher->aes_context, key->ptr, aesKeySize, PAL_KEY_TARGET_ENCRYPTION);
                }
                hCipher->aes_iv = iv->ptr;
                break;
            }
            default:
                // rc is still 1, this means the function returns Invalid Parameter
                break;
        }

        if (rc == PAL_SUCCESS) {
            result = (arm_uc_error_t) { ERR_NONE };
        }
    }

    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptUpdate(arm_uc_cipherHandle_t *hCipher, const uint8_t *input_ptr, uint32_t input_size,
                                          arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };
    size_t data_size = input_size < output->size_max ? input_size : output->size_max;
    output->size = 0;
    palStatus_t rc = pal_aesCTR(
                         hCipher->aes_context,
                         input_ptr,
                         output->ptr,
                         data_size,
                         hCipher->aes_iv
                     );
    if (rc == PAL_SUCCESS) {
        result = (arm_uc_error_t) { ERR_NONE };
        output->size = data_size;
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptFinish(arm_uc_cipherHandle_t *hCipher, arm_uc_buffer_t *output)
{
    pal_freeAes(&hCipher->aes_context);
    (void) output;
    return (arm_uc_error_t) {ERR_NONE};
}

arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key,
                                       arm_uc_buffer_t *input,
                                       arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };


    size_t outPutSize = 0;
    palStatus_t pal_st = pal_mdHmacSha256(key->ptr, key->size,
                                          input->ptr, input->size,
                                          output->ptr, &outPutSize);

    output->size = (uint32_t) outPutSize;  // we lose here some bits in 64 bit systems,
                                           // but as long as we are under u32 MAX size it does not matter
                                           // and as input size is read from u32 this should be safe


    if ((pal_st == PAL_SUCCESS) && (output->size == ARM_UC_SHA256_SIZE)) {
        result = (arm_uc_error_t) { ERR_NONE };
    }

    return result;
}

int8_t mbed_cloud_client_get_rot_128bit(uint8_t *key_buf, uint32_t length)
{
    int8_t rv = -1;
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;

    if (length < ARM_UC_ROT_SIZE) {
           return -1;
    }
    //Get RoT
    status = pal_plat_osGetRoT(key_buf, ARM_UC_ROT_SIZE);

    if (status == PAL_SUCCESS) {
        rv = 0;
    } else {
        /* clear buffer on failure so we don't leak the rot */
        memset(key_buf, 0, length);
    }

    return rv;
}

#endif
