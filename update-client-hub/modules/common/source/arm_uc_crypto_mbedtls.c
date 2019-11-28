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

#if defined(ARM_UC_FEATURE_CRYPTO_MBEDTLS) && (ARM_UC_FEATURE_CRYPTO_MBEDTLS == 1)

arm_uc_error_t ARM_UC_cryptoHashSetup(arm_uc_mdHandle_t *hDigest, arm_uc_mdType_t mdType)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    const mbedtls_md_info_t *md_info = NULL;

    if (hDigest) {
        mbedtls_md_init(hDigest);
        md_info = mbedtls_md_info_from_type(mdType);
        int mbedtls_result = mbedtls_md_setup(hDigest, md_info, 0);
        mbedtls_result |= mbedtls_md_starts(hDigest);

        if (mbedtls_result == 0) {
            result = (arm_uc_error_t) { ERR_NONE };
        }
    }

    return result;
}

arm_uc_error_t ARM_UC_cryptoHashUpdate(arm_uc_mdHandle_t *hDigest, const arm_uc_buffer_t *input)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (hDigest && input) {
        int mbedtls_result = mbedtls_md_update(hDigest, input->ptr, input->size);

        if (mbedtls_result == 0) {
            result = (arm_uc_error_t) { ERR_NONE };
        }
    }

    return result;
}

arm_uc_error_t ARM_UC_cryptoHashFinish(arm_uc_mdHandle_t *hDigest, arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (hDigest && output && (output->size_max >= (unsigned)hDigest->md_info->size)) {
        int mbedtls_result = mbedtls_md_finish(hDigest, output->ptr);

        if (mbedtls_result == 0) {
            result = (arm_uc_error_t) { ERR_NONE };

            output->size = hDigest->md_info->size;
        }
    }

    // free memory
    mbedtls_md_free(hDigest);

    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptSetup(arm_uc_cipherHandle_t *hCipher, arm_uc_buffer_t *key, arm_uc_buffer_t *iv,
                                         int32_t aesKeySize)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (key && key->ptr && iv && iv->ptr) {
        int mbedtls_result = 1;

        switch (aesKeySize) {
            case 128:
            case 256: {
                memset(hCipher->aes_partial, 0, sizeof(hCipher->aes_partial));
                hCipher->aes_nc_off = 0;
                mbedtls_aes_init(&hCipher->aes_context);
                /* NOTE: From the mbedtls documentation:
                 * Due to the nature of CTR you should use the same key schedule for
                 * both encryption and decryption. So a context initialized with
                 * mbedtls_aes_setkey_enc() for both MBEDTLS_AES_ENCRYPT and MBEDTLS_AES_DECRYPT.
                 */
                mbedtls_result = mbedtls_aes_setkey_enc(&hCipher->aes_context, key->ptr, aesKeySize);
                hCipher->aes_iv = iv->ptr;
                break;
            }
            default:
                // mbedtls_result is still 1, this means the function returns Invalid Parameter
                break;
        }

        if (mbedtls_result == 0) {
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
    int mbedtls_result = mbedtls_aes_crypt_ctr(
                             &hCipher->aes_context,
                             data_size,
                             &hCipher->aes_nc_off,
                             hCipher->aes_iv,
                             hCipher->aes_partial,
                             input_ptr,
                             output->ptr

                         );
    if (mbedtls_result == 0) {
        result = (arm_uc_error_t) { ERR_NONE };
        output->size = data_size;
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptFinish(arm_uc_cipherHandle_t *hCipher, arm_uc_buffer_t *output)
{
    (void) output;
    return (arm_uc_error_t) {ERR_NONE};
}

#endif
