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
#include "pal_Crypto.h"
#else
#include "mbedtls/md.h"
#endif

#if ARM_UC_FEATURE_MANIFEST_PUBKEY
#define ARM_UC_CU_SHA256 PAL_SHA256
arm_uc_error_t ARM_UC_verifyPkSignature(const arm_uc_buffer_t *ca, const arm_uc_buffer_t *hash,
                                        const arm_uc_buffer_t *sig)
{
    arm_uc_error_t err = {MFST_ERR_CERT_INVALID};
    palX509Handle_t x509Cert;
    if (PAL_SUCCESS == pal_x509Initiate(&x509Cert)) {
        err.code = MFST_ERR_CERT_INVALID;
        if (PAL_SUCCESS == pal_x509CertParse(x509Cert, ca->ptr, ca->size)) {
            // if (PAL_SUCCESS == pal_x509CertVerify(x509Cert, palX509Handle_t x509CertChain))
            // {
            err.code = MFST_ERR_INVALID_SIGNATURE;
            if (PAL_SUCCESS == pal_verifySignature(x509Cert, PAL_SHA256, hash->ptr, hash->size, sig->ptr, sig->size)) {
                err.code = MFST_ERR_NONE;
            }
            // }
        }
        pal_x509Free(&x509Cert);
    }
    return err;
}
#endif


arm_uc_error_t ARM_UC_cryptoHashSetup(arm_uc_mdHandle_t *hDigest, arm_uc_mdType_t mdType)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };
    if (hDigest) {
        palStatus_t rc = pal_mdInit(hDigest, mdType);
        if (rc == PAL_SUCCESS) {
            result.code = ARM_UC_CU_ERR_NONE;
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
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
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
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
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
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
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
        result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
        output->size = data_size;
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptFinish(arm_uc_cipherHandle_t *hCipher, arm_uc_buffer_t *output)
{
    pal_freeAes(&hCipher->aes_context);
    (void) output;
    return (arm_uc_error_t) {ARM_UC_CU_ERR_NONE};
}

arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key,
                                       arm_uc_buffer_t *input,
                                       arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    palStatus_t pal_st = pal_mdHmacSha256(key->ptr, key->size,
                                          input->ptr, input->size,
                                          output->ptr, &(output->size));
    if ((pal_st == PAL_SUCCESS) && (output->size == ARM_UC_SHA256_SIZE)) {
        result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
    }

    return result;
}

int8_t mbed_cloud_client_get_rot_128bit(uint8_t *key_buf, uint32_t length)
{
    int8_t rv = -1;
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;

#if (PAL_USE_HW_ROT)
    status = pal_plat_osGetRoTFromHW(key_buf, length);
#else
    uint16_t actual_size;

    sotp_result_e sotp_status = sotp_get(SOTP_TYPE_ROT, length, (uint32_t *)key_buf, &actual_size);
    if (SOTP_SUCCESS == sotp_status && actual_size == ARM_UC_ROT_SIZE) {
        status = PAL_SUCCESS;
    }
#endif

    if (status == PAL_SUCCESS) {
        rv = 0;
    } else {
        /* clear buffer on failure so we don't leak the rot */
        memset(key_buf, 0, length);
    }

    return rv;
}

#elif defined(ARM_UC_FEATURE_CRYPTO_MBEDTLS) && (ARM_UC_FEATURE_CRYPTO_MBEDTLS == 1)

#if ARM_UC_FEATURE_MANIFEST_PUBKEY

arm_uc_error_t ARM_UC_verifyPkSignature(const arm_uc_buffer_t *ca, const arm_uc_buffer_t *hash,
                                        const arm_uc_buffer_t *sig)
{
    arm_uc_error_t err = {MFST_ERR_NONE};
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int rc = mbedtls_x509_crt_parse_der(&crt, ca->ptr, ca->size);
    if (rc < 0) {
        err.code = MFST_ERR_CERT_INVALID;
    } else {
        rc = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, hash->ptr, hash->size, sig->ptr, sig->size);
        if (rc < 0) {
            err.code = MFST_ERR_INVALID_SIGNATURE;
        }
    }
    return err;
}
#endif

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
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
        }
    }

    return result;
}

arm_uc_error_t ARM_UC_cryptoHashUpdate(arm_uc_mdHandle_t *hDigest, arm_uc_buffer_t *input)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (hDigest && input) {
        int mbedtls_result = mbedtls_md_update(hDigest, input->ptr, input->size);

        if (mbedtls_result == 0) {
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
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
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };

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
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
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
        result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
        output->size = data_size;
    }
    return result;
}

arm_uc_error_t ARM_UC_cryptoDecryptFinish(arm_uc_cipherHandle_t *hCipher, arm_uc_buffer_t *output)
{
    (void) output;
    return (arm_uc_error_t) {ARM_UC_CU_ERR_NONE};
}

arm_uc_error_t ARM_UC_cryptoHMACSHA256(arm_uc_buffer_t *key,
                                       arm_uc_buffer_t *input,
                                       arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info != NULL) {
        int8_t rv = mbedtls_md_hmac(md_info,
                                    key->ptr, key->size,
                                    input->ptr, input->size,
                                    output->ptr);
        if (rv == 0) {
            output->size = ARM_UC_SHA256_SIZE;
            result = (arm_uc_error_t) { ARM_UC_CU_ERR_NONE };
        }
    }

    return result;
}

#endif

arm_uc_error_t ARM_UC_getDeviceKey256Bit(arm_uc_buffer_t *output)
{
    arm_uc_error_t result = (arm_uc_error_t) { ARM_UC_CU_ERR_INVALID_PARAMETER };

    if (output->size_max >= ARM_UC_DEVICE_KEY_SIZE) {
        int8_t rv = mbed_cloud_client_get_rot_128bit(output->ptr, output->size_max);
        if (rv == 0) {
            arm_uc_buffer_t input = {
                .size_max = ARM_UC_DEVICE_HMAC_KEY_SIZE,
                .size = ARM_UC_DEVICE_HMAC_KEY_SIZE,
                .ptr = (uint8_t *) &ARM_UC_DEVICE_HMAC_KEY
            };
            output->size = ARM_UC_ROT_SIZE;
#if defined(PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC) && \
    (PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC == 1)
            result = ARM_UC_cryptoHMACSHA256(&input, output, output);
#else
            result = ARM_UC_cryptoHMACSHA256(output, &input, output);
#endif
        }
    }

    if (result.code != ARM_UC_CU_ERR_NONE) {
        /* clear buffer on failure so we don't leak the rot */
        memset(output->ptr, 0, output->size_max);
    }

    return result;
}
