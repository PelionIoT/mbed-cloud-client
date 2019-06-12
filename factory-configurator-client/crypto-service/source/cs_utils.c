// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
#include <stdio.h>
#include "pv_log.h"
#include "cs_der_keys_and_csrs.h"
#include "cs_der_certs.h"
#include "pal.h"
#include "pv_error_handling.h"
#include "key_slot_allocator.h"

kcm_status_e cs_error_handler(palStatus_t pal_status)
{
    switch (pal_status) {
        case PAL_SUCCESS:
            return KCM_STATUS_SUCCESS;
        case PAL_ERR_NOT_SUPPORTED_CURVE:
            return KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE;
        case PAL_ERR_INVALID_ARGUMENT:
            return KCM_STATUS_INVALID_PARAMETER;
        case PAL_ERR_CREATION_FAILED:
            return KCM_STATUS_OUT_OF_MEMORY;
        case PAL_ERR_CERT_PARSING_FAILED:
            return KCM_CRYPTO_STATUS_PARSING_DER_CERT;
        case PAL_ERR_X509_BADCERT_EXPIRED:
            return KCM_CRYPTO_STATUS_CERT_EXPIRED;
        case PAL_ERR_X509_BADCERT_FUTURE:
            return KCM_CRYPTO_STATUS_CERT_FUTURE;
        case PAL_ERR_X509_BADCERT_BAD_MD:
            return KCM_CRYPTO_STATUS_CERT_MD_ALG;
        case PAL_ERR_X509_BADCERT_BAD_PK:
            return KCM_CRYPTO_STATUS_CERT_PUB_KEY_TYPE;
        case PAL_ERR_X509_BADCERT_NOT_TRUSTED:
            return KCM_CRYPTO_STATUS_CERT_NOT_TRUSTED;
        case PAL_ERR_X509_BADCERT_BAD_KEY:
            return KCM_CRYPTO_STATUS_CERT_PUB_KEY;
        case PAL_ERR_PARSING_PUBLIC_KEY:
            return KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY;
        case PAL_ERR_PARSING_PRIVATE_KEY:
            return KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY;
        case PAL_ERR_PRIVATE_KEY_VARIFICATION_FAILED:
            return KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED;
        case PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED:
             return KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED;
        case PAL_ERR_PK_UNKNOWN_PK_ALG:
            return KCM_CRYPTO_STATUS_PK_UNKNOWN_PK_ALG;
        case PAL_ERR_PK_KEY_INVALID_FORMAT:
            return KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT;
        case PAL_ERR_PK_INVALID_PUBKEY_AND_ASN1_LEN_MISMATCH:
            return KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY;
        case PAL_ERR_ECP_INVALID_KEY:
            return KCM_CRYPTO_STATUS_ECP_INVALID_KEY;
        case  PAL_ERR_PK_KEY_INVALID_VERSION:
            return KCM_CRYPTO_STATUS_PK_KEY_INVALID_VERSION;
        case PAL_ERR_PK_PASSWORD_REQUIRED:
            return KCM_CRYPTO_STATUS_PK_PASSWORD_REQUIRED;
        case PAL_ERR_NO_MEMORY:
            return KCM_STATUS_OUT_OF_MEMORY;
        case PAL_ERR_BUFFER_TOO_SMALL:
            return KCM_STATUS_INSUFFICIENT_BUFFER;
        case PAL_ERR_INVALID_X509_ATTR:
            return KCM_CRYPTO_STATUS_INVALID_X509_ATTR;
        case PAL_ERR_PK_SIG_VERIFY_FAILED:
        case PAL_ERR_FAILED_TO_VERIFY_SIGNATURE:
            return KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED;
        case PAL_ERR_FAILED_TO_COPY_KEYPAIR:
            return KCM_CRYPTO_STATUS_ECP_INVALID_KEY;
        case PAL_ERR_FAILED_TO_COPY_GROUP:
            return KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE;
        case PAL_ERR_INVALID_MD_TYPE:
            return KCM_CRYPTO_STATUS_INVALID_MD_TYPE;
        case PAL_ERR_FAILED_TO_WRITE_SIGNATURE:
            return KCM_CRYPTO_STATUS_FAILED_TO_WRITE_SIGNATURE;
        case PAL_ERR_FAILED_TO_WRITE_PRIVATE_KEY:
            return KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PRIVATE_KEY;
        case PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY:
            return KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PUBLIC_KEY;
        case PAL_ERR_CSR_WRITE_DER_FAILED:
            return KCM_CRYPTO_STATUS_FAILED_TO_WRITE_CSR;
        case PAL_ERR_X509_UNKNOWN_OID:
            return KCM_CRYPTO_STATUS_INVALID_OID;
        case PAL_ERR_X509_INVALID_NAME:
            return KCM_CRYPTO_STATUS_INVALID_NAME_FORMAT;
        case PAL_ERR_SET_EXTENSION_FAILED:
            return KCM_CRYPTO_STATUS_SET_EXTENSION_FAILED;
        default:
           return  KCM_STATUS_ERROR;
    }
}

/* The function checks private and certificate's public key correlation
*/
kcm_status_e cs_check_cert_with_priv_handle(palX509Handle_t x509_cert, kcm_key_handle_t priv_key_h)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status;
    uint8_t raw_signature[KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE] = { 0 };
    uint8_t der_signature[KCM_ECDSA_SECP256R1_MAX_SIGNATURE_DER_SIZE_IN_BYTES] = { 0 };
    size_t act_raw_signature_size = 0;
    size_t act_der_signature_size = 0;
    const uint8_t hash_digest[] =
    { 0x34, 0x70, 0xCD, 0x54, 0x7B, 0x0A, 0x11, 0x5F, 0xE0, 0x5C, 0xEB, 0xBC, 0x07, 0xBA, 0x91, 0x88,
        0x27, 0x20, 0x25, 0x6B, 0xB2, 0x7A, 0x66, 0x89, 0x1A, 0x4B, 0xB7, 0x17, 0x11, 0x04, 0x86, 0x6F };

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = cs_asymmetric_sign(priv_key_h, hash_digest, sizeof(hash_digest), raw_signature, sizeof(raw_signature), &act_raw_signature_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_asymmetric_sign failed");

    // convert signature from raw to der
    pal_status = pal_convertRawSignatureToDer(raw_signature, act_raw_signature_size, der_signature, sizeof(der_signature), &act_der_signature_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), cs_error_handler(pal_status), "Failed converting signature from RAW to DER format");

    kcm_status = cs_x509_cert_verify_der_signature(x509_cert, hash_digest, sizeof(hash_digest), der_signature, act_der_signature_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_x509_cert_verify_der_signature failed");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

// FIXME - Currently, for CEC only. Can be removed once CEC support PSA.
kcm_status_e cs_check_cert_with_priv_data(palX509Handle_t x509_cert, const uint8_t *private_key_data, size_t size_of_private_key_data)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t out_sign[KCM_ECDSA_SECP256R1_MAX_SIGNATURE_DER_SIZE_IN_BYTES] = { 0 }; // DER format expected
    size_t size_of_sign = sizeof(out_sign);
    size_t act_size_of_sign = 0;
    const uint8_t hash_digest[] =
    { 0x34, 0x70, 0xCD, 0x54, 0x7B, 0x0A, 0x11, 0x5F, 0xE0, 0x5C, 0xEB, 0xBC, 0x07, 0xBA, 0x91, 0x88,
        0x27, 0x20, 0x25, 0x6B, 0xB2, 0x7A, 0x66, 0x89, 0x1A, 0x4B, 0xB7, 0x17, 0x11, 0x04, 0x86, 0x6F };

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = cs_ecdsa_sign(private_key_data, size_of_private_key_data, hash_digest, sizeof(hash_digest), out_sign, size_of_sign, &act_size_of_sign);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_ecdsa_sign failed");

    kcm_status = cs_x509_cert_verify_der_signature(x509_cert, hash_digest, sizeof(hash_digest), out_sign, act_size_of_sign);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "cs_x509_cert_verify_signature failed");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
