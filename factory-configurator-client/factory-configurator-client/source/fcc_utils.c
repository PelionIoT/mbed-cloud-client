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

#include "factory_configurator_client.h"
#include "fcc_status.h"
#include "fcc_utils.h"
#include "key_config_manager.h"
#include "pv_error_handling.h"
#include "pal_errors.h"

fcc_status_e fcc_convert_kcm_to_fcc_status(kcm_status_e kcm_result)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    switch (kcm_result) {
        case KCM_STATUS_SUCCESS: 
            fcc_status = FCC_STATUS_SUCCESS;
            break;
        case KCM_STATUS_RBP_ERROR:
            fcc_status = FCC_STATUS_STORE_ERROR;
            break;
        case KCM_STATUS_ERROR:
        case KCM_STATUS_INVALID_PARAMETER:
        case KCM_STATUS_OUT_OF_MEMORY:
        case KCM_STATUS_INSUFFICIENT_BUFFER:
            fcc_status = FCC_STATUS_KCM_ERROR;
            break;
        case KCM_STATUS_ITEM_NOT_FOUND:
            fcc_status = FCC_STATUS_ITEM_NOT_EXIST;
            break;
        case KCM_STATUS_STORAGE_ERROR:
        case KCM_STATUS_META_DATA_NOT_FOUND:
        case KCM_STATUS_META_DATA_SIZE_ERROR:
        case KCM_STATUS_NOT_PERMITTED:
        case KCM_STATUS_ITEM_IS_EMPTY:
        case KCM_STATUS_INVALID_FILE_VERSION:
        case KCM_STATUS_UNKNOWN_STORAGE_ERROR:
        case KCM_STATUS_NOT_INITIALIZED:
        case KCM_STATUS_CLOSE_INCOMPLETE_CHAIN:
        case KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN:
        case KCM_STATUS_FILE_CORRUPTED:
        case KCM_STATUS_FILE_NAME_CORRUPTED:
        case KCM_STATUS_INVALID_FILE_ACCESS_MODE:
        case KCM_STATUS_CORRUPTED_CHAIN_FILE:
        case KCM_STATUS_FILE_NAME_INVALID:
        case KCM_STATUS_FILE_NAME_TOO_LONG:
            fcc_status = FCC_STATUS_KCM_STORAGE_ERROR;
            break;
        case KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR:
            fcc_status = FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR;
            break;
        case KCM_STATUS_FILE_EXIST:
        case KCM_STATUS_KEY_EXIST:
            fcc_status = FCC_STATUS_KCM_FILE_EXIST_ERROR;
            break;
        case KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE:
        case KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY:
        case KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY:
        case KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT:
        case KCM_CRYPTO_STATUS_INVALID_PK_PRIVKEY:
        case KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY:
        case KCM_CRYPTO_STATUS_ECP_INVALID_KEY:
        case KCM_CRYPTO_STATUS_PK_KEY_INVALID_VERSION:
        case KCM_CRYPTO_STATUS_PK_PASSWORD_REQUIRED:
        case KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED:
        case KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED:
        case KCM_CRYPTO_STATUS_PK_UNKNOWN_PK_ALG:
        case KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE:
        case KCM_CRYPTO_STATUS_PARSING_DER_CERT:
        case KCM_CRYPTO_STATUS_CERT_EXPIRED:
        case KCM_CRYPTO_STATUS_CERT_FUTURE:
        case KCM_CRYPTO_STATUS_CERT_MD_ALG:
        case KCM_CRYPTO_STATUS_CERT_PUB_KEY_TYPE:
        case KCM_CRYPTO_STATUS_CERT_PUB_KEY:
        case KCM_CRYPTO_STATUS_CERT_NOT_TRUSTED:
        case KCM_CRYPTO_STATUS_INVALID_X509_ATTR:
        case KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED:
        case KCM_CRYPTO_STATUS_INVALID_MD_TYPE:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_SIGNATURE:
        case KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PRIVATE_KEY:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PUBLIC_KEY:
        case KCM_CRYPTO_STATUS_INVALID_OID:
        case KCM_CRYPTO_STATUS_INVALID_NAME_FORMAT:
        case KCM_CRYPTO_STATUS_FAILED_TO_WRITE_CSR:
        case KCM_CRYPTO_STATUS_SET_EXTENSION_FAILED:
        case KCM_MAX_STATUS:
            fcc_status = FCC_STATUS_KCM_CRYPTO_ERROR;
            break;

    }
    return fcc_status;
}


fcc_status_e fcc_convert_pal_to_fcc_status(palStatus_t pal_result)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    switch (pal_result) {

        case PAL_ERR_INVALID_ARGUMENT:
            fcc_status = FCC_STATUS_KCM_ERROR;
            break;   
        case PAL_ERR_ITEM_EXIST:
            fcc_status = FCC_STATUS_KCM_FILE_EXIST_ERROR;
            break;
        case PAL_ERR_ITEM_NOT_EXIST:
            fcc_status = FCC_STATUS_ITEM_NOT_EXIST;
            break;
        case PAL_ERR_ENTROPY_EXISTS:
            fcc_status = FCC_STATUS_ENTROPY_ERROR;
            break;
        case PAL_ERR_NOT_SUPPORTED:
            fcc_status = FCC_STATUS_NOT_SUPPORTED;
            break;
        default:
            fcc_status = FCC_STATUS_ERROR;
            break;
        
    }
   
    return fcc_status;
}


