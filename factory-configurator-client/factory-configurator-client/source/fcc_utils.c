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
#include "fcc_sotp.h"


const char g_sotp_entropy_data_type_name[] = "EntropyData";
const char g_sotp_rot_data_type_name[] = "ROTData";
const char g_sotp_factory_disable_type_name[] = "FactoryDisableFlag";
const char g_sotp_ca_server_id_type_name[] = "CAServerId";
const char g_sotp_time_type_name[] = "Time";
const char g_sotp_wrong_type_name[] = "Wrong_sotp_type";


fcc_status_e fcc_get_sotp_type_name(sotp_type_e sotp_type,char **sotp_type_name, size_t *sotp_type_name_size)
{

    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_type_name_size == NULL), fcc_status, "Wrong sotp_type_name_size pointer");

    switch (sotp_type) {
    case SOTP_TYPE_ROT:
        *sotp_type_name = (char*)g_sotp_rot_data_type_name;
        *sotp_type_name_size = (size_t)strlen(g_sotp_rot_data_type_name);
        break;
    case SOTP_TYPE_FACTORY_DONE:
        *sotp_type_name = (char*)g_sotp_factory_disable_type_name;
        *sotp_type_name_size = (size_t)strlen(g_sotp_factory_disable_type_name);
        break;
    case SOTP_TYPE_RANDOM_SEED:
        *sotp_type_name = (char*)g_sotp_entropy_data_type_name;
        *sotp_type_name_size = (size_t)strlen(g_sotp_entropy_data_type_name);
        break;
    case SOTP_TYPE_SAVED_TIME:
        *sotp_type_name = (char*)g_sotp_time_type_name;
        *sotp_type_name_size = (size_t)strlen(g_sotp_time_type_name);
        break;
    case SOTP_TYPE_TRUSTED_TIME_SRV_ID:
        *sotp_type_name = (char*)g_sotp_ca_server_id_type_name;
        *sotp_type_name_size = (size_t)strlen(g_sotp_ca_server_id_type_name);
        break;
    default:
        SA_PV_LOG_ERR("Non existent sotp_type provided");
        *sotp_type_name = (char*)g_sotp_wrong_type_name;
        *sotp_type_name_size = (size_t)strlen(g_sotp_wrong_type_name);
        return FCC_STATUS_INVALID_PARAMETER;
    }

    return fcc_status;
}

fcc_status_e fcc_convert_kcm_to_fcc_status(kcm_status_e kcm_result)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    switch (kcm_result) {
        case KCM_STATUS_SUCCESS:
            fcc_status = FCC_STATUS_SUCCESS;
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
        case KCM_STATUS_FILE_NAME_TOO_LONG:
            fcc_status = FCC_STATUS_KCM_STORAGE_ERROR;
            break;
        case KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR:
            fcc_status = FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR;
        case KCM_STATUS_FILE_EXIST:
        case (KCM_STATUS_KEY_EXIST):
            fcc_status = FCC_STATUS_KCM_FILE_EXIST_ERROR;
            break;
        case KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE:
        case KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY:
        case KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY:
        case KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT:
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
        case KCM_MAX_STATUS:
            fcc_status = FCC_STATUS_KCM_CRYPTO_ERROR;
            break;

    }
    return fcc_status;
}
