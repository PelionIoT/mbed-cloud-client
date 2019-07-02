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


#include <stdbool.h>
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "storage_items.h"
#include "esfs.h"
#include "fcc_malloc.h"
#include "storage_internal.h"
#include "cs_der_certs.h"

extern bool g_kcm_initialized;

kcm_status_e storage_check_name_validity(const uint8_t *kcm_item_name, size_t kcm_item_name_len)
{
    size_t i;
    int ascii_val;

    // Check name length
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len > KCM_MAX_FILENAME_SIZE),
                                    KCM_STATUS_FILE_NAME_TOO_LONG,
                                    "kcm_item_name_len must be %d or less",
                                    KCM_MAX_FILENAME_SIZE);

    // Iterate all the characters and make sure all belong to {'A'-'Z' , 'a'-'z' , '0'-'9' , '.' , '-' , '_' }
    // Regular expression match: "^[a-zA-Z0-9_.-]*$"
    for (i = 0; i < kcm_item_name_len; i++) {
        ascii_val = (int) kcm_item_name[i];
        if (!((ascii_val >= 'A' && ascii_val <= 'Z') || (ascii_val >= 'a' && ascii_val <= 'z') || (ascii_val == '.') ||
                (ascii_val == '-') || (ascii_val == '_') || (ascii_val >= '0' && ascii_val <= '9'))) {
            return KCM_STATUS_FILE_NAME_INVALID;
        }
    }

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_get_prefix_from_type(kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type, const char** prefix)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid item_source_type");

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_PRIVATE_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_PRIVATE_KEY);
            break;
        case KCM_PUBLIC_KEY_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_PUBLIC_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_PUBLIC_KEY);
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_SYMMETRIC_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_SYMMETRIC_KEY);
            break;
        case KCM_CERTIFICATE_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_CERTIFICATE) : (*prefix = KCM_RENEWAL_FILE_PREFIX_CERTIFICATE);
            break;
        case KCM_CONFIG_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_CONFIG_PARAM) : (*prefix = KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM);
            break;
        default:
            status = KCM_STATUS_INVALID_PARAMETER;
            break;
    }
    return status;
}

kcm_status_e storage_item_store(const uint8_t * kcm_item_name,
                                size_t kcm_item_name_len,
                                kcm_item_type_e kcm_item_type,
                                bool kcm_item_is_factory,
                                storage_item_prefix_type_e item_prefix_type,
                                const uint8_t * kcm_item_data,
                                size_t kcm_item_data_size,
                                const kcm_security_desc_s kcm_item_info)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    bool kcm_item_is_encrypted = true;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_info != NULL), KCM_STATUS_INVALID_PARAMETER, "kcm_item_info is not NULL!");

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %.*s len=%" PRIu32 ", data size=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data == NULL) && (kcm_item_data_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_CONFIG_ITEM && kcm_item_data_size == 0), KCM_STATUS_ITEM_IS_EMPTY, "The data of current item is empty!");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type == STORAGE_ITEM_PREFIX_CE && kcm_item_is_factory == true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_is_factory parameter");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            break;
        case KCM_PUBLIC_KEY_ITEM:
            kcm_item_is_encrypted = false; //do not encrypt public key
            break;
        case KCM_CERTIFICATE_ITEM:
            kcm_item_is_encrypted = false; //do not encrypt certificates
            break;
        case  KCM_SYMMETRIC_KEY_ITEM:
            break;
        case KCM_CONFIG_ITEM:
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    }

    kcm_status = storage_item_store_impl(kcm_item_name, kcm_item_name_len, kcm_item_type, kcm_item_is_factory, kcm_item_is_encrypted, item_prefix_type, kcm_item_data, kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "storage_data_write_impl failed\n");

    return kcm_status;
}

kcm_status_e storage_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
        const uint8_t *kcm_cert_data,
        size_t kcm_cert_data_size,
        storage_item_prefix_type_e item_prefix_type)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Handle_t cert;

    SA_PV_LOG_INFO_FUNC_ENTER("cert_data_size = %" PRIu32 "", (uint32_t)kcm_cert_data_size);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL || kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data or kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != STORAGE_CHAIN_OP_TYPE_CREATE), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Parse the X509 and make sure it is of correct structure
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to parsing cert");

    if (chain_context->current_cert_index > 0) {
        // If not first certificate - validate based on params of previous certificate
        kcm_status = cs_x509_cert_verify_der_signature(cert, chain_context->prev_cert_params.htbs,
                     chain_context->prev_cert_params.htbs_actual_size,
                     chain_context->prev_cert_params.signature,
                     chain_context->prev_cert_params.signature_actual_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status == KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED), (kcm_status = KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED), Clean_X509, "Failed verifying child signature");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed verifying child signature");
    }

    // Save params only if certificate is not last in chain
    if(chain_context->current_cert_index < chain_context->num_of_certificates_in_chain - 1) {
        // Get params needed for validation by the signer
        // These will be used to validate this certificate in the chain when parsing the next one
        kcm_status = cs_child_cert_params_get(cert, &chain_context->prev_cert_params);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed to retrieve child cert params");
    }

    //Call internal storage_chain_add_next
    kcm_status = storage_cert_chain_add_next_impl(kcm_chain_handle,
                 kcm_cert_data,
                 kcm_cert_data_size,
                 item_prefix_type);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed in storage_chain_add_next");

Clean_X509:
    cs_close_handle_x509_cert(&cert);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

