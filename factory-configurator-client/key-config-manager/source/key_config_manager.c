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
#include "key_config_manager.h"
#include "storage.h"
#include "pv_error_handling.h"
#include "cs_der_certs.h"
#include "cs_der_keys_and_csrs.h"
#include "fcc_malloc.h"
#include "pal.h"
#include "cs_utils.h"
#include "kcm_internal.h"
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
#include "certificate_enrollment.h"
#endif  // MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT


bool g_kcm_initialized = false;

kcm_status_e kcm_init(void)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (!g_kcm_initialized) {
        palStatus_t pal_status;

        //Initialize PAL
        pal_status = pal_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_ERROR, "Failed initializing PAL (%" PRIu32 ")", pal_status);

        //Initialize back-end storage
        status = storage_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "Failed initializing storage\n");
        // Mark as "initialized"
        g_kcm_initialized = true;

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
        //Check status of renewal process and restore backup items if needed
        ce_check_and_restore_backup_status();
#endif // MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return status;
}

kcm_status_e kcm_finalize(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (g_kcm_initialized) {

        kcm_status = storage_finalize();
        if (kcm_status != KCM_STATUS_SUCCESS) {
            SA_PV_LOG_ERR("Failed finalizing storage\n");
        }

        //Finalize PAL
        pal_destroy();

        // Mark as "not initialized"
        g_kcm_initialized = false;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_item_store(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, bool kcm_item_is_factory, const uint8_t * kcm_item_data, size_t kcm_item_data_size, const kcm_security_desc_s security_desc)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data == NULL) && (kcm_item_data_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");

    //temporary check that security descriptor is NULL
    SA_PV_ERR_RECOVERABLE_RETURN_IF((security_desc != NULL), KCM_STATUS_INVALID_PARAMETER, "Security descriptor is not NULL!");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_CONFIG_ITEM && kcm_item_data_size == 0), KCM_STATUS_ITEM_IS_EMPTY, "The data of current item is empty!");

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            kcm_status = cs_der_priv_key_verify(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Private key validation failed");
            break;
        case KCM_PUBLIC_KEY_ITEM:
            kcm_status = cs_der_public_key_verify(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Public key validation failed");
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            //currently possible to write a symmetric key of size 0 since we do not check format
            break;
        case KCM_CERTIFICATE_ITEM:
            kcm_status = cs_check_der_x509_format(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Certificate validation failed");
            break;
        case KCM_CONFIG_ITEM:
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    }

    kcm_status =  _kcm_item_store(kcm_item_name, kcm_item_name_len, kcm_item_type, kcm_item_is_factory, kcm_item_data, kcm_item_data_size, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_store");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e kcm_item_get_data_size(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, size_t *kcm_item_data_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_item_get_data_size
    kcm_status = _kcm_item_get_data_size(kcm_item_name, kcm_item_name_len, kcm_item_type, KCM_ORIGINAL_ITEM, kcm_item_data_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_get_data_size");

    return kcm_status;
}

kcm_status_e kcm_item_get_data(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, uint8_t * kcm_item_data_out, size_t kcm_item_data_max_size, size_t * kcm_item_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_item_get_data
    kcm_status = _kcm_item_get_data(kcm_item_name, kcm_item_name_len, kcm_item_type, KCM_ORIGINAL_ITEM, kcm_item_data_out, kcm_item_data_max_size, kcm_item_data_act_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_get_data");

    return kcm_status;
}

kcm_status_e kcm_item_delete(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_item_delete
    kcm_status = _kcm_item_delete(kcm_item_name, kcm_item_name_len, kcm_item_type, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_delete");

    return kcm_status;
}

kcm_status_e kcm_factory_reset(void)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "KCM initialization failed\n");
    }

    status = storage_factory_reset();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != KCM_STATUS_SUCCESS), (status = status), Exit, "Failed perform factory reset");

Exit:
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return status;
}

kcm_status_e kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t kcm_chain_len, bool kcm_chain_is_factory)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_cert_chain_create
    kcm_status = _kcm_cert_chain_create(kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, kcm_chain_len, kcm_chain_is_factory, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_cert_chain_create");

    return kcm_status;
}

kcm_status_e kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t *kcm_chain_len_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_cert_chain_open
    kcm_status = _kcm_cert_chain_open(kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, KCM_ORIGINAL_ITEM, kcm_chain_len_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_cert_chain_open");

    return kcm_status;
}
/*
* If not first certificate in chain:
*     1. Validate previously added certificate with the public key inside kcm_cert_data
*     2. Set the chain_context->prev_cert_params to be the params of the current certificate so it can be validated with next call to this function.
*     3. Store the current certificate
*     4. Update the index of the chain handle iterator for next use of this function
* If is first certificate in chain:
*    File already open - skip step 1 (no previous cert available). Note in this case the file should already be open so no need to reopen it
*/
kcm_status_e kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Handle_t cert;

    SA_PV_LOG_INFO_FUNC_ENTER("cert_data_size =%" PRIu32 "", (uint32_t)kcm_cert_data_size);

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL || kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data or kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_CREATE), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    // Parse the X509 and make sure it is of correct structure
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to parsing cert");

    if (chain_context->current_cert_index > 0) {
        // If not first certificate - validate based on params of previous certificate
        kcm_status = cs_x509_cert_verify_signature(cert, chain_context->prev_cert_params.htbs,
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

    //Call internal _kcm_cert_chain_add_next
    kcm_status = _kcm_cert_chain_add_next(kcm_chain_handle, kcm_cert_data, kcm_cert_data_size, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed in _kcm_cert_chain_add_next");

Clean_X509:
    cs_close_handle_x509_cert(&cert);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e kcm_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_cert_chain_delete
    kcm_status = _kcm_cert_chain_delete(kcm_chain_name, kcm_chain_name_len, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_cert_chain_delete");

    return kcm_status;
}


kcm_status_e kcm_cert_chain_get_next_size(kcm_cert_chain_handle kcm_chain_handle, size_t *kcm_cert_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_cert_chain_delete
    kcm_status = _kcm_cert_chain_get_next_size(kcm_chain_handle, KCM_ORIGINAL_ITEM, kcm_cert_data_size );
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_cert_chain_get_next_size");

    return kcm_status;
}

kcm_status_e kcm_cert_chain_get_next_data(kcm_cert_chain_handle kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, size_t *kcm_actual_cert_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_cert_chain_get_next_data
    kcm_status = _kcm_cert_chain_get_next_data(kcm_chain_handle, kcm_cert_data, kcm_max_cert_data_size, KCM_ORIGINAL_ITEM, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_cert_chain_get_next_data");

    return kcm_status;
}


kcm_status_e kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal _kcm_cert_chain_get_next_data
    kcm_status = _kcm_cert_chain_close(kcm_chain_handle, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_cert_chain_close")

    return kcm_status;
}

kcm_status_e kcm_key_pair_generate_and_store(
    const kcm_crypto_key_scheme_e    key_scheme,
    const uint8_t                    *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                    *public_key_name,
    size_t                            public_key_name_len,
    bool                              kcm_item_is_factory,
    const kcm_security_desc_s        *kcm_params)

{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t actual_kcm_priv_key_size = 0;
    size_t actual_kcm_pub_key_size = 0;
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];
    uint8_t pub_key_buffer[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    bool pub_key_exists = false;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //temporary check that kcm_params is NULL                                                                                                   
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_params != NULL), KCM_STATUS_INVALID_PARAMETER, "kcm_params is not NULL!");

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_scheme != KCM_SCHEME_EC_SECP256R1), KCM_STATUS_INVALID_PARAMETER, "Invalid key_scheme");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name != NULL) && (public_key_name_len == 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is not NULL, but its size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name == NULL) && (public_key_name_len != 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is NULL, but its size is not 0");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32 ", pub_key_name = %.*s pub_key_len = %" PRIu32,
        (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);

    pub_key_exists = ((public_key_name != NULL) && (public_key_name_len != 0));

    //check private key existence
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &actual_kcm_priv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //fetch public key if exists
    if (pub_key_exists) {
        kcm_status = kcm_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM,
                                            &actual_kcm_pub_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");
    }

    //generate key pair
    kcm_status = cs_key_pair_generate(key_scheme, priv_key_buffer, sizeof(priv_key_buffer), &actual_kcm_priv_key_size, pub_key_buffer, sizeof(pub_key_buffer), &actual_kcm_pub_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate key pair");

    //store private key
    kcm_status = kcm_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, kcm_item_is_factory, priv_key_buffer, actual_kcm_priv_key_size, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store private key");

    //store public key if exists
    if (pub_key_exists) {
        kcm_status = kcm_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, kcm_item_is_factory, pub_key_buffer, actual_kcm_pub_key_size, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store public key");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e kcm_csr_generate(
    const uint8_t            *private_key_name,
    size_t                   private_key_name_len,
    const kcm_csr_params_s   *csr_params,
    uint8_t                  *csr_buff_out,
    size_t                   csr_buff_max_size,
    size_t                   *csr_buff_act_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t prv_key_size, actual_prv_key_size = 0;
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->md_type == KCM_MD_NONE), KCM_STATUS_INVALID_PARAMETER, "Invalid md type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_act_size");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32", csr_buff_max_size = %" PRIu32,
        (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (uint32_t)csr_buff_max_size);

    //fetch private key size
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &prv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get private key data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((prv_key_size == 0), kcm_status, "Size of private key is 0");

    //fetch private key
    kcm_status = kcm_item_get_data(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, priv_key_buffer,
                                   prv_key_size, &actual_prv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get private key");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((actual_prv_key_size == 0), kcm_status = KCM_STATUS_ITEM_IS_EMPTY, "Size of private key is 0");

    //generate csr
    kcm_status = cs_csr_generate(priv_key_buffer, actual_prv_key_size, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate CSR");

    SA_PV_LOG_INFO_FUNC_EXIT("csr_buff_act_size = %" PRIu32 "", (uint32_t)*csr_buff_act_size);

    return kcm_status;

}


kcm_status_e kcm_generate_keys_and_csr(
    kcm_crypto_key_scheme_e   key_scheme,
    const uint8_t             *private_key_name,
    size_t                    private_key_name_len,
    const uint8_t             *public_key_name,
    size_t                    public_key_name_len,
    bool                      kcm_item_is_factory,
    const kcm_csr_params_s    *csr_params,
    uint8_t                   *csr_buff_out,
    size_t                    csr_buff_max_size,
    size_t                    *csr_buff_act_size_out,
    const kcm_security_desc_s *kcm_params)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t actual_kcm_key_size = 0;
    size_t priv_key_act_size_out = 0;
    size_t pub_key_act_size_out = 0;
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];
    uint8_t pub_key_buffer[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    bool pub_key_exists = false;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //temporary check that kcm_params is NULL                                                                                                   
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_params != NULL), KCM_STATUS_INVALID_PARAMETER, "kcm_params is not NULL!");

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_scheme != KCM_SCHEME_EC_SECP256R1), KCM_STATUS_INVALID_PARAMETER, "Invalid key_scheme");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name != NULL) && (public_key_name_len == 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is not NULL, but its size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name == NULL) && (public_key_name_len != 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is NULL, but its size is not 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->md_type == KCM_MD_NONE), KCM_STATUS_INVALID_PARAMETER, "Invalid md type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_act_size");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32 ", pub_key_name = %.*s pub_key_len = %" PRIu32,
        (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);

    pub_key_exists = ((public_key_name != NULL) && (public_key_name_len != 0));

    //check private key existence
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &actual_kcm_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //check public key existence
    if (pub_key_exists) {
        kcm_status = kcm_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM,
                                            &actual_kcm_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");
    }

    //generat keys and csr
    kcm_status = cs_generate_keys_and_csr(key_scheme, csr_params, priv_key_buffer, sizeof(priv_key_buffer), &priv_key_act_size_out, pub_key_buffer, sizeof(pub_key_buffer), &pub_key_act_size_out, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate keys and csr");

    //store private key
    kcm_status = kcm_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, kcm_item_is_factory, priv_key_buffer, sizeof(priv_key_buffer), NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store private key");

    //store public key
    if (pub_key_exists) {
        kcm_status = kcm_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, kcm_item_is_factory, pub_key_buffer, sizeof(pub_key_buffer), NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store public key");
    }


    SA_PV_LOG_INFO_FUNC_EXIT("csr_buff_act_size_out = %" PRIu32 "", (uint32_t)*csr_buff_act_size_out);
    return kcm_status;

}

kcm_status_e kcm_certificate_verify_with_private_key(
    const uint8_t * kcm_cert_data,
    size_t kcm_cert_data_size,
    const uint8_t * kcm_priv_key_name,
    size_t kcm_priv_key_name_len)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t priv_key_data_size = 0;
    uint8_t *priv_key_data = NULL;
    size_t act_priv_key_data_size = 0;
    palX509Handle_t x509_cert;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_priv_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_priv_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_priv_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_priv_key_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("priv key name =  %.*s, cert size=%" PRIu32 "", (int)kcm_priv_key_name_len, (char*)kcm_priv_key_name,(uint32_t)kcm_cert_data_size);

    //Get private key size
    kcm_status = kcm_item_get_data_size(kcm_priv_key_name,
        kcm_priv_key_name_len,
        KCM_PRIVATE_KEY_ITEM,
        &priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS || priv_key_data_size == 0), kcm_status, "Failed to get kcm private key size");

    //Allocate memory and get private key data
    priv_key_data = fcc_malloc(priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_data == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate buffer for private key data");

    //Get private key data
    kcm_status = kcm_item_get_data(kcm_priv_key_name,
        kcm_priv_key_name_len,
        KCM_PRIVATE_KEY_ITEM,
        priv_key_data,
        priv_key_data_size,
        &act_priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS || act_priv_key_data_size != priv_key_data_size), (kcm_status = kcm_status), Exit, "Failed to get private key data");

    //Create certificate handle
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &x509_cert);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to create certificate handle");

    //Check current certificate against given private key
    kcm_status = cs_check_certifcate_public_key(x509_cert, priv_key_data, priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR), Exit, "Certificate verification failed against private key");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:

    fcc_free(priv_key_data);
    cs_close_handle_x509_cert(&x509_cert);
    return kcm_status;

}


