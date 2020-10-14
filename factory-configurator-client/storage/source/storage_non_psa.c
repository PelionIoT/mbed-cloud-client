// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#include "storage_kcm.h"
#include "storage_internal.h"
#include "kcm_defs.h"
#include "pv_error_handling.h"
#include "fcc_malloc.h"
#include "pv_macros.h"
#include "pal_Crypto.h"

/*The function copies certificate chain or single certificate from source  to destination (inside storage)*/
static kcm_status_e copy_certificate_chain(const uint8_t *item_name, size_t item_name_len, storage_item_prefix_type_e source_item_prefix_type, storage_item_prefix_type_e destination_item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e close_status = KCM_STATUS_SUCCESS;
    uint8_t *item_data = NULL;
    size_t item_data_len = 0;
    kcm_cert_chain_handle kcm_source_chain_handle = NULL;
    kcm_cert_chain_handle kcm_destination_chain_handle = NULL;
    size_t kcm_chain_len_out = 0;
    size_t  kcm_actual_cert_data_size = 0;
    int cert_index = 0;

    //Open chain 
    kcm_status = storage_cert_chain_open(&kcm_source_chain_handle, item_name, item_name_len, source_item_prefix_type, &kcm_chain_len_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open chain");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_chain_len_out == 0), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, exit, "Invalid kcm_chain_len_out");
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)item_name_len, (char*)item_name, (uint32_t)item_name_len);

    //Current item is a single certificate 
    if (storage_is_cert_chain(kcm_source_chain_handle) == false && kcm_chain_len_out == 1) {
        // close source chain handle. in single, not needed anymore
        kcm_status = storage_cert_chain_close(kcm_source_chain_handle, source_item_prefix_type);
        kcm_source_chain_handle = NULL;
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to close source chain");

        //Read the item from source 
        kcm_status = storage_item_get_size_and_data(item_name, item_name_len, KCM_CERTIFICATE_ITEM, source_item_prefix_type, &item_data, &item_data_len);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to get item data");

        //Save the item as backup item
        kcm_status = storage_item_store(item_name, item_name_len, KCM_CERTIFICATE_ITEM, false, destination_item_prefix_type, item_data, item_data_len, true);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to copy item data");
    } else {
        //Current item is certificate chain
        for (cert_index = 1; cert_index <= (int)kcm_chain_len_out; cert_index++) {
            //Create destination chain for start
            if (cert_index == 1) {
                kcm_status = storage_cert_chain_create(&kcm_destination_chain_handle, item_name, item_name_len, kcm_chain_len_out, false, destination_item_prefix_type);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to create destination chain");
            }
            //Get next certificate data size from source chain
            kcm_status = storage_cert_chain_get_next_size(kcm_source_chain_handle, source_item_prefix_type, &item_data_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to _kcm_cert_chain_get_next_sizen");

            //Allocate memory and get  certificate data from source chain
            item_data = fcc_malloc(item_data_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((item_data == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, exit_and_close, "Failed to allocate buffer for kcm data");

            //Get next certificate data
            kcm_status = storage_cert_chain_get_next_data(kcm_source_chain_handle, item_data, item_data_len, source_item_prefix_type, &kcm_actual_cert_data_size);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to get certificate kcm data");
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_actual_cert_data_size != item_data_len), kcm_status = kcm_status, exit_and_close, "Wrong certificate data size");

            //Add the data to destination chain
            kcm_status = storage_cert_chain_add_next(kcm_destination_chain_handle, item_data, item_data_len, destination_item_prefix_type, true);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to add data to chain");

            //free allocated buffer
            fcc_free(item_data);
            item_data = NULL;
        }
        //Close destination chain
exit_and_close:
        close_status = storage_cert_chain_close(kcm_destination_chain_handle, destination_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status == KCM_STATUS_SUCCESS) && (close_status != KCM_STATUS_SUCCESS),
            kcm_status = close_status, exit, "Failed to close destination chain");
    }

exit:
    if (item_data != NULL) {
        fcc_free(item_data);
    }
    //close source chain
    close_status = storage_cert_chain_close(kcm_source_chain_handle, source_item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS) && (close_status != KCM_STATUS_SUCCESS),
        close_status, "Failed to close source chain");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;

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


kcm_status_e storage_key_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    storage_item_prefix_type_e item_prefix_type,
    kcm_key_handle_t *key_h_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palKeyHandle_t pal_key_handle;
    size_t key_size_out, key_size_out_actual;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_h_out");

    *key_h_out = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name_len");
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)key_name_len, (char*)key_name, (uint32_t)key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid key_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != KCM_PRIVATE_KEY_ITEM && key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid key type");

    // Check key size
    kcm_status = storage_item_get_data_size(key_name, key_name_len, key_type, item_prefix_type, &key_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto exit;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_item_get_data_size read");

    //allocate buffer for new key
    pal_status = pal_newKeyHandle(&pal_key_handle, key_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_OUT_OF_MEMORY, "Failed during pal_newKeyHandle");

    // read the key
    kcm_status = storage_item_get_data(key_name, key_name_len, key_type, item_prefix_type, ((palCryptoBuffer_t*)pal_key_handle)->buffer, key_size_out, &key_size_out_actual);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "Failed during storage_item_get_data");

    *key_h_out = (kcm_key_handle_t)pal_key_handle;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    goto exit;

free_and_exit:
    storage_key_close_handle((kcm_key_handle_t*)&pal_key_handle);

exit:
    return kcm_status;


}

kcm_status_e storage_key_close_handle(kcm_key_handle_t *key_handle)
{

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_handle");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (*key_handle == 0) {
        return KCM_STATUS_SUCCESS;
    }

    pal_freeKeyHandle(key_handle);
    //check: *key_handle = 0;


    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_key_pair_generate_and_store(
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    storage_item_prefix_type_e        item_prefix_type,
    bool                              is_factory,
    const kcm_security_desc_s         kcm_item_info)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_del_status;
    size_t actual_kcm_priv_key_size = 0;
    size_t actual_kcm_pub_key_size = 0;
    cs_key_handle_t cs_key_h;
    bool write_public_key = false;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_info != NULL), KCM_STATUS_INVALID_PARAMETER, "Expected NULL for kcm_item_info");

    //Check if current private exists in the storage
    kcm_status = storage_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                            item_prefix_type, &actual_kcm_priv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //Check if current public exists in the storage
    if (public_key_name != NULL) {
        SA_PV_LOG_INFO("public_key_name = %.*s public_key_name = %" PRIu32, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);
        kcm_status = storage_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, item_prefix_type,
                                                &actual_kcm_pub_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");

        //write public key
        write_public_key = true;
    }

    //create cs_ec_context
    kcm_status = cs_key_pair_new(&cs_key_h, write_public_key);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to create key context");

    //generate key pair
    kcm_status = cs_key_pair_generate(KCM_SCHEME_EC_SECP256R1, cs_key_h);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "failed to generate key pair");

    //store private key
    cs_key_pair_context_s* cs_key_ctx = (cs_key_pair_context_s*)cs_key_h;

    kcm_status = storage_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, is_factory, item_prefix_type, ((palCryptoBuffer_t*)(cs_key_ctx->generated_priv_key_handle))->buffer,
        ((palCryptoBuffer_t*)(cs_key_ctx->generated_priv_key_handle))->size, true);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "failed to store private key");

    //store public key if exists
    if (public_key_name != NULL) {
        kcm_status = storage_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, is_factory, item_prefix_type, ((palCryptoBuffer_t*)(cs_key_ctx->generated_pub_key_handle))->buffer,
            ((palCryptoBuffer_t*)(cs_key_ctx->generated_pub_key_handle))->size, true);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), delete_priv_and_exit, "failed to store public key");
    }

    goto free_and_exit;

delete_priv_and_exit:
    // Failed to store public, remove stored private key
    kcm_del_status = storage_item_delete(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, item_prefix_type);
    if (kcm_del_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("failed destorying PSA key during cleanup (%u)", kcm_del_status);
    }

free_and_exit:
    cs_key_pair_free(&cs_key_h);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e storage_ce_item_copy(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e source_item_prefix_type,
    storage_item_prefix_type_e destination_item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *item_data = NULL;
    size_t item_data_len = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    //Read the data
    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        //copy certificate chain 
        kcm_status = copy_certificate_chain(kcm_item_name, kcm_item_name_len, source_item_prefix_type, destination_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy chain");
    } else {

        //Read the item from source
        kcm_status = storage_item_get_size_and_data(kcm_item_name, kcm_item_name_len, kcm_item_type, source_item_prefix_type, &item_data, &item_data_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get item data");

        //Save the item as backup item
        kcm_status = storage_item_store(kcm_item_name, kcm_item_name_len, kcm_item_type, false, destination_item_prefix_type, item_data, item_data_len, true);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to copy item data");
    }

exit:
    if (item_data != NULL) {
        fcc_free(item_data);
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;

}


kcm_status_e storage_ce_clean_item(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    bool clean_active_item_only)
{

    PV_UNUSED_PARAM(clean_active_item_only);

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = storage_item_delete(kcm_item_name, kcm_item_name_len, kcm_item_type, item_prefix_type);
    if ((kcm_item_type == KCM_CERTIFICATE_ITEM) && (kcm_status == KCM_STATUS_ITEM_NOT_FOUND)) {//We need to check certificate chain with the same name
        kcm_status = storage_cert_chain_delete((const uint8_t*)kcm_item_name, kcm_item_name_len, item_prefix_type);
    }

    return kcm_status;
}



#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

