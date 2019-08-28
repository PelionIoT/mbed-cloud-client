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
#include "pv_error_handling.h"
#include "storage_dispatcher.h"
#include "fcc_malloc.h"
#include "pv_macros.h"
#include "ce_internal.h"
#include "est_defs.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "storage_keys.h"
#endif

const char g_lwm2m_name[] = "LWM2M";
const char g_renewal_status_file[] = "renewal_status";

extern const char g_fcc_lwm2m_device_certificate_name[];
extern const char g_fcc_lwm2m_device_private_key_name[];

/* The function reads item from storage according to its kcm  and source type,
the function allocated buffer for the item*/
kcm_status_e ce_get_kcm_data(const uint8_t *parameter_name,
                             size_t size_of_parameter_name,
                             kcm_item_type_e kcm_type,
                             storage_item_prefix_type_e item_prefix_type,
                             uint8_t **kcm_data,
                             size_t *kcm_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    storage_get_data_size_f get_data_size_func = (storage_get_data_size_f)storage_func_dispatch(STORAGE_FUNC_GET_SIZE, kcm_type);
    storage_get_data_f get_data_func = (storage_get_data_f)storage_func_dispatch(STORAGE_FUNC_GET, kcm_type);
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((parameter_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong parameter_name pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((size_of_parameter_name == 0), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong parameter_name size.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data != NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong *kcm_data pointer, should be NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_data_size == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong kcm_data_size pointer.");

    //Get size of kcm data
    kcm_status = get_data_size_func(parameter_name,
                                    size_of_parameter_name,
                                    kcm_type,
                                    item_prefix_type,
                                    kcm_data_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get kcm data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data_size == 0), kcm_status = KCM_STATUS_ITEM_IS_EMPTY, "KCM item is empty");

    //Allocate memory and get device certificate data
    *kcm_data = fcc_malloc(*kcm_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate buffer for kcm data");

    kcm_status = get_data_func(parameter_name, size_of_parameter_name, kcm_type, item_prefix_type, *kcm_data, *kcm_data_size, kcm_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to get device certificate data");

exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(*kcm_data);
        *kcm_data = NULL;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

/*The function copies certificate chain or single certificate from source  to destination (inside storage)*/
static kcm_status_e copy_certificate_chain(const uint8_t *item_name, size_t item_name_len, storage_item_prefix_type_e source_item_prefix_type, storage_item_prefix_type_e destination_item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *item_data = NULL;
    size_t item_data_len = 0;
    kcm_cert_chain_handle kcm_source_chain_handle;
    kcm_cert_chain_handle kcm_destination_chain_handle;
    size_t kcm_chain_len_out = 0;
    size_t  kcm_actual_cert_data_size = 0;
    int cert_index = 0;
    storage_cert_chain_context_s *chain_context;
    storage_store_f store_func;

    //Open chain 
    kcm_status = storage_cert_chain_open(&kcm_source_chain_handle, item_name, item_name_len, source_item_prefix_type, &kcm_chain_len_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open chain");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_chain_len_out == 0), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, exit, "Invalid kcm_chain_len_out");
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)item_name_len, (char*)item_name, (uint32_t)item_name_len);

    chain_context = (storage_cert_chain_context_s*)kcm_source_chain_handle;

    //Current item is a single certificate 
    if (chain_context->is_meta_data == false && kcm_chain_len_out == 1) {
        //Read the item from source 
        kcm_status = ce_get_kcm_data(item_name, item_name_len, KCM_CERTIFICATE_ITEM, source_item_prefix_type, &item_data, &item_data_len);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to get item data");

        //Save the item as backup item
        store_func = (storage_store_f)storage_func_dispatch(STORAGE_FUNC_STORE, KCM_CERTIFICATE_ITEM);
        kcm_status = store_func(item_name, item_name_len, KCM_CERTIFICATE_ITEM, false, destination_item_prefix_type, item_data, item_data_len, NULL);
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
            kcm_status = storage_cert_chain_add_next(kcm_destination_chain_handle, item_data, item_data_len, destination_item_prefix_type);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to add data to chain");

            //free allocated buffer
            fcc_free(item_data);
            item_data = NULL;
        }
        //Close destination chain
exit_and_close:
        kcm_status = storage_cert_chain_close(kcm_destination_chain_handle, destination_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to close destination chain");

    }

exit:
    if (item_data != NULL) {
        fcc_free(item_data);
    }
    //close source chain
    kcm_status = storage_cert_chain_close(kcm_source_chain_handle, source_item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close source chain");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;

}
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
static kcm_status_e copy_kcm_item(const uint8_t *item_name,
                                  size_t item_name_len,
                                  kcm_item_type_e kcm_type,
                                  storage_item_prefix_type_e source_item_prefix_type,
                                  storage_item_prefix_type_e destination_item_prefix_type)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *item_data = NULL;
    size_t item_data_len = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)item_name_len, (char*)item_name, (uint32_t)item_name_len);
    //Read the data
    if (kcm_type == KCM_CERTIFICATE_ITEM) {
        //copy certificate chain 
        kcm_status = copy_certificate_chain(item_name, item_name_len, source_item_prefix_type, destination_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy chain");
    } else {
        storage_store_f store_func = (storage_store_f)storage_func_dispatch(STORAGE_FUNC_STORE, kcm_type);

        //Read the item from source
        kcm_status = ce_get_kcm_data(item_name, item_name_len, kcm_type, source_item_prefix_type, &item_data, &item_data_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get item data");

        //Save the item as backup item
        kcm_status = store_func(item_name, item_name_len, kcm_type, false, destination_item_prefix_type, item_data, item_data_len, NULL);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to copy item data");
    }

exit:
    if (item_data != NULL) {
        fcc_free(item_data);
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#else
static kcm_status_e copy_kcm_item(const uint8_t *item_name,
                                  size_t item_name_len,
                                  kcm_item_type_e kcm_type,
                                  storage_item_prefix_type_e source_item_prefix_type,
                                  storage_item_prefix_type_e destination_item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)item_name_len, (char*)item_name, (uint32_t)item_name_len);

    //Read the data
    if (kcm_type == KCM_CERTIFICATE_ITEM) {
        //copy certificate chain 
        kcm_status = copy_certificate_chain(item_name, item_name_len, source_item_prefix_type, destination_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy chain");
    } else {
        /*
       Example : copy CE key to original , original is always present!!
                        old status                                                       new status
        --------------------------------------------------           -----------------------------------------------
        | key name hash | Act ID | Factory ID | Renew ID |           | key name hash| Act ID | Factory ID | Renew ID |
        ---------------------------------------------                ---------------------------------------------
        | kcm_key1_hash |   3    |     1      |   0      |           | kcm_key1_hash|   1    |     1      |   3      |
        -------------------------------------------------     ==>    --------------------------------------------------
        | ce_key1_hash  |   1    |     1      |   3      |           |  ce_key1_hash|   1    |     1      |   3      |
        -------------------------------------------------           --------------------------------------------------

        Example: copy KCM key to CE : backup is new!!
        //Creates CE key
               old status                                                       new status
        --------------------------------------------------           -----------------------------------------------
        | key name hash | Act ID | Factory ID | Renew ID |           | key name hash| Act ID | Factory ID | Renew ID |
        ---------------------------------------------        =====>    ---------------------------------------------
        | kcm_key1_hash |   1    |     1      |   3      |          | kcm_key1_hash |   1    |     1      |   3      |
        -------------------------------------------------            -------------------------------------------------
                                                                    | ce_key1_hash  |   1    |     1      |   3      |
                                                                      ------------------------------------------------
        */
        //Copy key : copy the content of the source entry fields to destination entry.
        kcm_status = storage_key_copy(item_name, item_name_len, kcm_type, source_item_prefix_type, destination_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy item data");

        //If source_item_prefix type is CE - we need to clean CE id field in backup items,
        //The value is only deleted - not destroyed
        //the CE id value is still present in original item, as it was copied one step before.
        if (source_item_prefix_type == STORAGE_ITEM_PREFIX_CE) {
            /*
                            old status                                                       new status
            --------------------------------------------------           -----------------------------------------------
            | key name hash | Act ID | Factory ID | Renew ID |           | key name hash| Act ID | Factory ID | Renew ID |
            ---------------------------------------------                ---------------------------------------------
            | kcm_key1_hash |   1    |     1      |   3      |           | kcm_key1_hash|   1    |     1      |   3      |
            -------------------------------------------------           --------------------------------------------------
                                                                =====>
            //CE key
            --------------------------------------------------           -----------------------------------------------
            | key name hash | Act ID | Factory ID | Renew ID |           | key name hash| Act ID | Factory ID | Renew ID |
            ---------------------------------------------                ---------------------------------------------
            | ce_key1_hash  |   1    |     1      |   3      |           |  ce_key1_hash|   1    |     1      |   0      |
            -------------------------------------------------           --------------------------------------------------*/
            //Update CE id of backup key to 0
            kcm_status = storage_update_key_id(item_name, item_name_len, kcm_type, STORAGE_ITEM_PREFIX_CE, KSA_CE_PSA_ID_TYPE, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy item data");
        }
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#endif
static kcm_status_e check_items_existence(cs_renewal_names_s *renewal_items_name, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_cert_chain_handle kcm_source_chain_handle;
    size_t kcm_data_size = 0;
    storage_get_data_size_f get_data_size_func;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid renewal_items_name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = ce_private_key_existence((const uint8_t*)renewal_items_name->cs_priv_key_name, (size_t)strlen((char*)renewal_items_name->cs_priv_key_name), item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to check certificate private key %s", renewal_items_name->cs_priv_key_name);

    if (renewal_items_name->cs_pub_key_name != NULL) { //If not LWM2M
        get_data_size_func = (storage_get_data_size_f)storage_func_dispatch(STORAGE_FUNC_GET_SIZE, KCM_PUBLIC_KEY_ITEM);
        kcm_status = get_data_size_func((const uint8_t*)renewal_items_name->cs_pub_key_name, (size_t)strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, item_prefix_type, &kcm_data_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed to get public key size");

        if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
            renewal_items_name->cs_pub_key_name = NULL;
        }
    }

    kcm_status = storage_cert_chain_open(&kcm_source_chain_handle, (const uint8_t*)renewal_items_name->cs_cert_name, strlen((char*)renewal_items_name->cs_cert_name), item_prefix_type, &kcm_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get certificate size");

    kcm_status = storage_cert_chain_close(kcm_source_chain_handle, item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close source chain");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;

}
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
kcm_status_e ce_store_new_keys(cs_renewal_names_s *renewal_items_names, cs_key_handle_t crypto_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    cs_key_pair_context_s *ec_key_ctx = NULL;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid renewal_items_names");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((crypto_handle == NULLPTR), KCM_STATUS_INVALID_PARAMETER, "Invalid crypto handle");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    ec_key_ctx = (cs_key_pair_context_s*)crypto_handle;

    //Store the private key to KCM as original item
    kcm_status = kcm_item_store((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen(renewal_items_names->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, false, ((palCryptoBuffer_t*)ec_key_ctx->generated_priv_key_handle)->buffer, ((palCryptoBuffer_t*)ec_key_ctx->generated_priv_key_handle)->size, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falid to store new private key");

    if (renewal_items_names->cs_pub_key_name != NULL) {
        //Store the public key to KCM as original item
        kcm_status = kcm_item_store((const uint8_t*)renewal_items_names->cs_pub_key_name, strlen(renewal_items_names->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, false, ((palCryptoBuffer_t*)ec_key_ctx->generated_pub_key_handle)->buffer, ((palCryptoBuffer_t*)ec_key_ctx->generated_pub_key_handle)->size, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falid to store new public key");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#else
kcm_status_e ce_store_new_keys(cs_renewal_names_s *renewal_items_names, cs_key_handle_t crypto_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid renewal_items_names");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    PV_UNUSED_PARAM(crypto_handle);

    //Activate private CE key: set CE id value of the original key to ACTIVE id field and zero CE id field
    /* Example:
                   old status                                                       new status
    --------------------------------------------------           -----------------------------------------------
    | key name hash | Act ID | Factory ID | Renew ID |           | key name hash| Act ID | Factory ID | Renew ID |
    ---------------------------------------------                ---------------------------------------------
    | kcm_key1_hash |   1    |     1      |   3      |           | kcm_key1_hash|   3    |     1      |   0      |
    -------------------------------------------------           --------------------------------------------------
    */
    kcm_status = storage_key_activate_ce((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen(renewal_items_names->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falid to store new private key");

    if (renewal_items_names->cs_pub_key_name != NULL) {
        //Activate public CE key: set CE id value of the original key to ACTIVE id field and zero CE id field
        kcm_status = storage_key_activate_ce((const uint8_t*)renewal_items_names->cs_pub_key_name, strlen(renewal_items_names->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falid to store new public key");

    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

#endif
bool ce_set_item_names(const char *item_name, char **private_key_name_out, char **public_key_name_out, char **certificate_name_out)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), false, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_out == NULL), false, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_name_out == NULL), false, "Invalid certificate");
    // public key may be NULL - don't bother to check pointer

    if (pv_str_equals(item_name, g_lwm2m_name, (uint32_t)(strlen(item_name) + 1)) == true) {
        *private_key_name_out = (char*)g_fcc_lwm2m_device_private_key_name;
        *certificate_name_out = (char*)g_fcc_lwm2m_device_certificate_name;
        if (public_key_name_out != NULL) {
            *public_key_name_out = NULL;
        }
    } else {
        *private_key_name_out = (char*)item_name;
        *certificate_name_out = (char*)item_name;
        if (public_key_name_out != NULL) {
            *public_key_name_out = (char*)item_name;
        }
    }
    return true;
}


kcm_status_e ce_private_key_existence(const uint8_t *priv_key_name, size_t priv_key_name_len, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    size_t priv_key_size = 0;
    storage_get_data_size_f get_data_size_func;

    //Check private key
    get_data_size_func = (storage_get_data_size_f)storage_func_dispatch(STORAGE_FUNC_GET_SIZE, KCM_PRIVATE_KEY_ITEM);
    kcm_status = get_data_size_func((const uint8_t*)priv_key_name, (size_t)priv_key_name_len, KCM_PRIVATE_KEY_ITEM, item_prefix_type, &priv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get private key size");

#else
    kcm_key_handle_t key_handle_out = 0;

    //To check key existence try to get its handle
    kcm_status = storage_key_get_handle(priv_key_name, priv_key_name_len, KCM_PRIVATE_KEY_ITEM, item_prefix_type, &key_handle_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get handle of the private key");

    //Close the handle
    kcm_status = storage_key_close_handle(&key_handle_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to close handle of the private key");

#endif
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
//This API called only when all new items were successfully updated
kcm_status_e ce_destroy_old_active_and_remove_backup_entries(cs_renewal_names_s *renewal_items_names)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *public_key_name_pointer = NULL;
    size_t public_key_name_len = 0;


    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names->cs_priv_key_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid private key name");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (renewal_items_names->cs_pub_key_name != NULL) {
        public_key_name_pointer = (uint8_t*)renewal_items_names->cs_pub_key_name;
        public_key_name_len = strlen((char*)renewal_items_names->cs_pub_key_name);
    }

    //Activate private CE key: set CE id value of the original key to ACTIVE id field and zero CE id field
    /* Factory item example of old active id :
                              old status                                                                       new status
    --------------------------------------------------                                            -----------------------------------------------
    | key name hash | Act ID | Factory ID | Renew ID |                                            | key name hash| Act ID | Factory ID | Renew ID |
    -------------------------------------------------                                             -----------------------------------------------
    | kcm_key1_hash |   3    |     1      |   0      |                                            | kcm_key1_hash|   3    |     1      |   0      |
    -------------------------------------------------                                             ------------------------------------------------
    | ce_key1_hash  |   1    |     1      |   3      |   ==>remove the entry ==>                  |              |        |           |           |
    -------------------------------------------------                                             ------------------------------------------------

    Non-Factory item example of old active id :
                          old status                                                                       new status
    --------------------------------------------------                                            -----------------------------------------------
    | key name hash | Act ID | Factory ID | Renew ID |                                            | key name hash| Act ID | Factory ID | Renew ID |
    -------------------------------------------------                                             -----------------------------------------------
    | kcm_key1_hash |   3    |     2      |   0      |                                            | kcm_key1_hash|   3    |     2      |   0      |
    -------------------------------------------------                                             ------------------------------------------------
    | ce_key1_hash  |   1    |     2      |   3      |   ==>destroy(1) =>remove the entry ==>     |              |        |           |           |
    -------------------------------------------------                                             ------------------------------------------------
    */
    //destroy old active id (if non - factory id)  and remove backup entry
    kcm_status = storage_destory_old_active_and_remove_backup_entries((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen((char*)renewal_items_names->cs_priv_key_name), (const uint8_t*)public_key_name_pointer, public_key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get destory and clean backup keys");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#endif
/*! The API deletes set of items (key pair and certificate/certificate chain) according to given name and source type.
*   For PSA configuration : if the keys are original type (KCM item prefix), the keys entries will not be deleted as the need to stay in ksa table
*   and modified with updated keys later.
*
*    @param[in] item_name                pointer to item name.
*    @param[in] item_name_len            length of item name.
*    @param[in] source_data_type         type of data type to verify (backup or original)
*    @param[in] is_public_key                    flag that indicates if public key exists in the storage.
*    @returns
*        CE_STATUS_SUCCESS in case of success or one of the `::ce_status_e` errors otherwise.
*/
kcm_status_e ce_clean_items(cs_renewal_names_s *renewal_items_name, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    int num_of_failures = 0;
    storage_delete_f delete_func;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    //Try to delete private key
    delete_func = (storage_delete_f)storage_func_dispatch(STORAGE_FUNC_DELETE, KCM_PRIVATE_KEY_ITEM);
    kcm_status = delete_func((const uint8_t*)renewal_items_name->cs_priv_key_name, strlen((char*)renewal_items_name->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, item_prefix_type);
#else

    //Remove only if the key is CE storage key, in case of KCM storage key do nothing
    if (item_prefix_type != STORAGE_ITEM_PREFIX_KCM) {

        /*storage_entry_remove API only deletes the entry without any PSA operations
                              old status                                                                          new status
        --------------------------------------------------                                            -----------------------------------------------
        | key name hash | Act ID | Factory ID | Renew ID |                                            | key name hash| Act ID | Factory ID | Renew ID |
        -------------------------------------------------                                             -----------------------------------------------
        | ce_key1_hash  |   1    |     2      |   3      | =>remove the entry (no PSA operations!!)=> |              |        |           |           |
        -------------------------------------------------                                             ------------------------------------------------
        */

        kcm_status = storage_entry_remove((const uint8_t*)renewal_items_name->cs_priv_key_name, strlen((char*)renewal_items_name->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, item_prefix_type);
    }

#endif
    if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        num_of_failures++;
        SA_PV_LOG_ERR("Failed to delete private key");
    }

    if (renewal_items_name->cs_pub_key_name != NULL) {
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
        //Try to delete public key
        delete_func = (storage_delete_f)storage_func_dispatch(STORAGE_FUNC_DELETE, KCM_PUBLIC_KEY_ITEM);
        kcm_status = delete_func((const uint8_t*)renewal_items_name->cs_pub_key_name, strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, item_prefix_type);
#else
        //Remove only if the key is CE storage key, in case of KCM storage key do nothing
        if (item_prefix_type != STORAGE_ITEM_PREFIX_KCM) {
            /*storage_entry_remove API only deletes the entry without any PSA operations

                              old status                                                                       new status
            --------------------------------------------------                                            -----------------------------------------------
            | key name hash | Act ID | Factory ID | Renew ID |                                            | key name hash| Act ID | Factory ID | Renew ID |
            -------------------------------------------------                                             -----------------------------------------------
            | ce_key1_hash  |   1    |     2      |   3      | =>remove the entry (no PSA operations!!)=> |              |        |           |           |
            -------------------------------------------------                                             ------------------------------------------------
            */
            kcm_status = storage_entry_remove((const uint8_t*)renewal_items_name->cs_pub_key_name, strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, item_prefix_type);
        }
#endif
        if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
            num_of_failures++;
            SA_PV_LOG_ERR("Failed to delete public key");
        }
    }

    //Try to delete certificate/certificate chain
    delete_func = (storage_delete_f)storage_func_dispatch(STORAGE_FUNC_DELETE, KCM_CERTIFICATE_ITEM);
    kcm_status = delete_func((const uint8_t*)renewal_items_name->cs_cert_name, strlen((char*)renewal_items_name->cs_cert_name), KCM_CERTIFICATE_ITEM, item_prefix_type);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {//We need to check certificate chain with the same name
        kcm_status = storage_cert_chain_delete((const uint8_t*)renewal_items_name->cs_cert_name, strlen((char*)renewal_items_name->cs_cert_name), item_prefix_type);
    }
    if (kcm_status != KCM_STATUS_SUCCESS  && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        num_of_failures++;
        SA_PV_LOG_ERR("Failed to delete certificate/certificate chain");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    if (num_of_failures != 0) {
        return KCM_STATUS_STORAGE_ERROR;
    }
    return KCM_STATUS_SUCCESS;

}
/*! The API creates a copy of renewal items.
*
*    @param[in] item_name                pointer to item name.
*    @param[in] item_name_len           length of item name.
*    @param[in] is_public_key                    flag that indicates if public key exists in the storage.
*
*    @returns
*        CE_STATUS_SUCCESS in case of success or one of the `::ce_status_e` errors otherwise.
*/

kcm_status_e ce_create_backup_items(cs_renewal_names_s *renewal_items_name)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid renewal_items_name");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    //Backup private key
    kcm_status = copy_kcm_item((const uint8_t*)renewal_items_name->cs_priv_key_name, strlen((char*)renewal_items_name->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Falid to backup private key");

    //Check if public key exists
    if (renewal_items_name->cs_pub_key_name != NULL) {
        //Backup private key
        kcm_status = copy_kcm_item((const uint8_t*)renewal_items_name->cs_pub_key_name, strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, STORAGE_ITEM_PREFIX_CE);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Falid to backup public key");
    }

    //Backup certificate/certificate chain
    kcm_status = copy_kcm_item((const uint8_t*)renewal_items_name->cs_cert_name, strlen((char*)renewal_items_name->cs_cert_name), KCM_CERTIFICATE_ITEM, STORAGE_ITEM_PREFIX_KCM, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Falid to backup certificate");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;

exit:
    //Delete item that was already copied
    ce_clean_items(renewal_items_name, STORAGE_ITEM_PREFIX_CE);
    return kcm_status;
}

/*! The API restores backup items and moves it to original source, if the operation succeeded, the backup items deleted.
*    @param[in] item_name                pointer to item name.
*    @param[in] item_name_len            length of item name.
*    @returns
*        CE_STATUS_SUCCESS in case of success or one of the `::ce_status_e` errors otherwise.
*/
kcm_status_e ce_restore_backup_items(const char *item_name)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    cs_renewal_names_s renewal_items_name = { 0 };
    bool status = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", item_name);

    //Set renewal item names
    status = ce_set_item_names(item_name, (char**)&renewal_items_name.cs_priv_key_name, (char**)&renewal_items_name.cs_pub_key_name, (char**)&renewal_items_name.cs_cert_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Failed to set internal names for items");

    //Check first that backup items exists
    kcm_status = check_items_existence(&renewal_items_name, STORAGE_ITEM_PREFIX_CE);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //One of mandatory backup items is missing -> clean the backup items, do not change original items
        ce_clean_items(&renewal_items_name, STORAGE_ITEM_PREFIX_CE);
        return KCM_STATUS_ITEM_NOT_FOUND;
    } else {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to verify backup items");
    }

    //Clean original items before backup restore
    ce_clean_items(&renewal_items_name, STORAGE_ITEM_PREFIX_KCM);

    //Restore backup items by copying backup items to original source
    //Copy the backup private key to the original private key
    kcm_status = copy_kcm_item((const uint8_t *)renewal_items_name.cs_priv_key_name, strlen((char*)renewal_items_name.cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_CE, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup private key to original source");

    if (renewal_items_name.cs_pub_key_name != NULL) {
        //Copy the backup public key to the original private key
        kcm_status = copy_kcm_item((const uint8_t *)renewal_items_name.cs_pub_key_name, strlen((char*)renewal_items_name.cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_CE, STORAGE_ITEM_PREFIX_KCM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup public key to original source");
    }

    //Copy the backup certificate/certificate chain to the original  certificate/certificate chain
    kcm_status = copy_kcm_item((const uint8_t *)renewal_items_name.cs_cert_name, strlen((char*)renewal_items_name.cs_cert_name), KCM_CERTIFICATE_ITEM, STORAGE_ITEM_PREFIX_CE, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup certificate to original source");

    //Clean backup items after it was restored
    kcm_status = ce_clean_items(&renewal_items_name, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed to clean backup items");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    //At this stage backup entry is no longer exists and original entry is restored with CE id.
    /*                    old status                                                       new status
    --------------------------------------------------           -----------------------------------------------
    | key name hash | Act ID | Factory ID | Renew ID |           | key name hash| Act ID | Factory ID | Renew ID |
    ---------------------------------------------                ---------------------------------------------
    | kcm_key1_hash |   1    |     1      |   3      |           | kcm_key1_hash|   1    |     1      |   3      |
    -------------------------------------------------           --------------------------------------------------
   */
    //During restore backup items we need to destroy CE id of the generated keys as they no longer relevant
    kcm_status = storage_key_id_destroy((const uint8_t *)renewal_items_name.cs_priv_key_name, strlen((char*)renewal_items_name.cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, KSA_CE_PSA_ID_TYPE, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to clean CE id of private key");

    if (renewal_items_name.cs_pub_key_name != NULL) {
        kcm_status = storage_key_id_destroy((const uint8_t *)renewal_items_name.cs_pub_key_name, strlen((char*)renewal_items_name.cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, KSA_CE_PSA_ID_TYPE, STORAGE_ITEM_PREFIX_KCM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to clean CE id of public key");
    }
    /* After storage_key_id_destroy
    --------------------------------------------------                -----------------------------------------------
    | key name hash | Act ID | Factory ID | Renew ID |               | key name hash| Act ID | Factory ID | Renew ID |
    -------------------------------------------------                -----------------------------------------------
    | kcm_key1_hash |   1    |     1      |   3      | destroy(3)==> | kcm_key1_hash|   1    |     1      |          |
    -------------------------------------------------             --------------------------------------------------*/
#endif

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e ce_create_renewal_status(const char *item_name)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    storage_store_f store_func = (storage_store_f)storage_func_dispatch(STORAGE_FUNC_STORE, KCM_CONFIG_ITEM);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", item_name);

    kcm_status = store_func((const uint8_t*)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, false, STORAGE_ITEM_PREFIX_CE, (const uint8_t*)item_name, (size_t)strlen(item_name), NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create renewal status");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e ce_delete_renewal_status(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    storage_delete_f delete_func = (storage_delete_f)storage_func_dispatch(STORAGE_FUNC_DELETE, KCM_CONFIG_ITEM);
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    kcm_status = delete_func((const uint8_t*)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to delete renewal status");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e ce_store_new_certificate(const char *certificate_name, struct cert_chain_context_s *chain_data)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_cert_chain_handle kcm_chain_handle;
    uint32_t cert_index = 0;
    uint8_t *certificate = NULL;
    size_t certificate_size = 0;
    // struct cert_chain_context_s current_chain_data;
    struct cert_context_s *current_certs;
    storage_store_f store_func = (storage_store_f)storage_func_dispatch(STORAGE_FUNC_STORE, KCM_CERTIFICATE_ITEM);

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid certificate_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_data == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid chain_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_data->chain_length == 0), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid certificate chain length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_data->certs == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid certificate data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_data->certs->cert == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid first certificate pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_data->certs->cert_length == 0), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid first certificate length");
    SA_PV_LOG_INFO_FUNC_ENTER("certificate_name =  %s", certificate_name);

    //Get first certificate
    current_certs = chain_data->certs;
    certificate = current_certs->cert;
    certificate_size = current_certs->cert_length;

    if (chain_data->chain_length == 1) {
        //Save single certificate
        kcm_status = store_func((const uint8_t*)certificate_name, (size_t)strlen(certificate_name), KCM_CERTIFICATE_ITEM, false, STORAGE_ITEM_PREFIX_KCM, certificate, certificate_size, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store new certificate");

        return kcm_status;
    } else {
        //Save chain 
        kcm_status = storage_cert_chain_create(&kcm_chain_handle, (const uint8_t*)certificate_name, (size_t)strlen(certificate_name), chain_data->chain_length, false, STORAGE_ITEM_PREFIX_KCM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create chain");

        for (cert_index = 0; cert_index < chain_data->chain_length; cert_index++) {
            SA_PV_ERR_RECOVERABLE_GOTO_IF((certificate_size == 0 || certificate == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, exit, "Invalid certificate data at index %" PRIu32 "", cert_index);

            kcm_status = storage_cert_chain_add_next(kcm_chain_handle, certificate, certificate_size, STORAGE_ITEM_PREFIX_KCM);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to store certificate at index %" PRIu32 "", cert_index);

            //Get next certificate
           // chain_data->certs = chain_data->certs->next;
            current_certs = current_certs->next;
            if (current_certs != NULL) {
                certificate = current_certs->cert;
                certificate_size = current_certs->cert_length;
            }
        }
    }

exit:
    kcm_status = storage_cert_chain_close(kcm_chain_handle, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to close chain");

    return kcm_status;
}
