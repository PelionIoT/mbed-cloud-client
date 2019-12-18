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
#include "fcc_malloc.h"
#include "pv_macros.h"
#include "ce_internal.h"
#include "est_defs.h"
#include "storage_kcm.h"

const char g_lwm2m_name[] = "LWM2M";
const char g_renewal_status_file[] = "renewal_status";

extern const char g_fcc_lwm2m_device_certificate_name[];
extern const char g_fcc_lwm2m_device_private_key_name[];


static kcm_status_e check_items_existence(cs_renewal_names_s *renewal_items_name, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_cert_chain_handle kcm_source_chain_handle;
    size_t kcm_data_size = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid renewal_items_name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = ce_private_key_existence((const uint8_t*)renewal_items_name->cs_priv_key_name, (size_t)strlen((char*)renewal_items_name->cs_priv_key_name), item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to check certificate private key %s", renewal_items_name->cs_priv_key_name);

    if (renewal_items_name->cs_pub_key_name != NULL) { //If not LWM2M
        kcm_status = storage_item_get_data_size((const uint8_t*)renewal_items_name->cs_pub_key_name, (size_t)strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, item_prefix_type, &kcm_data_size);
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
    kcm_status = storage_item_store((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen(renewal_items_names->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, false, STORAGE_ITEM_PREFIX_KCM, 
        ((palCryptoBuffer_t*)ec_key_ctx->generated_priv_key_handle)->buffer, ((palCryptoBuffer_t*)ec_key_ctx->generated_priv_key_handle)->size, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falid to store new private key");

    if (renewal_items_names->cs_pub_key_name != NULL) {
        //Store the public key to KCM as original item
        kcm_status = storage_item_store((const uint8_t*)renewal_items_names->cs_pub_key_name, strlen(renewal_items_names->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, false, STORAGE_ITEM_PREFIX_KCM, 
            ((palCryptoBuffer_t*)ec_key_ctx->generated_pub_key_handle)->buffer, ((palCryptoBuffer_t*)ec_key_ctx->generated_pub_key_handle)->size, true);
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
    kcm_status = storage_ce_key_activate((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen(renewal_items_names->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falid to store new private key");

    if (renewal_items_names->cs_pub_key_name != NULL) {
        //Activate public CE key: set CE id value of the original key to ACTIVE id field and zero CE id field
        kcm_status = storage_ce_key_activate((const uint8_t*)renewal_items_names->cs_pub_key_name, strlen(renewal_items_names->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM);
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

    //Check private key
    kcm_status = storage_item_get_data_size((const uint8_t*)priv_key_name, (size_t)priv_key_name_len, KCM_PRIVATE_KEY_ITEM, item_prefix_type, &priv_key_size);
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
    uint8_t *cert_name_ptr = NULL;
    size_t cert_name_length = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names->cs_priv_key_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid private key name");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (renewal_items_names->cs_pub_key_name != NULL) {
        public_key_name_pointer = (uint8_t*)renewal_items_names->cs_pub_key_name;
        public_key_name_len = strlen((char*)renewal_items_names->cs_pub_key_name);
    }

    cert_name_ptr = (uint8_t*)renewal_items_names->cs_cert_name;
    cert_name_length = strlen(renewal_items_names->cs_cert_name);

    //Activate private CE key: set CE id value of the original key to ACTIVE id field and zero CE id field
    /* Factory item example of old active id :
                              old status                                                                       new status
    --------------------------------------------------                                            -----------------------------------------------
    | item name hash | Act ID | Factory ID | Renew ID |                                           | item name hash| Act ID | Factory ID | Renew ID |
    -------------------------------------------------                                             -----------------------------------------------
    | kcm_item_hash |   3    |     1      |   0      |                                            | kcm_item_hash |   3    |     1      |   0      |
    -------------------------------------------------                                             ------------------------------------------------
    | ce_item_hash  |   1    |     1      |   3      |   ==>remove the entry ==>                  |               |        |           |           |
    -------------------------------------------------                                             ------------ ------------------------------------

    Non-Factory item example of old active id :
                          old status                                                                       new status
    --------------------------------------------------                                             -----------------------------------------------
    | item name hash | Act ID | Factory ID | Renew ID |                                            | item name hash| Act ID | Factory ID | Renew ID |
    -------------------------------------------------                                              -----------------------------------------------
    | kcm_item1_hash |   3    |     2      |   0      |                                            | kcm_key1_hash|   3    |     2      |   0       |
    -------------------------------------------------                                              ------------------------------------------------
    | ce_item1_hash  |   1    |     2      |   3      |   ==>destroy(1) =>remove the entry ==>     |              |        |            |           |
    -------------------------------------------------                                               ------------------------------------------------
    */
    //destroy old active id (if non - factory id)  and remove backup entry
    kcm_status = storage_ce_destory_old_active_and_remove_backup_entries((const uint8_t*)renewal_items_names->cs_priv_key_name, strlen((char*)renewal_items_names->cs_priv_key_name),
        (const uint8_t*)public_key_name_pointer, public_key_name_len, (const uint8_t*)cert_name_ptr, cert_name_length);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get destory and clean backup keys");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ce_destroy_ce_keys(cs_renewal_names_s *renewal_items_name, storage_item_prefix_type_e data_source_type) {

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = storage_ce_destroy_ce_key ((const uint8_t*)renewal_items_name->cs_priv_key_name, strlen(renewal_items_name->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, data_source_type);
    if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        SA_PV_LOG_ERR("Failed to remove ce private key");
    }

    if (renewal_items_name->cs_pub_key_name != NULL) {

        kcm_status = storage_ce_destroy_ce_key ((const uint8_t*)renewal_items_name->cs_pub_key_name, strlen(renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, data_source_type);
        if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
            SA_PV_LOG_ERR("Failed to remove ce public key");
        }
    }
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

    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (item_prefix_type != STORAGE_ITEM_PREFIX_KCM) {
#endif

        kcm_status = storage_ce_clean_item((const uint8_t*)renewal_items_name->cs_priv_key_name, strlen((char*)renewal_items_name->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, item_prefix_type, false);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    }
#endif
    if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        num_of_failures++;
        SA_PV_LOG_ERR("Failed to delete private key");
    }

    if (renewal_items_name->cs_pub_key_name != NULL) {

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
       if (item_prefix_type != STORAGE_ITEM_PREFIX_KCM) {
#endif

            kcm_status = storage_ce_clean_item((const uint8_t*)renewal_items_name->cs_pub_key_name, strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, item_prefix_type, false);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
       }
#endif

        if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
            num_of_failures++;
            SA_PV_LOG_ERR("Failed to delete public key");
        }
    }

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (item_prefix_type != STORAGE_ITEM_PREFIX_KCM) {
#endif

        kcm_status = storage_ce_clean_item((const uint8_t*)renewal_items_name->cs_cert_name, strlen((char*)renewal_items_name->cs_cert_name), KCM_CERTIFICATE_ITEM, item_prefix_type, false);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    }
#endif

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
    kcm_status = storage_ce_item_copy((const uint8_t*)renewal_items_name->cs_priv_key_name, strlen((char*)renewal_items_name->cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Falid to backup private key");

    //Check if public key exists
    if (renewal_items_name->cs_pub_key_name != NULL) {
        //Backup private key
        kcm_status = storage_ce_item_copy((const uint8_t*)renewal_items_name->cs_pub_key_name, strlen((char*)renewal_items_name->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, STORAGE_ITEM_PREFIX_CE);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Falid to backup public key");
    }

    //Backup certificate/certificate chain
    kcm_status = storage_ce_item_copy((const uint8_t*)renewal_items_name->cs_cert_name, strlen((char*)renewal_items_name->cs_cert_name), KCM_CERTIFICATE_ITEM, STORAGE_ITEM_PREFIX_KCM, STORAGE_ITEM_PREFIX_CE);
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    // We need to destroy CE generated private key since we are reverting to original items.
    // We do it before copying the backup keys to the original ones, so the CE key won't be copied
    kcm_status = storage_ce_destroy_ce_key ((const uint8_t*)renewal_items_name.cs_priv_key_name, strlen((char*)renewal_items_name.cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_CE);
    if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
         SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to remove ce private key");
    }
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    kcm_status = storage_ce_item_copy((const uint8_t *)renewal_items_name.cs_priv_key_name, strlen((char*)renewal_items_name.cs_priv_key_name), KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_CE, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup private key to original source");

    if (renewal_items_name.cs_pub_key_name != NULL) {
        //Copy the backup public key to the original private key
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
        // We need to destroy CE generated private key since we are reverting to original items.
        // We do it before copying the backup keys to the original ones, so the CE key won't be copied
        kcm_status = storage_ce_destroy_ce_key ((const uint8_t*)renewal_items_name.cs_pub_key_name, strlen((char*)renewal_items_name.cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_CE);
        if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
            SA_PV_LOG_ERR("Failed to remove ce public key");
        }
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
        kcm_status = storage_ce_item_copy((const uint8_t *)renewal_items_name.cs_pub_key_name, strlen((char*)renewal_items_name.cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_CE, STORAGE_ITEM_PREFIX_KCM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup public key to original source");
    }

    //Copy the backup certificate/certificate chain to the original  certificate/certificate chain
    kcm_status = storage_ce_item_copy((const uint8_t *)renewal_items_name.cs_cert_name, strlen((char*)renewal_items_name.cs_cert_name), KCM_CERTIFICATE_ITEM, STORAGE_ITEM_PREFIX_CE, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup certificate to original source");

    //Clean backup items after it was restored
    kcm_status = ce_clean_items(&renewal_items_name, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed to clean backup items");


    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ce_create_renewal_status(const char *item_name)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", item_name);

    kcm_status = storage_item_store((const uint8_t*)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, false, 
        STORAGE_ITEM_PREFIX_CE, (const uint8_t*)item_name, (size_t)strlen(item_name), true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create renewal status");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}


kcm_status_e ce_delete_renewal_status(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_item_delete((const uint8_t*)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_CE);
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    /* Clean only the active certificate value  in KSA table just before storing the new certificate. We would always like to keep the factory certificate. Backup entry still keeps the original active value.
     * There still  might  be a small issue, since in case of power failure, after we removed the old KCM entry and before we stored a new certificate to KCM entry,we won't be able to restore the original certificate,
     * but it is less signficant than if we would've removed the active value in ce_clear_items flow
    */
    kcm_status = storage_ce_clean_item((const uint8_t*)certificate_name, strlen(certificate_name), KCM_CERTIFICATE_ITEM, STORAGE_ITEM_PREFIX_KCM, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to remove old cert entry");
#endif

    if (chain_data->chain_length == 1) {
        //Save single certificate
        kcm_status = storage_item_store((const uint8_t*)certificate_name, (size_t)strlen(certificate_name), KCM_CERTIFICATE_ITEM, false, 
            STORAGE_ITEM_PREFIX_KCM, certificate, certificate_size, true);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store new certificate");

        return kcm_status;
    } else {
        //Save chain 
        kcm_status = storage_cert_chain_create(&kcm_chain_handle, (const uint8_t*)certificate_name, (size_t)strlen(certificate_name), chain_data->chain_length, false, STORAGE_ITEM_PREFIX_KCM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create chain");

        for (cert_index = 0; cert_index < chain_data->chain_length; cert_index++) {
            SA_PV_ERR_RECOVERABLE_GOTO_IF((certificate_size == 0 || certificate == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, exit, "Invalid certificate data at index %" PRIu32 "", cert_index);

            kcm_status = storage_cert_chain_add_next(kcm_chain_handle, certificate, certificate_size, STORAGE_ITEM_PREFIX_KCM, true);
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
