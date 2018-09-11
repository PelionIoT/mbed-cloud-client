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
#include "storage.h"
#include "fcc_malloc.h"
#include "pv_macros.h"
#include "ce_internal.h"
#include "est_defs.h"


const char g_lwm2m_name[] = "LWM2M";
const char g_renewal_status_file[] = "renewal_status";

extern const char g_fcc_lwm2m_device_certificate_name[];
extern const char g_fcc_lwm2m_device_private_key_name[];

/* The function reads item from storage according to its kcm  and source type, 
the function allocated buffer for the item*/
kcm_status_e ce_get_kcm_data(const uint8_t *parameter_name, 
    size_t size_of_parameter_name,
    kcm_item_type_e kcm_type,
    kcm_data_source_type_e data_source_type,
    uint8_t **kcm_data,
    size_t *kcm_data_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((parameter_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong parameter_name pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((size_of_parameter_name == 0), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong parameter_name size.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data != NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong *kcm_data pointer, should be NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_data_size == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong kcm_data_size pointer.");

    //Get size of kcm data
    kcm_status = _kcm_item_get_data_size(parameter_name,
        size_of_parameter_name,
        kcm_type,
        data_source_type,
        kcm_data_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get kcm data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data_size == 0), kcm_status = KCM_STATUS_ITEM_IS_EMPTY, "KCM item is empty");

    //Allocate memory and get device certificate data
    *kcm_data = fcc_malloc(*kcm_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate buffer for kcm data");

    kcm_status = _kcm_item_get_data(parameter_name, size_of_parameter_name, kcm_type, data_source_type, *kcm_data, *kcm_data_size, kcm_data_size);
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
static kcm_status_e copy_certifcate_chain(const uint8_t *item_name, size_t item_name_len, kcm_data_source_type_e source_type, kcm_data_source_type_e destination_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *item_data = NULL;
    size_t item_data_len = 0;
    kcm_cert_chain_handle kcm_source_chain_handle;
    kcm_cert_chain_handle kcm_destination_chain_handle;
    size_t kcm_chain_len_out = 0;
    size_t  kcm_actual_cert_data_size = 0;
    int cert_index = 0;
    kcm_cert_chain_context_int_s *chain_context;

    //Open chain 
    kcm_status = _kcm_cert_chain_open(&kcm_source_chain_handle, item_name, item_name_len, source_type, &kcm_chain_len_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open chain");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_chain_len_out == 0), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, exit, "Invalid kcm_chain_len_out");

    chain_context = (kcm_cert_chain_context_int_s*)kcm_source_chain_handle;

    //Current item is a single certificate 
    if (chain_context->is_meta_data == false && kcm_chain_len_out == 1) {
        //Read the item from source 
        kcm_status = ce_get_kcm_data(item_name, item_name_len, KCM_CERTIFICATE_ITEM, source_type, &item_data, &item_data_len);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to get item data");

        //Save the item as backup item
        kcm_status = _kcm_item_store(item_name, item_name_len, KCM_CERTIFICATE_ITEM, false, item_data, item_data_len, destination_type);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to copy item data");
    }  else {
        //Current item is certificate chian
        for (cert_index = 1; cert_index <= (int)kcm_chain_len_out; cert_index++)
        {

            //Create destination chain for start
            if (cert_index == 1) {
                kcm_status = _kcm_cert_chain_create(&kcm_destination_chain_handle, item_name, item_name_len, kcm_chain_len_out, false, destination_type);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to create destination chain");
            }
            //Get next certificate data size from source chain
            kcm_status = _kcm_cert_chain_get_next_size(kcm_source_chain_handle, source_type, &item_data_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to _kcm_cert_chain_get_next_sizen");

            //Allocate memory and get  certificate data from source chain
            item_data = fcc_malloc(item_data_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((item_data == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, exit_and_close, "Failed to allocate buffer for kcm data");

            //Get next certificate data
            kcm_status = _kcm_cert_chain_get_next_data(kcm_source_chain_handle, item_data, item_data_len, source_type, &kcm_actual_cert_data_size);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to get certificate kcm data");
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_actual_cert_data_size != item_data_len), kcm_status = kcm_status, exit_and_close, "Wrong certificate data size");

            //Add the data to destination chain
            kcm_status = _kcm_cert_chain_add_next(kcm_destination_chain_handle, item_data, item_data_len, destination_type);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit_and_close, "Failed to add data to chain");

            //free allocated buffer
            fcc_free(item_data);
            item_data = NULL;
        }
        //Close destination chain
exit_and_close:
        kcm_status = _kcm_cert_chain_close(kcm_destination_chain_handle, destination_type);
         SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit,"Failed to close destination chain");

    }

exit:
        if (item_data != NULL) {
            fcc_free(item_data);
        }
        //close source chain
        kcm_status = _kcm_cert_chain_close(kcm_source_chain_handle, source_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close source chain");

        return kcm_status;

}
static kcm_status_e copy_kcm_item(const uint8_t *item_name, size_t item_name_len, kcm_item_type_e kcm_type, kcm_data_source_type_e source_type, kcm_data_source_type_e destination_type)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *item_data = NULL;
    size_t item_data_len = 0;

    //Read the data
    if (kcm_type == KCM_CERTIFICATE_ITEM) {

        //copy certificate chain 
        kcm_status = copy_certifcate_chain(item_name, item_name_len, source_type, destination_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy chain");
    }  else { //not certificate
        //Read the item from source 
        kcm_status = ce_get_kcm_data(item_name, item_name_len, kcm_type, source_type, &item_data, &item_data_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get item data");

        //Save the item as backup item
        kcm_status = _kcm_item_store(item_name, item_name_len, kcm_type, false, item_data, item_data_len, destination_type);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to copy item data");
    }

exit:
    if (item_data != NULL) {
        fcc_free(item_data);
    }
    return kcm_status;

}

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

static kcm_status_e check_items_existence(const char *item_name, kcm_data_source_type_e source_type, bool *is_public_key)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_cert_chain_handle kcm_source_chain_handle;
    size_t kcm_data_size = 0;
    uint8_t *private_key_name = NULL;
    uint8_t *public_key_name = NULL;
    uint8_t *certificate_name = NULL;
    bool local_is_public_key = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(!(ce_set_item_names(item_name, (char**)&private_key_name, (char**)&public_key_name, (char**)&certificate_name)), KCM_STATUS_INVALID_PARAMETER, "Failed to set internal names for items");

    //Check private key
    kcm_status = _kcm_item_get_data_size((const uint8_t*)private_key_name,(size_t)strlen((char*)private_key_name), KCM_PRIVATE_KEY_ITEM, source_type, &kcm_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get private key size");

    if (public_key_name != NULL) {
        kcm_status = _kcm_item_get_data_size((const uint8_t*)public_key_name, (size_t)strlen((char*)public_key_name), KCM_PUBLIC_KEY_ITEM, source_type, &kcm_data_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed to get public key size");

        if (kcm_status == KCM_STATUS_SUCCESS) {
            local_is_public_key = true;
        }
    } 

    kcm_status = _kcm_cert_chain_open(&kcm_source_chain_handle, (const uint8_t*)certificate_name, strlen((char*)certificate_name), source_type, &kcm_data_size);
     SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get certificate size");

    kcm_status = _kcm_cert_chain_close(kcm_source_chain_handle, source_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close source chain");

    *is_public_key = local_is_public_key;
    return kcm_status;

}
/*! The API deletes set of items (key pair and certificate/certificate chain) according to given name and source type.
*    @param[in] item_name                pointer to item name.
*    @param[in] item_name_len            length of item name.
*    @param[in] source_data_type         type of data type to verify (backup or original)
*    @param[in] is_public_key                    flag that indicates if public key exists in the storage.
*    @returns
*        CE_STATUS_SUCCESS in case of success or one of the `::ce_status_e` errors otherwise.
*/
kcm_status_e ce_clean_items(const char *item_name, kcm_data_source_type_e data_source_type, bool is_public_key)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    int num_of_failures = 0;
    uint8_t *private_key_name = NULL;
    uint8_t *public_key_name = NULL;
    uint8_t *certificate_name = NULL;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s",  item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(!(ce_set_item_names(item_name, (char**)&private_key_name, (char**)&public_key_name, (char**)&certificate_name)), KCM_STATUS_INVALID_PARAMETER, "Failed to set internal names for items");

    //Try to delete private key
    kcm_status = _kcm_item_delete((const uint8_t*)private_key_name, strlen((char*)private_key_name), KCM_PRIVATE_KEY_ITEM, data_source_type);
    if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        num_of_failures++;
        SA_PV_LOG_ERR("Failed to delete private key");
    }

    if (is_public_key == true && public_key_name != NULL)
    {
        //Try to delete public key
        kcm_status = _kcm_item_delete((const uint8_t*)public_key_name, strlen((char*)public_key_name), KCM_PUBLIC_KEY_ITEM, data_source_type);
        if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
            num_of_failures++;
            SA_PV_LOG_ERR("Failed to delete public key");
        }
    }

    //Try to delete certificate/certificate chain
    kcm_status = _kcm_item_delete((const uint8_t*)certificate_name, strlen((char*)certificate_name), KCM_CERTIFICATE_ITEM, data_source_type);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {//We need to check certificate chain with the same name
        kcm_status = _kcm_cert_chain_delete((const uint8_t*)certificate_name, strlen((char*)certificate_name), data_source_type);
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

kcm_status_e ce_create_backup_items(const char *item_name, bool is_public_key)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *private_key_name = NULL;
    uint8_t *public_key_name = NULL;
    uint8_t *certificate_name = NULL;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(!(ce_set_item_names(item_name, (char**)&private_key_name, (char**)&public_key_name, (char**)&certificate_name)), KCM_STATUS_INVALID_PARAMETER, "Failed to set internal names for items");

    //Backup private key
    kcm_status = copy_kcm_item(private_key_name, strlen((char*)private_key_name), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM, KCM_BACKUP_ITEM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit,  "Falid to backup private key");

    //Check if public key exists
    if (is_public_key == true && public_key_name != NULL) {
        //Backup private key
        kcm_status = copy_kcm_item(public_key_name, strlen((char*)public_key_name), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM, KCM_BACKUP_ITEM);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit , "Falid to backup public key");
    }

    //Backup certificate/certificate chain
    kcm_status = copy_kcm_item((const uint8_t*)certificate_name, strlen((char*)certificate_name), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM, KCM_BACKUP_ITEM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit , "Falid to backup certificate");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;

exit:
    //Delete item that was already copied
    ce_clean_items(item_name, KCM_BACKUP_ITEM, is_public_key);
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
    uint8_t *private_key_name = NULL;
    uint8_t *public_key_name = NULL;
    uint8_t *certificate_name = NULL;

    bool is_public_key_in_storage = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s",item_name);

    //Check first that backup items exists
    kcm_status = check_items_existence(item_name, KCM_BACKUP_ITEM, &is_public_key_in_storage);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //One of mandatory backup items is missing -> clean the backup items, do not change original items
        ce_clean_items(item_name, KCM_BACKUP_ITEM, true);
        return KCM_STATUS_ITEM_NOT_FOUND;
    } else {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to verify backup items");
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF(!(ce_set_item_names(item_name,(char**)&private_key_name, (char**)&public_key_name, (char**)&certificate_name)), KCM_STATUS_INVALID_PARAMETER, "Failed to set internal names for items");

 
    //Clean original items before backup restore
    ce_clean_items(item_name, KCM_ORIGINAL_ITEM, true);

    //Restore backup items by copying backup items to original source
    kcm_status = copy_kcm_item(private_key_name, strlen((char*)private_key_name), KCM_PRIVATE_KEY_ITEM, KCM_BACKUP_ITEM, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup private key to original source");

    if (is_public_key_in_storage == true && public_key_name != NULL) {
        kcm_status = copy_kcm_item(public_key_name, strlen((char*)public_key_name), KCM_PUBLIC_KEY_ITEM, KCM_BACKUP_ITEM, KCM_ORIGINAL_ITEM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup public key to original source");
    }

    kcm_status = copy_kcm_item(certificate_name, strlen((char*)certificate_name), KCM_CERTIFICATE_ITEM, KCM_BACKUP_ITEM, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to copy backup certificate to original source");
 
    //Clean backup items after it was restored
    kcm_status = ce_clean_items(item_name,KCM_BACKUP_ITEM, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed to clean backup items");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();


    return kcm_status;
}

kcm_status_e ce_create_renewal_status(const char *item_name)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", item_name);

    kcm_status = _kcm_item_store((const uint8_t*)g_renewal_status_file,(size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, false,(const uint8_t*)item_name, (size_t)strlen(item_name),KCM_BACKUP_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create renewal status");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e ce_delete_renewal_status(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    kcm_status = _kcm_item_delete((const uint8_t*)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM);
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

    if (chain_data->chain_length == 1) {
        //Save single certificate
        kcm_status = _kcm_item_store((const uint8_t*)certificate_name,(size_t)strlen(certificate_name), KCM_CERTIFICATE_ITEM, false, certificate, certificate_size, KCM_ORIGINAL_ITEM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store new certificate");

        return kcm_status;
    } else {
         //Save chain 
        kcm_status = _kcm_cert_chain_create(&kcm_chain_handle, (const uint8_t*)certificate_name,(size_t) strlen(certificate_name), chain_data->chain_length, false, KCM_ORIGINAL_ITEM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create chain");

        for (cert_index = 0; cert_index < chain_data->chain_length ; cert_index++)
        {
            SA_PV_ERR_RECOVERABLE_GOTO_IF((certificate_size == 0 || certificate == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, exit, "Invalid certificate data at index %" PRIu32 "", cert_index);

            kcm_status =  _kcm_cert_chain_add_next(kcm_chain_handle, certificate, certificate_size, KCM_ORIGINAL_ITEM);
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
    kcm_status = _kcm_cert_chain_close(kcm_chain_handle, KCM_ORIGINAL_ITEM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to close chain");

    return kcm_status;
}
