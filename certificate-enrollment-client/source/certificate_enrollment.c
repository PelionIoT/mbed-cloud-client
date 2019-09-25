// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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
#include <stdbool.h>
#include "pv_error_handling.h"
#include "certificate_enrollment.h"
#include "key_config_manager.h"
#include "pv_macros.h"
#include "fcc_defs.h"
#include "ce_internal.h"

extern const char g_renewal_status_file[];

ce_status_e ce_init(void)
{
    ce_status_e ce_status = CE_STATUS_SUCCESS;

    if (kcm_init() != KCM_STATUS_SUCCESS) {
        ce_status = CE_STATUS_ERROR;
    } else {
        ce_check_and_restore_backup_status();
    }

    return ce_status;
}


ce_status_e ce_error_handler(kcm_status_e kcm_status)
{
    switch (kcm_status) {
        case KCM_STATUS_SUCCESS:
            return CE_STATUS_SUCCESS;
        case KCM_STATUS_INVALID_PARAMETER:
            return CE_STATUS_INVALID_PARAMETER;
        case KCM_STATUS_OUT_OF_MEMORY:
            return CE_STATUS_OUT_OF_MEMORY;
        case KCM_STATUS_INSUFFICIENT_BUFFER:
            return CE_STATUS_INSUFFICIENT_BUFFER;
        case KCM_STATUS_ITEM_NOT_FOUND:
            return CE_STATUS_ITEM_NOT_FOUND;
        case KCM_STATUS_ITEM_IS_EMPTY:
            return CE_STATUS_ITEM_IS_EMPTY;
        default:
            return CE_STATUS_ERROR;
    }
}

ce_status_e ce_generate_keys_and_create_csr_from_certificate(
    const char *certificate_name, cs_renewal_names_s *renewal_items_names, const cs_key_handle_t key_h,
    uint8_t **csr_out, size_t *csr_size_out)
{
    bool success;
    ce_status_e ce_status = CE_STATUS_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *certificate_buff = NULL;
    size_t certificate_buff_max_size = 0, certificate_buff_size = 0, pub_key_size = 0;
    uint8_t *csr_buff = NULL;
    size_t csr_buff_size = 0, csr_buff_max_size;
    uint32_t kcm_crt_name_size = (uint32_t)strlen(certificate_name) + 1; // append null termination

    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_name == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid certificate_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h == 0), CE_STATUS_INVALID_PARAMETER, "Invalid key_h");
    SA_PV_LOG_INFO_FUNC_ENTER("certificate_name = %s key_h = %" PRIuPTR "", certificate_name, key_h);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_out == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid csr_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_size_out == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid csr_size_out");

    // assert NOT a bootstrap device certificate
    success = pv_str_equals(g_fcc_bootstrap_device_certificate_name, certificate_name, kcm_crt_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((success), CE_STATUS_FORBIDDEN_REQUEST, "device bootstrap certificate renewal is not allowed");

    // assert NOT a bootstrap device key
    success = pv_str_equals(g_fcc_bootstrap_device_private_key_name, certificate_name, kcm_crt_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((success), CE_STATUS_FORBIDDEN_REQUEST, "device bootstrap certificate renewal is not allowed");

    //Set names of the renewal items
    success = ce_set_item_names(certificate_name, &renewal_items_names->cs_priv_key_name, &renewal_items_names->cs_pub_key_name, &renewal_items_names->cs_cert_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), CE_STATUS_ITEM_NOT_FOUND, "failed for ce_set_item_names()");

    // Check existence of public key if not LWM2M
    if (renewal_items_names->cs_pub_key_name != NULL) {
        kcm_status = kcm_item_get_data_size((const uint8_t *)renewal_items_names->cs_pub_key_name, strlen(renewal_items_names->cs_pub_key_name), KCM_PUBLIC_KEY_ITEM, &pub_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), ce_error_handler(kcm_status), "failed to get the certificate public key length");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pub_key_size == 0 && kcm_status == KCM_STATUS_SUCCESS), CE_STATUS_ITEM_IS_EMPTY, "got empty public key for certificate %s", renewal_items_names->cs_pub_key_name);
        //If public key doesn't exists set its name renewal_items_names structure to NULL
        if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
            renewal_items_names->cs_pub_key_name = NULL;
        }
    }

    // getting the private key size successfully signifies that the certificate's private key exist and we're okay to continue
    kcm_status = ce_private_key_existence((const uint8_t *)renewal_items_names->cs_priv_key_name, strlen(renewal_items_names->cs_priv_key_name), STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), ce_error_handler(kcm_status), "failed to check certificate private key %s", renewal_items_names->cs_priv_key_name);

    // get the certificate octet length
    kcm_status = kcm_item_get_data_size((const uint8_t *)renewal_items_names->cs_cert_name, strlen(renewal_items_names->cs_cert_name), KCM_CERTIFICATE_ITEM, &certificate_buff_max_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), CE_STATUS_ERROR, "failed to get certificate octet length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_buff_max_size == 0), CE_STATUS_ITEM_IS_EMPTY, "got 0 length for certificate");

    certificate_buff = (uint8_t *)malloc(certificate_buff_max_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_buff == NULL), CE_STATUS_OUT_OF_MEMORY, "failed allocating certificate buffer");

    // get the certificate bytes
    kcm_status = kcm_item_get_data((const uint8_t *)renewal_items_names->cs_cert_name, strlen(renewal_items_names->cs_cert_name), KCM_CERTIFICATE_ITEM, certificate_buff, certificate_buff_max_size, &certificate_buff_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (ce_status = ce_error_handler(kcm_status)), exit, "failed to get certificate buffer");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((certificate_buff_size == 0), (ce_status = CE_STATUS_ITEM_IS_EMPTY), exit, "got 0 length for certificate");

    // we assume that the CSR size would not exceed the certificate size
    csr_buff_max_size = certificate_buff_size;

    csr_buff = (uint8_t *)malloc(csr_buff_max_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((csr_buff == NULL), (ce_status = CE_STATUS_OUT_OF_MEMORY), exit, "Failed allocating CSR buffer");

    kcm_status = cs_generate_keys_and_create_csr_from_certificate(certificate_buff, certificate_buff_size, key_h, renewal_items_names, csr_buff, csr_buff_max_size, &csr_buff_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (ce_status = ce_error_handler(kcm_status)), exit, "failed to generate keys and create CSR");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((csr_buff == NULL), (ce_status = CE_STATUS_ERROR), exit, "failed creating CSR or generating keys for certificate (%s)", renewal_items_names->cs_cert_name);

    // the calling user is responsible to free csr_out buffer
    *csr_out = csr_buff;
    *csr_size_out = csr_buff_size;

    SA_PV_LOG_INFO_FUNC_EXIT("csr_size_out = %" PRIu32 "", (uint32_t)(*csr_size_out));

exit:
    if (certificate_buff != NULL) {
        free(certificate_buff);
    }
    if (ce_status != CE_STATUS_SUCCESS) {
        free(csr_buff);
    }

    return ce_status;
}


ce_status_e ce_safe_renewal(const char *item_name, cs_renewal_names_s *renewal_items_names, ce_renewal_params_s *renewal_data)
{
    ce_status_e ce_status = CE_STATUS_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    struct cert_chain_context_s *certificate_chain_data = NULL;

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_items_names == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid renewal_items_names");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_data == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid renewal_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_data->crypto_handle == (cs_key_handle_t)NULL), CE_STATUS_INVALID_PARAMETER, "Invalid crypto handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((renewal_data->cert_data == NULL), CE_STATUS_INVALID_PARAMETER, "Invalid cert_data");
    certificate_chain_data = (struct cert_chain_context_s*)renewal_data->cert_data;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certificate_chain_data->certs == NULL || certificate_chain_data->chain_length == 0), CE_STATUS_INVALID_PARAMETER, "Invalid certificate data");
    SA_PV_LOG_INFO_FUNC_ENTER("item_name = %s ", item_name);

    //Verify items correlation
    kcm_status = cs_verify_items_correlation(renewal_data->crypto_handle, renewal_data->cert_data->certs->cert, renewal_data->cert_data->certs->cert_length);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), CE_STATUS_RENEWAL_ITEM_VALIDATION_ERROR, "failed to validate renewal items");

    //Create backup items
    kcm_status = ce_create_backup_items(renewal_items_names);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        ce_status = CE_STATUS_ORIGINAL_ITEM_ERROR;
    }
    if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        ce_status = CE_STATUS_BACKUP_ITEM_ERROR;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((ce_status != CE_STATUS_SUCCESS), ce_status = ce_status, exit_and_delete_renewal_data, "failed to create backup items");

    //Create renewal status file and write item_name to the file
    kcm_status = ce_create_renewal_status(item_name);
    if (kcm_status == KCM_STATUS_FILE_EXIST) {
        //Assumption : in case of existing  active renewal process ->ce_safe_renewal api blocked by event loop.
        // So we assume that it is ok to delete renewal status file, as it is impossible that it used by another active renewal process.
        //try to delete existing renewal status file and create new one
        ce_delete_renewal_status();
        kcm_status = ce_create_renewal_status(item_name);
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), ce_status = CE_STATUS_RENEWAL_STATUS_ERROR, exit_and_delete_renewal_data, "failed to create renewal status file");

    //Clean original items
    kcm_status = ce_clean_items(renewal_items_names, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), ce_status = CE_STATUS_STORAGE_ERROR, restore_backup_data, "Falid to clean original items");

    //Store the new keys
    kcm_status = ce_store_new_keys(renewal_items_names, renewal_data->crypto_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), ce_status = CE_STATUS_STORAGE_ERROR, restore_backup_data, "Falid to store new keys");

    //Save new certificate/certificate chain
    kcm_status = ce_store_new_certificate((const char*)renewal_items_names->cs_cert_name, certificate_chain_data);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), ce_status = CE_STATUS_STORAGE_ERROR, restore_backup_data, "Falid to store new certificate/certificate chain");

restore_backup_data:
    if (ce_status != CE_STATUS_SUCCESS) {
        //the restore here done only in case of some error, and at this stage we are not still want to return an original error
        //this is the reason why we don't read the returned error of ce_restore_backup_items API
        ce_restore_backup_items(item_name);
    }

exit_and_delete_renewal_data:

    //Delete renewal status file
    ce_delete_renewal_status();

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (ce_status == CE_STATUS_SUCCESS) {
        //If ce_status was successful - the old active id is no longer relevant we need to destroy it and delete the backup item entries 
        ce_destroy_old_active_and_remove_backup_entries(renewal_items_names);
    }
#endif

    //Clean backup items
    ce_clean_items(renewal_items_names, STORAGE_ITEM_PREFIX_CE);

    return ce_status;
}

/*! The API called during kcm_init() in case of error during renewal_certificate API.
* The functions checks status of the renewal process, restores original data and deletes redundant files.
* The APIs checks the status based on renewal file and its data.
*    @void
*/
void ce_check_and_restore_backup_status(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t renewal_item_data_len = 0;
    size_t act_renewal_item_data_len = 0;
    uint8_t renewal_item_name[CE_MAX_SIZE_OF_KCM_ITEM_NAME] = { 0 };

    //Get renewal status file size
    kcm_status = storage_item_get_data_size((const uint8_t *)g_renewal_status_file, strlen(g_renewal_status_file), KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_CE, &renewal_item_data_len);

    //If renewal status file is not found or failed to get data size -> exit , no data to restore
    if (kcm_status != KCM_STATUS_SUCCESS) {
        if (kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
            SA_PV_LOG_ERR("Failed to read renewal status");//Add error print, as this case is exceptional
        }
        return;
    }
    if (renewal_item_data_len + 1 > sizeof(renewal_item_name)) {
        SA_PV_LOG_ERR("Renewal item name is too big");//Add error print, as this case is exceptional
        return;
    }

    //Read renewal status data
    kcm_status = storage_item_get_data((const uint8_t *)g_renewal_status_file, strlen(g_renewal_status_file), KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_CE, renewal_item_name, renewal_item_data_len, &act_renewal_item_data_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS || act_renewal_item_data_len != renewal_item_data_len), kcm_status = kcm_status, exit, "Failed to read renewal status data");

    //Set null terminator
   // renewal_item_data[renewal_item_data_len] ='\0';
    renewal_item_name[renewal_item_data_len] = '\0';

    //Restore backup items - this will clean all unnecessary data
    kcm_status = ce_restore_backup_items((const char *)renewal_item_name);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, exit, "Failed to restore backup items");

exit:
    //Delete renewal status file
    kcm_status = storage_item_delete((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_CE);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("Failed to delete renewal status");//Add error print, as this case is exceptional
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return;
}

