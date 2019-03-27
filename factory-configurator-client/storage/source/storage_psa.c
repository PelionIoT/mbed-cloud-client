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
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#include <stdbool.h>
#include "key_slot_allocator.h"
#include "pv_error_handling.h"
#include "storage.h"

extern bool g_kcm_initialized;

extern kcm_status_e storage_create_complete_data_name(
    kcm_item_type_e  kcm_item_type,
    kcm_data_source_type_e data_source_type,
    const char *working_dir,
    kcm_chain_cert_name_info_s *cert_name_info,
    const uint8_t *kcm_name,
    size_t kcm_name_len,
    char *kcm_buffer_out);


kcm_status_e storage_import_key(const uint8_t *key_name, size_t key_name_len, kcm_item_type_e key_type, const uint8_t *key, size_t key_size, bool is_factory)
{
    kcm_status_e kcm_status;
    uint8_t raw_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE]; // should be bigger than KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE
    size_t raw_key_act_size;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Convert key from DER to RAW representation before importing to PSA
    if (key_type == KCM_PRIVATE_KEY_ITEM) {
        kcm_status = cs_priv_key_get_der_to_raw(key, key_size, raw_key, sizeof(raw_key), &raw_key_act_size);
    } else { //key_type == KCM_PUBLIC_KEY_ITEM
        kcm_status = cs_pub_key_get_der_to_raw(key, key_size, raw_key, sizeof(raw_key), &raw_key_act_size);
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed converting EC key from DER to RAW");

    //Import the key data to PSA slot
    kcm_status = ksa_store_key_to_psa(key_name, key_name_len, key_type, raw_key, raw_key_act_size, KCM_SCHEME_EC_SECP256R1, is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_KEY_EXIST), KCM_STATUS_FILE_EXIST, "Key exist in PSA Key Slot Allocator");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to import the key to PSA slot");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_export_key(const uint8_t *key_name, size_t key_name_len, kcm_item_type_e key_type, uint8_t *key_data_out, size_t key_data_max_size, size_t *key_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t raw_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE];
    size_t raw_key_act_size;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    kcm_status = ksa_export_key_from_psa(key_name, key_name_len, key_type, raw_key, sizeof(raw_key), &raw_key_act_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed export PSA key data");

    // Convert key from RAW representation to DER
    kcm_status = cs_pub_key_get_raw_to_der(raw_key, raw_key_act_size, key_data_out, key_data_max_size, key_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed converting EC key from RAW to DER");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_destory_key(const uint8_t *key_name, size_t key_name_len)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    kcm_status = ksa_destroy_key(key_name, key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed evacuating a key");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_close_handle(kcm_key_handle_t key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key handle");

    kcm_status = ksa_key_close_handle(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close key handle (%d)", kcm_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    kcm_data_source_type_e key_source_type,
    kcm_key_handle_t *key_h_out)
{
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_key_id_t key_id;
    bool is_key_exist;
    psa_key_handle_t key_handle;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)key_name_len, (char*)key_name, (uint32_t)key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_source_type != KCM_ORIGINAL_ITEM && key_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid key_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != KCM_PRIVATE_KEY_ITEM && key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid key type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_h_out");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }
    //Build complete data name
    kcm_status = storage_create_complete_data_name(key_type, key_source_type, STORAGE_WORKING_ACRONYM, NULL, key_name, key_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

    //Check if current key exists in the storage
    kcm_status = ksa_is_key_exists((const uint8_t *)kcm_complete_name, strlen(kcm_complete_name), &is_key_exist, &key_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during ksa_is_key_exist (%d)", kcm_status);

    if (!is_key_exist) {
        // no, this key has not found in KSA
        kcm_status = KCM_STATUS_ITEM_NOT_FOUND;
        goto Exit;
    }

    //Get key handle
    kcm_status = ksa_key_get_handle(key_id, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get key handle (%d)", kcm_status);

    *key_h_out = (kcm_key_handle_t)key_handle;

    SA_PV_LOG_INFO_FUNC_EXIT("kcm_item_h_out = %" PRIu32 "", (uint32_t)(*key_h_out));

Exit:
    return kcm_status;
}

kcm_status_e storage_key_pair_generate_and_store(
    const kcm_crypto_key_scheme_e     key_scheme,
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    kcm_data_source_type_e            key_source_type,
    bool                              is_factory)
{
    char kcm_complete_priv_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    char kcm_complete_pub_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_key_id_t key_id = 0;
    bool is_keypair_exist;
    uint8_t raw_pub_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE];
    size_t raw_pub_key_size;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Create complete data names
    kcm_status = storage_create_complete_data_name(KCM_PRIVATE_KEY_ITEM, key_source_type, STORAGE_WORKING_ACRONYM, NULL, private_key_name, private_key_name_len, kcm_complete_priv_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");
    if (public_key_name != NULL) {
        kcm_status = storage_create_complete_data_name(KCM_PUBLIC_KEY_ITEM, key_source_type, STORAGE_WORKING_ACRONYM, NULL, public_key_name, public_key_name_len, kcm_complete_pub_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");
    }

    //Check if current private exists in the storage
    kcm_status = ksa_is_key_exists((const uint8_t *)kcm_complete_priv_name, strlen(kcm_complete_priv_name), &is_keypair_exist, &key_id);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed during ksa_is_key_exists (%d)", kcm_status);

    if (!is_keypair_exist && public_key_name != NULL) {
        //Check if current public exists in the storage
        kcm_status = ksa_is_key_exists((const uint8_t *)kcm_complete_pub_name, strlen(kcm_complete_pub_name), &is_keypair_exist, &key_id);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed during ksa_is_key_exists (%d)", kcm_status);

    }

    if (is_keypair_exist) {
        //If current private or public key already exists return the error
        kcm_status = KCM_STATUS_KEY_EXIST;
        goto Exit;
    }

    //Generate and import the generated keypair to PSA slot
    kcm_status = ksa_store_key_to_psa((const uint8_t *)kcm_complete_priv_name, strlen(kcm_complete_priv_name), KCM_PRIVATE_KEY_ITEM, NULL, 0, key_scheme, is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_KEY_EXIST), KCM_STATUS_FILE_EXIST, "Key exist in PSA Key Slot Allocator");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to import the key to PSA slot");

    if (public_key_name != NULL) {
        // read public key from keypair using kcm complete private name
        kcm_status = ksa_export_key_from_psa((const uint8_t *)kcm_complete_priv_name, strlen(kcm_complete_priv_name),KCM_PUBLIC_KEY_ITEM,raw_pub_key,sizeof(raw_pub_key),&raw_pub_key_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "failed to export public key from pair");

        kcm_status = storage_create_complete_data_name(KCM_PUBLIC_KEY_ITEM, key_source_type, STORAGE_WORKING_ACRONYM, NULL, public_key_name, public_key_name_len, kcm_complete_pub_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

        // store public key using different slot
        kcm_status = ksa_store_key_to_psa((const uint8_t *)kcm_complete_pub_name, strlen(kcm_complete_pub_name), KCM_PUBLIC_KEY_ITEM, raw_pub_key, raw_pub_key_size, key_scheme, is_factory);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "failed to import public key");
    }

Exit:
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
