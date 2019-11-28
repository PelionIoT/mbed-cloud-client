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

#ifndef CE_INTERNAL_H
#define CE_INTERNAL_H

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "cs_hash.h"
#include "kcm_defs.h"
#include "est_defs.h"
#include "ce_status.h"
#include "storage_kcm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CE_MAX_SIZE_OF_KCM_ITEM_NAME 100

    /*! The API sets private key, public key and certificate item names according to its base name.
    *
    *    @param[in] item_name                item name string.
    *    @param[in] is_public_key            flag that indicates if public key exists in the storage.
    *
    *    @returns
    *        true/false
    */
    bool ce_set_item_names(const char *item_name, char **private_key_name_out, char **public_key_name_out, char **certificate_name_out);

    /*! The API stores new keys.
    *
    *    @param[in] renewal_items_names       pointer to items namse structure
    *    @param[in] crypto_handle             crypto handle of the new keys.
    *
    *    @returns
    *        true/false
    */
    kcm_status_e ce_store_new_keys(cs_renewal_names_s *renewal_items_names, cs_key_handle_t crypto_handle);

    /*! The API creates a copy of renewal items.
    *
    *    @param[in] renewal_items_name       pointer to items names structure.
    *    @param[in] is_public_key            flag that indicates if public key exists in the storage.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_create_backup_items(cs_renewal_names_s *renewal_items_name);

    /*! The API restores backup items and moves it to original source, if the operation succeeded, the backup items deleted.
    *    @param[in] item_name                item name string.
    *    @param[in] is_public_key            public key flag - indicates if public key is in the storage.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_restore_backup_items(const char *item_name);

    /*! The API checks existance of the private key.
    *    @param[in] priv_key_name            the name of the private key.
    *    @param[in] priv_key_name_len        the private key name length.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_private_key_existence(const uint8_t *priv_key_name, size_t priv_key_name_len, storage_item_prefix_type_e item_prefix_type);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    /*! The API destroys old active id after renewal process was completed successfully and removes backup items.
    *    @param[in] renewal_items_names        Pointer to renewal items names
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_destroy_old_active_and_remove_backup_entries(cs_renewal_names_s *renewal_items_names);

    /*! The API destroys renewal keys if renewal process was interrupted following item correlation check failure.
    *    @param[in] renewal_items_names Pointer to renewal items names
    *    @param[in] data_source_type Storage item prefix type
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_destroy_ce_keys(cs_renewal_names_s *renewal_items_name, storage_item_prefix_type_e data_source_type);
#endif

    /*! The API deletes set of items (key pair and certificate/certificate chain) according to given name and source type.
    *    @param[in] renewal_items_name       item names structure.
    *    @param[in] source_data_type         type of data type to verify (backup or original)
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_clean_items(cs_renewal_names_s *renewal_items_name, storage_item_prefix_type_e data_source_type);

    /*! The API creates renewal status file with item_name data.
    *    @param[in] item_name                item name string.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_create_renewal_status(const char *item_name);

    /*! The API deletes renewal status file.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */

    kcm_status_e ce_delete_renewal_status(void);

    /*! The API stores new certificate/certificate chain to original source.
    *    @param[in] item_name                item name string.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_store_new_certificate(const char *certificate_name, struct cert_chain_context_s *certificate_data);

#ifdef __cplusplus
}
#endif

#endif //CE_INTERNAL_H

