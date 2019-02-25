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
#include "storage.h"

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

    /*! The API creates a copy of renewal items.
    *
    *    @param[in] item_name                item name string.
    *    @param[in] is_public_key            flag that indicates if public key exists in the storage.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_create_backup_items(const char *item_name, bool is_public_key);

    /*! The API restores backup items and moves it to original source, if the operation succeeded, the backup items deleted.
    *    @param[in] item_name                item name string.
    *    @param[in] is_public_key            public key flag - indicates if public key is in the storage.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_restore_backup_items(const char *item_name);

    /*! The API deletes set of items (key pair and certificate/certificate chain) according to given name and source type.
    *    @param[in] item_name                item name string.
    *    @param[in] source_data_type         type of data type to verify (backup or original)
    *    @param[in] is_public_key                    flag that indicates if public key exists in the storage.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e ce_clean_items(const char *item_name, kcm_data_source_type_e data_source_type, bool is_public_key);

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

