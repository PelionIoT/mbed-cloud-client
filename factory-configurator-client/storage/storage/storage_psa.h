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
#ifndef __STORAGE_PSA_H__
#define __STORAGE_PSA_H__

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#include <inttypes.h>
#include "cs_der_keys_and_csrs.h"
#include "key_config_manager.h"
#include "key_slot_allocator.h"
#include "kcm_defs.h"
#include "cs_hash.h"
#include "storage.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

/** Retrieves a handle that refers to a valid existing KCM item in store according to the given data source type (original or backup).
*
*    @param[in] key_name KCM item name.
*    @param[in] key_name_len KCM item name length.
*    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] key_source_type KCM data source type as defined in `::kcm_data_source_type_e`
*    @param[out] key_h_out A handle value that refers the target KCM item in store.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    kcm_data_source_type_e key_source_type,
    kcm_key_handle_t *key_h_out);

/** Closes a key handle.
*
*    @key_handle[in] key handle.
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_close_handle(kcm_key_handle_t key_handle);

/** Imports a key into PSA store.
*
*    @param[in] key_name complete KCM item name.
*    @param[in] key_name_len complete KCM item name length.
*    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] key The key bytes to import.
*    @param[in] key_size The key bytes length.
*    @param[in] is_factory True if the KCM item is a factory item, otherwise false.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_import_key(const uint8_t *key_name, size_t key_name_len, kcm_item_type_e key_type, const uint8_t *key, size_t key_size, bool is_factory);

/** Exports a key into PSA store.
*
*    @param[in] key_name complete KCM item name.
*    @param[in] key_name_len complete KCM item name length.
*    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`. Currently, only `::KCM_PUBLIC_KEY_ITEM`
*    @param[in/out] key_data_out output buffer for exported key bytes
*    @param[in] key_data_max_size The size of key_data_out
*    @param[in] key_data_act_size_out Actual bytes written to key_data_out
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_export_key(const uint8_t *key_name, size_t key_name_len, kcm_item_type_e key_type, uint8_t *key_data_out, size_t key_data_max_size, size_t *key_data_act_size_out);

/** Destroys and evacuates a key from PSA store.
*
*    @param[in] kcm_item_name KCM item name.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_destory_key(const uint8_t *key_name, size_t key_name_len);

/** Generates a key pair according to the given key scheme.
*   The key pair is generated and stored in PSA.
*   The key pair may be used later by calling to _kcm_item_get_handle() with the same supplied name.
*
*    @param key_scheme The cryptographic scheme.
*    @param[in] private_key_name The private key name that will be refer to the generated keypair in PSA.
*    @param[in] private_key_name_len The private key name length.
*    @param[in] key_source_type The private key source type as defined in `::kcm_data_source_type_e.
*    @param[in] is_factory True if the KCM item is a factory item, false otherwise.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_key_pair_generate_and_store(
    const kcm_crypto_key_scheme_e     key_scheme,
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    kcm_data_source_type_e            key_source_type,
    bool                              is_factory);

#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#ifdef __cplusplus
}
#endif

#endif // MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#endif //__STORAGE_PSA_H__
