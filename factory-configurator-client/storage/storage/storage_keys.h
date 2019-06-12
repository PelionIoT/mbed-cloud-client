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

#ifndef __STORAGE_KEYS_H__
#define __STORAGE_KEYS_H__

#include "kcm_status.h"
#include "kcm_defs.h"
#include "storage_items.h"

/**
* For PSA - implemented by storage_psa.c
* For non-PSA - implemented by storage_non_psa.c
*/

/** Retrieves a handle that refers to a valid existing KCM item in store according to the given data source type (original or backup).
*
*    @param[in] key_name KCM item name.
*    @param[in] key_name_len KCM item name length.
*    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] item_prefix_type KCM item prefix type as defined in `::storage_item_prefix_type_e`
*    @param[out] key_h_out A handle value that refers the target KCM item in store.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_key_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    storage_item_prefix_type_e item_prefix_type,
    kcm_key_handle_t *key_h_out);

/** Frees all resources associated the key and sets zero to the handle value.
*
*    @key_handle[in] Pointer to key handle.
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
// Change to get const pointer to key_handle so struct is not passed by value?
kcm_status_e storage_key_close_handle(kcm_key_handle_t *key_handle);

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
    storage_item_prefix_type_e        item_prefix_type,
    bool                              is_factory);

/** Resets storage to a factory state.
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_reset_to_factory_state(void);

#endif // __STORAGE_KEYS_H__
