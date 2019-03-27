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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#ifndef KEY_SLOT_ALLOCATOR_H
#define KEY_SLOT_ALLOCATOR_H

#include <stdbool.h>
#include <inttypes.h>
#include "kcm_status.h"
#include "kcm_defs.h"
#include "psa/crypto.h"
#include "psa/crypto_extra.h"
#include "psa/crypto_types.h"


/** The maximum individual keys allow to store in KSA
*/
#define KSA_MAX_TABLE_ENTRIES 15


/** 0 is not a valid slot number under any circumstance
* as defined in psa_crypto.h
*/
#define KSA_INVALID_SLOT_NUMBER 0

#ifdef __cplusplus
extern "C" {
#endif



/** Translates PSA to KCM error codes.
*
* @psa_status[IN] A PSA error code as defined in crypto.h
*
* @returns one of the `::kcm_status_e` errors.
*/
kcm_status_e psa_to_kcm_error(psa_status_t psa_status);

/** Loads and initializes the Key Slot Allocator table
* 
* It loads the KSA table if it is already exists in backend store otherwise
* it will allocates and initializes a new table in volatile memory.
* This function also initializes the PSA crypto module.
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e ksa_init(void);

/** Release the volatile KSA table and finalize PSA Crypto resource.
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e ksa_fini(void);

    /**
    *   Clear the volatile KSA tables (active and backup)
    *   Use this API to clear the tables if the storage is wiped, without using a KCM API (i.e fcc_storage_delete())
    */
    void clear_volatile_ksa_tables(void);

/** Reset Key Slot Allocator to factory initial state by restoring all factory items
* from backend store.
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e ksa_factory_reset(void);

/** Imports the key to PSA slot.
*
* If the given key name already exist in store, the function will return KCM_STATUS_KEY_EXIST status.
*
* @key_name[IN] The complete key name in binary representation
* @key_name_size[IN] The complete key name size in bytes
* @kcm_key_type[IN] KCM key type as defined in `::kcm_item_type_e`
* @key[IN] The key data, if NULL, generate keypair with key_name
* @key_size[IN] The key data size , can be 0 if key is NULL
* @is_factory[IN] set to "true" if this item is factory, "false" otherwise
*
* @returns ::KCM_STATUS_SUCCESS if the given key name occupied a new key slot or one of the `::kcm_status_e` errors in case of an error.
* @        ::KCM_STATUS_KEY_EXIST if the given key name already exist.
*/
kcm_status_e ksa_store_key_to_psa( const uint8_t *key_name,
                                    size_t key_name_size,
                                    kcm_item_type_e kcm_key_type,
                                    const uint8_t *key,
                                    size_t key_size,
                                    kcm_crypto_key_scheme_e curve_name,
                                    bool is_factory);

/** Exports public key from PSA slot.
*
* If the given key name not exists in store, the function will return KCM_STATUS_ITEM_NOT_FOUND status.
*
* @key_name[IN] The complete key name in binary representation
* @key_name_size[IN] The complete key name size in bytes
* @kcm_key_type[IN] KCM key type as defined in `::kcm_item_type_e`
* @key_data_out[IN/OUT] key_data_out output buffer for exported key bytes
* @key_data_max_size[IN] key_data_max_size The size of key_data_out
* @key_data_act_size_out[OUT] key_data_act_size_out Actual bytes written to key_data_out
*
* @returns ::KCM_STATUS_SUCCESS if the given key name occupied a new key slot or one of the `::kcm_status_e` errors in case of an error.
* @        ::KCM_STATUS_KEY_EXIST if the given key name already exist.
*/
kcm_status_e ksa_export_key_from_psa( const uint8_t *key_name,
                                      size_t key_name_size,
                                      kcm_item_type_e kcm_key_type,
                                      uint8_t *key_data_out,
                                      size_t key_data_max_size, 
                                      size_t *key_data_act_size_out);

/** Unlinks and destroys an occupied key slot.
*
* This function unlink the associated key name that was previously linked by
* ksa_link_key_name_to_key_slot() function and makes the given key slot unocupied again.
* It deletes the PSA key slot by invoking to psa_destroy_key() function that destorys the content of the
* key slot from both volatile and non-volatile memory.
*
* @key_name[IN] The key name in binary representation
* @key_name_size[IN] The key name size in bytes
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e ksa_destroy_key(const uint8_t *key_name, size_t key_name_size);

/** Checks if the given key name is already exists and returns the key id.
*
* @key_name[IN] The key name in binary representation
* @key_name_size[IN] The key name size in bytes
* @is_key_exists_out[OUT] "true" if the key name was found, "false" otherwise.
*                   This out parameter is valid only if the status is KCM_STATUS_SUCCESS.
* @key_id_out[OUT] The key handle referred to the given key name, otherwise this out parameter value is undefined.
*                      This out parameter is valid only if the status is KCM_STATUS_SUCCESS and is_key_exit is "true".
*                      In any other case this out parameter value is undefined.
*
* @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
*          The user CAN refer the address pointed by "is_key_exist" ONLY if the returned status was KCM_STATUS_SUCCESS
*          If the returned value is NOT KCM_STATUS_SUCCES then the address pointed by "is_key_exist" is undefined.
*/
kcm_status_e ksa_is_key_exists(const uint8_t *key_name, size_t key_name_size, bool *is_key_exists_out, psa_key_id_t *key_id_out);



/** Returns a key handle if exists
*
* @key_id[IN] The key identifier
* @key_handle_out[OUT] The key handle referred to the given key name, otherwise this out parameter value is undefined.
*                      This out parameter is valid only if the status is KCM_STATUS_SUCCESS and is_key_exit is "true".
*                      In any other case this out parameter value is undefined.
*
* @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e ksa_key_get_handle(psa_key_id_t key_id, psa_key_handle_t *key_handle_out);

/** Closes a key handle 
*
* @key_handle[IN] The key handle
*
* @returns KCM_STATUS_SUCCESS if no error occured or one of the `::kcm_status_e` errors otherwise.
*/

kcm_status_e ksa_key_close_handle(psa_key_handle_t key_handle);

#ifdef __cplusplus
}
#endif

#endif //KEY_SLOT_ALLOCATOR_H
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
