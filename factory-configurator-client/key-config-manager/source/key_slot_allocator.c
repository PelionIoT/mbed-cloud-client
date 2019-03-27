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
#include "fcc_malloc.h"
#include "kcm_defs.h"
#include "storage.h"
#include "key_slot_allocator.h"
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "psa/crypto_types.h"
#include "psa/crypto.h"

/* TBD: few point to remember for future implementation
*
* 1. The KSA layer MUST always be synced with PSA crypto, we SHOULD use atomic operation when writing / deleting staff from KSA / PSA
* 2. Need to translate PSA to KCM error codes
* 3. Need to optimize allocation method in the future
* 4. KSA_MAX_TABLE_ENTRIES should be derived from KCM
*/

#if KSA_INVALID_SLOT_NUMBER != 0
#error KSA_INVALID_SLOT_NUMBER must be defined as ZERO, e.g.: #define KSA_INVALID_SLOT_NUMBER (0)
#endif

#if KSA_MAX_TABLE_ENTRIES == 0
#error KSA_MAX_TABLE_ENTRIES must be at least 1 or greater, e.g: #define KSA_MAX_TABLE_ENTRIES (5)
#endif

//Max value of PSA id in KSA
#define KSA_MAX_PSA_ID_VALUE   0x2800

/** The Key-Slot-Allocator table name as represent in persistent store
*/
#define KSA_TABLE_FILE_NAME ( "ksa-table" )

// TBD: check alignment issue
/** Key entry self describing object
Examples of key entries:
-------------------------------------------- -
| key name | Act ID | Factory ID | Renew ID |
-------------------------------------------- -
| key_1    |    0   |      3     |    0     |  : deleted factory key (from user's point of view doesn't exists)
-------------------------------------------- 
| key_2    |    2   |     4      |     0    |  : factory key that was updated 
-------------------------------------------- 
| key_3    |    5   |     5      |    0     |  : factory key
-------------------------------------------- 
| key_4    |    8   |      0     |     0    |  : non factory key
--------------------------------------------*/
typedef struct _key_entry {
    uint8_t key_name[KCM_MAX_FILENAME_SIZE];     // the name of the key (in binary) to map against the psa_key_slot
    size_t key_name_size;                        // the name length
    psa_key_id_t  active_key_id;                 // Active key ID - the actual key's ID that should be used for psa operations. Can be 0, if the key is factory and was deleted from storage.
    psa_key_id_t  factory_key_id;                // Factory key ID - the factory keys' ID, can be different from active ID. 0 - if the key is non factory item.
    psa_key_id_t  renewal_key_id;                // Renewal key ID  - updated during renewal certificate process by ID of device generated keys.Not used yet, for future use.
} key_entry_s;

typedef struct _ksa_table {
    key_entry_s tlb[KSA_MAX_TABLE_ENTRIES];               //KSA table in volatile memory
    psa_key_id_t free_id;                                 //Next possible free psa key id
} ksa_table_s;

/** Indicates if the KSA module has been
* initialized or not.
* default: module not initialized
*/
static bool g_ksa_initialized = false;

/** A warehouse of all factory and non-factory items.
* Table always resides in persistent store.
* This table by itself treated as non-factory item
* in persistent store. 
*/
static ksa_table_s g_ksa_table;

static kcm_status_e destroy_psa_key(psa_key_id_t psa_key_id)
{
    psa_status_t psa_status;
    psa_key_handle_t key_handle;
    kcm_status_e  kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_key_id == KSA_INVALID_SLOT_NUMBER), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Invalid key id ");

    //Get PSA key handle 
    kcm_status = ksa_key_get_handle(psa_key_id, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Falied to get key handle ");

    //destroy PSA key
    psa_status = psa_destroy_key(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_to_kcm_error(psa_status), "Failed destorying PSA key ");

    return KCM_STATUS_SUCCESS;
}

/** Destroys a key  from the given KSA volatile table AND from persistent store
* if this function succeed then the target KSA key id will be unoccupied again as well as
* the PSA persistent key will be free.
*
* @key_entry[IN/OUT] The KSA table entry object
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e destroy_non_factory_key_entry(key_entry_s *key_entry)
{
    kcm_status_e kcm_status;

    // if this entry is empty - return normally
    if (key_entry->active_key_id == KSA_INVALID_SLOT_NUMBER) {
        return KCM_STATUS_SUCCESS;
    }

    //Destroy the key
    kcm_status =destroy_psa_key(key_entry->active_key_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destorying PSA key ");

    // wipe form the volatile table
    memset(key_entry, 0, sizeof(*key_entry));

    return KCM_STATUS_SUCCESS;
}

/** Store the given values in the target key slot.
*
* @key_entry[IN/OUT] The target table entry to occupy
* @key_name[IN] The binary key name
* @key_name_size[IN] key name length in bytes
* @psa_key_id[IN] The PSA key id
* @is_factory[IN] set "true" if this item is factory, "false" otherwise
*/
static kcm_status_e fill_entry(key_entry_s *key_entry, const uint8_t *key_name, size_t key_name_size, const psa_key_id_t psa_key_id, bool is_factory)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //1. store key-name and slot in the FACTORY table
    key_entry->key_name_size = key_name_size;
    memcpy(key_entry->key_name, key_name, key_name_size);

    if (is_factory == true) {
        //If factory id of this entry is valid : this factory key is should be destroyed and its id should be overwritten in the table
        if (key_entry->factory_key_id != KSA_INVALID_SLOT_NUMBER) {

            /* Example for current case:
            The key_1 was deleted from active key, but still saved in the table as factory key associated with PSA ID 3
            Now we need to update the key as new factory key and to use PSA ID 14.
            We need to perform these steps:
            1.to destroy PSA IS 3 (step 2 in the code)
            2.update the factory_id with PSA ID 14 (step 3 in the code)
            3.update the active_id with PSA ID 14 (step 4 in the code)
            -------------------------------------------          --------------------------------------------
            | key name | Act ID | Factory ID | Renew ID |        | key name | Act ID | Factory ID | Renew ID |
            ---------------------------------------------  ==>   ---------------------------------------------
            | key_1    |   0    |     3      |   0      |        |   key_1  |   14   |     14      |   0     |
            ---------------------------------------------        ---------------------------------------------
            */
            // 2. Destroy the old factory key key
            kcm_status =destroy_psa_key(key_entry->factory_key_id);
            //In case of error - we don't need to wipe out any data, in this case the same name was already present in the entry
            // and the rest of the data like factory_id and active_id still wasn't updated
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destorying PSA key ");
        }
        //3. Update factory id to new value
        key_entry->factory_key_id = psa_key_id;
    }
    //4. Update active id to new value
    key_entry->active_key_id = psa_key_id;

    return KCM_STATUS_SUCCESS;
}

//Find free PSA key id and create a handle
//The next free PSA id stored and updated in the 0 entry of the  table
static kcm_status_e get_free_psa_key_id_and_handle(psa_key_id_t *psa_key_id_out, psa_key_handle_t *key_handle)
{
    psa_status_t psa_status;
    psa_key_id_t next_psa_id = 0;
    uint32_t id_index = 0;
    bool is_free_id_found = false;

    psa_key_id_t temp_id = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get next free PSA id
    next_psa_id = g_ksa_table.free_id;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((next_psa_id == 0 || next_psa_id > KSA_MAX_PSA_ID_VALUE),  KCM_STATUS_STORAGE_ERROR, "Wrong value of next PSA id");

    /*Try to find a free psa id.
    KSA uses PSA ID from 1 to KSA_MAX_PSA_ID_VALUE.
    The loop starts from a last saved free_id, if all PSA ID from this value and up to KSA_MAX_PSA_ID_VALUE are occupied,
    the loop starts over from 0 up to original value of free_id. In this way the loop searches all psa id range to find an unoccupied id
    ------------------------------------------------------------------
    |                                |                               |
    0                             free_id                        KSA_MAX_PSA_ID_VALUE
                                     ================================>                 the first iteration search all ids from free_id to KSA_MAX_PSA_ID_VALUE
    =================================>                                                 the second iteration search all ids from 0 to free_id
    */
    for (id_index = next_psa_id; id_index <= (uint32_t)KSA_MAX_PSA_ID_VALUE + next_psa_id; id_index++) {
        temp_id = id_index % KSA_MAX_PSA_ID_VALUE;
        if (temp_id != 0) {
            psa_status = psa_create_key(PSA_KEY_LIFETIME_PERSISTENT, temp_id, key_handle);
            if (psa_status == PSA_SUCCESS) {
                is_free_id_found = true;
                break;
            }
        }
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_free_id_found == false), KCM_STATUS_OUT_OF_MEMORY, "Failed to find free PSA ID ");

    //Update out PSA id
    *psa_key_id_out = temp_id;

    //Update next PSA id in table
    g_ksa_table.free_id = ++temp_id;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}
static bool get_ksa_entry_of_deleted_factory_key(const uint8_t *key_name, size_t key_name_size, const ksa_table_s *ksa_table, key_entry_s **empty_ksa_key_entry_out)
{
    uint32_t entry_index;
    /*Search for entries with deleted factory keys, for example:
    ---------------------------------------------
    | key name | Act ID | Factory ID | Renew ID |
    ---------------------------------------------
    | key_1    |    0   |       3    |    0     |
    --------------------------------------------- */
    //Check if current key is was already saved as factory and its active version was deleted ==> use the existing entry.
    for (entry_index = 0; entry_index < KSA_MAX_TABLE_ENTRIES; entry_index++) {
        // check sizes and key bytes
        //Check key name size
        if (ksa_table->tlb[entry_index].key_name_size == key_name_size) {
            //Check key name bytes and active id, if active id is 0 - this is a factory key that was deleted
            if (memcmp(ksa_table->tlb[entry_index].key_name, key_name, key_name_size) == 0 && ksa_table->tlb[entry_index].active_key_id == 0) {
                *empty_ksa_key_entry_out = (key_entry_s *)&(ksa_table->tlb[entry_index]);
                return true;
            }
        }
    }

    return false;
}

static bool get_ksa_free_entry(const ksa_table_s *ksa_table, key_entry_s **empty_ksa_key_entry_out)
{
    uint32_t entry_index;

    // If the key wasn't used - find free KSA slot
    for (entry_index = 0; entry_index < KSA_MAX_TABLE_ENTRIES; entry_index++) {

        //If this entry is not empty continue the search
        if (ksa_table->tlb[entry_index].key_name_size != 0) {
        continue; // this slot is taken, skip next
        }

        // found an empty one...
        *empty_ksa_key_entry_out = (key_entry_s *)&(ksa_table->tlb[entry_index]);
        return true;
    }

    return false;
}

static kcm_status_e get_ksa_entry_for_key(const uint8_t *key_name, size_t key_name_size, const ksa_table_s *ksa_table, key_entry_s **empty_ksa_key_entry_out)
{
    bool is_found = false;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    /*Search for entries with deleted factory keys, for example:
    ---------------------------------------------
    | key name | Act ID | Factory ID | Renew ID |
    ---------------------------------------------
    | key_1    |    0   |       3    |    0     |
    ---------------------------------------------
    For a new key with name "key_1" this is the entry that should be used to store the new data.
    */
    is_found = get_ksa_entry_of_deleted_factory_key(key_name, key_name_size, ksa_table, empty_ksa_key_entry_out);
    if (is_found == true) {
        return KCM_STATUS_SUCCESS;
    }

    //Get empty entry
    is_found = get_ksa_free_entry(ksa_table, empty_ksa_key_entry_out);
    if (is_found == true) {
        return KCM_STATUS_SUCCESS;
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    *empty_ksa_key_entry_out = NULL;
    return KCM_STATUS_INSUFFICIENT_BUFFER; // all slots are occupied
}

static void destroy_volatile_table(ksa_table_s *ksa_table)
{
        // do not leave any trace
        memset(ksa_table, 0, sizeof(ksa_table_s));
}

static kcm_status_e load_table(ksa_table_s *ksa_table)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t ksa_file_size = 0;

    /** check whether the table is already loaded to volatile memory
    * It should be already synced with the backend storage
    */
    if (ksa_table->free_id != KSA_INVALID_SLOT_NUMBER) {
        return KCM_STATUS_SUCCESS;
    }

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // read the table size first
    kcm_status = storage_data_size_read((const uint8_t*)KSA_TABLE_FILE_NAME, strlen(KSA_TABLE_FILE_NAME), KCM_CONFIG_ITEM, KCM_ORIGINAL_ITEM, &ksa_file_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_status != KCM_STATUS_SUCCESS) && (kcm_status != KCM_STATUS_ITEM_NOT_FOUND)), kcm_status, "Failed querying KSA table size (%d)", kcm_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS) && (ksa_file_size != sizeof(ksa_table_s)), KCM_STATUS_STORAGE_ERROR, "Table size in backend store is (%" PRIu32 "B) while we expect (%" PRIu32 "B)", (uint32_t)ksa_file_size, (uint32_t)(sizeof(ksa_table_s)));

    if (kcm_status == KCM_STATUS_SUCCESS) {
        SA_PV_LOG_TRACE("KSA table found in store (table size %" PRIu32 "B)", (uint32_t)(ksa_file_size));

        // try to load table from store (bear in mind that it may not exist)
        // TBD: check if casting could not compromise buffer alignment
        kcm_status = storage_data_read((const uint8_t*)KSA_TABLE_FILE_NAME, strlen(KSA_TABLE_FILE_NAME), KCM_CONFIG_ITEM, KCM_ORIGINAL_ITEM, (uint8_t *)ksa_table, sizeof(ksa_table_s), &ksa_file_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF(((kcm_status != KCM_STATUS_SUCCESS) && (kcm_status != KCM_STATUS_ITEM_NOT_FOUND)), (kcm_status = kcm_status), exit, "Failed reading KSA table from store (%d)", kcm_status);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((sizeof(ksa_table_s) != ksa_file_size), (kcm_status = kcm_status), exit, "Inconsist table size while raeding table from backend store");
    } else {
        SA_PV_LOG_TRACE("No KSA table found in persistent store, allocating table for the first time");
        //Initialize the table
        memset(ksa_table, 0, sizeof(ksa_table_s));

        //Set next free psa id to first entry of the table
        ksa_table->free_id = 1; //The first free id starts from 1
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;

exit:
    destroy_volatile_table(ksa_table);
    return kcm_status;
}

/** Store KSA table to a persistent backend.
*
* This function stores the volatile table to persistent store by
* deleting the persistent table BEFORE writing back the (new) volatile table.
*
* @ksa_table[IN] The target volatile table to store
* @is_factory[IN] Pass "true" if table is for factory purposes, otherwise false.
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e store_table(const ksa_table_s *ksa_table)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_data_delete((const uint8_t*)KSA_TABLE_FILE_NAME, strlen(KSA_TABLE_FILE_NAME), KCM_CONFIG_ITEM, KCM_ORIGINAL_ITEM);
    if ((kcm_status != KCM_STATUS_SUCCESS) && (kcm_status != KCM_STATUS_ITEM_NOT_FOUND)) {
        SA_PV_LOG_ERR("Failed deleting KSA table from store (%d)", kcm_status);
    }

    kcm_status = storage_data_write((const uint8_t*)KSA_TABLE_FILE_NAME, strlen(KSA_TABLE_FILE_NAME), KCM_CONFIG_ITEM, true, KCM_ORIGINAL_ITEM, (const uint8_t *)ksa_table, sizeof(ksa_table_s));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed writing KSA table to store (%d)", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_to_kcm_error(psa_status_t psa_status)
{
    kcm_status_e kcm_status;

    switch (psa_status) {
        case PSA_SUCCESS:
            kcm_status = KCM_STATUS_SUCCESS;
            break;
        case PSA_ERROR_OCCUPIED_SLOT:
            kcm_status = KCM_STATUS_FILE_EXIST;
            break;
        default:
            kcm_status = KCM_STATUS_ERROR;
            break;
    }
    return kcm_status;
}

kcm_status_e ksa_init(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS, kcm_fini_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (g_ksa_initialized) {
        return KCM_STATUS_SUCCESS;
    }

    // clear volatile tables
    memset(&g_ksa_table, 0, sizeof(g_ksa_table));

    // Init PSA crypto
    psa_status = psa_crypto_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), KCM_STATUS_ERROR, "Failed initializing PSA Crypto module (%" PRIu32 ")", (uint32_t)psa_status);

    // Load the table
    kcm_status = load_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), exit, "Failed loading the table (%d)", kcm_status);

    // KSA initialized successfully
    g_ksa_initialized = true;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;

exit:
    kcm_fini_status = ksa_fini();
    if (kcm_fini_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_TRACE("Failed for ksa_fini() while exiting because of an error (status %d)", kcm_fini_status);
    }

    return kcm_status;
}

kcm_status_e ksa_fini(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        return KCM_STATUS_SUCCESS;
    }

    // clear and release KSA volatile tables
    destroy_volatile_table(&g_ksa_table);

    // now it is safe to release PSA crypto which releases all volatile key slots
    mbedtls_psa_crypto_free();

    // mark as uninitialized
    g_ksa_initialized = false;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e ksa_factory_reset(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint32_t entry_index;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    // Load the table
    kcm_status = load_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed loading KSA FACTORY table (%d)", kcm_status);

    for (entry_index = 0; entry_index < KSA_MAX_TABLE_ENTRIES; entry_index++) {

        //Empty entry - continue
        if (g_ksa_table.tlb[entry_index].key_name_size == 0) {
            continue;
        }

        if ((g_ksa_table.tlb[entry_index].factory_key_id == KSA_INVALID_SLOT_NUMBER) &&
            (g_ksa_table.tlb[entry_index].active_key_id != KSA_INVALID_SLOT_NUMBER)) {
            /* Non factory key :
            -------------------------------------------          --------------------------------------------
            | key name | Act ID | Factory ID | Renew ID |        | key name | Act ID | Factory ID | Renew ID |
            ---------------------------------------------  ==>   ---------------------------------------------
            | key_1    |   5    |     0      |   0      |        |          |    0    |     0      |   0     |
            ---------------------------------------------        ---------------------------------------------
            => destroy the key and delete the entry*/
            kcm_status = destroy_non_factory_key_entry(&(g_ksa_table.tlb[entry_index]));
            if (kcm_status != KCM_STATUS_SUCCESS) {
                SA_PV_LOG_ERR("Failed deleting (non-factory) key ");
            }
            continue;
        }

        //Factory key - when the active_id and factory_id the same - do nothing
        if ((g_ksa_table.tlb[entry_index].factory_key_id == g_ksa_table.tlb[entry_index].active_key_id) &&
            (g_ksa_table.tlb[entry_index].active_key_id != KSA_INVALID_SLOT_NUMBER)) {
            /* Factory key : factory_id and active_id are the same:
            -------------------------------------------          --------------------------------------------
            | key name | Act ID | Factory ID | Renew ID |        | key name | Act ID | Factory ID | Renew ID |
            ---------------------------------------------  ==>   ---------------------------------------------
            | key_1    |   7    |     7      |   0      |        |  key_1   |    7    |     7      |   0     |
            ---------------------------------------------        ---------------------------------------------
            */
            continue;
        }

        //Factory key - when the active_id and factory_id are different
        if (g_ksa_table.tlb[entry_index].factory_key_id != KSA_INVALID_SLOT_NUMBER) {

            //If active_id and factory_id valid and different -> destroy the active_id and copy factory_id value to it
            if (g_ksa_table.tlb[entry_index].active_key_id != KSA_INVALID_SLOT_NUMBER) {

                /* Factory key : factory_id and active_id with different values:
                -------------------------------------------          --------------------------------------------
                | key name | Act ID | Factory ID | Renew ID |        | key name | Act ID | Factory ID | Renew ID |
                ---------------------------------------------  ==>   ---------------------------------------------
                | key_1    |   7    |     4      |   0      |        |  key_1   |    4    |     4      |   0     |
                ---------------------------------------------        ---------------------------------------------
                => destroy current active_id and set its factory_id to active_id*/
                //Destroy the key
                kcm_status =destroy_psa_key(g_ksa_table.tlb[entry_index].active_key_id);
                if (kcm_status != KCM_STATUS_SUCCESS) {
                    SA_PV_LOG_ERR("Failed deleting (non-factory) key ");
                }
            }
            /* Factory key : active_id is 0 (the key was deleted):
            -------------------------------------------          --------------------------------------------
            | key name | Act ID | Factory ID | Renew ID |        | key name | Act ID | Factory ID | Renew ID |
            ---------------------------------------------  ==>   ---------------------------------------------
            | key_1    |   0    |     4      |   0      |        |  key_1   |    4    |     4      |   0     |
            ---------------------------------------------        ---------------------------------------------
            =>  set its factory_id to  active_id*/
            //Set factory_id value to active_id
            g_ksa_table.tlb[entry_index].active_key_id = g_ksa_table.tlb[entry_index].factory_key_id;
            continue;
        }//End factory key
    }//End for

    // engage factory reset
    kcm_status = storage_factory_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Storage factory reset failed (%d)", kcm_status);

    //Store the volatile updated table to the storage after factory reset was engaged.
    kcm_status = store_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA table to persistent store");

    return kcm_status;
}

kcm_status_e ksa_key_get_handle(psa_key_id_t key_id, psa_key_handle_t *key_handle_out)
{
    psa_status_t psa_status = PSA_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_id == 0 || key_id > KSA_MAX_PSA_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "Invalid key id ");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Wrong key handle pointer");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    //Open key handle
    psa_status = psa_open_key((psa_key_lifetime_t)PSA_KEY_LIFETIME_PERSISTENT, key_id, key_handle_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle_out == NULL), psa_to_kcm_error(psa_status), "Failed to open the key with  ");

    return KCM_STATUS_SUCCESS;
}

kcm_status_e ksa_key_close_handle(psa_key_handle_t key_handle)
{
    psa_status_t psa_status = PSA_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_handle");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    //Close key handle
    psa_status = psa_close_key(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_to_kcm_error(psa_status), "Failed to close the key");

    return KCM_STATUS_SUCCESS;
}

kcm_status_e ksa_is_key_exists(const uint8_t *key_name, size_t key_name_size, bool *is_key_exists_out, psa_key_id_t *key_id_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint32_t entry_index;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_key_exists_out == NULL), KCM_STATUS_INVALID_PARAMETER, "is_key_exist is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_id_out == NULL), KCM_STATUS_INVALID_PARAMETER, "key_handle_out is NULL");

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    // Load the table
    kcm_status = load_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed loading KSA FACTORY table (%d)", kcm_status);

    for (entry_index = 0; entry_index < KSA_MAX_TABLE_ENTRIES; entry_index++) {
        // check sizes and key bytes
        //Check key name size
        if (g_ksa_table.tlb[entry_index].key_name_size == key_name_size) {
            //Check key name bytes and active id, if active id is 0 - this is a factory key that was deleted
            if (memcmp(g_ksa_table.tlb[entry_index].key_name, key_name, key_name_size) == 0 && g_ksa_table.tlb[entry_index].active_key_id != KSA_INVALID_SLOT_NUMBER) {
                *is_key_exists_out = true; // found it!
                *key_id_out = g_ksa_table.tlb[entry_index].active_key_id;
                return KCM_STATUS_SUCCESS;
            }
        }
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    // not found in KSA neither PSA store
    *is_key_exists_out = false;

    return KCM_STATUS_SUCCESS;
}

kcm_status_e ksa_store_key_to_psa( const uint8_t *key_name,
                                    size_t key_name_size,
                                    kcm_item_type_e kcm_key_type,
                                    const uint8_t *key,
                                    size_t key_size,
                                    kcm_crypto_key_scheme_e curve_name,
                                    bool is_factory)
{
    kcm_status_e kcm_status;
    psa_key_id_t free_psa_key_id = 0;
    key_entry_s *empty_ksa_key_entry = NULL;
    psa_key_id_t  key_id;
    bool is_key_exist = false;
    psa_key_policy_t policy;
    psa_key_handle_t key_handle = 0;
    psa_key_type_t psa_key_type;
    psa_key_usage_t psa_key_usage;
    size_t key_size_bits;
    psa_status_t psa_status = PSA_SUCCESS;
    bool need_to_generate;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    need_to_generate = (key == NULL) && (kcm_key_type == KCM_PRIVATE_KEY_ITEM);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((need_to_generate == false && key == NULL), KCM_STATUS_INVALID_PARAMETER, "Wrong key pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((need_to_generate == false && key_size == 0), KCM_STATUS_INVALID_PARAMETER, "Wrong key size");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    // Load the table
    kcm_status = load_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed loading KSA FACTORY table (%d)", kcm_status);

    // check if key-name already exist in the table
    kcm_status = ksa_is_key_exists(key_name, key_name_size, &is_key_exist, &key_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for ksa_is_key_exists (%d)", kcm_status);

    if (is_key_exist) {
        SA_PV_LOG_TRACE("Key already exist in KSA store (slot %d)", key_id);
        return KCM_STATUS_KEY_EXIST;
    }

    // Get free entry from the table
    kcm_status = get_ksa_entry_for_key(key_name, key_name_size,&g_ksa_table, &empty_ksa_key_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting KSA free slot (%d)", kcm_status);

    // Get free id from PSA store
    kcm_status = get_free_psa_key_id_and_handle(&free_psa_key_id, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting PSA free slot (%d)", kcm_status);

    // convert curve_name to pal_group_id
    switch (curve_name) {
        case KCM_SCHEME_EC_SECP256R1:
            if (kcm_key_type == KCM_PRIVATE_KEY_ITEM) {
                psa_key_type = PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1);
                psa_key_usage = PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY;
                key_size_bits = PSA_BYTES_TO_BITS(32);
            } else { // kcm_key_type == KCM_PUBLIC_KEY_ITEM
                psa_key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1);
                psa_key_usage = PSA_KEY_USAGE_VERIFY;
            }
            break;
        default:
            SA_PV_ERR_RECOVERABLE_GOTO_IF(true, kcm_status = KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE, exit, "unsupported curve name");
    }

    //Set the fields of a policy structure.
    psa_key_policy_set_usage(&policy, psa_key_usage, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    //Set the usage policy on a key slot.
    psa_status = psa_set_key_policy(key_handle,&policy);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_to_kcm_error(psa_status), exit, "Failed to set usage policy (%" PRIu32 ")", (uint32_t)psa_status);

    if (need_to_generate == true) {
        //Generate key pair to slot
        psa_status = psa_generate_key(key_handle, psa_key_type, key_size_bits, NULL, 0);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_to_kcm_error(psa_status), exit, "Failed to generate a key (%" PRIu32 ")", (uint32_t)psa_status);
    } else {
        PV_UNUSED_PARAM(key_size_bits);
        //Import a key in binary format.
        psa_status = psa_import_key(key_handle, psa_key_type, key, key_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_to_kcm_error(psa_status), exit, "Failed to import a key (%" PRIu32 ")", (uint32_t)psa_status);
    }

    //Close a key handle.
    psa_status = psa_close_key(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_to_kcm_error(psa_status), "Failed to close a key handle (%" PRIu32 ")", (uint32_t)psa_status);

    // occupy entry in the the table (although it might be a factory item as well) 
    kcm_status = fill_entry(empty_ksa_key_entry, key_name, key_name_size, free_psa_key_id, is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to update the table entry");

    //store he table
    kcm_status = store_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA  table to persistent memory");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        psa_close_key(key_handle);
    }

    return kcm_status;
}

kcm_status_e ksa_export_key_from_psa( const uint8_t *key_name,
                                      size_t key_name_size,
                                      kcm_item_type_e kcm_key_type,
                                      uint8_t *key_data_out,
                                      size_t key_data_max_size, 
                                      size_t *key_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_key_id_t key_id;
    bool is_key_exist;
    psa_status_t psa_status;
    psa_key_handle_t psa_handle;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_data_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_data_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_data_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_key_type");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    kcm_status = ksa_is_key_exists((const uint8_t *)key_name, key_name_size, &is_key_exist, &key_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during ksa_is_key_exist (%d)", kcm_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!is_key_exist), KCM_STATUS_ITEM_NOT_FOUND, "Key not exist");

    kcm_status = ksa_key_get_handle(key_id, &psa_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get psa handle (%d)", kcm_status);

    psa_status = psa_export_public_key(psa_handle, key_data_out, key_data_max_size, key_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status == PSA_ERROR_OCCUPIED_SLOT), kcm_status = psa_to_kcm_error(psa_status), exit, "PSA slot is occupied");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_to_kcm_error(psa_status), exit, "Failed export PSA key data");

exit:
    kcm_status = ksa_key_close_handle(psa_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close psa handle (%d)", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
kcm_status_e ksa_destroy_key(const uint8_t *key_name, size_t key_name_size)
{
    kcm_status_e kcm_status;
    uint32_t entry_index;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed");
    }

    // Load the table
    kcm_status = load_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed loading KSA FACTORY ");

    /** If current item is factory, we need to keep the entry of the key in the table and initialize its active id.
    In case the active id and factory id are not the same, we need to destroy the active id.
    */

    for (entry_index = 0; entry_index < KSA_MAX_TABLE_ENTRIES; entry_index++) {
        // check sizes and key bytes
        if (g_ksa_table.tlb[entry_index].key_name_size == key_name_size) {
            if (memcmp(g_ksa_table.tlb[entry_index].key_name, key_name, key_name_size) == 0) {

                //Current key is not factory -> destory the entire entry
                if (g_ksa_table.tlb[entry_index].factory_key_id == KSA_INVALID_SLOT_NUMBER) {
                    /* Non factory key should be destory and its entry should be deleted:
                    -------------------------------------------          --------------------------------------------
                    | key name | Act ID | Factory ID | Renew ID |        | key name | Act ID | Factory ID | Renew ID |
                    ---------------------------------------------  ==>   --------------------------------------------- 
                    | key_1    |   4    |     0      |   0      |        |          |    0    |     0      |   0     |
                    ---------------------------------------------        ---------------------------------------------*/
                    kcm_status = destroy_non_factory_key_entry(&(g_ksa_table.tlb[entry_index]));
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroy_non_factory_key_entry");

                    goto exit_and_store;
                } else { //Only factory keys

                    //If the entry exists, but the active id is not valid return KCM_STATUS_ITEM_NOT_FOUND,
                    // from user's point of view the keys doesn't exist.
                    if (g_ksa_table.tlb[entry_index].active_key_id == KSA_INVALID_SLOT_NUMBER) {
                        /* Factory key with active_id = 0 -> already deleted:
                        -------------------------------------------
                        | key name | Act ID | Factory ID | Renew ID |
                        ---------------------------------------------
                        | key_1    |   0    |     7      |   0      |
                        ---------------------------------------------*/
                        return KCM_STATUS_ITEM_NOT_FOUND;
                    }
                    //The key is factory-> we keep the key name and the factory id in the table
                    //If active id is different then factory -> destory the active
                    if (g_ksa_table.tlb[entry_index].active_key_id != g_ksa_table.tlb[entry_index].factory_key_id) {
                        /* Factory key with different valid values of active_id and factory_id:
                        The active_id should be destroyed and set to 0
                        -------------------------------------------             -------------------------------------------
                        | key name | Act ID | Factory ID | Renew ID |           | key name | Act ID | Factory ID | Renew ID |
                        ---------------------------------------------  ===>     ---------------------------------------------
                        | key_1    |   5    |     7      |   0      |           | key_1    |   0    |     7      |   0      |
                        ---------------------------------------------           ---------------------------------------------*/
                        //Destroy the key
                        kcm_status =destroy_psa_key(g_ksa_table.tlb[entry_index].active_key_id);
                        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destorying PSA key ");
                    }
                    /* Factory key with same values of active_id and factory_id:
                    The active_id should be set to 0
                    --------------------------------------------             -------------------------------------------
                    | key name | Act ID | Factory ID | Renew ID |           | key name | Act ID | Factory ID | Renew ID |
                    ---------------------------------------------  ===>     ---------------------------------------------
                    | key_1    |   5    |     5      |   0      |           | key_1    |   0    |     5      |   0      |
                    ---------------------------------------------           ---------------------------------------------*/
                    //Init active id value for all cases
                    g_ksa_table.tlb[entry_index].active_key_id = KSA_INVALID_SLOT_NUMBER;
                    goto exit_and_store;
                }
            }
        }
    }

    return KCM_STATUS_ITEM_NOT_FOUND;
exit_and_store:

    //Store updated volatile table
    kcm_status = store_table(&g_ksa_table);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA volatile table to persistent memory");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
