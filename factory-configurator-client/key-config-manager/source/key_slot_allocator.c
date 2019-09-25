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
#include "key_slot_allocator.h"
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "psa_driver.h"
#include "psa_driver_dispatcher.h"
#include "storage_internal.h"
#include "key_slot_allocator_internal.h"


/** The Key-Slot-Allocator table hard-coded PSA TS(trusted storage) id value
*/
typedef enum {
    KSA_PS_LAST_FREE_CRYPTO_ID_RESERVED_TYPE = PSA_PS_MIN_RESERVED_VALUE,
    KSA_VERSION_ID_VAL_RESERVED_TYPE,                //KSA version table uid
    KSA_KEY_TABLE_ID_RESERVED_TYPE,                  //KSA keys table uid 
    KSA_CFG_PARAMS_TABLE_ID_RESERVED_TYPE,           //KSA config params table uid 
    KSA_CERT_TABLE_ID_RESERVED_TYPE,                 //KSA certificates (with chains) table uid 
    KSA_RBP_TABLE_ID_RESERVED_TYPE,                  //KSA Rollback Protected items uid 
    KSA_MAX_ID_RESERVED_TYPE
}ksa_reserved_id_type_e;

//Storage location masks
#define KSA_LOCATION_MASK                       0x3 // use this with item_extra_info to get storage location

//KSA table version number
#define KSA_TABLE_VERSION  0x01
//KSA location mask


/* TBD: few point to remember for future implementation
*
* 1. The KSA layer MUST always be synced with PSA crypto, we SHOULD use atomic operation when writing / deleting staff from KSA / PSA
* 2. Need to translate PSA to KCM error codes
* 3  KSA_MAX_TABLE_ENTRIES should be derived from KCM
*/

#if KSA_INVALID_SLOT_NUMBER != 0
#error KSA_INVALID_SLOT_NUMBER must be defined as ZERO, e.g.: #define KSA_INVALID_SLOT_NUMBER (0)
#endif

#if KSA_INITIAL_TABLE_ENTRIES == 0
#error KSA_INITIAL_TABLE_ENTRIES must be at least 1 or greater, e.g: #define KSA_INITIAL_TABLE_ENTRIES (5)
#endif

/** The Key-Slot-Allocator buffer name as represent in persistent store
*/
#define KSA_BUFFER_FILE_NAME ( "ksa-buffer" ) 

/* size of item_name hash in bytes
*/
#define KSA_ITEM_NAME_HASH_SIZE_IN_BYTES  32

/** Item entry self describing object
Examples of item entries:
-------------------------------------------------
| item name hash| Act ID | Factory ID | Renew ID |
-------------------------------------------------
| 123           |    0   |      3     |    0     |  : deleted factory item (from user's point of view doesn't exists)
-------------------------------------------------
| 234           |    2   |      4     |     0    |  : factory item that was updated
--------------------------------------------------
| 345           |    5   |      5     |    0     |  : factory item
-------------------------------------------------
| 456           |    8   |      0     |     0    |  : non factory item
-------------------------------------------------*/

// #pragma pack directive makes sure that the below structs are packed to a single byte.
// It is supported by the following toolchains, GCC, GCC_ARM, ARMC6, IAR
#pragma pack(push, 1)

/**
* A single ksa table entry
*/
typedef struct _ksa_item_entry {
    uint8_t   item_name_hash[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES];   // the hash of item name to map against the psa id
    uint16_t  active_item_id;    // Active item ID - the actual item's ID that should be used for psa operations. Can be 0, if the item is factory and was deleted from storage. 
    uint16_t  factory_item_id;   // Factory item ID - the factory item' ID, can be different from active ID. 0 - if the item is non factory item. 
    uint16_t  renewal_item_id;   // Renewal item ID  - updated during renewal certificate process by ID of device generated items
    uint8_t   item_extra_info;  // Item info - 2 LSB indicate item location:
                                /* 00 - non psa
                                   01- psa
                                   02 - secure element
                                */
    uint16_t  reserved1;        //reserved for future use
    uint16_t  reserved2;        //reserved for future use
} ksa_item_entry_s;

#pragma pack(pop)

/**
* ksa descriptor
* contains metadata for ksa_buffer and managed by ksa module
*/
typedef struct ksa_descriptor {
    uint16_t ksa_table_uid;          // KSA table uid in PSA TS
    ksa_item_entry_s* ksa_start_entry;        //start of KSA table
    ksa_item_entry_s *ksa_last_occupied_entry;  // pointer to last slot that contains at least single valid psa_id (active, factory or renewal)
    uint32_t ksa_num_of_table_entries;     // ksa buffer size 
} ksa_descriptor_s;

//descriptor for KSA tables 
static ksa_descriptor_s  g_ksa_desc[KSA_LAST_ITEM] = { {0} };

/** Indicates if the KSA module has been
* initialized or not.
* default: module not initialized
*/
static bool g_ksa_initialized = false;


/*
* calculate sha256 of item name
*/
static kcm_status_e calculate_item_name_hash(const uint8_t *item_name, size_t item_name_size, uint8_t* item_name_hash)
{
    palStatus_t pal_status;

    //calculate sha256 of item_name
    pal_status = pal_sha256(item_name, item_name_size, item_name_hash);
    if (pal_status != PAL_SUCCESS) {
        return KCM_STATUS_ERROR;
    }
    return KCM_STATUS_SUCCESS;
}


static kcm_status_e get_ksa_item_entry(const uint8_t* item_name_hash, ksa_item_type_e item_type, ksa_item_entry_s **ksa_item_entry_out, bool *is_new_entry, bool perform_realloc)
{
    uint32_t current_table_index = (uint32_t)item_type;
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    uint32_t num_of_entries = g_ksa_desc[current_table_index].ksa_num_of_table_entries;
    ksa_item_entry_s* ksa_entry = (ksa_item_entry_s*)(g_ksa_desc[current_table_index].ksa_start_entry);
    uint8_t zero_buffer[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES] = { 0 };
    *is_new_entry = true;

    //Check if current item was already saved as factory and its active version was deleted ==> use the existing entry.
    for (uint32_t ksa_entry_index = 0; ksa_entry_index < num_of_entries; ksa_entry_index++, ksa_entry++) {

        /*first, check for empty slot. KSA table design guarantees that there are no occupied slots after an empty one
        -------------------------------------------------
        | item name hash | Act ID | Factory ID | Renew ID |
        --------------------------------------------------
        | 0000          |    0   |       0    |    0     |
        ------------------------------------------------- */
        if (memcmp(ksa_entry->item_name_hash, zero_buffer, KSA_ITEM_NAME_HASH_SIZE_IN_BYTES) == 0) {
            *ksa_item_entry_out = ksa_entry;
            return KCM_STATUS_SUCCESS;
        }

        //Check if the same item_name_hash already exists in the table in ase we search an entry for specific item name and not just an empty entry
        if (memcmp(ksa_entry->item_name_hash, item_name_hash, KSA_ITEM_NAME_HASH_SIZE_IN_BYTES) == 0) {

            /* if active item is present, item already exist in KSA table.
            ---------------------------------------------
            | item name hash | Act ID | Factory ID | Renew ID |
            ---------------------------------------------
            | 123           |    2   |       0    |    0     |
            --------------------------------------------- */
            if (ksa_entry->active_item_id != KSA_INVALID_SLOT_NUMBER) {
                *ksa_item_entry_out = ksa_entry; // item already exists! Nothing to do
                *is_new_entry = false;
                return KCM_STATUS_FILE_EXIST;
            }

            // if active item is not present, we can use that slot
            /*Search for entries with deleted factory items, for example:
            ---------------------------------------------
            | item name hash | Act ID | Factory ID | Renew ID |
            ---------------------------------------------
            | 123           |    0   |       3    |    0     |
            --------------------------------------------- */
            if ((ksa_entry->active_item_id == KSA_INVALID_SLOT_NUMBER) && (ksa_entry->factory_item_id != KSA_INVALID_SLOT_NUMBER)) {
                *ksa_item_entry_out = ksa_entry;
                *is_new_entry = false; // no new entry used (using the same entry where factory id resides)
                return KCM_STATUS_SUCCESS;
            }
        }
    }

    if (perform_realloc == true) {
        SA_PV_LOG_INFO("The existing KSA table is too small, reallocating bigger table");

        uint32_t new_ksa_table_size = num_of_entries * 2;
        g_ksa_desc[current_table_index].ksa_start_entry = realloc(g_ksa_desc[current_table_index].ksa_start_entry, (sizeof(ksa_item_entry_s) * new_ksa_table_size));
        SA_PV_ERR_RECOVERABLE_RETURN_IF((g_ksa_desc[current_table_index].ksa_start_entry == NULL), KCM_STATUS_OUT_OF_MEMORY, "Failed to reallocate ksa_buffer");

        // set the new allocated buffer to zero
        memset((void*)(g_ksa_desc[current_table_index].ksa_start_entry + num_of_entries), 0x0, sizeof(ksa_item_entry_s) *num_of_entries);

        //set the ksa_last_occupied_entry pointer to the last slot of the old table
        g_ksa_desc[current_table_index].ksa_last_occupied_entry = (ksa_item_entry_s*)(g_ksa_desc[current_table_index].ksa_start_entry + num_of_entries - 1);

        //the next empty slot is the first one of the additional slots in the new table
        *ksa_item_entry_out = (ksa_item_entry_s*)(g_ksa_desc[current_table_index].ksa_start_entry + num_of_entries);

        //update the size of the new table
        g_ksa_desc[current_table_index].ksa_num_of_table_entries = new_ksa_table_size;
    }


    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


/* Returns KCM_STATUS_FILE_EXIST if ACTIVE entry is available for a given item_name and returns a pointer to the entry
 *
 */
static kcm_status_e get_ksa_existing_entry(const uint8_t *item_name, size_t item_name_size, ksa_item_type_e item_type, ksa_item_entry_s **table_entry)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name_hash[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES];
    bool is_new_entry = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((table_entry == NULL), KCM_STATUS_INVALID_PARAMETER, "table_entry is NULL");
    SA_PV_LOG_TRACE_FUNC_ENTER("item_name = %s len = %" PRIu32 " item_type = %" PRIu32"", (char*)item_name, (uint32_t)item_name_size, (uint32_t)item_type);

    //calculate item name hash
    kcm_status = calculate_item_name_hash(item_name, item_name_size, (uint8_t*)item_name_hash);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to calulate item name hash (%d)", kcm_status);

    //Get an entry of the existing item
    kcm_status = get_ksa_item_entry((const uint8_t*)item_name_hash, item_type, table_entry, &is_new_entry, false);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_FILE_EXIST), kcm_status = KCM_STATUS_ITEM_NOT_FOUND, "Failed to get_ksa_item_entry");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


/** Store KSA table to a persistent backend.
*
* This function stores the volatile table to persistent store by
* deleting the persistent table BEFORE writing back the (new) volatile table.
*
* @table_descriptor[IN] The target volatile table descriptor.
*
* @returns ::KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e store_table(ksa_descriptor_s *table_descriptor)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Save the new table
    kcm_status = psa_drv_ps_set_data_direct(table_descriptor->ksa_table_uid,
        (const void*)table_descriptor->ksa_start_entry,
                                            (size_t)(table_descriptor->ksa_num_of_table_entries * sizeof(ksa_item_entry_s)), PSA_PS_CONFIDENTIALITY_FLAG);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to set a new table");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


static void destroy_ksa_tables()
{

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    for (int table_index = KSA_KEY_ITEM; table_index < KSA_LAST_ITEM; table_index++) {

        if (g_ksa_desc[table_index].ksa_start_entry != NULL) {
            // free allocated ksa_buffer
            free(g_ksa_desc[table_index].ksa_start_entry);
            g_ksa_desc[table_index].ksa_start_entry = NULL;
        }

        /*invalidate  ksa descriptor of the table*/
        memset(&g_ksa_desc[table_index], 0x0, sizeof(ksa_descriptor_s));
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
}


static kcm_status_e set_entry_id(ksa_item_entry_s *item_entry, ksa_id_type_e item_id_type, uint16_t id_value)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_entry == NULL), KCM_STATUS_INVALID_PARAMETER, "table_entry is NULL");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Set the value to id field
    switch (item_id_type) {
        case KSA_ACTIVE_PSA_ID_TYPE:
            item_entry->active_item_id = id_value;
            break;
        case KSA_FACTORY_PSA_ID_TYPE:
            item_entry->factory_item_id = id_value;
            break;
        case KSA_CE_PSA_ID_TYPE:
            item_entry->renewal_item_id = id_value;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid item_entry type");
    }

    //Save the table
    kcm_status = store_table(&g_ksa_desc[item_id_type]);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA table to persistent store");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


static void  ksa_copy_entry(const uint8_t* item_name_hash, const ksa_item_entry_s *source_entry, ksa_item_entry_s *destination_entry)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Set the destination item name field
    memcpy(destination_entry->item_name_hash, item_name_hash, KSA_ITEM_NAME_HASH_SIZE_IN_BYTES);

    //Copy the rest of the information
    destination_entry->active_item_id = source_entry->active_item_id;
    destination_entry->factory_item_id = source_entry->factory_item_id;
    destination_entry->renewal_item_id = source_entry->renewal_item_id;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

}


/*
* copies last occupied entry in KSA table to freed entry in order to avoid
* fragmentation in KSA table
*/
//TBD: for power failure protection, might need to check the whole table
static void squeeze_item_entries(ksa_item_entry_s *item_entry, ksa_item_type_e ksa_item_type)
{

    ksa_item_entry_s* last_occupied_entry = g_ksa_desc[ksa_item_type].ksa_last_occupied_entry;

    //copy ksa_item_entry_s parameters of ksa_last_occupied_entry to the destroyed entry.
    if (item_entry != last_occupied_entry) {
        memcpy(item_entry, last_occupied_entry, sizeof(ksa_item_entry_s));
        memset(last_occupied_entry, 0, sizeof(ksa_item_entry_s));

    }

    /*update ksa_last_occupied_entry*/
    if (last_occupied_entry == (ksa_item_entry_s*)(g_ksa_desc[ksa_item_type].ksa_start_entry)) {
        //if the last occupied slot was the only one in the table, set last occupied slot to NULL
        last_occupied_entry = NULL;
    } else {
        //otherwise, point to previous slot
        last_occupied_entry--;
    }

    g_ksa_desc[ksa_item_type].ksa_last_occupied_entry = last_occupied_entry;
}


/**
* find last occupied slot in KSA table
*/
static ksa_item_entry_s* find_last_occuppied_slot(ksa_item_entry_s *table_start_entry, uint32_t num_of_entries)
{
    ksa_item_entry_s* last_occupied_slot;
    ksa_item_entry_s* current_table_entry = table_start_entry;
    uint8_t zero_buffer[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES] = { 0 };

    last_occupied_slot = NULL;
    //TBD: consider go over the entire table to check if there are any fragmentations. Needed for power failure protection 
    for (uint32_t ksa_entry_index = 0; ksa_entry_index < num_of_entries; ksa_entry_index++, current_table_entry++) {
        if (memcmp(current_table_entry->item_name_hash, zero_buffer, KSA_ITEM_NAME_HASH_SIZE_IN_BYTES) != 0) {
            last_occupied_slot = current_table_entry;
        }
    }
    return last_occupied_slot;
}


static kcm_status_e store_item_to_entry(ksa_item_entry_s *item_entry, ksa_item_type_e ksa_item_type, bool is_new_entry, const uint8_t *item_name_hash, const uint16_t  psa_item_id, bool is_factory, ksa_type_location_e item_location)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //1. store item-name hash in the slot
    memcpy(item_entry->item_name_hash, item_name_hash, KSA_ITEM_NAME_HASH_SIZE_IN_BYTES);

    if (is_factory == true) {
        //If factory id of this entry is valid : this factory item is should be destroyed and its id should be overwritten in the table
        if (item_entry->factory_item_id != KSA_INVALID_SLOT_NUMBER) {

            /* Example for current case:
            The item_1 was deleted from active item, but still saved in the table as factory item associated with PSA ID 3
            Now we need to update the item as new factory item and to use PSA ID 14.
            We need to perform these steps:
            1.to destroy PSA IS 3 (step 2 in the code)
            2.update the factory_id with PSA ID 14 (step 3 in the code)
            3.update the active_id with PSA ID 14 (step 4 in the code)
            --------------------------------------------------          --------------------------------------------
            | item name hash | Act ID | Factory ID | Renew ID |       | item name hash | Act ID | Factory ID | Renew ID |
            ---------------------------------------------        ==>   ---------------------------------------------
            | 123           |   0    |     3      |   0      |        |   123         |   14   |     14      |   0     |
            --------------------------------------------------        ---------------------------------------------
            */
            // 2. Destroy the old factory item id
            // Use dispatcher to determinate "delete" function
            psa_drv_delete_f delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, ksa_item_type, item_location);
            //Call delete function
            kcm_status = delete_data(item_entry->factory_item_id);

            //In case of error - we don't need to wipe out any data, in this case the same name was already present in the entry
            // and the rest of the data like factory_id and active_id still wasn't updated
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying PSA item ");
        }
        //3. Update factory id to new value
        item_entry->factory_item_id = psa_item_id;
    }
    //4. Update active id to new value
    item_entry->active_item_id = psa_item_id;
    item_entry->item_extra_info = item_location;

    //5. update g_ksa_desc.ksa_last_occupied_entry only if totally new entry was used, otherwise last_occupied slot didn't change!
    if (is_new_entry) {
        g_ksa_desc[ksa_item_type].ksa_last_occupied_entry = item_entry;
    }

    return KCM_STATUS_SUCCESS;
}


static kcm_status_e remove_item_from_entry(ksa_item_entry_s *ksa_item_entry, ksa_item_type_e ksa_type)
{
    //invalidate active_item_id entry
    ksa_item_entry->active_item_id = KSA_INVALID_SLOT_NUMBER;

    if (ksa_item_entry->factory_item_id == KSA_INVALID_SLOT_NUMBER) {
        //remove the whole entry if this is non-factory item
        squeeze_item_entries(ksa_item_entry, ksa_type);
    }
    return KCM_STATUS_SUCCESS;
}


static kcm_status_e init_ksa_tables()
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint16_t table_id = 0;
    size_t data_size = 0;
    size_t actual_data_size = 0;
    uint32_t version_number = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Check version table number
    kcm_status = psa_drv_ps_get_data(KSA_VERSION_ID_VAL_RESERVED_TYPE, &version_number, sizeof(version_number), &actual_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS || actual_data_size != sizeof(version_number)), kcm_status, "Failed to read version number");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((version_number > KSA_TABLE_VERSION_NUM), kcm_status = KCM_STATUS_ERROR, "Wrong version number");


    //Init ksa tables
    for (int table_index = KSA_KEY_ITEM; table_index < KSA_LAST_ITEM; table_index++) {

        data_size = 0;
        actual_data_size = 0;

        table_id = (uint16_t)(KSA_KEY_TABLE_ID_RESERVED_TYPE + table_index);

        //Set table uid
        g_ksa_desc[table_index].ksa_table_uid = table_id;

        if (g_ksa_desc[table_index].ksa_start_entry == NULL) {//If the table is not loaded

            SA_PV_LOG_TRACE("KSA table at id 0x%x is not loaded, performing initialization", g_ksa_desc[table_index].ksa_table_uid);

            //Check if the table file is in the storage
            kcm_status = psa_drv_ps_get_data_size(g_ksa_desc[table_index].ksa_table_uid, &data_size);
            SA_PV_ERR_RECOVERABLE_GOTO_IF(((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND)), kcm_status = kcm_status, exit, "Failed to read reserved file");

            //If the table is not in the storage - create a new table and store it
            if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {

                SA_PV_LOG_TRACE("KSA table at id 0x%x is not found in the storage, creating a new file", g_ksa_desc[table_index].ksa_table_uid);

                //Allocate memory of initial size for the start pointer of the table
                g_ksa_desc[table_index].ksa_start_entry = malloc(sizeof(ksa_item_entry_s) * KSA_INITIAL_TABLE_ENTRIES);
                //init the allocated memory
                memset(g_ksa_desc[table_index].ksa_start_entry, 0x0, sizeof(ksa_item_entry_s) * KSA_INITIAL_TABLE_ENTRIES);

                //Set the table
                kcm_status = psa_drv_ps_set_data_direct(g_ksa_desc[table_index].ksa_table_uid, g_ksa_desc[table_index].ksa_start_entry, sizeof(ksa_item_entry_s) * KSA_INITIAL_TABLE_ENTRIES, PSA_PS_CONFIDENTIALITY_FLAG);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to store the table");

                //update the size of the table
                g_ksa_desc[table_index].ksa_num_of_table_entries = KSA_INITIAL_TABLE_ENTRIES;
                //update the last occupied_entry
                g_ksa_desc[table_index].ksa_last_occupied_entry = NULL;

            } else { //If the table is in the storage

                SA_PV_LOG_TRACE("KSA table at id 0x%x found in the store (table size %" PRIu32 "B)", g_ksa_desc[table_index].ksa_table_uid, (uint32_t)(data_size));

                //Allocate a memory to read the table according to it's size in the storage
                g_ksa_desc[table_index].ksa_start_entry = malloc(data_size);

                //get the table data
                kcm_status = psa_drv_ps_get_data(g_ksa_desc[table_index].ksa_table_uid, g_ksa_desc[table_index].ksa_start_entry, data_size, &actual_data_size);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS || actual_data_size != data_size), kcm_status = kcm_status, exit, "Failed to get the table data");

                //update number of entries
                g_ksa_desc[table_index].ksa_num_of_table_entries = (uint32_t)(data_size / sizeof(ksa_item_entry_s));

                //update pointer to last occupied entry
                g_ksa_desc[table_index].ksa_last_occupied_entry = find_last_occuppied_slot(g_ksa_desc[table_index].ksa_start_entry, g_ksa_desc[table_index].ksa_num_of_table_entries);
            }
        } else {//Table is loaded - nothing to do
            SA_PV_LOG_TRACE("KSA table at id 0x%x is already loaded", g_ksa_desc[table_index].ksa_table_uid);
        }
    }//Loop of the tables

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;

exit:
    destroy_ksa_tables();
    return kcm_status;
}


static ksa_item_type_e get_ksa_type(uint32_t item_type)
{
    switch (item_type) {
        case KCM_PRIVATE_KEY_ITEM:
        case KCM_PUBLIC_KEY_ITEM:
            return KSA_KEY_ITEM;
        case KCM_CERTIFICATE_ITEM:
            return KSA_CERTIFICATE_ITEM;
        case STORAGE_RBP_ITEM:
            return KSA_RBP_ITEM;
        case KCM_CONFIG_ITEM:
        case KCM_SYMMETRIC_KEY_ITEM:
            return KSA_CONFIG_ITEM;
        default:
            return KSA_LAST_ITEM;
    }
}

static kcm_status_e set_psa_driver_flags(uint32_t item_type, uint32_t storage_flags, uint32_t *psa_flags)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    switch (item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            *psa_flags = PSA_CRYPTO_PRIVATE_KEY_FLAG;
            break;
        case KCM_PUBLIC_KEY_ITEM:
            *psa_flags = PSA_CRYPTO_PUBLIC_KEY_FLAG;
            break;
        case KCM_CERTIFICATE_ITEM:
        case KCM_CONFIG_ITEM:
        case KCM_SYMMETRIC_KEY_ITEM:
        case STORAGE_RBP_ITEM:
            *psa_flags = storage_flags;
            break;
        default:
            return KCM_STATUS_INVALID_PARAMETER;
    }
    return kcm_status;
}


/*==============================================main flow KSA implementation =========================================*/

kcm_status_e ksa_init(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint32_t version_value = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (g_ksa_initialized) {
        return KCM_STATUS_SUCCESS;
    }

    // Init PSA crypto
    kcm_status = psa_drv_crypto_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, "Failed initializing PSA Crypto driver (%" PRIu32 ")", (uint32_t)kcm_status);

    //Init ksa version file
    version_value = KSA_TABLE_VERSION;
    kcm_status = psa_drv_ps_init_reserved_data(KSA_VERSION_ID_VAL_RESERVED_TYPE, (const void*)&version_value, sizeof(version_value));
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to initialize ksa version (%" PRIu32 ")", (uint32_t)kcm_status);

    //Init ksa tables 
    kcm_status = init_ksa_tables();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to initialize ksa tables (%" PRIu32 ")", (uint32_t)kcm_status);

    // KSA initialized successfully
    g_ksa_initialized = true;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;

exit:

    ksa_fini();
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
    destroy_ksa_tables();

    // Call crypto driver finilize - now it is safe to release PSA crypto which releases all volatile item slots
    psa_drv_crypto_fini();

    // mark as uninitialized
    g_ksa_initialized = false;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e ksa_item_store(const uint8_t *item_name,
                            size_t item_name_length,
                            uint32_t storage_flags,
                            uint32_t item_type,
                            const uint8_t *item_data,
                            size_t item_data_size,
                            ksa_type_location_e ksa_item_location,
                            bool kcm_item_is_factory)
{
    kcm_status_e kcm_status;
    uint16_t psa_item_id = 0;
    ksa_item_entry_s *empty_ksa_item_entry = NULL;
    bool need_to_generate = false;
    bool is_new_entry = true;
    char item_name_hash[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES];
    uint32_t ps_flags = 0;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    need_to_generate = (item_data == NULL) && (item_type == (kcm_item_type_e)KCM_PRIVATE_KEY_ITEM);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No item name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy item name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((ksa_item_type != KSA_CONFIG_ITEM && ksa_item_type != KSA_RBP_ITEM && need_to_generate == false) && (item_data == NULL)),
                                    KCM_STATUS_INVALID_PARAMETER, "Wrong item pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((ksa_item_type != KSA_CONFIG_ITEM  && ksa_item_type != KSA_RBP_ITEM && need_to_generate == false) && (item_data_size == 0)),
                                    KCM_STATUS_INVALID_PARAMETER, "Wrong item size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_item_type == KSA_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Wrong item type");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    //Set driver flags
    kcm_status = set_psa_driver_flags(item_type, storage_flags, &ps_flags);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to set ps flags");

    //calculate item name hash
    kcm_status = calculate_item_name_hash(item_name, item_name_length, (uint8_t*)item_name_hash);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to calulate item name hash (%d)", kcm_status);

    //Get an entry of the existing item
    kcm_status = get_ksa_item_entry((const uint8_t*)item_name_hash, ksa_item_type, &empty_ksa_item_entry, &is_new_entry, true);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_FILE_EXIST && ksa_item_type != KSA_RBP_ITEM), kcm_status, "Item already exist in KSA store");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS) && ksa_item_type != KSA_RBP_ITEM, kcm_status, "Failed getting KSA free slot (%d)", kcm_status);

    //special case for RBP existing items. Their value can be overridden (if not defined as WRITE_ONCE)
    if ((ksa_item_type == KSA_RBP_ITEM) && (kcm_status == KCM_STATUS_FILE_EXIST)) {

        //store the item directy to PSA PS
        kcm_status = psa_drv_ps_set_data_direct(empty_ksa_item_entry->active_item_id, item_data, item_data_size, ps_flags);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store RBP item");
        //nothing to do anymore, return
        goto exit;
    }

    //Use dispatcher to determinate store function
    psa_drv_store_f store_func = (psa_drv_store_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_WRITE, ksa_item_type, ksa_item_location);

    //Call store function
    kcm_status = store_func((const void*)item_data, item_data_size, ps_flags, &psa_item_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store the item");

    // occupy entry in the the table (although it might be a factory item as well) 
    kcm_status = store_item_to_entry(empty_ksa_item_entry, ksa_item_type, is_new_entry, (uint8_t*)item_name_hash, psa_item_id, kcm_item_is_factory, ksa_item_location);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to update the table entry");

    //store the table of the item
    kcm_status = store_table(&g_ksa_desc[ksa_item_type]);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA  table to persistent memory");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

exit:
    return kcm_status;
}


kcm_status_e ksa_item_get_data_size(const uint8_t *item_name,
                                    size_t item_name_length,
                                    uint32_t item_type,
                                    size_t *item_data_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_entry_s *table_item_entry = NULL;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);
    // char item_name_hash[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES];
    // bool is_new_entry = false;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_data_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_data_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_type == KCM_PRIVATE_KEY_ITEM || ksa_item_type == KSA_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    kcm_status = get_ksa_existing_entry(item_name, item_name_length, ksa_item_type, &table_item_entry);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, "Failed to get item entry");

    //Use dispatcher to determinate read data function
    psa_drv_get_data_size_f read_size_func = (psa_drv_get_data_size_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_READ_SIZE, ksa_item_type, (ksa_type_location_e)(table_item_entry->item_extra_info & KSA_LOCATION_MASK));

    //Call read item function
    kcm_status = read_size_func(table_item_entry->active_item_id, item_data_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to read the item size");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ksa_item_get_data(const uint8_t *item_name,
                               size_t item_name_length,
                               uint32_t item_type,
                               uint8_t *item_data_out,
                               size_t item_data_max_size,
                               size_t *item_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_entry_s *table_item_entry = NULL;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);
    // char item_name_hash[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES];
     //bool is_new_entry = false;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_item_type != KSA_CONFIG_ITEM && item_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_data_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_item_type != KSA_CONFIG_ITEM && item_data_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid item_data_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_data_act_size_out pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_type == KCM_PRIVATE_KEY_ITEM || ksa_item_type == KSA_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    kcm_status = get_ksa_existing_entry(item_name, item_name_length, ksa_item_type, &table_item_entry);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, "Failed to get item entry");

    //Use dispatcher to determinate read data function
    psa_drv_get_data_f read_func = (psa_drv_get_data_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_READ, ksa_item_type, (ksa_type_location_e)(table_item_entry->item_extra_info & KSA_LOCATION_MASK));

    //Call read item function
    kcm_status = read_func(table_item_entry->active_item_id, item_data_out, item_data_max_size, item_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to read the item");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ksa_item_delete(const uint8_t *item_name,
                             size_t item_name_length,
                             uint32_t item_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);
    ksa_item_entry_s *ksa_item_entry = NULL;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_item_type >= KSA_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Wrong item type");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    kcm_status = get_ksa_existing_entry(item_name, item_name_length, ksa_item_type, &ksa_item_entry);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, "Failed to get item entry");

    /*We proceed only if active items are valid!*/

    if (ksa_item_entry->active_item_id != ksa_item_entry->factory_item_id) {
        //The item is factory-> we keep the item name and the factory id in the table
        //If active id is different then factory -> destroy the active

        /* Factory item with different valid values of active_id and factory_id:
        The active_id should be destroyed and set to 0
        --------------------------------------------------             -----------------------------------------------
        | item name hash | Act ID | Factory ID | Renew ID |          | item name hash| Act ID | Factory ID | Renew ID |
        ---------------------------------------------        ===>     ---------------------------------------------
        | 425           |   5    |     7      |   0      |           | 425          |   0    |     7      |   0      |
        -------------------------------------------------           --------------------------------------------------*/
        //Destroy the item
        // Use dispatcher to determinate "delete" function
        psa_drv_delete_f delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, ksa_item_type,
            (ksa_type_location_e)(ksa_item_entry->item_extra_info & KSA_LOCATION_MASK));
        //Call delete function
        kcm_status = delete_data(ksa_item_entry->active_item_id);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying PSA item ");
    }

    //remove item from  ksa entry
    kcm_status = remove_item_from_entry(ksa_item_entry, ksa_item_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed removing PSA item from entry");

    //Store updated volatile table
    kcm_status = store_table(&g_ksa_desc[ksa_item_type]);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA volatile table to persistent memory");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ksa_reset(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;

    /*
     * Currently we can't use the item by item removal, since it in not possible to remove RBP "write once" items.
     * For now, we will use pal_fsRmFiles() to reset storage in Linux and pal_SSTReset() for SST.
     * Item by item removal implementation is under #if 0
    */

#ifdef __LINUX__ //reset for Linux
    //remove the PSA_STORAGE_FILE_C_STORAGE_PREFIX directory. This should be removed once lifecycle/psa storage removal API is implemented
    char dir_path[PAL_MAX_FOLDER_DEPTH_CHAR + 1] = { 0 };

    pal_status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FOLDER_DEPTH_CHAR + 1, dir_path);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_ERROR, "Failed to get mount point");

    pal_status = pal_fsRmFiles(dir_path);
#else
    //remove call to psa_ps_reset() once lifecycle/psa storage removal API is implemented
    extern psa_status_t psa_ps_reset();
    pal_status = psa_ps_reset();
#endif

#if 0
    psa_drv_delete_f delete_data;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    //Go over all tables
    for (uint32_t table_index = KSA_KEY_ITEM; table_index < KSA_LAST_ITEM; table_index++) {

        //pointer to the beginning of table entries
        ksa_item_entry_s *table_entry = (ksa_item_entry_s*)g_ksa_desc[table_index].ksa_start_entry;
        //pointer to the end of table entries
        ksa_item_entry_s *last_occupied_entry = g_ksa_desc[table_index].ksa_last_occupied_entry;

        //Check all the entries and destroy all slots
        for (int entry_index = 0; table_entry <= last_occupied_entry; entry_index++, table_entry++) {

            if (table_entry->active_item_id != KSA_INVALID_SLOT_NUMBER && table_entry->active_item_id == table_entry->factory_item_id) { //Active and factory with the same value
                delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, table_index, (ksa_type_location_e)(table_entry->item_extra_info & (uint8_t)KSA_LOCATION_MASK));
                //Call delete function
                kcm_status = delete_data(table_entry->active_item_id);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying active and factory id ");

            } else {//Active and factory with different values
                if (table_entry->active_item_id != KSA_INVALID_SLOT_NUMBER) {//Delete active
                    delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, table_index, (ksa_type_location_e)(table_entry->item_extra_info & (uint8_t)KSA_LOCATION_MASK));
                    //Call delete function
                    kcm_status = delete_data(table_entry->active_item_id);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying active id ");
                }
                if (table_entry->factory_item_id != KSA_INVALID_SLOT_NUMBER) {//Delete factory
                    delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, table_index, (ksa_type_location_e)(table_entry->item_extra_info & (uint8_t)KSA_LOCATION_MASK));
                    //Call delete function
                    kcm_status = delete_data(table_entry->factory_item_id);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying factory id ");
                }
            }

            if (table_entry->renewal_item_id != KSA_INVALID_SLOT_NUMBER) {//Destroy ce id
                delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, table_index, (ksa_type_location_e)(table_entry->item_extra_info & (uint8_t)KSA_LOCATION_MASK));
                //Call delete function
                kcm_status = delete_data(table_entry->renewal_item_id);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying renewal id");
            }
            memset(table_entry, 0, sizeof(ksa_item_entry_s));//init the entry
        }
        memset(g_ksa_desc[table_index].ksa_start_entry, 0, sizeof(ksa_item_entry_s)* g_ksa_desc[table_index].ksa_num_of_table_entries); //init the table
    }

    //Delete all reserved data
    for (ksa_reserved_id_type_e reserved_data_index = KSA_PS_LAST_FREE_CRYPTO_ID_RESERVED_TYPE; reserved_data_index < KSA_MAX_ID_RESERVED_TYPE; reserved_data_index++) {
        delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, KSA_CONFIG_ITEM, KSA_PSA_TYPE_LOCATION);
        //Call delete function
        kcm_status = delete_data((uint16_t)reserved_data_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying reserved data at id (%" PRIu32 ")", reserved_data_index);
    }

#endif 

    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_ERROR, "Failed to Reset storage");

    ksa_fini();//Frees global structure

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}



kcm_status_e ksa_factory_reset(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed storing item in PSA (%u)", kcm_status);

    //Factory reset should be done for all tables except RBP items, as they shouldn't be changed by factory reset
    for (ksa_item_type_e table_index = KSA_KEY_ITEM; table_index < KSA_RBP_ITEM; table_index++) {
        //pointer to the beginning of table entries
        ksa_item_entry_s *table_entry = (ksa_item_entry_s*)g_ksa_desc[table_index].ksa_start_entry;

        //check if active item is located in the table
        while (table_entry <= g_ksa_desc[table_index].ksa_last_occupied_entry) {

            if ((table_entry->active_item_id != KSA_INVALID_SLOT_NUMBER) && (table_entry->active_item_id != table_entry->factory_item_id)) {
                //The item is factory-> we keep the item name and the factory id in the table
                //If active id is different then factory -> destroy the active

                /* Factory item with different valid values of active_id and factory_id:
                The active_id should be destroyed and set to 0
                --------------------------------------------------             -----------------------------------------------
                | item name hash | Act ID | Factory ID | Renew ID |          | item name hash| Act ID | Factory ID | Renew ID |
                ---------------------------------------------        ===>     ---------------------------------------------
                | 425           |   5    |     7      |   0      |           | 425          |   0    |     7      |   0      |
                -------------------------------------------------           --------------------------------------------------*/
                //Destroy the item
                // Use dispatcher to determinate "delete" function
                psa_drv_delete_f delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, table_index,
                    (ksa_type_location_e)(table_entry->item_extra_info & KSA_LOCATION_MASK));
                //Call delete function
                kcm_status = delete_data(table_entry->active_item_id);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying PSA item ");

            }

            //actual factory item reset  - copy factory entry to active entry (also if they have the same value)
            table_entry->active_item_id = table_entry->factory_item_id;

            //squeeze the entry, if it became empty after factory reset - e.g both active and factory entries are 0
            if (table_entry->factory_item_id == KSA_INVALID_SLOT_NUMBER) {
                squeeze_item_entries(table_entry, table_index);

                //after squeeze, there are new values in this entry, we need to make factory reset for it in the next iteration, so
                //we don't move to the next entry.
                continue;
            }
            //proceed to next entry
            table_entry++;

        }//End while

         //Store the volatile updated table to the storage after factory reset was engaged.
        kcm_status = store_table(&g_ksa_desc[table_index]);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA table to persistent store");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ksa_item_check_existence(const uint8_t *item_name,
                                      size_t item_name_length,
                                      uint32_t item_type)
{
    ksa_item_entry_s* table_entry;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No item name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy item name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_item_type >= KSA_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Wrong item type");

    return get_ksa_existing_entry(item_name, item_name_length, ksa_item_type, &table_entry);
}


kcm_status_e ksa_key_get_handle(const uint8_t *key_name, size_t key_name_size, psa_key_handle_t *key_handle_out)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_entry_s* table_entry;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_handle_out");

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    kcm_status = get_ksa_existing_entry(key_name, key_name_size, KSA_KEY_ITEM, &table_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed to get key handle (%d)", kcm_status);

    return psa_drv_crypto_get_handle(table_entry->active_item_id, key_handle_out);
}


kcm_status_e ksa_key_close_handle(psa_key_handle_t key_handle)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    return psa_drv_crypto_close_handle(key_handle);
}


#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

kcm_status_e ksa_get_item_location(const uint8_t *item_name, size_t item_name_size, uint32_t item_type, kcm_item_location_e *item_location_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_entry_s *table_key_entry = NULL;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (!g_ksa_initialized) {
        kcm_status = ksa_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KSA initialization failed (%d)", kcm_status);
    }

    // TBD: call the relevant PSA function to fetch the key location, meanwhile set the default.
    kcm_status = get_ksa_existing_entry(item_name, item_name_size, ksa_item_type, &table_key_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during get_existing_entry (%d)", kcm_status);
    //      PSA will validate key existence in store
    *item_location_out = (kcm_item_location_e)(table_key_entry->item_extra_info & KSA_LOCATION_MASK);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

#endif


/* =======================================CE implementation =========================================== */

kcm_status_e ksa_generate_ce_keys(
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    psa_key_handle_t                  *psa_priv_key_handle,
    psa_key_handle_t                   *psa_pub_key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_entry_s *priv_key_entry = NULL;
    ksa_item_entry_s *pub_key_entry = NULL;
    uint16_t prv_ksa_id = PSA_INVALID_ID_NUMBER;
    uint16_t pub_ksa_id = PSA_INVALID_ID_NUMBER;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name != NULL && public_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid public_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_priv_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name != NULL && psa_pub_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid public_key_handle");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get the entry of the private key
    kcm_status = get_ksa_existing_entry(private_key_name, private_key_name_len, KSA_KEY_ITEM, &priv_key_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed private get_ksa_existing_entry");
    prv_ksa_id = priv_key_entry->active_item_id;

    if (public_key_name != NULL) {
        //Get the entry of the public key
        kcm_status = get_ksa_existing_entry(public_key_name, public_key_name_len, KSA_KEY_ITEM, &pub_key_entry);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed public get_ksa_existing_entry");
        pub_ksa_id = pub_key_entry->active_item_id;
    }

    kcm_status = psa_drv_crypto_generate_keys_from_existing_ids(prv_ksa_id, pub_ksa_id, &prv_ksa_id, &pub_ksa_id, psa_priv_key_handle, psa_pub_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to generate keys");
    
    kcm_status = set_entry_id(priv_key_entry, KSA_CE_PSA_ID_TYPE, prv_ksa_id);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to set_entry_id");

    if (public_key_name != NULL) {
        kcm_status = set_entry_id(pub_key_entry, KSA_CE_PSA_ID_TYPE, pub_ksa_id);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to set_entry_id");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        //In case of error we need to close and destroy allocated key handles
        if (psa_priv_key_handle != 0) {
            psa_destroy_key(*psa_priv_key_handle);
            set_entry_id(priv_key_entry, KSA_CE_PSA_ID_TYPE, 0);
            *psa_priv_key_handle = 0;
        }
        if (psa_pub_key_handle != 0) {
            psa_destroy_key(*psa_pub_key_handle);
            set_entry_id(pub_key_entry, KSA_CE_PSA_ID_TYPE, 0);
            *psa_pub_key_handle = 0;
        }
    }

    return kcm_status;
}

kcm_status_e  ksa_remove_entry(const uint8_t *item_name, size_t item_name_size, uint32_t item_type)
{
    ksa_item_entry_s *table_entry = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No item name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy item name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get the entry of the item
    kcm_status = get_ksa_existing_entry(item_name, item_name_size, ksa_item_type, &table_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed get_ksa_existing_entry");

    //Clean the entry and squeeze the table
    memset(table_entry, 0, sizeof(ksa_item_entry_s));
    kcm_status = remove_item_from_entry(table_entry, ksa_item_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to remove entry");

    kcm_status = store_table(&g_ksa_desc[item_type]);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA table to persistent store");
    return kcm_status;
}


kcm_status_e ksa_copy_item(const uint8_t *existing_item_name, size_t existing_item_name_size, uint32_t item_type, const uint8_t *new_item_name, size_t new_item_name_size)
{
    ksa_item_entry_s *ksa_source_key_entry = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char destination_item_name_hash[KSA_ITEM_NAME_HASH_SIZE_IN_BYTES];
    ksa_item_entry_s *ksa_destination_key_entry = NULL;
    bool is_new_entry = false;
    char* ce_prv_key_prefix;
    char* ce_pub_key_prefix;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //calculate destination key name hash
    kcm_status = calculate_item_name_hash(new_item_name, new_item_name_size, (uint8_t*)destination_item_name_hash);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to calulate key name hash (%d)", kcm_status);

    //Get the entry of the key
    kcm_status = get_ksa_existing_entry(existing_item_name, existing_item_name_size, ksa_item_type, &ksa_source_key_entry);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //We don't want print log in case the item wasn't found
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed get_ksa_existing_entry");

    //If source_item_prefix type is CE - we need to clean CE id field in duplicate items and destroy the id in PSA 
    // before we copy the dupliated item to the original one.

    //get the prefix of CE private key
    kcm_status = storage_get_prefix_from_type(KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_CE, (const char**)&ce_prv_key_prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_item_name_get_prefix");

    //get the prefix of CE public key
    kcm_status = storage_get_prefix_from_type(KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_CE, (const char**)&ce_pub_key_prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_item_name_get_prefix");


    //check if existing_key_name has CE prefix
    if (strstr((char*)existing_item_name, ce_prv_key_prefix) != NULL || strstr((char*)existing_item_name, ce_pub_key_prefix) != NULL) {

        /* After ksa_destroy_key_id
        --------------------------------------------------                -----------------------------------------------
        | key name hash | Act ID | Factory ID | Renew ID |                | key name hash| Act ID | Factory ID | Renew ID |
        -------------------------------------------------                -----------------------------------------------
        | ce_key1_hash |   1    |     1      |   3       | destroy(3)==>  | ce_key1_hash|   1    |     1      |     0     |
        -------------------------------------------------             -  -------------------------------------------------*/

        // Destroy the CE key. 
        // KCM_STATUS_INVALID_PARAMETER status can be received if the id is 0. This happens in testing, but shouldn't happen in real life scenario.
        //Anyway, this should not halt the process of restoration 
        psa_drv_delete_f delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, KSA_KEY_ITEM, (ksa_type_location_e)(ksa_source_key_entry->item_extra_info & KSA_LOCATION_MASK));
        //Call delete function
        kcm_status = delete_data(ksa_source_key_entry->renewal_item_id);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_INVALID_PARAMETER), kcm_status, "Failed to destroy key id");

        //Clean the current id field
        kcm_status = set_entry_id(ksa_source_key_entry, KSA_CE_PSA_ID_TYPE, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to update active id");
    }

    kcm_status = get_ksa_item_entry((const uint8_t*)destination_item_name_hash, ksa_item_type, &ksa_destination_key_entry, &is_new_entry, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_FILE_EXIST), kcm_status, "Failed to get a new entry");

    ksa_copy_entry((const uint8_t*)destination_item_name_hash, (const ksa_item_entry_s*)ksa_source_key_entry, ksa_destination_key_entry);
    if (ksa_destination_key_entry > ksa_source_key_entry) {
        g_ksa_desc[ksa_item_type].ksa_last_occupied_entry = ksa_destination_key_entry;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}

kcm_status_e ksa_activate_ce_key(const uint8_t *key_name, size_t key_name_size)
{
    ksa_item_entry_s *table_entry = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get the entry of the key
    kcm_status = get_ksa_existing_entry(key_name, key_name_size, KSA_KEY_ITEM, &table_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed get_ksa_existing_entry");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((table_entry->renewal_item_id == 0), kcm_status = KCM_STATUS_ITEM_NOT_FOUND, "Renewal ID is not valid");

    //Update active id of the entry with value of renewal id
    kcm_status = set_entry_id(table_entry, KSA_ACTIVE_PSA_ID_TYPE, table_entry->renewal_item_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to update active id");

    //Zero renewal id 
    kcm_status = set_entry_id(table_entry, KSA_CE_PSA_ID_TYPE, 0);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to zero renewal id");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ksa_destroy_old_active_and_remove_backup_entry(const uint8_t *item_name, size_t item_name_size, uint32_t item_type)
{
    ksa_item_entry_s *table_entry = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_type_e ksa_item_type = get_ksa_type(item_type);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get the entry of the key
    kcm_status = get_ksa_existing_entry(item_name, item_name_size, ksa_item_type, &table_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed get_ksa_existing_entry");

    //Destroy old active ID only if the ID is not factory 
    if (table_entry->active_item_id != table_entry->factory_item_id) {
        //Destroy the active key of the backup entry
        // Use dispatcher to determinate "delete" function
        psa_drv_delete_f delete_data = (psa_drv_delete_f)psa_drv_func_dispatch_operation(PSA_DRV_FUNC_DELETE, ksa_item_type, (ksa_type_location_e)(table_entry->item_extra_info & KSA_LOCATION_MASK));
        //Call delete function
        kcm_status = delete_data(table_entry->active_item_id);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destroying PSA key ");

        //Even if we failed to destory the id, continue?
        // kcm_status = KCM_STATUS_SUCCESS;
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), KCM_STATUS_STORAGE_ERROR, "Failed to destroy an old active id");
    }

    kcm_status = store_table(&g_ksa_desc[item_type]);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to store KSA table to persistent store");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


/*================================Test Functions=====================================================*/

kcm_status_e ksa_get_key_id(const uint8_t *item_name, size_t item_name_size, uint32_t table_index, ksa_id_type_e ksa_id_type, uint16_t *item_id)
{
    ksa_item_entry_s *table_entry = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    ksa_item_type_e ksa_item_type = get_ksa_type(table_index);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No item name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy item name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get the entry of the item
    kcm_status = get_ksa_existing_entry(item_name, item_name_size, ksa_item_type, &table_entry);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //We don't want print log in case the item wasn't found
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed get_ksa_existing_entry");

    switch (ksa_id_type) {
        case KSA_ACTIVE_PSA_ID_TYPE:
            *item_id = table_entry->active_item_id;
            break;
        case KSA_FACTORY_PSA_ID_TYPE:
            *item_id = table_entry->factory_item_id;
            break;
        case KSA_CE_PSA_ID_TYPE:
            *item_id = table_entry->renewal_item_id;
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid item_id type");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e ksa_update_key_id(const uint8_t *key_name, size_t key_name_size, ksa_id_type_e key_id_type, uint16_t id_value)
{
    ksa_item_entry_s *table_entry = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "No key name was given");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got emtpy key name");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Get the entry of the key
    kcm_status = get_ksa_existing_entry(key_name, key_name_size, KSA_KEY_ITEM, &table_entry);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed get_ksa_existing_entry");

    //Update active id of the entry with value of renewal id
    kcm_status = set_entry_id(table_entry, key_id_type, id_value);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to update active id");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

/*==================================KSA internal APIs==========================================*/

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
