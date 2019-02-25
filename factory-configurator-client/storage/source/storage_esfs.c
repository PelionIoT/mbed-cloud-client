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
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include <stdbool.h>
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "storage.h"
#include "esfs.h"
#include "fcc_malloc.h"
#include "sotp.h"

/**
* sotp type lookup record, correlating sotp type and name
*/
typedef struct storage_sotp_type_lookup_record_ {
    sotp_type_e sotp_type;
    const char *type_name;
} storage_sotp_type_lookup_record_s;
#define STORAGE_SOTP_NUMBER_OF_TYPES 9 
/**
* sotp type table, correlating for each sotp type and name.
*/
static const storage_sotp_type_lookup_record_s storage_sotp_type_lookup_table[STORAGE_SOTP_NUMBER_OF_TYPES] = {
    { SOTP_TYPE_FACTORY_DONE,               STORAGE_RBP_FACTORY_DONE_NAME },
    { SOTP_TYPE_RANDOM_SEED,                STORAGE_RBP_RANDOM_SEED_NAME },
    { SOTP_TYPE_SAVED_TIME,                 STORAGE_RBP_SAVED_TIME_NAME },
    { SOTP_TYPE_LAST_TIME_BACK,             STORAGE_RBP_LAST_TIME_BACK_NAME },
    { SOTP_TYPE_ROT,                        STORAGE_RBP_ROT_NAME },
    { SOTP_TYPE_TRUSTED_TIME_SRV_ID,        STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME },
    { SOTP_TYPE_EXECUTION_MODE,             STORAGE_RBP_EXECUTION_MODE_NAME },
    { SOTP_TYPE_OEM_TRANSFER_MODE_ENABLED,  STORAGE_RBP_OEM_TRANSFER_MODE_ENABLED_NAME },
    { SOTP_TYPE_MIN_FW_VERSION,             STORAGE_RBP_MIN_FW_VERSION_NAME },
};


extern bool g_kcm_initialized;

static bool storage_get_sotp_type(const char *sotp_item, sotp_type_e *sotp_type)
{
    int index = 0;

    for (index = 0; index < STORAGE_SOTP_NUMBER_OF_TYPES; index++) {
        if (strlen(sotp_item) == strlen(storage_sotp_type_lookup_table[index].type_name)){
            if (memcmp(storage_sotp_type_lookup_table[index].type_name, sotp_item, strlen(storage_sotp_type_lookup_table[index].type_name)) == 0) {
                *sotp_type = storage_sotp_type_lookup_table[index].sotp_type;
                return true;
            }
        }

    }
    return false;
}
static kcm_status_e sotp_to_kcm_error_translation(sotp_result_e err)
{
    kcm_status_e kcm_status;
    switch (err)
    {
    case SOTP_SUCCESS:
        kcm_status = KCM_STATUS_SUCCESS;
        break;
    case SOTP_NOT_FOUND:
        kcm_status = KCM_STATUS_ITEM_NOT_FOUND;
        break;
    case SOTP_ALREADY_EXISTS:
        kcm_status = KCM_STATUS_FILE_EXIST;//FCC_STATUS_INTERNAL_ITEM_ALREADY_EXIST
        break;
    case SOTP_READ_ERROR:
    case SOTP_WRITE_ERROR:
    case SOTP_DATA_CORRUPT:
    case SOTP_BAD_VALUE:
    case SOTP_BUFF_TOO_SMALL:
    case SOTP_FLASH_AREA_TOO_SMALL:
    case SOTP_OS_ERROR:
    case SOTP_BUFF_NOT_ALIGNED:
    default:
        kcm_status = KCM_STATUS_RBP_ERROR;
        break;
    }
    return kcm_status;
}

static bool storage_get_sotp_type_size(sotp_type_e sotp_type, uint16_t *required_size_out)
{
    size_t required_size;

    switch (sotp_type) {
    case SOTP_TYPE_ROT:
        required_size = FCC_ROT_SIZE;
        break;
    case SOTP_TYPE_FACTORY_DONE:
        required_size = FCC_FACTORY_DISABLE_FLAG_SIZE;
        break;
    case SOTP_TYPE_RANDOM_SEED:
        required_size = FCC_ENTROPY_SIZE;
        break;
    case SOTP_TYPE_SAVED_TIME:
        required_size = sizeof(uint64_t);
        break;
    case SOTP_TYPE_TRUSTED_TIME_SRV_ID:
        required_size = FCC_CA_IDENTIFICATION_SIZE;
        break;
    default:
        SA_PV_LOG_ERR("Wrong sotp_type");
        return false;
    }

    // Success
    *required_size_out = (uint16_t)required_size;

    return true;
}


static kcm_status_e storage_allocate_and_create_compelete_name(const uint8_t *kcm_name, size_t kcm_name_len, const char *prefix, uint8_t **kcm_buffer_out, size_t *kcm_buffer_size_allocated_out)
{
    size_t prefix_length = 0;
    size_t total_length = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER("name len=%" PRIu32 "", (uint32_t)kcm_name_len);

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_buffer_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_buffer_out parameter");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_buffer_size_allocated_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_buffer_size_allocated_out parameter");

    // Check that name is not too long. This is done only in this function since all KCM APIs using file names go through here.
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_name_len > KCM_MAX_FILENAME_SIZE), KCM_STATUS_FILE_NAME_TOO_LONG, "kcm_item_name_len must be %d or less", KCM_MAX_FILENAME_SIZE);

    prefix_length = strlen(prefix);
    total_length = kcm_name_len + prefix_length;

    // This Should never happen. This means that the total larger than permitted was used.
    SA_PV_ERR_RECOVERABLE_RETURN_IF((total_length > STORAGE_FILENAME_MAX_SIZE), KCM_STATUS_INVALID_PARAMETER, "KCM file name too long");

    *kcm_buffer_out = (uint8_t *)fcc_malloc(total_length);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_buffer_out == NULL), KCM_STATUS_OUT_OF_MEMORY, "Failed allocating kcm_buffer_out");

    /* Append prefix and name to allocated buffer */
    memcpy(*kcm_buffer_out, (uint8_t *)prefix, prefix_length);
    memcpy(*kcm_buffer_out + prefix_length, kcm_name, kcm_name_len);

    *kcm_buffer_size_allocated_out = total_length;

    SA_PV_LOG_TRACE_FUNC_EXIT("kcm_buffer_size_allocated_out=  %" PRIu32 "", (uint32_t)*kcm_buffer_size_allocated_out);
    return KCM_STATUS_SUCCESS;
}

static kcm_status_e storage_build_complete_item_name(kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    uint8_t **kcm_complete_name,
    size_t  *kcm_complete_name_size)
{
    const char *prefix = "DFghdfj";
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = storage_item_name_get_prefix(kcm_item_type, data_source_type, &prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_item_name_get_prefix");

    kcm_status = storage_allocate_and_create_compelete_name(kcm_item_name, kcm_item_name_len, prefix, kcm_complete_name, kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_allocate_and_create_compelete_name");

    return kcm_status;
}

static kcm_status_e error_handler(esfs_result_e esfs_status)
{
    switch (esfs_status) {
        case ESFS_SUCCESS:
            return KCM_STATUS_SUCCESS;
        case ESFS_INVALID_PARAMETER:
            return KCM_STATUS_INVALID_PARAMETER;
        case ESFS_BUFFER_TOO_SMALL:
            return KCM_STATUS_INSUFFICIENT_BUFFER;
        case ESFS_EXISTS:
            return KCM_STATUS_FILE_EXIST;
        case ESFS_NOT_EXISTS:
            return KCM_STATUS_ITEM_NOT_FOUND;
        case ESFS_INVALID_FILE_VERSION:
            return KCM_STATUS_INVALID_FILE_VERSION;
        case ESFS_CMAC_DOES_NOT_MATCH:
            return KCM_STATUS_FILE_CORRUPTED;
        case ESFS_ERROR:
            return KCM_STATUS_STORAGE_ERROR;
        case ESFS_HASH_CONFLICT:
            return KCM_STATUS_FILE_NAME_CORRUPTED;
        case ESFS_FILE_OPEN_FOR_READ:
        case ESFS_FILE_OPEN_FOR_WRITE:
            return KCM_STATUS_INVALID_FILE_ACCESS_MODE;
        default:
            return  KCM_STATUS_UNKNOWN_STORAGE_ERROR;
    }
}


static bool is_file_accessible(const kcm_ctx_s *ctx)
{
    // FIXME - We need to check file access availability by comparing KCM context TLVs vs the target file header stored in ESFS that contains
    //         TLVs and access rights. In order to retrieve ESFS file TLVs and access rights we should use the following methods
    //         that are currently not implemented:
    //              - esfs_get_meta_data_qty
    //              - esfs_get_meta_data_types
    //              - esfs_get_meta_data_buffer_size
    //              - esfs_read_meta_data
    //              - esfs_get_meta_data_qty

    PV_DEBUG_USE(ctx); // currently unused

    return true;
}

kcm_status_e storage_init()
{
    esfs_result_e esfs_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    esfs_status = esfs_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed initializing ESFS (esfs_status %d)", esfs_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_finalize()
{
    esfs_result_e esfs_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    esfs_status = esfs_finalize();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed finalizing ESFS (esfs_status %d)", esfs_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_reset()
{
    esfs_result_e esfs_status;
    sotp_result_e sotp_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    esfs_status = esfs_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed reset ESFS (esfs_status %d)", esfs_status);

    sotp_status = sotp_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_status != SOTP_SUCCESS), KCM_STATUS_STORAGE_ERROR, "Failed to reset sotp storage ");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_factory_reset()
{
    esfs_result_e esfs_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    esfs_status = esfs_factory_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed factory reset ESFS (esfs_status %d)", esfs_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

palStatus_t storage_rbp_read(
    const char *item_name,
    uint8_t *data,
    size_t data_size,
    size_t *data_actual_size_out)
{
    bool status = false;
    sotp_type_e sotp_type = SOTP_MAX_TYPES;
    sotp_result_e sotp_result = SOTP_SUCCESS;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", (char*)item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size == 0 || data_size > UINT16_MAX), PAL_ERR_INVALID_ARGUMENT, "Invalid data_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_actual_size_out == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data_actual_size_out");

    status = storage_get_sotp_type(item_name, &sotp_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), PAL_ERR_INVALID_ARGUMENT, "Invalid sotp data name");

    sotp_result = sotp_get(sotp_type,(uint16_t)data_size, (uint32_t*)data, (uint16_t*)data_actual_size_out);
    if (sotp_result == SOTP_NOT_FOUND) {
        //item not found. Print info level error
        SA_PV_LOG_INFO("SOTP item not found");
        return PAL_ERR_ITEM_NOT_EXIST;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS),   PAL_ERR_GENERIC_FAILURE, "SOTP get failed");

    return PAL_SUCCESS;
}

palStatus_t storage_rbp_write(
    const char *item_name,
    const uint8_t *data,
    size_t data_size,
    bool is_write_once)
{
    bool status = false;
    sotp_type_e sotp_type = SOTP_MAX_TYPES;
    sotp_result_e sotp_result = SOTP_SUCCESS;
    uint16_t sotp_buffer_size = 0;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", (char*)item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size == 0 || data_size > UINT16_MAX), PAL_ERR_INVALID_ARGUMENT, "Invalid data_length");

    status = storage_get_sotp_type(item_name, &sotp_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), PAL_ERR_INVALID_ARGUMENT, "Invalid sotp data name");

    if (is_write_once == true) {
        //Check if current type was already written to sotp by triyng to get the data
        sotp_result = sotp_get_item_size(sotp_type, &sotp_buffer_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result == SOTP_SUCCESS), PAL_ERR_ITEM_EXIST, "The item was already written to sotp");
    }

    sotp_result = sotp_set(sotp_type, (uint16_t)data_size, (const uint32_t*)data);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS), PAL_ERR_GENERIC_FAILURE, "SOTP set failed");

    return PAL_SUCCESS;
}

    
#ifdef RBP_TESTING
palStatus_t storage_rbp_delete(const char *item_name)
{
    bool status = false;
    sotp_type_e sotp_type = SOTP_MAX_TYPES;
    sotp_result_e sotp_result = SOTP_SUCCESS;
    
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");

    
    status = storage_get_sotp_type(item_name, &sotp_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), PAL_ERR_INVALID_ARGUMENT, "Invalid sotp data name");

    //Remove the item
    sotp_result = sotp_delete(sotp_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result == SOTP_NOT_FOUND), PAL_ERR_ITEM_NOT_EXIST, "SOTP item not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS),  PAL_ERR_GENERIC_FAILURE, "SOTP delete failed"); 

    return PAL_SUCCESS;
}
#endif


kcm_status_e storage_fcc_rbp_write(
    const char *item_name,
    const uint8_t *data,
    size_t data_size,
    bool is_write_once)
{
    bool success;
    sotp_result_e sotp_result;
    uint16_t required_size = 0;
    int64_t aligned_8_bytes_buffer[MAX_SOTP_BUFFER_SIZE / 8];
    uint16_t sotp_buffer_size = 0;
    sotp_type_e sotp_type = SOTP_MAX_TYPES;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size > UINT16_MAX || data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid param data");
    SA_PV_LOG_INFO_FUNC_ENTER("data_size = %" PRIu32 " item_name = %s", (uint32_t)data_size, item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid param data");

    PV_UNUSED_PARAM(is_write_once);

    success = storage_get_sotp_type(item_name, &sotp_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((success != true), KCM_STATUS_INVALID_PARAMETER, "Invalid sotp data name");

    success = storage_get_sotp_type_size(sotp_type, &required_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), KCM_STATUS_INVALID_PARAMETER, "Failed for get_sotp_type_size()");

    if (sotp_type != SOTP_TYPE_SAVED_TIME) {
        //Check if current type was already written to sotp by triyng to get the data
        sotp_result = sotp_get_item_size(sotp_type, &sotp_buffer_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result == SOTP_SUCCESS), KCM_STATUS_FILE_EXIST, "The item was already written to sotp");
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size != required_size), KCM_STATUS_INVALID_PARAMETER, "Wrong buf_size provided. Must be size of exactly %" PRIu32 " bytes", (uint32_t)required_size);

    // Write buf to SOTP. Cast is OK since size must be divisible by 8

    /*
    * Copy from data (uint8_t*) to aligned_8_bytes_buffer (uint64_t*) to make sure that data is 8 byte aligned.
    * Since sotp_set() gets a pointer to int64_t, if it is not aligned, and we just cast it to uint8_t*,
    * ARMCC functions like memcpy will assume 8 byte alignment resulting in possible access of unallocated memory.
    */
    memcpy(aligned_8_bytes_buffer, data, data_size);

    sotp_result = sotp_set(sotp_type, (uint16_t)(data_size), (const uint32_t*)aligned_8_bytes_buffer);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS), kcm_status = sotp_to_kcm_error_translation(sotp_result), "sotp_set failed");


    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

/** FCC initiated operation, writes a rollback protected data.
*
*   @param[in] item_name A string name of the rollback protected item
*   @param[in] data A pointer to memory with the data to write into the storage. Can be NULL if data_length is 0.
*   @param[in] data_size The data length in bytes. Can be 0 if we wish to write an empty file.
*   @param[in] is_write_once Write once flag.
*   @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_fcc_rbp_read(
    const char *item_name,
    uint8_t *data,
    size_t data_size,
    size_t *data_actual_size_out)
{

    bool success;
    sotp_result_e sotp_result;
    uint16_t required_size = 0;
    int64_t aligned_8_bytes_buffer[MAX_SOTP_BUFFER_SIZE / 8] = { 0 };
    size_t actual_data_size = 0;
    sotp_type_e sotp_type = SOTP_MAX_TYPES;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid param data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size == 0 || data_size > UINT16_MAX ), KCM_STATUS_INVALID_PARAMETER, "Invalid data_size");
    SA_PV_LOG_INFO_FUNC_ENTER("data_size = %" PRIu32 " item_name = %s", (uint32_t)data_size, item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_actual_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid data_actual_size_out");

    success = storage_get_sotp_type(item_name, &sotp_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((success != true), KCM_STATUS_INVALID_PARAMETER, "Invalid sotp data name");


    success = storage_get_sotp_type_size(sotp_type, &required_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), KCM_STATUS_INVALID_PARAMETER, "Failed for get_sotp_type_size()");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size < required_size), KCM_STATUS_INVALID_PARAMETER, "Wrong buf_size provided. Must be size of exactly %" PRIu32 " bytes", (uint32_t)required_size);

    sotp_result = sotp_get(sotp_type, (uint16_t)data_size, (uint32_t*)aligned_8_bytes_buffer, (uint16_t*)&actual_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((sotp_result != SOTP_SUCCESS), kcm_status = sotp_to_kcm_error_translation(sotp_result), "sotp_get failed");

    // Copy from aligned buffer to callers uint8_t* buffer
    memcpy(data, aligned_8_bytes_buffer, actual_data_size);

    *data_actual_size_out = (size_t)(actual_data_size);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;

}



kcm_status_e storage_data_write_impl(const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    bool kcm_item_is_encrypted,
    kcm_data_source_type_e data_source_type,
    const uint8_t * kcm_item_data,
    size_t kcm_item_data_size)
{
    uint8_t *kcm_complete_name = NULL; //Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Build complete item name
    kcm_status = storage_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_build_complete_item_name");

    //Store the item using the full name
    kcm_status = storage_file_write(&ctx, kcm_complete_name, kcm_complete_name_size, kcm_item_data, kcm_item_data_size, NULL, kcm_item_is_factory, kcm_item_is_encrypted);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed writing file to storage");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

Exit:
    fcc_free(kcm_complete_name);
    return kcm_status;
}

kcm_status_e storage_data_size_read(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    size_t * kcm_item_data_size_out)
{
    uint8_t *kcm_complete_name = NULL; //Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_data_size = 0;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Kcm size out pointer is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete item name
    kcm_status = storage_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_build_complete_item_name");

    //Get data item
    kcm_status = storage_file_size_get(&ctx, kcm_complete_name, kcm_complete_name_size, &kcm_data_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //We don't want print log in case the item wasn't found
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit, "Failed getting file size");

    *kcm_item_data_size_out = kcm_data_size;
    SA_PV_LOG_INFO_FUNC_EXIT("kcm data size = %" PRIu32 "", (uint32_t)*kcm_item_data_size_out);

Exit:
    fcc_free(kcm_complete_name);
    return kcm_status;

}

kcm_status_e storage_data_read(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    uint8_t *kcm_item_data_out,
    size_t kcm_item_data_max_size,
    size_t *kcm_item_data_act_size_out)
{

    uint8_t *kcm_complete_name = NULL; //Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t meta_data_size;
    uint16_t chain_len_to_read;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 ", data max size = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_max_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_data_act_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data_out == NULL) && (kcm_item_data_max_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete item name
    kcm_status = storage_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_build_complete_item_name");

    //Open the file
    kcm_status = storage_file_open(&ctx, kcm_complete_name, kcm_complete_name_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit, "Failed to open the given file");

    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        // check if there is meta data
        kcm_status = storage_file_get_meta_data_size(&ctx, KCM_CERT_CHAIN_LEN_MD_TYPE, &meta_data_size);
        if (kcm_status == KCM_STATUS_SUCCESS) {
            kcm_status = storage_file_read_meta_data_by_type(&ctx, KCM_CERT_CHAIN_LEN_MD_TYPE, (uint8_t*)&chain_len_to_read, meta_data_size, &meta_data_size);
            if (kcm_status == KCM_STATUS_SUCCESS && chain_len_to_read > 1) {
                SA_PV_LOG_WARN("Warning: Reading certificate chain using single certificate API");
            }
        }
    }

    kcm_status = storage_file_read_with_ctx(&ctx, kcm_item_data_out, kcm_item_data_max_size, kcm_item_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed reading file from storage (%d)", kcm_status);
    SA_PV_LOG_INFO_FUNC_EXIT("kcm data size = %" PRIu32 "", (uint32_t)*kcm_item_data_act_size_out);

Exit:
    if (kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        storage_file_close(&ctx);
    }
    fcc_free(kcm_complete_name);

    return kcm_status;
}

kcm_status_e storage_data_delete(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type)
{
    uint8_t *kcm_complete_name = NULL; //Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete item name
    kcm_status = storage_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_build_complete_item_name");

    kcm_status = storage_file_delete(&ctx, kcm_complete_name, kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed deleting kcm data");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

Exit:
    fcc_free(kcm_complete_name);
    return kcm_status;

}

void storage_cert_chain_update_name_prefixe(uint8_t *complete_file_name, uint32_t index, kcm_data_source_type_e data_source_type)
{
    if (index == 0) {
        if (data_source_type == KCM_ORIGINAL_ITEM) {
            memcpy(complete_file_name, KCM_FILE_PREFIX_CERT_CHAIN_0, strlen(KCM_FILE_PREFIX_CERT_CHAIN_0));
        }
        else {
            memcpy(complete_file_name, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, strlen(KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0));
        }
        return;
    }
    if (data_source_type == KCM_ORIGINAL_ITEM) {
        memcpy(complete_file_name, KCM_FILE_PREFIX_CERT_CHAIN_X, strlen(KCM_FILE_PREFIX_CERT_CHAIN_X));
        complete_file_name[KCM_FILE_PREFIX_CERT_CHAIN_X_OFFSET] = (uint8_t)('0' + (uint8_t)index);
    }
    else {
        memcpy(complete_file_name, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X, strlen(KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X));
        complete_file_name[KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X_OFFSET] = (uint8_t)('0' + (uint8_t)index);
    }

}
static void storage_cert_chain_files_delete(kcm_cert_chain_context_int_s *chain_context, kcm_data_source_type_e data_source_type)
{

    do {
        storage_cert_chain_update_name_prefixe(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
        //we don't check the result of storage_file_delete, as it is possible that not all certificates were saved to the storage
        (void)storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        if (chain_context->current_cert_index == 0) {
            break;
        }
        chain_context->current_cert_index--;
    } while (true);
}
kcm_status_e storage_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t kcm_chain_len, bool kcm_chain_is_factory, kcm_data_source_type_e data_source_type)
{
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_meta_data_list_s kcm_meta_data;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_cert_chain_context_int_s *chain_context = NULL;
    uint16_t chain_len_to_write = (uint16_t)kcm_chain_len;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s, chain len =%" PRIu32 "", (int)kcm_chain_name_len, kcm_chain_name, (uint32_t)kcm_chain_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len == 0 || kcm_chain_len > KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid chain len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type == KCM_BACKUP_ITEM && kcm_chain_is_factory == true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_is_factory");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (data_source_type == KCM_ORIGINAL_ITEM) {
        kcm_status = storage_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }
    else {
        kcm_status = storage_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_allocate_and_create_compelete_name");

    // allocate the context
    chain_context = (kcm_cert_chain_context_int_s*)fcc_malloc(sizeof(kcm_cert_chain_context_int_s));
    memset(chain_context, 0, sizeof(kcm_cert_chain_context_int_s));

    // Prepare one meta data item for saving kcm_chain_len as meta data of the first file
    kcm_meta_data.meta_data[0].type = KCM_CERT_CHAIN_LEN_MD_TYPE;
    kcm_meta_data.meta_data[0].data_size = sizeof(chain_len_to_write);
    kcm_meta_data.meta_data[0].data = (uint8_t*)&chain_len_to_write;
    kcm_meta_data.meta_data_count = 1;

    kcm_status = storage_file_create(&chain_context->current_kcm_ctx, kcm_complete_name, kcm_complete_name_size, &kcm_meta_data, kcm_chain_is_factory, false);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed creating kcm chain file");

    chain_context->operation_type = KCM_CHAIN_OP_TYPE_CREATE;
    chain_context->chain_name = kcm_complete_name;
    chain_context->chain_name_len = kcm_complete_name_size;
    chain_context->num_of_certificates_in_chain = kcm_chain_len;
    chain_context->current_cert_index = 0;
    chain_context->chain_is_factory = kcm_chain_is_factory;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(kcm_complete_name);
        fcc_free(chain_context);
        *kcm_chain_handle = NULL;
    }
    else {
        // set the handle only if success
        *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;
    }
    return kcm_status;
}

kcm_status_e storage_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size, kcm_data_source_type_e data_source_type)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER("cert_data_size =%" PRIu32 "", (uint32_t)kcm_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL || kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data or kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_CREATE), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (chain_context->current_cert_index > 0) {
        // only on the first certificate, the file is open
        // update file name by changing last char suffix and create the file
        storage_cert_chain_update_name_prefixe(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
        kcm_status = storage_file_create(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len, NULL, chain_context->chain_is_factory, false);
        if (kcm_status == KCM_STATUS_FILE_EXIST) {
            // trying to recover by deleting the existing file
            SA_PV_LOG_INFO("Certificate chain file for index %" PRIu32 " already exists. File will be overwritten.", (uint32_t)chain_context->current_cert_index);

            kcm_status = storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to delete existing kcm chain file");

            kcm_status = storage_file_create(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len, NULL, chain_context->chain_is_factory, false);
        }
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit, "Failed creating kcm chain file");
    }

    kcm_status = storage_file_write_with_ctx(&chain_context->current_kcm_ctx, kcm_cert_data, kcm_cert_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed writing kcm chain file");

    kcm_status = storage_file_close(&chain_context->current_kcm_ctx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed closing kcm chain file");

    // file written, increase current_cert_index
    chain_context->current_cert_index++;

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        if (chain_context->current_cert_index > 0) {
            storage_file_close(&chain_context->current_kcm_ctx);
        }
    }
    return kcm_status;
}

kcm_status_e storage_cert_chain_get_next_size(kcm_cert_chain_handle *kcm_chain_handle, kcm_data_source_type_e data_source_type, size_t *kcm_out_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_out_cert_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_out_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_OPEN), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (chain_context->current_cert_index > 0) {
        // only on the first certificate, the file is open
        // update file name by changing last char suffix and open the file
        storage_cert_chain_update_name_prefixe(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
        kcm_status = storage_file_open(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed opening kcm chain file");
    }

    kcm_status = storage_file_size_get_with_ctx(&chain_context->current_kcm_ctx, kcm_out_cert_data_size);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        if (chain_context->current_cert_index > 0) {
            // close the file only if was open in that function
            storage_file_close(&chain_context->current_kcm_ctx);
        }
        SA_PV_ERR_RECOVERABLE_RETURN(kcm_status, "Failed getting kcm chain file size");
    }
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_cert_chain_get_next_data(kcm_cert_chain_handle *kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, kcm_data_source_type_e data_source_type, size_t *kcm_actual_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t expected_data_size = 0;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_max_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_max_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_actual_cert_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_actual_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_OPEN), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");
    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (chain_context->current_kcm_ctx.is_file_size_checked == false) {
        // if user skip call to kcm_cert_chain_get_next_size
        kcm_status = storage_cert_chain_get_next_size((kcm_cert_chain_handle*)chain_context, data_source_type, &expected_data_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting kcm chain file size");
    }
    else {
        expected_data_size = chain_context->current_kcm_ctx.file_size;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_max_cert_data_size < expected_data_size), KCM_STATUS_INSUFFICIENT_BUFFER, "Certificate data buffer too small");

    kcm_status = storage_file_read_with_ctx(&chain_context->current_kcm_ctx, kcm_cert_data, kcm_max_cert_data_size, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed read kcm chain file");

    kcm_status = storage_file_close(&chain_context->current_kcm_ctx);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed closing kcm chain file");

    // file read, increase current_cert_index
    chain_context->current_cert_index++;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type, size_t *kcm_chain_len_out)
{
    kcm_cert_chain_context_int_s *chain_context = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    size_t meta_data_size;
    uint16_t chain_len_to_read;
    bool is_chain_opened = false;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain len out");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (data_source_type == KCM_ORIGINAL_ITEM) {
        kcm_status = storage_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }
    else {
        kcm_status = storage_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_allocate_and_create_compelete_name");

    // allocate the context
    chain_context = (kcm_cert_chain_context_int_s*)fcc_malloc(sizeof(kcm_cert_chain_context_int_s));
    memset(chain_context, 0, sizeof(kcm_cert_chain_context_int_s));

    kcm_status = storage_file_open(&chain_context->current_kcm_ctx, kcm_complete_name, kcm_complete_name_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        // skip the error log msg
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed opening kcm chain file");

    //Set chain handle flag
    is_chain_opened = true;

    kcm_status = storage_file_get_meta_data_size(&chain_context->current_kcm_ctx, KCM_CERT_CHAIN_LEN_MD_TYPE, &meta_data_size);
    if (kcm_status == KCM_STATUS_META_DATA_NOT_FOUND) {
        // treat single cert as chain with size 1
        chain_len_to_read = 1;
        kcm_status = KCM_STATUS_SUCCESS;
        chain_context->is_meta_data = false;
    }
    else {
        chain_context->is_meta_data = true;
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed getting kcm meta data size");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((meta_data_size != sizeof(chain_len_to_read)), (kcm_status = KCM_STATUS_META_DATA_SIZE_ERROR), Exit, "Wrong meta data size");

        kcm_status = storage_file_read_meta_data_by_type(&chain_context->current_kcm_ctx, KCM_CERT_CHAIN_LEN_MD_TYPE, (uint8_t*)&chain_len_to_read, meta_data_size, &meta_data_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed reading file's metadata");
        // Test if the read len is legitimate number
        SA_PV_ERR_RECOVERABLE_GOTO_IF((chain_len_to_read == 0 || chain_len_to_read > KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN), (kcm_status = KCM_STATUS_CORRUPTED_CHAIN_FILE), Exit, "Illegitimate chain len in file's metadata");
    }

    chain_context->operation_type = KCM_CHAIN_OP_TYPE_OPEN;
    chain_context->chain_name = kcm_complete_name;
    chain_context->chain_name_len = kcm_complete_name_size;
    chain_context->num_of_certificates_in_chain = (size_t)chain_len_to_read;
    chain_context->current_cert_index = 0;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        if (is_chain_opened == true) {
            storage_file_close(&chain_context->current_kcm_ctx);
        }
        fcc_free(kcm_complete_name);
        fcc_free(chain_context);
        *kcm_chain_handle = NULL;
    }
    else {
        *kcm_chain_len_out = chain_context->num_of_certificates_in_chain;
        // set the handle only if success
        *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;
    }
    return kcm_status;
}

kcm_status_e storage_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e first_status_err = KCM_STATUS_SUCCESS;
    size_t kcm_chain_len = 0;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s kcm_ctx;
    kcm_cert_chain_handle kcm_chain_handle;
    kcm_cert_chain_context_int_s *chain_context;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // open the first file and read the kcm_chain_len from meta data
    kcm_status = storage_cert_chain_open(&kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, data_source_type, &kcm_chain_len);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    else if (kcm_status != KCM_STATUS_SUCCESS) {
        if (data_source_type == KCM_ORIGINAL_ITEM) {
            kcm_status = storage_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
        }
        else {
            kcm_status = storage_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
        }

        if (kcm_status == KCM_STATUS_SUCCESS) {
            kcm_status = storage_file_delete(&kcm_ctx, kcm_complete_name, kcm_complete_name_size);
            fcc_free(kcm_complete_name);
        }
        first_status_err = kcm_status;
        goto Exit;
    }

    chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;

    if (kcm_status == KCM_STATUS_SUCCESS) {
        // close the file before calling delete
        storage_file_close(&chain_context->current_kcm_ctx);
    }

    for (; chain_context->current_cert_index < kcm_chain_len; chain_context->current_cert_index++) {
        storage_cert_chain_update_name_prefixe(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
        kcm_status = storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        // if there was an error, return the first one that occur
        if (kcm_status != KCM_STATUS_SUCCESS && first_status_err == KCM_STATUS_SUCCESS) {
            first_status_err = kcm_status;
        }
    }

    // close the chain to release the context
    (void)storage_cert_chain_close(kcm_chain_handle, data_source_type);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:
    SA_PV_ERR_RECOVERABLE_RETURN_IF((first_status_err != KCM_STATUS_SUCCESS), first_status_err, "Delete chain but with errors");
    return first_status_err;
}

kcm_status_e storage_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle, kcm_data_source_type_e data_source_type)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");

    if (kcm_chain_handle == NULL) {
        goto Exit; // and return KCM_STATUS_SUCCESS
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (chain_context->current_cert_index == 0 ||
        (chain_context->operation_type == KCM_CHAIN_OP_TYPE_OPEN &&
            chain_context->current_cert_index < chain_context->num_of_certificates_in_chain &&
            chain_context->current_kcm_ctx.is_file_size_checked)) {
        // close open file (after create/open or between get_next_size to get_next_data)
        // if is_file_size_checked is true, the file had open before
        kcm_status = storage_file_close(&chain_context->current_kcm_ctx);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed closing kcm chain file");
    }

    if (chain_context->operation_type == KCM_CHAIN_OP_TYPE_CREATE &&
        chain_context->current_cert_index < chain_context->num_of_certificates_in_chain) {
        // user added less certificates than num_of_certificates_in_chain, delete all and return error
        storage_cert_chain_files_delete(chain_context, KCM_ORIGINAL_ITEM);
        SA_PV_ERR_RECOVERABLE_GOTO_IF(true, (kcm_status = KCM_STATUS_CLOSE_INCOMPLETE_CHAIN), Exit, "Closing incomplete kcm chain");
    }
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:
    if (chain_context != NULL) {
        fcc_free(chain_context->chain_name);
        fcc_free(chain_context);
    }
    return kcm_status;
}


kcm_status_e storage_file_write(kcm_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length, const uint8_t *data, size_t data_length, const kcm_meta_data_list_s *kcm_meta_data_list, bool is_factory, bool is_encrypted)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e close_file_status = KCM_STATUS_SUCCESS;

    kcm_status = storage_file_create(ctx, file_name, file_name_length, kcm_meta_data_list, is_factory, is_encrypted);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "Failed to create new file");

    kcm_status = storage_file_write_with_ctx(ctx, data, data_length);// we don't check error because we need to close the file in any case

    // Data is only guaranteed to be flushed to the media on efs_close.
    close_file_status = storage_file_close(ctx);

    if (kcm_status != KCM_STATUS_SUCCESS) { // delete the file if didn't succeed to write
        (void)storage_file_delete(ctx, file_name, file_name_length);
        SA_PV_ERR_RECOVERABLE_RETURN(kcm_status, "Failed to write data");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF(close_file_status != KCM_STATUS_SUCCESS, close_file_status, "Failed to close file");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_file_size_get(kcm_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length, size_t *file_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e close_staus = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER("file_name_length=%" PRIu32 "", (uint32_t)file_name_length);

    kcm_status = storage_file_open(ctx, file_name, file_name_length);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto exit;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open the given file");

    kcm_status = storage_file_size_get_with_ctx(ctx, file_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed getting file size");

exit:
    if (kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        close_staus = storage_file_close(ctx);
    }
    if (kcm_status == KCM_STATUS_SUCCESS) {
        kcm_status = close_staus;
    }

    return kcm_status;
}

kcm_status_e storage_file_read(kcm_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length, uint8_t *buffer_out, size_t buffer_size, size_t *buffer_actual_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e close_status = KCM_STATUS_SUCCESS;

    kcm_status = storage_file_open(ctx, file_name, file_name_length);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto exit;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open the given file");

    kcm_status = storage_file_read_with_ctx(ctx, buffer_out, buffer_size, buffer_actual_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed ti read file");

exit:
    if (kcm_status != KCM_STATUS_ITEM_NOT_FOUND) {
        close_status = storage_file_close(ctx);
    }
    if (kcm_status == KCM_STATUS_SUCCESS) {
        kcm_status = close_status;
    }

    return kcm_status;
}

kcm_status_e storage_file_delete(kcm_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    esfs_result_e esfs_status;
    uint16_t esfs_mode = 0;        // FIXME - Unused, yet implemented
    bool success;

    SA_PV_LOG_TRACE_FUNC_ENTER("file_name_length=%" PRIu32 "", (uint32_t)file_name_length);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid file name context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Got empty file name");

    esfs_status = esfs_open(file_name, file_name_length, &esfs_mode, &ctx->esfs_file_h);

    //file does not exists, exit from delete function
    if (esfs_status == ESFS_NOT_EXISTS) {
        return error_handler(esfs_status);
    }

    if (esfs_status != ESFS_SUCCESS) { //file exists but there is some corruption. We will delete the file without checking it's permissions
        SA_PV_LOG_ERR("The file exists but corrupted. Delete it without checking permissions");
        esfs_status = ESFS_SUCCESS;

    } else { // check permissions
        success = is_file_accessible(ctx);
        if (!success) {
            SA_PV_LOG_ERR("Caller has no access rights to the given file");
            kcm_status = KCM_STATUS_NOT_PERMITTED;
        }

        esfs_status = esfs_close(&ctx->esfs_file_h);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed closing file (esfs_status %d)", esfs_status);

        if (kcm_status == KCM_STATUS_NOT_PERMITTED) {
            return kcm_status;
        }
    }

    // Delete the file
    esfs_status = esfs_delete(file_name, file_name_length);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed deleting file (esfs_status %d)", esfs_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e storage_file_create(kcm_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length, const kcm_meta_data_list_s *kcm_meta_data_list, bool is_factory, bool is_encrypted)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    esfs_result_e esfs_status;
    esfs_tlv_item_t meta_data_items[KCM_MD_TYPE_MAX_SIZE];
    size_t meta_data_count = 0;
    uint16_t access_flags = 0; // owner, signed, encrypted, factory, extended ACL bit mask

    SA_PV_LOG_TRACE_FUNC_ENTER("file_name_length=%" PRIu32 " ", (uint32_t)file_name_length);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid file name context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Got empty file name");

    memset(ctx, 0, sizeof(kcm_ctx_s));

    if (is_factory) {
        access_flags |= ESFS_FACTORY_VAL;
    }
    if (is_encrypted) {
        access_flags |= ESFS_ENCRYPTED;
    }

    // Convert kcm_meta_data_list to array of esfs_tlv_item
    if (kcm_meta_data_list != NULL) {
        for (meta_data_count = 0; meta_data_count < kcm_meta_data_list->meta_data_count; meta_data_count++) {
            meta_data_items[meta_data_count].type = kcm_meta_data_list->meta_data[meta_data_count].type;
            meta_data_items[meta_data_count].length_in_bytes = (uint16_t)kcm_meta_data_list->meta_data[meta_data_count].data_size;
            meta_data_items[meta_data_count].value = (void*)kcm_meta_data_list->meta_data[meta_data_count].data;
        }
    }

    esfs_status = esfs_create(file_name, file_name_length, meta_data_items, meta_data_count, access_flags, &ctx->esfs_file_h);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((esfs_status == ESFS_EXISTS), kcm_status = KCM_STATUS_FILE_EXIST, Exit, "File already exist in ESFS (esfs_status %" PRIu32 ")", (uint32_t)esfs_status);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((esfs_status != ESFS_SUCCESS), kcm_status = error_handler(esfs_status), Exit, "Failed creating file (esfs_status %" PRIu32 ")", (uint32_t)esfs_status);

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        memset(ctx, 0, sizeof(kcm_ctx_s));
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

/** Open existing file
*
*   @param ctx KCM operation context.
*   @param file_name A binary blob that uniquely identifies the file
*   @param file_name_length The binary blob length in bytes.
@param is_factory True if KCM item is factory item, or false otherwise
@param is_encrypted True if KCM item should be encrypted, or false otherwise
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_file_open(kcm_ctx_s *ctx, const uint8_t *file_name, size_t file_name_length)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    esfs_result_e esfs_status;
    uint16_t esfs_mode = 0;        // FIXME - Unused, yet implemented
    bool success;

    SA_PV_LOG_TRACE_FUNC_ENTER("file_name_length=%" PRIu32 "", (uint32_t)file_name_length);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid file name context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_name_length == 0), KCM_STATUS_INVALID_PARAMETER, "Got empty file name");

    memset(ctx, 0, sizeof(kcm_ctx_s));

    esfs_status = esfs_open(file_name, file_name_length, &esfs_mode, &ctx->esfs_file_h);
    if (esfs_status == ESFS_NOT_EXISTS) {
        kcm_status = error_handler(esfs_status);
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((esfs_status != ESFS_SUCCESS), kcm_status = error_handler(esfs_status), Exit, "Failed opening file (esfs_status %d)", esfs_status);

    success = is_file_accessible(ctx);
    if (!success) {
        kcm_status = KCM_STATUS_NOT_PERMITTED;
        esfs_close(&ctx->esfs_file_h);
        memset(ctx, 0, sizeof(kcm_ctx_s));
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit, "Caller has no access rights to the given file");

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        memset(ctx, 0, sizeof(kcm_ctx_s));
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

/** Close file in storage
*
*   @param ctx KCM operation context.
@param is_factory True if KCM item is factory item, or false otherwise
@param is_encrypted True if KCM item should be encrypted, or false otherwise
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_file_close(kcm_ctx_s *ctx)
{
    esfs_result_e esfs_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");

    // Data is only guaranteed to be flushed to the media on efs_close.
    esfs_status = esfs_close(&ctx->esfs_file_h);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed closing file (esfs_status %d)", esfs_status);

    memset(ctx, 0, sizeof(kcm_ctx_s));
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_file_write_with_ctx(kcm_ctx_s *ctx, const uint8_t *data, size_t data_length)
{
    esfs_result_e esfs_status;

    SA_PV_LOG_TRACE_FUNC_ENTER("data_length=%" PRIu32 "", (uint32_t)data_length);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((data == NULL) && (data_length > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided NULL data buffer and data_length greater than 0");

    if (data_length != 0) {
        esfs_status = esfs_write(&ctx->esfs_file_h, data, data_length);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed writing (%" PRIu32 " B) size to file (esfs_status %" PRIu32 ")", (uint32_t)data_length, (uint32_t)esfs_status);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;

}

kcm_status_e storage_file_size_get_with_ctx(kcm_ctx_s *ctx, size_t *file_size_out)
{
    esfs_result_e esfs_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((file_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid pointer to file size");

    esfs_status = esfs_file_size(&ctx->esfs_file_h, file_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed getting file size (esfs_status %d)", esfs_status);

    ctx->is_file_size_checked = true;
    ctx->file_size = *file_size_out;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_file_read_with_ctx(kcm_ctx_s *ctx, uint8_t *buffer_out, size_t buffer_size, size_t *buffer_actual_size_out)
{
    esfs_result_e esfs_status;
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER("buffer_size=%" PRIu32 "", (uint32_t)buffer_size);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((buffer_out == NULL && buffer_size != 0), KCM_STATUS_INVALID_PARAMETER, "Invalid pointer to read buffer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((buffer_actual_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid pointer to output size");

    *buffer_actual_size_out = 0;

    if (ctx->is_file_size_checked == false) {
        kcm_status = storage_file_size_get_with_ctx(ctx, buffer_actual_size_out);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting file data size (kcm_status %d)", kcm_status);
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((buffer_size < ctx->file_size), KCM_STATUS_INSUFFICIENT_BUFFER, "Buffer too small");

    if (ctx->file_size != 0) {
        esfs_status = esfs_read(&ctx->esfs_file_h, buffer_out, buffer_size, buffer_actual_size_out);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed reading file data (esfs_status %d)", esfs_status);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

static kcm_status_e storage_file_get_meta_data_size_and_index(kcm_ctx_s *ctx, kcm_meta_data_type_e type, size_t *meta_data_size_out, uint32_t *meta_data_index_out)
{
    esfs_result_e esfs_status;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    esfs_tlv_properties_t *meta_data_properties = NULL;
    uint32_t index = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((ctx == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((meta_data_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid pointer to meta_data_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((meta_data_index_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid pointer to meta_data_index_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((type >= KCM_MD_TYPE_MAX_SIZE), KCM_STATUS_INVALID_PARAMETER, "Invalid meta data type");

    esfs_status = esfs_get_meta_data_properties(&ctx->esfs_file_h, &meta_data_properties);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed reading meta data properties (esfs_status %d)", esfs_status);

    for (index = 0; index < meta_data_properties->number_of_items; index++) {
        if (type == meta_data_properties->tlv_items[index].type) {

            *meta_data_size_out = (size_t)meta_data_properties->tlv_items[index].length_in_bytes;
            *meta_data_index_out = index;
            kcm_status = KCM_STATUS_SUCCESS;
            break;
        }
    }

    if (index >= meta_data_properties->number_of_items) {
        return KCM_STATUS_META_DATA_NOT_FOUND;
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_file_get_meta_data_size(kcm_ctx_s *ctx, kcm_meta_data_type_e type, size_t *meta_data_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint32_t index = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_file_get_meta_data_size_and_index(ctx, type, meta_data_size_out, &index);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_file_read_meta_data_by_type(kcm_ctx_s *ctx, kcm_meta_data_type_e type, uint8_t *buffer_out, size_t buffer_size, size_t *buffer_actual_size_out)
{
    esfs_result_e esfs_status;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    esfs_tlv_item_t meta_data_item;
    uint32_t index = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF(buffer_out == NULL, KCM_STATUS_INVALID_PARAMETER, "Invalid pointer to kcm_meta_data");

    kcm_status = storage_file_get_meta_data_size_and_index(ctx, type, buffer_actual_size_out, &index);
    if (kcm_status == KCM_STATUS_META_DATA_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed reading meta data size and index");

    // return error in case the data buffer to read is too small
    SA_PV_ERR_RECOVERABLE_RETURN_IF((buffer_size < *buffer_actual_size_out), KCM_STATUS_INSUFFICIENT_BUFFER, "Data buffer to read is too small");

    meta_data_item.value = buffer_out;
    esfs_status = esfs_read_meta_data(&ctx->esfs_file_h, index, &meta_data_item);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((esfs_status != ESFS_SUCCESS), error_handler(esfs_status), "Failed reading meta data (esfs_status %d)", esfs_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}
#endif
