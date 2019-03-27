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

#include <stdbool.h>
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "storage.h"
#include "fcc_malloc.h"
#include "pal_sst.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "storage_psa.h"
#endif

extern bool g_kcm_initialized;
//TODO: add short explanation about certificate chains naming
#define STORAGE_MAX_ITEM_PREFIX_SIZE 16
#define STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX 3  //a,b,c,.. ==> Certa__, Certb__,
#define STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX 4  // e ==> Certae_
#define STORAGE_CHAIN_CERTIFICATE_END_OFFSET_IN_NAME  strlen(KCM_FILE_PREFIX_CERTIFICATE)//6 Size of certificate chain prefixes,the same for all chain certificates





static kcm_status_e storage_error_handler(palStatus_t pal_status)
{
    kcm_status_e kcm_status;

    switch (pal_status) 
    {
        case PAL_SUCCESS:
            kcm_status = KCM_STATUS_SUCCESS;
            break;
        case PAL_ERR_SST_ITEM_NOT_FOUND:
            kcm_status = KCM_STATUS_ITEM_NOT_FOUND;
            break;
        case PAL_ERR_SST_INVALID_SIZE:
        case PAL_ERR_INVALID_ARGUMENT:  
            kcm_status = KCM_STATUS_INVALID_PARAMETER;
            break;
        case PAL_ERR_SST_WRITE_PROTECTED:
        case PAL_ERR_SST_NOT_READY:
        case PAL_ERR_SST_READ_FAILED:
        case PAL_ERR_SST_INVALID_DATA_DETECTED:
        case PAL_ERR_SST_FAILED_OPERATION:
        default:
            kcm_status = KCM_STATUS_ERROR;
            break;
    }
    return kcm_status;
}
static kcm_status_e storage_get_prefix(
    kcm_item_type_e  kcm_item_type,
    kcm_data_source_type_e data_source_type,
    kcm_chain_cert_name_info_s *cert_name_info,
    char* prefix,
    size_t max_prefix_size)
{
    kcm_status_e  kcm_status = KCM_STATUS_SUCCESS;
    char *kcm_type_prefix;

    if (cert_name_info == NULL) {

        //For non-chain items use common function that returns item's prefix
        kcm_status = storage_item_name_get_prefix((kcm_item_type_e)kcm_item_type, data_source_type,(const char**)&kcm_type_prefix);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_name_get_prefix");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((strlen(kcm_type_prefix) > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Failed during _kcm_item_name_get_prefix");

        memcpy((uint8_t*)prefix, kcm_type_prefix, strlen(kcm_type_prefix) + 1);

    } else {

        //In case of chain build prefix according to current index
        if (data_source_type == KCM_ORIGINAL_ITEM) {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((strlen(KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "prefix exceedes max size");
            
            memcpy((uint8_t*)prefix, KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE, strlen(KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) + 1);//1 for '\0' from the KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE define
        }  else {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((strlen(KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "prefix exceedes max size");
            
            memcpy((uint8_t*)prefix, KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE, strlen(KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) + 1);//1 for '\0' from the KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE define
        }

        SA_PV_ERR_RECOVERABLE_RETURN_IF((STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "index exceedes max size");
        prefix[STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX] =(char) (cert_name_info->certificate_index + 'a'); 
      
        if (cert_name_info->is_last_certificate == true) {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "index exceedes max size"); 
            prefix[STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX] = 'e';
        }
    }

    return kcm_status;
}

static kcm_status_e check_name_validity(const uint8_t * kcm_item_name, size_t kcm_item_name_len)
{
    size_t i;
    int ascii_val;

    // Check size
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len > KCM_MAX_FILENAME_SIZE), KCM_STATUS_FILE_NAME_TOO_LONG, "kcm_item_name_len must be %d or less", KCM_MAX_FILENAME_SIZE);

    // Iterate all the characters and make sure all belong to {'A'-'Z' , 'a'-'z' , '0'-'9' , '.' , '-' , '_' }
    // Regular expression match: "^[a-zA-Z0-9_.-]*$"
    for (i = 0; i < kcm_item_name_len; i++) {
        ascii_val = (int)kcm_item_name[i];
        if (!(
            (ascii_val >= 'A' && ascii_val <= 'Z') ||
            (ascii_val >= 'a' && ascii_val <= 'z') ||
            (ascii_val == '.') ||
            (ascii_val == '-') ||
            (ascii_val == '_') ||
            (ascii_val >= '0' && ascii_val <= '9')
            )) {
            return KCM_STATUS_FILE_NAME_INVALID;
        }
    }

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_create_complete_data_name(
    kcm_item_type_e  kcm_item_type,
    kcm_data_source_type_e data_source_type,
    const char *working_dir,
    kcm_chain_cert_name_info_s *cert_name_info, 
    const uint8_t *kcm_name,
    size_t kcm_name_len,
    char *kcm_buffer_out)
{
    size_t prefix_length = 0;
    size_t total_length = 0;
    char prefix[STORAGE_MAX_ITEM_PREFIX_SIZE + 1]; //prefix length and null terminator
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER("name len=%" PRIu32 "", (uint32_t)kcm_name_len);

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_buffer_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_buffer_out parameter");
    kcm_status = check_name_validity(kcm_name, kcm_name_len);
    // Check that name is not too long. This is done only in this function since all KCM APIs using file names go through here.
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "Invalid KCM name");

    //Get item prefix according to source type and kcm type (including chains)
    kcm_status = storage_get_prefix((kcm_item_type_e)kcm_item_type, data_source_type, cert_name_info,(char*) &prefix, sizeof(prefix)- 1);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get item prefix");

    //Calculate total size of complete item name
    prefix_length = strlen(prefix);
    total_length = strlen(STORAGE_PELION_PREFIX) + strlen(working_dir)+ prefix_length + kcm_name_len ;

    // This Should never happen. This means that the total larger than permitted was used.
    SA_PV_ERR_RECOVERABLE_RETURN_IF((total_length > KCM_MAX_FILENAME_SIZE), KCM_STATUS_INVALID_PARAMETER, "KCM data name too long");

    /* Append prefix and name to allocated buffer */
    memcpy(kcm_buffer_out, STORAGE_PELION_PREFIX, strlen(STORAGE_PELION_PREFIX));
    memcpy(kcm_buffer_out + strlen(STORAGE_PELION_PREFIX), (uint8_t *)working_dir, strlen(working_dir));
    memcpy(kcm_buffer_out + strlen(STORAGE_PELION_PREFIX)+ strlen(working_dir), (uint8_t *)prefix, prefix_length);
    memcpy(kcm_buffer_out + strlen(STORAGE_PELION_PREFIX) + strlen(working_dir)+ prefix_length, (uint8_t *)kcm_name, kcm_name_len);
    kcm_buffer_out[total_length] = '\0';

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_init()
{
    palStatus_t pal_status = PAL_SUCCESS;
    size_t actual_size;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    //check if flag file exists
    pal_status = pal_SSTGet(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, NULL, 0, &actual_size);
    if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {
        //flag file was not found - positive scenario
        return KCM_STATUS_SUCCESS;
    } else if (pal_status == PAL_SUCCESS) {
        //flag file can be opened for reading
        //previous factory reset failed during execution
        //call factory reset to complete the process
        pal_status = storage_factory_reset();
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return storage_error_handler(pal_status);
}

kcm_status_e storage_finalize()
{
    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_reset()
{
    palStatus_t pal_status = PAL_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    pal_status = pal_SSTReset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), storage_error_handler(pal_status), "Failed pal_SSTReset  (%" PRIu32 ")", pal_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_factory_reset()
{
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    palSSTIterator_t sst_iterator = 0;
    palSSTItemInfo_t item_info = { 0 };
    uint8_t* data_buffer = NULL;
    size_t actual_data_size;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // set factory reset in progress item flag
    pal_status = pal_SSTSet(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, NULL, 0, PAL_SST_REPLAY_PROTECTION_FLAG);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), exit, "Failed pal_SSTSet  (%" PRIu32 ")", pal_status);

    //open iterator with working prefix
    pal_status = pal_SSTIteratorOpen(&sst_iterator, STORAGE_WORKING);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), exit, "Failed pal_SSTIteratorOpen  (%" PRIu32 ")", pal_status);

    //iterate over items with 'working' prefix and remove all items
    while ((pal_status = pal_SSTIteratorNext(sst_iterator, (char*)kcm_complete_name, KCM_MAX_FILENAME_SIZE)) == PAL_SUCCESS) {

        pal_status = pal_SSTRemove((const char*)kcm_complete_name);
        if (pal_status != PAL_SUCCESS) {
            // output warining in case of failure, but continue factory reset process
            SA_PV_LOG_ERR("Warning: failed to remove item. Continue factory reset...");
        }
    }

    //verify that we went over all items
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_ERR_SST_ITEM_NOT_FOUND), kcm_status = storage_error_handler(pal_status), iterator_close_end_exit, "Failed pal_SSTIteratorNext (%" PRIu32 ")", pal_status);

    //close iterator
    pal_status = pal_SSTIteratorClose(sst_iterator);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), exit, "Failed pal_SSTIteratorClose (%" PRIu32 ")", pal_status);

    //open iterator with backup prefix
    pal_status = pal_SSTIteratorOpen(&sst_iterator, STORAGE_BACKUP);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), exit, "Failed pal_SSTIteratorOpen  (%" PRIu32 ")", pal_status);

    //iterate over items with 'backup' prefix 
    while ((pal_status = pal_SSTIteratorNext(sst_iterator, (char*)kcm_complete_name, KCM_MAX_FILENAME_SIZE)) == PAL_SUCCESS) {

        //retreive item info (size and flags)
        pal_status = pal_SSTGetInfo((const char*)kcm_complete_name, &item_info);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), iterator_close_end_exit, "Failed pal_SSTGetInfo  (%" PRIu32 ")", pal_status);

        //allocate buffer for the data according to its size
        data_buffer = malloc(item_info.itemSize);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((data_buffer == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, iterator_close_end_exit, "Failed to allocate bffer");

        //read factory item to the buffer
        pal_status = pal_SSTGet((const char*)kcm_complete_name, data_buffer, item_info.itemSize, &actual_data_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), free_memory_and_exit, "Failed pal_SSTGet  (%" PRIu32 ")", pal_status);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((item_info.itemSize != actual_data_size), kcm_status = KCM_STATUS_FILE_CORRUPTED, free_memory_and_exit, "Failed pal_SSTGet  (%" PRIu32 ")", pal_status);

        //change item name prefix to STORAGE_DEFAULT_PATH ('working' prefix)
        memcpy(kcm_complete_name, STORAGE_WORKING, strlen(STORAGE_WORKING));

        //write item with 'working' prefix
        pal_status = pal_SSTSet((const char*)kcm_complete_name, data_buffer, item_info.itemSize, item_info.SSTFlagsBitmap);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), free_memory_and_exit, "Failed pal_SSTSet  (%" PRIu32 ")", pal_status);

        //free allocated buffer
        free(data_buffer);
    }

    //verify that we went over all items
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_ERR_SST_ITEM_NOT_FOUND), kcm_status = storage_error_handler(pal_status), iterator_close_end_exit, "Failed pal_SSTIteratorNext (%" PRIu32 ")", pal_status);

    //close iterator
    pal_status = pal_SSTIteratorClose(sst_iterator);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), exit, "Failed pal_SSTIteratorClose (%" PRIu32 ")", pal_status);

    //delete temporary file. if failed, set special status to `kcm_backup_status` since factory reset succedeed.
    pal_status = pal_SSTRemove(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM);

    if (pal_status != PAL_SUCCESS) {
         // output warining in case of failure, but continue factory reset process
        SA_PV_LOG_ERR("Warning: failed to remove item. Continue factory reset...");
    }

    goto exit;

free_memory_and_exit:

    //free allocated memory
    free(data_buffer);

iterator_close_end_exit:

    //close iterator
    pal_status = pal_SSTIteratorClose(sst_iterator);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), exit, "Failed pal_SSTIteratorClose (%" PRIu32 ")", pal_status);

exit:

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
   
    return kcm_status;
}


palStatus_t storage_rbp_read(
    const char *item_name,
    uint8_t *data,
    size_t data_size,
    size_t *data_actual_size_out)
{
    palStatus_t pal_status = PAL_SUCCESS;
    palSSTItemInfo_t palItemInfo;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", (char*)item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size == 0 || data_size > UINT16_MAX), PAL_ERR_INVALID_ARGUMENT, "Invalid data_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_actual_size_out == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data_actual_size_out");

    pal_status = pal_SSTGetInfo(item_name, &palItemInfo);
    if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {
        //item not found. Print info level error
        SA_PV_LOG_INFO("Item not found");
        return PAL_ERR_ITEM_NOT_EXIST;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), PAL_ERR_GENERIC_FAILURE, "pal_SSTGetInfo failed");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((palItemInfo.itemSize > data_size), PAL_ERR_BUFFER_TOO_SMALL, "data_size is too small");

    pal_status = pal_SSTGet(item_name, data, data_size, data_actual_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(pal_status != PAL_SUCCESS, PAL_ERR_GENERIC_FAILURE, "Failed to get data");

    return pal_status;
}

palStatus_t storage_rbp_write(
    const char *item_name,
    const uint8_t *data,
    size_t data_size,
    bool is_write_once)
{
    uint32_t flag_mask = PAL_SST_REPLAY_PROTECTION_FLAG | PAL_SST_CONFIDENTIALITY_FLAG;
    palStatus_t pal_status = PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size > UINT16_MAX || data_size == 0), PAL_ERR_INVALID_ARGUMENT, "Invalid param data");
    SA_PV_LOG_INFO_FUNC_ENTER("data_size = %" PRIu32 " item_name = %s", (uint32_t)data_size, item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid param data");

    if (is_write_once == true) {
        flag_mask |= PAL_SST_WRITE_ONCE_FLAG;
    }

    pal_status = pal_SSTSet(item_name, data, data_size, flag_mask);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_ERR_SST_WRITE_PROTECTED), PAL_ERR_ITEM_EXIST, "Failed to write rbp data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), PAL_ERR_GENERIC_FAILURE, "Failed to write rbp data");

    SA_PV_LOG_INFO_FUNC_EXIT();
    return pal_status;
}

/** Writes a new item to storage
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
*    @param[in] data_source_type KCM item data source (original or backup).
*    @param[in] kcm_item_data KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
*    @param[in] kcm_item_data_size KCM item data buffer size in bytes. Can be 0 if you wish to
*     store an empty file.
*
*  @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.*/
kcm_status_e storage_data_write_impl(const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    bool kcm_item_is_encrypted,
    kcm_data_source_type_e data_source_type,
    const uint8_t * kcm_item_data,
    size_t kcm_item_data_size)
{
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palSSTItemInfo_t palItemInfo;
    uint32_t flag_mask = 0;
    
    //Build complete data name (also checks name validity)
    kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");
    
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data already exists");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (kcm_item_type == KCM_PRIVATE_KEY_ITEM || kcm_item_type == KCM_PUBLIC_KEY_ITEM) {
        kcm_status = storage_import_key((const uint8_t *)kcm_complete_name, strlen(kcm_complete_name), kcm_item_type, kcm_item_data, kcm_item_data_size, kcm_item_is_factory);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to import key");
        goto Exit;  //success
    }
#endif

    //Check if certificate chain with the same name is exists, if yes -> return an error
    if (kcm_item_type == KCM_CERTIFICATE_ITEM) { 

        kcm_chain_cert_name_info_s cert_name_info = { 0 };
        cert_name_info.certificate_index = 0;
        cert_name_info.is_last_certificate = false;

        //Build complete name of first chain certificate
        kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, kcm_item_name, kcm_item_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change single certificate name");

        pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_ERR_SST_ITEM_NOT_FOUND), kcm_status = storage_error_handler(pal_status), "pal_SSTGetInfo FAILED");

        //Revert the name to certificate complete name 
        //Build complete name of single certificate
        kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change first certificate name");
    }

    //Create flag mask
    if (kcm_item_is_encrypted == true) {
        flag_mask |= PAL_SST_CONFIDENTIALITY_FLAG;
    }

    if (kcm_item_is_factory == true) {
        //Set the complete name to backup path
        kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_BACKUP_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change first certificate name to backup path");

        //Write the data to backup path
        pal_status = pal_SSTSet(kcm_complete_name, kcm_item_data, kcm_item_data_size, flag_mask);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed to write data to backup");

        //Set the backup path back to working
        kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change first certificate nameFailed to change to backup path");

    }

    //Write the data to working path
    pal_status = pal_SSTSet(kcm_complete_name, kcm_item_data, kcm_item_data_size, flag_mask);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed to write data");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
Exit:
#endif
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_data_size_read(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    size_t * kcm_item_data_size_out)
{
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palSSTItemInfo_t palItemInfo;
    palStatus_t pal_status = PAL_SUCCESS;
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    uint8_t der_pub_key[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    size_t der_pub_key_act_size;
#endif

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Kcm size out pointer is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type == KCM_PRIVATE_KEY_ITEM), KCM_STATUS_NOT_PERMITTED, "Cannot query private key size from PSA key store");
#endif

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete data name
    kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (kcm_item_type == KCM_PUBLIC_KEY_ITEM) {
        kcm_status = storage_export_key((const uint8_t *)kcm_complete_name, strlen(kcm_complete_name),kcm_item_type, der_pub_key, sizeof(der_pub_key), &der_pub_key_act_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to export key");
        //Set value of data size
        *kcm_item_data_size_out = der_pub_key_act_size;
        goto Exit; // success
    }
#endif

    //Try to get data info
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);

    //If the item is not found,at this stage we keep the error we need to read first certificate of a chain
    if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {
        return KCM_STATUS_ITEM_NOT_FOUND;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed to get data size");

    //Set value of data size
    *kcm_item_data_size_out = palItemInfo.itemSize;

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
Exit:
#endif

    SA_PV_LOG_INFO_FUNC_EXIT("kcm data size = %" PRIu32 "", (uint32_t)*kcm_item_data_size_out);
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
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palSSTItemInfo_t palItemInfo;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 ", data max size = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_max_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_data_act_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data_out == NULL) && (kcm_item_data_max_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type == KCM_PRIVATE_KEY_ITEM), KCM_STATUS_NOT_PERMITTED, "Cannot query private key bytes from PSA key store");
#endif

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete data name
    kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (kcm_item_type == KCM_PUBLIC_KEY_ITEM) {
        kcm_status = storage_export_key((const uint8_t *)kcm_complete_name, strlen(kcm_complete_name), kcm_item_type, kcm_item_data_out, kcm_item_data_max_size, kcm_item_data_act_size_out);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to export key");
        goto Exit; // success
    }
#endif

    //Get size
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);

    if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND && kcm_item_type == KCM_CERTIFICATE_ITEM) {

        kcm_chain_cert_name_info_s cert_name_info = { 0 };
        cert_name_info.certificate_index = 0;
        cert_name_info.is_last_certificate = false;

        //Change complete certificate name to first certificate in chain with the same name
        kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, kcm_item_name, kcm_item_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change single certificate name");

        //Get size
        pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
        if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {
            return  KCM_STATUS_ITEM_NOT_FOUND;
        }
        SA_PV_ERR_RECOVERABLE_RETURN_IF(pal_status != PAL_SUCCESS, kcm_status = storage_error_handler(pal_status), "Failed to get data size");

        SA_PV_LOG_WARN("Warning: Reading certificate chain using single certificate API");
    }
    if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {
        //item not found. Print info level error
        SA_PV_LOG_INFO("Item not found");
        return KCM_STATUS_ITEM_NOT_FOUND;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF(pal_status != PAL_SUCCESS, kcm_status = storage_error_handler(pal_status), "Failed to get data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((palItemInfo.itemSize > kcm_item_data_max_size), kcm_status = KCM_STATUS_INSUFFICIENT_BUFFER, "Data out buffer too small");

    pal_status = pal_SSTGet(kcm_complete_name, kcm_item_data_out, kcm_item_data_max_size, kcm_item_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed to get data ");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
Exit:
#endif

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_data_delete(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type)
{
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;

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

    //Build complete data name
    kcm_status = storage_create_complete_data_name(kcm_item_type, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_item_name, kcm_item_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (kcm_item_type == KCM_PRIVATE_KEY_ITEM || kcm_item_type == KCM_PUBLIC_KEY_ITEM) {
        // clear key from key-slot-allocator
        kcm_status = storage_destory_key((const uint8_t *)kcm_complete_name, strlen(kcm_complete_name));
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed evacuating a key slot");
        goto Exit; // success
    }
#endif
    
    //Remove the item name
    pal_status = pal_SSTRemove(kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(pal_status != PAL_SUCCESS, kcm_status = storage_error_handler(pal_status), "Failed to delete data");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
Exit:
#endif

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;

}

static kcm_status_e storage_check_if_certificate_exists(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type) {

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    palStatus_t pal_status = PAL_SUCCESS;
    palSSTItemInfo_t palItemInfo = { 0 };
    kcm_chain_cert_name_info_s cert_name_info = { 0 };

    //Build complete name of single certificate with given certificate chain name
    kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, NULL, kcm_chain_name, kcm_chain_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //If single certificate with the chain name is exists in the data base - return an error
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");

    //Build complete name of first certificate name in the chain
    cert_name_info.certificate_index = 0;
    cert_name_info.is_last_certificate = false;
    kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, kcm_chain_name, kcm_chain_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //If first certificate with the chain name is exists in the data base - return an error
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");

    return kcm_status;
}
kcm_status_e storage_cert_chain_create(
    kcm_cert_chain_handle *kcm_chain_handle,
    const uint8_t *kcm_chain_name,
    size_t kcm_chain_name_len,
    size_t kcm_chain_len,
    bool kcm_chain_is_factory,
    kcm_data_source_type_e data_source_type)
{
     kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
     kcm_cert_chain_context_int_s *chain_context = NULL;
     uint8_t *certificate_chain_name = NULL;


     // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s, chain len =%" PRIu32 "", (int)kcm_chain_name_len, kcm_chain_name, (uint32_t)kcm_chain_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len == 0 || kcm_chain_len > KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid chain len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type == KCM_BACKUP_ITEM && kcm_chain_is_factory == true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_is_factory");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Check if certificate chain or single certificate with the same name already exists
    kcm_status = storage_check_if_certificate_exists(kcm_chain_name, kcm_chain_name_len, data_source_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Data with the same name alredy exists");

    // allocate the context
    chain_context = (kcm_cert_chain_context_int_s*)fcc_malloc(sizeof(kcm_cert_chain_context_int_s));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate memory for certificate chain context");
    memset(chain_context, 0, sizeof(kcm_cert_chain_context_int_s));

    certificate_chain_name = fcc_malloc(kcm_chain_name_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((certificate_chain_name == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, Exit, "Failed to allocate memory for certificate chain name");
    memcpy(certificate_chain_name, kcm_chain_name, kcm_chain_name_len);

    //Prepare certificate chain context
    chain_context->operation_type = KCM_CHAIN_OP_TYPE_CREATE;
    chain_context->chain_name = (uint8_t*)certificate_chain_name;
    chain_context->chain_name_len = kcm_chain_name_len;
    chain_context->num_of_certificates_in_chain = kcm_chain_len;
    chain_context->current_cert_index = 0;
    chain_context->chain_is_factory = kcm_chain_is_factory;

    *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(chain_context);
    }
    return kcm_status;
}

kcm_status_e storage_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size, kcm_data_source_type_e data_source_type)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    palSSTItemInfo_t palItemInfo = { 0 };
    kcm_chain_cert_name_info_s cert_name_info = { 0 };
    uint32_t flag_mask = 0;
    palStatus_t pal_status = PAL_SUCCESS;

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

    //Set is the certificate is last in the chain
    if (chain_context->current_cert_index == chain_context->num_of_certificates_in_chain -1 ) {
        cert_name_info.is_last_certificate = true;
    } else {
        cert_name_info.is_last_certificate = false;
    }
    //Set current certificate index
    cert_name_info.certificate_index = chain_context->current_cert_index;

    //Build complete name of current certificate
    kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, NULL, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //If single certificate with the chain name is exists in the data base - return an error
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");
    //TODO : Add remove of the certificate and continue +add SA_PV_LOG_INFO

    if (chain_context->chain_is_factory == true) {

        //Set the complete name to backup path
        kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM, data_source_type, STORAGE_BACKUP_ACRONYM, &cert_name_info, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change certificate name to backup path");

        //Write the data to backup path
        pal_status = pal_SSTSet(kcm_complete_name, kcm_cert_data, kcm_cert_data_size, flag_mask);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed to write certificate to backup");
    }

    //Set the backup complete name
    kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //Write the certificate to the storage
    pal_status = pal_SSTSet(kcm_complete_name, kcm_cert_data, kcm_cert_data_size, flag_mask);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed to write data to storage");

    //Increase chian current index
    chain_context->current_cert_index++;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_cert_chain_get_next_size(kcm_cert_chain_handle *kcm_chain_handle, kcm_data_source_type_e data_source_type, size_t *kcm_out_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    int certificate_index =(int)chain_context->current_cert_index;

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

    //Retrieve current certificate size (was already read at open stage)
    *kcm_out_cert_data_size = chain_context->certificates_info[certificate_index];

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_cert_chain_get_next_data(kcm_cert_chain_handle *kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, kcm_data_source_type_e data_source_type, size_t *kcm_actual_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_name_info_s cert_name_info = { 0 , false };
    palStatus_t pal_status = PAL_SUCCESS;
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };

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

    cert_name_info.certificate_index = chain_context->current_cert_index;
    if ((chain_context->num_of_certificates_in_chain - 1) == chain_context->current_cert_index) {
        cert_name_info.is_last_certificate = true;
    }

    //Build certificate name according to its index in certificate chain
    kcm_status = storage_create_complete_data_name(KCM_LAST_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    pal_status = pal_SSTGet((const char*)kcm_complete_name, kcm_cert_data, kcm_max_cert_data_size, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(pal_status != PAL_SUCCESS, kcm_status = storage_error_handler(pal_status), "Failed to get data size");

    // file read, increase current_cert_index
    chain_context->current_cert_index++;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


static kcm_status_e set_certificates_info(kcm_cert_chain_context_int_s *chain_context, kcm_data_source_type_e data_source_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    palSSTItemInfo_t palItemInfo = { 0 };
    kcm_chain_cert_name_info_s cert_name_info = { 0 , false};
    palStatus_t pal_status = PAL_SUCCESS;
    int certificate_index = 0;

    //Try to read all certificate in the chain, retrieve the number of certificates in the chain and their sizes
    for (certificate_index = 0; (certificate_index < KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN) && ( cert_name_info.is_last_certificate == false); certificate_index++)
    {

        cert_name_info.certificate_index = (uint32_t)certificate_index;

        //Build certificate name according to its index in certificate chain
        kcm_status = storage_create_complete_data_name(KCM_LAST_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

        //Try to read certificate as not last certificate
        pal_status = pal_SSTGetInfo((const char*)kcm_complete_name, &palItemInfo);
        //If current name wasn't found, try to read the certificate as last one in the chain
        if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {

            cert_name_info.is_last_certificate = true;

            //Set the name certificate as last certificate in the chain
            kcm_status = storage_create_complete_data_name(KCM_LAST_ITEM, data_source_type, STORAGE_WORKING_ACRONYM, &cert_name_info, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

            //retrieve item info (size and flags)
            pal_status = pal_SSTGetInfo((const char*)kcm_complete_name, &palItemInfo);

            //Indication for last certificate
            if (pal_status == PAL_SUCCESS) {
                cert_name_info.is_last_certificate = true;
            }

        }
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = storage_error_handler(pal_status), "Failed pal_SSTGetInfo  (%" PRIu32 ")", pal_status);

        //Set in certificate info array the size of current index
        chain_context->certificates_info[certificate_index] = palItemInfo.itemSize;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_name_info.is_last_certificate != true ), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Failed to set size of certificate chain");

    chain_context->num_of_certificates_in_chain = (uint32_t)(certificate_index );
    return kcm_status;
}

kcm_status_e storage_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type, size_t *kcm_chain_len_out)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *certificate_chain_name = NULL;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;
    //SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain len out");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // allocate the context
    chain_context = (kcm_cert_chain_context_int_s*)fcc_malloc(sizeof(kcm_cert_chain_context_int_s));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate memory for certificate chain context");
    memset(chain_context, 0, sizeof(kcm_cert_chain_context_int_s));

    //Allocate memory for the certificate chain name
    certificate_chain_name = fcc_malloc(kcm_chain_name_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((certificate_chain_name == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, Exit, "Failed to allocate memory for certificate chain name");
    memcpy(certificate_chain_name, kcm_chain_name, kcm_chain_name_len);

    //Prepare certificate chain context
    chain_context->operation_type = KCM_CHAIN_OP_TYPE_OPEN;
    chain_context->chain_name = (uint8_t*)certificate_chain_name;
    chain_context->chain_name_len = kcm_chain_name_len;
    chain_context->current_cert_index = 0;

    //Set certificates_info structure
    kcm_status = set_certificates_info(chain_context,  data_source_type);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit,"Failed to set certificate chain context data");

    *kcm_chain_len_out = chain_context->num_of_certificates_in_chain;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(certificate_chain_name);
        fcc_free(chain_context);
        *kcm_chain_handle = NULL;
    } else {
        *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;
    }

    return kcm_status;
}

kcm_status_e storage_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e final_kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_chain_len = 0;
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    kcm_cert_chain_handle kcm_chain_handle;
    kcm_cert_chain_context_int_s *chain_context;
    kcm_chain_cert_name_info_s cert_name_info = { 0, false };
    palStatus_t pal_status = PAL_SUCCESS;

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
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open certificate chain\n");

    chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;

    //Go over all chain certificates and delete
    for (; chain_context->current_cert_index < kcm_chain_len; chain_context->current_cert_index++) {

        cert_name_info.certificate_index = chain_context->current_cert_index;
        if (chain_context->current_cert_index == kcm_chain_len - 1) {
            cert_name_info.is_last_certificate = true;
        }

        //Set the name certificate as last certificate in the chain
        kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM,
            data_source_type,
            STORAGE_WORKING_ACRONYM,
            &cert_name_info,
            chain_context->chain_name,
            chain_context->chain_name_len,
            kcm_complete_name);

        //Remove certificate only if complete_data_name is valid
        if (kcm_status == KCM_STATUS_SUCCESS) {
            //Remove the certificate
            pal_status = pal_SSTRemove(kcm_complete_name);
            if (pal_status != PAL_SUCCESS) {
                //If Remove failed, record the error and continue delete process
                final_kcm_status = storage_error_handler(pal_status);
            }
        }
    }

    (void)storage_cert_chain_close(kcm_chain_handle, data_source_type);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return final_kcm_status;
}

static void storage_cert_chain_files_delete(kcm_cert_chain_context_int_s *chain_context, kcm_data_source_type_e data_source_type, kcm_chain_operation_type_e operation_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_name_info_s cert_name_info = { 0, false };
    char kcm_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };

    do {
        cert_name_info.certificate_index = chain_context->current_cert_index;

        //Set the name of the certificate in working 
        kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM,
            data_source_type,
            STORAGE_WORKING_ACRONYM,
            &cert_name_info,
            chain_context->chain_name,
            chain_context->chain_name_len,
            kcm_complete_name);

        //we don't check the result of storage_file_delete, as it is possible that not all certificates were saved to the storage
        if (kcm_status == KCM_STATUS_SUCCESS) {
            pal_SSTRemove(kcm_complete_name);
        }

        //Only in case of invalid create operation we will remove wrong chain from backup path too
        if (operation_type == KCM_CHAIN_OP_TYPE_CREATE) {
            //Set the name the  certificate in backup (factory)
            kcm_status = storage_create_complete_data_name(KCM_CERTIFICATE_ITEM,
                data_source_type,
                STORAGE_BACKUP_ACRONYM,
                &cert_name_info,
                chain_context->chain_name,
                chain_context->chain_name_len,
                kcm_complete_name);

            //we don't check the result of storage_file_delete, as it is possible that not all certificates were saved to the storage
            if (kcm_status == KCM_STATUS_SUCCESS) {
                pal_SSTRemove(kcm_complete_name);
            }
        }

        if (chain_context->current_cert_index == 0) {
            break;
        }

        //
        chain_context->current_cert_index--;
    } while (true);
}

kcm_status_e storage_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle, kcm_data_source_type_e data_source_type)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

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

    if (chain_context->operation_type == KCM_CHAIN_OP_TYPE_CREATE &&  chain_context->current_cert_index < chain_context->num_of_certificates_in_chain) {
        // user added less certificates than num_of_certificates_in_chain, delete all and return error
        storage_cert_chain_files_delete(chain_context, data_source_type, KCM_CHAIN_OP_TYPE_CREATE);
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



#endif
