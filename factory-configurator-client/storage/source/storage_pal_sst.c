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

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#include <stdbool.h>
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "storage_kcm.h"
#include "fcc_malloc.h"
#include "pal_sst.h"
#include "storage_internal.h"

extern bool g_kcm_initialized;

//TODO: add short explanation about certificate chains naming
#define STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX 3  //a,b,c,.. ==> Crta__, Crtb__,
#define STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX 4  // e ==> Crtae_
#define STORAGE_CHAIN_CERTIFICATE_END_OFFSET_IN_NAME  strlen(KCM_FILE_PREFIX_CERTIFICATE)//6 Size of certificate chain prefixes,the same for all chain certificates

static kcm_status_e get_complete_prefix(
    kcm_item_type_e  kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    kcm_chain_cert_info_s *cert_name_info,
    char* prefix,
    size_t max_prefix_size)
{
    kcm_status_e  kcm_status = KCM_STATUS_SUCCESS;
    char *kcm_type_prefix;

    if (cert_name_info == NULL) {
        //For non-chain items use common function that returns item's prefix
        kcm_status = storage_get_prefix_from_type((kcm_item_type_e)kcm_item_type, item_prefix_type, (const char**)&kcm_type_prefix);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_name_get_prefix");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((strlen(kcm_type_prefix) > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Failed during _kcm_item_name_get_prefix");

        memcpy((uint8_t*)prefix, kcm_type_prefix, strlen(kcm_type_prefix) + 1);
    } else { //In case of chain build prefix according to current index

        //1. First we build the first name certificate according to its type: Crta__ for KCM type  and bCrta_ for CE type.
        //2. Then we change a certificate name according to its index : for example from bCrta_ --> bCrtc_
        //3. We check if the certificate is last one in the chain , if yes we change its name be adding end sign : bCrtc_ --> bCrtce.

        //1. First, build name of first certificate according to it's prefix type: KCM or CE.
        if (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) { //If item prefix type is KCM prefix, for example Crta__
            //Check that the prefix size doesn't exceed max prefix size.
            SA_PV_ERR_RECOVERABLE_RETURN_IF((strlen(KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "prefix exceedes max size");
            //Copy base of KCM first certificate name to the index
            memcpy((uint8_t*)prefix, KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE, strlen(KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) + 1);//1 for '\0' from the KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE define
        } else { //If item prefix type is CE prefix - added 'b' letter in the beggining of the prefix, for example bCrta_
            SA_PV_ERR_RECOVERABLE_RETURN_IF((strlen(KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "prefix exceedes max size");
            //Copy base of CE first certificate name to the index
            memcpy((uint8_t*)prefix, KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE, strlen(KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE) + 1);//1 for '\0' from the KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE define
        }

        //Check that index offset in certificate prefix doesn't exceed max prefix size.
        SA_PV_ERR_RECOVERABLE_RETURN_IF((STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "index exceedes max size");

        //2. Convert certificate index's number to a char (a,b,c,d...), for example built prefix bCrta_ will be changed to bCrtc_, for third certificate name in the chain.
        prefix[STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX] = (char)(cert_name_info->certificate_index + 'a');

        //If the certificate is the last one in the chain, set 'e' to the end sign offset in the prefix : bCrtc_ -->bCrtce
        if (cert_name_info->is_last_certificate == true) {
            //Check that the end sign offset in the prefix doesn't exceed max prefix size.
            SA_PV_ERR_RECOVERABLE_RETURN_IF((STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX > max_prefix_size), kcm_status = KCM_STATUS_INVALID_PARAMETER, "index exceedes max size");
            //3. Set the end sign 'e' in the end sign offset
            prefix[STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX] = 'e';
        }
    }

    return kcm_status;
}


static kcm_status_e create_complete_item_name(
    kcm_item_type_e  kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    const char *working_dir,
    kcm_chain_cert_info_s *cert_name_info,
    const uint8_t *kcm_name,
    size_t kcm_name_len,
    char *kcm_complete_name_out,
    size_t *kcm_complete_name_size_out)
{
    size_t prefix_length = 0;
    size_t total_length = 0;
    char prefix[STORAGE_ITEM_TYPE_PREFIX_MAX_LENGTH + 1]; //prefix length and null terminator
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER("name len=%" PRIu32 "", (uint32_t)kcm_name_len);

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_complete_name_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_buffer_out parameter");

    // Check name validation. This is done only in this function since all KCM APIs using file names go
    // through here.
    kcm_status = storage_check_name_validity(kcm_name, kcm_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "Invalid KCM name");

    //Get item prefix according to source type and kcm type (including chains)
    kcm_status = get_complete_prefix((kcm_item_type_e)kcm_item_type, item_prefix_type, cert_name_info, (char*)&prefix, sizeof(prefix) - 1);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get item prefix");

    //Calculate total size of complete item name
    prefix_length = strlen(prefix);
    total_length = strlen(STORAGE_PELION_PREFIX) + strlen(working_dir) + prefix_length + kcm_name_len;



    // This Should never happen. This means that the total larger than permitted was used.
    SA_PV_ERR_RECOVERABLE_RETURN_IF((total_length > STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH), KCM_STATUS_INVALID_PARAMETER, "KCM data name too long");

    /* Append prefix and name to allocated buffer */
    memcpy(kcm_complete_name_out, STORAGE_PELION_PREFIX, strlen(STORAGE_PELION_PREFIX));
    memcpy(kcm_complete_name_out + strlen(STORAGE_PELION_PREFIX), (uint8_t *)working_dir, strlen(working_dir));
    memcpy(kcm_complete_name_out + strlen(STORAGE_PELION_PREFIX) + strlen(working_dir), (uint8_t *)prefix, prefix_length);
    memcpy(kcm_complete_name_out + strlen(STORAGE_PELION_PREFIX) + strlen(working_dir) + prefix_length, (uint8_t *)kcm_name, kcm_name_len);
    kcm_complete_name_out[total_length] = '\0';

    if (kcm_complete_name_size_out != NULL) {
        // The name being return is always null terminated, however,
        // set the string size if caller asked for it
        *kcm_complete_name_size_out = total_length;
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_build_complete_working_item_name(kcm_item_type_e kcm_item_type,
                                                      storage_item_prefix_type_e item_prefix_type,
                                                      const uint8_t *kcm_item_name,
                                                      size_t kcm_item_name_len,
                                                      char *kcm_complete_name_out,
                                                      size_t *kcm_complete_name_size_out,
                                                      void *chain_cert_info)
{
    return create_complete_item_name(kcm_item_type,
                                     item_prefix_type,
                                     STORAGE_WORKING_ACRONYM,
                                     (kcm_chain_cert_info_s *)chain_cert_info,
                                     kcm_item_name,
                                     kcm_item_name_len,
                                     kcm_complete_name_out,
                                     kcm_complete_name_size_out);
}


// This is static because, in storage_items_pelions_sst.c, the backup is done internally inside ESFS.
// So this function is relevant only for storage_items_pal_sst.c
static kcm_status_e build_complete_backup_item_name(
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    char *kcm_complete_name_out,
    void *cert_name_info)
{
    size_t kcm_complete_name_size_out;

    return create_complete_item_name(kcm_item_type,
                                     item_prefix_type,
                                     STORAGE_BACKUP_ACRONYM,
                                     (kcm_chain_cert_info_s *)cert_name_info,
                                     kcm_item_name,
                                     kcm_item_name_len,
                                     kcm_complete_name_out,
                                     &kcm_complete_name_size_out);
}


static kcm_status_e storage_get_first_cert_in_chain_name_and_info(storage_item_prefix_type_e item_prefix_type,
                                                                  const uint8_t *kcm_item_name,
                                                                  size_t kcm_item_name_len,
                                                                  char *kcm_complete_name,
                                                                  size_t kcm_complete_name_len,
                                                                  palSSTItemInfo_t *palItemInfo)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_info_s cert_chain_info = { 0 };
    cert_chain_info.certificate_index = 0;
    cert_chain_info.is_last_certificate = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_complete_name_len != STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH || kcm_complete_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong kcm_complete_name parameter");

    //Change complete certificate name to first certificate in chain with the same name
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, &cert_chain_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change single certificate name");

    //Get size
    kcm_status = pal_SSTGetInfo(kcm_complete_name, palItemInfo);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return  kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "Failed to get data size");

    SA_PV_LOG_WARN("Warning: The operation made on first certificate of the chain using single certificate API!");

    return kcm_status;
}


kcm_status_e storage_init()
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t actual_size;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();


    //check if flag file exists
    kcm_status = pal_SSTGet(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, NULL, 0, &actual_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //flag file was not found - positive scenario
        return KCM_STATUS_SUCCESS;
    } else if (kcm_status == KCM_STATUS_SUCCESS) {
        //flag file can be opened for reading
        //previous factory reset failed during execution
        //call factory reset to complete the process
        kcm_status = storage_factory_reset();
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_finalize()
{
    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_reset()
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = pal_SSTReset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed pal_SSTReset  %u", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_factory_reset()
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    palSSTIterator_t sst_iterator = 0;
    palSSTItemInfo_t item_info = { 0 };
    uint8_t* data_buffer = NULL;
    size_t actual_data_size;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // set factory reset in progress item flag
    kcm_status = pal_SSTSet(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, NULL, 0, PAL_SST_REPLAY_PROTECTION_FLAG);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed pal_SSTSet  %u", kcm_status);

    //open iterator with working prefix
    kcm_status = pal_SSTIteratorOpen(&sst_iterator, STORAGE_WORKING);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed pal_SSTIteratorOpen  %u", kcm_status);

    //iterate over items with 'working' prefix and remove all items
    while ((kcm_status = pal_SSTIteratorNext(sst_iterator, (char*)kcm_complete_name, KCM_MAX_FILENAME_SIZE)) == KCM_STATUS_SUCCESS) {

        kcm_status = pal_SSTRemove((const char*)kcm_complete_name);
        if (kcm_status != KCM_STATUS_SUCCESS) {
            // output warining in case of failure, but continue factory reset process
            SA_PV_LOG_ERR("Warning: failed to remove item. Continue factory reset...");
        }
    }

    //verify that we went over all items
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, iterator_close_end_exit, "Failed pal_SSTIteratorNext %u", kcm_status);

    //close iterator
    kcm_status = pal_SSTIteratorClose(sst_iterator);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed pal_SSTIteratorClose %u", kcm_status);

    //open iterator with backup prefix
    kcm_status = pal_SSTIteratorOpen(&sst_iterator, STORAGE_BACKUP);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed pal_SSTIteratorOpen  %u", kcm_status);

    //iterate over items with 'backup' prefix
    while ((kcm_status = pal_SSTIteratorNext(sst_iterator, (char*)kcm_complete_name, KCM_MAX_FILENAME_SIZE)) == KCM_STATUS_SUCCESS) {

        //retreive item info (size and flags)
        kcm_status = pal_SSTGetInfo((const char*)kcm_complete_name, &item_info);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, iterator_close_end_exit, "Failed pal_SSTGetInfo  %u", kcm_status);

        //allocate buffer for the data according to its size
        data_buffer = fcc_malloc(item_info.itemSize);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((data_buffer == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, iterator_close_end_exit, "Failed to allocate bffer");

        //read factory item to the buffer
        kcm_status = pal_SSTGet((const char*)kcm_complete_name, data_buffer, item_info.itemSize, &actual_data_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_memory_and_exit, "Failed pal_SSTGet  %u", kcm_status);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((item_info.itemSize != actual_data_size), kcm_status = KCM_STATUS_FILE_CORRUPTED, free_memory_and_exit, "Failed pal_SSTGet  %u", kcm_status);

        //change item name prefix to STORAGE_DEFAULT_PATH ('working' prefix)
        memcpy(kcm_complete_name, STORAGE_WORKING, strlen(STORAGE_WORKING));

        //write item with 'working' prefix
        kcm_status = pal_SSTSet((const char*)kcm_complete_name, data_buffer, item_info.itemSize, item_info.SSTFlagsBitmap);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_memory_and_exit, "Failed pal_SSTSet  %u", kcm_status);

        //free allocated buffer
        fcc_free(data_buffer);
    }

    //verify that we went over all items
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, iterator_close_end_exit, "Failed pal_SSTIteratorNext %u", kcm_status);

    //close iterator
    kcm_status = pal_SSTIteratorClose(sst_iterator);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed pal_SSTIteratorClose %u", kcm_status);

    //delete temporary file. if failed, set special status to `kcm_backup_status` since factory reset succedeed.
    kcm_status = pal_SSTRemove(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        // output warining in case of failure, but continue factory reset process
        SA_PV_LOG_ERR("Warning: failed to remove item. Continue factory reset...");
    }

    goto exit;

free_memory_and_exit:

    //free allocated memory
    fcc_free(data_buffer);

iterator_close_end_exit:

    //close iterator
    kcm_status = pal_SSTIteratorClose(sst_iterator);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed pal_SSTIteratorClose %u", kcm_status);

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
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palSSTItemInfo_t palItemInfo;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", (char*)item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size == 0 || data_size > UINT16_MAX), PAL_ERR_INVALID_ARGUMENT, "Invalid data_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_actual_size_out == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data_actual_size_out");

    kcm_status = pal_SSTGetInfo(item_name, &palItemInfo);

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //item not found. Print info level error
        SA_PV_LOG_INFO("Item not found");
        return PAL_ERR_ITEM_NOT_EXIST;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), PAL_ERR_GENERIC_FAILURE, "pal_SSTGetInfo failed");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((palItemInfo.itemSize > data_size), PAL_ERR_BUFFER_TOO_SMALL, "data_size is too small");

    kcm_status = pal_SSTGet(item_name, data, data_size, data_actual_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, PAL_ERR_GENERIC_FAILURE, "Failed to get data");

    return pal_status;
}

palStatus_t storage_rbp_write(
    const char *item_name,
    const uint8_t *data,
    size_t data_size,
    bool is_write_once)
{
    uint32_t flag_mask = PAL_SST_REPLAY_PROTECTION_FLAG | PAL_SST_CONFIDENTIALITY_FLAG;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size > UINT16_MAX || data_size == 0), PAL_ERR_INVALID_ARGUMENT, "Invalid param data");
    SA_PV_LOG_INFO_FUNC_ENTER("data_size = %" PRIu32 " item_name = %s", (uint32_t)data_size, item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid param data");

    if (is_write_once == true) {
        flag_mask |= PAL_SST_WRITE_ONCE_FLAG;
    }

    kcm_status = pal_SSTSet(item_name, data, data_size, flag_mask);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_FILE_EXIST), PAL_ERR_ITEM_EXIST, "Failed to write rbp data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), PAL_ERR_GENERIC_FAILURE, "Failed to write rbp data");

    SA_PV_LOG_INFO_FUNC_EXIT();
    return pal_status;
}



kcm_status_e storage_item_store_impl(const uint8_t * kcm_item_name,
                                     size_t kcm_item_name_len,
                                     kcm_item_type_e kcm_item_type,
                                     bool kcm_item_is_factory,
                                     bool kcm_item_is_encrypted,
                                     storage_item_prefix_type_e item_prefix_type,
                                     const uint8_t * kcm_item_data,
                                     size_t kcm_item_data_size,
                                     bool is_delete_allowed)
{
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palSSTItemInfo_t palItemInfo;
    uint32_t flag_mask = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_delete_allowed != true), KCM_STATUS_INVALID_PARAMETER, 
        "is_delete_allowed should be true for non PSA storages, but got (=%u)!", is_delete_allowed);

    //Build complete data name (also checks name validity)
    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data already exists");

    //Check if certificate chain with the same name is exists, if yes -> return an error
    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        kcm_chain_cert_info_s cert_name_info = { 0 };
        cert_name_info.certificate_index = 0;
        cert_name_info.is_last_certificate = false;

        //Build complete name of first chain certificate
        kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, &cert_name_info);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change single certificate name");

        kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status , "pal_SSTGetInfo FAILED");

        //Revert the name to certificate complete name
        //Build complete name of single certificate
        kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change first certificate name");
    }

    //Create flag mask
    if (kcm_item_is_encrypted == true) {
        flag_mask |= PAL_SST_CONFIDENTIALITY_FLAG;
    }

    if (kcm_item_is_factory == true) {
        //Set the complete name to backup path
        kcm_status = build_complete_backup_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change first certificate name to backup path");

        //Write the data to backup path
        kcm_status = pal_SSTSet(kcm_complete_name, kcm_item_data, kcm_item_data_size, flag_mask);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status , "Failed to write data to backup");

        //Set the backup path back to working
        kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change first certificate nameFailed to change to backup path");

    }

    //Write the data to working path
    kcm_status = pal_SSTSet(kcm_complete_name, kcm_item_data, kcm_item_data_size, flag_mask);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to write data");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e storage_item_get_data_size(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    size_t * kcm_item_data_size_out)
{
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palSSTItemInfo_t palItemInfo;
   
    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Kcm size out pointer is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete data name
    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

    //Try to get data info
    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status , "Failed to get data size");

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
            kcm_status = storage_get_first_cert_in_chain_name_and_info(item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, sizeof(kcm_complete_name), &palItemInfo);
            if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
                //We don't want print log in case the item wasn't found
                return kcm_status;
            }
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to check single certificate name");
        } else {//not certificate
            SA_PV_LOG_INFO("Item not found");
            return KCM_STATUS_ITEM_NOT_FOUND;
        }
    }

    //Set value of data size
    *kcm_item_data_size_out = palItemInfo.itemSize;

    SA_PV_LOG_INFO_FUNC_EXIT("kcm data size = %" PRIu32 "", (uint32_t)*kcm_item_data_size_out);
    return kcm_status;
}

kcm_status_e storage_item_get_data(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    uint8_t *kcm_item_data_out,
    size_t kcm_item_data_max_size,
    size_t *kcm_item_data_act_size_out)
{
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palSSTItemInfo_t palItemInfo;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 ", data max size = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_max_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_data_act_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data_out == NULL) && (kcm_item_data_max_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete data name
    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

    //Get size
    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status , "Failed to get data size");

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {

        if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
            kcm_status = storage_get_first_cert_in_chain_name_and_info(item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, sizeof(kcm_complete_name), &palItemInfo);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to check single certificate name");
        } else {
            //item not found. Print info level error
            SA_PV_LOG_INFO("Item not found");
            return KCM_STATUS_ITEM_NOT_FOUND;
        }
    }
    //Check buffer size for the data
    SA_PV_ERR_RECOVERABLE_RETURN_IF((palItemInfo.itemSize > kcm_item_data_max_size), kcm_status = KCM_STATUS_INSUFFICIENT_BUFFER, "Data out buffer too small");

    kcm_status = pal_SSTGet(kcm_complete_name, kcm_item_data_out, kcm_item_data_max_size, kcm_item_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status , "Failed to get data ");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_item_delete(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type)
{
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palSSTItemInfo_t palItemInfo;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Build complete data name
    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

    //Get size
    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status , "Failed to get data size");

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {

        if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
            kcm_status = storage_get_first_cert_in_chain_name_and_info(item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, sizeof(kcm_complete_name), &palItemInfo);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to check single certificate name");
        } else {
            SA_PV_LOG_INFO("Item not found");
            return  KCM_STATUS_ITEM_NOT_FOUND;
        }
    }

    //Remove the item name
    kcm_status = pal_SSTRemove(kcm_complete_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status , "Failed to delete data");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;

}


kcm_status_e storage_check_certificate_existance(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, storage_item_prefix_type_e item_prefix_type)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    palSSTItemInfo_t palItemInfo = { 0 };
    kcm_chain_cert_info_s cert_name_info = { 0 };

    //Build complete name of single certificate with given certificate chain name
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, kcm_chain_name, kcm_chain_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //If single certificate with the chain name is exists in the data base - return an error
    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Item %.*s already exists as single certificate", (int)kcm_chain_name_len, kcm_chain_name);

    //Build complete name of first certificate name in the chain
    cert_name_info.certificate_index = 0;
    cert_name_info.is_last_certificate = false;
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, kcm_chain_name, kcm_chain_name_len, kcm_complete_name, NULL, &cert_name_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //If first certificate with the chain name is exists in the data base - return an error
    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Item %.*s already exists as certificate chain", (int)kcm_chain_name_len, kcm_chain_name);

    return kcm_status;
}

kcm_status_e storage_set_certs_and_chain_size(storage_cert_chain_context_s *chain_context, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    palSSTItemInfo_t palItemInfo = { 0 };
    kcm_chain_cert_info_s cert_name_info = { 0, false };
    int certificate_index = 0;

    //Try to read all certificate in the chain, retrieve the number of certificates in the chain and their sizes
    for (certificate_index = 0; (certificate_index < KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN) && (cert_name_info.is_last_certificate == false); certificate_index++) {
        cert_name_info.certificate_index = (uint32_t)certificate_index;

        //Build certificate name according to its index in certificate chain
        kcm_status = storage_build_complete_working_item_name(KCM_LAST_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

        //Try to read certificate as not last certificate
        kcm_status = pal_SSTGetInfo((const char*)kcm_complete_name, &palItemInfo);
        //If current name wasn't found, try to read the certificate as last one in the chain
        if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {

            cert_name_info.is_last_certificate = true;

            //Set the name certificate as last certificate in the chain
            kcm_status = storage_build_complete_working_item_name(KCM_LAST_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

            //retrieve item info (size and flags)
            kcm_status = pal_SSTGetInfo((const char*)kcm_complete_name, &palItemInfo);

            //Indication for last certificate
            if (kcm_status == KCM_STATUS_SUCCESS) {
                cert_name_info.is_last_certificate = true;
            }

        }
        if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
            //We don't want print log in case the item wasn't found
            return kcm_status;
        }
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status , "Failed pal_SSTGetInfo  %u", kcm_status);

        //Set in certificate info array the size of current index
        chain_context->certificates_info[certificate_index] = palItemInfo.itemSize;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_name_info.is_last_certificate != true), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Failed to set size of certificate chain");

    chain_context->num_of_certificates_in_chain = (uint32_t)(certificate_index);
    return kcm_status;
}


kcm_status_e storage_cert_chain_get_next_data(kcm_cert_chain_handle *kcm_chain_handle,
                                              uint8_t *kcm_cert_data,
                                              size_t kcm_max_cert_data_size,
                                              storage_item_prefix_type_e item_prefix_type,
                                              size_t *kcm_actual_cert_data_size)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_info_s cert_name_info = { 0, false };
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };

    SA_PV_LOG_INFO_FUNC_ENTER("max_cert_data_size = %" PRIu32 "", (uint32_t)kcm_max_cert_data_size);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_max_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_max_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_actual_cert_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_actual_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != STORAGE_CHAIN_OP_TYPE_OPEN), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
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
    kcm_status = storage_build_complete_working_item_name(KCM_LAST_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = pal_SSTGet((const char*)kcm_complete_name, kcm_cert_data, kcm_max_cert_data_size, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status , "Failed to get data size");

    // file read, increase current_cert_index
    chain_context->current_cert_index++;

    SA_PV_LOG_INFO_FUNC_EXIT("act_cert_data_size = %" PRIu32 "", (uint32_t)*kcm_actual_cert_data_size);

    return kcm_status;
}


/*
  The function adds a certificate to the chain.
  The name of the saved certificate determined by certificate's index in the chain
  and by certificate chain name:
 1. Crta__CertificateChainName   -  first certificate in the chain.
 2. Crtb__CertificateChainName   -  second certificate in the chain.
 3. Crtce_CertificateChainName   -  third last certificate in the chain.
*/
kcm_status_e storage_cert_chain_add_next_impl(kcm_cert_chain_handle kcm_chain_handle, 
                                                const uint8_t *kcm_cert_data, 
                                                size_t kcm_cert_data_size, 
                                                storage_item_prefix_type_e item_prefix_type, 
                                                bool is_delete_allowed)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_chain_cert_info_s cert_name_info = { 0 };
    uint32_t storage_flags = 0;
    palSSTItemInfo_t palItemInfo;

    SA_PV_LOG_TRACE_FUNC_ENTER("cert_data_size = %" PRIu32 "", (uint32_t)kcm_cert_data_size);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_delete_allowed != true), KCM_STATUS_INVALID_PARAMETER, 
        "is_delete_allowed should be true for non PSA storages, but got (=%u)!", is_delete_allowed);

    //Set is the certificate is last in the chain
    if (chain_context->current_cert_index == chain_context->num_of_certificates_in_chain - 1) {
        cert_name_info.is_last_certificate = true;
    } else {
        cert_name_info.is_last_certificate = false;
    }
    //Set current certificate index
    cert_name_info.certificate_index = chain_context->current_cert_index;

    //Build complete name of current certificate
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");

    //TODO : Add remove of the certificate and continue +add SA_PV_LOG_INFO

    //Set the complete name to working path
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = pal_SSTSet(kcm_complete_name, kcm_cert_data, kcm_cert_data_size, storage_flags);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status , "Failed to write data to working");
    //Increase chian current index
    chain_context->current_cert_index++;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_chain_len = 0;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_cert_chain_handle kcm_chain_handle;
    storage_cert_chain_context_s *chain_context = NULL;
    kcm_chain_cert_info_s cert_name_info = { 0, false };
    kcm_status_e final_kcm_status = KCM_STATUS_SUCCESS;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name = %.*s", (int)kcm_chain_name_len, kcm_chain_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }
    // open the first file and read the kcm_chain_len from meta data
    kcm_status = storage_cert_chain_open(&kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, item_prefix_type, &kcm_chain_len);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open certificate chain\n");

    chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;

    //Go over all chain certificates and delete
    for (; chain_context->current_cert_index < kcm_chain_len; chain_context->current_cert_index++) {

        cert_name_info.certificate_index = chain_context->current_cert_index;
        if (chain_context->current_cert_index == kcm_chain_len - 1) {
            cert_name_info.is_last_certificate = true;
        }

        //Set the name certificate as last certificate in the chain
        kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM,
                                                              item_prefix_type,
                                                              chain_context->chain_name,
                                                              chain_context->chain_name_len,
                                                              kcm_complete_name,
                                                              NULL,
                                                              &cert_name_info);

        //Remove certificate only if complete_data_name is valid
        if (kcm_status == KCM_STATUS_SUCCESS) {
            //Remove the certificate
            final_kcm_status = pal_SSTRemove(kcm_complete_name);
        }
    }

    (void)storage_cert_chain_close(kcm_chain_handle, item_prefix_type);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return final_kcm_status;
}


void storage_chain_delete(storage_cert_chain_context_s *chain_context, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_info_s cert_name_info = { 0, false };
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };

    do {
        cert_name_info.certificate_index = chain_context->current_cert_index;

        //Set the name of the certificate in working
        kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM,
                                                              item_prefix_type,
                                                              chain_context->chain_name,
                                                              chain_context->chain_name_len,
                                                              kcm_complete_name,
                                                              NULL,
                                                              &cert_name_info);

        //we don't check the result of storage_file_delete, as it is possible that not all certificates were saved to the storage
        if (kcm_status == KCM_STATUS_SUCCESS) {
            pal_SSTRemove(kcm_complete_name);
        }

        //Only in case of invalid create operation we will remove wrong chain from backup path too
        if (chain_context->operation_type == STORAGE_CHAIN_OP_TYPE_CREATE) {
            //Set the name the  certificate in backup (factory)
            kcm_status = build_complete_backup_item_name(KCM_CERTIFICATE_ITEM,
                                                         item_prefix_type,
                                                         chain_context->chain_name,
                                                         chain_context->chain_name_len,
                                                         kcm_complete_name,
                                                         &cert_name_info);

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

#endif
#endif //#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
