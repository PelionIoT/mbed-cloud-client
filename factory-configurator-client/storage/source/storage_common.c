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


#include <stdbool.h>
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "storage_items.h"
#include "esfs.h"
#include "fcc_malloc.h"
#include "storage_internal.h"
#include "cs_der_certs.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal_sst.h"
#endif
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "key_slot_allocator.h"
#endif

extern bool g_kcm_initialized;

//TODO: add short explanation about certificate chains naming

#if (defined  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) || (defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)
#define STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX 3  //a,b,c,.. ==> Crta__, Crtb__,
#define STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX 4  // e ==> Crtae_
#define STORAGE_CHAIN_CERTIFICATE_END_OFFSET_IN_NAME  strlen(KCM_FILE_PREFIX_CERTIFICATE)//6 Size of certificate chain prefixes,the same for all chain certificates
#endif //(defined  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) || (defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)



/** Common logic for PAL SST, ESFS and PSA */

kcm_status_e storage_check_name_validity(const uint8_t *kcm_item_name, size_t kcm_item_name_len)
{
    size_t i;
    int ascii_val;

    // Check name length
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len > KCM_MAX_FILENAME_SIZE),
                                    KCM_STATUS_FILE_NAME_TOO_LONG,
                                    "kcm_item_name_len must be %d or less",
                                    KCM_MAX_FILENAME_SIZE);

    // Iterate all the characters and make sure all belong to {'A'-'Z' , 'a'-'z' , '0'-'9' , '.' , '-' , '_' }
    // Regular expression match: "^[a-zA-Z0-9_.-]*$"
    for (i = 0; i < kcm_item_name_len; i++) {
        ascii_val = (int) kcm_item_name[i];
        if (!((ascii_val >= 'A' && ascii_val <= 'Z') || (ascii_val >= 'a' && ascii_val <= 'z') || (ascii_val == '.') ||
                (ascii_val == '-') || (ascii_val == '_') || (ascii_val >= '0' && ascii_val <= '9'))) {
            return KCM_STATUS_FILE_NAME_INVALID;
        }
    }

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_get_prefix_from_type(kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type, const char** prefix)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid item_source_type");

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_PRIVATE_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_PRIVATE_KEY);
            break;
        case KCM_PUBLIC_KEY_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_PUBLIC_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_PUBLIC_KEY);
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_SYMMETRIC_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_SYMMETRIC_KEY);
            break;
        case KCM_CERTIFICATE_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_CERTIFICATE) : (*prefix = KCM_RENEWAL_FILE_PREFIX_CERTIFICATE);
            break;
        case KCM_CONFIG_ITEM:
            (item_prefix_type == STORAGE_ITEM_PREFIX_KCM) ? (*prefix = KCM_FILE_PREFIX_CONFIG_PARAM) : (*prefix = KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM);
            break;
        default:
            status = KCM_STATUS_INVALID_PARAMETER;
            break;
    }
    return status;
}


bool storage_is_cert_chain(kcm_cert_chain_handle kcm_chain_handle)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;

    return chain_context->is_meta_data; 
}



/******** Item name build  for PSA and SST *********/

/* This implementation for SST and PSA only*/
#if (defined  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) || (defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)


#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
kcm_status_e pal_to_kcm_error_translation(palStatus_t pal_status)
{
    kcm_status_e kcm_status;

    switch (pal_status) {
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
#endif


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
kcm_status_e build_complete_backup_item_name(
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


/******** Certificate chains common logic for PSA and SST *********/

kcm_status_e storage_cert_chain_create(
    kcm_cert_chain_handle *kcm_chain_handle,
    const uint8_t *kcm_chain_name,
    size_t kcm_chain_name_len,
    size_t kcm_chain_len,
    bool kcm_chain_is_factory,
    storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    storage_cert_chain_context_s *chain_context = NULL;
    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s, chain len = %" PRIu32 ", is_factory = %" PRIu32 "",
        (int)kcm_chain_name_len, kcm_chain_name, (uint32_t)kcm_chain_len, (uint32_t)kcm_chain_is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len == 0 || kcm_chain_len > KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid chain len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type == STORAGE_ITEM_PREFIX_CE && kcm_chain_is_factory == true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_is_factory");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Check if certificate chain or single certificate with the same name already exists
    kcm_status = check_certificate_existance(kcm_chain_name, kcm_chain_name_len, item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_FILE_EXIST), kcm_status, "Data with the same name alredy exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Falied to check certificate existence");

    // allocate the context
    chain_context = (storage_cert_chain_context_s*)fcc_malloc(sizeof(*chain_context));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate memory for certificate chain context");

    // clear chain context
    memset(chain_context, 0, sizeof(*chain_context));

    // copy chain name
    memcpy(chain_context->chain_name, kcm_chain_name, kcm_chain_name_len);
    chain_context->chain_name_len = kcm_chain_name_len;

    //Prepare certificate chain context
    chain_context->operation_type = STORAGE_CHAIN_OP_TYPE_CREATE;
    chain_context->num_of_certificates_in_chain = kcm_chain_len;
    chain_context->current_cert_index = 0;
    chain_context->is_factory = kcm_chain_is_factory;

    *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;

   SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


kcm_status_e storage_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle,
                                     const uint8_t *kcm_chain_name,
                                     size_t kcm_chain_name_len,
                                     storage_item_prefix_type_e item_prefix_type,
                                     size_t *kcm_chain_len_out)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain len out");

    *kcm_chain_handle = NULL;
    *kcm_chain_len_out = 0;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // allocate the context
    chain_context = (storage_cert_chain_context_s*)fcc_malloc(sizeof(*chain_context));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate memory for certificate chain context");

    // clear chain context
    memset(chain_context, 0, sizeof(storage_cert_chain_context_s));

    // copy chain name
    memcpy(chain_context->chain_name, kcm_chain_name, kcm_chain_name_len);
    chain_context->chain_name_len = kcm_chain_name_len;

    //Prepare certificate chain context
    chain_context->operation_type = STORAGE_CHAIN_OP_TYPE_OPEN;
    chain_context->current_cert_index = 0;

    //Set certificates_info structure
    kcm_status = set_certificates_info(chain_context, item_prefix_type);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //We don't want print log in case the item wasn't found
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit, "Failed to set certificate chain context data");

    *kcm_chain_len_out = chain_context->num_of_certificates_in_chain;

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(chain_context);
        *kcm_chain_handle = NULL;
    } else {
        *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;
    }

    SA_PV_LOG_INFO_FUNC_EXIT("act_chain_len = %" PRIu32 "", (uint32_t)*kcm_chain_len_out);

    return kcm_status;
}


kcm_status_e storage_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    //kcm_status_e final_kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_chain_len = 0;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_cert_chain_handle kcm_chain_handle;
    storage_cert_chain_context_s *chain_context = NULL;
    kcm_chain_cert_info_s cert_name_info = { 0, false };
#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    palStatus_t pal_status = PAL_SUCCESS;
#endif
    kcm_status_e final_kcm_status = KCM_STATUS_SUCCESS;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);
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
#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
            pal_status = pal_SSTRemove(kcm_complete_name);
            if (pal_status != PAL_SUCCESS) {
                //If Remove failed, record the error and continue delete process
                final_kcm_status = pal_to_kcm_error_translation(pal_status);
            }
#else //PSA
            kcm_status = ksa_item_delete((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
            if (kcm_status != KCM_STATUS_SUCCESS) {
                //If Remove failed, record the error and continue delete process
                final_kcm_status = kcm_status;
            }
#endif 
        }
    }

    (void)storage_cert_chain_close(kcm_chain_handle, item_prefix_type);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return final_kcm_status;
}


kcm_status_e storage_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle, storage_item_prefix_type_e item_prefix_type)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    if (kcm_chain_handle == NULL) {
        goto Exit; // and return KCM_STATUS_SUCCESS
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    if (chain_context->operation_type == STORAGE_CHAIN_OP_TYPE_CREATE &&  chain_context->current_cert_index < chain_context->num_of_certificates_in_chain) {
        // user added less certificates than num_of_certificates_in_chain, delete all and return error
        chain_delete(chain_context, item_prefix_type);
        SA_PV_ERR_RECOVERABLE_GOTO_IF(true, (kcm_status = KCM_STATUS_CLOSE_INCOMPLETE_CHAIN), Exit, "Closing incomplete kcm chain");
    }

Exit:
    if (chain_context != NULL) {
        fcc_free(chain_context);
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e storage_cert_chain_get_next_size(kcm_cert_chain_handle *kcm_chain_handle, storage_item_prefix_type_e item_prefix_type, size_t *kcm_out_cert_data_size)
{
    storage_cert_chain_context_s *chain_context = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    int certificate_index = 0;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    certificate_index = (int)chain_context->current_cert_index;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_out_cert_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_out_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != STORAGE_CHAIN_OP_TYPE_OPEN), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Retrieve current certificate size (was already read at open stage)
    *kcm_out_cert_data_size = chain_context->certificates_info[certificate_index];

    SA_PV_LOG_INFO_FUNC_EXIT("cert_data_size = %" PRIu32 "", (uint32_t)*kcm_out_cert_data_size);

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
#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    palStatus_t pal_status = PAL_SUCCESS;
#endif 

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

#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    pal_status = pal_SSTGet((const char*)kcm_complete_name, kcm_cert_data, kcm_max_cert_data_size, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(pal_status != PAL_SUCCESS, kcm_status = pal_to_kcm_error_translation(pal_status), "Failed to get data size");
#else // PSA
    kcm_status = ksa_item_get_data((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM, kcm_cert_data, kcm_max_cert_data_size, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status = kcm_status, "Failed to get data");
#endif
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
kcm_status_e storage_cert_chain_add_next_impl(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size, storage_item_prefix_type_e item_prefix_type)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_chain_cert_info_s cert_name_info = { 0 };
    uint32_t storage_flags = 0;
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    ksa_type_location_e ksa_item_location = KSA_PSA_TYPE_LOCATION;
#endif
#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    palStatus_t pal_status = PAL_SUCCESS;
    palSSTItemInfo_t palItemInfo;
#endif 

    SA_PV_LOG_TRACE_FUNC_ENTER("cert_data_size = %" PRIu32 "", (uint32_t)kcm_cert_data_size);

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

#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT  
    pal_status = pal_SSTGetInfo(kcm_complete_name, &palItemInfo);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == PAL_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");
#else //PSA
    //If single certificate with the chain name is exists in the data base - return an error
    //kcm_status = ksa_check_key_existence((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name));
    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");
#endif //#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    
    //TODO : Add remove of the certificate and continue +add SA_PV_LOG_INFO

    //Set the complete name to working path
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    pal_status = pal_SSTSet(kcm_complete_name, kcm_cert_data, kcm_cert_data_size, storage_flags);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), kcm_status = pal_to_kcm_error_translation(pal_status), "Failed to write data to working");
#else //PSA

    //if certificate with the same name exists, overwrite with a new one
    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
    if (kcm_status == KCM_STATUS_SUCCESS) {
        ksa_item_delete((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status = kcm_status, "Failed to remove ceritificate in chain");
    }
    //Write the certificate
    kcm_status = ksa_item_store((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), storage_flags, KCM_CERTIFICATE_ITEM, kcm_cert_data, kcm_cert_data_size, ksa_item_location, chain_context->is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, "Failed to write data to PSA");
#endif

    //Increase chian current index
    chain_context->current_cert_index++;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}


#endif

kcm_status_e storage_item_store(const uint8_t * kcm_item_name,
                                size_t kcm_item_name_len,
                                kcm_item_type_e kcm_item_type,
                                bool kcm_item_is_factory,
                                storage_item_prefix_type_e item_prefix_type,
                                const uint8_t * kcm_item_data,
                                size_t kcm_item_data_size,
                                const kcm_security_desc_s kcm_item_info)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    bool kcm_item_is_encrypted = true;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %.*s len=%" PRIu32 ", data size=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data == NULL) && (kcm_item_data_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_CONFIG_ITEM && kcm_item_data_size == 0), KCM_STATUS_ITEM_IS_EMPTY, "The data of current item is empty!");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type == STORAGE_ITEM_PREFIX_CE && kcm_item_is_factory == true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_is_factory parameter");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_info != NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_info");
    

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            break;
        case KCM_PUBLIC_KEY_ITEM:
            kcm_item_is_encrypted = false; //do not encrypt public key
            break;
        case KCM_CERTIFICATE_ITEM:
            kcm_item_is_encrypted = false; //do not encrypt certificates
            break;
        case  KCM_SYMMETRIC_KEY_ITEM:
            break;
        case KCM_CONFIG_ITEM:
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    }

    kcm_status = storage_item_store_impl(kcm_item_name, kcm_item_name_len, kcm_item_type, kcm_item_is_factory, kcm_item_is_encrypted, item_prefix_type, kcm_item_data, kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "storage_data_write_impl failed\n");

    return kcm_status;
}

kcm_status_e storage_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
        const uint8_t *kcm_cert_data,
        size_t kcm_cert_data_size,
        storage_item_prefix_type_e item_prefix_type)
{
    storage_cert_chain_context_s *chain_context = (storage_cert_chain_context_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Handle_t cert;

    SA_PV_LOG_INFO_FUNC_ENTER("cert_data_size = %" PRIu32 "", (uint32_t)kcm_cert_data_size);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL || kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data or kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != STORAGE_CHAIN_OP_TYPE_CREATE), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Parse the X509 and make sure it is of correct structure
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to parsing cert");

    if (chain_context->current_cert_index > 0) {
        // If not first certificate - validate based on params of previous certificate
        kcm_status = cs_x509_cert_verify_der_signature(cert, chain_context->prev_cert_params.htbs,
                     chain_context->prev_cert_params.htbs_actual_size,
                     chain_context->prev_cert_params.signature,
                     chain_context->prev_cert_params.signature_actual_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status == KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED), (kcm_status = KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED), Clean_X509, "Failed verifying child signature");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed verifying child signature");
    }

    // Save params only if certificate is not last in chain
    if(chain_context->current_cert_index < chain_context->num_of_certificates_in_chain - 1) {
        // Get params needed for validation by the signer
        // These will be used to validate this certificate in the chain when parsing the next one
        kcm_status = cs_child_cert_params_get(cert, &chain_context->prev_cert_params);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed to retrieve child cert params");
    }

    //Call internal storage_chain_add_next
    kcm_status = storage_cert_chain_add_next_impl(kcm_chain_handle,
                 kcm_cert_data,
                 kcm_cert_data_size,
                 item_prefix_type);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed in storage_chain_add_next");

Clean_X509:
    cs_close_handle_x509_cert(&cert);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

