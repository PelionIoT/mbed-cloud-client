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
#include <stdbool.h>
#include "storage.h"
#include "pv_error_handling.h"
#include "cs_der_certs.h"
#include "cs_der_keys_and_csrs.h"
#include "fcc_malloc.h"
#include "pal.h"
#include "cs_utils.h"

extern bool g_kcm_initialized;

 static kcm_status_e _kcm_allocate_and_create_compelete_name(const uint8_t *kcm_name, size_t kcm_name_len, const char *prefix, uint8_t **kcm_buffer_out, size_t *kcm_buffer_size_allocated_out)
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
 /**
 *   The function returns prefix, according to kcm type and data source type
 *    @param[in] kcm_item_type     type of KCM item.
 *    @param[in] item_source_type  type of source type (original or backup)
 *    @param[out] prefix           returned prefix
 *    @returns
 *       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
 */
static kcm_status_e _kcm_item_name_get_prefix(kcm_item_type_e kcm_item_type, kcm_data_source_type_e item_source_type,const char** prefix)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_source_type != KCM_ORIGINAL_ITEM && item_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid item_source_type");

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            if (item_source_type == KCM_ORIGINAL_ITEM) {
                *prefix = KCM_FILE_PREFIX_PRIVATE_KEY;
            } else {
                *prefix = KCM_RENEWAL_FILE_PREFIX_PRIVATE_KEY;
            }
            break;
        case KCM_PUBLIC_KEY_ITEM:
            if (item_source_type == KCM_ORIGINAL_ITEM) {
                *prefix = KCM_FILE_PREFIX_PUBLIC_KEY;
            } else {
                *prefix = KCM_RENEWAL_FILE_PREFIX_PUBLIC_KEY;
            }
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            if (item_source_type == KCM_ORIGINAL_ITEM) {
                *prefix = KCM_FILE_PREFIX_SYMMETRIC_KEY;
            } else {
                *prefix = KCM_RENEWAL_FILE_PREFIX_SYMMETRIC_KEY;
            }
            break;
        case KCM_CERTIFICATE_ITEM:
            if (item_source_type == KCM_ORIGINAL_ITEM) {
                *prefix = KCM_FILE_PREFIX_CERTIFICATE;
            } else {
                *prefix = KCM_RENEWAL_FILE_PREFIX_CERTIFICATE;
            }
            break;
        case KCM_CONFIG_ITEM:
            if (item_source_type == KCM_ORIGINAL_ITEM) {
                *prefix = KCM_FILE_PREFIX_CONFIG_PARAM;
            } else {
                *prefix = KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM;
            }
            break;
        default:
            status = KCM_STATUS_INVALID_PARAMETER;
            break;
    }
    return status;
}

static kcm_status_e _kcm_build_complete_item_name(kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    uint8_t **kcm_complete_name,
    size_t  *kcm_complete_name_size)
{
    const char *prefix;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = _kcm_item_name_get_prefix(kcm_item_type, data_source_type, &prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_item_name_get_prefix");

    kcm_status = _kcm_allocate_and_create_compelete_name(kcm_item_name, kcm_item_name_len, prefix, kcm_complete_name, kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_allocate_and_create_compelete_name");

    return kcm_status;
}

void _kcm_cert_chain_update_name_prefix(uint8_t *complete_file_name, uint32_t index, kcm_data_source_type_e data_source_type)
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
static void _kcm_cert_chain_files_delete(kcm_cert_chain_context_int_s *chain_context, kcm_data_source_type_e data_source_type)
{

    do {
        _kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
        //we don't check the result of storage_file_delete, as it is possible that not all certificates were saved to the storage
        (void)storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        if (chain_context->current_cert_index == 0) {
            break;
        }
        chain_context->current_cert_index--;
    } while (true);
}

kcm_status_e _kcm_item_store(const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    const uint8_t * kcm_item_data,
    size_t kcm_item_data_size,
    kcm_data_source_type_e data_source_type)
{
    uint8_t *kcm_complete_name = NULL; //Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    bool kcm_item_is_encrypted = true;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %.*s len=%" PRIu32 ", data size=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type == KCM_BACKUP_ITEM && kcm_item_is_factory == true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_is_factory parameter");

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

    //Build complete item name
    kcm_status = _kcm_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_build_complete_item_name"); 

    //Store the item using the full name
    kcm_status = storage_file_write(&ctx, kcm_complete_name, kcm_complete_name_size, kcm_item_data, kcm_item_data_size, NULL, kcm_item_is_factory, kcm_item_is_encrypted);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed writing file to storage");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

Exit:
    fcc_free(kcm_complete_name);
    return kcm_status;
}

kcm_status_e _kcm_item_get_data_size(const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    size_t *kcm_item_data_size_out)
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
    kcm_status = _kcm_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_build_complete_item_name");

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

kcm_status_e  _kcm_item_get_data(const uint8_t * kcm_item_name,
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
    kcm_status = _kcm_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_build_complete_item_name");

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

kcm_status_e _kcm_item_delete(const uint8_t * kcm_item_name,
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
    kcm_status = _kcm_build_complete_item_name(kcm_item_type, data_source_type, kcm_item_name, kcm_item_name_len, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_build_complete_item_name");

     kcm_status = storage_file_delete(&ctx, kcm_complete_name, kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed deleting kcm data");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

Exit:
    fcc_free(kcm_complete_name);
    return kcm_status;
}

kcm_status_e _kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t kcm_chain_len, bool kcm_chain_is_factory, kcm_data_source_type_e data_source_type)
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
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_source_type != KCM_ORIGINAL_ITEM && data_source_type  != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid data_source_type");
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
        kcm_status = _kcm_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    } else {
        kcm_status = _kcm_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_allocate_and_create_compelete_name");

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

kcm_status_e _kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size, kcm_data_source_type_e data_source_type)
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
        _kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
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

kcm_status_e _kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type,size_t *kcm_chain_len_out)
{
    kcm_cert_chain_context_int_s *chain_context = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    size_t meta_data_size;
    uint16_t chain_len_to_read;
    bool is_chain_opened = false;

    // Validate function parameters
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
        kcm_status = _kcm_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }  else {
        kcm_status = _kcm_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during _kcm_allocate_and_create_compelete_name");

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
    }  else {
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

kcm_status_e _kcm_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type)
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
    kcm_status = _kcm_cert_chain_open(&kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, data_source_type, &kcm_chain_len);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    } else if (kcm_status != KCM_STATUS_SUCCESS) {
        if (data_source_type == KCM_ORIGINAL_ITEM) {
            kcm_status = _kcm_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
        } else {
            kcm_status = _kcm_allocate_and_create_compelete_name(kcm_chain_name, kcm_chain_name_len, KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
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
        _kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
        kcm_status = storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        // if there was an error, return the first one that occur
        if (kcm_status != KCM_STATUS_SUCCESS && first_status_err == KCM_STATUS_SUCCESS) {
            first_status_err = kcm_status;
        }
    }

    // close the chain to release the context
    (void)_kcm_cert_chain_close(kcm_chain_handle, data_source_type);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:
    SA_PV_ERR_RECOVERABLE_RETURN_IF((first_status_err != KCM_STATUS_SUCCESS), first_status_err, "Delete chain but with errors");
    return first_status_err;
}

kcm_status_e _kcm_cert_chain_get_next_size(kcm_cert_chain_handle *kcm_chain_handle, kcm_data_source_type_e data_source_type, size_t *kcm_out_cert_data_size)
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
        _kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index, data_source_type);
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

kcm_status_e _kcm_cert_chain_get_next_data(kcm_cert_chain_handle *kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, kcm_data_source_type_e data_source_type, size_t *kcm_actual_cert_data_size)
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
        kcm_status = _kcm_cert_chain_get_next_size((kcm_cert_chain_handle*)chain_context, data_source_type,&expected_data_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting kcm chain file size");
    } else {
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


kcm_status_e _kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle, kcm_data_source_type_e data_source_type)
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
        _kcm_cert_chain_files_delete(chain_context, KCM_ORIGINAL_ITEM);
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
