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
#include "key_config_manager.h"
#include "storage.h"
#include "pv_error_handling.h"
#include "cs_der_certs.h"
#include "cs_der_keys_and_csrs.h"
#include "fcc_malloc.h"
#include "pal.h"
#include "cs_utils.h"

typedef enum {
    KCM_PRIVATE_KEY_DATA,
    KCM_PUBLIC_KEY_DATA,
    KCM_SYMMETRIC_KEY_DATA,
    KCM_CERTIFICATE_DATA,
    KCM_CONFIG_DATA,
} kcm_data_type;

static bool kcm_initialized = false;

// The func create new name by adding kcm prefix
static kcm_status_e kcm_create_complete_name(const uint8_t *kcm_name, size_t kcm_name_len, const char *prefix, uint8_t **kcm_buffer_out, size_t *kcm_buffer_size_allocated_out)
{
    size_t prefix_length = 0;
    size_t total_length = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER("name len=%" PRIu32 "", (uint32_t)kcm_name_len);

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


static kcm_status_e kcm_item_name_get_prefix(kcm_item_type_e kcm_item_type, const char** prefix)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            *prefix = KCM_FILE_PREFIX_PRIVATE_KEY;
            break;
        case KCM_PUBLIC_KEY_ITEM:
            *prefix = KCM_FILE_PREFIX_PUBLIC_KEY;
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            *prefix = KCM_FILE_PREFIX_SYMMETRIC_KEY;
            break;
        case KCM_CERTIFICATE_ITEM:
            *prefix = KCM_FILE_PREFIX_CERTIFICATE;
            break;
        case KCM_CONFIG_ITEM:
            *prefix = KCM_FILE_PREFIX_CONFIG_PARAM;
            break;
        default:
            status = KCM_STATUS_INVALID_PARAMETER;
            break;
    }
    return status;
}

kcm_status_e kcm_init(void)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (!kcm_initialized) {
        palStatus_t pal_status;

        //Initialize PAL
        pal_status = pal_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_ERROR, "Failed initializing PAL (%" PRIu32 ")", pal_status);

        //Initialize back-end storage
        status = storage_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "Failed initializing storage\n");

        // Mark as "initialized"
        kcm_initialized = true;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return status;
}

kcm_status_e kcm_finalize(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (kcm_initialized) {

        kcm_status = storage_finalize();
        if (kcm_status != KCM_STATUS_SUCCESS) {
            SA_PV_LOG_ERR("Failed finalizing storage\n");
        }

        //Finalize PAL
        pal_destroy();

        // Mark as "not initialized"
        kcm_initialized = false;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_item_store(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, bool kcm_item_is_factory, const uint8_t * kcm_item_data, size_t kcm_item_data_size, const kcm_security_desc_s security_desc)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_ctx_s ctx;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    const char *prefix;
    bool kcm_item_is_encrypted = true; //encrypt by default

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %.*s len=%" PRIu32 ", data size=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_size);

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }


    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data == NULL) && (kcm_item_data_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");

    //temporary check that security descriptor is NULL
    SA_PV_ERR_RECOVERABLE_RETURN_IF((security_desc != NULL), KCM_STATUS_INVALID_PARAMETER, "Security descriptor is not NULL!");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_CONFIG_ITEM && kcm_item_data_size == 0), KCM_STATUS_ITEM_IS_EMPTY, "The data of current item is empty!");

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            kcm_status = cs_der_priv_key_verify(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Private key validation failed");
            break;
        case KCM_PUBLIC_KEY_ITEM:
            kcm_status = cs_der_public_key_verify(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Public key validation failed");
            kcm_item_is_encrypted = false; //do not encrypt public key
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            //currently possible to write a symmetric key of size 0 since we do not check format
            break;
        case KCM_CERTIFICATE_ITEM:
            kcm_status = cs_check_der_x509_format(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Certificate validation failed");
            kcm_item_is_encrypted = false; //do not encrypt certificates
            break;
        case KCM_CONFIG_ITEM:
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    }

    kcm_status = kcm_item_name_get_prefix(kcm_item_type, &prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_item_name_get_prefix");

    kcm_status = kcm_create_complete_name(kcm_item_name, kcm_item_name_len, prefix, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_create_complete_name");

    kcm_status = storage_file_write(&ctx, kcm_complete_name, kcm_complete_name_size, kcm_item_data, kcm_item_data_size, NULL, kcm_item_is_factory, kcm_item_is_encrypted);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed writing file to storage");

Exit:
    fcc_free(kcm_complete_name);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_item_get_data_size(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, size_t *kcm_item_data_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    size_t kcm_data_size = 0;
    const char *prefix;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Kcm size out pointer is NULL");

    kcm_status = kcm_item_name_get_prefix(kcm_item_type, &prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_item_name_get_prefix");

    kcm_status = kcm_create_complete_name(kcm_item_name, kcm_item_name_len, prefix, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_create_complete_name");

    kcm_status = storage_file_size_get(&ctx, kcm_complete_name, kcm_complete_name_size, &kcm_data_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Exit, "Failed getting file size");

    *kcm_item_data_size_out = kcm_data_size;
    SA_PV_LOG_INFO_FUNC_EXIT("kcm data size = %" PRIu32 "", (uint32_t)*kcm_item_data_size_out);

Exit:
    fcc_free(kcm_complete_name);

    return kcm_status;
}


kcm_status_e kcm_item_get_data(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, uint8_t * kcm_item_data_out, size_t kcm_item_data_max_size, size_t * kcm_item_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx;
    const char *prefix;
    size_t meta_data_size;
    uint16_t chain_len_to_read;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 ", data max size = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_max_size);

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_data_act_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data_out == NULL) && (kcm_item_data_max_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");

    kcm_status = kcm_item_name_get_prefix(kcm_item_type, &prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_item_name_get_prefix");

    kcm_status = kcm_create_complete_name(kcm_item_name, kcm_item_name_len, prefix, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_create_complete_name");

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


kcm_status_e kcm_item_delete(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s ctx; // FIXME - Currently not implemented
    const char *prefix;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type >= KCM_LAST_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");

    kcm_status = kcm_item_name_get_prefix(kcm_item_type, &prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_item_name_get_prefix");

    kcm_status = kcm_create_complete_name(kcm_item_name, kcm_item_name_len, prefix, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_create_complete_name");

    kcm_status = storage_file_delete(&ctx, kcm_complete_name, kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed deleting kcm data");

Exit:
    fcc_free(kcm_complete_name);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_factory_reset(void)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "KCM initialization failed\n");
    }

    status = storage_factory_reset();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != KCM_STATUS_SUCCESS), (status = status), Exit, "Failed perform factory reset");

Exit:
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return status;
}

// Internal function to update file name prefix according to chain index
void kcm_cert_chain_update_name_prefix(uint8_t *complete_file_name, uint32_t index)
{
    if (index == 0) {
        memcpy(complete_file_name, KCM_FILE_PREFIX_CERT_CHAIN_0, strlen(KCM_FILE_PREFIX_CERT_CHAIN_0));
        return;
    }
    memcpy(complete_file_name, KCM_FILE_PREFIX_CERT_CHAIN_X, strlen(KCM_FILE_PREFIX_CERT_CHAIN_X));
    complete_file_name[KCM_FILE_PREFIX_CERT_CHAIN_X_OFFSET] = (uint8_t)('0' + (uint8_t)index);
}

static void kcm_cert_chain_files_delete(kcm_cert_chain_context_int_s *chain_context)
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    do {
        kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index);
        storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        if (chain_context->current_cert_index == 0) {
            break;
        }
        chain_context->current_cert_index--;
    } while (true);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

kcm_status_e kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t kcm_chain_len, bool kcm_chain_is_factory)
{
    kcm_cert_chain_context_int_s *chain_context = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_meta_data_list_s kcm_meta_data;
    uint16_t chain_len_to_write = (uint16_t)kcm_chain_len;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s, chain len =%" PRIu32 "", (int)kcm_chain_name_len, kcm_chain_name, (uint32_t)kcm_chain_len);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len == 0 || kcm_chain_len > KCM_MAX_NUMBER_OF_CERTIFICATES_IN_CHAIN), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid chain len");

    kcm_status = kcm_create_complete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_create_complete_name");

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

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(kcm_complete_name);
        fcc_free(chain_context);
        *kcm_chain_handle = NULL;
    } else {
        // set the handle only if success
        *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;
    }


    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t *kcm_chain_len_out)
{
    kcm_cert_chain_context_int_s *chain_context = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    size_t meta_data_size;
    uint16_t chain_len_to_read;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid chain name len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid handle");
    *kcm_chain_handle = NULL;

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_len_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain len out");

    kcm_status = kcm_create_complete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during kcm_create_complete_name");

    // allocate the context
    chain_context = (kcm_cert_chain_context_int_s*)fcc_malloc(sizeof(kcm_cert_chain_context_int_s));
    memset(chain_context, 0, sizeof(kcm_cert_chain_context_int_s));

    kcm_status = storage_file_open(&chain_context->current_kcm_ctx, kcm_complete_name, kcm_complete_name_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        // skip the error log msg
        goto Exit;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed opening kcm chain file");

    kcm_status = storage_file_get_meta_data_size(&chain_context->current_kcm_ctx, KCM_CERT_CHAIN_LEN_MD_TYPE, &meta_data_size);
    if (kcm_status == KCM_STATUS_META_DATA_NOT_FOUND) {
        // treat single cert as chain with size 1
        chain_len_to_read = 1;
        kcm_status = KCM_STATUS_SUCCESS;
    } else {
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed getting kcm meta data size");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((meta_data_size != sizeof(chain_len_to_read)), (kcm_status = KCM_STATUS_META_DATA_SIZE_ERROR), Exit, "Wrong meta data size");

        kcm_status = storage_file_read_meta_data_by_type(&chain_context->current_kcm_ctx, KCM_CERT_CHAIN_LEN_MD_TYPE, (uint8_t*)&chain_len_to_read, meta_data_size, &meta_data_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed reading file's metadata");
        // Test if the read len is legitimate number
        SA_PV_ERR_RECOVERABLE_GOTO_IF((chain_len_to_read == 0 || chain_len_to_read > KCM_MAX_NUMBER_OF_CERTIFICATES_IN_CHAIN), (kcm_status = KCM_STATUS_CORRUPTED_CHAIN_FILE), Exit, "Illegitimate chain len in file's metadata");
    }

    chain_context->operation_type = KCM_CHAIN_OP_TYPE_OPEN;
    chain_context->chain_name = kcm_complete_name;
    chain_context->chain_name_len = kcm_complete_name_size;
    chain_context->num_of_certificates_in_chain = (size_t)chain_len_to_read;
    chain_context->current_cert_index = 0;

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        storage_file_close(&chain_context->current_kcm_ctx);
        fcc_free(kcm_complete_name);
        fcc_free(chain_context);
        *kcm_chain_handle = NULL;
    } else {
        *kcm_chain_len_out = chain_context->num_of_certificates_in_chain;
        // set the handle only if success
        *kcm_chain_handle = (kcm_cert_chain_handle)chain_context;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

/*
* If not first certificate in chain:
*     1. Validate previously added certificate with the public key inside kcm_cert_data
*     2. Set the chain_context->prev_cert_params to be the params of the current certificate so it can be validated with next call to this function.
*     3. Store the current certificate
*     4. Update the index of the chain handle iterator for next use of this function
* If is first certificate in chain:
*    File already open - skip step 1 (no previous cert available). Note in this case the file should already be open so no need to reopen it
*/
kcm_status_e kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Handle_t cert;

    SA_PV_LOG_INFO_FUNC_ENTER("cert_data_size =%" PRIu32 "", (uint32_t)kcm_cert_data_size);

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm context");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL || kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data or kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_CREATE), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    // Parse the X509 and make sure it is of correct structure
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to parsing cert");

    if (chain_context->current_cert_index > 0) {
        // If not first certificate - validate based on params of previous certificate
        kcm_status = cs_x509_cert_verify_signature(cert, chain_context->prev_cert_params.htbs,
                                                   chain_context->prev_cert_params.htbs_actual_size,
                                                   chain_context->prev_cert_params.signature,
                                                   chain_context->prev_cert_params.signature_actual_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status == KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED), (kcm_status = KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED), Clean_X509, "Failed verifying child signature");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed verifying child signature");
        // only on the first certificate, the file is open
        // update file name by changing last char suffix and create the file
        kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index);
        kcm_status = storage_file_create(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len, NULL, chain_context->chain_is_factory, false);
        if (kcm_status == KCM_STATUS_FILE_EXIST) {
            // trying to recover by deleting the existing file
            SA_PV_LOG_INFO("Certificate chain file for index %" PRIu32 " already exists. File will be overwritten.", (uint32_t)chain_context->current_cert_index);

            kcm_status = storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Clean_X509, "Failed to delete existing kcm chain file");

            kcm_status = storage_file_create(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len, NULL, chain_context->chain_is_factory, false);
        }
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, Clean_X509, "Failed creating kcm chain file");
    }

    // Save params only if certificate is not last in chain 
    if(chain_context->current_cert_index < chain_context->num_of_certificates_in_chain - 1) {
        // Get params needed for validation by the signer
        // These will be used to validate this certificate in the chain when parsing the next one
        kcm_status = cs_child_cert_params_get(cert, &chain_context->prev_cert_params);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to retrieve child cert params");
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

Clean_X509:
    cs_close_handle_x509_cert(&cert);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e kcm_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e first_status_err = KCM_STATUS_SUCCESS;
    kcm_cert_chain_handle kcm_chain_handle;
    kcm_cert_chain_context_int_s *chain_context;
    size_t kcm_chain_len = 0;
    uint8_t *kcm_complete_name = NULL; // Filename including prefix
    size_t kcm_complete_name_size;
    kcm_ctx_s kcm_ctx;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_chain_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("chain name =  %.*s", (int)kcm_chain_name_len, kcm_chain_name);

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // open the first file and read the kcm_chain_len from meta data
    kcm_status = kcm_cert_chain_open(&kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, &kcm_chain_len);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    } else if (kcm_status != KCM_STATUS_SUCCESS) {
        kcm_status = kcm_create_complete_name(kcm_chain_name, kcm_chain_name_len, KCM_FILE_PREFIX_CERT_CHAIN_0, &kcm_complete_name, &kcm_complete_name_size);
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
        kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index);
        kcm_status = storage_file_delete(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        // if there was an error, return the first one that occur
        if (kcm_status != KCM_STATUS_SUCCESS && first_status_err == KCM_STATUS_SUCCESS) {
            first_status_err = kcm_status;
        }
    }

    // close the chain to release the context
    kcm_cert_chain_close(kcm_chain_handle);

Exit:
    SA_PV_ERR_RECOVERABLE_RETURN_IF((first_status_err != KCM_STATUS_SUCCESS), first_status_err, "Delete chain but with errors");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return first_status_err;
}


kcm_status_e kcm_cert_chain_get_next_size(kcm_cert_chain_handle kcm_chain_handle, size_t *kcm_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_OPEN), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    if (chain_context->current_cert_index > 0) {
        // only on the first certificate, the file is open
        // update file name by changing last char suffix and open the file
        kcm_cert_chain_update_name_prefix(chain_context->chain_name, chain_context->current_cert_index);
        kcm_status = storage_file_open(&chain_context->current_kcm_ctx, chain_context->chain_name, chain_context->chain_name_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed opening kcm chain file");
    }

    kcm_status = storage_file_size_get_with_ctx(&chain_context->current_kcm_ctx, kcm_cert_data_size);
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


kcm_status_e kcm_cert_chain_get_next_data(kcm_cert_chain_handle kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, size_t *kcm_actual_cert_data_size)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t expected_data_size = 0;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_chain_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid chain handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_max_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_max_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_actual_cert_data_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_actual_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->operation_type != KCM_CHAIN_OP_TYPE_OPEN), KCM_STATUS_INVALID_PARAMETER, "Invalid operation type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->current_cert_index >= chain_context->num_of_certificates_in_chain), KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Invalid certificate index");

    if (chain_context->current_kcm_ctx.is_file_size_checked == false) {
        // if user skip call to kcm_cert_chain_get_next_size
        kcm_status = kcm_cert_chain_get_next_size((kcm_cert_chain_handle*)chain_context, &expected_data_size);
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


kcm_status_e kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle)
{
    kcm_cert_chain_context_int_s *chain_context = (kcm_cert_chain_context_int_s*)kcm_chain_handle;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (kcm_chain_handle == NULL) {
        goto Exit; // and return KCM_STATUS_SUCCESS
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((chain_context->num_of_certificates_in_chain == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid num_of_certificates_in_chain");

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
        kcm_cert_chain_files_delete(chain_context);
        SA_PV_ERR_RECOVERABLE_GOTO_IF(true, (kcm_status = KCM_STATUS_CLOSE_INCOMPLETE_CHAIN), Exit, "Closing incomplete kcm chain");
    }

Exit:
    if (chain_context != NULL) {
        fcc_free(chain_context->chain_name);
        fcc_free(chain_context);
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;

}


kcm_status_e kcm_key_pair_generate_and_store(
    const kcm_crypto_key_scheme_e    key_scheme,
    const uint8_t                    *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                    *public_key_name,
    size_t                            public_key_name_len,
    bool                              kcm_item_is_factory,
    const kcm_security_desc_s        *kcm_params)

{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t actual_kcm_priv_key_size = 0;
    size_t actual_kcm_pub_key_size = 0;
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];
    uint8_t pub_key_buffer[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    bool pub_key_exists = false;

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //temporary check that kcm_params is NULL                                                                                                   
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_params != NULL), KCM_STATUS_INVALID_PARAMETER, "kcm_params is not NULL!");

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_scheme != KCM_SCHEME_EC_SECP256R1), KCM_STATUS_INVALID_PARAMETER, "Invalid key_scheme");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name != NULL) && (public_key_name_len == 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is not NULL, but its size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name == NULL) && (public_key_name_len != 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is NULL, but its size is not 0");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32 ", pub_key_name = %.*s pub_key_len = %" PRIu32,
        (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);

    pub_key_exists = ((public_key_name != NULL) && (public_key_name_len != 0));

    //check private key existence
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &actual_kcm_priv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //fetch public key if exists
    if (pub_key_exists) {
        kcm_status = kcm_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM,
                                            &actual_kcm_pub_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");
    }

    //generate key pair
    kcm_status = cs_key_pair_generate(key_scheme, priv_key_buffer, sizeof(priv_key_buffer), &actual_kcm_priv_key_size, pub_key_buffer, sizeof(pub_key_buffer), &actual_kcm_pub_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate key pair");

    //store private key
    kcm_status = kcm_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, kcm_item_is_factory, priv_key_buffer, actual_kcm_priv_key_size, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store private key");

    //store public key if exists
    if (pub_key_exists) {
        kcm_status = kcm_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, kcm_item_is_factory, pub_key_buffer, actual_kcm_pub_key_size, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store public key");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e kcm_csr_generate(
    const uint8_t            *private_key_name,
    size_t                   private_key_name_len,
    const kcm_csr_params_s   *csr_params,
    uint8_t                  *csr_buff_out,
    size_t                   csr_buff_max_size,
    size_t                   *csr_buff_act_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t prv_key_size, actual_prv_key_size = 0;
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->md_type == KCM_MD_NONE), KCM_STATUS_INVALID_PARAMETER, "Invalid md type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_act_size");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32", csr_buff_max_size = %" PRIu32,
        (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (uint32_t)csr_buff_max_size);

    //fetch private key size
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &prv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get private key data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((prv_key_size == 0), kcm_status, "Size of private key is 0");

    //fetch private key
    kcm_status = kcm_item_get_data(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, priv_key_buffer,
                                   prv_key_size, &actual_prv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to get private key");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((actual_prv_key_size == 0), kcm_status = KCM_STATUS_ITEM_IS_EMPTY, "Size of private key is 0");

    //generate csr
    kcm_status = cs_csr_generate(priv_key_buffer, actual_prv_key_size, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate CSR");

    SA_PV_LOG_INFO_FUNC_EXIT("csr_buff_act_size = %" PRIu32 "", (uint32_t)*csr_buff_act_size);

    return kcm_status;

}


kcm_status_e kcm_generate_keys_and_csr(
    kcm_crypto_key_scheme_e   key_scheme,
    const uint8_t             *private_key_name,
    size_t                    private_key_name_len,
    const uint8_t             *public_key_name,
    size_t                    public_key_name_len,
    bool                      kcm_item_is_factory,
    const kcm_csr_params_s    *csr_params,
    uint8_t                   *csr_buff_out,
    size_t                    csr_buff_max_size,
    size_t                    *csr_buff_act_size_out,
    const kcm_security_desc_s *kcm_params)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t actual_kcm_key_size = 0;
    size_t priv_key_act_size_out = 0;
    size_t pub_key_act_size_out = 0;
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];
    uint8_t pub_key_buffer[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    bool pub_key_exists = false;

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //temporary check that kcm_params is NULL                                                                                                   
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_params != NULL), KCM_STATUS_INVALID_PARAMETER, "kcm_params is not NULL!");

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_scheme != KCM_SCHEME_EC_SECP256R1), KCM_STATUS_INVALID_PARAMETER, "Invalid key_scheme");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name != NULL) && (public_key_name_len == 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is not NULL, but its size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name == NULL) && (public_key_name_len != 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is NULL, but its size is not 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->md_type == KCM_MD_NONE), KCM_STATUS_INVALID_PARAMETER, "Invalid md type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_act_size");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32 ", pub_key_name = %.*s pub_key_len = %" PRIu32,
        (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);

    pub_key_exists = ((public_key_name != NULL) && (public_key_name_len != 0));

    //check private key existence
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &actual_kcm_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //check public key existence
    if (pub_key_exists) {
        kcm_status = kcm_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM,
                                            &actual_kcm_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");
    }

    //generat keys and csr
    kcm_status = cs_generate_keys_and_csr(key_scheme, csr_params, priv_key_buffer, sizeof(priv_key_buffer), &priv_key_act_size_out, pub_key_buffer, sizeof(pub_key_buffer), &pub_key_act_size_out, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate keys and csr");

    //store private key
    kcm_status = kcm_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, kcm_item_is_factory, priv_key_buffer, sizeof(priv_key_buffer), NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store private key");

    //store public key
    if (pub_key_exists) {
        kcm_status = kcm_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, kcm_item_is_factory, pub_key_buffer, sizeof(pub_key_buffer), NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store public key");
    }


    SA_PV_LOG_INFO_FUNC_EXIT("csr_buff_act_size_out = %" PRIu32 "", (uint32_t)*csr_buff_act_size_out);
    return kcm_status;

}

kcm_status_e kcm_certificate_verify_with_private_key(
    const uint8_t * kcm_cert_data,
    size_t kcm_cert_data_size,
    const uint8_t * kcm_priv_key_name,
    size_t kcm_priv_key_name_len)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t priv_key_data_size = 0;
    uint8_t *priv_key_data = NULL;
    size_t act_priv_key_data_size = 0;
    palX509Handle_t x509_cert;

    // Check if KCM initialized, if not initialize it
    if (!kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_priv_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_priv_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_priv_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_priv_key_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("priv key name =  %.*s, cert size=%" PRIu32 "", (int)kcm_priv_key_name_len, (char*)kcm_priv_key_name,(uint32_t)kcm_cert_data_size);

    //Get private key size
    kcm_status = kcm_item_get_data_size(kcm_priv_key_name,
        kcm_priv_key_name_len,
        KCM_PRIVATE_KEY_ITEM,
        &priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS || priv_key_data_size == 0), kcm_status, "Failed to get kcm private key size");

    //Allocate memory and get private key data
    priv_key_data = fcc_malloc(priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_data == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to allocate buffer for private key data");

    //Get private key data
    kcm_status = kcm_item_get_data(kcm_priv_key_name,
        kcm_priv_key_name_len,
        KCM_PRIVATE_KEY_ITEM,
        priv_key_data,
        priv_key_data_size,
        &act_priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS || act_priv_key_data_size != priv_key_data_size), (kcm_status = kcm_status), Exit, "Failed to get private key data");

    //Create certificate handle
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &x509_cert);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to create certificate handle");

    //Check current certificate against given private key
    kcm_status = cs_check_certifcate_public_key(x509_cert, priv_key_data, priv_key_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR), Exit, "Certificate verification failed against private key");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
Exit:

    fcc_free(priv_key_data);
    cs_close_handle_x509_cert(&x509_cert);
    return kcm_status;

}


