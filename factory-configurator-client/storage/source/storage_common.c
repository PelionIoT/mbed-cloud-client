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
#include "storage.h"
#include "esfs.h"
#include "fcc_malloc.h"

extern bool g_kcm_initialized;

/**
*   The function returns prefix, according to kcm type and data source type
*    @param[in] kcm_item_type     type of KCM item.
*    @param[in] item_source_type  type of source type (original or backup)
*    @param[out] prefix           returned prefix
*    @returns
*       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_item_name_get_prefix(kcm_item_type_e kcm_item_type, kcm_data_source_type_e item_source_type, const char** prefix)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_source_type != KCM_ORIGINAL_ITEM && item_source_type != KCM_BACKUP_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid item_source_type");

    switch (kcm_item_type) {
    case KCM_PRIVATE_KEY_ITEM:
        (item_source_type == KCM_ORIGINAL_ITEM) ? (*prefix = KCM_FILE_PREFIX_PRIVATE_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_PRIVATE_KEY);
        break;
    case KCM_PUBLIC_KEY_ITEM:
        (item_source_type == KCM_ORIGINAL_ITEM) ? (*prefix = KCM_FILE_PREFIX_PUBLIC_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_PUBLIC_KEY);
        break;
    case KCM_SYMMETRIC_KEY_ITEM:
        (item_source_type == KCM_ORIGINAL_ITEM) ? (*prefix = KCM_FILE_PREFIX_SYMMETRIC_KEY) : (*prefix = KCM_RENEWAL_FILE_PREFIX_SYMMETRIC_KEY);
        break;
    case KCM_CERTIFICATE_ITEM:
        (item_source_type == KCM_ORIGINAL_ITEM) ? (*prefix = KCM_FILE_PREFIX_CERTIFICATE) : (*prefix = KCM_RENEWAL_FILE_PREFIX_CERTIFICATE);
        break;
    case KCM_CONFIG_ITEM:
        (item_source_type == KCM_ORIGINAL_ITEM) ? (*prefix = KCM_FILE_PREFIX_CONFIG_PARAM) : (*prefix = KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM);
        break;
    default:
        status = KCM_STATUS_INVALID_PARAMETER;
        break;
    }
    return status;
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
kcm_status_e storage_data_write(const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    kcm_data_source_type_e data_source_type,
    const uint8_t * kcm_item_data,
    size_t kcm_item_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    bool kcm_item_is_encrypted = true;


    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %.*s len=%" PRIu32 ", data size=%" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data == NULL) && (kcm_item_data_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_CONFIG_ITEM && kcm_item_data_size == 0), KCM_STATUS_ITEM_IS_EMPTY, "The data of current item is empty!");
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

    kcm_status = storage_data_write_impl(kcm_item_name, kcm_item_name_len, kcm_item_type, kcm_item_is_factory, kcm_item_is_encrypted, data_source_type, kcm_item_data, kcm_item_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "storage_data_write_impl failed\n");

    return kcm_status;

}

