// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#include "storage_dispatcher.h"

// Declare the operation functions in this .c file so that they are never called directly.
// They should always be called via the dispatcher

/* === Data Operations === */

/** Writes a new item to storage
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
*    @param[in] item_prefix_type KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
*    @param[in] kcm_item_data KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
*    @param[in] kcm_item_data_size KCM item data buffer size in bytes. Can be 0 if you wish to
*     store an empty file.
*
*  @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_item_store(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    storage_item_prefix_type_e item_prefix_type,
    const uint8_t *kcm_item_data,
    size_t kcm_item_data_size,
    const kcm_security_desc_s kcm_item_info);

/** Reads data size from the storage.
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] item_prefix_type KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
*    @param[out] kcm_item_data_size_out KCM item data size in bytes.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.*/
kcm_status_e storage_item_get_data_size(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    size_t *kcm_item_data_size_out);

/** Reads data item from the storage.
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] item_prefix_type KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
*    @param[in/out] kcm_item_data_out KCM item data output buffer. Can be NULL if `kcm_item_data_size` is 0.
*    @param[in] kcm_item_data_max_size The maximum size of the KCM item data output buffer in bytes.
*    @param[out] kcm_item_data_act_size_out Actual KCM item data output buffer size in bytes.
*
*    @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_item_get_data(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    uint8_t *kcm_item_data_out,
    size_t kcm_item_data_max_size,
    size_t *kcm_item_data_act_size_out);

/** Deletes data item from the storage.
*
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] item_prefix_type KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
*
*    @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_item_delete(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
// Declare these functions here instead of an external header files since they should not be called directly - only via storage_func_dispatch()
kcm_status_e storage_key_store(const uint8_t * key_name, size_t key_name_len, kcm_item_type_e key_type, bool kcm_item_is_factory, storage_item_prefix_type_e item_prefix_type, const uint8_t * kcm_item_data, size_t kcm_item_data_size, const kcm_security_desc_s kcm_item_info);
kcm_status_e storage_key_get_data(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e key_type, storage_item_prefix_type_e item_prefix_type, uint8_t *key_data_out, size_t key_data_max_size, size_t *key_data_act_size_out);
kcm_status_e storage_key_get_data_size(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e key_type, storage_item_prefix_type_e item_prefix_type, size_t *key_data_act_size_out);
kcm_status_e storage_key_delete(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type);

// PSA storage function table
static void *g_storage_functions[STORAGE_FUNC_NUM][STORAGE_TYPE_DATA_NUM] = {
    { (void *)storage_key_get_data,      (void *)storage_item_get_data},
    { (void *)storage_key_get_data_size, (void *)storage_item_get_data_size},
    { (void *)storage_key_store,         (void *)storage_item_store},
    { (void *)storage_key_delete,        (void *)storage_item_delete}
};

#else

// Non-PSA storage function table
static void *g_storage_functions[STORAGE_FUNC_NUM][STORAGE_TYPE_DATA_NUM] =
{
    { (void *)storage_item_get_data,      (void *)storage_item_get_data},
    { (void *)storage_item_get_data_size, (void *)storage_item_get_data_size},
    { (void *)storage_item_store,         (void *)storage_item_store},
    { (void *)storage_item_delete,        (void *)storage_item_delete}
};
#endif

#define GET_STORAGE_ELEMENT_TYPE(kcm_item_type) ((kcm_item_type < KCM_SYMMETRIC_KEY_ITEM) ? 0 : 1)

void *storage_func_dispatch(storage_func_e caller, kcm_item_type_e kcm_item_type)
{
    return g_storage_functions[caller][GET_STORAGE_ELEMENT_TYPE(kcm_item_type)];
}
