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

#ifndef __STORAGE_INTERNAL_H__
#define __STORAGE_INTERNAL_H__

#include "storage_items.h"



/** Implementation function of writing a new item to storage
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

kcm_status_e storage_item_store_impl(const uint8_t * kcm_item_name,
                                     size_t kcm_item_name_len,
                                     kcm_item_type_e kcm_item_type,
                                     bool kcm_item_is_factory,
                                     bool kcm_item_is_encrypted,
                                     storage_item_prefix_type_e item_prefix_type,
                                     const uint8_t * kcm_item_data,
                                     size_t kcm_item_data_size);

/**
*   The function returns prefix, according to kcm type and data source type
*    @param[in] kcm_item_type     type of KCM item.
*    @param[in] item_prefix_type  KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
*    @param[out] prefix           returned prefix
*    @returns
*       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_get_prefix_from_type(kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type, const char** prefix);


/**
 * @param[in] kcm_item_type                 KCM item type as defined in `::kcm_item_type_e`
 * @param[in] item_prefix_type              KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
 * @param[in] kcm_item_name                 KCM item name.
 * @param[in] kcm_item_name_len             KCM item name length. Must be at most KCM_MAX_FILENAME_SIZE bytes
 * @param[out] kcm_complete_name_out        KCM item name.
 *                                          if MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is defined, then
 *                                          null terminator will be written at the end of the name.
 *                                          if MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is *NOT* defined, then
 *                                          there is no guaranty null terminator at the end of the name, the caller MUST
 *                                          use the kcm_complete_name_size_out to verify the name actual size.
 * @param[out] kcm_complete_name_size_out   KCM item name length.
 * @param[out] chain_cert_info              KCM certificate name info. Relevant for storage_items_pal_sst.c only.
 *                                          not used ion storage_items_pelion_sst.c implementation.
 */
kcm_status_e storage_build_complete_working_item_name(
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    char *kcm_complete_name_out,
    size_t *kcm_complete_name_size_out,
    void *chain_cert_info);

/**
 * The function checks KCM item name length. Should be less than ::KCM_MAX_FILENAME_SIZE bytes (including "\0")
 * Also checks characters validity. Can be only alphanumeric, ".", "-", "_"
 *
 * @param[in] kcm_item_name                 KCM item name.
 * @param[in] kcm_item_name_len             KCM item name length. Must be at most ::KCM_MAX_FILENAME_SIZE bytes
 */
kcm_status_e storage_check_name_validity(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len);

/**
 * The implementation of storage_cert_chain_add_next API.
 * There are 2 implementations - one in storage_items_pal_sst.c and another one in storage_items_pelion_sst
 *
 *    @param[in] kcm_chain_handle                 certificate chain handle.
 *    @param[in] kcm_cert_data                    pointer to certificate data in DER format.
 *    @param[in] kcm_cert_data_size               size of certificate data buffer.
 *    @param[in] item_prefix_type                 KCM item prefix type (KCM or CE) as defined in
 * `::storage_item_prefix_type_e`
 *
 *    @returns
 *        KCM_STATUS_SUCCESS in case of success.
 *        KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED in case that one of the certificate in the chain failed to
 * verify its predecessor In other casese - one of the `::kcm_status_e` errors.
 *
 */
kcm_status_e storage_cert_chain_add_next_impl(kcm_cert_chain_handle kcm_chain_handle,
        const uint8_t *kcm_cert_data,
        size_t kcm_cert_data_size,
        storage_item_prefix_type_e item_prefix_type);

/** Initializes the specific storage backend so that it can be used.
*   Must be called once after boot.
*   Existing data in storage would not compromised.
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_specific_init(void);

/** Finalize the specific storage backend.
*   Must be called once to close all storage resources.
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_specific_finalize(void);

#endif //__STORAGE_INTERNAL_H__
