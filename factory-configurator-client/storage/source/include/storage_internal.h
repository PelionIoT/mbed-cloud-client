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


/**
* KCM file prefixes defines
*/
#define KCM_FILE_PREFIX_PRIVATE_KEY       "PrvKey_"
#define KCM_FILE_PREFIX_PUBLIC_KEY        "PubKey_"
#define KCM_FILE_PREFIX_SYMMETRIC_KEY     "SymKey_"
#define KCM_FILE_PREFIX_CONFIG_PARAM      "CfgParam_"

/**
* KCM file prefixes defines for backup items
*/
#define KCM_RENEWAL_FILE_PREFIX_PRIVATE_KEY       "bPvKey_"
#define KCM_RENEWAL_FILE_PREFIX_PUBLIC_KEY        "bPbKey_"
#define KCM_RENEWAL_FILE_PREFIX_SYMMETRIC_KEY     "bSmKey_"
#define KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM      "mCfgParm_"


#if !defined  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#define KCM_FILE_PREFIX_CERTIFICATE       "Cert_"
#define KCM_FILE_PREFIX_CERT_CHAIN_0      KCM_FILE_PREFIX_CERTIFICATE
#define KCM_FILE_PREFIX_CERT_CHAIN_X      "Crt1_" // must be same length as KCM_FILE_PREFIX_CERT_CHAIN_0
#define KCM_FILE_PREFIX_CERT_CHAIN_X_OFFSET 3
#define KCM_RENEWAL_FILE_PREFIX_CERTIFICATE       "bCrt_"
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0      KCM_RENEWAL_FILE_PREFIX_CERTIFICATE
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X      "bCt1_" // must be same length as KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X_OFFSET 3
#define STORAGE_TYPE_PREFIX_MAX_LENGTH  0
#else //PSA
/**
* KCM file prefixes defines
*/
#define KCM_FILE_PREFIX_CERTIFICATE       "Crtae_"
#define KCM_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE       "Crta__"

/**
* KCM file prefixes defines for backup items
*/
#define KCM_RENEWAL_FILE_PREFIX_CERTIFICATE       "bCtae_"
#define KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM      "mCfgParm_"
#define KCM_RENEWAL_FILE_PREFIX_FIRST_CHAIN_CERTIFICATE       "bCta__"

#define STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM   "FR_ON"
//The complete name of kcm items will be build from pelion prefix and working or backup(for factory) acronyms : "pelion_w" or "pelion_b" for factory kcm items.
//Pelion prefix
#define STORAGE_PELION_PREFIX "pelion_"
//Defines of working and backup acronyms
#define STORAGE_WORKING_ACRONYM "w"
#define STORAGE_BACKUP_ACRONYM "b"
#define STORAGE_WORKING  STORAGE_PELION_PREFIX STORAGE_WORKING_ACRONYM// "pelion_w"
#define STORAGE_BACKUP STORAGE_PELION_PREFIX STORAGE_BACKUP_ACRONYM // "pelion_b"
#define STORAGE_TYPE_PREFIX_MAX_LENGTH 8 //sizeof STORAGE_BACKUP //8 STORAGE_WORKING

typedef struct kcm_chain_cert_name_info_ {
    uint32_t certificate_index;
    bool is_last_certificate;
} kcm_chain_cert_info_s;

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

//Max size of storage item prefix
#define STORAGE_ITEM_TYPE_PREFIX_MAX_LENGTH 16
#define STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH  STORAGE_TYPE_PREFIX_MAX_LENGTH + STORAGE_ITEM_TYPE_PREFIX_MAX_LENGTH + KCM_MAX_FILENAME_SIZE
//The complete storage item name composed from :
//    1. STORAGE_TYPE_PREFIX_MAX_LENGTH -
//     for esfs configuration : STORAGE_TYPE_PREFIX_MAX_LENGTH = 0
//     for EXTERNAL_SST configuration: STORAGE_TYPE_PREFIX_MAX_LENGTH=STORAGE_WORKING = 8 = strlen"pelion_w"
//    2. STORAGE_ITEM_TYPE_PREFIX_MAX_LENGTH - 
//        item type prefix refers to KCM item prefixes of both types (KCM and CE) and certificate chain naming = 16
//    3. KCM_MAX_FILENAME_SIZE = 100
//  Total complete max name size is 124 for external sst and 116 for esfs.

/**
* Chain operations
*/
typedef enum {
    STORAGE_CHAIN_OP_TYPE_CREATE = 1,
    STORAGE_CHAIN_OP_TYPE_OPEN,
    STORAGE_CHAIN_OP_TYPE_MAX
} storage_chain_operation_type_e;


/**
* The chain context used internally only and should not be changed by user.
*/
typedef struct storage_cert_chain_context_ {
    uint8_t chain_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH];//!< The name of certificate chain.
    size_t  chain_name_len;                                 //!< The size of certificate chain name.
    size_t num_of_certificates_in_chain;                    //!< The number of certificate in the chain.
#if !defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    store_esfs_file_ctx_s current_kcm_ctx;                  //!< Current KCM operation context.
#endif
    uint32_t current_cert_index;                            //!< Current certificate iterator.
    storage_chain_operation_type_e operation_type;          //!< Type of Current operation.
    bool is_factory;                                        //!< Is chain is a factory item, otherwise false.
    storage_chain_prev_cert_params_s prev_cert_params;      //!< Saved params of previous parsed certificate. used only in create operation
    bool is_meta_data;                                      //!< Is this a single certificate or chain with one certificate.
#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT || defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT 
    size_t  certificates_info[KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN]; //!< Array of the sizes of the certificates in chain
#endif
} storage_cert_chain_context_s;


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


/** Internal Ceritificate chains APIs for PAL SST and PSA */

/** Set certificate info for the certificate chain
 * This API sets size for each certificate in the chain and updates the total certificates number in the chain
 *
 * @param[in] chain_context                 certificate chain context.
 * @param[in] item_prefix_type              Storage item prefix type.
 *
 *   @returns
 *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e set_certificates_info(storage_cert_chain_context_s *chain_context, storage_item_prefix_type_e item_prefix_type);


/** Delete certificate chain
 *
 * @param[in] chain_context                 certificate chain context.
 * @param[in] item_prefix_type              Storage item prefix type.
*/
void chain_delete(storage_cert_chain_context_s *chain_context, storage_item_prefix_type_e item_prefix_type);


kcm_status_e pal_to_kcm_error_translation(palStatus_t pal_status);

kcm_status_e build_complete_backup_item_name(
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    char *kcm_complete_name_out,
    void *cert_name_info);


kcm_status_e check_certificate_existance(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, storage_item_prefix_type_e item_prefix_type);



#endif //__STORAGE_INTERNAL_H__
