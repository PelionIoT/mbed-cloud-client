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
#ifndef __STORAGE_ITEMS_H__
#define __STORAGE_ITEMS_H__

#include <inttypes.h>
#include "key_config_manager.h"
#include "kcm_defs.h"
#include "cs_der_keys_and_csrs.h"
#if !defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "storage_pelion_sst.h"
#endif
#if defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal_sst.h"
#endif
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* === Definitions and Prototypes === */

    /* === FCC data Defines === */
#define FCC_ENTROPY_SIZE 48
#define FCC_ROT_SIZE 16
#define FCC_CA_IDENTIFICATION_SIZE 33
#define FCC_TIME_SIZE sizeof(uint64_t)
// Size of factory disabled flag in SOTP - internal use only.
#define FCC_FACTORY_DISABLE_FLAG_SIZE sizeof(int64_t)

/**
 * Storage item prefix types
 * Based on this enum, prefix of the item, as it's stored in the back-end storage, is build
 * The current difference is between KCM prefix and certificate renewal prefix
 */
    typedef enum {
        STORAGE_ITEM_PREFIX_KCM, //!< KCM item prefix
        STORAGE_ITEM_PREFIX_CE,  //!< CE item prefix - prefix 'b' is added
        STORAGE_ITEM_PREFIX_MAX  //!< Prefix isn't defined
    } storage_item_prefix_type_e;

    /*
     * Structure containing all necessary data of a child X509 Certificate to be validated with its signers public key
     */
    typedef struct storage_chain_prev_cert_params_ {
        uint8_t signature[KCM_ECDSA_SECP256R1_MAX_SIGNATURE_DER_SIZE_IN_BYTES]; //!< The signature of certificate.
        size_t signature_actual_size;                                           //!< The size of signature.
        uint8_t htbs[KCM_SHA256_SIZE];                                          //!< The hash of certificate's tbs.
        size_t htbs_actual_size;                                                //!< The size of hash digest.
    } storage_chain_prev_cert_params_s;

#if defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    /**
     * Rollback Protected item type
     * RBP items behave differently during factory reset and therefore passed as a separate type to KSA. It shouldn't
     * collide with KCM Item types.
     */
    typedef enum {
        STORAGE_RBP_ITEM = KCM_LAST_ITEM + 1, // STORAGE rollback protected item
        STORAGE_LAST_ITEM
    } storage_item_type_e;
#endif // MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    // Protected data names
#define MAX_SOTP_BUFFER_SIZE FCC_ENTROPY_SIZE
#define STORAGE_RBP_FACTORY_DONE_NAME "factory_done"
#define STORAGE_RBP_RANDOM_SEED_NAME "entropy"
#define STORAGE_RBP_SAVED_TIME_NAME "saved_time"
#define STORAGE_RBP_LAST_TIME_BACK_NAME "last_time_back"
#define STORAGE_RBP_ROT_NAME "rot"
#define STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME "time_srv_id"
#define STORAGE_RBP_EXECUTION_MODE_NAME "execution_mode"
#define STORAGE_RBP_OEM_TRANSFER_MODE_ENABLED_NAME "oem_transfer_mode"
#define STORAGE_RBP_MIN_FW_VERSION_NAME "min_fw_version"

/* === Data Operations === */

/** Writes a new item to storage
 *
 *    @param[in] kcm_item_name KCM item name.
 *    @param[in] kcm_item_name_len KCM item name length.
 *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
 *    @param[in] kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
 *    @param[in] item_prefix_type KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
 *    @param[in] kcm_item_data KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
 *    @param[in] kcm_item_data_size KCM item data buffer size in bytes. Can be 0 if you wish to store an empty file.
 *    @param[in] is_delete_allowed True if the item is allowed to be deleted, otherwise false.
 *
 *  @returns
 *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
 */
    kcm_status_e storage_item_store(const uint8_t *kcm_item_name,
                                    size_t kcm_item_name_len,
                                    kcm_item_type_e kcm_item_type,
                                    bool kcm_item_is_factory,
                                    storage_item_prefix_type_e item_prefix_type,
                                    const uint8_t *kcm_item_data,
                                    size_t kcm_item_data_size,
                                    bool is_delete_allowed);

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
    kcm_status_e storage_item_get_data(const uint8_t *kcm_item_name,
                                       size_t kcm_item_name_len,
                                       kcm_item_type_e kcm_item_type,
                                       storage_item_prefix_type_e item_prefix_type,
                                       uint8_t *key_data_out,
                                       size_t key_data_max_size,
                                       size_t *key_data_act_size_out);

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
    kcm_status_e storage_item_get_data_size(const uint8_t *kcm_item_name,
                                            size_t kcm_item_name_len,
                                            kcm_item_type_e kcm_item_type,
                                            storage_item_prefix_type_e item_prefix_type,
                                            size_t *kcm_item_data_size_out);

    /**
     * Reads item data and its size from storage.
     * The buffer for the data is allocated internally and the caller is responsible to free it.
     * If kcm_status_e` error returned, no need to free the buffer
     * In PSA mode (MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is on), ::KCM_PRIVATE_KEY_ITEM type is not supported.
     *
     *    @param[in]  kcm_item_name              KCM item name.
     *    @param[in]  kcm_item_name_len          KCM item name length.
     *    @param[in]  kcm_item_type              KCM item type as defined in `::kcm_item_type_e`.
     *    @param[out] kcm_item_data_out          KCM item data output buffer. The buffer allocated internally.
     *    @param[out] kcm_item_data_size_out     KCM item data output buffer size in bytes.
     *
     *    @returns
     *        ::KCM_STATUS_SUCCESS            in case of success.
     *        ::KCM_STATUS_ITEM_NOT_FOUND     if kcm_item_name isn't found in the secure storage.
     *        One of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_item_get_size_and_data(const uint8_t *kcm_item_name,
                                                size_t kcm_item_name_len,
                                                kcm_item_type_e kcm_item_type,
                                                storage_item_prefix_type_e item_prefix_type,
                                                uint8_t **kcm_item_data_out,
                                                size_t *kcm_item_data_size_out);

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
    kcm_status_e storage_item_delete(const uint8_t *kcm_item_name,
                                     size_t kcm_item_name_len,
                                     kcm_item_type_e kcm_item_type,
                                     storage_item_prefix_type_e item_prefix_type);


#if defined (MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT) && defined (MBED_CONF_APP_SECURE_ELEMENT_PARSEC_TPM_SUPPORT)
    /** Deletes factory item data from the storage.
     *  Deletes items that were stored with factory_item tag.  
     *  Note: this function should be used only in a very special case!
     *
     *    @param[in] kcm_item_name KCM item name.
     *    @param[in] kcm_item_name_len KCM item name length.
     *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
     *    @param[in] item_prefix_type KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
     *
     *    @returns
     *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
     */
    kcm_status_e storage_factory_item_delete(const uint8_t *kcm_item_name,
                                    size_t kcm_item_name_len,
                                    kcm_item_type_e kcm_item_type,
                                    storage_item_prefix_type_e item_prefix_type);
#endif


    /* === Roll back protected data Operations === */
    /** Reads a rollback protected data from the storage
     *
     *   @param[in] item_name A string name of the rollback protected item
     *   @param[in/out] buffer A pointer to memory buffer where the data will be read.
     *   @param[in] buffer_size The data buffer size in bytes.
     *   @param[out] buffer_actual_size_out The effective bytes size read.
     *   @returns
     *        PAL_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    palStatus_t storage_rbp_read(const char *item_name,
                                 uint8_t *buffer,
                                 size_t buffer_size,
                                 size_t *buffer_actual_size_out);

    /** Writes a rollback protected data to the storage
     *
     *   @param[in] item_name A string name of the rollback protected item
     *   @param[in] data Buffer containing data (must be aligned to a 32 bit boundary).
     *   @param[in] data_length The data length in bytes. Can be 0 if we wish to write an empty file.
     *   @param[in] is_write_once Write once flag.
     *   @returns
     *        PAL_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    palStatus_t storage_rbp_write(const char *item_name, const uint8_t *data, size_t data_size, bool is_write_once);

    /* === Initialization and Finalization === */

    /** Initializes storage so that it can be used.
     *   Must be called once after boot.
     *   Existing data in storage would not compromised.
     *
     *   @returns
     *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
     */
    kcm_status_e storage_init(void);

    /** Finalize storage.
     *   Must be called once to close all storage resources.
     *
     *   @returns
     *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
     */
    kcm_status_e storage_finalize(void);

    /** Cleans all data (including keys) that was stored in backend storage and reset storage to an empty state
     *
     *   @returns
     *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
     */
    kcm_status_e storage_reset(void);

    /** Resets storage to a factory state.
     *
     *   @returns
     *       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
     */
    kcm_status_e storage_factory_reset(void);

    /* === Certificates chain APIs === */

    /** The API initializes chain context for write chain operation,
     *   This API should be called prior to ::kcm_cert_chain_add_next API.
     *
     *    @param[out] kcm_chain_handle                 pointer to certificate chain handle.
     *    @param[in]  kcm_chain_name                   pointer to certificate chain name.
     *    @param[in]  kcm_chain_name_len               length of certificate name buffer.
     *    @param[in]  kcm_chain_len                    number of certificates in the chain.
     *    @param[in]  kcm_chain_is_factory             True if the KCM chain is a factory item, otherwise false.
     *    @param[in]  item_prefix_type                 KCM item prefix type (KCM or CE) as defined in
     * `::storage_item_prefix_type_e`
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle,
                                           const uint8_t *kcm_chain_name,
                                           size_t kcm_chain_name_len,
                                           size_t kcm_chain_len,
                                           bool kcm_chain_is_factory,
                                           storage_item_prefix_type_e item_prefix_type);

    /** The API initializes chain context for read chain operation.
     *   This API should be called prior to ::kcm_cert_chain_get_next_size and ::kcm_cert_chain_get_next_data APIs
     *
     *    @param[out] kcm_chain_handle                  pointer to certificate chain handle.
     *    @param[in]  kcm_chain_name                    pointer to certificate chain name.
     *    @param[in]  kcm_chain_name_len                size of certificate name buffer.
     *    @param[in] item_prefix_type                   KCM item prefix type (KCM or CE) as defined in
     * `::storage_item_prefix_type_e`
     *    @param[out] kcm_chain_len                     length of certificate chain.
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle,
                                         const uint8_t *kcm_chain_name,
                                         size_t kcm_chain_name_len,
                                         storage_item_prefix_type_e item_prefix_type,
                                         size_t *kcm_chain_len_out);

    /** The API deletes all certificates of the chain from the storage, the certificate chain name created according to data
     * source type(original or backup).
     *
     *    @param[in] kcm_chain_name                pointer to certificate chain name.
     *    @param[in] kcm_chain_name_len            length of certificate chain name.
     *    @param[in] item_prefix_type              KCM item prefix type (KCM or CE) as defined in
     * `::storage_item_prefix_type_e`
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_cert_chain_delete(const uint8_t *kcm_chain_name,
                                           size_t kcm_chain_name_len,
                                           storage_item_prefix_type_e item_prefix_type);

    /** This API adds next certificate of chain to the storage, the certificate added with prefix according to data source
     * type(original/backup).
     *
     *    @param[in] kcm_chain_handle                 certificate chain handle.
     *    @param[in] kcm_cert_data                    pointer to certificate data in DER format.
     *    @param[in] kcm_cert_data_size               size of certificate data buffer.
     *    @param[in] item_prefix_type                 KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
     *    @param[in] is_delete_allowed                True if the item is allowed to be deleted, otherwise false.
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success.
     *        KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED in case that one of the certificate in the chain failed to
     * verify its predecessor In other casese - one of the `::kcm_status_e` errors.
     *
     */
    kcm_status_e storage_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
                                             const uint8_t *kcm_cert_data,
                                             size_t kcm_cert_data_size,
                                             storage_item_prefix_type_e item_prefix_type,
                                             bool is_delete_allowed);

    /** The API returns size of the next certificate in the chain, the certificate chain name created according to data
     * source type(original or backup). This API should be called prior to ::kcm_cert_chain_get_next_data. This operation
     * does not increase chain's context iterator.
     *
     *    @param[in]  kcm_chain_handle        certificate chain handle.
     *    @param[in] item_prefix_type         KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
     *    @param[out] kcm_cert_data_size      pointer size of next certificate.
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success.
     *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN in case we reached the end of the chain
     *        Otherwise one of the `::kcm_status_e` errors.
     */
    kcm_status_e storage_cert_chain_get_next_size(kcm_cert_chain_handle *kcm_chain_handle,
                                                  storage_item_prefix_type_e item_prefix_type,
                                                  size_t *kcm_out_cert_data_size);

    /** The API returns data of the next certificate in the chain, the certificate chain name created according to data
     * source type(original or backup). To get exact size of a next certificate use ::kcm_cert_chain_get_next_size. In the
     * end of get data operation, chain context points to the next certificate of current chain.
     *
     *    @param[in] kcm_chain_handle                    certificate chain handle.
     *    @param[in/out] kcm_cert_data                   pointer to certificate data in DER format.
     *    @param[in] kcm_max_cert_data_size              max size of certificate data buffer.
     *    @param[in] item_prefix_type                    KCM item prefix type (KCM or CE) as defined in
     * `::storage_item_prefix_type_e`
     *    @param[out] kcm_actual_cert_data_size          actual size of certificate data.
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success.
     *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN in case we reached the end of the chain
     *        Otherwise one of the `::kcm_status_e` errors.
     */
    kcm_status_e storage_cert_chain_get_next_data(kcm_cert_chain_handle *kcm_chain_handle,
                                                  uint8_t *kcm_cert_data,
                                                  size_t kcm_max_cert_data_size,
                                                  storage_item_prefix_type_e item_prefix_type,
                                                  size_t *kcm_actual_cert_data_size);

    /** The API releases the context and frees allocated resources, the certificate chain name created according to data
     * source type(original or backup). When operation type is creation--> if total number of added/stored certificates is
     * not equal to number of certificates in the chain, the API will return an error.
     *
     *    @param[in] kcm_chain_handle                    certificate chain handle.
     *    @param[in] item_prefix_type                    KCM item prefix type (KCM or CE) as defined in
     * `::storage_item_prefix_type_e`
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success.
     *        KCM_STATUS_CLOSE_INCOMPLETE_CHAIN in case of not all certificates were saved. In this case the chain will be
     * deleted. Otherwise one of the `::kcm_status_e` errors.
     */
    kcm_status_e storage_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle,
                                          storage_item_prefix_type_e item_prefix_type);

    /** The API returns true if chain hanlde holds a single certificate or a certificate chain.

    *    @param[in] kcm_chain_handle                    certificate chain handle.
    *
    *    @returns
    *        TRUE in case of certificate chain.
    *        FALSE in case of single certificate.
    */
    bool storage_is_cert_chain(kcm_cert_chain_handle kcm_chain_handle);

    /** Copies the content of an existing item entry to destination entry using a destination name prefix.
     *
     *    @param[in] kcm_item_name KCM item name.
     *    @param[in] kcm_item_name_len KCM item name length.
     *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
     *    @param[in] source_item_prefix_type existing key item_prefix_type KCM item prefix type as defined in
     * `::storage_item_prefix_type_e`
     *    @param[in] destination_item_prefix_type new key item_prefix_type KCM item prefix type as defined in
     * `::storage_item_prefix_type_e`
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_ce_item_copy(const uint8_t *kcm_item_name,
                                      size_t kcm_item_name_len,
                                      kcm_item_type_e kcm_item_type,
                                      storage_item_prefix_type_e source_item_prefix_type,
                                      storage_item_prefix_type_e destination_item_prefix_type);

    /** Removes an existing item. Exact implementation varies upon configuration
     *
     *    @param[in] key_name KCM item name.
     *    @param[in] key_name_len KCM item name length.
     *    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`
     *    @param[in] item_prefix_type KCM item prefix type as defined in `::storage_item_prefix_type_e`
     *    @param[in] new key item_prefix_type KCM item prefix type as defined in `::storage_item_prefix_type_e`
     *    @param[in] clean_active_item_only Flag to indicate if only active item should be cleaned. Used in PSA only
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_ce_clean_item(const uint8_t *kcm_item_name,
                                       size_t kcm_item_name_len,
                                       kcm_item_type_e kcm_item_type,
                                       storage_item_prefix_type_e item_prefix_type,
                                       bool clean_active_item_only);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

    /**
     * Gets the location of a certain item.
     * The location is the actual storage meduim as defined by ::kcm_item_location_e
     *
     *    @param[in]  kcm_item_name          KCM item name.
     *    @param[in]  kcm_item_name_len      KCM item name length.
     *    @param[in]  kcm_item_type          KCM item type as defined in `::kcm_item_type_e`.
     *                                       Only ::KCM_PRIVATE_KEY_ITEM and ::KCM_PUBLIC_KEY_ITEM are valid.
     *                                       Other types result in a ::KCM_STATUS_INVALID_PARAMETER error.
     *    @param[in] kcm_item_prefix_type    KCM item prefix type (KCM or CE) as defined in `::storage_item_prefix_type_e`
     *    @param[out] kcm_item_location_out  A pointer to the location on which the item resides.
     *                                       This variable will be set to the corresponding storage location as defined in
     * `::kcm_item_location_e`
     *    @returns
     *        ::KCM_STATUS_SUCCESS            in case of success.
     *        ::KCM_STATUS_ITEM_NOT_FOUND     if the item isn't found in the PSA storage.
     *        One of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_item_get_location(const uint8_t *kcm_item_name,
                                           size_t kcm_item_name_len,
                                           kcm_item_type_e kcm_item_type,
                                           storage_item_prefix_type_e kcm_item_prefix_type,
                                           kcm_item_location_e *kcm_item_location_out);

    /**
     * Gets the slot number of the private key.
     *
     *    @param[in]  prv_key_name          KCM private key name.
     *    @param[in]  prv_key_name_len      KCM private key name length in bytes.
     *    @param[out] se_prv_key_slot       output SE slot number of the key.
     *                                      Use output value only if function returns KCM_STATUS_SUCCESS.
     *
     *    @returns
     *        ::KCM_STATUS_SUCCESS            in case of success.
     *        One of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_se_private_key_get_slot(const uint8_t *prv_key_name,
                                                 size_t prv_key_name_len,
                                                 uint64_t *se_prv_key_slot);

#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

    /**
     * For PSA - implemented by storage_psa.c
     * For non-PSA - implemented by storage_non_psa.c
     */

     /** Retrieves a handle that refers to a valid existing KCM item in store according to the given data source type
      * (original or backup).
      *
      *    @param[in] key_name KCM item name.
      *    @param[in] key_name_len KCM item name length.
      *    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`
      *    @param[in] item_prefix_type KCM item prefix type as defined in `::storage_item_prefix_type_e`
      *    @param[out] key_h_out A handle value that refers the target KCM item in store.
      *
      *    @returns
      *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
      */
    kcm_status_e storage_key_get_handle(const uint8_t *key_name,
                                        size_t key_name_len,
                                        kcm_item_type_e key_type,
                                        storage_item_prefix_type_e item_prefix_type,
                                        kcm_key_handle_t *key_h_out);

    /** Frees all resources associated the key and sets zero to the handle value.
     *
     *    @key_handle[in] Pointer to key handle.
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
     // Change to get const pointer to key_handle so struct is not passed by value?
    kcm_status_e storage_key_close_handle(kcm_key_handle_t *key_handle);

    /** Generates a key pair according to the EC_SECP256R1 key scheme.
     *   The key pair is generated and stored in PSA.
     *   The key pair may be used later by calling to _kcm_item_get_handle() with the same supplied name.
     *
     *    @param[in] private_key_name The private key name that will be refer to the generated keypair in PSA.
     *    @param[in] private_key_name_len The private key name length.
     *    @param[in] key_source_type The private key source type as defined in `::kcm_data_source_type_e.
     *    @param[in] is_factory True if the KCM item is a factory item, false otherwise.
     *    @param[in] kcm_item_info Additional item data.
     *                             If NULL, the private and public keys are generated and stored in the default key resident, which is set pre-build.
     *                             If `kcm_item_policy_s`, the private and public keys are generated and stored in the selected resident defined in `::kcm_item_policy_s`.
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_key_pair_generate_and_store(const uint8_t *private_key_name,
                                                     size_t private_key_name_len,
                                                     const uint8_t *public_key_name,
                                                     size_t public_key_name_len,
                                                     storage_item_prefix_type_e item_prefix_type,
                                                     bool is_factory,
                                                     const kcm_security_desc_s kcm_item_info);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    /** Generates a new key/key pair based on existing keys using its policy.
     *   The generated keys saved in CE filed of existing keys. The active id of the existing keys is not changed.
     *
     *    @param[in] private_key_name KCM private key name.
     *    @param[in] private_key_name_len KCM private key length.
     *    @param[in] public_key_name KCM public key name.
     *    @param[in] public_key_name_len KCM public key length.
     *    @param[in/out] private_key_handle pointer to key handle with generated private key.
     *    @param[in/out] public_key_handle pointer to key handle with generated public key.
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */

    kcm_status_e storage_ce_generate_keys(const uint8_t *private_key_name,
                                          size_t private_key_name_len,
                                          const uint8_t *public_key_name,
                                          size_t public_key_name_len,
                                          kcm_key_handle_t *private_key_handle,
                                          kcm_key_handle_t *public_key_handle);

    /** Removes enrollment keys that were generated as part of CE proceess.
     *
     *    @param[in] ce_key_name CE key name.
     *    @param[in] ce_key_name_len CE key name length.
     *    @param[in] ce_key_type CE key type. Should be provate or public
     *    @param[in] ce_key_prefix_type CE key prefix type as defined in `::storage_item_prefix_type_e`
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_ce_destroy_ce_key(const uint8_t *ce_key_name,
                                           size_t ce_key_name_len,
                                           kcm_item_type_e ce_key_type,
                                           storage_item_prefix_type_e ce_key_prefix_type);

    /** Stores a new generated CE key using the existing name of the renewed key.
     *
     *    @param[in] key_name KCM item name.
     *    @param[in] key_name_len KCM item name length.
     *    @param[in] key_type KCM item type as defined in `::kcm_item_type_e`
     *    @param[in] item_prefix_type KCM item prefix type as defined in `::storage_item_prefix_type_e`
     *
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_ce_key_activate(const uint8_t *kcm_item_name,
                                         size_t kcm_item_name_len,
                                         kcm_item_type_e kcm_item_type,
                                         storage_item_prefix_type_e item_prefix_type);

    /** Destroys active id of backup keys and removes the key
     *
     *    @param[in] private_key_name KCM private key name.
     *    @param[in] private_key_name_len KCM private key name length.
     *    @param[in] public_key_name KCM public key name.
     *    @param[in] public_key_name_len KCM public key name length.
     *    @param[in] cert_name KCM cert name.
     *    @param[in] cert_name_len KCM cert name length.
     *    @returns
     *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
     */
    kcm_status_e storage_ce_destory_old_active_and_remove_backup_entries(const uint8_t *private_key_name,
                                                                         size_t private_key_name_len,
                                                                         const uint8_t *public_key_name,
                                                                         size_t public_key_name_len,
                                                                         const uint8_t *cert_name,
                                                                         size_t cert_name_len);

#endif

#ifdef __cplusplus
}
#endif

#endif //__STORAGE_ITEMS_H__
