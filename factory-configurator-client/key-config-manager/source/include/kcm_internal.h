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

#ifndef KEYS_CONFIG_MANAGER_INTERNAL_H
#define KEYS_CONFIG_MANAGER_INTERNAL_H

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "esfs.h"
#include "cs_hash.h"
#include "kcm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* === Definitions and Prototypes === */

/* === Defines === */
#define FCC_ENTROPY_SIZE                   48
#define FCC_ROT_SIZE                       16
#define FCC_CA_IDENTIFICATION_SIZE         33 //PAL_CERT_ID_SIZE

/* === EC max sizes === */
#define KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE           150
#define KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE            65
#define KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE            91
#define KCM_ECDSA_SECP256R1_MAX_SIGNATURE_SIZE_IN_BYTES  (256/8)*2 + 10 //74 bytes

/**
* KCM file prefixes defines
*/
#define KCM_FILE_PREFIX_PRIVATE_KEY       "PrvKey_"
#define KCM_FILE_PREFIX_PUBLIC_KEY        "PubKey_"
#define KCM_FILE_PREFIX_SYMMETRIC_KEY     "SymKey_"
#define KCM_FILE_PREFIX_CERTIFICATE       "Cert_"
#define KCM_FILE_PREFIX_CONFIG_PARAM      "CfgParam_"
#define KCM_FILE_PREFIX_CERT_CHAIN_0      KCM_FILE_PREFIX_CERTIFICATE
#define KCM_FILE_PREFIX_CERT_CHAIN_X      "Crt1_" // must be same length as KCM_FILE_PREFIX_CERT_CHAIN_0
#define KCM_FILE_PREFIX_CERT_CHAIN_X_OFFSET 3

/**
* KCM file prefixes defines for backup items
*/

#define KCM_RENEWAL_FILE_PREFIX_PRIVATE_KEY       "bPvKey_"
#define KCM_RENEWAL_FILE_PREFIX_PUBLIC_KEY        "bPbKey_"
#define KCM_RENEWAL_FILE_PREFIX_SYMMETRIC_KEY     "bSmKey_"
#define KCM_RENEWAL_FILE_PREFIX_CERTIFICATE       "bCrt_"
#define KCM_RENEWAL_FILE_PREFIX_CONFIG_PARAM      "mCfgParm_"
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0      KCM_RENEWAL_FILE_PREFIX_CERTIFICATE
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X      "bCt1_" // must be same length as KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X_OFFSET 3



#define KCM_FILE_PREFIX_MAX_SIZE 12


// Make sure that pointer_to_complete_name points to a type of size 1 (char or uint8_t) so that arithmetic works correctly
#define KCM_FILE_BASENAME(pointer_to_complete_name, prefix_define) (pointer_to_complete_name + sizeof(prefix_define) - 1)
// Complete name is the prefix+name (without '/0')
#define KCM_FILE_BASENAME_LEN(complete_name_size, prefix_define) (complete_name_size - (sizeof(prefix_define) - 1))

/**
* KCM  internal item types
*/
    typedef enum {
        KCM_ORIGINAL_ITEM,        //!< KCM original data type 
        KCM_BACKUP_ITEM,          //!< KCM backup data type - added prefix "b"
        KCM_SOURCE_TYPE_LAST_ITEM     //!< KCM not defined item type.
    } kcm_data_source_type_e;



    typedef enum {
        /* KCM_LOCAL_ACL_MD_TYPE,
           KCM_REMOTE_ACL_MD_TYPE,
           KCM_AUDIT_MD_TYPE,
           KCM_NAME_MD_TYPE,
           KCM_USAGE_MD_TYPE,*/
        KCM_CERT_CHAIN_LEN_MD_TYPE,
        KCM_MD_TYPE_MAX_SIZE // can't be bigger than ESFS_MAX_TYPE_LENGTH_VALUES
    } kcm_meta_data_type_e;

#if ESFS_MAX_TYPE_LENGTH_VALUES < KCM_MD_TYPE_MAX_SIZE
#error "KCM_MD_TYPE_MAX_SIZE can't be greater than ESFS_MAX_TYPE_LENGTH_VALUES"
#endif

    typedef struct kcm_meta_data_ {
        kcm_meta_data_type_e type;
        size_t data_size;
        uint8_t *data;
    } kcm_meta_data_s;

    typedef struct kcm_meta_data_list_ {
        // allocate a single meta data for each type
        kcm_meta_data_s meta_data[KCM_MD_TYPE_MAX_SIZE];
        size_t meta_data_count;
    } kcm_meta_data_list_s;

    typedef struct kcm_ctx_ {
        esfs_file_t esfs_file_h;
        size_t file_size;
        bool is_file_size_checked;
    } kcm_ctx_s;

    typedef enum {
        KCM_CHAIN_OP_TYPE_CREATE = 1,
        KCM_CHAIN_OP_TYPE_OPEN,
        KCM_CHAIN_OP_TYPE_MAX
    } kcm_chain_operation_type_e;


    /*
    * Structure containing all necessary data of a child X509 Certificate to be validated with its signers public key
    */
    typedef struct kcm_cert_chain_prev_params_int_ {
        uint8_t signature[KCM_ECDSA_SECP256R1_MAX_SIGNATURE_SIZE_IN_BYTES]; //!< The signature of certificate.
        size_t signature_actual_size;                                      //!< The size of signature.
        uint8_t htbs[CS_SHA256_SIZE];                                      //!< The hash of certificate's tbs.
        size_t htbs_actual_size;                                           //!< The size of hash digest.
    } kcm_cert_chain_prev_params_int_s;


    /** The chain context used internally only and should not be changed by user.
    */
    typedef struct kcm_cert_chain_context_int_ {
        uint8_t *chain_name;                      //!< The name of certificate chain.
        size_t  chain_name_len;                   //!< The size of certificate chain name.
        size_t num_of_certificates_in_chain;      //!< The number of certificate in the chain.
        kcm_ctx_s current_kcm_ctx;                //!< Current KCM operation context.
        uint32_t current_cert_index;              //!< Current certificate iterator.
        kcm_chain_operation_type_e operation_type;//!< Type of Current operation.
        bool chain_is_factory;                    //!< Is chain is a factory item, otherwise false.
        kcm_cert_chain_prev_params_int_s prev_cert_params; //!< Saved params of previous parsed certificate. used only in create operation
        bool is_meta_data;                        //!< Is this a single certificate or chain with one certificate.
    } kcm_cert_chain_context_int_s;


    /** Store the KCM item into a secure storage, the item name cerated according to data source type(original/backup).
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[in] kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *    @param[in] kcm_item_is_encrypted True if the KCM item should be encrypted, otherwise false.
    *    @param[in] kcm_item_data KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in] kcm_item_data_size KCM item data buffer size in bytes. Can be 0 if you wish to store an empty file.
    *    @param[in] data_source_type KCM item data source (original or backup).
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e _kcm_item_store(const uint8_t * kcm_item_name,
        size_t kcm_item_name_len,
        kcm_item_type_e kcm_item_type,
        bool kcm_item_is_factory,
        const uint8_t * kcm_item_data,
        size_t kcm_item_data_size,
        kcm_data_source_type_e data_source_type);

    /** Retrieve the KCM item data size from a storage according to data source type(original/backup).
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[in] data_source_type KCM data source type as defined in `::kcm_data_source_type_e`
    *    @param[out] kcm_item_data_size_out KCM item data size in bytes.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e _kcm_item_get_data_size(const uint8_t * kcm_item_name,
        size_t kcm_item_name_len,
        kcm_item_type_e kcm_item_type,
        kcm_data_source_type_e data_source_type,
        size_t *kcm_item_data_size_out);

    /** Retrieve KCM item data from a secure storage according to data source type(original/backup).
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[in] data_source_type KCM data source type as defined in `::kcm_data_source_type_e`
    *    @param[in/out] kcm_item_data_out KCM item data output buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in] kcm_item_data_max_size The maximum size of the KCM item data output buffer in bytes.
    *    @param[out] kcm_item_data_act_size_out Actual KCM item data output buffer size in bytes.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e  _kcm_item_get_data(const uint8_t * kcm_item_name,
        size_t kcm_item_name_len,
        kcm_item_type_e kcm_item_type,
        kcm_data_source_type_e data_source_type,
        uint8_t *kcm_item_data_out,
        size_t kcm_item_data_max_size,
        size_t *kcm_item_data_act_size_out);

    /** Delete a KCM item from a secure storage according to data source type(original/backup).
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[in] data_source_type KCM data source type as defined in `::kcm_data_source_type_e`
    *
    *    @returns
    *        KCM_STATUS_SUCCESS status in case of success or one of ::kcm_status_e errors otherwise.
    */
    kcm_status_e _kcm_item_delete(const uint8_t * kcm_item_name,
        size_t kcm_item_name_len,
        kcm_item_type_e kcm_item_type,
        kcm_data_source_type_e data_source_type);

    /* === Certificates chain APIs === */

    /** The API initializes chain context for write chain operation,
    *   This API should be called prior to ::kcm_cert_chain_add_next API.
    *
    *    @param[out] kcm_chain_handle                 pointer to certificate chain handle.
    *    @param[in]  kcm_chain_name                   pointer to certificate chain name.
    *    @param[in]  kcm_chain_name_len               length of certificate name buffer.
    *    @param[in]  kcm_chain_len                    number of certificates in the chain.
    *    @param[in]  kcm_chain_is_factory             True if the KCM chain is a factory item, otherwise false.
    *    @param[in] data_source_type                  The name of the certificate created according to data source type `::kcm_data_source_type_e`.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e _kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t kcm_chain_len, bool kcm_chain_is_factory, kcm_data_source_type_e data_source_type);

    /** The API initializes chain context for read chain operation.
    *   This API should be called prior to ::kcm_cert_chain_get_next_size and ::kcm_cert_chain_get_next_data APIs
    *
    *    @param[out] kcm_chain_handle                  pointer to certificate chain handle.
    *    @param[in]  kcm_chain_name                    pointer to certificate chain name.
    *    @param[in]  kcm_chain_name_len                size of certificate name buffer.
    *    @param[in] data_source_type                   The name of the certificate created according to data source type `::kcm_data_source_type_e`.
    *    @param[out] kcm_chain_len                     length of certificate chain.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e _kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type, size_t *kcm_chain_len_out);

    /** This API adds next certificate of chain to the storage, the certificate added with prefix according to data source type(original/backup).
    *
    *    @param[in] kcm_chain_handle                 certificate chain handle.
    *    @param[in] kcm_cert_data                    pointer to certificate data in DER format.
    *    @param[in] kcm_cert_data_size               size of certificate data buffer.
    *    @param[in] data_source_type                 certificate source type as defined in `::kcm_data_source_type_e`.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED in case that one of the certificate in the chain failed to verify its predecessor
    *        In other casese - one of the `::kcm_status_e` errors.
    *
    */
    kcm_status_e _kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size, kcm_data_source_type_e data_source_type);
    /** The API deletes all certificates of the chain from the storage, the certificate chain name created according to data source type(original or backup).
    *
    *    @param[in] kcm_chain_name                pointer to certificate chain name.
    *    @param[in] kcm_chain_name_len            length of certificate chain name.
    *    @param[in] data_source_type              certificate source type as defined in `::kcm_data_source_type_e`.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e _kcm_cert_chain_delete( const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, kcm_data_source_type_e data_source_type);
    /** The API returns size of the next certificate in the chain, the certificate chain name created according to data source type(original or backup).
    *  This API should be called prior to ::kcm_cert_chain_get_next_data.
    *  This operation does not increase chain's context iterator.
    *
    *    @param[in]  kcm_chain_handle        certificate chain handle.
    *    @param[in] data_source_type         certificate source type as defined in `::kcm_data_source_type_e.
    *    @param[out] kcm_cert_data_size      pointer size of next certificate.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN in case we reached the end of the chain
    *        Otherwise one of the `::kcm_status_e` errors.
    */
    kcm_status_e _kcm_cert_chain_get_next_size(kcm_cert_chain_handle *kcm_chain_handle, kcm_data_source_type_e data_source_type, size_t *kcm_out_cert_data_size);
    /** The API returns data of the next certificate in the chain, the certificate chain name created according to data source type(original or backup).
    *   To get exact size of a next certificate use ::kcm_cert_chain_get_next_size.
    *   In the end of get data operation, chain context points to the next certificate of current chain.
    *
    *    @param[in] kcm_chain_handle                    certificate chain handle.
    *    @param[in/out] kcm_cert_data                   pointer to certificate data in DER format.
    *    @param[in] kcm_max_cert_data_size              max size of certificate data buffer.
    *    @param[in] data_source_type                    certificate source type as defined in `::kcm_data_source_type_e.
    *    @param[out] kcm_actual_cert_data_size          actual size of certificate data.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN in case we reached the end of the chain
    *        Otherwise one of the `::kcm_status_e` errors.
    */
    kcm_status_e _kcm_cert_chain_get_next_data(kcm_cert_chain_handle *kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, kcm_data_source_type_e data_source_type, size_t *kcm_actual_cert_data_size);
    /** The API releases the context and frees allocated resources, the certificate chain name created according to data source type(original or backup).
    *   When operation type is creation--> if total number of added/stored certificates is not equal to number
    *   of certificates in the chain, the API will return an error.
    *
    *    @param[in] kcm_chain_handle                    certificate chain handle.
    *    @param[in] data_source_type                    certificate chain source type as defined in `::kcm_data_source_type_e.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_CLOSE_INCOMPLETE_CHAIN in case of not all certificates were saved. In this case the chain will be deleted.
    *        Otherwise one of the `::kcm_status_e` errors.
    */
    kcm_status_e _kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle, kcm_data_source_type_e data_source_type);

#ifdef __cplusplus
}
#endif

#endif //KEYS_CONFIG_MANAGER_INTERNAL_H
