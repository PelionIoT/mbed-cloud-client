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
#ifndef __STORAGE_H__
#define __STORAGE_H__

#include <inttypes.h>
#include "key_config_manager.h"
#include "kcm_defs.h"
#include "cs_hash.h"
#include "cs_der_keys_and_csrs.h"
#include "storage_esfs.h"
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#define STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM   "FR_ON"
//The complete name of kcm items will be build from pelion prefix and working or backup(for factory) acronyms : "pelion_w" or "pelion_b" for factory kcm items.
//Pelion prefix
#define STORAGE_PELION_PREFIX "pelion_"
//Defines of working and backup acronyms
#define STORAGE_WORKING_ACRONYM "w"
#define STORAGE_BACKUP_ACRONYM "b"
#define STORAGE_WORKING  STORAGE_PELION_PREFIX STORAGE_WORKING_ACRONYM// "pelion_w"
#define STORAGE_BACKUP STORAGE_PELION_PREFIX STORAGE_BACKUP_ACRONYM // "pelion_b"
    typedef struct kcm_chain_cert_name_info_ {
        uint32_t certificate_index;
        bool is_last_certificate;
    } kcm_chain_cert_name_info_s;
#endif

/* === Definitions and Prototypes === */

/* === FCC data Defines === */
#define FCC_ENTROPY_SIZE                   48
#define FCC_ROT_SIZE                       16
#define FCC_CA_IDENTIFICATION_SIZE         33
#define FCC_TIME_SIZE        sizeof(uint64_t)
// Size of factory disabled flag in SOTP - internal use only.
#define FCC_FACTORY_DISABLE_FLAG_SIZE    sizeof(int64_t)

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

#ifndef  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#define KCM_FILE_PREFIX_CERTIFICATE       "Cert_"
#define KCM_FILE_PREFIX_CERT_CHAIN_0      KCM_FILE_PREFIX_CERTIFICATE
#define KCM_FILE_PREFIX_CERT_CHAIN_X      "Crt1_" // must be same length as KCM_FILE_PREFIX_CERT_CHAIN_0
#define KCM_FILE_PREFIX_CERT_CHAIN_X_OFFSET 3
#define KCM_RENEWAL_FILE_PREFIX_CERTIFICATE       "bCrt_"
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0      KCM_RENEWAL_FILE_PREFIX_CERTIFICATE
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X      "bCt1_" // must be same length as KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_0
#define KCM_RENEWAL_FILE_PREFIX_CERT_CHAIN_X_OFFSET 3
#else

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
#endif


/**
* KCM  internal item types
*/
typedef enum {
    KCM_ORIGINAL_ITEM,        //!< KCM original data type 
    KCM_BACKUP_ITEM,          //!< KCM backup data type - added prefix "b"
    KCM_SOURCE_TYPE_LAST_ITEM     //!< KCM not defined item type.
} kcm_data_source_type_e;


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
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    kcm_ctx_s current_kcm_ctx;                //!< Current KCM operation context.
#endif


    uint32_t current_cert_index;              //!< Current certificate iterator.
    kcm_chain_operation_type_e operation_type;//!< Type of Current operation.
    bool chain_is_factory;                    //!< Is chain is a factory item, otherwise false.
    kcm_cert_chain_prev_params_int_s prev_cert_params; //!< Saved params of previous parsed certificate. used only in create operation
    bool is_meta_data;   //!< Is this a single certificate or chain with one certificate.
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    size_t  certificates_info[KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN];
#endif
} kcm_cert_chain_context_int_s;


//TODO: when kvstore chain implemented remove this to esfs defines
// Make sure that pointer_to_complete_name points to a type of size 1 (char or uint8_t) so that arithmetic works correctly
#define KCM_FILE_BASENAME(pointer_to_complete_name, prefix_define) (pointer_to_complete_name + sizeof(prefix_define) - 1)
// Complete name is the prefix+name (without '/0')
#define KCM_FILE_BASENAME_LEN(complete_name_size, prefix_define) (complete_name_size - (sizeof(prefix_define) - 1))



//Protected data names
#define MAX_SOTP_BUFFER_SIZE    FCC_ENTROPY_SIZE
#define STORAGE_RBP_FACTORY_DONE_NAME               "factory_done"
#define STORAGE_RBP_RANDOM_SEED_NAME                "entropy"
#define STORAGE_RBP_SAVED_TIME_NAME                 "saved_time"
#define STORAGE_RBP_LAST_TIME_BACK_NAME             "last_time_back"
#define STORAGE_RBP_ROT_NAME                        "rot"
#define STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME        "time_srv_id"
#define STORAGE_RBP_EXECUTION_MODE_NAME             "execution_mode"
#define STORAGE_RBP_OEM_TRANSFER_MODE_ENABLED_NAME  "oem_transfer_mode"
#define STORAGE_RBP_MIN_FW_VERSION_NAME             "min_fw_version"


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
palStatus_t storage_rbp_read(
        const char *item_name,
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
palStatus_t storage_rbp_write(
        const char *item_name,
        const uint8_t *data,
        size_t data_size,
        bool is_write_once);


#ifdef RBP_TESTING
/** Removes a rollback protected data from the storage.
*   For testing purposes only.
*   For "write once" items the behavior is different: In SOTP implementation - deletion allowed
*                                                     In SST implementation - PAL_ERR_ITEM_EXIST error returned
*   
*
*   @param[in] item_name A string name of the rollback protected item
*   @returns
*        PAL_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
palStatus_t storage_rbp_delete(const char *item_name);
#endif

/** FCC initiated operation, writes a rollback protected data.
*
*   @param[in] item_name A string name of the rollback protected item
*   @param[in] data A pointer to memory with the data to write into the storage. Can be NULL if data_length is 0.
*   @param[in] data_size The data length in bytes. Can be 0 if we wish to write an empty file.
*   @param[in] is_write_once Write once flag.
*   @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_fcc_rbp_write(
    const char *item_name,
    const uint8_t *data,
    size_t data_size,
    bool is_write_once);
/** FCC initiated operation, writes a rollback protected data.
*
*   @param[in] item_name A string name of the rollback protected item
*   @param[in] data A pointer to memory with the data to write into the storage. Can be NULL if data_length is 0.
*   @param[in] data_size The data length in bytes. Can be 0 if we wish to write an empty file.
*   @param[in] is_write_once Write once flag.
*   @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_fcc_rbp_read(
    const char *item_name,
    uint8_t *data,
    size_t data_size,
    size_t *data_actual_lenght_out);
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

/** Resets storage to an empty state.
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

/**
*   The function returns prefix, according to kcm type and data source type
*    @param[in] kcm_item_type     type of KCM item.
*    @param[in] item_source_type  type of source type (original or backup)
*    @param[out] prefix           returned prefix
*    @returns
*       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_item_name_get_prefix(kcm_item_type_e kcm_item_type, kcm_data_source_type_e item_source_type, const char** prefix);

/* === Data Operations === */
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
    size_t kcm_item_data_size);

kcm_status_e storage_data_write_impl(const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    bool kcm_item_is_encrypted,
    kcm_data_source_type_e data_source_type,
    const uint8_t * kcm_item_data,
    size_t kcm_item_data_size);


/** Reads data size from the storage.
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] data_source_type KCM data source type as defined in `::kcm_data_source_type_e`
*    @param[out] kcm_item_data_size_out KCM item data size in bytes.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.*/
kcm_status_e storage_data_size_read(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    size_t * kcm_item_data_size_out);

/** Reads data item from the storage.
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
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_data_read(
    const uint8_t * kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    kcm_data_source_type_e data_source_type,
    uint8_t *kcm_item_data_out,
    size_t kcm_item_data_max_size,
    size_t *kcm_item_data_act_size_out);

/** Deletes data item from the storage.
*
*
*    @param[in] kcm_item_name KCM item name.
*    @param[in] kcm_item_name_len KCM item name length.
*    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
*    @param[in] data_source_type KCM data source type as defined in `::kcm_data_source_type_e`
*
*    @returns
*       KCM_STATUS_SUCCESS in case of success otherwise one of kcm_status_e errors
*/
kcm_status_e storage_data_delete(
    const uint8_t * kcm_item_name,
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
kcm_status_e storage_cert_chain_create(
    kcm_cert_chain_handle *kcm_chain_handle,
    const uint8_t *kcm_chain_name,
    size_t kcm_chain_name_len,
    size_t kcm_chain_len,
    bool kcm_chain_is_factory,
    kcm_data_source_type_e data_source_type);

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
kcm_status_e storage_cert_chain_open(kcm_cert_chain_handle * kcm_chain_handle,
    const uint8_t *kcm_chain_name,
    size_t kcm_chain_name_len,
    kcm_data_source_type_e data_source_type,
    size_t *kcm_chain_len_out);

/** The API deletes all certificates of the chain from the storage, the certificate chain name created according to data source type(original or backup).
*
*    @param[in] kcm_chain_name                pointer to certificate chain name.
*    @param[in] kcm_chain_name_len            length of certificate chain name.
*    @param[in] data_source_type              certificate source type as defined in `::kcm_data_source_type_e`.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e storage_cert_chain_delete(const uint8_t *kcm_chain_name,
    size_t kcm_chain_name_len,
    kcm_data_source_type_e data_source_type);

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
kcm_status_e storage_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
    const uint8_t *kcm_cert_data,
    size_t kcm_cert_data_size,
    kcm_data_source_type_e data_source_type);

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
kcm_status_e storage_cert_chain_get_next_size(
    kcm_cert_chain_handle *kcm_chain_handle,
    kcm_data_source_type_e data_source_type,
    size_t *kcm_out_cert_data_size);
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
kcm_status_e storage_cert_chain_get_next_data(
    kcm_cert_chain_handle *kcm_chain_handle,
    uint8_t *kcm_cert_data,
    size_t kcm_max_cert_data_size,
    kcm_data_source_type_e data_source_type,
    size_t *kcm_actual_cert_data_size);

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
kcm_status_e storage_cert_chain_close(
    kcm_cert_chain_handle kcm_chain_handle,
    kcm_data_source_type_e data_source_type);


#ifdef __cplusplus
}
#endif

#endif //__STORAGE_H__
