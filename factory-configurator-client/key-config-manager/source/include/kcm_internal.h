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

#ifdef __cplusplus
extern "C" {
#endif

/* === Definitions and Prototypes === */

/* === Defines === */
#define FCC_ENTROPY_SIZE                   48
#define FCC_ROT_SIZE                       16
#define FCC_CA_IDENTIFICATION_SIZE         33 //PAL_CERT_ID_SIZE

/* === EC max sizes === */
#define KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE           130
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

#define KCM_FILE_PREFIX_MAX_SIZE 12


// Make sure that pointer_to_complete_name points to a type of size 1 (char or uint8_t) so that arithmetic works correctly
#define KCM_FILE_BASENAME(pointer_to_complete_name, prefix_define) (pointer_to_complete_name + sizeof(prefix_define) - 1)
// Complete name is the prefix+name (without '/0')
#define KCM_FILE_BASENAME_LEN(complete_name_size, prefix_define) (complete_name_size - (sizeof(prefix_define) - 1))


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
    } kcm_cert_chain_context_int_s;


#ifdef __cplusplus
}
#endif

#endif //KEYS_CONFIG_MANAGER_INTERNAL_H

