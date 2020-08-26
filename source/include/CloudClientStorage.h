// ----------------------------------------------------------------------------
// Copyright 2016-2018 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef CLOUD_CLIENT_STORAGE_H
#define CLOUD_CLIENT_STORAGE_H

/** \internal \file CloudClientStorage.h */

#include <stddef.h>
#include <stdint.h>

#define KEY_ACCOUNT_ID                          "mbed.AccountID"
#define KEY_INTERNAL_ENDPOINT                   "mbed.InternalEndpoint"
#define KEY_DEVICE_SOFTWAREVERSION              "mbed.SoftwareVersion"
#define KEY_FIRST_TO_CLAIM                      "mbed.FirstToClaim"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CCS_STATUS_MEMORY_ERROR = -4,
    CCS_STATUS_VALIDATION_FAIL = -3,
    CCS_STATUS_KEY_DOESNT_EXIST = -2,
    CCS_STATUS_ERROR = -1,
    CCS_STATUS_SUCCESS = 0
} ccs_status_e;

/**
* CCS item types
* Keep these sync with ones that found from kcm_defs.h
*/
typedef enum {
    CCS_PRIVATE_KEY_ITEM,          //!< KCM private key item type. KCM Supports ECC keys with curves defined in palGroupIndex_t(pal_Crypto.h)
    CCS_PUBLIC_KEY_ITEM,           //!< KCM public key item type.  KCM Supports ECC keys with curves defined in palGroupIndex_t(pal_Crypto.h)
    CCS_SYMMETRIC_KEY_ITEM,        //!< KCM symmetric key item type.
    CCS_CERTIFICATE_ITEM,          //!< KCM certificate item type. Supported x509 certificates in der format.
    CCS_CONFIG_ITEM                //!< KCM configuration parameter item type.
} ccs_item_type_e;

/**
*  \brief Uninitializes the CFStore handle.
*/
ccs_status_e uninitialize_storage(void);

/**
*  \brief Initializes the CFStore handle.
*/
ccs_status_e initialize_storage(void);

/* Bootstrap credential handling methods */
ccs_status_e ccs_get_string_item(const char* key, uint8_t *buffer, const size_t buffer_size, ccs_item_type_e item_type);
ccs_status_e ccs_check_item(const char* key, ccs_item_type_e item_type);
ccs_status_e ccs_delete_item(const char* key, ccs_item_type_e item_type);
ccs_status_e ccs_get_item(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length, ccs_item_type_e item_type);
ccs_status_e ccs_set_item(const char* key, const uint8_t *buffer, const size_t buffer_size, ccs_item_type_e item_type);
ccs_status_e ccs_item_size(const char* key, size_t* size_out, ccs_item_type_e item_type);

/* Certificate chain handling methods */
void *ccs_create_certificate_chain(const char *chain_file_name, size_t chain_len);
void *ccs_open_certificate_chain(const char *chain_file_name, size_t *chain_size);
ccs_status_e ccs_close_certificate_chain(void *chain_handle);
ccs_status_e ccs_add_next_cert_chain(void *chain_handle, const uint8_t *cert_data, size_t data_size);
ccs_status_e ccs_get_next_cert_chain(void *chain_handle, void *cert_data, size_t *data_size);
ccs_status_e ccs_parse_cert_chain_and_store(const uint8_t *cert_chain_name,
                                            const size_t cert_chain_name_len,
                                            const uint8_t *cert_chain_data,
                                            const uint16_t cert_chain_data_len);
#ifdef __cplusplus
}
#endif
#endif // CLOUD_CLIENT_STORAGE_H
