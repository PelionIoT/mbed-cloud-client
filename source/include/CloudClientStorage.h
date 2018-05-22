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
*  \brief Uninitializes the CFStore handle.
*/
ccs_status_e uninitialize_storage(void);

/**
*  \brief Initializes the CFStore handle.
*/
ccs_status_e initialize_storage(void);

/* Bootstrap credential handling methods */
ccs_status_e get_config_parameter(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length);
ccs_status_e get_config_parameter_string(const char* key, uint8_t *buffer, const size_t buffer_size);
ccs_status_e set_config_parameter(const char* key, const uint8_t *buffer, const size_t buffer_size);
ccs_status_e check_config_parameter(const char* key);
ccs_status_e delete_config_parameter(const char* key);
ccs_status_e size_config_parameter(const char* key, size_t* size_out);

ccs_status_e get_config_private_key(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length);
ccs_status_e set_config_private_key(const char* key, const uint8_t *buffer, const size_t buffer_size);
ccs_status_e delete_config_private_key(const char* key);

ccs_status_e get_config_public_key(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length);
ccs_status_e set_config_public_key(const char* key, const uint8_t *buffer, const size_t buffer_size);
ccs_status_e delete_config_public_key(const char* key);

ccs_status_e get_config_certificate(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length);
ccs_status_e set_config_certificate(const char* key, const uint8_t *buffer, const size_t buffer_size);
ccs_status_e delete_config_certificate(const char* key);



#ifdef __cplusplus
}
#endif
#endif // CLOUD_CLIENT_STORAGE_H
