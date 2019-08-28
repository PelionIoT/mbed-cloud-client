// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

#ifndef __SDA_INTERNAL_DEFS_H__
#define __SDA_INTERNAL_DEFS_H__

#include "sda_data_token.h"
#include "cs_der_keys_and_csrs.h"
#include "tinycbor.h"
/**
* @file sda_internal_defs.h
*  \brief device based authorization defines.
*
*/

#ifdef __cplusplus
extern "C" {
#endif

#define SDA_AUDIENCE_DEVICE_ID_TYPE_STRING_OLD        "device-id:"
#define SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING_OLD    "endpoint-name:"
#define SDA_AUDIENCE_DEVICE_ID_TYPE_STRING            "id:"
#define SDA_AUDIENCE_ENDPOINT_NAME_TYPE_STRING        "ep:"

#define SDA_DEVICE_ID_SIZE_IN_BITES                       128
#define SDA_DEVICE_ID_SIZE_IN_BYTES                       SDA_DEVICE_ID_SIZE_IN_BITES/8
#define SDA_DEVICE_ID_STRING_SIZE_IN_BYTES                SDA_DEVICE_ID_SIZE_IN_BYTES*2 //*2 - for each char
#define SDA_ENDPOINT_NAME_STRING_MAX_SIZE_IN_BYTES        60

typedef struct cwt_claims {
    uint8_t *issuer_data; //("iss", 1)
    size_t issuer_data_size;
    uint8_t *subject_data;//("sub", 2)
    size_t subject_data_size;
    const uint8_t *audience_array_ptr;
    size_t audience_array_size;
    uint64_t exp; //("exp", 4) -expiration
    uint64_t nbf;// ("nbf", 5) - not before
    uint64_t iat;// ("iat", 6) - current time
    uint8_t *scope_data; //("scope", 12)
    size_t scope_data_size;
    uint8_t *cti_data;// ("cti", 7) - cwt id
    size_t cti_data_size;
    uint8_t *pk_data;// ("cnf", 25) - public key in COSE format
    size_t pk_data_size_size;
    uint8_t pk[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE];
    size_t pk_size;

} cwt_claims_s;

typedef enum {
    SDA_OP_START_PROCESSING_MESSAGE = 0,
    SDA_OP_PROCESSING_MESSAGE = 1,
    SDA_OP_INVALID_MESSAGE = 2
} sda_message_state_e;

/**
* The parsed data of user operation bundle,
*/
typedef struct sda_user_operation_data_ {
    uint8_t type_id;  //Operation type id
    const char *function_name;
    size_t function_name_size;
    const uint8_t *encoded_params_buffer; //Pointer to function parameters encoded buffer
    size_t encoded_params_buffer_size;
}sda_user_operation_data_s;

typedef struct sda_buffer_ {
    const uint8_t *data_buffer_ptr;
    size_t data_buffer_size;
}sda_buffer_s;

/**
* The message structure data,
* The data holds all parsed and retrieved data during  
*/
typedef struct sda_message_data_ {
    uint64_t nonce;
    sda_user_operation_data_s parsed_user_operation;
    sda_buffer_s user_operation_encoded_buffer;
    sda_buffer_s access_token;
    sda_buffer_s main_signed_operation_bundle; // The big main bundle containing everything
    cwt_claims_s claims;
    sda_string_token_context_s data_token_ctx;
} sda_message_data_s;

/**
* The message ID values from the remote proxy to the device and back.
* - Note: the remote proxy MUST be aligned with those values
*/
typedef enum {
    SDA_NONCE_REQUEST_MESSAGE_ID = 1,
    SDA_NONCE_RESPONSE_MESSAGE_ID = 2,
    SDA_OPERATION_REQUEST_MESSAGE_ID = 3,
    SDA_OPERATION_RESPONSE_MESSAGE_ID = 4,
    SDA_ERROR_MESSAGE_ID = 0xFF
} sda_message_id_e;

/**
* The map keys of the SDA response from the device to the proxy
* - Note: the remote proxy MUST be aligned with those values
*/
typedef enum {
    SDA_RESPONSE_MAP_KEY_TYPE = 1,
    SDA_RESPONSE_MAP_KEY_RESULT = 2,
    SDA_RESPONSE_MAP_KEY_NONCE = 3,
    SDA_RESPONSE_MAP_KEY_USER_BUFFER = 4
} sda_response_map_key_e;

/**
* The internal context data struct ,
* includes message data, message id, message state and nonce response.
*/
typedef struct _sda_ctx {
    sda_message_state_e message_state;
    uint64_t nonce_response;
    sda_message_data_s message_data;
    CborEncoder *map_encoder;
    size_t response_max_size;
} sda_ctx_internal_s;

#ifdef __cplusplus
}
#endif

#endif //__SDA_INTERNAL_DEFS_H__
