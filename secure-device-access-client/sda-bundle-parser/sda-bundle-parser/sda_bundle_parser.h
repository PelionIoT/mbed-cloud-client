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

#ifndef __SDA_BUNDLE_PARSER_H__
#define __SDA_BUNDLE_PARSER_H__

#include <stdlib.h>
#include <inttypes.h>
#include "sda_status_internal.h"
#include "sda_data_token.h"
#include "sda_internal_defs.h"
#include "sda_status.h"
#include "secure_device_access.h"

#ifdef __cplusplus
extern "C" {
#endif

#define unsigned_operation_bundle_NONCE_INDEX 0
#define unsigned_operation_bundle_OPERATION_INDEX 1
#define unsigned_operation_bundle_ACCESS_TOKEN_INDEX 2

#define FUNCTION_PARAMETERS_ARRAY_INDEX 2

#define SDA_COSE_PAYLOAD_INDEX 2

#define SDA_UNTAGGED_REQUEST_ARRAY_SIZE 3
#define SDA_USER_OPERATION_ARRAY_SIZE 3

#define SDA_COSE_SIGN0_ARRAY_LENGTH 4

#define SDA_CBOR_TAG_CWT 61

typedef enum {
    SDA_ISS = 1,
    SDA_SUB = 2, //optional field
    SDA_AUD = 3,
    SDA_EXP = 4,
    SDA_NBF = 5,
    SDA_IAT = 6,
    SDA_CTI = 7,
    SDA_SCOPE = 12,
    SDA_CNF = 25,
    SDA_MAX_CONFIG_PARAM_GROUP_TYPE    //!< Max group type
} sda_bundle_param_group_type_e;

#define SDA_COSE_KEY_MAP_KEY 1

    /**
    * @file sda_bundle_parser.h
    *  \brief The fcc bundle handler APIs.
    * {
    / iss / 1: "xxxxxxxxx",
    / aud / 3 : "coap://light.example.com",
    / exp / 4 : 1444064944,
    / nbf / 5 : 1443944944,
    / iat / 6 : 1443944944,
    / cti / 7 : h'0b71',
    / scope / 12 : "do"
    / cnf / 25 : {
    "COSE_Key":{
    "kty": "EC",
    "crv" : "P-256",
    "x" : "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
    "y" : "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
    }
    },

    }
    */

/** Decodes and processes an inbound device SDA bundle created by proxy.
* Also creates an outbound bundle that should be sent to proxy.
* The function assumes that the bundle includes CWT legal structure.
*
* @param encoded_bundle The encoded SDA bundle.
* @param encoded_blob_size The encoded SDA bundle size in bytes.
* @param bundle_response_out The encoded outbound bundle. .
*        The response associates a descriptive error in case of a fault. Will be NULL if response not created successfully.
* @param bundle_response_size_out The encoded outbound bundle size in bytes.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_cwt_parse(const uint8_t *encoded_blob, size_t encoded_blob_size, cwt_claims_s *cwt_out);

/** Decodes and processes an inbound device SDA bundle created by proxy.
* Also creates an outbound bundle that should be sent to proxy.
* The function assumes that the bundle includes CWT legal structure.
*
* @param encoded_bundle The encoded SDA bundle.
* @param encoded_blob_size The encoded SDA bundle size in bytes.
* @param bundle_response_out The encoded outbound bundle. .
*        The response associates a descriptive error in case of a fault. Will be NULL if response not created successfully.
* @param bundle_response_size_out The encoded outbound bundle size in bytes.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_cwt_parse_tiny(const uint8_t *encoded_bundle, size_t encoded_bundle_size, cwt_claims_s *cwt_out);

/** Parses an encoded Operation bundle COSE into a sda_message_data_s object.
*
* @param encoded_operation_bundle Pointer to the encoded operation bundle.
* @param encoded_operation_bundle_size The size of the operation bundle.
* @param bundle_data_out Pointer to a sda_message_data_s which will be filled according to the data in encoded_operation_bundle.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_operation_bundle_parse(const uint8_t *encoded_operation_bundle, size_t encoded_operation_bundle_size, sda_message_data_s *bundle_data_out);



/** This function parses user operation data and checks that its structure is valid.
*
* @param bundle_data Pointer tosda_message_data_s that includes operation data.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_user_operation_parse(sda_message_data_s *bundle_data);

typedef struct sda_unsigned_request_data {
    uint64_t nonce;
    CborValue user_operation;//todo ->remove
    const uint8_t *user_operation_ptr;
    size_t user_operation_size;
    CborValue encoded_access_token;//todo ->remove
    uint8_t *encoded_access_token_ptr;
    size_t encoded_access_token_size;
} sda_unsigned_request_data_s;

typedef enum {
    SDA_STRING_FUNCTION_PARAMETER,
    SDA_NUMERIC_PARAMETER,
    SDA_ERROR_PARAMETER = 0xFF
} sda_function_parameter_type_e;

typedef struct sda_parameter_data_ {
    sda_function_parameter_type_e parameter_type;
    uint8_t *data_param;      //pointer to string parameter
    size_t  data_param_size;  //size of string parameter
    int64_t numeric_parameter;
}sda_parameter_data_s;

/** This function parses cbor value buffer and returns pointer to its data and data size.
*
* @param cbor_value Pointer to cbor value.
* @param out_data_buffer pointer to out data.
* @param out_size pointer to out data size.
*
* @return
*       true in case of success, otherwise false.
*/
bool sda_get_data_buffer_from_cbor_tiny(CborValue *cbor_value, uint8_t **out_data_buffer, size_t *out_size);

/** This function parses function call bundle, checks its validity and returns parameter at given index.
* The function assumes internal usage only and for this reason the parameters are not checked.
*
* @param handle         -  Pointer to sda operation handle
* @param parameter_data -  Pointer to output function parameter structure
* @return index         -  Index of parameter to get
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_get_function_parameter_tiny(sda_operation_ctx_h handle, sda_parameter_data_s *parameter_data, uint32_t index);

#ifdef __cplusplus
}
#endif

#endif //__SDA_BUNDLE_PARSER_H__
