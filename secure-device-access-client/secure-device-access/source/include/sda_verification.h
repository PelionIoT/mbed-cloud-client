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

#ifndef __SDA_VERIFICATION_H__
#define __SDA_VERIFICATION_H__

#include "sda_status_internal.h"
#include <stdbool.h>
#include <stdint.h>
#include "sda_bundle_parser.h"
#include "sda_status_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* Audience types
*/
typedef enum {
    SDA_DEVICE_ID_AUDIENCE_TYPE = 1,
    SDA_ENDPONT_NAME_AUDIENCE_TYPE = 2,
    SDA_MAX_AUDIENCE_TYPE
} sda_audience_type_e;

/**
* Audience data
*/
typedef struct sda_audience_data {
    uint8_t *audience_data;
    size_t audience_data_size;
    sda_audience_type_e audience_data_type;
} sda_audience_data_s;

/**
* Device Audience data
*/
typedef struct sda_device_audience_data_ {
    uint8_t device_endpoint_name[SDA_ENDPOINT_NAME_STRING_MAX_SIZE_IN_BYTES];
    size_t device_endpoint_name_size;
    uint8_t device_id[SDA_DEVICE_ID_STRING_SIZE_IN_BYTES];
} sda_device_audience_data_s;
/** Verifies access token's expiration.
*
* @param cwt_claims Pointer to a access token claims.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_token_expiration_verify(const cwt_claims_s *cwt_claims);

/** Verifies all the parsed operation bundle data. This object is obtained by calling sda_operation_bundle_parse().
*   The function verifies the nonce, the the signatures of the operation bundle COSE as well as the Access Token COSE within,
*   and The audience.
*
* @param bundle_data Pointer to a sda_message_data_s object containing all the relevant operation bundle data.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_operation_bundle_verify(const sda_message_data_s *bundle_data);

/** Verifies cwt audience against device audience data
*
* @param audience_array Pointer to an audience cbor array .
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_audience_verify_tiny(const uint8_t *audience_array_ptr, size_t audience_array_size);

extern uint64_t g_saved_nonce;

#ifdef __cplusplus
}
#endif
#endif // __SDA_VERIFICATION_H__
