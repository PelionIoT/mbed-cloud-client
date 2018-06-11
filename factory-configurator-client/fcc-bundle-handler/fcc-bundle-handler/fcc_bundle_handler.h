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

#ifndef __FCC_BUNDLE_HANDLER_H__
#define __FCC_BUNDLE_HANDLER_H__

#include <stdlib.h>
#include <inttypes.h>
#include "fcc_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Decodes and processes an inbound device configuration bundle created by FCU.
* Also creates an outbound bundle that should be sent to FCU.
* The function assumes that the bundle includes four groups represented as cbor maps.
* The names of the groups are `SchemeVersion`, `Keys`, `Certificates` and `ConfigParams`.
* Each group contains a list of items, and for each item, there are a number of relevant parameters.
*
* @param encoded_bundle The encoded FCU bundle that is written into a secure storage.
* @param encoded_blob_size The encoded FCU bundle size in bytes.
* @param bundle_response_out The encoded outbound bundle. It may contain data such as CSR and different types of key schemes.
*        The response associates a descriptive error in case of a fault. Will be NULL if response not created successfully.
* @param bundle_response_size_out The encoded outbound bundle size in bytes.
*
* @return
*       FCC_STATUS_SUCCESS in case of success or one of the `::fcc_status_e` errors otherwise.
*/
fcc_status_e fcc_bundle_handler(const uint8_t *encoded_bundle, size_t encoded_bundle_size, uint8_t **bundle_response_out, size_t *bundle_response_size_out);
#ifdef __cplusplus
}
#endif

#endif //__FCC_BUNDLE_HANDLER_H__
