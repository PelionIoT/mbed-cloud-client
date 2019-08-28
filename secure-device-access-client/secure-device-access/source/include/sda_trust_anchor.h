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

#ifndef __SDA_TRUST_ANCOR_H__
#define __SDA_TRUST_ANCOR_H__

#include <stdlib.h>
#include <inttypes.h>
#include "sda_status_internal.h"
#include "sda_bundle_parser.h"
#include "sda_internal_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SDA_TRUST_ANCHOR_SIZE KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE

/** Gets the trust anchor.
*
* @param trust_anchor_key_out Pointer to a buffer which the Trust Anchor will be copied to.
* @param trust_anchor_key_out_size The size of the provided trust_anchor_key_out buffer.
* @param trust_anchor_key_size_out Pointer to where the size of the trust anchor will be placed.
*
* @return
*       SDA_STATUS_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_trust_anchor_get(const uint8_t *trust_anchor_key_name, size_t trust_anchor_key_name_size,
    uint8_t *trust_anchor_key_out, size_t trust_anchor_key_out_size, size_t *trust_anchor_key_size_out);


#ifdef __cplusplus
}
#endif

#endif //__SDA_TRUST_ANCOR_H__
