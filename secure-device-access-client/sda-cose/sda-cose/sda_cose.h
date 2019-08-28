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

#ifndef __SDA_COSE_H__
#define __SDA_COSE_H__

#include <stdlib.h>
#include <inttypes.h>
#include "sda_status_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Decodes and validates a COSE with a user provided public key.
*
* @param cose_msg Pointer to the encoded COSE buffer.
* @param cose_msg_size Size of the encoded COSE buffer .
* @param pKey Pointer to the verifying key in raw bytes. In case of Curve P-256, the key is of the following format: [compresion type (1 byte), X coordinate (32 bytes), Y coordinate].
* @param keySize size of the verifying key.
*
* @return
*       SDA_STATUS_INTERNAL_SUCCESS in case of success or one of the `::sda_status_internal_e` errors otherwise.
*/
sda_status_internal_e sda_cose_validate_with_raw_pk(const uint8_t *cose_msg, size_t cose_msg_size, const uint8_t *pKey, size_t keySize);

#ifdef __cplusplus
}
#endif

#endif
