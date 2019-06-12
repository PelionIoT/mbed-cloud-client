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

#ifndef __CS_HASH_H__
#define __CS_HASH_H__

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "kcm_status.h"
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CS_SHA256,//not supported : MD2, MD5, SHA, SHA512, SHA384,SHA512
} cs_hash_mode_e;

/**Calculate hash on input data
*

*@mode – hash mode as defined in hash_mode enum.
*@data – data to calculate hash on it
*@data_size – data size
*@digest – calculated digest output
*@digest_size – the size of hash output buffer, should be equal or bigger than current mode hash size in
*                    hash_size enum.The actual size of hash result is as defined in hash_size enum.
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/

kcm_status_e cs_hash(cs_hash_mode_e mode, const uint8_t *data, size_t data_size, uint8_t *digest, size_t digest_size);

#ifdef __cplusplus
}
#endif

#endif  // __CS_HASH_H__

