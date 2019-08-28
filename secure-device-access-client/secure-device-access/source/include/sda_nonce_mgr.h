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

#ifndef __SDA_NONCE_MGR_H__
#define __SDA_NONCE_MGR_H__

#include <stdlib.h>
#include <inttypes.h>
#include "sda_status.h"
#include "sda_bundle_parser.h"
#include <stdbool.h>
#include <inttypes.h>
#include "sda_status.h"


#define SDA_CYCLIC_BUFFER_MAX_SIZE 10

#ifdef __cplusplus
extern "C" {
#endif

/** Initializes the a circular buffer to store the nonce values.
*
* - The circular buffer is in-memory buffer which holds up to `SDA_CYCLIC_BUFFER_MAX_SIZE` nonce values
* - This function fills the entire circular buffer with random nonce values
*
* @return
*       SDA_STATUS_INTERNAL_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_nonce_init(void);

/** Finalizes the circular buffer resource and wipes out any memory trace left.
*
* @return
*       SDA_STATUS_INTERNAL_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_nonce_fini(void);


/** Sets nonce value to nonce management structure.
*
* @param nonce_s nonce_value
*/
void circ_buf_insert(uint64_t nonce_value);


/** Gets a fresh nonce value from the circular buffer.
*
* @param nonce_out [OUT] The nonce value
*
* @return
*       SDA_STATUS_INTERNAL_SUCCESS in case of success or one of the `::sda_status_e` errors otherwise.
*/
sda_status_internal_e sda_nonce_get(uint64_t *nonce_out);

/** Checks whether a given nonce value exists in the circular buffer.
*
* - If exist - true is returned and the given nonce will be removed from the circular buffer.
*              the circular buffer will automatically renew itself with a fresh nonce value.
* - If not exist - false is returned and the circular buffer remain untouched.
*
* @param nonce_out [IN] The target nonce value to verify.
*
* @return
*       true - if exists, false otherwise.
*/
bool sda_nonce_verify_and_delete(uint64_t nonce);


#ifdef __cplusplus
}
#endif

#endif //__SDA_NONCE_MGR_H__
