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

#ifndef __CS_DER_KEYS_H__
#define __CS_DER_KEYS_H__

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "kcm_status.h"

typedef enum {
    CS_SECP256R1
} cs_curve_name_e;

#define CS_EC_SECP256R1_PK_RAW_SIZE 65
#define CS_EC_SECP256R1_PK_DER_SIZE 91

#define CS_SECP256R1_SIZE_IN_BITS 256
/*The max size of ecdsa signature defined according ecdsa.h file of mbedtls :
 *  The "sig" buffer must be at least as large as twice the
 *                  size of the curve used, plus 9 (eg. 73 bytes if a 256-bit
 *                  curve is used). MBEDTLS_ECDSA_MAX_LEN is always safe.
 *  The reason of adding of additional 9 bytes is according to RFC 4492 page 20 
 *   used in mbedtls for signature serialization.
 */
#define CS_ECDSA_SECP256R1_MAX_SIGNATURE_SIZE_IN_BYTES  (CS_SECP256R1_SIZE_IN_BITS/8)*2 + 10 //74 bytes

/**Verify private Key In DER format. For now only EC keys supported
*
*@key_data – DER format private key data.
*@key_data_length – key data size
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/

kcm_status_e cs_der_priv_key_verify(const uint8_t* key, size_t key_length);

/**Verify public Key In DER format. For now only EC keys supported
*
*@key_data – DER format puclic key data.
*@key_data_length – key data size
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/

kcm_status_e cs_der_public_key_verify(const uint8_t* key, size_t key_length);

/**Calculate signature on hash digest using ecdsa private key.
*
*@der_priv_key[in] - DER private key data.
*@der_priv_key_length[in] - key data size
*@hash_dgst[in] - hash digest buffer
*@size_of_hash_dgst[in] - size of hash digest buffer
*@out_sign[in/out] - output buffer for calculated signature
*@signature_data_max_size[in] - size of signature buffer
*@signature_data_act_size_out[out] - actual size of output signature buffer
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_ecdsa_sign(const uint8_t *der_priv_key, size_t der_priv_key_length, const uint8_t *hash_dgst, size_t size_of_hash_dgst, uint8_t *out_sign, size_t  signature_data_max_size, size_t * signature_data_act_size_out);

/**Extracts public raw key data from public der key
*
*@der_key[in] - DER public key data.
*@der_key_length[in] - public key data size
*@raw_key_data_out[out] - raw key out buffer
*@raw_key_data_max_size[in] - size of raw key out buffer
*@raw_key_data_act_size_out[out] - actual output size of raw key
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_get_pub_raw_key_from_der(const uint8_t *der_key, size_t der_key_length, uint8_t *raw_key_data_out, size_t raw_key_data_max_size, size_t *raw_key_data_act_size_out);
#ifdef __cplusplus
}
#endif

#endif  //__CS_DER_KEYS_H__

