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
#include "kcm_defs.h"

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

/** Generate a key pair complying the given crypto scheme DER.
*
* @param curve_name The curve name
* @param priv_key_out Out buffer for private key to generate in DER format.
* @param priv_key_max_size Size of the private key buffer
* @param priv_key_act_size_out Actual private key size in bytes.
* @param pub_key_out Out buffer for public key to generate in DER format. Send NULL if no public key needed.
* @param pub_key_max_size Size of the public key buffer
* @param pub_key_act_size_out Actual public key size in bytes.
*
* @returns
* Operation status.
*/
kcm_status_e cs_key_pair_generate(kcm_crypto_key_scheme_e curve_name,
                                  uint8_t *priv_key_out,
                                  size_t priv_key_max_size,
                                  size_t *priv_key_act_size_out,
                                  uint8_t *pub_key_out,
                                  size_t pub_key_max_size,
                                  size_t *pub_key_act_size_out);

/** Generate a general CSR from the given private key.
* @param priv_key The private key buffer in DER format.
* @param priv_key_size The private key buffer size.
* @param csr_params Pointer to CSR request params struct.
* @param csr_buff_out Out buffer for CSR to generate in DER format.
* @param csr_buff_max_size Size of the CSR buffer
* @param csr_buff_act_size_out Actual CSR size in bytes.
*
* @returns
* Operation status.
*/
kcm_status_e cs_csr_generate(const uint8_t *priv_key,
                             size_t priv_key_size,
                             const kcm_csr_params_s *csr_params,
                             uint8_t *csr_buff_out,
                             size_t csr_buff_max_size,
                             size_t *csr_buff_act_size_out);

/** Generate private key and CSR from the given crypto scheme DER.
* @param curve_name The curve name
* @param csr_params Pointer to CSR request params struct.
* @param priv_key_out Out buffer for private key to generate in DER format.
* @param priv_key_max_size Size of the private key buffer
* @param priv_key_act_size_out Actual private key size in bytes.
* @param pub_key_out Out buffer for public key to generate in DER format. Send NULL if no public key needed.
* @param pub_key_max_size Size of the public key buffer
* @param pub_key_act_size_out Actual public key size in bytes.
* @param csr_buff_out Out buffer for CSR to generate in DER format.
* @param csr_buff_max_size Size of the CSR buffer
* @param csr_buff_act_size_out Actual CSR size in bytes.
*
* @returns
* Operation status.
*/
kcm_status_e cs_generate_keys_and_csr(kcm_crypto_key_scheme_e curve_name,
                                      const kcm_csr_params_s *csr_params,
                                      uint8_t *priv_key_out,
                                      size_t priv_key_max_size,
                                      size_t *priv_key_act_size_out,
                                      uint8_t *pub_key_out,
                                      size_t pub_key_max_size,
                                      size_t *pub_key_act_size_out,
                                      uint8_t *csr_buff_out,
                                      const size_t csr_buff_max_size,
                                      size_t *csr_buff_act_size_out);


#ifdef __cplusplus
}
#endif

#endif  //__CS_DER_KEYS_H__
