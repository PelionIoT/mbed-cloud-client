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
#include "kcm_internal.h"


/* CS key object handle */
typedef uintptr_t cs_key_handle_t;

/** EC key context
* Contains the private and public keys buffers
* and their actual sizes
*
* FIXME: this sturct should be private
*/
typedef struct _cs_ec_key_context {
    uint8_t priv_key[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];
    size_t priv_key_size;
    uint8_t pub_key[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    size_t pub_key_size;
} cs_ec_key_context_s;

/**Verify private Key In DER format. For now only EC keys supported
*
*@key_data - DER format private key data.
*@key_data_length - key data size
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/

kcm_status_e cs_der_priv_key_verify(const uint8_t* key, size_t key_length);

/**Verify public Key In DER format. For now only EC keys supported
*
*@key_data - DER format puclic key data.
*@key_data_length - key data size
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/

kcm_status_e cs_der_public_key_verify(const uint8_t* key, size_t key_length);

/** Verify the ECDSA signature of a previously hashed message.
*
* @param[in] der_pub_key:         The public key buffer for verification.
* @param[in] der_pub_key_len:     The size of public key buffer.
* @param[in] hash_dgst:           The message buffer.
* @param[in] hash_dgst_len:   The length of the message buffer.
* @param[in] sign:                The signature buffer
* @param[in] signature size:      The size of signature buffer.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e cs_ecdsa_verify(const uint8_t *der_pub_key, size_t der_pub_key_len, const uint8_t *hash_dgst, size_t hash_dgst_len,const uint8_t *sign, size_t  signature_size);


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

/**Verifies correlation between private and public key.
*
*@priv_key_data[in] - DER private key data.
*@priv_key_data_size[in] - private key data size
*@pub_key_data[in] - DER private key data.
*@pub_key_data_size[in] - private key data size
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_verify_key_pair(const uint8_t *priv_key_data, size_t priv_key_data_size, const uint8_t *pub_key_data, size_t pub_key_data_size);

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

/** Allocates and initializes a key object and return the key handle.
*
*   @param key_h_out[out] A handle to a key object in store.
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e cs_ec_key_new(cs_key_handle_t *key_h_out);

/** Frees the allocated bytes of the key handle.
*
*   @param key_h[in] A pointer to the handle that represents the key object in store.
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e cs_ec_key_free(cs_key_handle_t *key_h);

/** Generates key pair and a CSR from a given certificate name.
*   The function will search for the certificate in store.
*
*   @param certificate[in] A pointer to a valid buffer that holds the certificate bytes
*   @param certificate_size[in] The certificate octets length
*   @param key_h[out] A handle to the CSR key object.
*   @param csr_out[out] A pointer to a newly allocated buffer that accommodate the CSR
*   @param csr_max_size[in] The max size in bytes of csr_out buffer
*   @param csr_actual_size_out[in] The actual size in bytes of csr_out buffer
*
*   @returns
*       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e cs_generate_keys_and_create_csr_from_certificate(
    const uint8_t *certificate,
    size_t certificate_size,
    cs_key_handle_t csr_key_h,
    uint8_t *csr_buff_out,
    const size_t csr_buff_max_size,
    size_t *csr_buff_act_size_out);


/*! The API checks correlation of a certificate
*
*    @param[in] crypto_handle          crypto handle.
*    @param[in] certificate_data       public key buffer(optional).
*    @param[in] certificate_data_len   length of public key buffer.

storage.
*
*    @returns
*        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
*/

kcm_status_e cs_verify_items_correlation(cs_key_handle_t crypto_handle, const uint8_t *certificate_data, size_t certificate_data_len);

#ifdef __cplusplus
}
#endif

#endif  //__CS_DER_KEYS_H__
