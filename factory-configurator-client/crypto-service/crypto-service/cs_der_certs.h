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

#ifndef __CS_DER_CERTS_H__
#define __CS_DER_CERTS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "kcm_status.h"
#include "storage_kcm.h"

/*
* Types certificate's attributes
*/
typedef enum cs_certificate_attribute_type_ {
    CS_CN_ATTRIBUTE_TYPE,
    CS_VALID_FROM_ATTRIBUTE_TYPE,
    CS_VALID_TO_ATTRIBUTE_TYPE,
    CS_OU_ATTRIBUTE_TYPE,
    CS_SUBJECT_ATTRIBUTE_TYPE,
    CS_ISSUER_ATTRIBUTE_TYPE,
    CS_CERT_ID_ATTR,
    CS_MAX_ATTRIBUTE_TYPE
} cs_certificate_attribute_type_e;


/** 
* Parameters of the previous certificate in the chain required to verify that the current cert actually signed the previous one.
*/
typedef storage_chain_prev_cert_params_s cs_child_cert_params_s;


/** Verify handle of x509 formatted certificate using certificate chain handle.
*
* In case one of certificate handle is NULLPTR the API returns an error.
*
* @param[in] x509_cert -  A handle holding the parsed certificate.
* @param[in] x509_cert_chain - The pointer to the handle of chain to verify the X509 certificate : Optional
*
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_verify_x509_cert(palX509Handle_t x509_cert, palX509Handle_t x509_cert_chain);

/**Parse x509 certificate in DER format.
* The API parses der certificate and during the parsing checks basic fields structure of the certificate.
*
*@cert[in] - DER format certificate.
*@cert_length[in] - certificate length
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_check_der_x509_format(const uint8_t *cert, size_t cert_length);

/**Parse and create handle for x509 der certificate.
* In case certificate is NULL , return empty initialized handle.
*
*@cert[in] - DER format certificate.
*@cert_length[in] - certificate length
*@x509_cert_handle[out] - certificate handle
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_create_handle_from_der_x509_cert(const uint8_t *cert, size_t cert_length, palX509Handle_t *x509_cert_handle);


/**Add certificate to chain handle.
* Parse x509 der certificate and add to the chain handle.
*
*@cert[in] - DER format certificate.
*@cert_length[in] - certificate length
*@x509_chain_handle[out] - certificate chain handle
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_add_to_chain_x509_cert(const uint8_t *cert, size_t cert_length, palX509Handle_t x509_chain_handle);

/**Close created x509 handle certificate.
*
*@x509_cert_handle[in/out] – handle of parsed x509 certificate.
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_close_handle_x509_cert(palX509Handle_t *x509_cert_handle);

/**Verify that x509 certificate is self-signed.
*
*@x509_cert[in] - x509 certificate handle.
*@is_self_signed[out] - if the value is true the certificate is self-signed, otherwise not self-signed
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_is_self_signed_x509_cert(palX509Handle_t x509_cert, bool* is_self_signed);


/**Gets current attribute from certificate
*
*@x509_cert[in] - x509 certificate handle.
*@cs_attribute_type[in] - certificate attribute type
*@attribute_output_buffer[out] -pointer to output attribute buffer.
*@max_size_of_attribute_output_buffer[in] -size of output attribute buffer.
*@actual_size_of_attribute_output_buffer[out] -actual size of attribute.
*
* note in case of "KCM_STATUS_INSUFFICIENT_BUFFER" error the required size will be assigned into the "actual_size_of_output" parameter.
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e  cs_attr_get_data_x509_cert(palX509Handle_t x509_cert,
                                         cs_certificate_attribute_type_e cs_attribute_type,
                                         uint8_t *attribute_output_buffer,
                                         size_t max_size_of_attribute_output_buffer,
                                         size_t *actual_size_of_attribute_output_buffer);

/**Gets current attribute size from certificate
*
*@x509_cert[in] - x509 certificate handle.
*@cs_attribute_type[in] - certificate attribute type
*@size_of_attribute[out] - size of attribute.
*
*@return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e  cs_attr_get_data_size_x509_cert(palX509Handle_t x509_cert,
                                              cs_certificate_attribute_type_e cs_attribute_type,
                                              size_t *size_of_attribute);

/**Checks signature using x509 certificate
*
*@x509_cert[in] - handle of  x509 certificate.
*@hash[in] - hash digest for verification
*@hash_size[in] - size of hash digest.
*@signature[in] - pointer to signature in der format.
*@signature_size[in] -signature size.
*
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/

kcm_status_e  cs_x509_cert_verify_der_signature(palX509Handle_t x509_cert,
                                            const unsigned char *hash,
                                            size_t hash_size,
                                            const unsigned char *signature,
                                            size_t signature_size);

/** Retrieve all the parameters of a child X509 (signed by a parent) certificate, required for validation by the parent (signer) certificate
*
* Once these parameters are retrieved, The validity of the child certificate may be checked with the public key of the signer (the pal_verifySignature() API)
*
* @param[in] x509_cert Handle to an X509 certificate
* @param[out] params_out pointer to a cs_child_cert_params_s structure which the relevant data will be filled
*
* @return
*     KCM_STATUS_SUCCESS on success, otherwise appropriate error from  kcm_status_e.
*/
kcm_status_e cs_child_cert_params_get(palX509Handle_t x509_cert, cs_child_cert_params_s *params_out);


#ifdef __cplusplus
}
#endif

#endif  // __CS_DER_CERTS_H__

