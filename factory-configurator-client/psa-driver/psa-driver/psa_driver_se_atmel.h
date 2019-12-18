// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#ifndef __PSA_DRIVER_SE_ATMEL_H__
#define __PSA_DRIVER_SE_ATMEL_H__

#include <stdbool.h>
#include <inttypes.h>
#include "kcm_status.h"
#include "psa/crypto.h"

/******** Atmel's Secure Element related declaration *****/

/** Return the maximum possible certificate size in bytes for a
*         signer certificate. Certificate can be variable size, so this
*         gives an appropriate buffer size when reading the certificate.
*
* \param[out] max_cert_size_out  Maximum certificate size in bytes.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_get_max_signer_cert_size(size_t *max_cert_size_out);

/** Return the maximum possible certificate size in bytes for a
*         signer certificate. Certificate can be variable size, so this
*         gives an appropriate buffer size when reading the certificate.
*
* \param[out] max_cert_size_out  Maximum certificate size in bytes.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_get_max_device_cert_size(size_t *max_cert_size_out);

/** Reads the signer certificate from secure element.
*
* \param[out]   cert       Buffer to received the certificate (DER format).
* \param[inout] cert_size  As input, the size of the cert buffer in bytes.
*                          As output, the size of the certificate returned
*                          in cert in bytes.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_read_signer_cert(uint8_t *cert, size_t *cert_size_out);

/** Reads the device certificate from secure element.
*
* \param[out]   cert       Buffer to received the certificate (DER format).
* \param[inout] cert_size  As input, the size of the cert buffer in bytes.
*                          As output, the size of the certificate returned
*                          in cert in bytes.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_read_device_cert(uint8_t *cert, size_t *cert_size_out);

/** Gets Secure Element handle from a given key ID.
* Atmel�s secure element retain the device private key in slot zero which
* is (currently) the only available secret, hence, the key ID value should
* always be zero.
*
* \param[in]   key_id         The key ID, value should always be zero.
* \param[out]  key_handle_out The key handle referred to the given key ID.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_get_handle(uint16_t key_id, psa_key_handle_t *key_handle_out);

/** Closes a key handle
*
* \param[in]  key_handle The key handle to close.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_close_handle(psa_key_handle_t key_handle);

/** Reads the CN (Common Name) from a certificate.
*
* \param[in]  cert        The certificate bytes (DER format).
* \param[in]  cert_size   The certificate size in bytes.
* \param[out] cn_out      The CN bytes as parsed from the given certificate.
*                         Callee must free this buffer upon end of use.
* \param[out] cn_size_out The CN actual bytes written to cn_out.
*
* \return KCM_STATUS_SUCCESS if no error occurred or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_atca_get_cn(const uint8_t *cert, size_t cert_size, uint8_t **cn_out, size_t *cn_size_out);

/** Initializes Atmel's secure element with the
* pre-defined hardware specific setup
*/
kcm_status_e psa_drv_atca_init(void);
/** Registers ATMEL driver to PSA
*/
kcm_status_e psa_drv_atca_register(void);

/** Release Atmel's secure element resources.
*/
void psa_drv_atca_release(void);

#ifdef __cplusplus
}
#endif

#endif //__PSA_DRIVER_SE_ATMEL_H__
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
