// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef ARM_UPDATE_CERTIFICATES_H
#define ARM_UPDATE_CERTIFICATES_H

#include "update-client-common/arm_uc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Add certificate.
 * @details [long description]
 *
 * @param certificate Pointer to certiface being added.
 * @param certificate_length Certificate length.
 * @param fingerprint Pointer to the fingerprint of the certificate being added.
 * @param fingerprint_length Fingerprint length.
 * @return Error code.
 */
 arm_uc_error_t ARM_UC_Certificate_Add(const uint8_t* certificate,
                                       uint16_t certificate_size,
                                       const uint8_t* fingerprint,
                                       uint16_t fingerprint_size,
                                       void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*));

typedef arm_uc_error_t (* arm_uc_certificateStorer)(const arm_uc_buffer_t* certificate,
                                                    const arm_uc_buffer_t* fingerprint,
                                                    void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*));

/**
 * @brief Fetch a certificate by fingerprint
 * @details This API is registered with the hub by the application. The application must handle any required certificate
 * chain validation. The API for parsing a certificate chain will be provided by the manifest manager, but the API
 * is TBD, so the DERCertificateList should be ignored for now.
 *
 * @param[out] certificates A pointer to the buffer to populate with the certificate. The buffer's ptr should be updated
 *                          to point to the certificate.
 * @param[in] fingerprint The fingerprint of the certificate
 * @param[in] DERCertificateList The encoded list of certificate fingerprint/URL pairs that define the chain of
 *                               certificates used to verify the requested certificate (The requested certificate will
 *                               always be the first in the list)
 * @param[in] callback The function to call when the certificate is available
 */
typedef arm_uc_error_t (*arm_uc_certificateFetcher)(arm_uc_buffer_t* certificate,
    const arm_uc_buffer_t* fingerprint,
    const arm_uc_buffer_t* DERCertificateList,
    void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*, const arm_uc_buffer_t*));


struct arm_uc_certificate_api {
    arm_uc_certificateFetcher fetch;
    arm_uc_certificateStorer  store;
};

arm_uc_error_t ARM_UC_certificateFetch(arm_uc_buffer_t* certificate,
    const arm_uc_buffer_t* fingerprint,
    const arm_uc_buffer_t* DERCertificateList,
    void (*callback)(arm_uc_error_t, const arm_uc_buffer_t*, const arm_uc_buffer_t*));

#ifdef __cplusplus
};
#endif

#endif // ARM_UPDATE_CERTIFICATES_H
