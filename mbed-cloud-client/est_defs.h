// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

/*! \file est_defs.h
* \brief Definitions for certificate chain structures and Enrollment over Secure
         Transport (EST) callback.
*/

#ifndef __EST_DEFS_H__
#define __EST_DEFS_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* The structure describing a certificate within a certificate chain.
* \param cert_length, The length of the certificate.
* \param cert, A buffer containing the certificate.
* \param next, A pointer to the next certificate in chain, NULL if last certificate.
*/
struct cert_context_s {
    uint16_t cert_length;
    uint8_t *cert;
    struct cert_context_s *next;
};

/**
* The structure describing a certificate chain with.
* \param chain_length, The number of certificates in the certificate chain.
* \param cert_data_context, A context pointer, user should ignore.
* \param first_cert, A pointer to the first certificate in chain.
*/
struct cert_chain_context_s {
    uint8_t chain_length;
    void *cert_data_context;
    struct cert_context_s *certs;
};

typedef enum {
    EST_ENROLLMENT_SUCCESS,
    EST_ENROLLMENT_FAILURE
} est_enrollment_result_e;

typedef enum {
    EST_STATUS_SUCCESS,
    EST_STATUS_INVALID_PARAMETERS,
    EST_STATUS_MEMORY_ALLOCATION_FAILURE
} est_status_e;

/**
* \brief When the enrollment result has been handled by the callback, the free_cert_chain_context
*        function must be called with the cert_chain as parameter to free the certificate chain
*        buffer(s).
* \param result, The result of the enrollment operation.
* \param cert_chain, A pointer to cert_chain_context_s if enrollment was successful, otherwise NULL.
* \param context, The user context.
*/
typedef void(*est_enrollment_result_cb)(est_enrollment_result_e result,
                                        struct cert_chain_context_s *cert_chain,
                                        void *context);

#ifdef __cplusplus
}
#endif

#endif // __EST_DEFS_H__
