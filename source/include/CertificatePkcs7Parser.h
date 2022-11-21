// ----------------------------------------------------------------------------
// Copyright 2022 Pelion Ltd.
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

#ifndef CERTIFICATE_PKCS7_PARSER_H
#define CERTIFICATE_PKCS7_PARSER_H

/** \internal \file CertificatePkcs7Parser.h  */

#ifdef __cplusplus
extern "C" {
#endif

#include "est_defs.h"

/**
*  \brief A utility function to extract parse certificate or certificate chain in pkcs#7 format.
*  \param cert_chain_data, The certificate or certificate chain to be parsed in pkcs#7 format.
*  \param cert_chain_data_len, The length of the cert_chain_data.
*  \param result, The parsing status. Will equal to EST_STATUS_SUCCESS on success.
*  \return Parsed certificate chain context. If the context isn't NULL and the result isn't equal to EST_STATUS_SUCCESS, the context must be free.
*/
struct cert_chain_context_s* parse_pkcs7_cert(uint8_t **cert_chain_data, 
                                              uint16_t cert_chain_data_len,
                                              est_status_e *result);

#ifdef __cplusplus
}
#endif

#endif //CERTIFICATE_PKCS7_PARSER_H
