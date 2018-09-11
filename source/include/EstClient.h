// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#ifndef __EST_CLIENT_H__
#define __EST_CLIENT_H__

#include "mbed-client/m2minterface.h"
#include "est_defs.h"

class ConnectorClient;

/**
 * \brief EstClient
 * This class is an interface towards the EST service and is used to enroll
 * certificates using a CSR.
 */
class EstClient {

public:

    /**
     * \brief Constructor.
     */
    EstClient(ConnectorClient& connector_client);

    /**
     * \brief Destructor.
     */
    ~EstClient();

    /**
     * \brief Request certificate enrollment from the EST service.
     * \param cert_name, The name of certificate to enroll. Null enrolls a LwM2M certificate.
     * \param cert_name_length, The length of cert_name buffer.
     * \param csr_length, The length of the certificate signing request within csr buffer.
     * \param csr, A buffer containing the certificate signing request.
     * \param result_cb, The callback function that is called when EST enrollment has completed.
     * \param context, The user context that is passed to the result_cb callback.
     */
    est_status_e est_request_enrollment(const char *cert_name,
                                        const size_t cert_name_length,
                                        uint8_t *csr,
                                        const size_t csr_length,
                                        est_enrollment_result_cb result_cb,
                                        void *context) const;

    static void free_cert_chain_context(cert_chain_context_s *context);

protected:
    static void est_post_data_cb(const uint8_t *buffer,
                                 size_t buffer_size,
                                 size_t total_size,
                                 bool last_block,
                                 void *context);

    static void est_post_data_error_cb(get_data_req_error_t error_code,
                                       void *context);

private:

    static char* make_est_uri(const char *cert_name,
                              const size_t cert_name_length);

    static cert_chain_context_s* parse_cert_chain(uint8_t *cert_chain_data,
                                                  uint16_t cert_chain_data_len);

private:
    ConnectorClient           &_connector_client;

};

#endif // !__EST_CLIENT_H__
