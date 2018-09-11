// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#include "CertificateEnrollmentClientCommon.h"

namespace CertificateEnrollmentClient {

    // User callback to be invoked when server POSTs g_cert_enroll_lwm2m_resource
    // Important: Do not call directly, always call call_user_cert_renewal_cb() instead
    static cert_renewal_cb_f cert_renewal_cb = NULL;

    // Certificate Renewal LWM2M Resource 
    M2MResource* g_cert_enroll_lwm2m_resource = NULL;

    const CERT_ENROLLMENT_EST_CLIENT *g_est_client;

    void call_user_cert_renewal_cb(const char *cert_name, ce_status_e status, ce_initiator_e initiator)
    {
        if (cert_renewal_cb) {
            cert_renewal_cb(cert_name, status, initiator);
        }
    }

    void set_user_cert_renewal_cb(cert_renewal_cb_f user_cb)
    {
        cert_renewal_cb = user_cb;
    }
}

