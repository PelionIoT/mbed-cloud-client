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

#ifndef __CERTIFICATE_ENROLLMENT_COMMON_H__
#define __CERTIFICATE_ENROLLMENT_COMMON_H__

#include "mbed-client/m2mresource.h"
#include "ce_defs.h"
#include "CertificateEnrollmentClient.h"
#include "EstClient.h"

#ifdef CERT_ENROLLMENT_EST_MOCK
#include "ce_est_mock.h"
#define CERT_ENROLLMENT_EST_CLIENT EstClientMock
#else 
#define CERT_ENROLLMENT_EST_CLIENT EstClient
#endif

/*
* This file declares common functions, and extern's common global variables needed by multiple C++ CertificateEnrollmentClient files.
* The definitions are in CertificateEnrollmentClientCommon.cpp
*/

namespace CertificateEnrollmentClient {

    /**
    * \brief Call the user registered certificate renewal callback if it is not NULL
    * All calls to the user must be with this function so that if the callback is NULL - do nothing.
    * The event will have an application level priority
    * \param cert_name A null terminated string - the renewed certificate name. Persistence guaranteed only in context of the callback.
    * \param ce_status_e The return status of the renewal operation
    * \param initiator whether the renewal was initiated by the device or by the server
    */
    void call_user_cert_renewal_cb(const char *cert_name, ce_status_e status, ce_initiator_e initiator);

    /**
    * \brief Set the user callback
    * Simply set the cert_renewal_cb static pointer to whatever the user passed.
    *
    * \param user_cb Pointer to the user callback. May be NULL
    */
    void set_user_cert_renewal_cb(cert_renewal_cb_f user_cb);

    // The certificate renewal LwM2M resource. the pointer to this object is needed in order to set the resource value and set delayed responses.
    extern M2MResource* g_cert_enroll_lwm2m_resource;
    extern M2MObject *g_cert_enroll_lwm2m_obj;

}

#endif // __CERTIFICATE_ENROLLMENT_COMMON_H__
