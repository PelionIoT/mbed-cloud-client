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

#ifndef __CERTIFICATE_ENROLLMENT_CLIENT_H__
#define __CERTIFICATE_ENROLLMENT_CLIENT_H__

#include "mbed-client/m2minterface.h"
#include "ce_defs.h"

class EstClient;

namespace CertificateEnrollmentClient {

    /**
    * \brief Create the Certificate renewal LWM2M object, instance and resource and push the object to the list
    * Also save the pointers to the object and resource, register the event handler, and create the renewal_mutex
    * Should be called by ServiceClient::initialize_and_register()
    * \param list MbedCloudClient object list
    */
    ce_status_e init(M2MBaseList& list, const EstClient *est_client);

    /**
    * \brief Release all the resources owned by the CertificateEnrollmentClient
    * Should be called by the ServiceClient destructor.
    * Does not free the LWM2M resources as the pointers are owned by the ServiceClient. They are freed by the ServiceClient object when device unregisters.
    */
    void finalize();

    /**
    * \brief Initiate a renewal for a specific certificate.
    * The process will generate new keys in order to create a CSR. The CSR is then sent to the EST service to retrieve the renewed certificate.
    * The new certificate is then atomically stored in the device, along with its corresponding private key.
    * Note: The certificate to be removed *must* already exist in the device.
    * \param cert_name A null terminated C string indicating the name of the certificate to be renewed.
    * \return CE_STATUS_SUCCESS if asynchronous operations has started successfully - In this case, user callback will be executed at the end of the operation, indicating completion status.
    *         If any other ce_status_e:: status is returned - operation encountered some error prior to start of the asynchronous stage and user callback will NOT be executed.
    */
    ce_status_e certificate_renew(const char *cert_name);

    /**
    * \brief Sets the callback function that is called when a certificate renewal process finishes.
    * Should be called prior to any certificate renewal operation.
    * If a certificate renewal is initiated (either by the certificate_renew() API or by the server) - operation will run normal but the device application will not be notified when done.
    * \param user_cb A function pointer to the user callback. If user_cb is NULL - no callback will be called when process finishes.
    */
    void on_certificate_renewal(cert_renewal_cb_f user_cb);

}


#endif //__CERTIFICATE_ENROLLMENT_CLIENT_H__
