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

#include "ce_tlv.h"
#include "CertificateEnrollmentClientCommon.h"
#include "CertificateRenewalData.h"
#include "key_config_manager.h"
#include "cs_der_keys_and_csrs.h"
#include "pv_log.h"


#include <string.h>
#include <stdio.h>

namespace CertificateEnrollmentClient {

    // Base class constructor - Allocate raw data so that it remains persistent
    CertificateRenewalDataBase::CertificateRenewalDataBase(const uint8_t *raw_data, size_t raw_data_size)
    {
        _raw_data_size = raw_data_size;
        cert_name = NULL;
        csr = NULL;
        csr_size = 0;
        est_data = NULL;
        key_handle = 0;
        _raw_data = (uint8_t *)malloc(raw_data_size);        
        memcpy(_raw_data, raw_data, _raw_data_size);
    }

    // Free _raw_data, private_key, public_key (base destructor is called implicitly after derived destructor), 
    CertificateRenewalDataBase::~CertificateRenewalDataBase()
    {
        kcm_status_e kcm_status;
        ce_status_e ce_status;

        free(_raw_data);
        free(csr);

        // Release the key handle, this shouldn't fail...
        kcm_status = cs_ec_key_free(&key_handle);
        ce_status = ce_error_handler(kcm_status);

        if (ce_status != CE_STATUS_SUCCESS) {
            SA_PV_LOG_ERR("Failed releasing CSR's key handle (status %u)\n", kcm_status);
        }
    }

    CertificateRenewalDataFromServer::CertificateRenewalDataFromServer(const uint8_t *raw_data, size_t raw_data_size) :
        CertificateRenewalDataBase(raw_data, raw_data_size)
    {
    }

    CertificateRenewalDataFromServer::~CertificateRenewalDataFromServer()
    {
    }

    // Parse the CertificateRenewalDataFromServer::data as a CBOR and retrieve the cert name and size
    ce_status_e CertificateRenewalDataFromServer::parse()
    {
        // NOTE: We should treat the TLV's VALUE according to the given type
        //       since there is only one type at the moment no parsing is needed.

        ce_tlv_status_e status;
        ce_tlv_element_s element;
        
        cert_name = NULL;

        if (ce_tlv_parser_init(_raw_data, _raw_data_size, &element) != CE_TLV_STATUS_SUCCESS) {
            return CE_STATUS_BAD_INPUT_FROM_SERVER;
        }

        while ((status = ce_tlv_parse_next(&element)) != CE_TLV_STATUS_END) {
            if (status != CE_TLV_STATUS_SUCCESS) {
                // something got wrong while parsing
                return CE_STATUS_BAD_INPUT_FROM_SERVER;
            }

            // element parsed successfully - check if type supported

            if ((element.type != CE_TLV_TYPE_CERT_NAME) && (is_required(&element))) {
                return CE_STATUS_BAD_INPUT_FROM_SERVER;
            } else if ((element.type != CE_TLV_TYPE_CERT_NAME) && (!is_required(&element))) {
                // unsupported type but optional - ignored
                continue;
            }

            cert_name = element.val.text;
            SA_PV_LOG_INFO("\nParsed certificate to be updated is %s\n", (char *)element.val.text);
        }

        if (cert_name == NULL) {
            // parsing succeeded however we haven't got a concrete certificate name
            return CE_STATUS_BAD_INPUT_FROM_SERVER;
        }

        return CE_STATUS_SUCCESS;
    };

    // call the user callback and send message to the cloud
    void CertificateRenewalDataFromServer::finish(ce_status_e status)
    {
        SA_PV_LOG_INFO("sending delayed response, status: %d\n", (int)status);
        g_cert_enroll_lwm2m_resource->set_value((int64_t)status);
        g_cert_enroll_lwm2m_resource->send_delayed_post_response();

        // Call the user callback after setting the resource so that the user may delete the MCC object from the CB.
        // If we had called the CB prior to setting the resource value, this would result in writing to unallocated memory.
        call_user_cert_renewal_cb(cert_name, status, CE_INITIATOR_SERVER);
    };

    CertificateRenewalDataFromDevice::CertificateRenewalDataFromDevice(const char *raw_data) :
        CertificateRenewalDataBase((uint8_t *)raw_data, (strlen(raw_data) + 1))
    {
    }

    CertificateRenewalDataFromDevice::~CertificateRenewalDataFromDevice()
    {
    }

    // Nothing to do other than set the cert_name field
    ce_status_e CertificateRenewalDataFromDevice::parse()
    {
        cert_name = (const char *)_raw_data;
        return CE_STATUS_SUCCESS;
    }

    // Call the user callback but do not send anything to the server
    void CertificateRenewalDataFromDevice::finish(ce_status_e status)
    {
        call_user_cert_renewal_cb(cert_name, status, CE_INITIATOR_DEVICE);
    }

}
