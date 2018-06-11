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

#include "fcc_bundle_handler.h"
#include "cn-cbor.h"
#include "pv_error_handling.h"
#include "fcc_bundle_utils.h"
#include "key_config_manager.h"
#include "fcc_output_info_handler.h"
#include "fcc_time_profiling.h"
#include "fcc_utils.h"


/** Processes  certificate list.
* The function extracts data parameters for each certificate and stores it.
*
* @param certs_list_cb[in]   The cbor structure with certificate list.
*
* @return
*     true for success, false otherwise.
*/
fcc_status_e fcc_bundle_process_certificates(const cn_cbor *certs_list_cb)
{
    bool status = false;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_status_e output_info_fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_result =  KCM_STATUS_SUCCESS;
    uint32_t cert_index = 0;
    cn_cbor *cert_cb;
    fcc_bundle_data_param_s certificate;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certs_list_cb == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Invalid certs_list_cb pointer");

    //Initialize data struct
    memset(&certificate, 0, sizeof(fcc_bundle_data_param_s));

    for (cert_index = 0; cert_index < (uint32_t)certs_list_cb->length; cert_index++) {

        FCC_SET_START_TIMER(fcc_certificate_timer);

        //fcc_bundle_clean_and_free_data_param(&certificate);

        //Get key CBOR struct at index key_index
        cert_cb = cn_cbor_index(certs_list_cb, cert_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_cb == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Failed to get certificate at index (%" PRIu32 ") ", cert_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_cb->type != CN_CBOR_MAP), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Wrong type of certificate CBOR struct at index (%" PRIu32 ") ", cert_index);

        status = fcc_bundle_get_data_param(cert_cb, &certificate);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Failed to get certificate data at index (%" PRIu32 ") ", cert_index);

        //If private key name was passed with the certificate - the certificate is self-generated and we need to verify it agains given private key
        if (certificate.private_key_name != NULL) {
            //Try to retrieve the private key from the device and verify the certificate against key data
            kcm_result = kcm_certificate_verify_with_private_key(
                certificate.data,
                certificate.data_size,
                certificate.private_key_name,
                certificate.private_key_name_len);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR, exit, "Failed to verify certificate against given private key (%" PRIu32 ") ", cert_index);
        }

        kcm_result = kcm_item_store(certificate.name, certificate.name_len, KCM_CERTIFICATE_ITEM, true, certificate.data, certificate.data_size, certificate.acl);
        FCC_END_TIMER((char*)certificate.name, certificate.name_len,fcc_certificate_timer);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit,"Failed to store certificate at index (%" PRIu32 ") ", cert_index);

    }

exit:
    if (kcm_result != KCM_STATUS_SUCCESS) {
        //FCC_STATUS_ITEM_NOT_EXIST returned only if private key of self-generate certificate is missing. In this case we need to return name of missing item
        if (kcm_result == KCM_STATUS_ITEM_NOT_FOUND) {
            output_info_fcc_status = fcc_bundle_store_error_info(certificate.private_key_name, certificate.private_key_name_len, kcm_result);
        }
        else {
            output_info_fcc_status = fcc_bundle_store_error_info(certificate.name, certificate.name_len, kcm_result);
        }


        SA_PV_ERR_RECOVERABLE_RETURN_IF((output_info_fcc_status != FCC_STATUS_SUCCESS),
                                        fcc_status = FCC_STATUS_OUTPUT_INFO_ERROR, 
                                        "Failed to create output kcm_status error %d", kcm_result);
    }
    fcc_bundle_clean_and_free_data_param(&certificate);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}
