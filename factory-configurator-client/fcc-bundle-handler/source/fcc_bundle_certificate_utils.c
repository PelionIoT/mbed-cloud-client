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
#include "pv_error_handling.h"
#include "fcc_bundle_utils.h"
#include "key_config_manager.h"
#include "fcc_output_info_handler.h"
#include "fcc_utils.h"

fcc_status_e fcc_bundle_process_certificates_cb(CborValue *tcbor_val, void *extra_info)
{
    bool is_chains = (bool)extra_info;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_result = KCM_STATUS_SUCCESS;
    bool status;
    CborError tcbor_error = CborNoError;
    const char    *key_name = NULL;
    size_t        key_name_len;
    const char    *param_name = NULL;
    size_t        param_name_len = 0;
    const char    *param_priv_key_name = NULL;
    size_t        param_priv_key_name_len = 0;
    const char    *param_format = NULL;
    size_t        param_format_len = 0;
    const uint8_t *cert_chain_data[KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN] = { NULL };
    size_t        cert_chain_data_size[KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN] = { 0 };
    size_t        cert_chain_len = 0;
    size_t        cert_chain_index = 0;
    kcm_cert_chain_handle cert_chain_handle = NULL;
    CborValue     tcbor_arr_item_val;
    const uint8_t *failed_item_name = NULL;
    size_t        failed_item_name_len = 0;

    // go over the map elements (key,value)
    while (!cbor_value_at_end(tcbor_val)) {

        // get key name
        status = fcc_bundle_get_text_string(tcbor_val, &key_name, &key_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate param");

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate param");

        if (strncmp(FCC_BUNDLE_DATA_PARAMETER_NAME, key_name, key_name_len) == 0) {
            
            // get param name
            status = fcc_bundle_get_text_string(tcbor_val, &param_name, &param_name_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_PRIVATE_KEY_NAME, key_name, key_name_len) == 0) {

            // get param private key name
            status = fcc_bundle_get_text_string(tcbor_val, &param_priv_key_name, &param_priv_key_name_len, param_name, param_name_len);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_FORMAT, key_name, key_name_len) == 0) {

            // get param format
            status = fcc_bundle_get_text_string(tcbor_val, &param_format, &param_format_len, param_name, param_name_len);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_DATA, key_name, key_name_len) == 0 && is_chains == false) {

            // get single certificate data
            status = fcc_bundle_get_byte_string(tcbor_val, &cert_chain_data[0], &cert_chain_data_size[0], param_name, param_name_len);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate param");
            cert_chain_len = 1;

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_ARRAY, key_name, key_name_len) == 0 && is_chains == true) {

            // parse "DataArray" array and get chain certificates data
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!cbor_value_is_array(tcbor_val)), FCC_STATUS_BUNDLE_ERROR, "Unexpected CBOR type");
            
            // get array length
            tcbor_error = cbor_value_get_array_length(tcbor_val, &cert_chain_len);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_chain_len <= 0 || cert_chain_len > KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN), FCC_STATUS_BUNDLE_ERROR, "Unexpected certificates in chain");

            // enter array container
            tcbor_error = cbor_value_enter_container(tcbor_val, &tcbor_arr_item_val);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate chain param");

            while (!cbor_value_at_end(&tcbor_arr_item_val)) {

                // get certificate data
                status = fcc_bundle_get_byte_string(&tcbor_arr_item_val, &cert_chain_data[cert_chain_index], &cert_chain_data_size[cert_chain_index], param_name, param_name_len);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate chain param");
                
                // increase index
                cert_chain_index++;

                // advance tcbor_arr_item_val next item in array
                tcbor_error = cbor_value_advance(&tcbor_arr_item_val);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse certificate chain param");

            } // end loop "DataArray" elements

            // save chain len to cert_chain_len
            cert_chain_len = cert_chain_index;

        } else {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_NOT_SUPPORTED, "Certificate param field is not supported");
        }

        // advance tcbor_val to next key name
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

    } // end loop element

    // check existance of mandatory fields (name, type and data)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((param_name == NULL || cert_chain_len == 0), FCC_STATUS_BUNDLE_ERROR, "mandatory certificate param fields is missing");

    // check certificate format - expect DER only
    SA_PV_ERR_RECOVERABLE_RETURN_IF((strncmp(FCC_BUNDLE_DER_DATA_FORMAT_NAME, param_format, param_format_len) != 0), FCC_STATUS_NOT_SUPPORTED, "unsupported certificate format");

    //If private key name was passed with the certificate - the certificate is self-generated and we need to verify it agains given private key
    if (param_priv_key_name != NULL) {
        //Try to retrieve the private key from the device and verify the certificate against key data
        kcm_result = kcm_certificate_verify_with_private_key(cert_chain_data[0], cert_chain_data_size[0], (const uint8_t*)param_priv_key_name, param_priv_key_name_len);
        // KCM_STATUS_ITEM_NOT_FOUND returned only if private key of self-generate certificate is missing. 
        // In this case we return FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR but store kcm error for missing private key
        if (kcm_result == KCM_STATUS_ITEM_NOT_FOUND) {
            failed_item_name = (const uint8_t*)param_priv_key_name;
            failed_item_name_len = param_priv_key_name_len;
        }
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR, exit, "Failed to verify certificate against given private key");
    }

    if (is_chains) {

        // Store chain certificate in kcm

        // Create chain
        kcm_result = kcm_cert_chain_create(&cert_chain_handle, (const uint8_t*)param_name, param_name_len, cert_chain_len, true);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_KCM_ERROR, exit, "Failed to create certificate chain");

        for (cert_chain_index = 0; cert_chain_index < cert_chain_len; cert_chain_index++) {
            kcm_result = kcm_cert_chain_add_next(cert_chain_handle, cert_chain_data[cert_chain_index], cert_chain_data_size[cert_chain_index]);            
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to add certificate chain");
        }
        
        // Close chain
        kcm_result = kcm_cert_chain_close(cert_chain_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to close certificate chain");

    } else {
        // Store single certificate in kcm
        kcm_result = kcm_item_store((const uint8_t*)param_name, param_name_len, KCM_CERTIFICATE_ITEM, true, cert_chain_data[0], cert_chain_data_size[0], NULL);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to store certificate param");
    }
exit:
    if (kcm_result != KCM_STATUS_SUCCESS) {
        if (cert_chain_handle != NULL) {
            kcm_cert_chain_close(cert_chain_handle);
        }

        // store error
        if (failed_item_name == NULL) {
            // if failed_item_name not set, set param_name as default
            failed_item_name = (const uint8_t*)param_name;
            failed_item_name_len = param_name_len;
        }
        (void)fcc_bundle_store_kcm_error_info((const uint8_t*)failed_item_name, failed_item_name_len, kcm_result);
    }

    return fcc_status;
}
