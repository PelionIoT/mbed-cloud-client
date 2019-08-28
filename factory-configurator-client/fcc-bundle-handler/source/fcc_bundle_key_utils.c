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
#include "pv_macros.h"

fcc_status_e fcc_bundle_process_keys_cb(CborValue *tcbor_val, void *extra_info)
{
    PV_UNUSED_PARAM(extra_info);
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_result = KCM_STATUS_SUCCESS;
    bool status;
    CborError tcbor_error = CborNoError;
    const char    *key_name = NULL;
    size_t        key_name_len;
    const char    *param_name = NULL;
    size_t        param_name_len = 0;
    const char    *param_key_type = NULL;
    size_t        param_key_type_len = 0;
    const char    *param_format = NULL;
    size_t        param_format_len = 0;
    const uint8_t *param_data = NULL;
    size_t        param_data_size = 0;
    kcm_item_type_e kcm_item_type;

    // go over the map elements (key,value)
    while (!cbor_value_at_end(tcbor_val)) {

        // get key name
        status = fcc_bundle_get_text_string(tcbor_val, &key_name, &key_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse key param");

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse key param");

        if (strncmp(FCC_BUNDLE_DATA_PARAMETER_NAME, key_name, key_name_len) == 0) {
            
            // get param name
            status = fcc_bundle_get_text_string(tcbor_val, &param_name, &param_name_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse key param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_TYPE, key_name, key_name_len) == 0) {

            // get param type
            status = fcc_bundle_get_text_string(tcbor_val, &param_key_type, &param_key_type_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse key param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_FORMAT, key_name, key_name_len) == 0) {

            // get param format
            status = fcc_bundle_get_text_string(tcbor_val, &param_format, &param_format_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse key param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_DATA, key_name, key_name_len) == 0) {

            // get param data
            status = fcc_bundle_get_byte_string(tcbor_val, &param_data, &param_data_size, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse key param");

        } else {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_NOT_SUPPORTED, "Key param field is not supported");
        }

        // advance tcbor_val to next key name
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

    } // end loop element

    // check existance of mandatory fields (name, type and data)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((param_name == NULL || param_key_type == NULL), FCC_STATUS_BUNDLE_ERROR, "mandatory key param fields is missing");

    // convert key type string to kcm_item_type
         if (strncmp(FCC_ECC_PRIVATE_KEY_TYPE_NAME, param_key_type, param_key_type_len) == 0) { kcm_item_type = KCM_PRIVATE_KEY_ITEM; }
//    else if (strncmp(FCC_RSA_PRIVATE_KEY_TYPE_NAME, param_key_type, param_key_type_len) == 0) { kcm_item_type = KCM_PRIVATE_KEY_ITEM; }
    else if (strncmp(FCC_ECC_PUBLIC_KEY_TYPE_NAME , param_key_type, param_key_type_len) == 0) { kcm_item_type = KCM_PUBLIC_KEY_ITEM; }
//    else if (strncmp(FCC_RSA_PUBLIC_KEY_TYPE_NAME , param_key_type, param_key_type_len) == 0) { kcm_item_type = KCM_PUBLIC_KEY_ITEM; }
//    else if (strncmp(FCC_SYMMETRIC_KEY_TYPE_NAME  , param_key_type, param_key_type_len) == 0) { kcm_item_type = KCM_SYMMETRIC_KEY_ITEM; }
    else {
        SA_PV_ERR_RECOVERABLE_RETURN(FCC_STATUS_NOT_SUPPORTED, "unsupported key type");
    }

    // check key format - expect DER only
    SA_PV_ERR_RECOVERABLE_RETURN_IF((strncmp(FCC_BUNDLE_DER_DATA_FORMAT_NAME, param_format, param_format_len) != 0), FCC_STATUS_NOT_SUPPORTED, "unsupported key format");

    // store key param in kcm
    kcm_result = kcm_item_store((const uint8_t*)param_name, param_name_len, kcm_item_type, true, param_data, param_data_size, NULL);
    if (kcm_result != KCM_STATUS_SUCCESS) {
        // store error
        (void)fcc_bundle_store_kcm_error_info((const uint8_t*)param_name, param_name_len, kcm_result);
        SA_PV_ERR_RECOVERABLE_RETURN(fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), "Failed to store key param");
    }

    return fcc_status;
}
