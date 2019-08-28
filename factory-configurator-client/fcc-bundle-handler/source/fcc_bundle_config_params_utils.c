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
#include "fcc_defs.h"
#include "factory_configurator_client.h"
#include "fcc_utils.h"
#include "pv_macros.h"

fcc_status_e fcc_bundle_process_config_param_cb(CborValue *tcbor_val, void *extra_info)
{
    PV_UNUSED_PARAM(extra_info);
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_result = KCM_STATUS_SUCCESS;
    bool status;
    CborError tcbor_error = CborNoError;
    const char    *key_name = NULL;
    size_t        key_name_len = 0;
    const char    *param_name = NULL;
    size_t        param_name_len = 0;
    const uint8_t *param_data = NULL;
    size_t        param_data_size = 0;
    uint64_t      data64_val;

    // go over the map elements (key,value)
    while (!cbor_value_at_end(tcbor_val)) {

        // get key name
        status = fcc_bundle_get_text_string(tcbor_val, &key_name, &key_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

        if (strncmp(FCC_BUNDLE_DATA_PARAMETER_NAME, key_name, key_name_len) == 0) {
            
            // get param name
            status = fcc_bundle_get_text_string(tcbor_val, &param_name, &param_name_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

        } else if (strncmp(FCC_BUNDLE_DATA_PARAMETER_DATA, key_name, key_name_len) == 0) {

            // get param data - the type of the data is variant
            status = fcc_bundle_get_variant(tcbor_val, &param_data, &param_data_size , &data64_val ,param_name, param_name_len);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

        } else {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_NOT_SUPPORTED, "config param field name is illegal");
        }

        // advance tcbor_val to next key name
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse config param");

    } // end loop element

    // check existance of mandatory fields (name and data)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((param_name == NULL), FCC_STATUS_BUNDLE_ERROR, "mandatory config param fields is missing");

    if (strncmp(g_fcc_current_time_parameter_name, param_name, param_name_len) == 0) {
        // mbed.CurrentTime (expect unsigned integer)
        // set time
        fcc_status = fcc_time_set(data64_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "failed to set time");

    } else {

        // Special treat for mbed.UseBootstrap, mbed.MemoryTotalKB, mbed.FirstToClaim - store it as uint32_t
        if ((strncmp(g_fcc_use_bootstrap_parameter_name, param_name, param_name_len) == 0) ||
            (strncmp(g_fcc_memory_size_parameter_name, param_name, param_name_len) == 0) ||
            (strncmp(g_fcc_first_to_claim_parameter_name, param_name, param_name_len) == 0)) {
            param_data_size = sizeof(uint32_t);
        }

        // store config param in kcm
        kcm_result = kcm_item_store((const uint8_t*)param_name, param_name_len, KCM_CONFIG_ITEM, true, param_data ,param_data_size, NULL);
        if (kcm_result != KCM_STATUS_SUCCESS) {
            // store error
            (void)fcc_bundle_store_kcm_error_info((const uint8_t*)param_name, param_name_len, kcm_result);
            SA_PV_ERR_RECOVERABLE_RETURN(fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), "Failed to store config param");
        }
    }

    return fcc_status;
}
