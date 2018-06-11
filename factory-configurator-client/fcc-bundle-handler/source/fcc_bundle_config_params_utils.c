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
#include "fcc_defs.h"
#include "fcc_output_info_handler.h"
#include "factory_configurator_client.h"
#include "general_utils.h"
#include "fcc_time_profiling.h"
#include "fcc_utils.h"

static fcc_status_e set_time_from_config_param(const fcc_bundle_data_param_s *current_time)
{

    fcc_status_e status;
    uint64_t time = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((current_time == NULL), FCC_STATUS_INVALID_PARAMETER, "Got invalid or corrupted 'current_time' pointer");

    // Check given time length before copying
    SA_PV_ERR_RECOVERABLE_RETURN_IF((current_time->data_size > sizeof(uint64_t)), FCC_STATUS_MEMORY_OUT, "Time length (%" PRIu32 "B) too long (corrupted format?)", (uint32_t)current_time->data_size);
    memcpy(&time, current_time->data, current_time->data_size);

    status = fcc_time_set(time);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != FCC_STATUS_SUCCESS), FCC_STATUS_ERROR, "fcc_time_set failed");


    return FCC_STATUS_SUCCESS;
}

fcc_status_e fcc_bundle_process_config_params(const cn_cbor *config_params_list_cb)
{

    bool success = false;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_status_e output_info_fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_result = KCM_STATUS_SUCCESS;
    uint32_t config_param_index = 0;
    cn_cbor *config_param_cb;
    fcc_bundle_data_param_s config_param;
    size_t currentTimeLength = strlen(g_fcc_current_time_parameter_name);

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((config_params_list_cb == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Invalid config_params_list_cb pointer");

    //Initialize data struct
    memset(&config_param, 0, sizeof(config_param));

    for (config_param_index = 0; config_param_index < (uint32_t)config_params_list_cb->length; config_param_index++) {

        FCC_SET_START_TIMER(fcc_config_param_timer);

        //fcc_bundle_clean_and_free_data_param(&config_param);

        //Get key CBOR struct at index key_index
        config_param_cb = cn_cbor_index(config_params_list_cb, config_param_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((config_param_cb == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Failed to get certificate at index (%" PRIu32 ") ", config_param_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((config_param_cb->type != CN_CBOR_MAP), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Wrong type of config param CBOR struct at index (%" PRIu32 ")", config_param_index);

        success = fcc_bundle_get_data_param(config_param_cb, &config_param);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((success != true), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Failed to get config param data at index (%" PRIu32 ") ", config_param_index);

        // Sets the time
        if (is_memory_equal(config_param.name, config_param.name_len, g_fcc_current_time_parameter_name, currentTimeLength)) {
            fcc_status = set_time_from_config_param(&config_param);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit, "set_time_from_config_param failed");
        } else {
            kcm_result = kcm_item_store(config_param.name, config_param.name_len, KCM_CONFIG_ITEM, true, config_param.data, config_param.data_size, config_param.acl);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to store configuration parameter at index (%" PRIu32 ") ", (uint32_t)config_param_index);
        }
        FCC_END_TIMER((char*)config_param.name, config_param.name_len, fcc_config_param_timer);
    }

exit:
    if (kcm_result != KCM_STATUS_SUCCESS) {

        output_info_fcc_status =  fcc_bundle_store_error_info(config_param.name, config_param.name_len, kcm_result);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((output_info_fcc_status != FCC_STATUS_SUCCESS),
                                        fcc_status = FCC_STATUS_OUTPUT_INFO_ERROR,
                                        "Failed to create output kcm_status error %d", kcm_result);
    }
    fcc_bundle_clean_and_free_data_param(&config_param);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return fcc_status;
}
