// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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
#ifndef DS_INTERNAL_H
#define DS_INTERNAL_H

#include <stdint.h>
#include "ds_status.h"
#include "ds_custom_metrics_internal.h"

// name of the active configuration persistent file that stores the configuration over the resets.  
extern char active_conf_filename[];

// length of the field policy id
#define POLICY_ID_LEN 32

/**
* \brief Parse received message and initialize metrics and report interval.
*
* \param message an input configuration message.
* \param message_size an input message size.
*/
ds_status_e ds_metrics_config_message_handle(const uint8_t *message, uint16_t message_size);

/**
* \brief Create message that contains metrics report.
*
* \param metrics_report to metrics buffer to be allocated.
* \param metrics_report_size to output metrics buffer size.
*/
ds_status_e ds_metrics_report_create(uint8_t *metrics_report, size_t *metrics_report_size);

/**
 * @brief Returns current minimal report interval.
 * 
 * @return uint32_t current minimal report interval
 */
uint32_t ds_metrics_ctx_min_report_interval_get();


/**
 * @brief Returns report intervals internal array.
 * 
 * @return uint32_t* internal array of report intervals.
 */
const uint32_t* ds_metrics_ctx_device_metrics_report_intervals_get();

/**
 * @brief Returns custom metrics config data internal array.
 * 
 * @return ds_custom_metric_t* internal array of custom metrics config data.
 */
const ds_custom_metric_t* ds_custom_metrics_ctx_array_get();

/**
 * @brief Returns policy id.
 * \param is_policy_initialized_out output value that tells if the policy_id was initialized. 
 * @return char* policy id string.
 */
const char* ds_metrics_ctx_policy_id_get(bool *is_policy_initialized_out);

/**
 * @brief Resets report intervals array and policy id 
 */
void ds_metrics_active_metric_config_reset();


#endif // DS_INTERNAL_H