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

// name of the active configuration persistent file that stores the configuration over the resets.  
extern char active_conf_filename[];

// length of each field in the active configuration persistent file.  
extern const size_t ACTIVE_CONFIG_FILE_FIELD_SIZE;


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
ds_status_e metrics_report_create(uint8_t *metrics_report, size_t *metrics_report_size);

/**
 * @brief Returns current minimal report interval.
 * 
 * @return uint32_t current minimal report interval
 */
uint32_t ds_metrics_config_min_report_interval_get();

/**
 * @brief Returns report intervals internal array.
 * 
 * @return uint32_t* internal array of report intervals.
 */
const uint32_t* ds_metrics_config_report_intervals_get();

/**
 * @brief Resets report intervals array 
 */
void ds_metrics_config_report_intervals_reset();


#endif // DS_INTERNAL_H