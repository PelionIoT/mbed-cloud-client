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

#ifndef DS_CUSTOM_METRICS_H
#define DS_CUSTOM_METRICS_H

#include <stddef.h>
#include <stdint.h>
#include "ds_status.h"


    /**
    * @file ds_custom_metrics.h
    *  \brief Device Sentry custom metrics definitions.
    */

/* all valid custom metrics' ids should be above this value */
#define DS_CUSTOM_METRIC_MIN_ID 1000
#define DS_CUSTOM_METRIC_MAX_ID 0x7FFF

/* metic id (integer in the range DS_CUSTOM_METRIC_MIN_ID < metric_id < DS_CUSTOM_METRIC_MAX_ID) */
typedef uint64_t ds_custom_metric_id_t;

/* Type of the custom metric                    Size of the custom metric
 Note: currently we support only DS_INT64. */
typedef enum ds_custom_metrics_value_type_t { 
    DS_INVALID_TYPE = 0,                           //!< invalid or not intialized type 
    DS_STRING,                                     //!< size of null terminated char array, result of strlen() 
    DS_INT64,                                      //!< 8 bytes 
    DS_FLOAT,                                      //!< TBD 
    DS_BOOLEAN,                                    //!< TBD 
    DS_OPAQUE_BUFFER,                              //!< custom size in bytes 

    DS_MAX_TYPE                                    //!< should be the last item
} ds_custom_metrics_value_type_t;

// sizes of the different metrics' types
#define DS_SIZE_OF_INT64 8 

/**
 * @brief Custom metric value getter callback function prototype.
 * Client application should implement this callback function according to the following prototype.
 * This function will be called each time when Device Sentry is required to know the value and the type of the 
 * particular metric (i.g. before sending metric report to the Pelion).
 * @param[in] metric_id custom metric id.
 * @param[in] user_context the opaque pointer that was passed during he callback registration.
 * @param[out] metric_value_out_addr address of the pointer that should point to the buffer that contains value of the metric.
 *                              Note: 1. This buffer should be allocated by user.
 *                                    2. This buffer will not be freed by Device Sentry.
 * @param[out] metric_value_type_out output type of the metric with an appropriate metric id.
 *                              Note: currently we support only DS_INT64. 
 * @param[out] metric_value_size_out metric_value_out size in bytes (i.e. size of the output buffer that contains value of the metric).
 *                              Note: currently we support only 8 byte DS_INT64. 
 * @returns 
 *      ::DS_STATUS_SUCCESS if all output values were successfully filled.
 *      One of the ::ds_status_e errors otherwise.
 */
typedef ds_status_e (*ds_custom_metric_value_getter_t)(
                                        ds_custom_metric_id_t metric_id,
                                        void *user_context,
                                        uint8_t **metric_value_out_addr,
                                        ds_custom_metrics_value_type_t *metric_value_type_out,
                                        size_t *metric_value_size_out
                                    ); 

/**
 * @brief Custom user metric value getter callback setting function.
 * @param cb callback that will be called each time when Device Sentry is sending custom metric report to the Pelion.
 * @param user_context the opaque pointer that will be stored in Device Sentry. 
 *                     Note: this pointer will be passed back to user during the invocation of the callback.
 */
void ds_custom_metric_callback_set(
        ds_custom_metric_value_getter_t cb, 
        void *user_context
    );  

#endif // DS_CUSTOM_METRICS_H