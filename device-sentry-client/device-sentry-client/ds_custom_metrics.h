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

    /**
     * Minimum custom metric ID value. All custom metric IDs must be above this value.
     */
    #define DS_CUSTOM_METRIC_MIN_ID 1000

    /**
     * Maximum custom metric ID value. All custom metric IDs must be below this value.
     */
    #define DS_CUSTOM_METRIC_MAX_ID 0x7FFF

    /**
     * Numeric integer type size.
     */
    #define DS_SIZE_OF_INT64 8

    /**
     * Metric ID type is an integer between DS_CUSTOM_METRIC_MIN_ID and DS_CUSTOM_METRIC_MAX_ID.
     */
    typedef uint64_t ds_custom_metric_id_t;

    /** Type of the custom metric.
     * Note: We currently support DS_INT64 only.
     */
    typedef enum ds_custom_metrics_value_type_t {
        DS_INVALID_TYPE = 0,                           /** Invalid or uninitialized type.*/
        DS_STRING,                                     /** Null terminated char array.*/
        DS_INT64,                                      /** Numeric integer type.*/
        DS_FLOAT,                                      /** Numeric float type.*/
        DS_BOOLEAN,                                    /** Boolean type.*/
        DS_OPAQUE_BUFFER,                              /** Byte array.*/

        DS_MAX_TYPE                                    /** Must be the last item.*/
    } ds_custom_metrics_value_type_t;


    /**
     * Custom metric value getter callback function prototype.
     * The client application must implement this callback function consistent with the following declaration.
     * Device Sentry calls this function periodically to create and send a custom metric report to Pelion Device Management.
     *
     * @param[in] metric_id - Custom metric ID.
     * @param[in] user_context - Opaque pointer that was passed during callback registration.
     * @param[out] metric_value_out_addr - Address of the pointer that points to the output buffer.
     *                              Note: You are responsible for managing the memory allocation for the output buffer (Device Sentry does not free this buffer).
     * @param[out] metric_value_type_out - Output type of the metric with an appropriate metric ID.
     *                              Note: We currently support DS_INT64 only.
     * @param[out] metric_value_size_out - The metric_value_out_addr buffer size in bytes.
     *                              Note: We currently support DS_INT64 only.
     * @returns
     *      ::DS_STATUS_SUCCESS If the function returns all output values successfully.
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
     * Custom metric value getter callback setting function.
     * @param cb - Callback that Device Sentry calls periodically to create and send a custom metric report to Pelion Device Management.
     * @param user_context - Opaque pointer to your context that you need to store in Device Sentry.
     *                              Note: The framework passes this pointer back to the ds_custom_metric_value_getter_t function during the invocation.
     */
    void ds_custom_metric_callback_set(
            ds_custom_metric_value_getter_t cb,
            void *user_context
        );

#endif // DS_CUSTOM_METRICS_H
