/*
 * Copyright (c) 2021 Pelion. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef M2M_DISCOVER_H
#define M2M_DISCOVER_H

#include "mbed-client/m2mobject.h"
#include "include/m2mreporthandler.h"

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY) && (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY == 1)

class M2MDiscover {

public:

    /**
     * \brief Creates Discover request payload from the given M2MObject.
     * @param object M2MObject which is to create payload.
     * @param data_length reference which is updated to length of the data returned. Initial value does not mather.
     * \return NULL if allocation failed, otherwise allocated uint8_t* with payload.
     */
    static uint8_t *create_object_payload(const M2MObject *object, uint32_t &data_length);

    /**
     * \brief Creates Discover request payload from the given M2MObjectInstance.
     * @param obj_instance M2MObjectInstance which is to create payload.
     * @param data_length reference which is updated to length of the data returned. Initial value does not mather.
     * \return NULL if allocation failed, otherwise allocated uint8_t* with payload.
     */
    static uint8_t *create_object_instance_payload(const M2MObjectInstance *obj_instance, uint32_t &data_length);

    /**
     * \brief Creates Discover request payload from the given M2MResource.
     * @param res M2MResource which is to create payload.
     * @param data_length reference which is updated to length of the data returned. Initial value does not mather.
     * \return NULL if allocation failed, otherwise allocated uint8_t* with payload.
     */
    static uint8_t *create_resource_payload(const M2MResource *res, uint32_t &data_length);

private:
    // Prevent instantiate of this class
    M2MDiscover();

    static void create_object_payload(const M2MObject *object, uint8_t **data, uint32_t &data_length);

    static void create_object_instance_payload(const M2MObjectInstance *obj_instance, uint8_t **data, uint32_t &data_length, bool add_resource_dimension, bool add_resource_attribute, bool add_object_attributes);

    static void create_resource_payload(const M2MResource *res, uint8_t **data, uint32_t &data_length, bool add_resource_dimension, bool add_resource_attribute, bool add_inherited = false);

    static void set_path(const char *path, uint8_t **data, uint32_t &data_length);

    static void set_path_and_attributes(M2MReportHandler *report_handler, const char *path, uint8_t **data, uint32_t &data_length);

    static void set_string_and_value(uint8_t **data, uint32_t &data_length, const char* str, float value, int32_t int_value, bool float_type);

    static void set_comma(uint8_t **data, uint32_t &data_length);

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    static void set_resource_attributes(const M2MResource &res, uint8_t **data, uint32_t &data_length, bool add_inherited);

    static const char *get_attribute_string(M2MReportHandler::WriteAttribute attribute);

    static void get_write_attributes(M2MReportHandler &report_handler, M2MReportHandler:: WriteAttribute attribute, float &attribute_value_float, uint32_t &attribute_value_int, bool float_val);
#endif
};

#endif // defined (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY) && (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY == 1)
#endif // M2M_DISCOVER_H
