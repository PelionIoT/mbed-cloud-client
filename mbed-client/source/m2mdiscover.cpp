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

#include "include/m2mdiscover.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"

#include <stdio.h>
#include <string.h>

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY) && (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY == 1)

#define TRACE_GROUP "mDisc"

uint8_t *M2MDiscover::create_object_payload(const M2MObject *object, uint32_t &data_length)
{
    // First we do a dryrun to calculate the needed space
    uint32_t len = 0;
    uint8_t *data = 0;
    create_object_payload(object, &data, len);

    // Then allocate memory and fill the data
    data = (uint8_t *)malloc(len + 1);
    len = 0;

    if (data) {
        // copy pointer as it's moved inside the function
        uint8_t *tmp_data = data;
        create_object_payload(object, &tmp_data, len);

        tr_debug("M2MDiscover::create_object_payload - len: %d, data:\n%.*s", len, len, (char *)data);
        data_length = len;
    }
    return data;
}

uint8_t *M2MDiscover::create_object_instance_payload(const M2MObjectInstance *obj_instance, uint32_t &data_length)
{
    // First we do a dryrun to calculate the needed space
    uint32_t len = 0;
    uint8_t *data = 0;
    create_object_instance_payload(obj_instance, &data, len, true, true, true);

    // Then allocate memory and fill the data
    data = (uint8_t *)malloc(len + 1);
    len = 0;

    if (data) {
        // copy pointer as it's moved inside the function
        uint8_t *tmp_data = data;
        create_object_instance_payload(obj_instance, &tmp_data, len, true, true, true);

        tr_debug("M2MDiscover::create_object_instance_payload - len: %d, data:\n%.*s", len, len, (char *)data);
        data_length = len;
    }
    return data;
}

uint8_t *M2MDiscover::create_resource_payload(const M2MResource *res, uint32_t &data_length)
{
    // First we do a dryrun to calculate the needed space
    uint32_t len = 0;
    uint8_t *data = 0;
    create_resource_payload(res, &data, len, true, true, true);

    // Then allocate memory and fill the data
    data = (uint8_t *)malloc(len + 1);
    len = 0;

    if (data) {
        // copy pointer as it's moved inside the function
        uint8_t *tmp_data = data;
        create_resource_payload(res, &tmp_data, len, true, true, true);

        tr_debug("M2MDiscover::create_resource_payload - len: %d, data:\n%.*s", len, len, (char *)data);
        data_length = len;
    }
    return data;
}

void M2MDiscover::create_object_payload(const M2MObject *object, uint8_t **data, uint32_t &data_length)
{
    // when Discover is done to object level, only object level attributes are listed and then list of object instances and their resources
    // for example </3>;pmin=10,</3/0>,</3/0/1>,</3/0/2>,</3/0/3>,</3/0/4>,</3/0/6>,</3/0/7>,</3/0/8>,</3/0/11>,</3/0/16>
    // which means that the LwM2M Client supports the Device Info Object (Instance 0) Resources with IDs 1,2,3,4
    // 6,7,8,11, and 16 among the Resources of Device Info Object, with an R-Attributes assigned to the Object level.
    const M2MObjectInstanceList &object_instance_list = object->instances();

    // Add object path and it's Write-Attributes to payload
    set_path_and_attributes(object->report_handler(), object->uri_path(), data, data_length);

    // Add object instances paths and their resource paths to payload
    if (!object_instance_list.empty()) {
        // add comma between object and object instances
        set_comma(data, data_length);

        M2MObjectInstanceList::const_iterator it;
        it = object_instance_list.begin();
        for (; it != object_instance_list.end();) {
            create_object_instance_payload((const M2MObjectInstance *)*it, data, data_length, false, false, false);
            it++;
            if (it != object_instance_list.end()) {
                // add comma between object instances
                set_comma(data, data_length);
            }
        }
    }
}

void M2MDiscover::create_object_instance_payload(const M2MObjectInstance *obj_instance, uint8_t **data, uint32_t &data_length, bool add_resource_dimension,
                                                 bool add_resource_attribute, bool add_object_attribute)
{
    // when Discover is done to object instance level, attributes for object instance must be listed, resources and their attibutes
    // For example </3/0>;pmax=60,</3/0/1>,<3/0/2>,</3/0/3>,</3/0/4>,</3/0/6>;dim=8,</3/0/7>;dim=8;gt=50;lt=42.2,</3/0/8>;dim=8,</3/0/11>,</3/0/16>
    // means that regarding the Device Info Object Instance, an R-Attribute has been assigned to this Instance level. And
    // the LwM2M Client supports the multiple Resources 6, 7, and 8 with a dimension of 8 and has 2 additional
    // Notification parameters assigned for Resource 7.
    const M2MResourceList &resource_list = obj_instance->resources();

    // Add object instance path and it's Write-Attributes to payload
    if (add_object_attribute) {
        set_path_and_attributes(obj_instance->report_handler(), obj_instance->uri_path(), data, data_length);
    } else {
        set_path(obj_instance->uri_path(), data, data_length);
    }

    // Add resource paths to payload and possible Write-Attributes to payload
    if (!resource_list.empty()) {
        // add comma between object instance and resources
        set_comma(data, data_length);

        M2MResourceList::const_iterator it;
        it = resource_list.begin();
        for (; it != resource_list.end();) {
            create_resource_payload((const M2MResource *)*it, data, data_length, add_resource_dimension, add_resource_attribute);
            it++;
            if (it != resource_list.end()) {
                // add comma between resources
                set_comma(data, data_length);
            }
        }
    }
}

void M2MDiscover::create_resource_payload(const M2MResource *res, uint8_t **data, uint32_t &data_length, bool add_resource_dimension, bool add_resource_attribute, bool add_inherited)
{
    // when Discover is done to resource level, list resource and it's attributes,
    // including the assigned R-Attributes and the R-Attributes inherited from the Object and Object Instance
    // For example: if Object ID is 3, and Resource ID is 7, then
    // </3/0/7>;dim=8;pmin=10;pmax=60;gt=50;lt=42.2
    // with pmin assigned at the Object level, and pmax assigned at the Object Instance level

    // Add resource path to payload
    set_path(res->uri_path(), data, data_length);

    // add dimension, e.g. how many resource instances does this resource have, if none, then nothing is added to payload
    if (add_resource_dimension && res->supports_multiple_instances()) {
        set_string_and_value(data, data_length, ";dim=", 0, res->resource_instance_count(), false);
    }

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    // Add possible Write-Attributes to payload
    if (add_resource_attribute) {
        set_resource_attributes(*res, data, data_length, add_inherited);
    }
#endif
}

void M2MDiscover::set_comma(uint8_t **data, uint32_t &data_length)
{
     if (*data) {
        memcpy(*data, ",", 1);
        *data += 1;
    }
    data_length++;
}

void M2MDiscover::set_string_and_value(uint8_t **data, uint32_t &data_length, const char* str, float float_value, int32_t int_value, bool float_type)
{
    int max_val_len = REGISTRY_FLOAT_STRING_MAX_LEN;
    if (*data == NULL) {
        max_val_len = 0;
    }
    uint32_t tmp_len = strlen(str);
    data_length += tmp_len;
    if (*data) {
        memcpy(*data, str, tmp_len);
        *data += tmp_len;
    }

#if MBED_MINIMAL_PRINTF
    if (float_type) {
        tmp_len = snprintf((char *)*data, max_val_len, "%f", float_value);
    } else {
        tmp_len = snprintf((char *)*data, max_val_len, "%d", int_value);
    }
#else
    tmp_len = snprintf((char *)*data, max_val_len, "%g", float_type ? float_value : int_value);
#endif

    data_length += tmp_len;
    if (*data) {
        // move data pointer to point after the added data
        *data += tmp_len;
    }
}

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
void M2MDiscover::set_resource_attributes(const M2MResource &res, uint8_t **data, uint32_t &data_length, bool add_inherited)
{
    float attribute_value_float;
    uint32_t attribute_value_int;
    bool set_attribute = false;
    bool float_val = true;
    M2MReportHandler *report_handler = res.report_handler();

    for (int attribute = M2MReportHandler::Pmin; attribute <= M2MReportHandler::St; attribute *= 2) {
        if ((attribute == M2MReportHandler::Pmin) || (attribute == M2MReportHandler::Pmax)) {
            float_val = false;
        } else {
            float_val = true;
        }

        report_handler = res.report_handler();
        set_attribute = false;

        if (report_handler && report_handler->attribute_flags() & attribute) {
            get_write_attributes(*report_handler, (M2MReportHandler::WriteAttribute)attribute, attribute_value_float, attribute_value_int, float_val);
            set_attribute = true;
        } else if (add_inherited) {
            // check if inherited from object or object instance
            M2MObjectInstance &obj_inst = res.get_parent_object_instance();
            report_handler = obj_inst.report_handler();
            if (report_handler && (report_handler->attribute_flags() & attribute)) {
                get_write_attributes(*report_handler, (M2MReportHandler::WriteAttribute)attribute, attribute_value_float, attribute_value_int, float_val);
                set_attribute = true;
            } else {
                M2MObject &obj = obj_inst.get_parent_object();
                report_handler = obj.report_handler();
                if (report_handler && (report_handler->attribute_flags() & attribute)) {
                    get_write_attributes(*report_handler, (M2MReportHandler::WriteAttribute)attribute, attribute_value_float, attribute_value_int, float_val);
                    set_attribute = true;
                }
            }
        }
        if (set_attribute) {
            set_string_and_value(data, data_length, get_attribute_string((M2MReportHandler::WriteAttribute)attribute), attribute_value_float, attribute_value_int, float_val);
        }
    }
}

void M2MDiscover::get_write_attributes(M2MReportHandler &report_handler, M2MReportHandler:: WriteAttribute attribute, float &attribute_value_float, uint32_t &attribute_value_int, bool float_val)
{
    if (float_val) {
        attribute_value_float = report_handler.get_notification_attribute_float(attribute);
    } else {
        attribute_value_int = report_handler.get_notification_attribute_int(attribute);
    }
}

const char *M2MDiscover::get_attribute_string(M2MReportHandler::WriteAttribute attribute)
{
    const char *tmp = 0;
    switch (attribute) {
        case M2MReportHandler::Pmin:
            tmp = ";pmin=";
            break;
        case M2MReportHandler::Pmax:
            tmp = ";pmax=";
            break;
        case M2MReportHandler::Lt:
            tmp = ";lt=";
            break;
        case M2MReportHandler::Gt:
            tmp = ";gt=";
            break;
        case M2MReportHandler::St:
            tmp = ";st=";
            break;
        case M2MReportHandler::Cancel:
        /* fall-thru */
        default:
            // Can't actually come here as we start looping from pmin, but let's satisfy the compiler
            tr_error("Invalid attrubute type: %d", attribute);
            assert(true);
            break;
    }
    return tmp;
}
#endif

void M2MDiscover::set_path_and_attributes(M2MReportHandler *report_handler, const char *path, uint8_t **data, uint32_t &data_length)
{
    set_path(path, data, data_length);

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    if (report_handler) {
        float attribute_value_float;
        uint32_t attribute_value_int;
        bool float_val = true;
        for (int i = M2MReportHandler::Pmin; i <= M2MReportHandler::St; i *= 2) {
            if (report_handler->attribute_flags() & i) {
                if ((i == M2MReportHandler::Pmin) || (i == M2MReportHandler::Pmax)) {
                    float_val = false;
                } else {
                    float_val = true;
                }
                get_write_attributes(*report_handler, (M2MReportHandler::WriteAttribute)i, attribute_value_float, attribute_value_int, float_val);
                set_string_and_value(data, data_length, get_attribute_string((M2MReportHandler::WriteAttribute)i), attribute_value_float, attribute_value_int, float_val);
            }
        }
    }
#endif
}

void M2MDiscover::set_path(const char *path, uint8_t **data, uint32_t &data_length)
{
    data_length += 3; // </ >
    data_length += strlen(path); // e.g. "3" or "3/0" or "3/0/7"

    if (*data) {
        memcpy(*data, "</", 2);
        *data += 2;
        memcpy(*data, path, strlen(path));
        *data += strlen(path);
        memcpy(*data, ">", 1);
        *data += 1;
    }
}

#endif // defined (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY) && (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY == 1)
