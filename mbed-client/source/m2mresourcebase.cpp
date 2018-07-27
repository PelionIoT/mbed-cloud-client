/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
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

// Needed for PRIu64 on FreeRTOS
#include <stdio.h>
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdlib.h>
#include "mbed-client/m2mresourcebase.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mobservationhandler.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "include/m2mcallbackstorage.h"
#include "include/m2mreporthandler.h"
#include "include/nsdllinker.h"
#include "include/m2mtlvserializer.h"
#include "mbed-client/m2mblockmessage.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

// -9223372036854775808 - +9223372036854775807
// max length of int64_t string is 20 bytes + nil
#define REGISTRY_INT64_STRING_MAX_LEN 21
// (space needed for -3.402823 × 10^38) + (magic decimal 6 digits added as no precision is added to "%f") + trailing zero
#define REGISTRY_FLOAT_STRING_MAX_LEN 48



M2MResourceBase::M2MResourceBase(
                                         const String &res_name,
                                         M2MBase::Mode resource_mode,
                                         const String &resource_type,
                                         M2MBase::DataType type,
                                         char* path,
                                         bool external_blockwise_store,
                                         bool multiple_instance,
                                         const uint8_t *value,
                                         const uint8_t value_length)
: M2MBase(res_name,
          resource_mode,
#ifndef DISABLE_RESOURCE_TYPE
          resource_type,
#endif
          path,
          external_blockwise_store,
          multiple_instance,
          type)
#ifndef DISABLE_BLOCK_MESSAGE
 ,_block_message_data(NULL),
#endif
 _notification_status(M2MResourceBase::INIT)
{
    if( value != NULL && value_length > 0 ) {
        M2MBase::set_base_type(M2MBase::ResourceInstance);
        sn_nsdl_dynamic_resource_parameters_s* res = get_nsdl_resource();
        res->resource = alloc_string_copy(value, value_length);
        res->resource_len = value_length;
    }
}

M2MResourceBase::M2MResourceBase(
                                         const lwm2m_parameters_s* s,
                                         M2MBase::DataType /*type*/)
: M2MBase(s)
#ifndef DISABLE_BLOCK_MESSAGE
  ,_block_message_data(NULL),
#endif
  _notification_status(M2MResourceBase::INIT)
{
    // we are not there yet for this check as this is called from M2MResource(): assert(base_type() == M2MBase::ResourceInstance);
}

M2MResourceBase::~M2MResourceBase()
{
    execute_callback* callback = (execute_callback*)M2MCallbackStorage::remove_callback(*this,
                                    M2MCallbackAssociation::M2MResourceInstanceExecuteCallback);
    delete callback;

    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback2);
#ifndef DISABLE_BLOCK_MESSAGE
    incoming_block_message_callback *in_callback = (incoming_block_message_callback*)M2MCallbackStorage::remove_callback(*this,
                                                        M2MCallbackAssociation::M2MResourceInstanceIncomingBlockMessageCallback);
    delete in_callback;

    outgoing_block_message_callback *out_callback = (outgoing_block_message_callback*)M2MCallbackStorage::remove_callback(*this,
                                                        M2MCallbackAssociation::M2MResourceInstanceOutgoingBlockMessageCallback);
    delete out_callback;
#endif

    notification_sent_callback *notif_callback = (notification_sent_callback*)M2MCallbackStorage::remove_callback(*this,
                                                        M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback);
    delete notif_callback;

    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback2);

    notification_status_callback *notif_status_callback = (notification_status_callback*)M2MCallbackStorage::remove_callback(*this,
                                                        M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback);
    delete notif_status_callback;

    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback2);

#ifndef DISABLE_BLOCK_MESSAGE
    delete _block_message_data;
#endif
}

M2MResourceBase::ResourceType M2MResourceBase::resource_instance_type() const
{
    M2MBase::lwm2m_parameters_s* param = M2MBase::get_lwm2m_parameters();
    return (M2MResourceBase::ResourceType)(param->data_type);
}


bool M2MResourceBase::set_execute_function(execute_callback callback)
{
    execute_callback* old_callback = (execute_callback*)M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback);
    delete old_callback;
    // XXX: create a copy of the copy of callback object. Perhaps it would better to
    // give a reference as parameter and just store that, as it would save some memory.
    execute_callback* new_callback = new execute_callback(callback);

    return M2MCallbackStorage::add_callback(*this, new_callback, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback);
}

bool M2MResourceBase::set_execute_function(execute_callback_2 callback)
{
    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback2);

    return M2MCallbackStorage::add_callback(*this, (void*)callback, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback2);
}

bool M2MResourceBase::set_resource_read_callback(read_resource_value_callback callback, void *client_args)
{
    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceBaseValueReadCallback);
    M2MBase::lwm2m_parameters_s* param = M2MBase::get_lwm2m_parameters();
    param->read_write_callback_set = true;
    return M2MCallbackStorage::add_callback(*this,
                                            (void*)callback,
                                            M2MCallbackAssociation::M2MResourceBaseValueReadCallback,
                                            client_args);

}

bool M2MResourceBase::set_resource_write_callback(write_resource_value_callback callback, void *client_args)
{
    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceBaseValueWriteCallback);
    M2MBase::lwm2m_parameters_s* param = M2MBase::get_lwm2m_parameters();
    param->read_write_callback_set = true;

    return M2MCallbackStorage::add_callback(*this,
                                            (void*)callback,
                                            M2MCallbackAssociation::M2MResourceBaseValueWriteCallback,
                                            client_args);
}

void M2MResourceBase::clear_value()
{
    tr_debug("M2MResourceBase::clear_value");

    sn_nsdl_dynamic_resource_parameters_s* res = get_nsdl_resource();
    free(res->resource);
    res->resource = NULL;
    res->resource_len = 0;

    report();
}

bool M2MResourceBase::set_value_float(float value)
{
    bool success;
    char buffer[REGISTRY_FLOAT_STRING_MAX_LEN];

    // Convert value to string
    /* write the float value to a decimal number string and copy it into a buffer allocated for caller */
    uint32_t size = snprintf(buffer, REGISTRY_FLOAT_STRING_MAX_LEN, "%f", value);

    success = set_value((const uint8_t*)buffer, size);

    return success;
}

bool M2MResourceBase::set_value(int64_t value)
{
    bool success;
    char buffer[REGISTRY_INT64_STRING_MAX_LEN];
    uint32_t size = m2m::itoa_c(value, buffer);

    success = set_value((const uint8_t*)buffer, size);

    return success;
}

bool M2MResourceBase::set_value(const uint8_t *value,
                                const uint32_t value_length)
{
    tr_debug("M2MResourceBase::set_value()");
    bool success = false;
    if( value != NULL && value_length > 0 ) {
        M2MBase::lwm2m_parameters_s* param = M2MBase::get_lwm2m_parameters();
        if (param->read_write_callback_set) {
            return write_resource_value(*this, value, value_length);
        } else {
            uint8_t *value_copy = alloc_string_copy(value, value_length);
            if (value_copy) {
                value_set_callback callback = (value_set_callback)M2MCallbackStorage::get_callback(*this, M2MCallbackAssociation::M2MResourceBaseValueSetCallback);
                if (callback) {
                    (*callback)((const M2MResourceBase*)this, value_copy, value_length);
                }
                else {
                    update_value(value_copy, value_length);
                }
                success = true;
            }
        }
    }
    return success;
}

bool M2MResourceBase::set_value_raw(uint8_t *value,
                                const uint32_t value_length)

{
    tr_debug("M2MResourceBase::set_value_raw()");
    bool success = false;
    if( value != NULL && value_length > 0 ) {
        success = true;
        value_set_callback callback = (value_set_callback)M2MCallbackStorage::get_callback(*this, M2MCallbackAssociation::M2MResourceBaseValueSetCallback);
        if (callback) {
            (*callback)((const M2MResourceBase*)this, value, value_length);
        }
        else {
            update_value(value, value_length);
        }
    }
    return success;
}

void M2MResourceBase::update_value(uint8_t *value, const uint32_t value_length)
{
    bool changed = has_value_changed(value,value_length);
    sn_nsdl_dynamic_resource_parameters_s* res = get_nsdl_resource();
    free(res->resource);
    res->resource = value;
    res->resource_len = value_length;
    if (changed) {
        report_value_change();
    }
}

void M2MResourceBase::report()
{
    M2MBase::Observation observation_level = M2MBase::observation_level();
    tr_debug("M2MResourceBase::report() - level %d", observation_level);

    // We must combine the parent object/objectinstance/resource observation information
    // when determining if there is observation set or not.
    M2MObjectInstance& object_instance = get_parent_resource().get_parent_object_instance();
    int parent_observation_level = (int)object_instance.observation_level();

    parent_observation_level |= (int)object_instance.get_parent_object().observation_level();
    parent_observation_level |= (int)get_parent_resource().observation_level();
    parent_observation_level |= (int)observation_level;

    tr_debug("M2MResourceBase::report() - combined level %d", parent_observation_level);

    if((M2MBase::O_Attribute & parent_observation_level) == M2MBase::O_Attribute ||
       (M2MBase::OI_Attribute & parent_observation_level) == M2MBase::OI_Attribute) {
        tr_debug("M2MResourceBase::report() -- object/instance level");
        M2MObjectInstance& object_instance = get_parent_resource().get_parent_object_instance();
        object_instance.notification_update((M2MBase::Observation)parent_observation_level);
    }

    if(M2MBase::Dynamic == mode() &&
       (M2MBase::R_Attribute & parent_observation_level) == M2MBase::R_Attribute) {
        tr_debug("M2MResourceBase::report() - resource level");

        if (((resource_instance_type() != M2MResourceBase::STRING) &&
             (resource_instance_type() != M2MResourceBase::OPAQUE)) &&
             (observation_level != M2MBase::None)) {
            M2MReportHandler *report_handler = M2MBase::report_handler();
            if (report_handler && is_observable()) {
                const float float_value = get_value_float();
                report_handler->set_value(float_value);
            }
        }
        else {
            if (base_type() == M2MBase::ResourceInstance) {
                const M2MResource& parent_resource = get_parent_resource();
                M2MReportHandler *report_handler = parent_resource.report_handler();
                if(report_handler && parent_resource.is_observable()) {
                    report_handler->set_notification_trigger(parent_resource.get_parent_object_instance().instance_id());
                }
            }
        }
    } else if(M2MBase::Static == mode()) {
        M2MObservationHandler *obs_handler = observation_handler();
        if(obs_handler) {
            obs_handler->value_updated(this);
        }
    } else {
        if (is_observable()) {
            tr_warn("M2MResourceBase::report() - resource %s is observable but not yet subscribed!", uri_path());
        }
        tr_debug("M2MResourceBase::report() - mode = %d, is_observable = %d", mode(), is_observable());
    }
}

bool M2MResourceBase::has_value_changed(const uint8_t* value, const uint32_t value_len)
{
    bool changed = false;
    sn_nsdl_dynamic_resource_parameters_s* res = get_nsdl_resource();

    if(value_len != res->resource_len) {
        changed = true;
    } else if(value && !res->resource) {
        changed = true;
    } else if(res->resource && !value) {
        changed = true;
    } else {
        if (res->resource) {
            if (memcmp(value, res->resource, res->resource_len) != 0) {
                changed = true;
            }
        }
    }
    return changed;
}

void M2MResourceBase::report_value_change()
{
    if (resource_instance_type() == M2MResourceBase::STRING ||
        resource_instance_type() == M2MResourceBase::OPAQUE) {
        M2MReportHandler *report_handler = M2MBase::report_handler();
        if(report_handler && is_under_observation()) {
            report_handler->set_notification_trigger();
        }
    }
    report();
}

void M2MResourceBase::execute(void *arguments)
{
    // XXX: this line is expected by seven testcases and until this code hits master branch
    // the testcases can not be modified and we need to print the false information too.
    tr_debug("M2MResourceBase::execute");

    execute_callback* callback = (execute_callback*)M2MCallbackStorage::get_callback(*this, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback);

    if (callback) {
        (*callback)(arguments);
    }

    execute_callback_2 callback2 = (execute_callback_2)M2MCallbackStorage::get_callback(*this, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback2);
    if (callback2) {
        (*callback2)(arguments);
    }
}

int M2MResourceBase::read_resource_value(const M2MResourceBase &resource, void *buffer, size_t *buffer_len)
{
    tr_debug("M2MResourceBase::read_resource_value");

    M2MCallbackAssociation* item = M2MCallbackStorage::get_association_item(resource,
                                                                            M2MCallbackAssociation::M2MResourceBaseValueReadCallback);

    if (item) {
        read_resource_value_callback callback = (read_resource_value_callback)item->_callback;
        assert(callback);
        return (*callback)(resource, buffer, buffer_len, item->_client_args);
    } else {
        if (value_length() > *buffer_len) {
            return -1;
        } else {
            memcpy(buffer, value(), value_length());
            *buffer_len = value_length();
            return 0;
        }
    }
}

bool M2MResourceBase::write_resource_value(const M2MResourceBase &resource, const uint8_t *buffer, const size_t buffer_size)
{
    tr_debug("M2MResourceBase::write_resource_value");
    M2MCallbackAssociation* item = M2MCallbackStorage::get_association_item(resource,
                                                                            M2MCallbackAssociation::M2MResourceBaseValueWriteCallback);
    if (item) {
        write_resource_value_callback callback = (write_resource_value_callback)item->_callback;
        if (callback) {
            return (*callback)(resource, buffer, buffer_size, item->_client_args);
        }
    }

    return false;
}

void M2MResourceBase::get_value(uint8_t *&value, uint32_t &value_length)
{
    value_length = 0;
    if(value) {
        free(value);
        value = NULL;
    }

    sn_nsdl_dynamic_resource_parameters_s* res = get_nsdl_resource();
    if(res->resource && res->resource_len > 0) {
        value = alloc_string_copy(res->resource, res->resource_len);
        if(value) {
            value_length = res->resource_len;
        }
    }
}

int64_t M2MResourceBase::get_value_int() const
{
    int64_t value_int = 0;

    const char *value_string = (char *)value();
    const uint32_t value_len = value_length();

    if ((value_string) && (value_len <= REGISTRY_INT64_STRING_MAX_LEN)) {

        // -9223372036854775808 - +9223372036854775807
        // max length of int64_t string is 20 bytes + nil
        // The +1 here is there in case the string was already zero terminated.
        char temp[REGISTRY_INT64_STRING_MAX_LEN + 1];

        memcpy(temp, value_string, value_len);
        temp[value_len] = 0;

        value_int = atoll(temp);
    }
    return value_int;
}

String M2MResourceBase::get_value_string() const
{
    // XXX: do a better constructor to avoid pointless malloc
    String value;
    if (get_nsdl_resource()->resource) {
        value.append_raw((char*)get_nsdl_resource()->resource, get_nsdl_resource()->resource_len);
    }
    return value;
}

float M2MResourceBase::get_value_float() const
{
    float value_float = 0;

    const char *value_string = (char *)value();
    const uint32_t value_len = value_length();

    if ((value_string) && (value_len <= REGISTRY_FLOAT_STRING_MAX_LEN)) {

        // (space needed for -3.402823 × 10^38) + (magic decimal 6 digits added as no precision is added to "%f") + trailing zero
        // The +1 here is there in case the string was already zero terminated.
        char temp[REGISTRY_FLOAT_STRING_MAX_LEN + 1];

        memcpy(temp, value_string, value_len);
        temp[value_len] = 0;

        value_float = atof(temp);
    }

    return value_float;
}

uint8_t* M2MResourceBase::value() const
{
    return get_nsdl_resource()->resource;
}

uint32_t M2MResourceBase::value_length() const
{
    return get_nsdl_resource()->resource_len;
}

void M2MResourceBase::set_value_set_callback(value_set_callback callback)
{
    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceBaseValueSetCallback);
    M2MCallbackStorage::add_callback(*this, (void*)callback, M2MCallbackAssociation::M2MResourceBaseValueSetCallback);
}

sn_coap_hdr_s* M2MResourceBase::handle_get_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler)
{
    tr_info("M2MResourceBase::handle_get_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
    sn_coap_hdr_s *coap_response = sn_nsdl_build_response(nsdl,
                                                          received_coap_header,
                                                          msg_code);
    if (received_coap_header) {
        // process the GET if we have registered a callback for it
        if ((operation() & SN_GRS_GET_ALLOWED) != 0) {
            if (coap_response) {
                bool content_type_present = false;
                if (received_coap_header->options_list_ptr &&
                    received_coap_header->options_list_ptr->accept != COAP_CT_NONE) {
                    content_type_present = true;
                    coap_response->content_format = received_coap_header->options_list_ptr->accept;
                    set_coap_content_type(coap_response->content_format);
                }
                if (!content_type_present) {
                    if (resource_instance_type() == M2MResourceInstance::OPAQUE) {
                        coap_response->content_format = sn_coap_content_format_e(COAP_CONTENT_OMA_OPAQUE_TYPE);
                    } else {
                        coap_response->content_format = sn_coap_content_format_e(COAP_CONTENT_OMA_PLAIN_TEXT_TYPE);
                    }
                }
                // fill in the CoAP response payload
                coap_response->payload_ptr = NULL;
                uint32_t payload_len = 0;
#ifndef DISABLE_BLOCK_MESSAGE
                //If handler exists it means that resource value is stored in application side
                if (block_message() && block_message()->is_block_message()) {
                    outgoing_block_message_callback* outgoing_block_message_cb = (outgoing_block_message_callback*)M2MCallbackStorage::get_callback(*this,
                                                                                    M2MCallbackAssociation::M2MResourceInstanceOutgoingBlockMessageCallback);
                    if (outgoing_block_message_cb) {
                        String name = "";
                        if (received_coap_header->uri_path_ptr != NULL &&
                            received_coap_header->uri_path_len > 0) {
                            name.append_raw((char *)received_coap_header->uri_path_ptr, received_coap_header->uri_path_len);
                        }
                        (*outgoing_block_message_cb)(name, coap_response->payload_ptr, payload_len);
                    }
                } else {
#endif
                    if (coap_response->content_format == COAP_CONTENT_OMA_TLV_TYPE ||
                        coap_response->content_format == COAP_CONTENT_OMA_TLV_TYPE_OLD) {
                        coap_response->payload_ptr = M2MTLVSerializer::serialize(&get_parent_resource(), payload_len);
                    } else {
                        get_value(coap_response->payload_ptr,payload_len);
                    }
#ifndef DISABLE_BLOCK_MESSAGE
                }
#endif
                tr_debug("M2MResourceBase::handle_get_request() - Request Content-type: %d", coap_response->content_format);
                coap_response->payload_len = payload_len;
                coap_response->options_list_ptr = sn_nsdl_alloc_options_list(nsdl, coap_response);
                if (coap_response->options_list_ptr) {
                    coap_response->options_list_ptr->max_age = max_age();
                }

                if (received_coap_header->options_list_ptr) {
                    if (received_coap_header->options_list_ptr->observe != -1) {
                        if (is_observable()) {
                            uint32_t number = 0;
                            uint8_t observe_option = 0;
                            observe_option = received_coap_header->options_list_ptr->observe;

                            if (START_OBSERVATION == observe_option) {
                                // If the observe length is 0 means register for observation.
                                if (received_coap_header->options_list_ptr->observe != -1) {
                                    number = received_coap_header->options_list_ptr->observe;
                                }

                                // If the observe value is 0 means register for observation.
                                if (number == 0) {
                                    tr_info("M2MResourceBase::handle_get_request - put resource under observation");
                                    set_under_observation(true,observation_handler);
                                    send_notification_delivery_status(*this, NOTIFICATION_STATUS_SUBSCRIBED);
                                    M2MBase::add_observation_level(M2MBase::R_Attribute);
                                    if (coap_response->options_list_ptr) {
                                        coap_response->options_list_ptr->observe = observation_number();
                                    }
                                }

                                if (received_coap_header->token_ptr) {
                                    set_observation_token(received_coap_header->token_ptr,
                                                          received_coap_header->token_len);
                                }

                            } else if (STOP_OBSERVATION == observe_option) {
                                tr_info("M2MResourceBase::handle_get_request - stops observation");
                                set_under_observation(false,NULL);
                                M2MBase::remove_observation_level(M2MBase::R_Attribute);
                                send_notification_delivery_status(*this, NOTIFICATION_STATUS_UNSUBSCRIBED);
                            }
                        } else {
                            msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
                        }
                    }
                }
            }
        } else {
            tr_error("M2MResourceBase::handle_get_request - Return COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED");
            // Operation is not allowed.
            msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
        }
    } else {
        msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    }

    if (coap_response) {
        coap_response->msg_code = msg_code;
    }

    return coap_response;
}

sn_coap_hdr_s* M2MResourceBase::handle_put_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated)
{
    tr_info("M2MResourceBase::handle_put_request()");

    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_CHANGED; // 2.04
    sn_coap_hdr_s *coap_response = sn_nsdl_build_response(nsdl,
                                                           received_coap_header,
                                                           msg_code);
    // process the PUT if we have registered a callback for it
    if(received_coap_header && coap_response) {
        uint16_t coap_content_type = 0;
        if(received_coap_header->content_format != COAP_CT_NONE) {
            coap_content_type = received_coap_header->content_format;
        }
        if(received_coap_header->options_list_ptr &&
           received_coap_header->options_list_ptr->uri_query_ptr) {
            char *query = (char*)alloc_string_copy(received_coap_header->options_list_ptr->uri_query_ptr,
                                                    received_coap_header->options_list_ptr->uri_query_len);
            if (query){
                tr_info("M2MResourceBase::handle_put_request() - query %s", query);

                // if anything was updated, re-initialize the stored notification attributes
                if (!handle_observation_attribute(query)){
                    tr_error("M2MResourceBase::handle_put_request() - Invalid query");
                    msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
                }
                free(query);
            }
            else {
                // memory allocation for query fails
                tr_error("M2MResourceBase::handle_put_request() - Out of memory !!!");
                msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR; // 4.00
            }
        } else if ((operation() & SN_GRS_PUT_ALLOWED) != 0) {
            tr_debug("M2MResourceBase::handle_put_request() - Request Content-type: %d", coap_content_type);

            if(COAP_CONTENT_OMA_TLV_TYPE == coap_content_type ||
               COAP_CONTENT_OMA_TLV_TYPE_OLD == coap_content_type) {
                msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
            } else {
#ifndef DISABLE_BLOCK_MESSAGE
                if (block_message()) {
                    block_message()->set_message_info(received_coap_header);
                    if (block_message()->is_block_message()) {
                        incoming_block_message_callback* incoming_block_message_cb = (incoming_block_message_callback*)M2MCallbackStorage::get_callback(*this,
                                                                                M2MCallbackAssociation::M2MResourceInstanceIncomingBlockMessageCallback);
                        if (incoming_block_message_cb) {
                            (*incoming_block_message_cb)(_block_message_data);
                        }
                        if (block_message()->is_last_block()) {
                            block_message()->clear_values();
                            coap_response->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED;
                        } else {
                            coap_response->coap_status = COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING;
                        }
                        if (block_message()->error_code() != M2MBlockMessage::ErrorNone) {
                            block_message()->clear_values();
                        }
                    }
                }
#endif
                // Firmware object uri path is limited to be max 255 bytes
                if ((strcmp(uri_path(), FIRMAWARE_PACKAGE_URI_PATH) == 0) &&
                    received_coap_header->payload_len > 255) {
                    msg_code = COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE;
                } else if ((strcmp(uri_path(), SERVER_LIFETIME_PATH) == 0)) {
                    // Check that lifetime can't go below 60s
                    char *query = (char*)alloc_string_copy(received_coap_header->payload_ptr,
                                                           received_coap_header->payload_len);

                    if (query) {
                        int32_t lifetime = atol(query);
                        if (lifetime < MINIMUM_REGISTRATION_TIME) {
                            tr_error("M2MResourceBase::handle_put_request() - lifetime value % " PRId32 " not acceptable", lifetime);
                            msg_code = COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE;
                        }
                        free(query);
                    }
                    else {
                        // memory allocation for query fails
                        tr_error("M2MResourceBase::handle_put_request() - Out of memory !!!");
                        msg_code = COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR;
                    }
                }

                // Do not update resource value in error case.
                if ((received_coap_header->payload_ptr) && (msg_code == COAP_MSG_CODE_RESPONSE_CHANGED)) {
                    execute_value_updated = true;
                }
            }
        } else {
            // Operation is not allowed.
            tr_error("M2MResourceBase::handle_put_request() - COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED");
            msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
        }
    } else {
        msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    }
    if(coap_response) {
        coap_response->msg_code = msg_code;
    }

    return coap_response;
}


#ifndef DISABLE_BLOCK_MESSAGE

M2MBlockMessage* M2MResourceBase::block_message() const
{
    return _block_message_data;
}

bool M2MResourceBase::set_incoming_block_message_callback(incoming_block_message_callback callback)
{
    incoming_block_message_callback* old_callback = (incoming_block_message_callback*)M2MCallbackStorage::remove_callback(*this,
                                                        M2MCallbackAssociation::M2MResourceInstanceIncomingBlockMessageCallback);
    delete old_callback;

    // copy the callback object. This will change on next version to be a direct pointer to a interface class,
    // this FPn<> is just too heavy for this usage.
    incoming_block_message_callback* new_callback = new incoming_block_message_callback(callback);

    delete _block_message_data;
    _block_message_data = NULL;
    _block_message_data = new M2MBlockMessage();

    return M2MCallbackStorage::add_callback(*this,
                                            new_callback,
                                            M2MCallbackAssociation::M2MResourceInstanceIncomingBlockMessageCallback);
}

bool M2MResourceBase::set_outgoing_block_message_callback(outgoing_block_message_callback callback)
{
    outgoing_block_message_callback *old_callback = (outgoing_block_message_callback*)M2MCallbackStorage::remove_callback(*this,
                                                         M2MCallbackAssociation::M2MResourceInstanceOutgoingBlockMessageCallback);
    delete old_callback;

    outgoing_block_message_callback *new_callback = new outgoing_block_message_callback(callback);
    return M2MCallbackStorage::add_callback(*this,
                                            new_callback,
                                            M2MCallbackAssociation::M2MResourceInstanceOutgoingBlockMessageCallback);
}
#endif

bool M2MResourceBase::set_notification_sent_callback(notification_sent_callback callback)
{
    notification_sent_callback *old_callback = (notification_sent_callback*)M2MCallbackStorage::remove_callback(*this,
                                                         M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback);
    delete old_callback;

    notification_sent_callback *new_callback = new notification_sent_callback(callback);
    return M2MCallbackStorage::add_callback(*this,
                                            new_callback,
                                            M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback);
}

bool M2MResourceBase::set_notification_sent_callback(notification_sent_callback_2 callback)
{
    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback2);

    return M2MCallbackStorage::add_callback(*this,
                                            (void*)callback,
                                            M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback2);
}

bool M2MResourceBase::set_notification_status_callback(notification_status_callback callback)
{
    notification_status_callback *old_callback = (notification_status_callback*)M2MCallbackStorage::remove_callback(*this,
                                                         M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback);
    delete old_callback;

    notification_status_callback *new_callback = new notification_status_callback(callback);
    return M2MCallbackStorage::add_callback(*this,
                                            new_callback,
                                            M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback);
}

bool M2MResourceBase::set_notification_status_callback(notification_status_callback_2 callback)
{
    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback2);

    return M2MCallbackStorage::add_callback(*this,
                                            (void*)callback,
                                            M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback2);
}

void M2MResourceBase::notification_sent()
{
    // Now we will call both callbacks, if they are set. This is different from original behavior.
    notification_sent_callback* callback =
            (notification_sent_callback*)M2MCallbackStorage::get_callback(*this,
                                                                          M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback);
    if (callback) {
        (*callback)();
    }

    notification_sent_callback_2 callback2 =
            (notification_sent_callback_2)M2MCallbackStorage::get_callback(*this,
                                                                           M2MCallbackAssociation::M2MResourceInstanceNotificationSentCallback2);
    if (callback2) {
        (*callback2)();
    }
}

void M2MResourceBase::notification_status(const uint16_t msg_id, const NotificationStatus status)
{
    if (_notification_status != status) {
        _notification_status = status;
        // Now we will call both callbacks, if they are set. This is different from original behavior.
        notification_status_callback* callback =
                (notification_status_callback*)M2MCallbackStorage::get_callback(*this,
                                                                              M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback);
        if (callback) {
            (*callback)(msg_id, status);
        }

        notification_status_callback_2 callback2 =
                (notification_status_callback_2)M2MCallbackStorage::get_callback(*this,
                                                                               M2MCallbackAssociation::M2MResourceInstanceNotificationStatusCallback2);
        if (callback2) {
            (*callback2)(msg_id, status);
        }
    }
}

M2MResourceBase::NotificationStatus M2MResourceBase::notification_status() const
{
    return _notification_status;
}

void M2MResourceBase::clear_notification_status()
{
    _notification_status = M2MResourceBase::INIT;
}

void M2MResourceBase::publish_value_in_registration_msg(bool publish_value)
{
    M2MBase::lwm2m_parameters_s* param = M2MBase::get_lwm2m_parameters();
    assert(param->data_type == M2MBase::INTEGER ||
           param->data_type == M2MBase::STRING ||
           param->data_type == M2MBase::FLOAT ||
           param->data_type == M2MBase::BOOLEAN ||
           param->data_type == M2MBase::OPAQUE);

    uint8_t pub_value = publish_value;

    if (param->data_type == M2MBase::OPAQUE) {
        pub_value = 2;
    } else {
        pub_value = (uint8_t)publish_value;
    }
    param->dynamic_resource_params->publish_value = pub_value;
}
