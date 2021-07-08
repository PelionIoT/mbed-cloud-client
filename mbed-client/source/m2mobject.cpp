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

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mconstants.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mtlvdeserializer.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2mstringbuffer.h"
#include "include/m2mcallbackstorage.h"
#include "include/m2mdiscover.h"

#include <stdlib.h>

#define BUFFER_SIZE 10
#define TRACE_GROUP "mClt"

M2MObject::M2MObject(const String &object_name, char *path, bool external_blockwise_store)
    : M2MBase(object_name,
              M2MBase::Dynamic,
#ifndef DISABLE_RESOURCE_TYPE
              "",
#endif
              path,
              external_blockwise_store,
              false),
      _observation_handler(NULL)
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    , _endpoint(NULL)
#endif
{
    M2MBase::set_base_type(M2MBase::Object);
    M2MBase::set_operation(M2MBase::GET_ALLOWED);
    if (M2MBase::name_id() != -1) {
        M2MBase::set_coap_content_type(COAP_CONTENT_OMA_TLV_TYPE);
    }
}

M2MObject::M2MObject(const M2MBase::lwm2m_parameters_s *static_res)
    : M2MBase(static_res),
      _observation_handler(NULL)
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    , _endpoint(NULL)
#endif
{
    M2MBase::set_operation(M2MBase::GET_ALLOWED);
    if (M2MBase::name_id() != -1) {
        M2MBase::set_coap_content_type(COAP_CONTENT_OMA_TLV_TYPE);
    }
}

M2MObject::~M2MObject()
{
    if (!_instance_list.empty()) {

        M2MObjectInstanceList::const_iterator it;
        it = _instance_list.begin();
        M2MObjectInstance *obj = NULL;
        uint16_t index = 0;
        for (; it != _instance_list.end(); it++, index++) {
            //Free allocated memory for object instances.
            obj = *it;
            delete obj;
        }

        _instance_list.clear();
    }

    free_resources();
}

M2MObjectInstance *M2MObject::create_object_instance(uint16_t instance_id)
{
    tr_debug("M2MObject::create_object_instance - id: %d", instance_id);
    M2MObjectInstance *instance = NULL;
    if (!object_instance(instance_id)) {
        char *path = create_path(*this, instance_id);
        if (path) {
            // Note: the object instance's name contains actually object's name.
            instance = new M2MObjectInstance(*this, "", path);
            if (instance) {
                instance->add_observation_level(observation_level());
                instance->set_instance_id(instance_id);
                if (M2MBase::name_id() != -1) {
                    instance->set_coap_content_type(COAP_CONTENT_OMA_TLV_TYPE);
                }
                _instance_list.push_back(instance);
                set_changed();
            }
        }
    }
    return instance;
}


M2MObjectInstance *M2MObject::create_object_instance(const lwm2m_parameters_s *s)
{
    tr_debug("M2MObject::create_object_instance - id: %d", s->identifier.instance_id);
    M2MObjectInstance *instance = NULL;
    if (!object_instance(s->identifier.instance_id)) {

        instance = new M2MObjectInstance(*this, s);
        if (instance) {
            instance->add_observation_level(observation_level());
            //instance->set_instance_id(instance_id);
            //if(M2MBase::name_id() != -1) {
            //  instance->set_coap_content_type(COAP_CONTENT_OMA_TLV_TYPE);
            //}
            _instance_list.push_back(instance);
            set_changed();
        }
    }
    return instance;
}

bool M2MObject::remove_object_instance(uint16_t inst_id)
{
    tr_debug("M2MObject::remove_object_instance(inst_id %d)", inst_id);
    bool success = false;
    if (!_instance_list.empty()) {
        M2MObjectInstance *obj = NULL;
        M2MObjectInstanceList::const_iterator it;
        it = _instance_list.begin();
        int pos = 0;
        for (; it != _instance_list.end(); it++, pos++) {
            if ((*it)->instance_id() == inst_id) {
                // Instance found and deleted.
                obj = *it;

                _instance_list.erase(pos);
                delete obj;
                success = true;
                set_changed();
                break;
            }
        }
    }
    return success;
}

M2MObjectInstance *M2MObject::object_instance(uint16_t inst_id) const
{
    tr_debug("M2MObject::object_instance(inst_id %d)", inst_id);
    M2MObjectInstance *obj = NULL;
    if (!_instance_list.empty()) {
        M2MObjectInstanceList::const_iterator it;
        it = _instance_list.begin();
        for (; it != _instance_list.end(); it++) {
            if ((*it)->instance_id() == inst_id) {
                // Instance found.
                obj = *it;
                break;
            }
        }
    }
    return obj;
}

const M2MObjectInstanceList &M2MObject::instances() const
{
    return _instance_list;
}

uint16_t M2MObject::instance_count() const
{
    return (uint16_t)_instance_list.size();
}

M2MObservationHandler *M2MObject::observation_handler() const
{
    // XXX: need to check the flag too
    return _observation_handler;
}

void M2MObject::set_observation_handler(M2MObservationHandler *handler)
{
    tr_debug("M2MObject::set_observation_handler - handler: 0x%p", (void *)handler);
    _observation_handler = handler;
}

void M2MObject::add_observation_level(M2MBase::Observation observation_level)
{
    M2MBase::add_observation_level(observation_level);
    if (!_instance_list.empty()) {
        M2MObjectInstanceList::const_iterator it;
        it = _instance_list.begin();
        for (; it != _instance_list.end(); it++) {
            (*it)->add_observation_level(observation_level);
        }
    }
}

void M2MObject::remove_observation_level(M2MBase::Observation observation_level)
{
    M2MBase::remove_observation_level(observation_level);
    if (!_instance_list.empty()) {
        M2MObjectInstanceList::const_iterator it;
        it = _instance_list.begin();
        for (; it != _instance_list.end(); it++) {
            (*it)->remove_observation_level(observation_level);
        }
    }
}

sn_coap_hdr_s *M2MObject::handle_get_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler *observation_handler)
{
    tr_info("M2MObject::handle_get_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
    sn_coap_hdr_s *coap_response = sn_nsdl_build_response(nsdl,
                                                          received_coap_header,
                                                          msg_code);
    uint8_t *data = NULL;
    uint32_t data_length = 0;
    if (received_coap_header) {
        // process the GET if we have registered a callback for it
        if ((operation() & M2MBase::GET_ALLOWED) != 0) {
            if (coap_response) {
                bool content_type_present = false;
                bool is_content_type_supported = true;

                if (received_coap_header->options_list_ptr &&
                        received_coap_header->options_list_ptr->accept != COAP_CT_NONE) {
                    content_type_present = true;
                    coap_response->content_format = received_coap_header->options_list_ptr->accept;

                }

                // Check if preferred content type is supported
                if (content_type_present) {
                    if ((coap_response->content_format != COAP_CONTENT_OMA_TLV_TYPE_OLD) &&
                            (coap_response->content_format != COAP_CONTENT_OMA_TLV_TYPE)
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY) && (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY == 1)
                            && (coap_response->content_format != COAP_CONTENT_OMA_LINK_FORMAT_TYPE)
#endif
                            ) {
                        is_content_type_supported = false;
                    }
                }

                if (is_content_type_supported) {
                    if (!content_type_present &&
                            (M2MBase::coap_content_type() == COAP_CONTENT_OMA_TLV_TYPE ||
                             M2MBase::coap_content_type() == COAP_CONTENT_OMA_TLV_TYPE_OLD)) {
                        coap_response->content_format = sn_coap_content_format_e(M2MBase::coap_content_type());
                    }

                    // fill in the CoAP response payload
                    if (COAP_CONTENT_OMA_TLV_TYPE == coap_response->content_format ||
                            COAP_CONTENT_OMA_TLV_TYPE_OLD == coap_response->content_format) {
                        set_coap_content_type(coap_response->content_format);
                        data = M2MTLVSerializer::serialize(_instance_list, data_length);
                    }
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY) && (MBED_CONF_MBED_CLIENT_ENABLE_DISCOVERY == 1)
                    else if (coap_response->content_format == COAP_CONTENT_OMA_LINK_FORMAT_TYPE) {
                        // Discover
                        data_length = 0;
                        data = M2MDiscover::create_object_payload(this, data_length);
                        if (!data) {
                            data_length = 0;
                            tr_error("M2MObject::handle_get_request() - Discover data allocation failed!");
                        }
                    }
#endif
                    coap_response->payload_len = data_length;
                    coap_response->payload_ptr = data;
                    if (data) {
                        coap_response->options_list_ptr = sn_nsdl_alloc_options_list(nsdl, coap_response);
                        if (coap_response->options_list_ptr) {
                            coap_response->options_list_ptr->max_age = max_age();
                        }
                        if (received_coap_header->options_list_ptr) {
                            if (received_coap_header->options_list_ptr->observe != -1) {
                                handle_observation(nsdl, *received_coap_header, *coap_response, observation_handler, msg_code);
                            }
                        }
                    } else {
                        msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT; // Content format not supported
                    }
                } else {
                    tr_error("M2MObject::handle_get_request() - Content-Type %d not supported", coap_response->content_format);
                    msg_code = COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE;
                }
            }
        } else {
            tr_error("M2MResource::handle_get_request - Return COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED");
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

sn_coap_hdr_s *M2MObject::handle_put_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler */*observation_handler*/,
                                             bool &/*execute_value_updated*/)
{
    tr_info("M2MObject::handle_put_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_CHANGED; // 2.04
    sn_coap_hdr_s *coap_response = sn_nsdl_build_response(nsdl,
                                                          received_coap_header,
                                                          msg_code);
    if (received_coap_header) {
        if (received_coap_header->content_format != COAP_CT_NONE) {
            set_coap_content_type(received_coap_header->content_format);
        }
        if (received_coap_header->options_list_ptr &&
                received_coap_header->options_list_ptr->uri_query_ptr) {
            char *query = (char *)alloc_string_copy(received_coap_header->options_list_ptr->uri_query_ptr,
                                                    received_coap_header->options_list_ptr->uri_query_len);

            if (query) {
                tr_info("M2MObject::handle_put_request() - query %s", query);
                // if anything was updated, re-initialize the stored notification attributes
#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
                if (!handle_observation_attribute(query)) {
                    tr_debug("M2MObject::handle_put_request() - Invalid query");
                    msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST; // 4.00
                }
#else
                msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST; // 4.00
#endif
                free(query);
            }
        } else {
            tr_error("M2MObject::handle_put_request() - COAP_MSG_CODE_RESPONSE_BAD_REQUEST - Empty URI_QUERY");
            msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }
    } else {
        msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    }
    if (coap_response) {
        coap_response->msg_code = msg_code;
    }
    return coap_response;
}


sn_coap_hdr_s *M2MObject::handle_post_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated,
                                              sn_nsdl_addr_s *)
{
    tr_info("M2MObject::handle_post_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_CHANGED; // 2.04
    // process the POST if we have registered a callback for it
    sn_coap_hdr_s *coap_response = sn_nsdl_build_response(nsdl,
                                                          received_coap_header,
                                                          msg_code);

    if (received_coap_header) {
        if ((operation() & M2MBase::POST_ALLOWED) != 0) {
            if (received_coap_header->content_format != COAP_CT_NONE) {
                set_coap_content_type(received_coap_header->content_format);
            }
            if (received_coap_header->payload_ptr) {
                tr_debug("M2MObject::handle_post_request() - Update Object with new values");
                uint16_t coap_content_type = 0;
                bool content_type_present = false;
                if (received_coap_header->content_format != COAP_CT_NONE) {
                    content_type_present = true;
                    if (coap_response) {
                        coap_content_type = received_coap_header->content_format;
                    }
                } // if(received_coap_header->content_format)
                if (!content_type_present &&
                        (M2MBase::coap_content_type() == COAP_CONTENT_OMA_TLV_TYPE ||
                         M2MBase::coap_content_type() == COAP_CONTENT_OMA_TLV_TYPE_OLD)) {
                    coap_content_type = M2MBase::coap_content_type();
                }

                tr_debug("M2MObject::handle_post_request() - Request Content-type: %d", coap_content_type);

                if (COAP_CONTENT_OMA_TLV_TYPE == coap_content_type ||
                        COAP_CONTENT_OMA_TLV_TYPE_OLD == coap_content_type) {
                    set_coap_content_type(coap_content_type);
                    uint32_t instance_id = 0;
                    // Check next free instance id
                    for (instance_id = 0; instance_id <= UINT16_MAX; instance_id++) {
                        if (NULL == object_instance(instance_id)) {
                            break;
                        }
                        if (instance_id == UINT16_MAX) {
                            msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
                            break;
                        }
                    }


                    bool is_obj_instance = false;
                    is_obj_instance = M2MTLVDeserializer::is_object_instance(received_coap_header->payload_ptr);
                    if (is_obj_instance) {
                        if (M2MTLVDeserializer::instance_id(received_coap_header->payload_ptr) >= UINT16_MAX) {
                            tr_error("M2MObject::handle_post_request() - id must be less than 65535");
                            msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
                        }
                    }

                    if (COAP_MSG_CODE_RESPONSE_CHANGED == msg_code) {
                        bool obj_instance_exists = false;
                        if (is_obj_instance) {
                            instance_id = M2MTLVDeserializer::instance_id(received_coap_header->payload_ptr);
                            tr_debug("M2MObject::handle_post_request() - instance id in TLV: %" PRIu32, instance_id);
                            // Check if instance id already exists
                            if (object_instance(instance_id)) {
                                obj_instance_exists = true;
                            }
                        }
                        if (!obj_instance_exists && coap_response) {
                            M2MObjectInstance *obj_instance = create_object_instance(instance_id);
                            if (obj_instance) {
                                obj_instance->set_operation(M2MBase::GET_PUT_ALLOWED);
                            }

                            M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
                            if (is_obj_instance) {
                                tr_debug("M2MObject::handle_post_request() - TLV data contains ObjectInstance");
                                error = M2MTLVDeserializer::deserialise_object_instances(received_coap_header->payload_ptr,
                                                                                         received_coap_header->payload_len,
                                                                                         *this,
                                                                                         M2MTLVDeserializer::Post);
                            } else if (obj_instance &&
                                       (M2MTLVDeserializer::is_resource(received_coap_header->payload_ptr) ||
                                        M2MTLVDeserializer::is_multiple_resource(received_coap_header->payload_ptr))) {
                                tr_debug("M2MObject::handle_post_request() - TLV data contains Resources");
                                error = M2MTLVDeserializer::deserialize_resources(received_coap_header->payload_ptr,
                                                                                  received_coap_header->payload_len,
                                                                                  *obj_instance,
                                                                                  M2MTLVDeserializer::Post);
                            } else {
                                error = M2MTLVDeserializer::NotValid;
                            }
                            switch (error) {
                                case M2MTLVDeserializer::None:
                                    if (observation_handler) {
                                        execute_value_updated = true;
                                    }
                                    coap_response->options_list_ptr = sn_nsdl_alloc_options_list(nsdl, coap_response);

                                    if (coap_response->options_list_ptr) {

                                        StringBuffer<MAX_OBJECT_PATH_NAME> obj_name;

                                        if (obj_name.ensure_space(M2MBase::resource_name_length() + (1 + 5 + 1))) {
                                            obj_name.append(M2MBase::name());
                                            obj_name.append('/');
                                            obj_name.append_int(instance_id);

                                            coap_response->options_list_ptr->location_path_len = obj_name.get_size();
                                            coap_response->options_list_ptr->location_path_ptr =
                                                alloc_copy((uint8_t *)obj_name.c_str(), obj_name.get_size());
                                            // todo: else return error
                                        }
                                    }
                                    // todo: else return error
                                    msg_code = COAP_MSG_CODE_RESPONSE_CREATED;
                                    break;
                                case M2MTLVDeserializer::NotAllowed:
                                    msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
                                    break;
                                case M2MTLVDeserializer::NotValid:
                                    msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
                                    break;
                                case M2MTLVDeserializer::NotFound:
                                    msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
                                    break;
                                case M2MTLVDeserializer::OutOfMemory:
                                    msg_code = COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE;
                                    break;
                                case M2MTLVDeserializer::NotAccepted:
                                    msg_code = COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE;
                                    break;
                            }

                        } else {
                            tr_error("M2MObject::handle_post_request() - COAP_MSG_CODE_RESPONSE_BAD_REQUEST");
                            msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
                        }
                    }
                } else {
                    msg_code = COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
                } // if(COAP_CONTENT_OMA_TLV_TYPE == coap_content_type)
            } else {
                tr_error("M2MObject::handle_post_request - COAP_MSG_CODE_RESPONSE_BAD_REQUEST - Missing Payload");
                msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST; //
            }
        } else { // if ((object->operation() & SN_GRS_POST_ALLOWED) != 0)
            tr_error("M2MObject::handle_post_request - COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED");
            msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED; // 4.05
        }
    } else { //if(received_coap_header)
        tr_error("M2MObject::handle_post_request - COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED");
        msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED; // 4.05
    }

    if (coap_response) {
        coap_response->msg_code = msg_code;
    }
    return coap_response;
}

void M2MObject::notification_update(uint16_t obj_instance_id)
{
    tr_debug("M2MObject::notification_update - id: %d", obj_instance_id);
    M2MReportHandler *report_handler = M2MBase::report_handler();
    if (report_handler && is_under_observation()) {
        report_handler->set_notification_trigger(obj_instance_id);
    }
}

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
void M2MObject::set_endpoint(M2MEndpoint *endpoint)
{
    _endpoint = endpoint;
}

M2MEndpoint *M2MObject::get_endpoint() const
{
    return _endpoint;
}
#endif

M2MBase *M2MObject::get_parent() const
{
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    return (M2MBase *) get_endpoint();
#else
    return NULL;
#endif
}
