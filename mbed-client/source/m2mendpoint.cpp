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

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION

#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mconstants.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mtlvdeserializer.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2mstringbuffer.h"
#include "mbed-client/m2mstring.h"
#include "nsdl-c/sn_nsdl_lib.h"

#include <stdlib.h>

#define BUFFER_SIZE 10
#define TRACE_GROUP "mClt"

M2MEndpoint::M2MEndpoint(const String &object_name, char *path)
: M2MBase(object_name,
          M2MBase::Dynamic,
#ifndef DISABLE_RESOURCE_TYPE
          "",
#endif
          path,
          false,
          false),
    _observation_handler(NULL),
    _ctx(NULL),
    _changed(true)
{
    M2MBase::set_base_type(M2MBase::ObjectDirectory);
    get_nsdl_resource()->always_publish = false;
#ifdef RESOURCE_ATTRIBUTES_LIST
    sn_nsdl_attribute_item_s item;
    item.attribute_name = ATTR_ENDPOINT_NAME;
    item.value = (char*)alloc_string_copy((uint8_t*) object_name.c_str(), object_name.length());
    sn_nsdl_set_resource_attribute(get_nsdl_resource()->static_resource_parameters, &item);
#endif
}


M2MEndpoint::~M2MEndpoint()
{
    tr_debug("~M2MEndpoint %p", this);
    if(!_object_list.empty()) {

        M2MObjectList::const_iterator it;
        it = _object_list.begin();
        M2MObject* obj = NULL;
        uint16_t index = 0;
        for (; it!=_object_list.end(); it++, index++ ) {
            //Free allocated memory for object instances.
            obj = *it;
            tr_debug("  deleting object %p", obj);
            delete obj;
        }

        _object_list.clear();
    }

    free_resources();
}

M2MObject* M2MEndpoint::create_object(const String &name)
{
    M2MObject *obj = NULL;
    if (object(name) == NULL) {
        char *path = create_path(*this, name.c_str());
        obj = new M2MObject(name, path, false);
        if (obj != NULL) {
            _object_list.push_back(obj);
        }
    }
    return obj;
}

bool M2MEndpoint::remove_object(const String &name)
{
    bool success = false;
    if (object_count() == 0) {
        return success;
    }
    M2MObjectList::const_iterator it;
    M2MObject *obj = NULL;
    int pos = 0;
    it = _object_list.begin();
    for (; it != _object_list.end(); it++, pos++) {
        obj = *it;
        if (name == obj->name()) {
            delete obj;
            _object_list.erase(pos);
            success = true;
            break;
        }
    }
    return success;

}

M2MObject* M2MEndpoint::object(const String &name) const
{
    M2MObject *obj = NULL;
    if (object_count() == 0) {
        return obj;
    }
    M2MObjectList::const_iterator it = _object_list.begin();
    for (; it != _object_list.end(); it++) {
        if (name == (*it)->name()) {
            obj = *it;
            break;
        }
    }
    return obj;
}

const M2MObjectList& M2MEndpoint::objects() const
{
    return _object_list;
}

uint16_t M2MEndpoint::object_count() const
{
    return _object_list.size();
}

M2MObservationHandler* M2MEndpoint::observation_handler() const
{
    return _observation_handler;
}

void M2MEndpoint::set_observation_handler(M2MObservationHandler *handler)
{
    _observation_handler = handler;
}

void M2MEndpoint::add_observation_level(M2MBase::Observation observation_level)
{
    (void)observation_level;
}

void M2MEndpoint::remove_observation_level(M2MBase::Observation observation_level)
{
    (void)observation_level;
}

sn_coap_hdr_s* M2MEndpoint::handle_get_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler *observation_handler)
{
    tr_debug("M2MEndpoint::handle_get_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    sn_coap_hdr_s * coap_response = sn_nsdl_build_response(nsdl,
            received_coap_header, msg_code);
    return coap_response;

}

sn_coap_hdr_s* M2MEndpoint::handle_put_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler */*observation_handler*/,
                                             bool &/*execute_value_updated*/)
{
    tr_debug("M2MEndpoint::handle_put_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    sn_coap_hdr_s * coap_response = sn_nsdl_build_response(nsdl,
            received_coap_header, msg_code);
    return coap_response;
}


sn_coap_hdr_s* M2MEndpoint::handle_post_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated,
                                              sn_nsdl_addr_s *)
{
    tr_debug("M2MEndpoint::handle_post_request()");
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    sn_coap_hdr_s * coap_response = sn_nsdl_build_response(nsdl,
            received_coap_header, msg_code);
    return coap_response;
}

void M2MEndpoint::set_context(void *ctx)
{
    _ctx = ctx;
}

void* M2MEndpoint::get_context() const
{
    return _ctx;
}

void M2MEndpoint::set_changed()
{
    _changed = true;
}

void M2MEndpoint::clear_changed()
{
    _changed = false;
}

bool M2MEndpoint::get_changed() const
{
    return _changed;
}

#endif // MBED_CLOUD_CLIENT_EDGE_EXTENSION
