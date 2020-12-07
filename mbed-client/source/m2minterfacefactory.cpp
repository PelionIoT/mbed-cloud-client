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

#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mserver.h"
#include "mbed-client/m2mdevice.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mconfig.h"
#include "include/m2minterfaceimpl.h"
#include "mbed-trace/mbed_trace.h"

#include <inttypes.h>

#define TRACE_GROUP "mClt"

M2MInterface* M2MInterfaceFactory::create_interface(M2MInterfaceObserver &observer,
                                                    const String &endpoint_name,
                                                    const String &endpoint_type,
                                                    const int32_t life_time,
                                                    const uint16_t listen_port,
                                                    const String &domain,
                                                    M2MInterface::BindingMode mode,
                                                    M2MInterface::NetworkStack stack,
                                                    const String &context_address)
{
    tr_debug("M2MInterfaceFactory::create_interface - IN");
    tr_info("M2MInterfaceFactory::create_interface - parameters endpoint name : %s",endpoint_name.c_str());
    tr_info("M2MInterfaceFactory::create_interface - parameters endpoint type : %s",endpoint_type.c_str());
    tr_info("M2MInterfaceFactory::create_interface - parameters life time(in secs): %" PRId32,life_time);
    tr_info("M2MInterfaceFactory::create_interface - parameters Listen Port : %d",listen_port);
    tr_info("M2MInterfaceFactory::create_interface - parameters Binding Mode : %d",(int)mode);
    tr_info("M2MInterfaceFactory::create_interface - parameters NetworkStack : %d",(int)stack);
    M2MInterfaceImpl *interface = NULL;


    bool endpoint_type_valid = true;
    if(!endpoint_type.empty()) {
        if(endpoint_type.size() > MAX_ALLOWED_STRING_LENGTH){
            endpoint_type_valid = false;
        }
    }

    bool domain_valid = true;
    if(!domain.empty()) {
        if(domain.size() > MAX_ALLOWED_STRING_LENGTH){
            domain_valid = false;
        }
    }

    if(((life_time == -1) || (life_time >= MINIMUM_REGISTRATION_TIME)) &&
       !endpoint_name.empty() && (endpoint_name.size() <= MAX_ALLOWED_STRING_LENGTH) &&
       endpoint_type_valid && domain_valid) {
        tr_debug("M2MInterfaceFactory::create_interface - Creating M2MInterfaceImpl");
        interface = new M2MInterfaceImpl(observer, endpoint_name,
                                         endpoint_type, life_time,
                                         listen_port, domain, mode,
                                         stack, context_address);

    }
    tr_debug("M2MInterfaceFactory::create_interface - OUT");
    return interface;
}

M2MSecurity* M2MInterfaceFactory::create_security(M2MSecurity::ServerType server_type)
{
    tr_debug("M2MInterfaceFactory::create_security");
    M2MSecurity *security = M2MSecurity::get_instance();
    return security;
}

M2MServer* M2MInterfaceFactory::create_server()
{
    tr_debug("M2MInterfaceFactory::create_server");
    M2MServer *server = new M2MServer();
    return server;
}

M2MDevice* M2MInterfaceFactory::create_device()
{
    tr_debug("M2MInterfaceFactory::create_device");
    M2MDevice* device = M2MDevice::get_instance();
    return device;
}

M2MObject* M2MInterfaceFactory::create_object(const String &name)
{
    tr_debug("M2MInterfaceFactory::create_object : Name : %s", name.c_str());
    if(name.size() > MAX_ALLOWED_STRING_LENGTH || name.empty()){
        return NULL;
    }

    M2MObject *object = NULL;
    char *name_copy = M2MBase::stringdup(name.c_str());
    if (name_copy) {
        object = new M2MObject(name, name_copy);
    }
    return object;
}

M2MObject* M2MInterfaceFactory::find_or_create_object(M2MObjectList &object_list,
                                                      const uint16_t object_id,
                                                      bool &object_created)
{
    // Check list for existing object
    object_created = false;
    for (int i=0; i<object_list.size(); i++) {
        if (object_list[i]->name_id() == object_id) {
            tr_debug("Found existing /%" PRIu16, object_id);
            return object_list[i];
        }
    }

    // Not found, create
    String object_name_str;
    object_name_str.append_int(object_id);
    M2MObject *object = M2MInterfaceFactory::create_object(object_name_str);
    if (object == NULL) {
        tr_err("Couldn't create /%" PRIu16 " (out of memory?)", object_id);
        return NULL;
    }
    object_list.push_back(object);
    object_created = true;

    // All good
    tr_debug("Created new /%" PRIu16, object_id);
    return object;
}

M2MObjectInstance* M2MInterfaceFactory::find_or_create_object_instance(M2MObject &object,
                                                                       const uint16_t object_instance_id,
                                                                       bool &object_instance_created)
{
    // Check object instances for existing one
    object_instance_created = false;
    M2MObjectInstance *object_instance = object.object_instance(object_instance_id);
    if (object_instance != NULL) {
        tr_debug("Found existing /%d/%" PRIu16, object.name_id(), object_instance_id);
        return object_instance;
    }

    // Create object instance if not found
    if (object_instance == NULL) {
        object_instance = object.create_object_instance(object_instance_id);
        if (object_instance == NULL) {
            tr_err("Couldn't create /%d/%" PRIu16 " (out of memory?)", object.name_id(), object_instance_id);
            return NULL;
        }
    }
    object_instance_created = true;

    // All good
    tr_debug("Created /%d/%" PRIu16, object.name_id(), object_instance_id);
    return object_instance;
}

M2MResource* M2MInterfaceFactory::find_or_create_resource(M2MObjectInstance &object_instance,
                                                          const uint16_t resource_id,
                                                          const M2MResourceInstance::ResourceType resource_type,
                                                          bool multiple_instance,
                                                          bool external_blockwise_store)
{
    // Check resources for existing one
    M2MResource *resource = object_instance.resource(resource_id);
    if (resource != NULL) {
        tr_debug("Found existing /%d/%d/%" PRIu16,
            object_instance.get_parent_object().name_id(), object_instance.instance_id(), resource_id);
        return resource;
    }

    // Create resource if existing not found
    resource = object_instance.create_dynamic_resource(resource_id, "", resource_type,
                                                       true, multiple_instance, external_blockwise_store);
    if (resource == NULL) {
        tr_err("Couldn't create /%d/%d/%" PRIu16 " (out of memory?)",
            object_instance.get_parent_object().name_id(), object_instance.instance_id(), resource_id);
        return NULL;
    }

    // All good
    tr_debug("Created new /%d/%d/%" PRIu16,
        object_instance.get_parent_object().name_id(), object_instance.instance_id(), resource_id);
    return resource;
}

M2MResource* M2MInterfaceFactory::create_resource(M2MObjectList &object_list,
                                                  const uint16_t object_id,
                                                  const uint16_t object_instance_id,
                                                  const uint16_t resource_id,
                                                  const M2MResourceInstance::ResourceType resource_type,
                                                  const M2MBase::Operation allowed,
                                                  bool multiple_instance,
                                                  bool external_blockwise_store)
{
    tr_debug("M2MInterfaceFactory::create_resource() - creating /%" PRIu16 "/%" PRIu16 "/%" PRIu16,
        object_id, object_instance_id, resource_id);

    M2MObject *object;
    M2MObjectInstance *object_instance;
    M2MResource *resource;

    // Check and create object if necessary
    bool object_created;
    object = M2MInterfaceFactory::find_or_create_object(object_list, object_id, object_created);
    if (object == NULL) {
        tr_err("M2MInterfaceFactory::create_resource() - failed to get object");
        goto exit;
    }

    // Check and create object instance if necessary
    bool object_instance_created;
    object_instance = M2MInterfaceFactory::find_or_create_object_instance(
        *object, object_instance_id, object_instance_created);
    if (object_instance == NULL) {
        tr_err("M2MInterfaceFactory::create_resource() - failed to get object instance");
        goto cleanup_object;
    }

    // Check and create resource if necessary
    resource = M2MInterfaceFactory::find_or_create_resource(
        *object_instance, resource_id, resource_type,
        multiple_instance, external_blockwise_store);
    if (resource == NULL) {
        tr_err("M2MInterfaceFactory::create_resource() - failed to get resource");
        goto cleanup_object_instance;
    }

    // All good
    resource->set_operation(allowed);
    return resource;

cleanup_object_instance:
    // Need to check the created flag as the object instance
    // could have existed before entering to this function.
    if (object_instance_created) {
        if (object->remove_object_instance(object_instance_id) == false) {
            tr_err("M2MInterfaceFactory::create_resource() - failed to delete created object_instance");
        }
    }
cleanup_object:
    if (object_created) {
        object_list.pop_back();
        delete object;
    }
exit:
    return NULL;
}

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
M2MEndpoint* M2MInterfaceFactory::create_endpoint(const String &name)
{
    tr_debug("M2MInterfaceFactory::create_endpoint : Name : %s", name.c_str());
    if(name.size() > MAX_ALLOWED_STRING_LENGTH || name.empty()){
        return NULL;
    }

    M2MEndpoint *object = NULL;
    char *path = (char*)malloc(2 + name.size() + 1);
    if (path) {
        // Prepend path with directory prefix "d/" so that all endpoints will be under common path
        path[0] = 'd';
        path[1] = '/';
        memcpy(&path[2], name.c_str(), name.size());
        path[name.size() + 2] = '\0';
        object = new M2MEndpoint(name, path);
    }
    return object;
}
#endif
