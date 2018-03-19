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
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mstring.h"
#include "mbed-trace/mbed_trace.h"

#include <stdlib.h>

#define TRACE_GROUP "mClt"

#define BUFFER_SIZE 21

// Default instance id's that server uses
#define DEFAULT_M2M_INSTANCE       0
#define DEFAULT_BOOTSTRAP_INSTANCE 1

M2MSecurity* M2MSecurity::_instance = NULL;

M2MSecurity* M2MSecurity::get_instance()
{
    if (_instance == NULL) {
        _instance = new M2MSecurity(M2MServer);
    }
    return _instance;
}

void M2MSecurity::delete_instance()
{
    delete _instance;
    _instance = NULL;
}


M2MSecurity::M2MSecurity(ServerType ser_type)
: M2MObject(M2M_SECURITY_ID, stringdup(M2M_SECURITY_ID))
{
}

M2MSecurity::~M2MSecurity()
{
}

M2MObjectInstance* M2MSecurity::create_object_instance(ServerType server_type)
{
    uint16_t instance_id = DEFAULT_M2M_INSTANCE;
    if (server_type == Bootstrap) {
        instance_id = DEFAULT_BOOTSTRAP_INSTANCE;
    }

    M2MObjectInstance *server_instance = M2MObject::object_instance(instance_id);
    if (server_instance != NULL) {
        // Instance already exists, return NULL
        return NULL;
    }

    server_instance = M2MObject::create_object_instance(instance_id);
    if (server_instance) {
        M2MResource* res = server_instance->create_dynamic_resource(SECURITY_M2M_SERVER_URI,
                                                                     OMA_RESOURCE_TYPE,
                                                                     M2MResourceInstance::STRING,
                                                                     false);
        if (res) {
            res->set_operation(M2MBase::NOT_ALLOWED);
        }
        res = server_instance->create_dynamic_resource(SECURITY_BOOTSTRAP_SERVER,
                                                        OMA_RESOURCE_TYPE,
                                                        M2MResourceInstance::BOOLEAN,
                                                        false);
        if (res) {
            res->set_operation(M2MBase::NOT_ALLOWED);
            res->set_value((int)server_type);
        }
        res = server_instance->create_dynamic_resource(SECURITY_SECURITY_MODE,
                                                        OMA_RESOURCE_TYPE,
                                                        M2MResourceInstance::INTEGER,
                                                        false);
        if (res) {
            res->set_operation(M2MBase::NOT_ALLOWED);
        }
        res = server_instance->create_dynamic_resource(SECURITY_PUBLIC_KEY,
                                                        OMA_RESOURCE_TYPE,
                                                        M2MResourceInstance::OPAQUE,
                                                        false);
        if (res) {
            res->set_operation(M2MBase::NOT_ALLOWED);
        }
        res = server_instance->create_dynamic_resource(SECURITY_SERVER_PUBLIC_KEY,
                                                        OMA_RESOURCE_TYPE,
                                                        M2MResourceInstance::OPAQUE,
                                                        false);
        if (res) {
            res->set_operation(M2MBase::NOT_ALLOWED);
        }
        res = server_instance->create_dynamic_resource(SECURITY_SECRET_KEY,
                                                        OMA_RESOURCE_TYPE,
                                                        M2MResourceInstance::OPAQUE,
                                                        false);
        if (res) {
            res->set_operation(M2MBase::NOT_ALLOWED);
        }
        if (M2MSecurity::M2MServer == server_type) {
            res = server_instance->create_dynamic_resource(SECURITY_SHORT_SERVER_ID,
                                                            OMA_RESOURCE_TYPE,
                                                            M2MResourceInstance::INTEGER,
                                                            false);
            if (res) {
                res->set_operation(M2MBase::NOT_ALLOWED);
            }
        }
    }
    return server_instance;
}

void M2MSecurity::remove_security_instances()
{
    int32_t instance_id = _instance->get_security_instance_id(M2MSecurity::Bootstrap);
    if (instance_id >= 0) {
        _instance->remove_object_instance(instance_id);
    }
    instance_id = _instance->get_security_instance_id(M2MSecurity::M2MServer);
    if (instance_id >= 0) {
        _instance->remove_object_instance(instance_id);
    }
}

M2MResource* M2MSecurity::create_resource(SecurityResource resource, uint32_t value, uint16_t instance_id)
{
    M2MResource* res = NULL;
    M2MObjectInstance *server_instance = M2MObject::object_instance(instance_id);
    if (server_instance == NULL) {
        return NULL;
    }

    const char* security_id_ptr = "";
    if (!is_resource_present(resource, instance_id)) {
        switch(resource) {
            case SMSSecurityMode:
               security_id_ptr = SECURITY_SMS_SECURITY_MODE;
               break;
            case M2MServerSMSNumber:
                security_id_ptr = SECURITY_M2M_SERVER_SMS_NUMBER;
                break;
            case ShortServerID:
                security_id_ptr = SECURITY_SHORT_SERVER_ID;
                break;
            case ClientHoldOffTime:
                security_id_ptr = SECURITY_CLIENT_HOLD_OFF_TIME;
                break;
            default:
                break;
        }
    }

    const String security_id(security_id_ptr);

    if (!security_id.empty()) {
        if (server_instance) {
            res = server_instance->create_dynamic_resource(security_id,OMA_RESOURCE_TYPE,
                                                            M2MResourceInstance::INTEGER,
                                                            false);

            if (res) {
                res->set_operation(M2MBase::NOT_ALLOWED);
                res->set_value(value);
            }
        }
    }
    return res;
}

bool M2MSecurity::delete_resource(SecurityResource resource, uint16_t instance_id)
{
    bool success = false;
    const char* security_id_ptr;
    M2MObjectInstance *server_instance = M2MObject::object_instance(instance_id);
    if (server_instance == NULL) {
        return NULL;
    }
    switch(resource) {
        case SMSSecurityMode:
           security_id_ptr = SECURITY_SMS_SECURITY_MODE;
           break;
        case M2MServerSMSNumber:
            security_id_ptr = SECURITY_M2M_SERVER_SMS_NUMBER;
            break;
        case ShortServerID:
            if (M2MSecurity::Bootstrap == server_type(instance_id)) {
                security_id_ptr = SECURITY_SHORT_SERVER_ID;
            } else {
                security_id_ptr = NULL;
            }
            break;
        case ClientHoldOffTime:
            security_id_ptr = SECURITY_CLIENT_HOLD_OFF_TIME;
            break;
        default:
            // Others are mandatory resources hence cannot be deleted.
            security_id_ptr = NULL;
            break;
    }

    if (security_id_ptr) {
        if (server_instance) {
            success = server_instance->remove_resource(security_id_ptr);
        }
    }
    return success;
}

bool M2MSecurity::set_resource_value(SecurityResource resource,
                                     const String &value,
                                     uint16_t instance_id)
{
    bool success = false;
    if (M2MSecurity::M2MServerUri == resource) {
        M2MResource* res = get_resource(resource, instance_id);
        if (res) {
            success = res->set_value((const uint8_t*)value.c_str(),(uint32_t)value.length());
        }
    }
    return success;
}

bool M2MSecurity::set_resource_value(SecurityResource resource,
                                     uint32_t value,
                                     uint16_t instance_id)
{
    bool success = false;
    M2MResource* res = get_resource(resource, instance_id);
    if (res) {
        if (M2MSecurity::SecurityMode == resource        ||
           M2MSecurity::SMSSecurityMode == resource     ||
           M2MSecurity::M2MServerSMSNumber == resource  ||
           M2MSecurity::ShortServerID == resource       ||
           M2MSecurity::BootstrapServer == resource     ||
           M2MSecurity::ClientHoldOffTime == resource) {
            success = res->set_value(value);

        }
    }
    return success;
}

bool M2MSecurity::set_resource_value(SecurityResource resource,
                                     const uint8_t *value,
                                     const uint16_t length,
                                     uint16_t instance_id)
{
    bool success = false;
    M2MResource* res = get_resource(resource, instance_id);
    if (res) {
        if (M2MSecurity::PublicKey == resource           ||
           M2MSecurity::ServerPublicKey == resource     ||
           M2MSecurity::Secretkey == resource           ||
           M2MSecurity::M2MServerUri == resource) {
            success = res->set_value(value,length);
        }
    }
    return success;
}

String M2MSecurity::resource_value_string(SecurityResource resource, uint16_t instance_id) const
{
    String value = "";
    M2MResource* res = get_resource(resource, instance_id);
    if (res) {
        if (M2MSecurity::M2MServerUri == resource) {
            value = res->get_value_string();
        }
    }
    return value;
}

uint32_t M2MSecurity::resource_value_buffer(SecurityResource resource,
                                            uint8_t *&data,
                                            uint16_t instance_id) const
{
    uint32_t size = 0;
    M2MResource* res = get_resource(resource, instance_id);
    if (res) {
        if (M2MSecurity::PublicKey == resource        ||
           M2MSecurity::ServerPublicKey == resource  ||
           M2MSecurity::Secretkey == resource) {
            res->get_value(data,size);
        }
    }
    return size;
}

uint32_t M2MSecurity::resource_value_buffer(SecurityResource resource,
                                            const uint8_t *&data,
                                            uint16_t instance_id) const
{
    uint32_t size = 0;
    M2MResource* res = get_resource(resource, instance_id);
    if (res) {
        if (M2MSecurity::PublicKey == resource        ||
           M2MSecurity::ServerPublicKey == resource  ||
           M2MSecurity::Secretkey == resource) {
            data = res->value();
            size = res->value_length();
        }
    }
    return size;
}


uint32_t M2MSecurity::resource_value_int(SecurityResource resource, uint16_t instance_id) const
{
    uint32_t value = 0;
    M2MResource* res = get_resource(resource, instance_id);
    if (res) {
        if (M2MSecurity::SecurityMode == resource        ||
           M2MSecurity::SMSSecurityMode == resource     ||
           M2MSecurity::M2MServerSMSNumber == resource  ||
           M2MSecurity::ShortServerID == resource       ||
           M2MSecurity::BootstrapServer == resource     ||
           M2MSecurity::ClientHoldOffTime == resource) {
            // note: the value may be 32bit int on 32b archs.
            value = res->get_value_int();
        }
    }
    return value;
}

bool M2MSecurity::is_resource_present(SecurityResource resource, uint16_t instance_id) const
{
    bool success = false;
    M2MResource *res = get_resource(resource, instance_id);
    if (res) {
        success = true;
    }
    return success;
}

uint16_t M2MSecurity::total_resource_count(uint16_t instance_id) const
{
    uint16_t count = 0;
    M2MObjectInstance *server_instance = M2MObject::object_instance(instance_id);
    if (server_instance) {
        count = server_instance->resources().size();
    }
    return count;
}

M2MSecurity::ServerType M2MSecurity::server_type(uint16_t instance_id) const
{
    uint32_t sec_mode = resource_value_int(M2MSecurity::BootstrapServer, instance_id);
    M2MSecurity::ServerType type = M2MSecurity::M2MServer;
    if (sec_mode == 1) {
        type = M2MSecurity::Bootstrap;
    }
    return type;
}

M2MResource* M2MSecurity::get_resource(SecurityResource res, uint16_t instance_id) const
{
    M2MResource* res_object = NULL;
    M2MObjectInstance *server_instance = M2MObject::object_instance(instance_id);
    if (server_instance == NULL) {
        return NULL;
    }

    if (server_instance) {
        const char* res_name_ptr = NULL;
        switch(res) {
            case M2MServerUri:
                res_name_ptr = SECURITY_M2M_SERVER_URI;
                break;
            case BootstrapServer:
                res_name_ptr = SECURITY_BOOTSTRAP_SERVER;
                break;
            case SecurityMode:
                res_name_ptr = SECURITY_SECURITY_MODE;
                break;
            case PublicKey:
                res_name_ptr = SECURITY_PUBLIC_KEY;
                break;
            case ServerPublicKey:
                res_name_ptr = SECURITY_SERVER_PUBLIC_KEY;
                break;
            case Secretkey:
                res_name_ptr = SECURITY_SECRET_KEY;
                break;
            case SMSSecurityMode:
                res_name_ptr = SECURITY_SMS_SECURITY_MODE;
                break;
            case SMSBindingKey:
                res_name_ptr = SECURITY_SMS_BINDING_KEY;
                break;
            case SMSBindingSecretKey:
                res_name_ptr = SECURITY_SMS_BINDING_SECRET_KEY;
                break;
            case M2MServerSMSNumber:
                res_name_ptr = SECURITY_M2M_SERVER_SMS_NUMBER;
                break;
            case ShortServerID:
                res_name_ptr = SECURITY_SHORT_SERVER_ID;
                break;
            case ClientHoldOffTime:
                res_name_ptr = SECURITY_CLIENT_HOLD_OFF_TIME;
                break;
        }

        if (res_name_ptr) {
            res_object = server_instance->resource(res_name_ptr);
        }
    }
    return res_object;
}

void M2MSecurity::clear_resources(uint16_t instance_id)
{
    for(int i = 0; i <= M2MSecurity::ClientHoldOffTime; i++) {
        M2MResource *res = get_resource((SecurityResource) i, instance_id);
        if (res) {
            res->clear_value();
        }
    }
}

int32_t M2MSecurity::get_security_instance_id(ServerType ser_type) const
{
    M2MObjectInstanceList::const_iterator it;
    M2MObjectInstanceList insts = instances();
    it = insts.begin();
    int32_t instance_id = -1;
    for ( ; it != insts.end(); it++ ) {
        uint16_t id = (*it)->instance_id();
        if (server_type(id) == ser_type) {
            instance_id = id;
            break;
        }
    }
    return instance_id;
}
