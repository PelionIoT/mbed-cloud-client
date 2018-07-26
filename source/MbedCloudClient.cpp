// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#include "mbed-cloud-client/MbedCloudClientConfig.h"
#include "mbed-cloud-client/MbedCloudClient.h"
#include "mbed-cloud-client/SimpleM2MResource.h"

#include "mbed-trace/mbed_trace.h"

#include <assert.h>

#define xstr(s) str(s)
#define str(s) #s

#define TRACE_GROUP "mClt"

MbedCloudClient::MbedCloudClient()
:_client(*this),
 _value_callback(NULL),
 _error_description(NULL)
{
}

MbedCloudClient::~MbedCloudClient()
{
    _object_list.clear();
}

void MbedCloudClient::add_objects(const M2MObjectList& object_list)
{
    if(!object_list.empty()) {
        M2MObjectList::const_iterator it;
        it = object_list.begin();
        for (; it!= object_list.end(); it++) {
            _object_list.push_back((M2MBase*)*it);
        }
    }
}

void MbedCloudClient::add_objects(const M2MBaseList& base_list)
{
    if(!base_list.empty()) {
        M2MBaseList::const_iterator it;
        it = base_list.begin();
        for (; it!= base_list.end(); it++) {
            _object_list.push_back(*it);
        }
    }
}

void MbedCloudClient::remove_object(M2MBase *object)
{
    M2MBaseList::const_iterator it;
    int found_index = -1;
    int index;
    tr_debug("MbedCloudClient::remove_object %p", object);
    for (it = _object_list.begin(), index = 0; it != _object_list.end(); it++, index++) {
        if(*it == object) {
            found_index = index;
            break;
        }
    }
    if(found_index != -1) {
        tr_debug("  object found at index %d", found_index);
        _object_list.erase(found_index);
        _client.connector_client().m2m_interface()->remove_object(object);
    }
}

void MbedCloudClient::set_update_callback(MbedCloudClientCallback *callback)
{
    _value_callback = callback;
}

bool MbedCloudClient::setup(void* iface)
{
    tr_debug("MbedCloudClient setup()");
    // Add objects to list
    m2m::UnorderedMap<m2m::String, M2MObject*>::iterator it;
    for (it = _objects.begin(); it != _objects.end(); it++)
    {
        _object_list.push_back((M2MBase*)it->second);
    }
    _client.connector_client().m2m_interface()->set_platform_network_handler(iface);

    _client.initialize_and_register(_object_list);
    return true;
}

void MbedCloudClient::on_registered(void(*fn)(void))
{
    FP0<void> fp(fn);
    _on_registered = fp;
}


void MbedCloudClient::on_error(void(*fn)(int))
{
    _on_error = fn;
}


void MbedCloudClient::on_unregistered(void(*fn)(void))
{
    FP0<void> fp(fn);
    _on_unregistered = fp;
}

void MbedCloudClient::on_registration_updated(void(*fn)(void))
{
    FP0<void> fp(fn);
    _on_registration_updated = fp;
}

void MbedCloudClient::keep_alive()
{
    _client.connector_client().update_registration();
}

void MbedCloudClient::register_update()
{
    _client.connector_client().update_registration();
}

void MbedCloudClient::close()
{
    _client.connector_client().m2m_interface()->unregister_object(NULL);
}

const ConnectorClientEndpointInfo *MbedCloudClient::endpoint_info() const
{
    return _client.connector_client().endpoint_info();
}

void MbedCloudClient::set_queue_sleep_handler(callback_handler handler)
{
    _client.connector_client().m2m_interface()->set_queue_sleep_handler(handler);
}

void MbedCloudClient::set_random_number_callback(random_number_cb callback)
{
    _client.connector_client().m2m_interface()->set_random_number_callback(callback);
}

void MbedCloudClient::set_entropy_callback(entropy_cb callback)
{
    _client.connector_client().m2m_interface()->set_entropy_callback(callback);
}

bool MbedCloudClient::set_device_resource_value(M2MDevice::DeviceResource resource,
                                                const m2m::String &value)
{
    return _client.set_device_resource_value(resource, value);
}

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
void MbedCloudClient::set_update_authorize_handler(void (*handler)(int32_t request))
{
    _client.set_update_authorize_handler(handler);
}

void MbedCloudClient::set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total))
{
    _client.set_update_progress_handler(handler);
}

void MbedCloudClient::update_authorize(int32_t request)
{
    _client.update_authorize(request);
}
#endif

const char *MbedCloudClient::error_description() const
{
    return _error_description;
}


void MbedCloudClient::register_update_callback(m2m::String route,
                                               SimpleM2MResourceBase* resource)
{
    _update_values[route] = resource;
}

void MbedCloudClient::complete(ServiceClientCallbackStatus status)
{
    tr_info("MbedCloudClient::complete status (%d)", status);
    if (status == Service_Client_Status_Registered) {
        _on_registered.call();
    } else if (status == Service_Client_Status_Unregistered) {
        _object_list.clear();
        _on_unregistered.call();
    } else if (status == Service_Client_Status_Register_Updated) {
        _on_registration_updated.call();
    }
}

void MbedCloudClient::error(int error, const char *reason)
{
    tr_error("MbedCloudClient::error code (%d)", error);
    _error_description = reason;
    _on_error(error);
}

void MbedCloudClient::value_updated(M2MBase *base, M2MBase::BaseType type)
{
    if (base) {
        tr_info("MbedCloudClient::value_updated path %s", base->uri_path());
        if (base->uri_path()) {
            if (_update_values.count(base->uri_path()) != 0) {
                tr_debug("MbedCloudClient::value_updated calling update() for %s", base->uri_path());
                _update_values[base->uri_path()]->update();
            } else {
                // way to tell application that there is a value update
                if (_value_callback) {
                    _value_callback->value_updated(base, type);
                }
            }
        }
    }
}

void MbedCloudClient::send_get_request(const char *uri,
                                       const size_t offset,
                                       get_data_cb data_cb,
                                       get_data_error_cb error_cb,
                                       void *context)
{
    _client.connector_client().m2m_interface()->get_data_request(uri,
                                                                offset,
                                                                true,
                                                                data_cb,
                                                                error_cb,
                                                                context);
}
