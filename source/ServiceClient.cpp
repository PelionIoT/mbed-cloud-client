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

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include "include/ServiceClient.h"
#include "include/CloudClientStorage.h"
#include "include/UpdateClientResources.h"
#include "include/UpdateClient.h"
#include "factory_configurator_client.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-trace/mbed_trace.h"
#include <assert.h>

#define TRACE_GROUP "mClt"

#define CONNECT 0
#define ERROR_UPDATE "Update has failed, check MbedCloudClient::Error"

/* lookup table for printing hexadecimal values */
const uint8_t ServiceClient::hex_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

ServiceClient::ServiceClient(ServiceClientCallback& callback)
: _service_callback(callback),
  _service_uri(NULL),
  _stack(NULL),
  _client_objs(NULL),
  _current_state(State_Init),
  _event_generated(false),
  _state_engine_running(false),
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
  _setup_update_client(false),
#endif
  _connector_client(this)
{
}

ServiceClient::~ServiceClient()
{
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    ARM_UC_HUB_Uninitialize();
#endif
}

void ServiceClient::initialize_and_register(M2MBaseList& reg_objs)
{
    tr_debug("ServiceClient::initialize_and_register");
    if(_current_state == State_Init ||
       _current_state == State_Unregister ||
       _current_state == State_Failure) {
        _client_objs = &reg_objs;

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        tr_debug("ServiceClient::initialize_and_register: update client supported");

        if(!_setup_update_client) {
            _setup_update_client = true;

#ifdef MBED_CLOUD_DEV_UPDATE_ID
            /* Overwrite values stored in KCM. This is for development only
               since these IDs should be provisioned in the factory.
            */
            tr_debug("ServiceClient::initialize_and_register: update IDs defined");

            /* Delete VendorId */
            ccs_delete_item("mbed.VendorId", CCS_CONFIG_ITEM);
            /* Store Vendor Id to mbed.VendorId. No conversion is performed. */
            set_device_resource_value(M2MDevice::Manufacturer,
                                      (const char*) arm_uc_vendor_id,
                                      arm_uc_vendor_id_size);

            /* Delete ClassId */
            ccs_delete_item("mbed.ClassId", CCS_CONFIG_ITEM);
            /* Store Class Id to mbed.ClassId. No conversion is performed. */
            set_device_resource_value(M2MDevice::ModelNumber,
                                      (const char*) arm_uc_class_id,
                                      arm_uc_class_id_size);
#endif /* MBED_CLOUD_DEV_UPDATE_ID */

#ifdef ARM_UPDATE_CLIENT_VERSION
            /* Inject Update Client version number if no other software
               version is present in the KCM.
            */
            tr_debug("ServiceClient::initialize_and_register: update version defined");
;
            const size_t buffer_size = 16;
            uint8_t buffer[buffer_size];
            size_t size = 0;

            /* check if software version is already set */
            ccs_status_e status = ccs_get_item(KEY_DEVICE_SOFTWAREVERSION,
                                               buffer, buffer_size, &size, CCS_CONFIG_ITEM);

            if (status == CCS_STATUS_KEY_DOESNT_EXIST) {
                tr_debug("ServiceClient::initialize_and_register: insert update version");

                /* insert value from Update Client Common */
                ccs_set_item(KEY_DEVICE_SOFTWAREVERSION,
                             (const uint8_t*) ARM_UPDATE_CLIENT_VERSION,
                             sizeof(ARM_UPDATE_CLIENT_VERSION),
                             CCS_CONFIG_ITEM);
            }
#endif /* ARM_UPDATE_CLIENT_VERSION */

            /* Update Client adds the OMA LWM2M Firmware Update object */
            UpdateClient::populate_object_list(*_client_objs);

            /* Initialize Update Client */
            FP1<void, int32_t> callback(this, &ServiceClient::update_error_callback);
            UpdateClient::UpdateClient(callback);
        }
#endif /* MBED_CLOUD_CLIENT_SUPPORT_UPDATE */

        /* Device Object is mandatory.
           Get instance and add it to object list
        */
        M2MDevice *device_object = device_object_from_storage();

        if (device_object) {
            M2MObjectInstance* instance = device_object->object_instance(0);
            if (instance) {
                M2MResource *res = instance->resource(DEVICE_MANUFACTURER);
                if (res) {
                    res->publish_value_in_registration_msg(true);
                }
                res = instance->resource(DEVICE_MODEL_NUMBER);
                if (res) {
                    res->publish_value_in_registration_msg(true);
                }
                res = instance->resource(DEVICE_SERIAL_NUMBER);
                if (res) {
                    res->publish_value_in_registration_msg(true);
                }
             }
            /* Publish device object resource to mds */
            M2MResourceList list = device_object->object_instance()->resources();
            if(!list.empty()) {
                M2MResourceList::const_iterator it;
                it = list.begin();
                for ( ; it != list.end(); it++ ) {
                    (*it)->set_register_uri(true);
                }
            }

            /* Add Device Object to object list. */
            _client_objs->push_back(device_object);
        }

        internal_event(State_Bootstrap);
    } else if (_current_state == State_Success) {
        state_success();
    }
}

ConnectorClient &ServiceClient::connector_client()
{
    return _connector_client;
}

const ConnectorClient &ServiceClient::connector_client() const
{
    return _connector_client;
}

// generates an internal event. called from within a state
// function to transition to a new state
void ServiceClient::internal_event(StartupMainState new_state)
{
    tr_debug("ServiceClient::internal_event: state: %d -> %d", _current_state, new_state);

    _event_generated = true;
    _current_state = new_state;

    if (!_state_engine_running) {
        state_engine();
    }
}

// the state engine executes the state machine states
void ServiceClient::state_engine(void)
{
    tr_debug("ServiceClient::state_engine");

    // this simple flagging gets rid of recursive calls to this method
    _state_engine_running = true;

    // while events are being generated keep executing states
    while (_event_generated) {
        _event_generated = false;  // event used up, reset flag

        state_function(_current_state);
    }

    _state_engine_running = false;
}

void ServiceClient::state_function(StartupMainState current_state)
{
    switch (current_state) {
        case State_Init:        // -> Goes to bootstrap state
        case State_Bootstrap:    // -> State_Register OR State_Failure
            state_bootstrap();
            break;
        case State_Register:     // -> State_Succes OR State_Failure
            state_register();
            break;
        case State_Success:      // return success to user
            state_success();
            break;
        case State_Failure:      // return error to user
            state_failure();
            break;
        case State_Unregister:   // return error to user
            state_unregister();
            break;
    }
}

void ServiceClient::state_bootstrap()
{
    tr_info("ServiceClient::state_bootstrap()");
    bool credentials_ready = _connector_client.connector_credentials_available();
    bool bootstrap = _connector_client.use_bootstrap();
    tr_info("ServiceClient::state_bootstrap() - lwm2m credentials available: %d", credentials_ready);
    tr_info("ServiceClient::state_bootstrap() - use bootstrap: %d", bootstrap);
    if (credentials_ready || !bootstrap) {
        internal_event(State_Register);
    } else {
        _connector_client.start_bootstrap();
    }
}

void ServiceClient::state_register()
{
    tr_info("ServiceClient::state_register()");
    _connector_client.start_registration(_client_objs);
}

void ServiceClient::registration_process_result(ConnectorClient::StartupSubStateRegistration status)
{
    tr_debug("ServiceClient::registration_process_result(): status: %d", status);
    if (status == ConnectorClient::State_Registration_Success) {
        internal_event(State_Success);
    } else if(status == ConnectorClient::State_Registration_Failure ||
              status == ConnectorClient::State_Bootstrap_Failure){
        internal_event(State_Failure); // XXX: the status should be saved to eg. event object
    }
    if(status == ConnectorClient::State_Bootstrap_Success) {
        internal_event(State_Register);
    }
    if(status == ConnectorClient::State_Unregistered) {
        internal_event(State_Unregister);
    }
    if (status == ConnectorClient::State_Registration_Updated) {
        _service_callback.complete(ServiceClientCallback::Service_Client_Status_Register_Updated);
    }
}

void ServiceClient::connector_error(M2MInterface::Error error, const char *reason)
{
    tr_error("ServiceClient::connector_error() error %d", (int)error);
    if (_current_state == State_Register) {
        registration_process_result(ConnectorClient::State_Registration_Failure);
    }
    else if (_current_state == State_Bootstrap) {
        registration_process_result(ConnectorClient::State_Bootstrap_Failure);
    }
    _service_callback.error(int(error),reason);
    internal_event(State_Failure);
}

void ServiceClient::value_updated(M2MBase *base, M2MBase::BaseType type)
{
    tr_debug("ServiceClient::value_updated()");
    _service_callback.value_updated(base, type);
}

void ServiceClient::state_success()
{
    tr_info("ServiceClient::state_success()");
    // this is verified already at client API level, but this might still catch some logic failures
    _service_callback.complete(ServiceClientCallback::Service_Client_Status_Registered);
}

void ServiceClient::state_failure()
{
    tr_error("ServiceClient::state_failure()");
    _service_callback.complete(ServiceClientCallback::Service_Client_Status_Failure);
}

void ServiceClient::state_unregister()
{
    tr_debug("ServiceClient::state_unregister()");
    _service_callback.complete(ServiceClientCallback::Service_Client_Status_Unregistered);
}

M2MDevice* ServiceClient::device_object_from_storage()
{
    M2MDevice *device_object = M2MInterfaceFactory::create_device();
    if (device_object == NULL) {
        return NULL;
    }

    const size_t buffer_size = 128;
    uint8_t buffer[buffer_size];
    size_t size = 0;

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    uint8_t guid[sizeof(arm_uc_guid_t)] = {0};
    // Read out the binary Vendor UUID
    ccs_status_e status = (ccs_status_e)UpdateClient::getVendorId(guid, sizeof(arm_uc_guid_t), &size);

    // Format the binary Vendor UUID into a hex string
    if (status == CCS_STATUS_SUCCESS) {
        size_t j = 0;
        for(size_t i = 0; i < size; i++)
        {
            buffer[j++] = hex_table[(guid[i] >> 4) & 0xF];
            buffer[j++] = hex_table[(guid[i] >> 0) & 0xF];
        }
        buffer[j] = '\0';
        const String data((char*)buffer, size * 2);
        // create_resource() returns NULL if resource already exists
        if (device_object->create_resource(M2MDevice::Manufacturer, data) == NULL) {
            device_object->set_resource_value(M2MDevice::Manufacturer, data);
        }
    }

    // Read out the binary Class UUID
    status = (ccs_status_e)UpdateClient::getClassId(guid, sizeof(arm_uc_guid_t), &size);

    // Format the binary Class UUID into a hex string
    if (status == CCS_STATUS_SUCCESS) {
        size_t j = 0;
        for(size_t i = 0; i < size; i++)
        {
            buffer[j++] = hex_table[(guid[i] >> 4) & 0xF];
            buffer[j++] = hex_table[(guid[i] >> 0) & 0xF];
        }
        buffer[j] = '\0';
        const String data((char*)buffer, size * 2);
        // create_resource() returns NULL if resource already exists
        if (device_object->create_resource(M2MDevice::ModelNumber, data) == NULL) {
            device_object->set_resource_value(M2MDevice::ModelNumber, data);
        }
    }
#else
    // Read values to device object
    // create_resource() function returns NULL if resource already exists
    ccs_status_e status = ccs_get_item(g_fcc_manufacturer_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::Manufacturer, data) == NULL) {
            device_object->set_resource_value(M2MDevice::Manufacturer, data);
        }
    }
    status = ccs_get_item(g_fcc_model_number_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::ModelNumber, data) == NULL) {
            device_object->set_resource_value(M2MDevice::ModelNumber, data);
        }
    }
#endif
    status = ccs_get_item(g_fcc_device_serial_number_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::SerialNumber, data) == NULL) {
            device_object->set_resource_value(M2MDevice::SerialNumber, data);
        }
    }

    status = ccs_get_item(g_fcc_device_type_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::DeviceType, data) == NULL) {
            device_object->set_resource_value(M2MDevice::DeviceType, data);
        }
    }

    status = ccs_get_item(g_fcc_hardware_version_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::HardwareVersion, data) == NULL) {
            device_object->set_resource_value(M2MDevice::HardwareVersion, data);
        }
    }

    status = ccs_get_item(KEY_DEVICE_SOFTWAREVERSION, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::SoftwareVersion, data) == NULL) {
            device_object->set_resource_value(M2MDevice::SoftwareVersion, data);
        }
    }

    uint8_t data[4] = {0};
    uint32_t value;
    status = ccs_get_item(g_fcc_memory_size_parameter_name, data, 4, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        memcpy(&value, data, 4);
        if (device_object->create_resource(M2MDevice::MemoryTotal, value) == NULL) {
            device_object->set_resource_value(M2MDevice::MemoryTotal, value);
        }
        tr_debug("ServiceClient::device_object_from_storage() - setting memory total value %" PRIu32 " (%s)", value, tr_array(data, 4));
    }

    status = ccs_get_item(g_fcc_current_time_parameter_name, data, 4, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        memcpy(&value, data, 4);
        if (device_object->create_resource(M2MDevice::CurrentTime, value) == NULL) {
            device_object->set_resource_value(M2MDevice::CurrentTime, value);
        }
        tr_debug("ServiceClient::device_object_from_storage() - setting current time value %" PRIu32 " (%s)", value, tr_array(data, 4));
    }

    status = ccs_get_item(g_fcc_device_time_zone_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::Timezone, data) == NULL) {
            device_object->set_resource_value(M2MDevice::Timezone, data);
        }
    }

    status = ccs_get_item(g_fcc_offset_from_utc_parameter_name, buffer, buffer_size, &size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        const String data((char*)buffer, size);
        if (device_object->create_resource(M2MDevice::UTCOffset, data) == NULL) {
            device_object->set_resource_value(M2MDevice::UTCOffset, data);
        }
    }

    return device_object;
}

/**
 * \brief Set resource value in the Device Object
 *
 * \param resource Device enum to have value set.
 * \param value String object.
 * \return True if successful, false otherwise.
 */
bool ServiceClient::set_device_resource_value(M2MDevice::DeviceResource resource,
                                              const m2m::String& value)
{
    return set_device_resource_value(resource,
                                     value.c_str(),
                                     value.size() - 1);
}

/**
 * \brief Set resource value in the Device Object
 *
 * \param resource Device enum to have value set.
 * \param value Byte buffer.
 * \param length Buffer length.
 * \return True if successful, false otherwise.
 */
bool ServiceClient::set_device_resource_value(M2MDevice::DeviceResource resource,
                                              const char* value,
                                              uint32_t length)
{
    bool retval = false;

    /* sanity check */
    if (value && (length < 256) && (length > 0))
    {
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        /* Pass resource value to Update Client.
           Used for validating the manifest.
        */
        switch (resource) {
            case M2MDevice::Manufacturer:
                ARM_UC_SetVendorId((const uint8_t*) value, length);
                break;
            case M2MDevice::ModelNumber:
                ARM_UC_SetClassId((const uint8_t*) value, length);
                break;
            default:
                break;
        }
#endif

        /* Convert resource to printable string if necessary */

        /* Getting object instance from factory */
        M2MDevice *device_object = M2MInterfaceFactory::create_device();

        /* Check device object and resource both are present */
        if (device_object && device_object->is_resource_present(resource)) {
            /* set counter to not-zero */
            uint8_t printable_length = 0xFF;

            /* set printable_length to 0 if the buffer is not printable */
            for (uint8_t index = 0; index < length; index++) {
                /* break if character is not printable */
                if ((value[index] < ' ') || (value[index] > '~')) {
                    printable_length = 0;
                    break;
                }
            }

            /* resource is a string */
            if (printable_length != 0) {
                /* reset counter */
                printable_length = 0;

                /* find actual printable length */
                for ( ; printable_length < length; printable_length++) {
                    /* break prematurely if end-of-string character is found */
                    if (value[printable_length] == '\0') {
                        break;
                    }
                }

                /* convert to string and set value in object */
                String string_value(value, printable_length);
                retval = device_object->set_resource_value(resource, string_value);
            }
            else
            {
                /* resource is a byte array */
                char value_buffer[0xFF] = { 0 };

                /* count length */
                uint8_t index = 0;

                /* convert byte array to string */
                for ( ;
                    (index < length) && ((2*index +1) < 0xFF);
                    index++) {

                    uint8_t byte = value[index];

                    value_buffer[2 * index]     = hex_table[byte >> 4];
                    value_buffer[2 * index + 1] = hex_table[byte & 0x0F];
                }

                /* convert to string and set value in object */
                String string_value(value_buffer, 2 * (index - 1));
                retval = device_object->set_resource_value(resource, string_value);
            }
        }
    }

    return retval;
}

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
void ServiceClient::set_update_authorize_handler(void (*handler)(int32_t request))
{
    UpdateClient::set_update_authorize_handler(handler);
}

void ServiceClient::update_authorize(int32_t request)
{
    UpdateClient::update_authorize(request);
}

void ServiceClient::set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total))
{
    UpdateClient::set_update_progress_handler(handler);
}

void ServiceClient::update_error_callback(int32_t error)
{
    _service_callback.error(error, ERROR_UPDATE);
}
#endif
