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

// fixup the compilation on ARMCC for PRId32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "include/ConnectorClient.h"
#include "include/CloudClientStorage.h"
#include "include/CertificateParser.h"
#include "MbedCloudClient.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"
#include "mbed-trace/mbed_trace.h"
#include "factory_configurator_client.h"

#include <assert.h>
#include <string>
#include <stdio.h>

#define TRACE_GROUP "mClt"

#define INTERNAL_ENDPOINT_PARAM     "&iep="
#define DEFAULT_ENDPOINT "endpoint"
#define INTERFACE_ERROR             "Client interface is not created. Restart"
#define CREDENTIAL_ERROR            "Failed to read credentials from storage"
#define DEVICE_NOT_PROVISIONED      "Device not provisioned"
#define ERROR_NO_MEMORY             "Not enough memory to stroe LWM2M credentials"

// XXX: nothing here yet
class EventData {

};

ConnectorClient::ConnectorClient(ConnectorClientCallback* callback)
: _callback(callback),
  _current_state(State_Bootstrap_Start),
  _event_generated(false), _state_engine_running(false),
  _interface(NULL), _security(NULL),
  _endpoint_info(M2MSecurity::Certificate), _client_objs(NULL),
  _rebootstrap_timer(*this), _bootstrap_security_instance(1), _lwm2m_security_instance(0)
{
    assert(_callback != NULL);

    // Create the lwm2m server security object we need always
    _security = M2MInterfaceFactory::create_security(M2MSecurity::M2MServer);
    _interface = M2MInterfaceFactory::create_interface(*this,
                                                      DEFAULT_ENDPOINT,                     // endpoint name string
                                                      MBED_CLOUD_CLIENT_ENDPOINT_TYPE,      // endpoint type string
                                                      MBED_CLOUD_CLIENT_LIFETIME,           // lifetime
                                                      MBED_CLOUD_CLIENT_LISTEN_PORT,        // listen port
                                                      _endpoint_info.account_id,            // domain string
                                                      transport_mode(),                     // binding mode
                                                      M2MInterface::LwIP_IPv4);             // network stack

    initialize_storage();
}


ConnectorClient::~ConnectorClient()
{
    uninitialize_storage();
    M2MDevice::delete_instance();
    M2MSecurity::delete_instance();
    delete _interface;
}

void ConnectorClient::start_bootstrap()
{
    tr_debug("ConnectorClient::start_bootstrap()");
    assert(_callback != NULL);
    // Stop rebootstrap timer if it was running
    _rebootstrap_timer.stop_timer();
    if (create_bootstrap_object()) {
        _interface->update_endpoint(_endpoint_info.endpoint_name);
        _interface->update_domain(_endpoint_info.account_id);
        internal_event(State_Bootstrap_Start);
    } else {
        tr_error("ConnectorClient::start_bootstrap() - bootstrap object fail");
    }
    state_engine();
}

void ConnectorClient::start_registration(M2MObjectList* client_objs)
{
    tr_debug("ConnectorClient::start_registration()");
    assert(_callback != NULL);
    _client_objs = client_objs;

    // XXX: actually this call should be external_event() to match the pattern used in other m2m classes
    create_register_object();
    if(_security->get_security_instance_id(M2MSecurity::M2MServer) >= 0) {
        if(use_bootstrap()) {
            // Bootstrap registration always uses iep
            _interface->update_endpoint(_endpoint_info.internal_endpoint_name);
        } else {
            // Registration without bootstrap always uses external id
            _interface->update_endpoint(_endpoint_info.endpoint_name);
        }
        _interface->update_domain(_endpoint_info.account_id);
        internal_event(State_Registration_Start);
    } else {
        tr_error("ConnectorClient::state_init(): failed to create objs");
        _callback->connector_error(M2MInterface::InvalidParameters, INTERFACE_ERROR);
    }
    state_engine();
}

M2MInterface * ConnectorClient::m2m_interface()
{
    return _interface;
}

void ConnectorClient::update_registration()
{
    if(_interface && _security && _security->get_security_instance_id(M2MSecurity::M2MServer) >= 0) {
        if (_client_objs != NULL) {
            _interface->update_registration(_security, *_client_objs);
        }
        else {
            _interface->update_registration(_security);
        }
    }
}

// generates an internal event. called from within a state
// function to transition to a new state
void ConnectorClient::internal_event(StartupSubStateRegistration new_state)
{
    tr_debug("ConnectorClient::internal_event: state: %d -> %d", _current_state, new_state);
    _event_generated = true;
    _current_state = new_state;

    // Avoid recursive chain which eats too much of stack
    if (!_state_engine_running) {
        state_engine();
    }
}

// the state engine executes the state machine states
void ConnectorClient::state_engine(void)
{
    tr_debug("ConnectorClient::state_engine");

    // this simple flagging gets rid of recursive calls to this method
    _state_engine_running = true;

    // while events are being generated keep executing states
    while (_event_generated) {
        _event_generated = false;  // event used up, reset flag

        state_function(_current_state);
    }

    _state_engine_running = false;
}

void ConnectorClient::state_function(StartupSubStateRegistration current_state)
{
    switch (current_state) {
        case State_Bootstrap_Start:
            state_bootstrap_start();
            break;
        case State_Bootstrap_Started:
            state_bootstrap_started();
            break;
        case State_Bootstrap_Success:
            state_bootstrap_success();
            break;
        case State_Bootstrap_Failure:
            state_bootstrap_failure();
            break;
        case State_Registration_Start:
            state_registration_start();
            break;
        case State_Registration_Started:
            state_registration_started();
            break;
        case State_Registration_Success:
            state_registration_success();
            break;
        case State_Registration_Failure:
            state_registration_failure();
            break;
        case State_Unregistered:
            state_unregistered();
            break;
        default:
            break;
    }
}

/*
*  Creates register server object with mbed device server address and other parameters
*  required for client to connect to mbed device server.
*/
void ConnectorClient::create_register_object()
{
    tr_debug("ConnectorClient::create_register_object()");
    if(_security && _security->get_security_instance_id(M2MSecurity::M2MServer) == -1) {
        _security->create_object_instance(M2MSecurity::M2MServer);
        int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
        _security->set_resource_value(M2MSecurity::BootstrapServer, M2MSecurity::M2MServer, m2m_id);
        // Add ResourceID's and values to the security ObjectID/ObjectInstance
        _security->set_resource_value(M2MSecurity::SecurityMode, _endpoint_info.mode, m2m_id);

        // Allocate scratch buffer, this will be used to copy parameters from storage to security object
        const int max_size = 2048;
        uint8_t *buffer = (uint8_t*)malloc(max_size);
        size_t real_size = 0;
        bool success = false;
        if (buffer != NULL) {
            success = true;
        }

        // Connector CA
        if (success) {
            success = false;
            if (get_config_certificate(g_fcc_lwm2m_server_ca_certificate_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                tr_info("ConnectorClient::create_register_object - ServerPublicKey %d", (int)real_size);
                success = true;
                _security->set_resource_value(M2MSecurity::ServerPublicKey,
                                              buffer,
                                              (uint32_t)real_size,
                                              m2m_id);
            }
            else {
                tr_error("KEY_CONNECTOR_CA cert failed.");
            }
        }

        // Connector device public key
        if (success) {
            success = false;
            if (get_config_certificate(g_fcc_lwm2m_device_certificate_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                tr_info("ConnectorClient::create_register_object - PublicKey %d", (int)real_size);
                success = true;
                _security->set_resource_value(M2MSecurity::PublicKey, buffer, (uint32_t)real_size, m2m_id);
            }
            else {
                tr_error("KEY_CONNECTOR__DEVICE_CERT failed.");
            }
        }

        // Connector device private key
        if (success) {
            success = false;
            if (get_config_private_key(g_fcc_lwm2m_device_private_key_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                tr_info("ConnectorClient::create_register_object - SecretKey %d", (int)real_size);
                success = true;
                _security->set_resource_value(M2MSecurity::Secretkey, buffer, (uint32_t)real_size, m2m_id);
            }
            else
                tr_error("KEY_CONNECTOR_DEVICE_PRIV failed.");
        }

        // Connector URL
        if (success) {
            success = false;
            if (get_config_parameter(g_fcc_lwm2m_server_uri_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                tr_info("ConnectorClient::create_register_object - M2MServerUri %.*s", (int)real_size, buffer);
                success = true;
                _security->set_resource_value(M2MSecurity::M2MServerUri, buffer, (uint32_t)real_size, m2m_id);
            }
            else
                tr_error("KEY_CONNECTOR_URL failed.");
        }

        // Endpoint
        if (success) {
            success = false;
            if (get_config_parameter(g_fcc_endpoint_parameter_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                tr_info("ConnectorClient::create_register_object - endpoint name %.*s", (int)real_size, buffer);
                success = true;
                _endpoint_info.endpoint_name = String((const char*)buffer, real_size);
            }
            else
                tr_error("KEY_ENDPOINT_NAME failed.");
        }

        // Try to get internal endpoint name
        if (success) {
            if (get_config_parameter(KEY_INTERNAL_ENDPOINT, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                _endpoint_info.internal_endpoint_name = String((const char*)buffer, real_size);
                tr_info("Using internal endpoint name instead: %s", _endpoint_info.internal_endpoint_name.c_str());
            }
            else {
                tr_debug("KEY_INTERNAL_ENDPOINT failed.");
            }
        }

        // Account ID, not mandatory
        if (success) {
            if (get_config_parameter(KEY_ACCOUNT_ID, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                tr_info("ConnectorClient::create_register_object - AccountId %.*s", (int)real_size, buffer);
                _endpoint_info.account_id = String((const char*)buffer, real_size);
            }
            else
                tr_debug("KEY_ACCOUNT_ID failed.");
        }

        free(buffer);
        if (!success) {
            tr_error("ConnectorClient::create_register_object - Failed to read credentials");
            _callback->connector_error((M2MInterface::Error)MbedCloudClient::ConnectorFailedToReadCredentials,CREDENTIAL_ERROR);
            // TODO: what to do with the m2mserver security instance
        }
    } else {
        tr_info("ConnectorClient::create_register_object() - Credentials already exists");
    }
}

/*
*  Creates bootstrap server object with bootstrap server address and other parameters
*  required for connecting to mbed Cloud bootstrap server.
*/
bool ConnectorClient::create_bootstrap_object()
{
    tr_debug("ConnectorClient::create_bootstrap_object");
    bool success = false;

    // Check if bootstrap credentials are already stored in KCM
    if (bootstrap_credentials_stored_in_kcm() && _security) {
        if (_security->get_security_instance_id(M2MSecurity::Bootstrap) == -1) {
            _security->create_object_instance(M2MSecurity::Bootstrap);
            int32_t bs_id = _security->get_security_instance_id(M2MSecurity::Bootstrap);
            _security->set_resource_value(M2MSecurity::SecurityMode, M2MSecurity::Certificate, bs_id);
            tr_info("ConnectorClient::create_bootstrap_object - bs_id = %" PRId32, bs_id);
            tr_info("ConnectorClient::create_bootstrap_object - use credentials from storage");

            // Allocate scratch buffer, this will be used to copy parameters from storage to security object
            size_t real_size = 0;
            const int max_size = 2048;
            uint8_t *buffer = (uint8_t*)malloc(max_size);
            if (buffer != NULL) {
                success = true;
            }

            // Read internal endpoint name if it exists, we need to append
            // it to bootstrap uri if device already bootstrapped
            uint8_t *iep = NULL;
            if (success && get_config_parameter_string(KEY_INTERNAL_ENDPOINT, buffer, max_size) == CCS_STATUS_SUCCESS) {
                iep = (uint8_t*)malloc(strlen((const char*)buffer) + strlen(INTERNAL_ENDPOINT_PARAM) + 1);
                if (iep != NULL) {
                    strcpy((char*)iep, INTERNAL_ENDPOINT_PARAM);
                    strcat((char*)iep, (const char*)buffer);
                    tr_info("ConnectorClient::create_bootstrap_object - iep: %s", buffer);
                }
                //TODO: Should handle error if iep exists but allocation fails?
            }

            // Bootstrap URI
            if (success) {
                success = false;
                if (get_config_parameter_string(g_fcc_bootstrap_server_uri_name, buffer, max_size) == CCS_STATUS_SUCCESS) {
                    success = true;

                    real_size = strlen((const char*)buffer);
                    // Append iep if we 1. have it 2. it doesn't already exist in uri 3. it fits
                    if (iep &&
                        strstr((const char*)buffer, (const char*)iep) == NULL &&
                        (real_size + strlen((const char*)iep) + 1) <= max_size) {
                        strcat((char*)buffer, (const char*)iep);
                        real_size += strlen((const char*)iep) + 1;
                    }

                    tr_info("ConnectorClient::create_bootstrap_object - M2MServerUri %.*s", (int)real_size, buffer);
                    _security->set_resource_value(M2MSecurity::M2MServerUri, buffer, real_size, bs_id);
                }
            }

            free(iep);

            // Bootstrap server public key (certificate)
            if (success) {
                success = false;
                if (get_config_certificate(g_fcc_bootstrap_server_ca_certificate_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                    success = true;
                    tr_info("ConnectorClient::create_bootstrap_object - ServerPublicKey %d", (int)real_size);
                    _security->set_resource_value(M2MSecurity::ServerPublicKey, buffer, real_size, bs_id);
                }
            }

            // Bootstrap client public key (certificate)
            if (success) {
                success = false;
                if (get_config_certificate(g_fcc_bootstrap_device_certificate_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                    success = true;
                    tr_info("ConnectorClient::create_bootstrap_object - PublicKey %d", (int)real_size);
                    _security->set_resource_value(M2MSecurity::PublicKey, buffer, real_size, bs_id);
                }
            }

            // Bootstrap client private key
            if (success) {
                success = false;
                if (get_config_private_key(g_fcc_bootstrap_device_private_key_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                    success = true;
                    tr_info("ConnectorClient::create_bootstrap_object - Secretkey %d", (int)real_size);
                    _security->set_resource_value(M2MSecurity::Secretkey, buffer, real_size, bs_id);
                }
            }

            // Endpoint
            if (success) {
                success = false;
                if (get_config_parameter(g_fcc_endpoint_parameter_name, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                    success = true;
                    _endpoint_info.endpoint_name = String((const char*)buffer, real_size);
                    tr_info("ConnectorClient::create_bootstrap_object - Endpoint %s", _endpoint_info.endpoint_name.c_str());
                }
            }

            // Account ID, not mandatory
            if (success) {
                if (get_config_parameter(KEY_ACCOUNT_ID, buffer, max_size, &real_size) == CCS_STATUS_SUCCESS) {
                    _endpoint_info.account_id = String((const char*)buffer, real_size);
                    tr_info("ConnectorClient::create_bootstrap_object - AccountId %s", _endpoint_info.account_id.c_str());
                }
            }
            free(buffer);

            if (!success) {
                tr_error("ConnectorClient::create_bootstrap_object - Failed to read credentials");
                _callback->connector_error((M2MInterface::Error)MbedCloudClient::ConnectorFailedToReadCredentials,CREDENTIAL_ERROR);
                _security->remove_object_instance(bs_id);
            }
        } else {
            success = true;
            tr_info("ConnectorClient::create_bootstrap_object - bootstrap object already done");
        }
    // Device not provisioned
    } else {
        _callback->connector_error((M2MInterface::Error)MbedCloudClient::ConnectorInvalidCredentials, DEVICE_NOT_PROVISIONED);
        tr_error("ConnectorClient::create_bootstrap_object - device not provisioned!");
    }
    return success;
}

void ConnectorClient::state_bootstrap_start()
{
    tr_info("ConnectorClient::state_bootstrap_start()");
    assert(_interface != NULL);
    assert(_security != NULL);

    _interface->bootstrap(_security);

    internal_event(State_Bootstrap_Started);
}

void ConnectorClient::state_bootstrap_started()
{
    // this state may be useful only for verifying the callbacks?
}

void ConnectorClient::state_bootstrap_success()
{
    assert(_callback != NULL);
    // Parse internal endpoint name from mDS cert
    _callback->registration_process_result(State_Bootstrap_Success);
}

void ConnectorClient::state_bootstrap_failure()
{
    assert(_callback != NULL);
    // maybe some additional canceling and/or leanup is needed here?
    _callback->registration_process_result(State_Bootstrap_Failure);
}

void ConnectorClient::state_registration_start()
{
    tr_info("ConnectorClient::state_registration_start()");
    assert(_interface != NULL);
    assert(_security != NULL);
    _interface->register_object(_security, *_client_objs);
    internal_event(State_Registration_Started);
}

void ConnectorClient::state_registration_started()
{
    // this state may be useful only for verifying the callbacks?
}

void ConnectorClient::state_registration_success()
{
    assert(_callback != NULL);
    _endpoint_info.internal_endpoint_name = _interface->internal_endpoint_name();

    //The endpoint is maximum 32 character long, we put bigger buffer for future extensions
    const int max_size = 64;
    uint8_t buffer[max_size];

    bool no_param_update = true;

    if(get_config_parameter_string(KEY_INTERNAL_ENDPOINT, buffer, max_size) == CCS_STATUS_SUCCESS) {
        if (strcmp((const char*)buffer, _endpoint_info.internal_endpoint_name.c_str()) != 0) {
            // Update is required as the stored KCM entry is different than _endpoint_info.internal_endpoint_name.
            no_param_update = false;
        }
    }

    // Update INTERNAL_ENDPOINT setting only if there is no such entry or the value is not matching the
    // _endpoint_info.internal_endpoint_name.
    if(!no_param_update) {
        delete_config_parameter(KEY_INTERNAL_ENDPOINT);
        set_config_parameter(KEY_INTERNAL_ENDPOINT, (const uint8_t*)_endpoint_info.internal_endpoint_name.c_str(),
                             (size_t)_endpoint_info.internal_endpoint_name.size());
    }

    _callback->registration_process_result(State_Registration_Success);
}

void ConnectorClient::state_registration_failure()
{
    assert(_callback != NULL);
    // maybe some additional canceling and/or leanup is needed here?
    _callback->registration_process_result(State_Registration_Failure);
}

void ConnectorClient::state_unregistered()
{
    assert(_callback != NULL);
    _callback->registration_process_result(State_Unregistered);
}

void ConnectorClient::bootstrap_done(M2MSecurity *security_object)
{
    tr_info("ConnectorClient::bootstrap_done");
    ccs_status_e status = CCS_STATUS_ERROR;
    StartupSubStateRegistration state = State_Bootstrap_Success;
    if(security_object) {
        // Update bootstrap credentials (we could skip this if we knew whether they were updated)
        // This will also update the address in case of first to claim
        status = set_bootstrap_credentials(security_object);
        if (status != CCS_STATUS_SUCCESS) {
            // TODO: what now?
            tr_error("ConnectorClient::bootstrap_done - couldn't store bootstrap credentials");
        }

        // Clear the first to claim flag if it's active
        if (is_first_to_claim()) {
            status = clear_first_to_claim();
            if (status != CCS_STATUS_SUCCESS) {
                // TODO: what now?
                tr_error("ConnectorClient::bootstrap_done - couldn't clear first to claim flag!");
            }
        }

        // Bootstrap might delete m2mserver security object instance completely to force bootstrap
        // with new credentials, in that case delete the stored lwm2m credentials as well and re-bootstrap
        if (security_object->get_security_instance_id(M2MSecurity::M2MServer) == -1) {
            tr_info("ConnectorClient::bootstrap_done() - Clearing lwm2m credentials");
            // delete the old connector credentials when BS sends re-direction.
            delete_config_parameter(g_fcc_lwm2m_server_uri_name);
            delete_config_certificate(g_fcc_lwm2m_server_ca_certificate_name);
            delete_config_certificate(g_fcc_lwm2m_device_certificate_name);
            delete_config_private_key(g_fcc_lwm2m_device_private_key_name);
            // Start re-bootstrap timer
            tr_info("ConnectorClient::bootstrap_done() - Re-directing bootstrap in 100 milliseconds");
            _rebootstrap_timer.start_timer(100, M2MTimerObserver::BootstrapFlowTimer, true);
            return;
        }
        // Bootstrap wrote M2MServer credentials, store them and also update first to claim status if it's configured
        else {
            tr_info("ConnectorClient::bootstrap_done() - Storing lwm2m credentials");
            status = set_connector_credentials(security_object);
        }
    }
    if (status != CCS_STATUS_SUCCESS) {
        internal_event(State_Bootstrap_Failure);
        //Failed to store credentials, bootstrap failed
        _callback->connector_error(M2MInterface::MemoryFail, ERROR_NO_MEMORY); // Translated to error code ConnectMemoryConnectFail
        return;
    } else {
        tr_error("ConnectorClient::bootstrap_done - set_credentials status %d", status);
    }
    internal_event(state);
}

void ConnectorClient::object_registered(M2MSecurity *security_object, const M2MServer &server_object)
{
    internal_event(State_Registration_Success);
}

void ConnectorClient::object_unregistered(M2MSecurity *server_object)
{
    internal_event(State_Unregistered);
}

void ConnectorClient::registration_updated(M2MSecurity *security_object, const M2MServer & server_object)
{
    _callback->registration_process_result(State_Registration_Updated);
}

void ConnectorClient::error(M2MInterface::Error error)
{
    tr_error("ConnectorClient::error() - error: %d", error);
    assert(_callback != NULL);
    if (_current_state >= State_Registration_Start &&
            use_bootstrap() &&
            (error == M2MInterface::SecureConnectionFailed ||
            error == M2MInterface::InvalidParameters)) {
        tr_info("ConnectorClient::error() - Error during lwm2m registration");
        tr_info("ConnectorClient::error() - Clearing lwm2m credentials");
        // delete the old connector credentials when DTLS handshake fails or
        // server rejects the registration.
        delete_config_parameter(g_fcc_lwm2m_server_uri_name);
        delete_config_certificate(g_fcc_lwm2m_server_ca_certificate_name);
        delete_config_certificate(g_fcc_lwm2m_device_certificate_name);
        delete_config_private_key(g_fcc_lwm2m_device_private_key_name);
        // Delete the lwm2m security instance
        int32_t id = _security->get_security_instance_id(M2MSecurity::M2MServer);
        if (id >= 0) {
            _security->remove_object_instance(id);
        }
        // Delete bootstrap security instance
        id = _security->get_security_instance_id(M2MSecurity::Bootstrap);
        if (id >= 0) {
            _security->remove_object_instance(id);
        }
        // Start re-bootstrap timer
        tr_info("ConnectorClient::error() - Re-bootstrapping in 100 milliseconds");
        _rebootstrap_timer.start_timer(100, M2MTimerObserver::BootstrapFlowTimer, true);
    }
    else {
        _callback->connector_error(error, _interface->error_description());
    }
}

void ConnectorClient::value_updated(M2MBase *base, M2MBase::BaseType type)
{
    assert(_callback != NULL);
    _callback->value_updated(base, type);
}

bool ConnectorClient::connector_credentials_available()
{
    tr_debug("ConnectorClient::connector_credentials_available");
    const int max_size = 2048;
    uint8_t *buffer = (uint8_t*)malloc(max_size);
    size_t real_size = 0;
    get_config_private_key(g_fcc_lwm2m_device_private_key_name, buffer, max_size, &real_size);
    free(buffer);
    if (real_size > 0) {
        return true;
    }
    return false;
}

bool ConnectorClient::use_bootstrap()
{
    tr_debug("ConnectorClient::use_bootstrap");
    const int max_size = 32;
    uint8_t *buffer = (uint8_t*)malloc(max_size);
    bool ret = false;
    if (buffer != NULL) {
        memset(buffer, 0, max_size);
        size_t real_size = 0;
        ccs_status_e status = get_config_parameter(g_fcc_use_bootstrap_parameter_name, buffer, max_size, &real_size);
        if (status == CCS_STATUS_SUCCESS && real_size > 0 && buffer[0] > 0) {
            ret = true;
        }
        free(buffer);
    }
    return ret;
}


bool ConnectorClient::get_key(const char *key, const char *endpoint, char *&key_name)
{
    if(key_name) {
        free(key_name);
        key_name = NULL;
    }

    key_name = (char*)malloc(strlen(key)+strlen(endpoint)+1);
    if(key_name) {
        strcpy(key_name, key);
        strcat(key_name, endpoint);
        tr_debug("key %s", key_name);
        return true;
    }
    return false;
}

ccs_status_e ConnectorClient::set_connector_credentials(M2MSecurity *security)
{
    tr_debug("ConnectorClient::set_connector_credentials");
    ccs_status_e status = CCS_STATUS_ERROR;

    const uint8_t *srv_public_key = NULL;
    const uint8_t *public_key = NULL;
    const uint8_t *sec_key = NULL;

    int32_t m2m_id = security->get_security_instance_id(M2MSecurity::M2MServer);
    if (m2m_id == -1) {
        return status;
    }

    uint32_t srv_public_key_size = security->resource_value_buffer(M2MSecurity::ServerPublicKey, srv_public_key, m2m_id);
    uint32_t public_key_size = security->resource_value_buffer(M2MSecurity::PublicKey, public_key, m2m_id);
    uint32_t sec_key_size = security->resource_value_buffer(M2MSecurity::Secretkey, sec_key, m2m_id);

    if(srv_public_key && public_key && sec_key) {
        // Parse common name
        char common_name[64];
        memset(common_name, 0, 64);
        if (extract_cn_from_certificate(public_key, public_key_size, common_name)){
            tr_info("ConnectorClient::set_connector_credentials - CN: %s", common_name);
            _endpoint_info.internal_endpoint_name = String(common_name);
            delete_config_parameter(KEY_INTERNAL_ENDPOINT);
            status = set_config_parameter(KEY_INTERNAL_ENDPOINT,(uint8_t*)common_name, strlen(common_name));
        }

        if(status == CCS_STATUS_SUCCESS) {
            delete_config_certificate(g_fcc_lwm2m_server_ca_certificate_name);
            status = set_config_certificate(g_fcc_lwm2m_server_ca_certificate_name,
                                            srv_public_key,
                                            (size_t)srv_public_key_size);
        }
        if(status == CCS_STATUS_SUCCESS) {
            status = set_config_certificate(g_fcc_lwm2m_device_certificate_name,
                                            public_key,
                                            (size_t)public_key_size);
        }
        if(status == CCS_STATUS_SUCCESS) {
            status = set_config_private_key(g_fcc_lwm2m_device_private_key_name,
                                            sec_key,
                                            (size_t)sec_key_size);
        }

        if(status == CCS_STATUS_SUCCESS) {
            delete_config_parameter(KEY_ACCOUNT_ID);
            // AccountID optional so don't fail if unable to store
            set_config_parameter(KEY_ACCOUNT_ID,
                                 (const uint8_t*)_endpoint_info.account_id.c_str(),
                                 (size_t)_endpoint_info.account_id.size());
        }
        if(status == CCS_STATUS_SUCCESS) {
            status = set_config_parameter(g_fcc_lwm2m_server_uri_name,
                                          (const uint8_t*)security->resource_value_string(M2MSecurity::M2MServerUri, m2m_id).c_str(),
                                          (size_t)security->resource_value_string(M2MSecurity::M2MServerUri, m2m_id).size());
        }
        M2MDevice *device = M2MInterfaceFactory::create_device();
        if (device) {
            String temp = "";
            uint32_t currenttime = (uint32_t)device->resource_value_int(M2MDevice::CurrentTime, 0);
            uint8_t data[4];
            memcpy(data, &currenttime, 4);
            delete_config_parameter(g_fcc_current_time_parameter_name);
            set_config_parameter(g_fcc_current_time_parameter_name, data, 4);

            temp = device->resource_value_string(M2MDevice::Timezone, 0);
            delete_config_parameter(g_fcc_device_time_zone_parameter_name);
            set_config_parameter(g_fcc_device_time_zone_parameter_name, (const uint8_t*)temp.c_str(), temp.size());

            temp = device->resource_value_string(M2MDevice::UTCOffset, 0);
            delete_config_parameter(g_fcc_offset_from_utc_parameter_name);
            set_config_parameter(g_fcc_offset_from_utc_parameter_name, (const uint8_t*)temp.c_str(), temp.size());

            status = CCS_STATUS_SUCCESS;
        }
        else {
            tr_debug("No device object to store!");
        }
    }

    return status;
}

ccs_status_e ConnectorClient::set_bootstrap_credentials(M2MSecurity *security)
{
    tr_debug("ConnectorClient::set_bootstrap_credentials");
    ccs_status_e status = CCS_STATUS_ERROR;

    const uint8_t *srv_public_key = NULL;
    const uint8_t *public_key = NULL;
    const uint8_t *sec_key = NULL;

    int32_t bs_id = security->get_security_instance_id(M2MSecurity::Bootstrap);
    if (bs_id == -1) {
        return status;
    }

    uint32_t srv_public_key_size = security->resource_value_buffer(M2MSecurity::ServerPublicKey, srv_public_key, bs_id);
    uint32_t public_key_size = security->resource_value_buffer(M2MSecurity::PublicKey, public_key, bs_id);
    uint32_t sec_key_size = security->resource_value_buffer(M2MSecurity::Secretkey, sec_key, bs_id);

    if(srv_public_key && public_key && sec_key) {
        delete_config_certificate(g_fcc_bootstrap_server_ca_certificate_name);
        status = set_config_certificate(g_fcc_bootstrap_server_ca_certificate_name,
                                            srv_public_key,
                                            (size_t)srv_public_key_size);
        if(status == CCS_STATUS_SUCCESS) {
            delete_config_certificate(g_fcc_bootstrap_device_certificate_name);
            status = set_config_certificate(g_fcc_bootstrap_device_certificate_name,
                                            public_key,
                                            (size_t)public_key_size);
        }
        if(status == CCS_STATUS_SUCCESS) {
            delete_config_private_key(g_fcc_bootstrap_device_private_key_name);
            status = set_config_private_key(g_fcc_bootstrap_device_private_key_name,
                                            sec_key,
                                            (size_t)sec_key_size);
        }
        if(status == CCS_STATUS_SUCCESS) {
            delete_config_parameter(g_fcc_bootstrap_server_uri_name);
            status = set_config_parameter(g_fcc_bootstrap_server_uri_name,
                                          (const uint8_t*)security->resource_value_string(M2MSecurity::M2MServerUri, bs_id).c_str(),
                                          (size_t)security->resource_value_string(M2MSecurity::M2MServerUri, bs_id).size());
        }
    }

    return status;
}

ccs_status_e ConnectorClient::store_bootstrap_address(M2MSecurity *security)
{
    tr_debug("ConnectorClient::store_bootstrap_address");
    ccs_status_e status = CCS_STATUS_ERROR;

    const uint8_t *srv_address = NULL;
    int32_t bs_id = security->get_security_instance_id(M2MSecurity::Bootstrap);
    if (bs_id == -1) {
        return status;
    }

    uint32_t srv_address_size = security->resource_value_buffer(M2MSecurity::M2MServerUri, srv_address, bs_id);

    if(srv_address) {
        delete_config_parameter(g_fcc_bootstrap_server_uri_name);
        status = set_config_parameter(g_fcc_bootstrap_server_uri_name,
                                      srv_address,
                                      (size_t)srv_address_size);
    }

    return status;
}

ccs_status_e ConnectorClient::clear_first_to_claim()
{
    tr_debug("ConnectorClient::clear_first_to_claim");
    return delete_config_parameter(KEY_FIRST_TO_CLAIM);
}


const ConnectorClientEndpointInfo *ConnectorClient::endpoint_info() const
{
    return &_endpoint_info;
}

bool ConnectorClient::bootstrap_credentials_stored_in_kcm()
{
    size_t real_size = 0;
    ccs_status_e success = size_config_parameter(g_fcc_bootstrap_server_uri_name, &real_size);
    // Return true if bootstrap uri exists in KCM
    if ((success == CCS_STATUS_SUCCESS) && real_size > 0) {
        return true;
    } else {
        return false;
    }
}

bool ConnectorClient::is_first_to_claim()
{
    size_t real_size = 0;
    uint8_t data[4] = {0};
    uint32_t value = 0;
    ccs_status_e status = get_config_parameter(KEY_FIRST_TO_CLAIM, data, 4, &real_size);
    if (status == CCS_STATUS_SUCCESS) {
        memcpy(&value, data, 4);
        // Return true if bootstrap uri exists in KCM
        if (value == 1) {
            return true;
        }
    }
    return false;
}

void ConnectorClient::timer_expired(M2MTimerObserver::Type type)
{
    if (type == M2MTimerObserver::BootstrapFlowTimer) {
        start_bootstrap();
    }
}

M2MInterface::BindingMode ConnectorClient::transport_mode()
{
#ifdef MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP
    return M2MInterface::UDP;
#elif defined MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP
    return M2MInterface::TCP;
#elif defined MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
    return M2MInterface::UDP_QUEUE;
#elif defined MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE
    return M2MInterface::TCP_QUEUE;
#else
    return M2MInterface::UDP;
#endif
}
