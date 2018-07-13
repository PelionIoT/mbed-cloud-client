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
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-trace/mbed_trace.h"
#include "factory_configurator_client.h"
#include "key_config_manager.h"
#include "mbed-client/uriqueryparser.h"

#include <assert.h>
#include <string>
#include <stdio.h>

#include "ns_hal_init.h"

#ifdef MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE
#define MBED_CLIENT_EVENT_LOOP_SIZE MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE
#else
#define MBED_CLIENT_EVENT_LOOP_SIZE 1024
#endif

#define TRACE_GROUP "mClt"

#define INTERNAL_ENDPOINT_PARAM     "&iep="
#define DEFAULT_ENDPOINT            "endpoint"
#define INTERFACE_ERROR             "Client interface is not created. Restart"
#define CREDENTIAL_ERROR            "Failed to read credentials from storage"
#define DEVICE_NOT_PROVISIONED      "Device not provisioned"
#define ERROR_NO_MEMORY             "Not enough memory to store LWM2M credentials"

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
#define ERROR_EST_ENROLLMENT_REQUEST_FAILED   "EST enrollment request failed"
#define LWM2M_CSR_SUBJECT_FORMAT              "L=%s,OU=%s,CN=%s"
#endif

// XXX: nothing here yet
class EventData {

};

static int read_callback_helper(const char *key, void *buffer, size_t *buffer_len)
{
    size_t cert_size = 0;
    if (strcmp(key, g_fcc_lwm2m_device_private_key_name) == 0 ||
        strcmp(key, g_fcc_bootstrap_device_private_key_name) == 0) {
        if (ccs_item_size(key, buffer_len, CCS_PRIVATE_KEY_ITEM) != CCS_STATUS_SUCCESS) {
            *buffer_len = 0;
            return CCS_STATUS_ERROR;
        }

        if (ccs_get_item(key, (uint8_t*)buffer, *buffer_len, &cert_size, CCS_PRIVATE_KEY_ITEM) != CCS_STATUS_SUCCESS) {
            *buffer_len = 0;
            return CCS_STATUS_ERROR;
        }
    } else {
        if (ccs_item_size(key, buffer_len, CCS_CERTIFICATE_ITEM) != CCS_STATUS_SUCCESS) {
            *buffer_len = 0;
            return CCS_STATUS_ERROR;
        }

        if (ccs_get_item(key, (uint8_t*)buffer, *buffer_len, &cert_size, CCS_CERTIFICATE_ITEM) != CCS_STATUS_SUCCESS) {
            *buffer_len = 0;
            return CCS_STATUS_ERROR;
        }
    }

    *buffer_len = cert_size;

    return CCS_STATUS_SUCCESS;
}

static bool write_security_object_data_to_kcm(const M2MResourceBase& resource, const uint8_t *buffer, const size_t buffer_size, void */*client_args*/)
{
    ccs_status_e status = CCS_STATUS_ERROR;
    uint32_t resource_id = resource.name_id();
    uint16_t object_instance_id = resource.object_instance_id();

    switch (resource_id) {
        case M2MSecurity::PublicKey:
            if (object_instance_id == M2MSecurity::Bootstrap) {
                ccs_delete_item(g_fcc_bootstrap_device_certificate_name, CCS_CERTIFICATE_ITEM);
                status = ccs_set_item(g_fcc_bootstrap_device_certificate_name, buffer, buffer_size, CCS_CERTIFICATE_ITEM);
            } else {
                ccs_delete_item(g_fcc_lwm2m_device_certificate_name, CCS_CERTIFICATE_ITEM);
                status = ccs_set_item(g_fcc_lwm2m_device_certificate_name, buffer, buffer_size, CCS_CERTIFICATE_ITEM);
            }
            break;

        case M2MSecurity::ServerPublicKey:
            if (object_instance_id == M2MSecurity::Bootstrap) {
                ccs_delete_item(g_fcc_bootstrap_server_ca_certificate_name, CCS_CERTIFICATE_ITEM);
                status = ccs_set_item(g_fcc_bootstrap_server_ca_certificate_name, buffer, buffer_size, CCS_CERTIFICATE_ITEM);
            } else {
                ccs_delete_item(g_fcc_lwm2m_server_ca_certificate_name, CCS_CERTIFICATE_ITEM);
                status = ccs_set_item(g_fcc_lwm2m_server_ca_certificate_name, buffer, buffer_size, CCS_CERTIFICATE_ITEM);
            }
            break;

        case M2MSecurity::Secretkey:
            if (object_instance_id == M2MSecurity::Bootstrap) {
                ccs_delete_item(g_fcc_bootstrap_device_private_key_name, CCS_PRIVATE_KEY_ITEM);
                status = ccs_set_item(g_fcc_bootstrap_device_private_key_name, buffer, buffer_size, CCS_PRIVATE_KEY_ITEM);
            } else {
                ccs_delete_item(g_fcc_lwm2m_device_private_key_name, CCS_PRIVATE_KEY_ITEM);
                status = ccs_set_item(g_fcc_lwm2m_device_private_key_name, buffer, buffer_size, CCS_PRIVATE_KEY_ITEM);
            }
            break;

        default:
            break;
    }

    return (status == CCS_STATUS_SUCCESS) ? true : false;
}

static int read_security_object_data_from_kcm(const M2MResourceBase& resource, void *buffer, size_t *buffer_len, void */*client_args*/)
{
    uint32_t resource_id = resource.name_id();
    uint16_t object_instance_id = resource.object_instance_id();
    switch (resource_id) {
        case M2MSecurity::PublicKey:
            if (object_instance_id == M2MSecurity::Bootstrap) {
                return read_callback_helper(g_fcc_bootstrap_device_certificate_name, buffer, buffer_len);
            } else {
                return read_callback_helper(g_fcc_lwm2m_device_certificate_name, buffer, buffer_len);
            }

        case M2MSecurity::ServerPublicKey:
            if (object_instance_id == M2MSecurity::Bootstrap) {
                return read_callback_helper(g_fcc_bootstrap_server_ca_certificate_name, buffer, buffer_len);
            } else {
                return read_callback_helper(g_fcc_lwm2m_server_ca_certificate_name, buffer, buffer_len);
            }

        case M2MSecurity::Secretkey:
            if (object_instance_id == M2MSecurity::Bootstrap) {
                return read_callback_helper(g_fcc_bootstrap_device_private_key_name, buffer, buffer_len);
            } else {
                return read_callback_helper(g_fcc_lwm2m_device_private_key_name, buffer, buffer_len);
            }

        default:
            break;
    }

    return CCS_STATUS_ERROR;
}

static int open_certificate_chain_callback(const M2MResourceBase& resource, void */*buffer*/, size_t *chain_size, void *client_args)
{
    void *handle = NULL;
    uint16_t object_instance_id = resource.object_instance_id();
    ConnectorClient *client = (ConnectorClient*)client_args;
    if (object_instance_id == M2MSecurity::Bootstrap) {
        handle = ccs_open_certificate_chain(g_fcc_bootstrap_device_certificate_name, chain_size);
        client->set_certificate_chain_handle(handle);
    } else {
        handle = ccs_open_certificate_chain(g_fcc_lwm2m_device_certificate_name, chain_size);
        client->set_certificate_chain_handle(handle);
    }

    return (handle) ? CCS_STATUS_SUCCESS : CCS_STATUS_ERROR;
}

static int read_certificate_chain_callback(const M2MResourceBase& /*resource*/, void *buffer, size_t *buffer_len, void *client_args)
{
    ConnectorClient *client = (ConnectorClient*) client_args;
    ccs_status_e status = CCS_STATUS_ERROR;
    if (client->certificate_chain_handle()) {
        status = ccs_get_next_cert_chain(client->certificate_chain_handle(), buffer, buffer_len);
    }

    return status;
}

static int close_certificate_chain_callback(const M2MResourceBase& /*resource*/, void */*buffer*/, size_t *, void *client_args)
{
    ccs_status_e status = CCS_STATUS_ERROR;
    ConnectorClient *client = (ConnectorClient*) client_args;
    if (client->certificate_chain_handle()) {
        status = ccs_close_certificate_chain(client->certificate_chain_handle());
        client->set_certificate_chain_handle(NULL);
    }
    return status;
}

ConnectorClient::ConnectorClient(ConnectorClientCallback* callback)
: _callback(callback),
  _current_state(State_Bootstrap_Start),
  _event_generated(false), _state_engine_running(false),
  _interface(NULL), _security(NULL),
  _endpoint_info(M2MSecurity::Certificate), _client_objs(NULL),
  _rebootstrap_timer(*this), _bootstrap_security_instance(1), _lwm2m_security_instance(0), _certificate_chain_handle(NULL)
{
    assert(_callback != NULL);

    // XXX: this initialization sequence needs more work, as doing the allocations
    // and static initializations from constructor is really troublesome.
    // All this needs to be moved to the separate setup() call.

    // The ns_hal_init() needs to be called by someone before create_interface(),
    // as it will also initialize the tasklet.
    ns_hal_init(NULL, MBED_CLIENT_EVENT_LOOP_SIZE, NULL, NULL);

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
    init_security_object();
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

void ConnectorClient::start_registration(M2MBaseList* client_objs)
{
    tr_debug("ConnectorClient::start_registration()");
    assert(_callback != NULL);
    init_security_object();
    _client_objs = client_objs;

    // XXX: actually this call should be external_event() to match the pattern used in other m2m classes
    create_register_object();
    if(_security->get_security_instance_id(M2MSecurity::M2MServer) >= 0) {
        _interface->update_endpoint(_endpoint_info.endpoint_name);
        _interface->update_domain(_endpoint_info.account_id);
        internal_event(State_Registration_Start);
    } else {
        tr_error("ConnectorClient::start_registration(): failed to create objs");
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
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
        case State_EST_Start:
            state_est_start();
            break;
        case State_EST_Started:
            state_est_started();
            break;
        case State_EST_Success:
            state_est_success();
            break;
        case State_EST_Failure:
            state_est_failure();
            break;
#endif // !MBED_CLIENT_DISABLE_EST_FEATURE
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
    int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
    if (m2m_id == -1) {
        init_security_object();
    }

    m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
    _security->set_resource_value(M2MSecurity::BootstrapServer, M2MSecurity::M2MServer, m2m_id);

    // Add ResourceID's and values to the security ObjectID/ObjectInstance
    _security->set_resource_value(M2MSecurity::SecurityMode, _endpoint_info.mode, m2m_id);

    // Allocate scratch buffer, this will be used to copy parameters from storage to security object
    const int max_size = MAX_CERTIFICATE_SIZE;
    uint8_t *buffer = (uint8_t*)malloc(max_size);
    size_t real_size = 0;
    bool success = false;

    if (buffer != NULL) {
        success = true;
    }
    else {
        tr_error("ConnectorClient::create_register_object - Temporary certificate buffer allocation failed!");
    }

    // Endpoint
    if (success) {
        success = false;
        char device_id[64];

        size_t cert_size = max_size;
        uint8_t certificate[MAX_CERTIFICATE_SIZE];
        uint8_t *certificate_ptr = (uint8_t*)&certificate;

        // TODO! Update to use chain api
        _security->resource_value_buffer(M2MSecurity::PublicKey, certificate_ptr, m2m_id, &cert_size);
        real_size = cert_size;
        if (extract_field_from_certificate((uint8_t*)certificate, real_size, "CN", device_id)) {
            tr_info("ConnectorClient::create_register_object - CN - endpoint_name : %s", device_id);
            _endpoint_info.endpoint_name = String(device_id);
            success = true;
        } else {
            tr_error("KEY_ENDPOINT_NAME failed.");
        }
    }

    // Connector URL
    if (success) {
        success = false;
        if (ccs_get_item(g_fcc_lwm2m_server_uri_name, buffer, max_size, &real_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
            tr_info("ConnectorClient::create_register_object - M2MServerUri %.*s", (int)real_size, buffer);
            success = true;
            _security->set_resource_value(M2MSecurity::M2MServerUri, buffer, (uint32_t)real_size, m2m_id);
        }
        else
            tr_error("KEY_CONNECTOR_URL failed.");
    }

    // Try to get internal endpoint name
    if (success) {
        if (ccs_get_item(KEY_INTERNAL_ENDPOINT, buffer, max_size, &real_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
            _endpoint_info.internal_endpoint_name = String((const char*)buffer, real_size);
            tr_info("ConnectorClient::create_register_object - internal endpoint name : %s", _endpoint_info.internal_endpoint_name.c_str());
        }
        else {
            tr_debug("KEY_INTERNAL_ENDPOINT failed.");
        }
    }

    // Account ID, not mandatory
    if (success) {
        if (ccs_get_item(KEY_ACCOUNT_ID, buffer, max_size, &real_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
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
        int32_t bs_id = _security->get_security_instance_id(M2MSecurity::Bootstrap);
        _security->set_resource_value(M2MSecurity::SecurityMode, M2MSecurity::Certificate, bs_id);

        tr_info("ConnectorClient::create_bootstrap_object - bs_id = %" PRId32, bs_id);
        tr_info("ConnectorClient::create_bootstrap_object - use credentials from storage");

        // Allocate scratch buffer, this will be used to copy parameters from storage to security object
        size_t real_size = 0;
        const int max_size = MAX_CERTIFICATE_SIZE;
        uint8_t *buffer = (uint8_t*)malloc(max_size);
        if (buffer != NULL) {
            success = true;
        }
        else {
            tr_error("ConnectorClient::create_bootstrap_object - Temporary certificate buffer allocation failed!");
        }

        // Read internal endpoint name if it exists, we need to append
        // it to bootstrap uri if device already bootstrapped
        uint8_t *iep = NULL;
        if (success && ccs_get_string_item(KEY_INTERNAL_ENDPOINT, buffer, max_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
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
            if (ccs_get_string_item(g_fcc_bootstrap_server_uri_name, buffer, max_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
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

        // Endpoint
        if (success) {
            success = false;
            if (ccs_get_item(g_fcc_endpoint_parameter_name, buffer, max_size, &real_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
                success = true;
                _endpoint_info.endpoint_name = String((const char*)buffer, real_size);
                tr_info("ConnectorClient::create_bootstrap_object - Endpoint %s", _endpoint_info.endpoint_name.c_str());
            }
        }

        // Account ID, not mandatory
        if (success) {
            if (ccs_get_item(KEY_ACCOUNT_ID, buffer, max_size, &real_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
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

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
void ConnectorClient::state_est_start()
{
    // - Generate CSR from data during bootstrap phase
    // - Call EST enrollment API from InterfaceImpl

    // Update the internal endpoint name and account id to endpoint info structure
    // as we get those during bootstrap phase
    _endpoint_info.internal_endpoint_name = _interface->internal_endpoint_name();

    int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
    uint32_t sec_mode = M2MSecurity::SecurityNotSet;
    if (m2m_id >= 0) {
        sec_mode = _security->resource_value_int(M2MSecurity::SecurityMode, m2m_id);

        // We need to parse account id from lwm2m server uri query if it is not yet
        // set in endpoint info structure
        if (_endpoint_info.account_id.length() <= 0) {
            String address = _security->resource_value_string(M2MSecurity::M2MServerUri, m2m_id);
            tr_debug("ConnectorClient::state_est_start - address: %s", address.c_str());
            if (address.size() > 0) {
                const char *aid = NULL;
                const int aid_size = parse_query_parameter_value_from_uri((const char*)address.c_str(), QUERY_PARAM_AID, &aid);
                if (aid_size > 0) {
                    _endpoint_info.account_id.append_raw(aid, aid_size);
                }
            }
        }
    }

    tr_debug("ConnectorClient::state_est_start - security instance id: %" PRId32, m2m_id);
    tr_debug("ConnectorClient::state_est_start - ep: %s", _endpoint_info.internal_endpoint_name.c_str());
    tr_debug("ConnectorClient::state_est_start - iep: %s", _endpoint_info.endpoint_name.c_str());
    tr_debug("ConnectorClient::state_est_start - aid: %s", _endpoint_info.account_id.c_str());

    // Check EST required parameters are in place
    if (m2m_id < 0 ||
        _endpoint_info.endpoint_name.length() <= 0 ||
        _endpoint_info.internal_endpoint_name.length() <= 0 ||
        _endpoint_info.account_id.length() <= 0) {
        tr_error("ConnectorClient::state_est_start - Missing parameters for EST enrollment!");
        internal_event(State_EST_Failure);
        return;
    }

    uint32_t is_bs_server = _security->resource_value_int(M2MSecurity::BootstrapServer, m2m_id);
    size_t public_key_size = MAX_CERTIFICATE_SIZE;
    size_t server_key_size = MAX_CERTIFICATE_SIZE;
    size_t private_key_size = MAX_CERTIFICATE_SIZE;

    // Temp buffer for storing CSR and certificates
    uint8_t *buffer = (uint8_t*)malloc(MAX_CERTIFICATE_SIZE);
    size_t real_size = 0;
    if (buffer == NULL) {
        tr_error("ConnectorClient::state_est_start - Allocating temp buffer failed!");
        internal_event(State_EST_Failure);
        return;
    }
    uint8_t *buffer_ptr = buffer;

    // TODO! Update to use chain api
    if (_security->resource_value_buffer(M2MSecurity::PublicKey, buffer_ptr, m2m_id, &public_key_size) != 0) {
        public_key_size = 0;
    }
    if (_security->resource_value_buffer(M2MSecurity::ServerPublicKey, buffer_ptr, m2m_id, &server_key_size) != 0) {
        server_key_size = 0;
    }
    if (_security->resource_value_buffer(M2MSecurity::Secretkey, buffer_ptr, m2m_id, &private_key_size) != 0) {
        private_key_size = 0;
    }

    tr_info("est check - is bs server /0/1: %" PRIu32, is_bs_server);
    tr_info("est check - Security Mode /0/2: %" PRIu32, sec_mode);
    tr_info("est check - Public key size /0/3: %" PRIu32, public_key_size);
    tr_info("est check - Server Public key size /0/4: %" PRIu32, server_key_size);
    tr_info("est check - Secret key size /0/5: %" PRIu32, private_key_size);

    // Configure CSR params
    kcm_csr_params_s csr_params;
    int subject_size = snprintf(NULL, 0, LWM2M_CSR_SUBJECT_FORMAT,
                                _endpoint_info.internal_endpoint_name.c_str(),
                                _endpoint_info.account_id.c_str(),
                                _endpoint_info.endpoint_name.c_str());
    if (subject_size <= 0) {
        tr_error("ConnectorClient::state_est_start - CSR Subject formatting failed!");
        free(buffer);
        internal_event(State_EST_Failure);
        return;
    }

    // For null-terminator
    subject_size++;

    csr_params.subject = (char*)malloc(subject_size);
    if (csr_params.subject == NULL) {
        tr_error("ConnectorClient::state_est_start - CSR Subject formatting failed!");
        free(buffer);
        internal_event(State_EST_Failure);
        return;
    }

    snprintf(csr_params.subject, subject_size, LWM2M_CSR_SUBJECT_FORMAT,
             _endpoint_info.internal_endpoint_name.c_str(),
             _endpoint_info.account_id.c_str(),
             _endpoint_info.endpoint_name.c_str());

    tr_debug("est csr subject '%s'", csr_params.subject);

    csr_params.md_type = KCM_MD_SHA256;
    csr_params.key_usage = KCM_CSR_KU_NONE;
    csr_params.ext_key_usage = KCM_CSR_EXT_KU_NONE;

    kcm_status_e status = kcm_generate_keys_and_csr(KCM_SCHEME_EC_SECP256R1,
                                                    (const uint8_t*)g_fcc_lwm2m_device_private_key_name,
                                                    strlen(g_fcc_lwm2m_device_private_key_name),
                                                    NULL,
                                                    0,
                                                    false,
                                                    &csr_params,
                                                    buffer,
                                                    MAX_CERTIFICATE_SIZE,
                                                    &real_size,
                                                    NULL);

    free(csr_params.subject);

    if (status != KCM_STATUS_SUCCESS) {
        tr_error("ConnectorClient::state_est_start - Generating keys and csr failed!");
        free(buffer);
        internal_event(State_EST_Failure);
        return;
    }

    // Update state and start the enrollment by sending the enroll request
    internal_event(State_EST_Started);
    _interface->post_data_request("est/sen",
                                 false,
                                 real_size,
                                 buffer,
                                 ConnectorClient::est_post_data_cb,
                                 ConnectorClient::est_post_data_error_cb,
                                 this);

    free(buffer);
}

void ConnectorClient::state_est_started()
{
}

void ConnectorClient::state_est_success()
{
    tr_info("ConnectorClient::state_est_success()");
    _interface->finish_bootstrap();
}

void ConnectorClient::state_est_failure()
{
    tr_info("ConnectorClient::state_est_failure()");
    internal_event(State_Bootstrap_Failure);
    //Failed to store credentials, bootstrap failed
    _callback->connector_error(M2MInterface::ESTEnrollmentFailed, ERROR_EST_ENROLLMENT_REQUEST_FAILED); // Translated to error code ConnectMemoryConnectFail
}
#endif /* !MBED_CLIENT_DISABLE_EST_FEATURE */

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

    if(ccs_get_string_item(KEY_INTERNAL_ENDPOINT, buffer, max_size, CCS_CONFIG_ITEM) == CCS_STATUS_SUCCESS) {
        if (strcmp((const char*)buffer, _endpoint_info.internal_endpoint_name.c_str()) != 0) {
            // Update is required as the stored KCM entry is different than _endpoint_info.internal_endpoint_name.
            no_param_update = false;
        }
    }

    // Update INTERNAL_ENDPOINT setting only if there is no such entry or the value is not matching the
    // _endpoint_info.internal_endpoint_name.
    if(!no_param_update) {
        ccs_delete_item(KEY_INTERNAL_ENDPOINT, CCS_CONFIG_ITEM);
        ccs_set_item(KEY_INTERNAL_ENDPOINT, (const uint8_t*)_endpoint_info.internal_endpoint_name.c_str(),
                             (size_t)_endpoint_info.internal_endpoint_name.size(),
                             CCS_CONFIG_ITEM);
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

void ConnectorClient::bootstrap_data_ready(M2MSecurity *security_object)
{
    tr_info("ConnectorClient::bootstrap_data_ready");
    ccs_status_e status = CCS_STATUS_ERROR;
    if(security_object) {
        // Update bootstrap credentials (we could skip this if we knew whether they were updated)
        // This will also update the address in case of first to claim
        status = set_bootstrap_credentials(security_object);
        if (status != CCS_STATUS_SUCCESS) {
            // TODO: what now?
            tr_error("ConnectorClient::bootstrap_data_ready - couldn't store bootstrap credentials");
        }

        // Clear the first to claim flag if it's active
        if (is_first_to_claim()) {
            status = clear_first_to_claim();
            if (status != CCS_STATUS_SUCCESS) {
                // TODO: what now?
                tr_error("ConnectorClient::bootstrap_data_ready - couldn't clear first to claim flag!");
            }
        }

        // Bootstrap might delete m2mserver security object instance completely to force bootstrap
        // with new credentials, in that case delete the stored lwm2m credentials as well and re-bootstrap
        if (security_object->get_security_instance_id(M2MSecurity::M2MServer) == -1) {
            tr_info("ConnectorClient::bootstrap_data_ready() - Clearing lwm2m credentials");
            // delete the old connector credentials when BS sends re-direction.
            ccs_delete_item(g_fcc_lwm2m_server_uri_name, CCS_CONFIG_ITEM);
            ccs_delete_item(g_fcc_lwm2m_server_ca_certificate_name, CCS_CERTIFICATE_ITEM);
            ccs_delete_item(g_fcc_lwm2m_device_certificate_name, CCS_CERTIFICATE_ITEM);
            ccs_delete_item(g_fcc_lwm2m_device_private_key_name, CCS_PRIVATE_KEY_ITEM);
            // Start re-bootstrap timer
            tr_info("ConnectorClient::bootstrap_data_ready() - Re-directing bootstrap in 100 milliseconds");
            _rebootstrap_timer.start_timer(100, M2MTimerObserver::BootstrapFlowTimer, true);
            return;
        }
        // Bootstrap wrote M2MServer credentials, store them and also update first to claim status if it's configured
        else {
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
            int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
            if (m2m_id >= 0 &&
                _security->resource_value_int(M2MSecurity::SecurityMode, m2m_id) == M2MSecurity::EST) {
                // If EST is supported, continue to EST state to start EST enrollment
                tr_info("ConnectorClient::bootstrap_data_ready() - Continue to EST enrollment");
                internal_event(State_EST_Start);
                return;
            }
#endif // MBED_CLIENT_DISABLE_EST_FEATURE
            // Security mode was not EST, in that case just store the received credentials
            tr_info("ConnectorClient::bootstrap_data_ready() - Storing lwm2m credentials");
            status = set_connector_credentials(security_object);
        }

        if (status != CCS_STATUS_SUCCESS) {
            internal_event(State_Bootstrap_Failure);
            //Failed to store credentials, bootstrap failed
            _callback->connector_error(M2MInterface::MemoryFail, ERROR_NO_MEMORY); // Translated to error code ConnectMemoryConnectFail
            return;
        } else {
            tr_info("ConnectorClient::bootstrap_data_ready - set_credentials status %d", status);
        }
    }
}

void ConnectorClient::bootstrap_done(M2MSecurity *security_object)
{
    tr_info("ConnectorClient::bootstrap_done");
    internal_event(State_Bootstrap_Success);
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
        ccs_delete_item(g_fcc_lwm2m_server_uri_name, CCS_CONFIG_ITEM);
        ccs_delete_item(g_fcc_lwm2m_server_ca_certificate_name, CCS_CERTIFICATE_ITEM);
        ccs_delete_item(g_fcc_lwm2m_device_certificate_name, CCS_CERTIFICATE_ITEM);
        ccs_delete_item(g_fcc_lwm2m_device_private_key_name, CCS_PRIVATE_KEY_ITEM);
        // Delete the lwm2m security instance
        int32_t id = _security->get_security_instance_id(M2MSecurity::M2MServer);
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
    // Read 1 byte of lwm2m private key, should return real_size > 0 if it exists
    const int max_size = 1;
    uint8_t buffer;
    size_t real_size = 0;
    ccs_get_item(g_fcc_lwm2m_device_private_key_name, &buffer, max_size, &real_size, CCS_PRIVATE_KEY_ITEM);
    if (real_size > 0) {
        return true;
    }
    return false;
}

bool ConnectorClient::use_bootstrap()
{
    tr_debug("ConnectorClient::use_bootstrap");
    size_t real_size = 0;
    uint8_t data[CONFIG_BOOLEAN_ITEM_SIZE] = {0};
    uint32_t value = 0;
    ccs_status_e status = ccs_get_item(g_fcc_use_bootstrap_parameter_name, data, CONFIG_BOOLEAN_ITEM_SIZE, &real_size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        memcpy(&value, data, CONFIG_BOOLEAN_ITEM_SIZE);
        // Return true if use_bootstrap is set
        if (value == 1) {
            return true;
        }
    }
    return false;
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

    int32_t m2m_id = security->get_security_instance_id(M2MSecurity::M2MServer);
    if (m2m_id == -1) {
        return status;
    }

    size_t buffer_size = MAX_CERTIFICATE_SIZE;
    uint8_t public_key[MAX_CERTIFICATE_SIZE];
    uint8_t *public_key_ptr = (uint8_t*)&public_key;

    // TODO! Update to use chain api
    if (security->resource_value_buffer(M2MSecurity::PublicKey, public_key_ptr, m2m_id, &buffer_size) != 0) {
        return status;
    }

    char device_id[64];
    memset(device_id, 0, 64);
    if (extract_field_from_certificate(public_key, buffer_size, "L", device_id)) {
        tr_info("ConnectorClient::set_connector_credentials - L internal_endpoint_name : %s", device_id);
        _endpoint_info.internal_endpoint_name = String(device_id);
        ccs_delete_item(KEY_INTERNAL_ENDPOINT, CCS_CONFIG_ITEM);
        status = ccs_set_item(KEY_INTERNAL_ENDPOINT,(uint8_t*)device_id, strlen(device_id), CCS_CONFIG_ITEM);
    }

    memset(device_id, 0, 64);
    if (extract_field_from_certificate(public_key, buffer_size, "CN", device_id)) {
        tr_info("ConnectorClient::set_connector_credentials - CN endpoint_name : %s", device_id);
        _endpoint_info.endpoint_name = String(device_id);
    }

    if(status == CCS_STATUS_SUCCESS) {
        ccs_status_e check_status = ccs_check_item(KEY_ACCOUNT_ID, CCS_CONFIG_ITEM);
        // Do not call delete if KEY does not exist.
        if ((check_status == CCS_STATUS_KEY_DOESNT_EXIST) || (check_status == CCS_STATUS_ERROR)) {
            tr_debug("No KEY_ACCOUNT_ID stored.");
        } else {
            ccs_delete_item(KEY_ACCOUNT_ID, CCS_CONFIG_ITEM);
            // AccountID optional so don't fail if unable to store
            ccs_set_item(KEY_ACCOUNT_ID,
                         (const uint8_t*)_endpoint_info.account_id.c_str(),
                         (size_t)_endpoint_info.account_id.size(),
                         CCS_CONFIG_ITEM);
        }
    }

    if (status == CCS_STATUS_SUCCESS) {
        status = ccs_set_item(g_fcc_lwm2m_server_uri_name,
                              (const uint8_t*)security->resource_value_string(M2MSecurity::M2MServerUri, m2m_id).c_str(),
                              (size_t)security->resource_value_string(M2MSecurity::M2MServerUri, m2m_id).size(),
                              CCS_CONFIG_ITEM);
    }

    M2MDevice *device = M2MInterfaceFactory::create_device();
    if (status == CCS_STATUS_SUCCESS && device) {
        String temp = "";
        uint32_t currenttime = (uint32_t)device->resource_value_int(M2MDevice::CurrentTime, 0);
        uint8_t data[4];
        memcpy(data, &currenttime, 4);
        ccs_delete_item(g_fcc_current_time_parameter_name, CCS_CONFIG_ITEM);
        ccs_set_item(g_fcc_current_time_parameter_name, data, 4, CCS_CONFIG_ITEM);

        temp = device->resource_value_string(M2MDevice::Timezone, 0);
        if (temp.size() > 0) {
            ccs_delete_item(g_fcc_device_time_zone_parameter_name, CCS_CONFIG_ITEM);
            ccs_set_item(g_fcc_device_time_zone_parameter_name, (const uint8_t*)temp.c_str(), temp.size(), CCS_CONFIG_ITEM);
        }

        temp = device->resource_value_string(M2MDevice::UTCOffset, 0);
        if (temp.size() > 0) {
            ccs_delete_item(g_fcc_offset_from_utc_parameter_name, CCS_CONFIG_ITEM);
            ccs_set_item(g_fcc_offset_from_utc_parameter_name, (const uint8_t*)temp.c_str(), temp.size(), CCS_CONFIG_ITEM);
        }

        status = CCS_STATUS_SUCCESS;
    }
    else {
        tr_debug("No device object to store!");
    }

    return status;
}

ccs_status_e ConnectorClient::set_bootstrap_credentials(M2MSecurity *security)
{
    tr_debug("ConnectorClient::set_bootstrap_credentials");
    ccs_status_e status = CCS_STATUS_ERROR;

    size_t buffer_size = MAX_CERTIFICATE_SIZE;
    uint8_t key[MAX_CERTIFICATE_SIZE];
    uint8_t *key_ptr = (uint8_t*)&key;

    int32_t bs_id = security->get_security_instance_id(M2MSecurity::Bootstrap);
    if (bs_id == -1) {
        return status;
    }

    // TODO! Update to use chain api
    if (security->resource_value_buffer(M2MSecurity::PublicKey, key_ptr, bs_id, &buffer_size) != 0) {
        return status;
    }

    if (buffer_size) {
        ccs_delete_item(g_fcc_bootstrap_device_certificate_name, CCS_CERTIFICATE_ITEM);
        status = ccs_set_item(g_fcc_bootstrap_device_certificate_name,
                                            key_ptr,
                                            buffer_size,
                                        CCS_CERTIFICATE_ITEM);
        buffer_size = MAX_CERTIFICATE_SIZE;
    }

    if (status == CCS_STATUS_SUCCESS) {
        if (security->resource_value_buffer(M2MSecurity::Secretkey, key_ptr, bs_id, &buffer_size) != 0) {
            status = CCS_STATUS_ERROR;
            buffer_size = 0;
        }

        if(buffer_size) {
            ccs_delete_item(g_fcc_bootstrap_device_private_key_name, CCS_PRIVATE_KEY_ITEM);
            status = ccs_set_item(g_fcc_bootstrap_device_private_key_name,
                                            key_ptr,
                                            buffer_size,
                                            CCS_PRIVATE_KEY_ITEM);
            buffer_size = MAX_CERTIFICATE_SIZE;
        }
    }

    if (status == CCS_STATUS_SUCCESS) {
        if (security->resource_value_buffer(M2MSecurity::ServerPublicKey, key_ptr, bs_id, &buffer_size) != 0) {
            status = CCS_STATUS_ERROR;
            buffer_size = 0;
        }

        if (buffer_size) {
            ccs_delete_item(g_fcc_bootstrap_server_ca_certificate_name, CCS_CERTIFICATE_ITEM);
            status = ccs_set_item(g_fcc_bootstrap_server_ca_certificate_name,
                              key_ptr,
                              buffer_size,
                              CCS_CERTIFICATE_ITEM);
        }
    }

    if(status == CCS_STATUS_SUCCESS) {
        ccs_delete_item(g_fcc_bootstrap_server_uri_name, CCS_CONFIG_ITEM);
        status = ccs_set_item(g_fcc_bootstrap_server_uri_name,
                          (const uint8_t*)security->resource_value_string(M2MSecurity::M2MServerUri, bs_id).c_str(),
                          (size_t)security->resource_value_string(M2MSecurity::M2MServerUri, bs_id).size(),
                          CCS_CONFIG_ITEM);
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
        ccs_delete_item(g_fcc_bootstrap_server_uri_name, CCS_CONFIG_ITEM);
        status = ccs_set_item(g_fcc_bootstrap_server_uri_name,
                                      srv_address,
                                      (size_t)srv_address_size,
                                      CCS_CONFIG_ITEM);
    }

    return status;
}

ccs_status_e ConnectorClient::clear_first_to_claim()
{
    tr_debug("ConnectorClient::clear_first_to_claim");
    return ccs_delete_item(KEY_FIRST_TO_CLAIM, CCS_CONFIG_ITEM);
}


const ConnectorClientEndpointInfo *ConnectorClient::endpoint_info() const
{
    return &_endpoint_info;
}

bool ConnectorClient::bootstrap_credentials_stored_in_kcm()
{
    size_t real_size = 0;
    ccs_status_e success = ccs_item_size(g_fcc_bootstrap_server_uri_name, &real_size, CCS_CONFIG_ITEM);
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
    uint8_t data[CONFIG_BOOLEAN_ITEM_SIZE] = {0};
    uint32_t value = 0;
    ccs_status_e status = ccs_get_item(KEY_FIRST_TO_CLAIM, data, CONFIG_BOOLEAN_ITEM_SIZE, &real_size, CCS_CONFIG_ITEM);
    if (status == CCS_STATUS_SUCCESS) {
        memcpy(&value, data, CONFIG_BOOLEAN_ITEM_SIZE);
        // Return true if first to claim is set
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

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
void ConnectorClient::est_enrollment_result(bool success,
                                            const uint8_t *payload_ptr,
                                            const uint16_t payload_len)
{
    tr_debug("ConnectorClient::est_enrollment_result - %s", success ? "successful" : "failed");
    tr_debug("ConnectorClient::est_enrollment_result - PublicKey size %d", (int)payload_len);

    assert(_security != NULL);
    int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
    StartupSubStateRegistration state = State_EST_Failure;

    if (success && payload_ptr && payload_len > 0 && m2m_id >= 0) {
        const uint8_t *ptr = payload_ptr;
        tr_debug("Payload start: %s", tr_array(payload_ptr, 10));
        ccs_status_e ccs_status = ccs_parse_cert_chain_and_store((const uint8_t*)g_fcc_lwm2m_device_certificate_name,
                                                                 strlen(g_fcc_lwm2m_device_certificate_name),
                                                                 payload_ptr,
                                                                 payload_len);
        if (ccs_status != CCS_STATUS_SUCCESS) {
            tr_error("ConnectorClient::est_enrollment_result - storing certificate chain failed!");
        }
        else {
            tr_info("ConnectorClient::est_enrollment_result() - Storing lwm2m credentials");
            if (set_connector_credentials(_security) == CCS_STATUS_SUCCESS) {
                state = State_EST_Success;
            }
        }

    }

    internal_event(state);
}

void ConnectorClient::est_post_data_cb(const uint8_t *buffer,
                                       size_t buffer_size,
                                       size_t total_size,
                                       void *context)
{
    ConnectorClient *cc = static_cast<ConnectorClient*>(context);
    assert(cc);
    cc->est_enrollment_result(true, buffer, buffer_size);

}

void ConnectorClient::est_post_data_error_cb(get_data_req_error_t error_code,
                                             void *context)
{
    ConnectorClient *cc = static_cast<ConnectorClient*>(context);
    assert(cc);
    cc->est_enrollment_result(false, NULL, 0);
}
#endif /* !MBED_CLIENT_DISABLE_EST_FEATURE */


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

void ConnectorClient::init_security_object()
{
    if (_security) {
        for (int i = 0; i <= M2MSecurity::Bootstrap; i++) {
            // _security->create_object_instance() returns NULL if object already exists
            if (_security->create_object_instance((M2MSecurity::ServerType)i)) {
                M2MResource* res = _security->get_resource(M2MSecurity::ServerPublicKey, i);
                if (res) {
                    res->set_resource_read_callback(read_security_object_data_from_kcm, this);
                    res->set_resource_write_callback(write_security_object_data_to_kcm, this);
                }

                res = _security->get_resource(M2MSecurity::PublicKey, i);
                if (res) {
                    res->set_resource_read_callback(read_security_object_data_from_kcm, this);
                    res->set_resource_write_callback(write_security_object_data_to_kcm, this);
                }

                res = _security->get_resource(M2MSecurity::Secretkey, i);
                if (res) {
                    res->set_resource_read_callback(read_security_object_data_from_kcm, this);
                    res->set_resource_write_callback(write_security_object_data_to_kcm, this);
                }

                res = _security->get_resource(M2MSecurity::OpenCertificateChain, i);
                if (res) {
                    res->set_resource_read_callback(open_certificate_chain_callback, this);
                }

                res = _security->get_resource(M2MSecurity::ReadDeviceCertificateChain, i);
                if (res) {
                    res->set_resource_read_callback(read_certificate_chain_callback, this);
                }

                res = _security->get_resource(M2MSecurity::CloseCertificateChain, i);
                if (res) {
                    res->set_resource_read_callback(close_certificate_chain_callback, this);
                }
            }
        }
    }
}

void *ConnectorClient::certificate_chain_handle() const
{
    return _certificate_chain_handle;
}

void ConnectorClient::set_certificate_chain_handle(void *cert_handle)
{
    _certificate_chain_handle = cert_handle;
}
