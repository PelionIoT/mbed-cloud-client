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

#ifndef __SERVICE_CLIENT_H__
#define __SERVICE_CLIENT_H__

#include "mbed-cloud-client/MbedCloudClientConfig.h"
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#include "UpdateClient.h"
#endif
#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mdevice.h"
#include "ConnectorClient.h"

#include <string>

class M2MSecurity;
class ConnectorClientCallback;
struct MbedClientDeviceInfo;
struct MBedClientInterfaceInfo;

/**
 * \brief ServiceClientCallback
 * A callback class for passing the client progress and error condition to the
 * MbedCloudClient class object.
 */
class ServiceClientCallback {
public:

    typedef enum {
        Service_Client_Status_Failure = -1,
        Service_Client_Status_Registered = 0,
        Service_Client_Status_Unregistered = 1,
        Service_Client_Status_Register_Updated = 2
    } ServiceClientCallbackStatus;

    /**
    * \brief Indicates that the setup or close operation is complete
    * with success or failure.
    * \param status, Indicates success or failure in terms of status code.
    */
    virtual void complete(ServiceClientCallbackStatus status) = 0;

    /**
    * \brief Indicates an error condition from one of the underlying clients, including
    * identity, connector or update client.
    * \param error, Indicates an error code translated to MbedCloudClient::Error.
    * \param reason, Indicates human readable text for error description.
    */
    virtual void error(int error, const char *reason) = 0;

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LWM2M Cloud server.
    * \param base, The object whose value is updated.
    * \param type, The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type) = 0;
};


/**
 *  \brief ServiceClient
 *  This class handles all internal interactions between various client
 *  components including connector, identity and update.
 *  This class maintains the state machine for the use case flow of mbed Cloud
 *  Client.
 */

class ServiceClient : private ConnectorClientCallback
{
public:

    /**
     * \brief An enum defining the different states of
     * ServiceClient during the client flow.
     */
    enum StartupMainState {
        State_Init,
        State_Bootstrap,
        State_Register,
        State_Success,
        State_Failure,
        State_Unregister
    };

public:

    /**
    *  \brief Constructor.
    *  \param interface, Takes the structure that contains the
    *   needed information for an endpoint client to register.
    */
    ServiceClient(ServiceClientCallback& callback);

    /**
    *  \brief Destructor.
    */
    virtual ~ServiceClient();

    /**
    *  \brief Starts the registration or bootstrap sequence from MbedCloudClient.
    *  \param callback, Takes the callback for the status from ConnectorClient.
    *  \param client_objs, A list of objects to be registered to Cloud.
    */
    void initialize_and_register(M2MBaseList& reg_objs);

    /**
    *  \brief Finished the initialization of MbedCloudClient.
    */
    void finish_initialization(void);

    /**
     * \brief Returns the ConnectorClient handler.
     * \return ConnectorClient, handled for ConnectorClient.
    */
    ConnectorClient &connector_client();

    /**
     * \brief Returns const ConnectorClient handler.
     * \return const ConnectorClient, handled for ConnectorClient.
    */
    const ConnectorClient &connector_client() const;

    /**
     * \brief Set resource value in the Device Object
     *
     * \param resource Device enum to have value set.
     * \param value String object.
     * \return True if successful, false otherwise.
     */
    bool set_device_resource_value(M2MDevice::DeviceResource resource,
                                   const std::string& value);

    /**
     * \brief Set resource value in the Device Object
     *
     * \param resource Device enum to have value set.
     * \param value Byte buffer.
     * \param length Buffer length.
     * \return True if successful, false otherwise.
     */
    bool set_device_resource_value(M2MDevice::DeviceResource resource,
                                   const char* value,
                                   uint32_t length);

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    /**
     * \brief Registers a callback function for authorizing firmware downloads and reboots.
     * \param handler Callback function.
     */
    void set_update_authorize_handler(void (*handler)(int32_t request));

    /**
     * \brief Authorize request passed to authorization handler.
     * \param request Request being authorized.
     */
    void update_authorize(int32_t request);

    /**
     * \brief Registers a callback function for monitoring download progress.
     * \param handler Callback function.
     */
    void set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total));

    /**
     * \brief Callback function for the Update Client.
     * \param error Internal Update Client error code.
     */
    void update_error_callback(int32_t error);
#endif

protected :

    // Implementation of ConnectorClientCallback
    /**
    * \brief Indicates that the registration or unregistration operation is complete
    * with success or failure.
    * \param status, Indicates success or failure in terms of status code.
    */
    virtual void registration_process_result(ConnectorClient::StartupSubStateRegistration status);

    /**
    * \brief Indicates a connector error condition from an underlying M2MInterface client.
    * \param error, Indicates an error code translated from M2MInterface::Error.
    */
    virtual void connector_error(M2MInterface::Error error, const char *reason);

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LWM2M Cloud server.
    * \param base, The object whose value is updated.
    * \param type, The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type);

    /**
     * \brief Redirects the state machine to the right function.
     * \param current_state, The current state to be set.
     * \param data, The data to be passed to the state function.
     */
    void state_function(StartupMainState current_state);

    /**
     * \brief The state engine maintaining the state machine logic.
     */
    void state_engine(void);

    /**
    * An external event that can trigger the state machine.
    * \param new_state, The new state to which the state machine should go.
    * \param data, The data to be passed to the state machine.
    */
    void external_event(StartupMainState new_state);

    /**
    * An internal event generated by the state machine.
    * \param new_state, The new state to which the state machine should go.
    * \param data, The data to be passed to the state machine.
    */
    void internal_event(StartupMainState new_state);

    /**
    * When the bootstrap is started.
    */
    void state_bootstrap();

    /**
    * When the registration is started.
    */
    void state_register();

    /**
    * When the registration is successful.
    */
    void state_success();

    /**
    * When the registration has failed.
    */

    void state_failure();

    /**
    * When the client unregisters.
    */
    void state_unregister();

private:
    M2MDevice* device_object_from_storage();

    /* lookup table for printing hexadecimal values */
    static const uint8_t hex_table[16];

    ServiceClientCallback           &_service_callback;
    // data which is pending for the registration
    const char                      *_service_uri;
    void                            *_stack;
    M2MBaseList                     *_client_objs;
    StartupMainState                _current_state;
    bool                            _event_generated;
    bool                            _state_engine_running;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    bool                            _setup_update_client;
#endif
    ConnectorClient                 _connector_client;
};

#endif // !__SERVICE_CLIENT_H__
