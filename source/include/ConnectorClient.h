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

#ifndef __CONNECTOR_CLIENT_H__
#define __CONNECTOR_CLIENT_H__

#include "mbed-client/functionpointer.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"
#include "mbed-client/m2minterfaceobserver.h"
#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mtimerobserver.h"
#include "mbed-client/m2mtimer.h"
#include "include/CloudClientStorage.h"

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
#include "include/EstClient.h"
#endif // !MBED_CLIENT_DISABLE_EST_FEATURE

class ConnectorClientCallback;

using namespace std;


/**
 * \brief ConnectorClientEndpointInfo
 * A structure that contains the needed endpoint information to register with the Cloud service.
 * Note: this should be changed to a class instead of struct and/or members changed to "const char*".
 */
struct ConnectorClientEndpointInfo {

public:
    ConnectorClientEndpointInfo(M2MSecurity::SecurityModeType m) : mode(m) {};
    ~ConnectorClientEndpointInfo() {};

public:

    String                          endpoint_name;
    String                          account_id;
    String                          internal_endpoint_name;
    M2MSecurity::SecurityModeType   mode;
};

/**
 * \brief ConnectorClient
 * This class is an interface towards the M2MInterface client to handle all
 * data flow towards Connector through this client.
 * This class is intended to be used via ServiceClient, not directly.
 * This class contains also the bootstrap functionality.
 */
class ConnectorClient : public M2MInterfaceObserver, public M2MTimerObserver {

public:
    /**
     * \brief An enum defining the different states of
     * ConnectorClient during the client flow.
     */
    enum StartupSubStateRegistration {
        State_Bootstrap_Start,
        State_Bootstrap_Started,
        State_Bootstrap_Success,
        State_Bootstrap_Failure,
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
        State_EST_Start,
        State_EST_Started,
        State_EST_Success,
        State_EST_Failure,
#endif // !MBED_CLIENT_DISABLE_EST_FEATURE
        State_Registration_Start,
        State_Registration_Started,
        State_Registration_Success,
        State_Registration_Failure,
        State_Registration_Updated,
        State_Unregistered
    };

public:

    /**
    *  \brief Constructor.
    *  \param callback, A callback for the status from ConnectorClient.
    */
    ConnectorClient(ConnectorClientCallback* callback);

    /**
    *  \brief Destructor.
    */
    ~ConnectorClient();

    /**
    *  \brief Starts the bootstrap sequence from the Service Client.
    */
    void start_bootstrap();

    /**
    *  \brief Starts the registration sequence from the Service Client.
    *  \param client_objs, A list of objects implementing the M2MBase interface to be registered with Cloud.
    */
    void start_registration(M2MBaseList* client_objs);

    /**
    *  \brief Sends an update registration message to the LWM2M server.
    */
    void update_registration();

    /**
     * \brief Returns the M2MInterface handler.
     * \return M2MInterface, Handled for M2MInterface.
    */
    M2MInterface * m2m_interface();

    /**
     * \brief Checks whether to use Bootstrap or direct Connector mode.
     * \return True if bootstrap mode, False if direct Connector flow
    */
    bool use_bootstrap();

    /**
     * \brief Checks whether to go connector registration flow
     * \return True if connector credentials available otherwise false.
    */
    bool connector_credentials_available();

    /**
     * \brief A utility function to generate the key name.
     * \param key, The key to get the value for.
     * \param endpoint, The name of the endpoint to be appended
     * to the key.
     * \param key_name, The [OUT] final key name.
     * \return True if available, else false.
    */
    bool get_key(const char *key, const char *endpoint, char *&key_name);

    /**
     * \brief Returns pointer to the ConnectorClientEndpointInfo object.
     * \return ConnectorClientEndpointInfo pointer.
    */
   const ConnectorClientEndpointInfo *endpoint_info() const;

   /**
    * \brief Returns KCM Certificate chain handle pointer.
    * \return KCM Certificate chain handle pointer.
    */
   void *certificate_chain_handle() const;

   /**
    * \brief Sets the KCM certificate chain handle pointer.
    * \param cert_handle KCM Certificate chain handle.
    */
   void set_certificate_chain_handle(void *cert_handle);

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
   static void est_enrollment_result(est_enrollment_result_e result,
                                     cert_chain_context_s *cert_chain,
                                     void *context);

   /**
    * \brief Get reference to the EST client instance.
   */
   const EstClient &est_client();
#endif /* MBED_CLIENT_DISABLE_EST_FEATURE */

public:
    // implementation of M2MInterfaceObserver:

    /**
     * \brief A callback indicating that the bootstap has been performed successfully.
     * \param server_object, The server object that contains the information fetched
     * about the LWM2M server from the bootstrap server. This object can be used
     * to register with the LWM2M server. The object ownership is passed.
     */
    virtual void bootstrap_done(M2MSecurity *server_object);

    /**
     * \brief A callback indicating when all bootstrap data has been received.
     * \param security_object, The security object that contains the security information.
     */
    virtual void bootstrap_data_ready(M2MSecurity *security_object);

    /**
     * \brief A callback indicating that the device object has been registered
     * successfully with the LWM2M server.
     * \param security_object, The server object on which the device object is
     * registered. The object ownership is passed.
     * \param server_object, An object containing information about the LWM2M server.
     * The client maintains the object.
     */
    virtual void object_registered(M2MSecurity *security_object, const M2MServer &server_object);

    /**
     * \brief A callback indicating that the device object has been successfully unregistered
     * from the LWM2M server.
     * \param server_object, The server object from which the device object is
     * unregistered. The object ownership is passed.
     */
    virtual void object_unregistered(M2MSecurity *server_object);

    /**
     * \brief A callback indicating that the device object registration has been successfully
     * updated on the LWM2M server.
     * \param security_object, The server object on which the device object registration is
     * updated. The object ownership is passed.
     * \param server_object, An object containing information about the LWM2M server.
     * The client maintains the object.
     */
    virtual void registration_updated(M2MSecurity *security_object, const M2MServer & server_object);

    /**
     * \brief A callback indicating that there was an error during the operation.
     * \param error, An error code for the occurred error.
     */
    virtual void error(M2MInterface::Error error);

    /**
     * \brief A callback indicating that the value of the resource object is updated by the server.
     * \param base, The object whose value is updated.
     * \param type, The type of the object.
     */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type);

protected: // from M2MTimerObserver

    virtual void timer_expired(M2MTimerObserver::Type type);

private:
    /**
     * \brief Redirects the state machine to right function.
     * \param current_state, The current state to be set.
     * \param data, The data to be passed to the state function.
     */
    void state_function(StartupSubStateRegistration current_state);

    /**
     * \brief The state engine maintaining the state machine logic.
     */
    void state_engine(void);

    /**
    * \brief An internal event generated by the state machine.
    * \param new_state, The new state to which the state machine should go.
    * \param data, The data to be passed to the state machine.
    */
    void internal_event(StartupSubStateRegistration new_state);

    /**
    * When the bootstrap starts.
    */
    void state_bootstrap_start();

    /**
    * When the bootstrap is started.
    */
    void state_bootstrap_started();

    /**
    * When the bootstrap is successful.
    */
    void state_bootstrap_success();

    /**
    * When the bootstrap failed.
    */
    void state_bootstrap_failure();

#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
    /**
     * When the EST (enrollment-over-secure-transport) enrollment starts.
     */
    void state_est_start();

    /**
     * When the EST (enrollment-over-secure-transport) enrollment has been started.
     */
    void state_est_started();

    /**
     * When the EST (enrollment-over-secure-transport) enrollment is successful.
     */
    void state_est_success();

    /**
     * When the EST (enrollment-over-secure-transport) enrollment failed.
     */
    void state_est_failure();
#endif // !MBED_CLIENT_DISABLE_EST_FEATURE

    /**
    * When the registration starts.
    */
    void state_registration_start();

    /**
    * When the registration started.
    */
    void state_registration_started();

    /**
    * When the registration is successful.
    */
    void state_registration_success();

    /**
     * When the registration failed.
    */
    void state_registration_failure();

    /**
    * When the client is unregistered.
    */
    void state_unregistered();

    /**
     * \brief A utility function to create an M2MSecurity object
     * for registration.
     */
    void create_register_object();

    /**
     * \brief A utility function to create an M2MSecurity object
     * for bootstrap.
     */
    bool create_bootstrap_object();

    /**
     * \brief A utility function to set the connector credentials
     * in storage. This includes endpoint, domain, connector URI
     *  and certificates.
     * \param security, The Connector certificates.
     */
    ccs_status_e set_connector_credentials(M2MSecurity *security);

    /**
     * \brief A utility function to set the bootstrap credentials
     * in storage. This includes Bootstrap URI and certificates.
     * \param security, The Bootstrap certificates.
     */
    ccs_status_e set_bootstrap_credentials(M2MSecurity *security);

    /**
     * \brief A utility function to set the bootstrap address in storage.
     * \param security, The bootstrap security object containing the address.
     */
    ccs_status_e store_bootstrap_address(M2MSecurity *security);

    /**
     * \brief A utility function to check whether bootstrap credentials are stored in KCM.
     */
    bool bootstrap_credentials_stored_in_kcm();

    /**
     * \brief A utility function to check whether first to claim feature is configured.
     */
    bool is_first_to_claim();

    /**
     * \brief A utility function to clear the first to claim parameter in storage.
     */
    ccs_status_e clear_first_to_claim();

    /**
    * \brief Returns the binding mode selected by the client
    * through the configuration.
    * \return Binding mode of the client.
    */
    static M2MInterface::BindingMode transport_mode();

    /**
    * \brief Initializes the security object and callbacks.
    *
    */
    void init_security_object();

private:
    // A callback to be called after the sequence is complete.
    ConnectorClientCallback*            _callback;
    StartupSubStateRegistration         _current_state;
    bool                                _event_generated;
    bool                                _state_engine_running;
    M2MInterface                        *_interface;
    M2MSecurity                         *_security;
    ConnectorClientEndpointInfo         _endpoint_info;
    M2MBaseList                         *_client_objs;
    M2MTimer                            _rebootstrap_timer;
    uint16_t                            _bootstrap_security_instance;
    uint16_t                            _lwm2m_security_instance;
    void                                *_certificate_chain_handle;
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
    EstClient                           _est_client;
#endif // !MBED_CLIENT_DISABLE_EST_FEATURE
};

/**
 * \brief ConnectorClientCallback
 * A callback class for passing the client progress and error condition to the
 * ServiceClient class object.
 */
class ConnectorClientCallback {
public:

    /**
    * \brief Indicates that the registration or unregistration operation is complete
    * with success or failure.
    * \param status, Indicates success or failure in terms of status code.
    */
    virtual void registration_process_result(ConnectorClient::StartupSubStateRegistration status) = 0;

    /**
    * \brief Indicates the Connector error condition of an underlying M2MInterface client.
    * \param error, Indicates an error code translated from M2MInterface::Error.
    * \param reason, Indicates human readable text for error description.
    */
    virtual void connector_error(M2MInterface::Error error, const char *reason) = 0;

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LWM2M Cloud server.
    * \param base, The object whose value is updated.
    * \param type, The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type) = 0;
};

#endif // !__CONNECTOR_CLIENT_H__
