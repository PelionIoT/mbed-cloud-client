/*
 * Copyright (c) 2015-2021 Pelion. All rights reserved.
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
#ifndef M2M_INTERFACE_IMPL_H
#define M2M_INTERFACE_IMPL_H

#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mserver.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconnectionsecurity.h"
#include "include/m2mnsdlobserver.h"
#include "include/m2mnsdlinterface.h"
#include "mbed-client/m2mtimerobserver.h"
#include "mbed-client/m2mtimer.h"
#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mconfig.h"

//FORWARD DECLARATION
class M2MConnectionSecurity;
class EventData;
class M2MUpdateRegisterData;
/**
 *  @brief M2MInterfaceImpl.
 *  This class implements handling of all mbed Client Interface operations
 *  defined in OMA LWM2M specifications.
 *  This includes Bootstrapping, Client Registration, Device Management &
 *  Service Enablement and Information Reporting.
 */

class  M2MInterfaceImpl : public M2MInterface,
    public M2MNsdlObserver,
    public M2MConnectionObserver,
    public M2MTimerObserver {
private:
    // Prevents the use of assignment operator by accident.
    M2MInterfaceImpl &operator=(const M2MInterfaceImpl & /*other*/);

    // Prevents the use of copy constructor by accident
    M2MInterfaceImpl(const M2MInterfaceImpl & /*other*/);

    friend class M2MInterfaceFactory;

private:

    /**
     * @brief Constructor
     * @param observer, Observer to pass the event callbacks for various
     * interface operations.
     * @param endpoint_name Endpoint name of the client.
     * @param endpoint_type Endpoint type of the client.
     * @param life_time Life time of the client in seconds
     * @param listen_port Listening port for the endpoint, default is 8000.
     * @param domain Domain of the client.
     * @param mode Binding mode of the client, default is UDP
     * @param stack Network stack to be used for connection, default is LwIP_IPv4.
     * @param context_address Context address, default is empty.
     * @param version Version of the LwM2M Enabler that the LwM2M Client supports.
     */
    M2MInterfaceImpl(M2MInterfaceObserver &observer,
                     const String &endpoint_name,
                     const String &endpoint_type,
                     const int32_t life_time,
                     const uint16_t listen_port,
                     const String &domain = "",
                     BindingMode mode = M2MInterface::NOT_SET,
                     M2MInterface::NetworkStack stack = M2MInterface::LwIP_IPv4,
                     const String &context_address = "",
                     const String &version = "");

public:

    /**
     * @brief Destructor
     */
    virtual ~M2MInterfaceImpl();

#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    /**
     * @brief Initiates bootstrapping of the client with the provided Bootstrap
     * server information.
     * @param security_object Security object which contains information
     * required for successful bootstrapping of the client.
     */
    virtual void bootstrap(M2MSecurity *security);

    /**
     * @brief Cancels on going bootstrapping operation of the client. If the client has
     * already successfully bootstrapped then this function deletes existing
     * bootstrap information from the client.
     */
    virtual void cancel_bootstrap();

    /**
     * @brief Finishes on going bootstrap in cases where client is the one to finish it.
     */
    virtual void finish_bootstrap();
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    /**
     * \brief Initiates the registration of a provided security object to the
     * corresponding LWM2M server.
     * \param security_object The security object that contains information
     * required for registering to the LWM2M server.
     * If the client wants to register to multiple LWM2M servers, it must call
     * this function once for each of the LWM2M server objects separately.
     * \param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     * \param full_registration If True client will perform full registration and not just register update.
     */
    virtual void register_object(M2MSecurity *security, const M2MBaseList &list, bool full_registration = false);

    /**
     * @brief Initiates registration of the provided Security object to the
     * corresponding LWM2M server.
     * @param security_object Security object which contains information
     * required for registering to the LWM2M server.
     * If client wants to register to multiple LWM2M servers then it has call
     * this function once for each of LWM2M server object separately.
     * @param object_list Objects which contains information
     * which the client want to register to the LWM2M server.
     */
    virtual void register_object(M2MSecurity *security_object, const M2MObjectList &object_list);

    /**
     * @brief Updates or refreshes the client's registration on the LWM2M
     * server.
     * @param security_object Security object from which the device object
     * needs to update registration, if there is only one LWM2M server registered
     * then this parameter can be NULL.
     * @param lifetime Lifetime for the endpoint client in seconds.
     */
    virtual void update_registration(M2MSecurity *security_object, const uint32_t lifetime = 0);

    /**
     * @brief Updates or refreshes the client's registration on the LWM2M
     * server. Use this function to publish new objects to LWM2M server.
     * @param security_object The security object from which the device object
     * needs to update the registration. If there is only one LWM2M server registered,
     * this parameter can be NULL.
     * @param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     * @param lifetime The lifetime of the endpoint client in seconds. If the same value
     * has to be passed, set the default value to 0.
     */
    virtual void update_registration(M2MSecurity *security_object, const M2MBaseList &list,
                                     const uint32_t lifetime = 0);

    /**
     * @brief Updates or refreshes the client's registration on the LWM2M
     * server. Use this function to publish new objects to LWM2M server.
     * @param security_object The security object from which the device object
     * needs to update the registration. If there is only one LWM2M server registered,
     * this parameter can be NULL.
     * @param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     * @param lifetime The lifetime of the endpoint client in seconds. If the same value
     * has to be passed, set the default value to 0.
     */
    virtual void update_registration(M2MSecurity *security_object, const M2MObjectList &object_list,
                                     const uint32_t lifetime = 0);

    /**
     * @brief Unregisters the registered object from the LWM2M server
     * @param security_object Security object from which the device object
     * needs to be unregistered. If there is only one LWM2M server registered
     * this parameter can be NULL.
     */
    virtual void unregister_object(M2MSecurity *security = NULL);

    /**
     * @brief Sets the function which will be called indicating client
     * is going to sleep when the Binding mode is selected with Queue mode.
     * @param callback A function pointer that will be called when client
     * goes to sleep.
     */
    virtual void set_queue_sleep_handler(callback_handler handler);

    /**
     * @brief Sets the network interface handler that is used by client to connect
     * to a network over IP.
     * @param handler A network interface handler that is used by client to connect.
     *  This API is optional but provides a mechanism for different platforms to
     * manage usage of underlying network interface by client.
     */
    virtual void set_platform_network_handler(void *handler = NULL);

    /**
     * @brief Sets the network interface handler that is used by client to connect
     * to a network over IP.
     * @param handler A network interface handler that is used by client to connect.
     *  This API is optional but provides a mechanism for different platforms to
     * manage usage of underlying network interface by client.
     * @param credentials_available This extra parameter allows the client to further
     * optimize its internal connection logic in high latency networks when dynamic
     * handling of network staggering is supported. (Platform-dependent).
     */
    virtual void set_platform_network_handler(void *handler = NULL, bool credentials_available = 0);

    /**
     * \brief Sets the function callback that will be called by mbed-client for
     * fetching random number from application for ensuring strong entropy.
     * \param random_callback A function pointer that will be called by mbed-client
     * while performing secure handshake.
     * Function signature should be uint32_t (*random_number_callback)(void);
     */
    virtual void set_random_number_callback(random_number_cb callback);

    /**
     * \brief Sets the function callback that will be called by mbed-client for
     * providing entropy source from application for ensuring strong entropy.
     * \param entropy_callback A function pointer that will be called by mbed-client
     * while performing secure handshake.
     * Function signature , if using mbed-client-mbedtls should be
     * int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output,
     *                                     size_t len, size_t *olen);
     */
    virtual void set_entropy_callback(entropy_cb callback);

    /**
      * \brief Removes an object from M2MInterfaceImpl.
      * Does not call delete on the object though.
      * \return true if the object was found and false if the object was not found.
      */
    virtual bool remove_object(M2MBase *object);

    /**
     * @brief Updates the endpoint name.
     * @param name New endpoint name
     */
    virtual void update_endpoint(const String &name);

    /**
     * @brief Updates the domain name.
     * @param domain New domain name
     */
    virtual void update_domain(const String &domain);

    /**
     * @brief Return internal endpoint name
     * @return internal endpoint name
     */
    virtual const String internal_endpoint_name() const;

    /**
     * @brief Return error description for the latest error code
     * @return Error description string
     */
    virtual const char *error_description() const;

    /**
     * @brief Sends the CoAP GET request to the server.
     * @type Download type.
     * @uri Uri path to the data.
     * @offset Data offset.
     * @async In async mode application must call this API again with the updated offset.
     *        If set to false then client will automatically download the whole package.
     * @get_data_cb Callback which is triggered once there is data available.
     * @get_data_error_cb Callback which is trigged in case of any error.
    */
    virtual void get_data_request(DownloadType type,
                                  const char *uri,
                                  const size_t offset,
                                  const bool async,
                                  get_data_cb data_cb,
                                  get_data_error_cb error_cb,
                                  void *context);

    /**
     * @brief Sends the CoAP POST request to the server.
     * @uri Uri path to the data.
     * @async In async mode application must call this API again with the updated offset.
     *        If set to false then client will automatically download the whole package.
     * @payload_len Length of payload.
     * @payload_ptr, Pointer to payload buffer.
     * @get_data_cb Callback which is triggered once there is data available.
     * @get_data_error_cb Callback which is trigged in case of any error.
     */
    virtual void post_data_request(const char *uri,
                                   const bool async,
                                   const uint16_t payload_len,
                                   uint8_t *payload_ptr,
                                   get_data_cb data_cb,
                                   get_data_error_cb error_cb,
                                   void *context);

    /**
     * @brief Set custom uri query paramaters used in LWM2M registration.
     * @uri_query_params Uri query params. Parameters must be in key-value format:
     * "a=100&b=200". Maximum length can be up to 64 bytes.
     * @return False if maximum length exceeded otherwise True.
    */
    virtual bool set_uri_query_parameters(const char *uri_query_params);

    /**
     * \brief Pauses client's timed functionality and closes network connection
     * to the Cloud. After successful call the operation is continued
     * by calling register_object().
     *
     * \note This operation does not unregister client from the Cloud.
     * Closes the socket and removes interface from the interface list.
     */
    virtual void pause();

    /**
     * \brief Sets client into an alert mode.
     *
     * \note In alert mode client halts all data
     * sendings/active operations and waits for priority data to be sent.
     */
    virtual void alert();

    /**
     * @brief Get ndsl handle.
     * @return nsdl handle
     */
    virtual nsdl_s *get_nsdl_handle() const;

    /**
     * @brief Returns M2MServer handle.
     * @return M2MServer handle
     */
    virtual M2MServer *get_m2mserver() const;

    /**
     * \brief Internal test function. Set CID for current tls session.
     * \param data_ptr CID
     * \param data_len length of the CID
     */
    virtual void set_cid_value(const uint8_t *data_ptr, const size_t data_len);

protected: // From M2MNsdlObserver

    virtual void coap_message_ready(uint8_t *data_ptr,
                                    uint16_t data_len,
                                    sn_nsdl_addr_s *address_ptr);

    virtual void client_registered(M2MServer *server_object);

    virtual void registration_updated(const M2MServer &server_object);

    virtual void registration_error(uint8_t error_code, bool retry = false, bool full_registration = false, bool ping_recovery = false);

    virtual void client_unregistered(bool success = true);

#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    virtual void init_security_object(uint16_t instance_id);

    virtual void bootstrap_done();

    virtual void bootstrap_finish();

    virtual void bootstrap_wait();

    virtual void bootstrap_error_wait(const char *reason);

    virtual void bootstrap_error(M2MInterface::Error error, const char *reason);
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    virtual void coap_data_processed();

    virtual void value_updated(M2MBase *base);

    virtual uint16_t stagger_wait_time(bool bootstrap) const;

protected: // From M2MConnectionObserver

    virtual void data_available(uint8_t *data,
                                uint16_t data_size,
                                const M2MConnectionObserver::SocketAddress &address);

    virtual void socket_error(int error_code, bool retry = true);

    virtual void address_ready(const M2MConnectionObserver::SocketAddress &address,
                               M2MConnectionObserver::ServerType server_type,
                               const uint16_t server_port);

    virtual void data_sent();

    virtual void network_interface_status_change(NetworkInterfaceStatus status);

protected: // from M2MTimerObserver

    virtual void timer_expired(M2MTimerObserver::Type type);


private: // state machine state functions

    /**
    * When the state is Idle.
    */
    void state_idle(EventData *data);

#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    /**
    * When the client starts bootstrap.
    */
    void state_bootstrap(EventData *data);

    /**
    * When the bootstrap server address is resolved.
    */
    void state_bootstrap_address_resolved(EventData *data);

    /**
    * When the bootstrap resource is created.
    */
    void state_bootstrap_resource_created(EventData *data);

    /**
    * When the server has sent response and bootstrapping is done.
    */
    void state_bootstrapped(EventData *data);
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE

    /**
    * When the client starts register.
    */
    void state_register(EventData *data);

    /**
    * When the server address for register is resolved.
    */
    void state_register_address_resolved(EventData *data);

    /**
    * When the client is registered.
    */
    void state_registered(EventData *data);

    /**
    * When the client is updating registration.
    */
    void state_update_registration(EventData *data);

    /**
    * When the client starts unregister.
    */
    void state_unregister(EventData *data);

    /**
    * When the client has been unregistered.
    */
    void state_unregistered(EventData *data);

    /**
    * When the coap data is been sent through socket.
    */
    void state_sending_coap_data(EventData *data);

    /**
    * When the coap data is sent successfully.
    */
    void state_coap_data_sent(EventData *data);

    /**
    * When the socket is receiving coap data.
    */
    void state_receiving_coap_data(EventData *data);

    /**
    * When the socket has received coap data.
    */
    void state_coap_data_received(EventData *data);

    /**
    * When the coap message is being processed.
    */
    void state_processing_coap_data(EventData *data);

    /**
    * When the coap message has been processed.
    */
    void state_coap_data_processed(EventData *data);

    /**
    * When the client is waiting to receive or send data.
    */
    void state_waiting(EventData *data);

    /**
     * Start registration update.
     */
    void start_register_update(M2MUpdateRegisterData *data);

    /**
    * State enumeration order must match the order of state
    * method entries in the state map
    */
    enum E_States {
        STATE_IDLE = 0,
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        STATE_BOOTSTRAP,
        STATE_BOOTSTRAP_ADDRESS_RESOLVED,
        STATE_BOOTSTRAP_RESOURCE_CREATED,
        STATE_BOOTSTRAP_WAIT,
        STATE_BOOTSTRAP_ERROR_WAIT, // 5
        STATE_BOOTSTRAPPED,
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        STATE_REGISTER,
        STATE_REGISTER_ADDRESS_RESOLVED,
        STATE_REGISTERED,
        STATE_UPDATE_REGISTRATION, // 10
        STATE_UNREGISTER,
        STATE_UNREGISTERED,
        STATE_SENDING_COAP_DATA,
        STATE_COAP_DATA_SENT,
        STATE_COAP_DATA_RECEIVED, // 15
        STATE_PROCESSING_COAP_DATA,
        STATE_COAP_DATA_PROCESSED,
        STATE_WAITING,
        STATE_MAX_STATES
    };

    /**
     * @brief Redirects the state machine to right function.
     * @param current_state Current state to be set.
     * @param data Data to be passed to the state function.
     */
    void state_function(uint8_t current_state, EventData *data);

    /**
     * @brief State Engine maintaining state machine logic.
     */
    void state_engine(void);

    /**
    * External event which can trigger the state machine.
    * @param New The state to which the state machine should go.
    * @param data The data to be passed to the state machine.
    */
    void external_event(uint8_t, EventData * = NULL);

    /**
    * Internal event generated by state machine.
    * @param New State which the state machine should go to.
    * @param data The data to be passed to the state machine.
    */
    void internal_event(uint8_t, EventData * = NULL);

    /**
    * Queue mode enabled or not.
    * @return True if queue mode otherwise false.
    */
    bool queue_mode() const;

    enum {
        EVENT_IGNORED = 0xFE,
        CANNOT_HAPPEN
    };

    /**
     * Helper method for extracting the IP address part and port from the
     * given server address.
     * @param server_address Source URL (without "coap" or "coaps" prefix).
     * @param ip_address The extracted IP.
     * @param port The extracted port.
     */
    static void process_address(const String &server_address, String &ip_address, uint16_t &port);

    /**
     * Helper method for storing the error description to _error_description if the feature
     * has not been turned off.
     * @param error description
     */
    void set_error_description(const char *description);

    /**
     * Helper method for creating random initial reconnection time interval.
     */
    void create_random_initial_reconnection_time();

    void update_network_latency_configurations_with_rtt();

    /**
     * @brief Callback function which is called when POST comes to resource 1/0/4. Triggers de-registration.
     * @param argument, Pointer to M2MResource::M2MExecuteParameter.
    */
    void disable_callback(void *argument);

    /**
     * @brief Callback function which is called when acknowledgement for the response to POST to resource 1/0/4
     * is received from server.
    */
    static void post_response_status_handler(const M2MBase &base,
                                             const M2MBase::MessageDeliveryStatus status,
                                             const M2MBase::MessageType type,
                                             void *me);

    enum ReconnectionState {
        None,
        WithUpdate,
        ClientPing
    };

private:

    EventData                               *_event_data;
    M2MConnectionObserver::SocketAddress    _server_address;
    uint16_t                                _server_port;
    uint16_t                                _listen_port;
    int32_t                                 _life_time;
    String                                  _server_ip_address;
    M2MSecurity                             *_register_server; //TODO: to be the list not owned
    M2MTimer                                _queue_sleep_timer;
    M2MTimer                                _retry_timer;
    callback_handler                        _callback_handler;
    const uint8_t                           _max_states;
    bool                                    _event_ignored;
    bool                                    _event_generated;
    bool                                    _reconnecting;
    bool                                    _retry_timer_expired;
    bool                                    _bootstrapped;
    bool                                    _bootstrap_finished;
    bool                                    _queue_mode_timer_ongoing;
    uint8_t                                 _current_state;
    BindingMode                             _binding_mode;
    ReconnectionState                       _reconnection_state;
    M2MInterfaceObserver                    &_observer;
    M2MConnectionSecurity                   *_security_connection; // Doesn't own
    M2MConnectionHandler                    _connection_handler;
    M2MNsdlInterface                        _nsdl_interface;
    M2MSecurity                             *_security;

#ifndef DISABLE_ERROR_DESCRIPTION
    // The DISABLE_ERROR_DESCRIPTION macro will reduce the flash usage by ~1800 bytes.
    char                                    _error_description[MAX_ALLOWED_ERROR_STRING_LENGTH];
#endif

    // Reconnection related variables (in seconds)
    uint16_t                                _initial_reconnection_time;
    uint32_t                                _reconnection_time;

    // Get M2M server IP address from security's instance with the given id
    void get_security_server_ip_address(int32_t instance_id);

    friend class Test_M2MInterfaceImpl;

};

#define BEGIN_TRANSITION_MAP \
    static const uint8_t TRANSITIONS[] = {\

#define TRANSITION_MAP_ENTRY(entry)\
    entry,

#define END_TRANSITION_MAP(data) \
    0 };\
    external_event(TRANSITIONS[_current_state], data);

#endif //M2M_INTERFACE_IMPL_H


