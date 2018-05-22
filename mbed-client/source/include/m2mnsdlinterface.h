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
#ifndef M2MNSDLINTERFACE_H
#define M2MNSDLINTERFACE_H

#include "ns_list.h"
#include "mbed-client/m2mvector.h"
#include "mbed-client/m2mconfig.h"
#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mtimerobserver.h"
#include "mbed-client/m2mobservationhandler.h"
#include "mbed-client/m2mtimer.h"
#include "mbed-client/m2mbase.h"
#include "mbed-client/m2mserver.h"
#include "include/nsdllinker.h"
#include "eventOS_event.h"

//FORWARD DECLARARTION
class M2MSecurity;
class M2MObject;
class M2MObjectInstance;
class M2MResource;
class M2MResourceInstance;
class M2MNsdlObserver;
class M2MServer;
class M2MConnectionHandler;
class M2MNotificationHandler;

/**
 * @brief M2MNsdlInterface
 * Class which interacts between mbed Client C++ Library and mbed-client-c library.
 */
class M2MNsdlInterface : public M2MTimerObserver,
                         public M2MObservationHandler
{
private:
    // Prevents the use of assignment operator by accident.
    M2MNsdlInterface& operator=( const M2MNsdlInterface& /*other*/ );

    // Prevents the use of copy constructor by accident
    M2MNsdlInterface( const M2MNsdlInterface& /*other*/ );

public:

    struct get_data_request_s {
        get_data_cb         on_get_data_cb;
        get_data_error_cb   on_get_data_error_cb;
        size_t              received_size;
        uint32_t            msg_token;
        char                *uri_path;
        void                *context;
        bool                async_req;
        ns_list_link_t      link;
    };

    struct nsdl_coap_data_s {
        nsdl_s              *nsdl_handle;
        sn_coap_hdr_s       *received_coap_header;
        sn_nsdl_addr_s      address;
    };

    typedef NS_LIST_HEAD(get_data_request_s, link) get_data_request_list_t;

    /**
    * @brief Constructor
    * @param observer, Observer to pass the event callbacks from nsdl library.
    */
    M2MNsdlInterface(M2MNsdlObserver &observer, M2MConnectionHandler &connection_handler);

    /**
     * @brief Destructor
     */
    virtual ~M2MNsdlInterface();

    /**
     * @brief Creates endpoint object for the nsdl stack.
     * @param endpoint_name, Endpoint name of the client.
     * @param endpoint_type, Endpoint type of the client.
     * @param life_time, Life time of the client in seconds
     * @param domain, Domain of the client.
     * @param mode, Binding mode of the client, default is UDP
     * @param context_address, Context address default is empty.
    */
    void create_endpoint(const String &endpoint_name,
                         const String &endpoint_type,
                         const int32_t life_time,
                         const String &domain,
                         const uint8_t mode,
                         const String &context_address);

    /**
     * @brief Deletes the endpoint.
    */
    void delete_endpoint();

    /**
     * @brief Updates endpoint name.
    */
    void update_endpoint(const String &name);

    /**
     * @brief Updates domain.
    */
    void update_domain(const String &domain);

    /**
     * @brief Creates the NSDL structure for the registered objectlist.
     * @param list, List of objects implementing the M2MBase interface to be registered.
     * @return true if structure created successfully else false.
    */
    bool create_nsdl_list_structure(const M2MBaseList &list);

    /**
     * @brief Removed the NSDL resource for the given resource.
     * @param base, Resource to be removed.
     * @return true if removed successfully else false.
    */
    bool remove_nsdl_resource(M2MBase *base);

    /**
     * @brief Creates the bootstrap object.
     * @param address Bootstrap address.
     * @return true if created and sent successfully else false.
    */
    bool create_bootstrap_resource(sn_nsdl_addr_s *address);

    /**
     * @brief Sets the register message to the server.
     * @param address M2MServer address.
     * @param address_length M2MServer address length.
     * @param port M2MServer port.
     * @param address_type IP Address type.
    */
    void set_server_address(uint8_t* address,
                            uint8_t address_length,
                            const uint16_t port,
                            sn_nsdl_addr_type_e address_type);
    /**
     * @brief Sends the register message to the server.
     * @return  true if register sent successfully else false.
    */
    bool send_register_message();

    /**
     * @brief Sends the CoAP GET request to the server.
     * @uri Uri path to the data.
     * @offset Data offset.
     * @async In async mode application must call this API again with the updated offset.
     *        If set to false then client will automatically download the whole package.
     * @get_data_cb Callback which is triggered once there is data available.
     * @get_data_error_cb Callback which is trigged in case of any error.
     * @context Application context.
    */
    bool send_get_data_request(const char *uri,
                               const size_t offset,
                               const bool async,
                               get_data_cb data_cb,
                               get_data_error_cb error_cb,
                               void *context);

    /**
     * @brief Sends the update registration message to the server.
     * @param lifetime, Updated lifetime value in seconds.
     * @param clear_queue, Empties resending queue, by default it doesn't empties queue.
     * @return  true if sent successfully else false.
     *
    */
    bool send_update_registration(const uint32_t lifetime = 0, bool clear_queue = false);

    /**
     * @brief Sends unregister message to the server.
     * @return  true if unregister sent successfully else false.
    */
    bool send_unregister_message();

    /**
     * @brief Memory Allocation required for libCoap.
     * @param size, Size of memory to be reserved.
    */
    static void* memory_alloc(uint32_t size);

    /**
     * @brief Memory free functions required for libCoap
     * @param ptr, Object whose memory needs to be freed.
    */
    static void memory_free(void *ptr);

    /**
    * @brief Callback from nsdl library to inform the data is ready
    * to be sent to server.
    * @param nsdl_handle, Handler for the nsdl structure for this endpoint
    * @param protocol, Protocol format of the data
    * @param data, Data to be sent.
    * @param data_len, Size of the data to be sent
    * @param address, server address where data has to be sent.
    * @return 1 if successful else 0.
    */
    uint8_t send_to_server_callback(struct nsdl_s * nsdl_handle,
                                    sn_nsdl_capab_e protocol,
                                    uint8_t *data,
                                    uint16_t data_len,
                                    sn_nsdl_addr_s *address);

    /**
    * @brief Callback from nsdl library to inform the data which is
    * received from server for the client has been converted to coap message.
    * @param nsdl_handle, Handler for the nsdl structure for this endpoint
    * @param coap_header, Coap message formed from data.
    * @param address, Server address from where the data is received.
    * @return 1 if successful else 0.
    */
    uint8_t received_from_server_callback(struct nsdl_s * nsdl_handle,
                                          sn_coap_hdr_s *coap_header,
                                          sn_nsdl_addr_s *address);

    /**
    * @brief Callback from nsdl library to inform the data which is
    * received from server for the resources has been converted to coap message.
    * @param nsdl_handle, Handler for the nsdl resource structure for this endpoint..
    * @param coap_header, Coap message formed from data.
    * @param address, Server address from where the data is received.
    * @param nsdl_capab, Protocol for the message, currently only coap is supported.
    * @return 1 if successful else 0.
    */
    uint8_t resource_callback(struct nsdl_s *nsdl_handle, sn_coap_hdr_s *coap,
                               sn_nsdl_addr_s *address,
                               sn_nsdl_capab_e nsdl_capab);

    /**
    * @brief Callback from event loop for handling CoAP messages received from server for the resources
    * that has been converted to coap message.
    * @param coap_header, Coap message formed from data.
    * @param address, Server address from where the data is received.
    * @return 1 if successful else 0.
    */
    uint8_t resource_callback_handle_event(sn_coap_hdr_s *coap,
                                           sn_nsdl_addr_s *address);


    /**
     * @brief Callback when there is data received from server and needs to be processed.
     * @param data, data received from server.
     * @param data_size, data size received from server.
     * @param addres, address structure of the server.
     * @return true if successfully processed else false.
     */
    bool process_received_data(uint8_t *data,
                               uint16_t data_size,
                               sn_nsdl_addr_s *address);

    /**
     * @brief Stops all the timers in case there is any errors.
     */
    void stop_timers();

    /**
     * @brief Returns nsdl handle.
     * @return ndsl handle
     */
    nsdl_s* get_nsdl_handle() const;

    /**
     * @brief Get endpoint name
     * @return endpoint name
     */
    const String& endpoint_name() const;

    /**
     * @brief Get internal endpoint name
     * @return internal endpoint name
     */
    const String internal_endpoint_name() const;

    /**
     * @brief Set server address
     * @param server_address, Bootstrap or M2M server address.
     */
    void set_server_address(const char *server_address);

    /**
     * @brief Remove an object from the list kept by the NSDLInteface.
     * Does not call delete on the object.
     */
    bool remove_object_from_list(M2MBase *base);

    /*
     * @brief Get NSDL timer.
     * @return NSDL execution timer.
     */
    M2MTimer &get_nsdl_execution_timer();

    /**
     * @brief Get unregister state.
     * @return Is unregistration ongoing.
     */
    bool get_unregister_ongoing() const;

    /**
     * @brief Starts the NSDL execution timer.
     */
    void start_nsdl_execution_timer();

    /**
     * @brief Returns security object.
     * @return M2MSecurity object, contains lwm2m server information.
     */
    M2MSecurity* get_security_object();

    /**
     * @brief Returns auto-observation token.
     * @param path, Resource path, used for searching the right object.
     * @param token[OUT], Token data.
     * @return Length of the token if found otherwise 0.
     */
    uint8_t find_auto_obs_token(const char *path, uint8_t *token) const;

    /**
     * @brief Set custom uri query paramaters used in LWM2M registration.
     * @uri_query_params Uri query params. Parameters must be in key-value pair format:
     * "a=100&b=200". Maximum length can be up to 64 bytes.
     * @return False if maximum length exceeded otherwise True.
    */
    bool set_uri_query_parameters(const char *uri_query_params);

    /**
     * @brief Clears the sent blockwise message list in CoAP library.
    */
    void clear_sent_blockwise_messages();

    /**
     * @brief Send next notification message.
    */
    void send_next_notification(bool clear_token);

    /**
     * @brief Store the "BS finished" response id.
     * @param msg_id Response id.
    */
    void store_bs_finished_response_id(uint16_t msg_id);

    void set_registration_status(bool registered);

protected: // from M2MTimerObserver

    virtual void timer_expired(M2MTimerObserver::Type type);

protected: // from M2MObservationHandler

    virtual bool observation_to_be_sent(M2MBase *object,
                                        uint16_t obs_number,
                                        const m2m::Vector<uint16_t> &changed_instance_ids,
                                        bool send_object = false);

    virtual void resource_to_be_deleted(M2MBase* base);

    virtual void value_updated(M2MBase *base);

    virtual void remove_object(M2MBase *object);
#ifndef DISABLE_DELAYED_RESPONSE
    virtual void send_delayed_response(M2MBase *base);
#endif

private:

    /**
     * Enum defining an LWM2M object type.
    */
    typedef enum {
        SECURITY = 0x00,
        SERVER   = 0x01,
        DEVICE   = 0x02
    }ObjectType;

    /**
    * @brief Initializes all the nsdl library component to be usable.
    * @return true if initialization is successful else false.
    */
    bool initialize();

    bool add_object_to_list(M2MBase *base);

    bool create_nsdl_structure(M2MBase *base);

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    bool create_nsdl_endpoint_structure(M2MEndpoint *endpoint);
#endif

    bool create_nsdl_object_structure(M2MObject *object);

    bool create_nsdl_object_instance_structure(M2MObjectInstance *object_instance);

    bool create_nsdl_resource_structure(M2MResource *resource,
                                        bool multiple_instances = false);

    bool create_nsdl_resource(M2MBase *base);

    static String coap_to_string(const uint8_t *coap_data_ptr,
                          int coap_data_ptr_length);

    void execute_nsdl_process_loop();

    uint64_t registration_time() const;

    M2MBase* find_resource(const String &object,
                           const uint16_t msg_id) const;

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    M2MBase* find_resource(const M2MEndpoint *endpoint,
                                             const String &object_name,
                                             const uint16_t msg_id) const;
#endif

    M2MBase* find_resource(const M2MObject *object,
                           const String &object_instance,
                           const uint16_t msg_id) const;

    M2MBase* find_resource(const M2MObjectInstance *object_instance,
                           const String &resource_instance,
                           const uint16_t msg_id) const;

    M2MBase* find_resource(const M2MResource *resource,
                           const String &object_name,
                           const String &resource_instance) const;

    bool object_present(M2MBase *base) const;

    int object_index(M2MBase *base) const;

    static M2MInterface::Error interface_error(const sn_coap_hdr_s &coap_header);

    void send_object_observation(M2MObject *object,
                                 uint16_t obs_number,
                                 const m2m::Vector<uint16_t> &changed_instance_ids,
                                 bool send_object);

    void send_object_instance_observation(M2MObjectInstance *object_instance,
                                          uint16_t obs_number);

    void send_resource_observation(M2MResource *resource, uint16_t obs_number);



    /**
     * @brief Allocate (size + 1) amount of memory, copy size bytes into
     * it and add zero termination.
     * @param source Source string to copy, may not be NULL.
     * @param size The size of memory to be reserved.
    */
    static uint8_t* alloc_string_copy(const uint8_t* source, uint16_t size);

    /**
     * @brief Utility method to convert given lifetime int to ascii
     * and allocate a buffer for it and set it to _endpoint->lifetime_ptr.
     * @param lifetime A new value for lifetime.
    */
    void set_endpoint_lifetime_buffer(int lifetime);

    /**
     * @brief Handle incoming bootstrap PUT message.
     * @param coap_header, Received CoAP message
     * @param address, Server address
    */
    void handle_bootstrap_put_message(sn_coap_hdr_s *coap_header, sn_nsdl_addr_s *address);

    /**
     * @brief Handle bootstrap finished message.
     * @param coap_header, Received CoAP message
     * @param address, Server address
    */
    void handle_bootstrap_finished(sn_coap_hdr_s *coap_header,sn_nsdl_addr_s *address);

    /**
     * @brief Handle bootstrap delete message.
     * @param coap_header, Received CoAP message
     * @param address, Server address
    */
    void handle_bootstrap_delete(sn_coap_hdr_s *coap_header,sn_nsdl_addr_s *address);

    /**
     * @brief Parse bootstrap TLV message.
     * @param coap_header, Received CoAP message
     * @return True if parsing was succesful else false
    */
    bool parse_bootstrap_message(sn_coap_hdr_s *coap_header, M2MNsdlInterface::ObjectType lwm2m_object_type);

    /**
     * @brief Parse bootstrap TLV message.
     * @param coap_header, Received CoAP message
     * @return True if parsing was succesful else false
    */
    bool validate_security_object();

    /**
     * @brief Handle bootstrap errors.
     * @param reason, Reason for Bootstrap failure.
     * @param wait, True if need to wait that ACK has been sent.
     *              False if reconnection can start immediately.
    */
    void handle_bootstrap_error(const char *reason, bool wait);

    /**
     * @brief Handle different coap errors.
     * @param coap_header, CoAP structure.
     * @return Error reason.
    */
    static const char *coap_error(const sn_coap_hdr_s &coap_header);

    /**
     * @brief Claim
     */
    void claim_mutex();

    /**
     * @brief Release
     */
    void release_mutex();

    /**
     * @brief Change operation mode of every resource.
     * @param object, Object to be updated.
     * @return operation, New operation mode.
    */
    void change_operation_mode(M2MObject *object, M2MBase::Operation operation);

    /**
     * @brief Parse URI query parameters and pass those to nsdl-c.
     * @return True if parsing success otherwise False
    */
    bool parse_and_send_uri_query_parameters();

    /**
     * @brief Callback function that triggers the registration update call.
     * @param argument, Arguments part of the POST request.
    */
    void update_trigger_callback(void *argument);

    bool lifetime_value_changed() const;

    void execute_notification_delivery_status_cb(M2MBase* object, int32_t msgid);

    bool is_response_to_get_req(const sn_coap_hdr_s *coap_header, get_data_request_s &get_data);

    void free_get_request_list(const sn_coap_hdr_s *coap_header = NULL);

    /**
     * @brief Send next notification for object, return true if notification sent, false
     *        if no notification to send or send already in progress.
     * @param object, M2MObject whose next notification should be sent
     * @param clear_token, Flag to indicate whether observation token should be cleared.
     * @return True if notification sent, false otherwise or if send already in progress
     */
    bool send_next_notification_for_object(M2MObject& object, bool clear_token);

    static char* parse_uri_query_parameters(char* uri);

    void calculate_new_coap_ping_send_time();

    void send_coap_ping();

    void send_empty_ack(const sn_coap_hdr_s *header, sn_nsdl_addr_s *address);

    struct M2MNsdlInterface::nsdl_coap_data_s* create_coap_event_data(sn_coap_hdr_s *received_coap_header,
                                                  sn_nsdl_addr_s *address,
                                                  struct nsdl_s *nsdl_handle,
                                                  uint8_t coap_msg_code = COAP_MSG_CODE_EMPTY);

    void handle_register_response(const sn_coap_hdr_s *coap_header);

    void handle_unregister_response(const sn_coap_hdr_s *coap_header);

    void handle_register_update_response(const sn_coap_hdr_s *coap_header);

    void handle_get_response(const sn_coap_hdr_s *coap_header, get_data_request_s *get_data);

    void handle_bootstrap_response(const sn_coap_hdr_s *coap_header);

    void handle_empty_ack(const sn_coap_hdr_s *coap_header, bool is_bootstrap_msg);

    bool handle_post_response(sn_coap_hdr_s *coap_header,
                              sn_nsdl_addr_s *address,
                              sn_coap_hdr_s *&coap_response,
                              M2MObjectInstance *&obj_instance,
                              bool is_bootstrap_msg);

private:

    M2MNsdlObserver                         &_observer;
    M2MBaseList                            _base_list;
    sn_nsdl_ep_parameters_s                 *_endpoint;
    nsdl_s                                  *_nsdl_handle;
    M2MSecurity                             *_security; // Not owned
    M2MServer                               *_server;
    M2MTimer                                _nsdl_execution_timer;
    M2MTimer                                _registration_timer;
    M2MConnectionHandler                    &_connection_handler;
    sn_nsdl_addr_s                          _sn_nsdl_address;
    String                                  _endpoint_name;
    uint32_t                                _counter_for_nsdl;
    uint32_t                                _next_coap_ping_send_time;
    uint16_t                                _bootstrap_id;
    char                                    *_server_address; // BS or M2M address
    bool                                    _unregister_ongoing;
    bool                                    _identity_accepted;
    bool                                    _nsdl_execution_timer_running;
    uint8_t                                 _binding_mode;
    uint16_t                                _auto_obs_token;
    get_data_request_list_t                 _get_request_list;
    char                                    *_custom_uri_query_params;
    static int8_t                           _tasklet_id;
    M2MNotificationHandler                  *_notification_handler;
    bool                                    _notification_send_ongoing;
    arm_event_storage_t                     _event;
    bool                                    _registered;

friend class Test_M2MNsdlInterface;

};

#endif // M2MNSDLINTERFACE_H

