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
#ifndef M2M_BASE_H
#define M2M_BASE_H

// Support for std args
#include <stdint.h>
#include "mbed-client/m2mconfig.h"
#include "mbed-client/m2mreportobserver.h"
#include "mbed-client/functionpointer.h"
#include "mbed-client/m2mstringbuffer.h"
#ifdef ENABLE_ASYNC_REST_RESPONSE
#include "mbed-client/coap_response.h"
#endif
#include "nsdl-c/sn_nsdl.h"
#include "sn_coap_header.h"
#include "nsdl-c/sn_nsdl_lib.h"

//FORWARD DECLARATION
struct sn_coap_hdr_;
typedef sn_coap_hdr_ sn_coap_hdr_s;
struct nsdl_s;
struct sn_nsdl_addr_;
typedef sn_nsdl_addr_ sn_nsdl_addr_s;

typedef FP1<void, const char*> value_updated_callback;
typedef void(*value_updated_callback2) (const char* object_name);
class M2MObservationHandler;
class M2MReportHandler;

class M2MObjectInstance;
class M2MObject;
class M2MResource;
class M2MEndpoint;


/*! \file m2mbase.h
 *  \brief M2MBase.
 *  This class is the base class based on which all LwM2M object models
 *  can be created.
 *
 *  This serves as a base class for Objects, ObjectInstances and Resources.
 */

/*! \class M2MBase
 *  \brief The base class based on which all LwM2M object models can be created.
 *
 * It serves as the base class for Objects, ObjectInstances and Resources.
 */
class M2MBase : public M2MReportObserver {

public:

    /**
      * \brief Enum to define the type of object.
      */
    typedef enum {
        Object = 0x0,
        Resource = 0x1,
        ObjectInstance = 0x2,
        ResourceInstance = 0x3
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
        ,ObjectDirectory = 0x4
#endif
    } BaseType;

    /**
      * \brief Enum to define observation level.
      */
    typedef enum {
        None                 = 0x0,
        R_Attribute          = 0x01,
        OI_Attribute         = 0x02,
        OIR_Attribute        = 0x03,
        O_Attribute          = 0x04,
        OR_Attribute         = 0x05,
        OOI_Attribute        = 0x06,
        OOIR_Attribute       = 0x07
    } Observation;


    /**
     * \brief Enum defining a resource type.
    */
    typedef enum {
        Static,
        Dynamic,
        Directory
    }Mode;

    /**
     * \brief Enum defining a resource data type.
    */
    typedef enum {
        STRING,
        INTEGER,
        FLOAT,
        BOOLEAN,
        OPAQUE,
        TIME,
        OBJLINK
    }DataType;

    /**
     * \brief Enum defining an operation that can be
     * supported by a given resource.
    */
    typedef enum {
        NOT_ALLOWED                 = 0x00,
        GET_ALLOWED                 = 0x01,
        PUT_ALLOWED                 = 0x02,
        GET_PUT_ALLOWED             = 0x03,
        POST_ALLOWED                = 0x04,
        GET_POST_ALLOWED            = 0x05,
        PUT_POST_ALLOWED            = 0x06,
        GET_PUT_POST_ALLOWED        = 0x07,
        DELETE_ALLOWED              = 0x08,
        GET_DELETE_ALLOWED          = 0x09,
        PUT_DELETE_ALLOWED          = 0x0A,
        GET_PUT_DELETE_ALLOWED      = 0x0B,
        POST_DELETE_ALLOWED         = 0x0C,
        GET_POST_DELETE_ALLOWED     = 0x0D,
        PUT_POST_DELETE_ALLOWED     = 0x0E,
        GET_PUT_POST_DELETE_ALLOWED = 0x0F
    }Operation;

    /**
     * \brief Enum defining an status codes that can happen when
     * sending confirmable message.
    */
    typedef enum {
        MESSAGE_STATUS_INIT = 0,           // Initial state.
        MESSAGE_STATUS_BUILD_ERROR,        // CoAP message building fails.
        MESSAGE_STATUS_RESEND_QUEUE_FULL,  // CoAP resend queue full.
        MESSAGE_STATUS_SENT,               // Message sent to the server but ACK not yet received.
        MESSAGE_STATUS_DELIVERED,          // Received ACK from server.
        MESSAGE_STATUS_SEND_FAILED,        // Message sending failed.
        MESSAGE_STATUS_SUBSCRIBED,         // Server has started the observation
        MESSAGE_STATUS_UNSUBSCRIBED,       // Server has stopped the observation (RESET message or GET with observe 1)
        MESSAGE_STATUS_REJECTED            // Server has rejected the response
    } MessageDeliveryStatus;

    typedef enum {
        NOTIFICATION = 0,
        DELAYED_POST_RESPONSE,
        BLOCK_SUBSCRIBE,
        PING,
#ifdef ENABLE_ASYNC_REST_RESPONSE
        DELAYED_RESPONSE,
#endif // ENABLE_ASYNC_REST_RESPONSE
    } MessageType;

    enum MaxPathSize {
        MAX_NAME_SIZE = 64,
        MAX_INSTANCE_SIZE = 5,

        MAX_PATH_SIZE = ((MAX_NAME_SIZE * 2) + (MAX_INSTANCE_SIZE * 2) + 3 + 1),
        MAX_PATH_SIZE_2 = ((MAX_NAME_SIZE * 2) + MAX_INSTANCE_SIZE + 2 + 1),
        MAX_PATH_SIZE_3 = (MAX_NAME_SIZE + (MAX_INSTANCE_SIZE * 2) + 2 + 1),
        MAX_PATH_SIZE_4 = (MAX_NAME_SIZE + MAX_INSTANCE_SIZE + 1 + 1)
    };

    // The setter for this callback (set_notification_delivery_status_cb()) is in m2m_deprecated
    // category, but it can not be used here as then the GCC will scream for the declaration of
    // setter, not just from references of it.
    typedef void(*notification_delivery_status_cb) (const M2MBase& base,
                                                    const NotificationDeliveryStatus status,
                                                    void *client_args);

    typedef void(*message_delivery_status_cb) (const M2MBase& base,
                                               const MessageDeliveryStatus status,
                                               const MessageType type,
                                               void *client_args);

#ifdef ENABLE_ASYNC_REST_RESPONSE
    /**
     * \brief Type definition for an asynchronous CoAP request callback function.
     * \param operation The operation, for example M2MBase::PUT_ALLOWED.
     * \param token The token. Client needs to copy this if it cannot respond immediately.
     * \param token_len The length of the token.
     * \param buffer The payload of the request. Client needs to copy this if it cannot respond immediately.
     * \param buffer_size The size of the payload.
     * \param client_args Some pointer given by client when requesting asynchronus request callback using
     *        set_async_coap_request_cb.
     */
    typedef void (*handle_async_coap_request_cb)(const M2MBase &base,
                                                 M2MBase::Operation operation,
                                                 const uint8_t *token,
                                                 const uint8_t token_len,
                                                 const uint8_t *buffer,
                                                 size_t buffer_size,
                                                 void *client_args);
#endif // ENABLE_ASYNC_REST_RESPONSE

    /*! \brief LwM2M parameters.
     */
    typedef struct lwm2m_parameters {
        //add multiple_instances
        uint32_t            max_age; // todo: add flag
        /*! \union identifier
         *  \brief Parameter identifier.
         */
        union {
            char*               name; //for backwards compatibility
            uint16_t            instance_id; // XXX: this is not properly aligned now, need to reorder these after the elimination is done
        } identifier;
        sn_nsdl_dynamic_resource_parameters_s *dynamic_resource_params;
        BaseType            base_type : 3;
        M2MBase::DataType   data_type : 3;
        bool                multiple_instance;
        bool                free_on_delete;   /**< \brief true if struct is dynamically allocated and it
                                                 and its members (name) are to be freed on destructor.
                                                 \note The `sn_nsdl_dynamic_resource_parameters_s` has
                                                 its own similar, independent flag.

                                                 \note This also serves as a read-only flag. */
       bool                 identifier_int_type;
       bool                 read_write_callback_set; /**< \brief If set, all the read and write operations are handled in callbacks
                                                         and the resource value is not stored anymore in M2MResourceBase. */
    } lwm2m_parameters_s;

protected:

    // Prevents the use of default constructor.
    M2MBase();

    // Prevents the use of assignment operator.
    M2MBase& operator=( const M2MBase& /*other*/ );

    // Prevents the use of copy constructor
    M2MBase( const M2MBase& /*other*/ );

    /**
     * \brief Constructor
     * \param name Name of the object created.
     * \param mode Type of the resource.
     * \param resource_type Textual information of resource.
     * \param path Path of the object like 3/0/1
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     */
    M2MBase(const String &name,
            M2MBase::Mode mode,
#ifndef DISABLE_RESOURCE_TYPE
            const String &resource_type,
#endif
            char *path,
            bool external_blockwise_store,
            bool multiple_instance,
            M2MBase::DataType type = M2MBase::OBJLINK);

    M2MBase(const lwm2m_parameters_s* s);

public:

    /**
     * \brief Destructor
     */
    virtual ~M2MBase();

    /**
     * \brief Sets the operation type for an object.
     * \param operation The operation to be set.
     */
    void set_operation(M2MBase::Operation operation);

#if !defined(MEMORY_OPTIMIZED_API) || defined(RESOURCE_ATTRIBUTES_LIST)
    /**
     * \brief Sets the interface description of the object.
     * \param description The description to be set.
     */
#if !defined(DISABLE_INTERFACE_DESCRIPTION) || defined(RESOURCE_ATTRIBUTES_LIST)
    void set_interface_description(const String &description);

    /**
     * \brief Sets the interface description of the object.
     * \param description The description to be set.
     */
    void set_interface_description(const char *description);

    /**
     * \brief Returns the interface description of the object.
     * \return The interface description of the object.
     */
    const char* interface_description() const;
#endif
#if !defined(DISABLE_RESOURCE_TYPE) || defined(RESOURCE_ATTRIBUTES_LIST)
    /**
     * \brief Sets the resource type of the object.
     * \param resource_type The resource type to be set.
     */
    virtual void set_resource_type(const String &resource_type);

    /**
     * \brief Sets the resource type of the object.
     * \param resource_type The resource type to be set.
     */
    virtual void set_resource_type(const char *resource_type);

    /**
     * \brief Returns the resource type of the object.
     * \return The resource type of the object.
     */
    const char* resource_type() const;
#endif
#endif

    /**
     * \brief Sets the CoAP content type of the object.
     * \param content_type The content type to be set based on
     * CoAP specifications.
     */
    void set_coap_content_type(const uint16_t content_type);

    /**
     * \brief Sets the observable mode for the object.
     * \param observable A value for the observation.
     */
    void set_observable(bool observable);

    /**
     * \brief Sets the object to be auto-observable.
     *
     * \note This is not a standard CoAP or LwM2M feature and it only works in Device Management.
     * \note You must call this before registration process, since this info must be in a registration message.
     * \note Auto-observable will take higher precedence if both observable methods are set.
     *
     * \param auto_observable Is auto-obs feature enabled or not.
     */
    void set_auto_observable(bool auto_observable);

    /**
     * \brief Adds the observation level for the object.
     * \param observation_level The level of observation.
     */
    virtual void add_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Removes the observation level for the object.
     * \param observation_level The level of observation.
     */
    virtual void remove_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Sets the object under observation.
     * \param observed The value for observation. When true, starts observing. When false, the ongoing observation is cancelled.
     * \param handler A handler object for sending
     * observation callbacks.
     */
    void set_under_observation(bool observed,
                               M2MObservationHandler *handler);
    /**
     * \brief Returns the Observation Handler object.
     * \return M2MObservationHandler object.
    */
    virtual M2MObservationHandler* observation_handler() const = 0;

    /**
     * \brief Sets the observation handler
     * \param handler Observation handler
    */
    virtual void set_observation_handler(M2MObservationHandler *handler) = 0;

    /**
     * \brief Sets the instance ID of the object.
     * \param instance_id The instance ID of the object.
     */
    void set_instance_id(const uint16_t instance_id);

    /**
     * \brief Sets the max age for the resource value to be cached.
     * \param max_age The max age in seconds.
     */
    void set_max_age(const uint32_t max_age);

    /**
     * \brief Returns the object type.
     * \return The base type of the object.
     */
    M2MBase::BaseType base_type() const;

    /**
     * \brief Returns the operation type of the object.
     * \return The supported operation on the object.
     */
    M2MBase::Operation operation() const;

    /**
     * \brief Returns the object name.
     * \return The name of the object.
     */
    const char* name() const;

    /**
     * \brief Returns the object name in integer.
     * \return The name of the object in integer.
     */
    int32_t name_id() const;

    /**
     * \brief Returns the object's instance ID.
     * \returns The instance ID of the object.
     */
    uint16_t instance_id() const;

    /**
     * \brief Returns the path of the object.
     * \return The path of the object (eg. 3/0/1).
     */
    const char* uri_path() const;

    /**
     * \brief Returns the CoAP content type of the object.
     * \return The CoAP content type of the object.
     */
    uint16_t coap_content_type() const;

    /**
     * \brief Returns the observation status of the object.
     * \return True if observable, else false.
     */
    bool is_observable() const;

    /**
     * \brief Returns the auto observation status of the object.
     * \return True if observable, else false.
     */
    bool is_auto_observable() const;

    /**
     * \brief Returns the observation level of the object.
     * \return The observation level of the object.
     */
    M2MBase::Observation observation_level() const;

    /**
     * \brief Returns the mode of the resource.
     * \return The mode of the resource.
     */
     Mode mode() const;

    /**
     * \brief Returns the observation number.
     * \return The observation number of the object.
     */
    uint16_t observation_number() const;

    /**
     * \brief Returns the max age for the resource value to be cached.
     * \return The maax age in seconds.
     */
    uint32_t max_age() const;

    /**
     * \brief Parses the received query for the notification
     * attribute.
     * \param query The query that needs to be parsed.
     * \return True if required attributes are present, else false.
     */
    virtual bool handle_observation_attribute(const char *query);

    /**
     * \brief Handles GET request for the registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The received CoAP message from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \return sn_coap_hdr_s The message that needs to be sent to server.
     */
    virtual sn_coap_hdr_s* handle_get_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler = NULL);
    /**
     * \brief Handles PUT request for the registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The received CoAP message from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \param execute_value_updated True executes the "value_updated" callback.
     * \return sn_coap_hdr_s The message that needs to be sent to server.
     */
    virtual sn_coap_hdr_s* handle_put_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated);

    /**
     * \brief Handles GET request for the registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The received CoAP message from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \param execute_value_updated True executes the "value_updated" callback.
     * \return sn_coap_hdr_s  The message that needs to be sent to server.
     */
    virtual sn_coap_hdr_s* handle_post_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated,
                                               sn_nsdl_addr_s *address = NULL);

    /**
     * \brief Executes the function that is set in "set_notification_delivery_status_cb".
     * Note: the setter for this callback is marked as m2m_deprecated, but there is no point
     * having it here, as then the code will always give warnings. This simply must be there
     * until the set_notification_delivery_status_cb() is removed.
     */
    void send_notification_delivery_status(const M2MBase& object, const NotificationDeliveryStatus status);

    /**
     * \brief Executes the function that is set in "set_message_delivery_status_cb".
     */
    void send_message_delivery_status(const M2MBase& object, const MessageDeliveryStatus status, const MessageType type);

    /**
     * \brief Sets whether this resource is published to server or not.
     * \param register_uri True sets the resource as part of registration message.
     */
    void set_register_uri(bool register_uri);

    /**
     * \brief Returns whether this resource is published to server or not.
     * \return True if the resource is a part of the registration message, else false.
     */
    bool register_uri();

    /**
     * @brief Returns whether this resource is under observation or not.
     * @return True if the resource is under observation, else false,
     */
    bool is_under_observation() const;

    /**
     * @brief Sets the function that is executed when this
     * object receives a PUT or POST command.
     * @param callback The function pointer that is called.
     * @return True, if callback could be set, false otherwise.
     */
    bool set_value_updated_function(value_updated_callback callback);

    /**
     * @brief Sets the function that is executed when this
     * object receives a PUT or POST command.
     * @param callback The function pointer that is called.
     * @return True, if callback could be set, false otherwise.
     */
    bool set_value_updated_function(value_updated_callback2 callback);

    /**
     * @brief Returns whether a callback function is set or not.
     * @return True if the callback function is set, else false.
     */
    bool is_value_updated_function_set() const;

    /**
     * @brief Calls the function that is set in the "set_value_updated_function".
     * @param name The name of the object.
     */
    void execute_value_updated(const String& name);

    /**
     * @brief Returns length of the object name.
     * @return Length of the object name.
     */
    size_t resource_name_length() const;

    /**
     * @brief Returns the resource information.
     * @return Resource information.
     */
    sn_nsdl_dynamic_resource_parameters_s* get_nsdl_resource() const;

    /**
     * @brief Returns the resource structure.
     * @return Resource structure.
     */
    M2MBase::lwm2m_parameters_s* get_lwm2m_parameters() const;

#ifdef ENABLE_ASYNC_REST_RESPONSE
    /**
     * \brief A trigger to send the async response for the CoAP request.
     * \param code The code for the response, for example: 'COAP_RESPONSE_CHANGED'.
     * \param payload Payload for the resource.
     * \param payload_len Length of the payload.
     * \param token Token for the incoming CoAP request.
     * \param token_len Token length for the incoming CoAP request.
     * \return True if a response is sent, else False.
     */
    bool send_async_response_with_code(const uint8_t *payload,
                                       size_t payload_len,
                                       const uint8_t* token,
                                       const uint8_t token_len,
                                       coap_response_code_e code = COAP_RESPONSE_CHANGED);

    /**
     * @brief Sets the function that is executed when CoAP request arrives.
     * Callback is not called if the request are invalid, for example content-type is not matching.
     * In that case the error response is sent by the client itself.
     * @param callback The function pointer that is called.
     * @param client_args The argument which is passed to the callback function.
     */
    bool set_async_coap_request_cb(handle_async_coap_request_cb callback, void *client_args);

#endif //ENABLE_ASYNC_REST_RESPONSE

    /**
     * @brief Returns the notification message id.
     * @return Message id.
     */
    uint16_t get_notification_msgid() const m2m_deprecated;

    /**
     * @brief Sets the notification message id.
     * This is used to map RESET and EMPTY ACK messages.
     * @param msgid The message id.
     */
    void set_notification_msgid(uint16_t msgid) m2m_deprecated;

    /**
     * @brief Sets the function that is executed when notification message state changes.
     * @param callback The function pointer that is called.
     * @param client_args The argument which is passed to the callback function.
     */
    bool set_notification_delivery_status_cb(notification_delivery_status_cb callback, void *client_args) m2m_deprecated;

    /**
     * @brief Sets the function that is executed when message state changes.
     * Currently this is used to track notifications and delayed response delivery statuses.
     * @param callback The function pointer that is called.
     * @param client_args The argument which is passed to the callback function.
     */
    bool set_message_delivery_status_cb(message_delivery_status_cb callback, void *client_args);

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    static char* create_path(const M2MEndpoint &parent, const char *name);
#endif
    static char* create_path(const M2MObject &parent, const char *name);
    static char* create_path(const M2MObject &parent, uint16_t object_instance);
    static char* create_path(const M2MResource &parent, uint16_t resource_instance);
    static char* create_path(const M2MResource &parent, const char *name);
    static char* create_path(const M2MObjectInstance &parent, const char *name);

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION

    /**
     * @brief The data is set deleted and it needs to be updated into Device Management.
     *        Current implementation maintains the deleted state only in M2MEndpoint.
     *        The deleted state is `false` for every other M2M class.
     */
    virtual void set_deleted();


    /**
     * @brief The deleted state check function.
     * @return True if the deleted state is set, else false.
     */
    virtual bool is_deleted();

#endif // MBED_CLOUD_CLIENT_EDGE_EXTENSION

protected: // from M2MReportObserver

    virtual bool observation_to_be_sent(const m2m::Vector<uint16_t> &changed_instance_ids,
                                        uint16_t obs_number,
                                        bool send_object = false);

    /**
     * \brief Sets the base type for an object.
     * \param type The base type of the object.
     */
    void set_base_type(M2MBase::BaseType type);

    /**
     * \brief Memory allocation required for libCoap.
     * \param size The size of memory to be reserved.
    */
    static void* memory_alloc(uint32_t size);

    /**
     * \brief Memory free functions required for libCoap.
     * \param ptr The object whose memory needs to be freed.
    */
    static void memory_free(void *ptr);

    /**
     * \brief Allocate and make a copy of given zero terminated string. This
     * is functionally equivalent with strdup().
     * \param source The source string to copy, may not be NULL.
    */
    static char* alloc_string_copy(const char* source);

    /**
     * \brief Allocate (size + 1) amount of memory, copy size bytes into
     * it and add zero termination.
     * \param source The source string to copy, may not be NULL.
     * \param size The size of memory to be reserved.
    */
    static uint8_t* alloc_string_copy(const uint8_t* source, uint32_t size);

    /**
     * \brief Allocate (size) amount of memory, copy size bytes into it.
     * \param source The source buffer to copy, may not be NULL.
     * \param size The size of memory to be reserved.
    */
    static uint8_t* alloc_copy(const uint8_t* source, uint32_t size);

    // validate string length to be [min_length..max_length]
    static bool validate_string_length(const String &string, size_t min_length, size_t max_length);
    static bool validate_string_length(const char* string, size_t min_length, size_t max_length);

    /**
     * \brief Create Report Handler object.
     * \return M2MReportHandler object.
    */
    M2MReportHandler* create_report_handler();

    /**
     * \brief Returns the Report Handler object.
     * \return M2MReportHandler object.
    */
    M2MReportHandler* report_handler() const;

    static bool build_path(StringBuffer<MAX_PATH_SIZE> &buffer, const char *s1, uint16_t i1, const char *s2, uint16_t i2);

    static bool build_path(StringBuffer<MAX_PATH_SIZE_2> &buffer, const char *s1, uint16_t i1, const char *s2);

    static bool build_path(StringBuffer<MAX_PATH_SIZE_3> &buffer, const char *s1, uint16_t i1, uint16_t i2);

    static bool build_path(StringBuffer<MAX_PATH_SIZE_4> &buffer, const char *s1, uint16_t i1);

    static char* stringdup(const char* s);

    /**
     * \brief Delete the resource structures owned by this object. Note: this needs
     * to be called separately from each subclass' destructor as this method uses a
     * virtual method and the call needs to be done at same class which has the
     * implementation of the pure virtual method.
     */
    void free_resources();

    /**
     * \brief Returns notification send status.
     * \return Notification status.
     */
    NotificationDeliveryStatus get_notification_delivery_status() const m2m_deprecated;

    /**
     * \brief Clears the notification send status to initial state.
     */
    void clear_notification_delivery_status() m2m_deprecated;

    /**
     * \brief Provides the observation token of the object.
     * \param[out] token A pointer to the value of the token.
     * \param[out] token_length The length of the token pointer.
     */
    void get_observation_token(uint8_t *token, uint8_t &token_length) const;

    /**
     * \brief Sets the observation token value.
     * \param token A pointer to the token of the resource.
     * \param length The length of the token pointer.
     */
    void set_observation_token(const uint8_t *token,
                               const uint8_t length);

    /**
     * \brief The data has changed and it needs to be updated into Device Management.
     *        Current implementation maintains the changed state only in M2MEndpoint. If any of the changes in an
     *        object changes the M2M registration structure, the information is propagated to M2MEndpoint using
     *        this interface.
     */
    virtual void set_changed();

    /**
     * \brief Returns the owner object. Can return NULL if the object has no parent.
     */
    virtual M2MBase *get_parent() const;

    /**
     * \brief Checks whether blockwise is needed to send resource value to server.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param payload_len Length of the CoAP payload.
     * \return True if blockwise transfer is needed, else false.
     */
    static bool is_blockwise_needed(const nsdl_s *nsdl, uint32_t payload_len);

    /**
     * \brief Handles subscription request.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The received CoAP message from the server.
     * \param coap_response The CoAP response to be sent to server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     */
    void handle_observation(nsdl_s *nsdl,
                            const sn_coap_hdr_s &received_coap_header,
                            sn_coap_hdr_s &coap_response,
                            M2MObservationHandler *observation_handler,
                            sn_coap_msg_code_e &response_code);

    /**
     * \brief Start the observation.
     * \param received_coap_header An NSDL handler for the CoAP library.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     */
    void start_observation(const sn_coap_hdr_s &received_coap_header, M2MObservationHandler *observation_handler);

#ifdef ENABLE_ASYNC_REST_RESPONSE

    /**
     * @brief Executes the callback set in 'set_async_coap_request_cb'.
     * @param coap_request CoAP request containing the requesting payload and payload size.
     * @param operation Operation mode to be passed to the application.
     * @param handled Caller to know whether callback is processed or not.
     */
    void call_async_coap_request_callback(sn_coap_hdr_s *coap_request,
                                          M2MBase::Operation operation,
                                          bool &handled);

    /**
     * @brief Returns whether asynchronous callback is set or not.
     * @return True if set otherwise False.
     */
    bool is_async_coap_request_callback_set();

#endif //ENABLE_ASYNC_REST_RESPONSE

private:
    static bool is_integer(const String &value);

    static bool is_integer(const char *value);

    static char* create_path_base(const M2MBase &parent, const char *name);

    lwm2m_parameters_s          *_sn_resource;
    M2MReportHandler            *_report_handler; // TODO: can be broken down to smaller classes with inheritance.

friend class Test_M2MBase;
friend class Test_M2MObject;
friend class M2MNsdlInterface;
friend class M2MInterfaceFactory;
friend class M2MObject;
};

#endif // M2M_BASE_H
