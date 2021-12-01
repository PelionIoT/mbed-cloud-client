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
#ifndef M2M_RESOURCE_BASE_H
#define M2M_RESOURCE_BASE_H

#include "mbed-client/m2mbase.h"
#include "mbed-client/functionpointer.h"

// (space needed for -3.402823 × 10^38) + (magic decimal 6 digits added as no precision is added to "%f") + trailing zero
#define REGISTRY_FLOAT_STRING_MAX_LEN 48

/*! \file m2mresourcebase.h \brief header for M2MResourceBase. */

// Forward declarations

class M2MBlockMessage;
class M2MCallbackAssociation;

typedef FP1<void, void *> execute_callback;
typedef void(*execute_callback_2)(void *arguments);

typedef FP0<void> notification_sent_callback;
typedef void(*notification_sent_callback_2)(void);

#ifndef DISABLE_BLOCK_MESSAGE
typedef FP1<void, M2MBlockMessage *> incoming_block_message_callback;
typedef FP3<void, const String &, uint8_t *&, uint32_t &> outgoing_block_message_callback;
#endif

class M2MResource;

/**
 * This class is a base class for LwM2M resources.
 * Common functionality between M2MResource and M2MResourceInstance is here.
 */
class M2MResourceBase : public M2MBase {

    friend class M2MObjectInstance;
    friend class M2MResource;
    friend class M2MResourceInstance;

public:

    /**
     * An enum defining a resource type that can be
     * supported by a given resource.
    */
    typedef enum {
        STRING,
        INTEGER,
        FLOAT,
        BOOLEAN,
        OPAQUE,
        TIME,
        OBJLINK
    } ResourceType;

    /**
     * \brief Value set callback function.
     * \param resource Pointer to resource whose value should be updated
     * \param value Pointer to value buffer containing new value, ownership is transferred to callback function
     * \param value_length Length of value buffer
     */
    typedef void(*value_set_callback)(const M2MResourceBase *resource, uint8_t *value, const uint32_t value_length);

    /**
     * \brief Read resource value callback function.
     * \param resource Pointer to resource whose value should will be read
     * \param buffer[OUT] Buffer containing the resource value
     * \param buffer_size[IN/OUT] Buffer length
     * \param client_args Client arguments
     * \return Error code, 0 on success otherwise < 0
     */
    typedef int(*read_resource_value_callback)(const M2MResourceBase &resource,
                                               void *buffer,
                                               size_t *buffer_size,
                                               void *client_args);

    /**
     * \brief Type definition for a read resource value callback function.
     * \param[in]       resource        Pointer to resource whose value should will be read.
     * \param[out]      buffer          Pointer to value buffer.
     * \param[in, out]  buffer_size     On input, tells the maximum size of bytes to read. On output, tells how many bytes have been written to buffer.
     * \param[out]      total_size      Total size of the resource data.
     * \param[in]       offset          Offset to read from in data.
     * \param[in]       client_args     Client arguments.
     * \return CoAP response code for the response.
     */
    typedef coap_response_code_e(*read_value_callback)(const M2MResourceBase &resource,
                                                       uint8_t *&buffer,
                                                       size_t &buffer_size,
                                                       size_t &total_size,
                                                       const size_t offset,
                                                       void *client_args);

    /**
     * \brief Read resource value size callback function.
     * \param resource Pointer to resource whose size will be read
     * \param buffer_size[OUT] Buffer size
     * \param client_args Client arguments
     * \return Error code, 0 on success otherwise < 0
     */
    typedef int(*read_resource_value_size_callback)(const M2MResourceBase &resource,
                                                    size_t *buffer_size,
                                                    void *client_args);

    /**
     * \brief Set resource value callback function.
     * \param resource Pointer to resource whose value will be updated
     * \param buffer Buffer containing the new value
     * \param buffer_size Size of the data
     * \param client_args Client arguments
     * \return error code, True if value storing completed otherwise False
     */
    typedef bool(*write_resource_value_callback)(const M2MResourceBase &resource,
                                                 const uint8_t *buffer,
                                                 const size_t buffer_size,
                                                 void *client_args);

protected: // Constructor and destructor are private
    // which means that these objects can be created or
    // deleted only through a function provided by the M2MObjectInstance.

    M2MResourceBase(
        const lwm2m_parameters_s *s,
        M2MBase::DataType type);
    /**
     * \brief A constructor for creating a resource.
     * \param resource_name The name of the resource.
     * \param resource_type The type of the resource.
     * \param type The resource data type of the object.
     * \param object_name Object name where resource exists.
     * \param path Path of the object like 3/0/1
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     */
    M2MResourceBase(
        const String &resource_name,
        M2MBase::Mode mode,
        const String &resource_type,
        M2MBase::DataType type,
        char *path,
        bool external_blockwise_store,
        bool multiple_instance);

    /**
     * \brief A Constructor for creating a resource.
     * \param resource_name The name of the resource.
     * \param resource_type The type of the resource.
     * \param type The resource data type of the object.
     * \param value The value pointer of the object.
     * \param value_length The length of the value pointer.
     * \param value_length The length of the value pointer.
     * \param object_name Object name where resource exists.
     * \param path Path of the object like 3/0/1
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     */
    M2MResourceBase(
        const String &resource_name,
        M2MBase::Mode mode,
        const String &resource_type,
        M2MBase::DataType type,
        const uint8_t *value,
        const uint8_t value_length,
        char *path,
        bool external_blockwise_store,
        bool multiple_instance);

    // Prevents the use of default constructor.
    M2MResourceBase();

    // Prevents the use of assignment operator.
    M2MResourceBase &operator=(const M2MResourceBase & /*other*/);

    // Prevents the use of copy constructor
    M2MResourceBase(const M2MResourceBase & /*other*/);

    /**
     * Destructor
     */
    virtual ~M2MResourceBase();

public:

    /**
     * \brief Returns the resource data type.
     * \return ResourceType.
     */
    M2MResourceBase::ResourceType resource_instance_type() const;

    /**
     * \brief Sets the function that should be executed when this
     * resource receives a POST command.
     * \param callback The function pointer that needs to be executed.
     * \return True, if callback could be set, false otherwise.
     *
     * \deprecated Function pointer classes are deprecated. Please use M2MResourceBase::set_execute_function(execute_callback_2 callback) instead.
     */
    bool set_execute_function(execute_callback callback);

    /**
     * \brief Sets the function that should be executed when this
     * resource receives a POST command.
     * \param callback The function pointer that needs to be executed.
     * \return True, if callback could be set, false otherwise.
     */
    bool set_execute_function(execute_callback_2 callback);

    /**
     * \brief Sets the callback function that is executed when reading the resource value.
     * \param callback The function pointer that needs to be executed.
     * \param client_args Client arguments.
     * \return True, if callback could be set, false otherwise.
     */
    bool set_resource_read_callback(read_resource_value_callback callback, void *client_args) m2m_deprecated;

    /**
     * @brief Sets the function that is executed when this object receives a GET request.
     * \param client_args Client arguments.
     * \return True, if callback could be set, false otherwise.
     */
    bool set_read_resource_function(read_value_callback callback, void *client_args);

    /**
     * \brief Sets the callback function that is executed when reading the resource value size.
     * \param callback The function pointer that needs to be executed.
     * \param client_args Client arguments.
     * \return True, if callback could be set, false otherwise.
     */
    bool set_resource_read_size_callback(read_resource_value_size_callback callback, void *client_args);

    /**
     * \brief Sets the callback function that is executed when writing the resource value.
     * \param callback The function pointer that needs to be executed.
     * \param client_args Client arguments.
     * \return True, if callback could be set, false otherwise.
     */
    bool set_resource_write_callback(write_resource_value_callback callback, void *client_args);

    /**
     * \brief Executes the function that is set in "set_resource_read_callback".
     * \note If "read_resource_value_callback" is not set this is internally calling value() and value_length() API's.
     * \param resource Pointer to resource whose value will be read.
     * \param buffer[OUT] Buffer where the value is stored.
     * \param[in, out]  buffer_len On input, tells the maximum size of bytes to read. On output, tells how many bytes have been written to buffer.
     * \return Error code, 0 on success otherwise < 0
     */
    int read_resource_value(const M2MResourceBase &resource, void *buffer, size_t *buffer_len);

    /**
     * \brief Executes the function that is set in "set_resource_read_size_callback".
     * \note If "read_resource_value_size_callback" is not set this is internally calling value_length() API.
     * \param resource Pointer to resource whose size will be read.
     * \param buffer_len[OUT] Buffer size
     * \return Error code, 0 on success otherwise < 0
     */
    int read_resource_value_size(const M2MResourceBase &resource, size_t *buffer_len);

    /**
     * \brief Executes the function that is set in "set_resource_write_callback".
     * \param resource Pointer to resource where value will be stored.
     * \param buffer Buffer containing the new value.
     * \param buffer_size Size of the data.
     * \return True if storing succeeded otherwise False.
     */
    bool write_resource_value(const M2MResourceBase &resource, const uint8_t *buffer, const size_t buffer_size);

    /**
     * \brief Sets a value of a given resource.
     * \param value A pointer to the value to be set on the resource.
     * \param value_length The length of the value pointer.
     * \return True if successfully set, else false.
     * \note If resource is observable, calling this API rapidly (< 1s) can fill up the CoAP resending queue
     * and notification sending fails. CoAP resending queue size can be modified through:
     * "sn-coap-resending-queue-size-msgs" and "sn-coap-resending-queue-size-bytes" parameters.
     * Increasing these parameters will increase the memory consumption.
     */
    bool set_value(const uint8_t *value, const uint32_t value_length);

    /**
     * \brief Sets a value of a given resource.
     * \param value A pointer to the value to be set on the resource, ownerhip transfered.
     * \param value_length The length of the value pointer.
     * \return True if successfully set, else false.
     * \note If resource is observable, calling this API rapidly (< 1s) can fill up the CoAP resending queue
     * and notification sending fails. CoAP resending queue size can be modified through:
     * "sn-coap-resending-queue-size-msgs" and "sn-coap-resending-queue-size-bytes" parameters.
     * Increasing these parameters will increase the memory consumption.
     */
    bool set_value_raw(uint8_t *value, const uint32_t value_length);

    /**
     * \brief Sets a value of a given resource.
     * \param value, A new value formatted as a string
     * and set on the resource.
     * \return True if successfully set, else false.
     * \note If resource is observable, calling this API rapidly (< 1s) can fill up the CoAP resending queue
     * and notification sending fails. CoAP resending queue size can be modified through:
     * "sn-coap-resending-queue-size-msgs" and "sn-coap-resending-queue-size-bytes" parameters.
     * Increasing these parameters will increase the memory consumption.
     */
    bool set_value(int64_t value);

    /**
     * \brief Sets a value of a given resource.
     * \param value, A new value formatted as a string
     * and set on the resource.
     * \return True if successfully set, else false.
     * \note If resource is observable, calling this API rapidly (< 1s) can fill up the CoAP resending queue
     * and notification sending fails. CoAP resending queue size can be modified through:
     * "sn-coap-resending-queue-size-msgs" and "sn-coap-resending-queue-size-bytes" parameters.
     * Increasing these parameters will increase the memory consumption.
     */
    bool set_value_float(float value);

    /**
     * \brief Clears the value of a given resource.
     */
    void clear_value();

    /**
     * \brief Executes the function that is set in "set_execute_function".
     * \param arguments The arguments that are passed to be executed.
     */
    void execute(void *arguments);

    /**
     * \brief Provides the value of the given resource.
     * \param value[OUT] A pointer to the resource value.
     * \param value_length[OUT] The length of the value pointer.
     * \note If value argument is not NULL, it will be freed.
     */
    void get_value(uint8_t *&value, uint32_t &value_length);

    /**
     * \brief Converts a value to integer and returns it. Note: Conversion
     * errors are not detected.
     * \return int64 value.
     */
    int64_t get_value_int() const;

    /**
     * Get the value as a string object. No encoding/charset conversions
     * are done for the value, just a raw copy.
     * \return value as a String object.
     */
    String get_value_string() const;

    /**
     * \brief Converts a value to float and returns it. Note: Conversion
     * errors are not detected.
     * \return value as a float.
     */
    float get_value_float() const;

    /**
     * \brief Returns the value pointer of the object.
     * \return The value pointer of the object.
     */
    uint8_t *value() const;

    /**
     * \brief Returns the length of the value pointer.
     * \return The length of the value pointer.
     */
    uint32_t value_length() const;

    /**
     * \brief Set the value set callback. The set callback will be called instead of setting
     * the value in set_value methods. When this function is set actual value change is done
     * using the update_value function.
     * \param callback Callback function that will handle new value
     */
    void set_value_set_callback(value_set_callback callback);

    /**
     * \brief Default value update function. This function frees old value, stores the new value
     * and informs report handler in case it changed.
     * \param value Pointer to new value, ownership is transferred to client
     * \param value_length Length of new value buffer
     */
    void update_value(uint8_t *value, const uint32_t value_length);

    /**
     * \brief Function to report the value changes to the object instance and object parent of the
     * resource if they have been subscribed
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    void report_to_parents();

    /**
     * \brief Handles the GET request for the registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \return sn_coap_hdr_s The message that needs to be sent to the server.
     */
    virtual sn_coap_hdr_s *handle_get_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler = NULL);
    /**
     * \brief Handles the PUT request for the registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \param execute_value_updated True will execute the "value_updated" callback.
     * \return sn_coap_hdr_s The message that needs to be sent to the server.
     */
    virtual sn_coap_hdr_s *handle_put_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated);

    /**
     * \brief Returns the instance ID of the object where the resource exists.
     * \return Object instance ID.
    */
    virtual uint16_t object_instance_id() const = 0;

    /**
     * \brief Returns the name of the object where the resource exists.
     * \return Object name.
    */
    virtual const char *object_name() const = 0;

    /**
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual M2MResource &get_parent_resource() const = 0;

#ifndef DISABLE_BLOCK_MESSAGE
    /**
     * @brief Sets the function that is executed when this
     * object receives a block-wise message.
     * @param callback The function pointer that is called.
     * @return True if successfully set, otherwise return False.
     */
    bool set_incoming_block_message_callback(incoming_block_message_callback callback);

    /**
     * @brief Sets the function that is executed when this
     * object receives a GET request.
     * This is called if resource values are stored on the application side.
     * @note Due to a limitation in the mbed-client-c library, the whole
     * payload up to 64 KiB must be supplied in the single callback.
     * @param callback The function pointer that is called.
     * @return True if successfully set, otherwise return False.
     */
    bool set_outgoing_block_message_callback(outgoing_block_message_callback callback) m2m_deprecated;

    /**
     * \brief Returns the block message object.
     * \return Block message.
    */
    M2MBlockMessage *block_message() const;

#endif

    /**
     * @brief Set the status whether resource value will be part of registration message.
     * This only allowed for following resource types:
     * STRING,
     * INTEGER,
     * FLOAT,
     * BOOLEAN
     * OPAQUE
     *
     * @param publish_value If true then resource value will be part of registration message.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    void publish_value_in_registration_msg(bool publish_value);

private:

    void report();

    void report_value_change();

    bool has_value_changed(const uint8_t *value, const uint32_t value_len);

    M2MResourceBase::ResourceType convert_data_type(M2MBase::DataType type) const;

    void read_data_from_application(M2MCallbackAssociation *item, nsdl_s *nsdl, const sn_coap_hdr_s *received_coap,
                                    sn_coap_hdr_s *coap_response, size_t &payload_len);

private:

#ifndef DISABLE_BLOCK_MESSAGE
    M2MBlockMessage     *_block_message_data;
#endif

    friend class Test_M2MResourceInstance;
    friend class Test_M2MResource;
    friend class Test_M2MObjectInstance;
    friend class Test_M2MObject;
    friend class Test_M2MDevice;
    friend class Test_M2MSecurity;
    friend class Test_M2MServer;
    friend class Test_M2MNsdlInterface;
    friend class Test_M2MTLVSerializer;
    friend class Test_M2MTLVDeserializer;
    friend class Test_M2MDynLog;
};

#endif // M2M_RESOURCE_BASE_H
