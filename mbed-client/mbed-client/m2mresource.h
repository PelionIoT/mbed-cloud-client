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
#ifndef M2M_RESOURCE_H
#define M2M_RESOURCE_H

#include "mbed-client/m2mvector.h"
#include "mbed-client/m2mresourcebase.h"
#include "mbed-client/m2mresourceinstance.h"
#include "mbed-client/coap_response.h"
#include <stdlib.h>

/*! \file m2mresource.h \brief header for M2MResource. */

//FORWARD DECLARATION
class M2MObjectInstance;
typedef Vector<M2MResourceInstance *> M2MResourceInstanceList;


/**
 * This class represent LwM2M resource.
 *
 * You can create any LwM2M resources with it.
 * This class will also hold all resources instances associated with the given object.
 */
class M2MResource : public M2MResourceBase
{

    friend class M2MObjectInstance;

public:
    class M2MExecuteParameter;

private: // Constructor and destructor are private,
         // which means that these objects can be created or
         // deleted only through a function provided by the M2MObjectInstance.

    M2MResource(M2MObjectInstance &_parent,
                 const lwm2m_parameters_s* s,
                 M2MBase::DataType type);
    /**
     * \brief Constructor
     * \param resource_name The resource name of the object.
     * \param resource_type The resource type of the object.
     * \param type The resource data type of the object.
     * \param value The value pointer of the object.
     * \param value_length The length of the value pointer.
     * \param path Full path of the resource, eg. 1/2/3. Ownership of the memory is transferred.
     * \param object_name The name of the object where the resource exists.
     * \param multiple_instance True if the resource supports instances.
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     */
    M2MResource(M2MObjectInstance &_parent,
                const String &resource_name,
                M2MBase::Mode mode,
                const String &resource_type,
                M2MBase::DataType type,
                const uint8_t *value,
                const uint8_t value_length,
                char *path,
                bool multiple_instance = false,
                bool external_blockwise_store = false);

    /**
     * \brief Constructor
     * \param resource_name The resource name of the object.
     * \param resource_type The resource type of the object.
     * \param type The resource data type of the object.
     * \param observable Indicates whether the resource is observable or not.
     * \param path Full path of the resource, eg. 1/2/3. Ownership of the memory is transferred.
     * \param object_name The name of the object where the resource exists.
     * \param multiple_instance True if the resource supports instances.
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     */
    M2MResource(M2MObjectInstance &_parent,
                const String &resource_name,
                M2MBase::Mode mode,
                const String &resource_type,
                M2MBase::DataType type,
                bool observable,
                char *path,
                bool multiple_instance = false,
                bool external_blockwise_store = false);

    // Prevents the use of a default constructor.
    M2MResource();

    // Prevents the use of an assignment operator.
    M2MResource& operator=( const M2MResource& /*other*/ );

    // Prevents the use of a copy constructor
    M2MResource( const M2MResource& /*other*/ );

    /**
     * \brief Returns the owner object. Can return NULL if the object has no parent.
     */
    virtual M2MBase *get_parent() const;

    /**
     * Destructor
     */
    virtual ~M2MResource();

public:

    /**
     * \brief Adds resource instances to a M2MResource.
     * \param resource_instance The resource instance to be added.
     */
    void add_resource_instance(M2MResourceInstance *resource_instance);

    /**
     * \brief Returns whether the resource has multiple
     * resource instances or not.
     * \return True if the resource base has multiple instances,
     * else false.
     */
    bool supports_multiple_instances() const;

#ifndef DISABLE_DELAYED_RESPONSE
    /**
     * \brief Sets whether the resource should send a delayed response for a POST request.
     * This only works for resources which don't support multiple instances.
     * Please use M2MBase::set_async_coap_request_cb method, if you are using
     * ENABLE_ASYNC_REST_RESPONSE flag, because this method will be deprecated.
     * \param delayed_response A boolean value to set the delayed response.
     */
#ifdef ENABLE_ASYNC_REST_RESPONSE
    void set_delayed_response(bool delayed_response) m2m_deprecated;
#else
    void set_delayed_response(bool delayed_response);
#endif
    /**
     * \brief Check if resource is set to send delayed responses for POST request.
     * Use set_delayed_response() for enabling or disabling delayed response.
     * \return True, if delayed response is enabled.
     */
    bool delayed_response() const;

    /**
     * \brief A trigger to send the delayed response for the POST request.
     * The delayed_response flag must be set before receiving the POST request
     * and the value of the resource must be updated before calling this function.
     * This sends the post response with the code provided by caller.
     * Please use M2MBase::send_async_response_with_code method, if you are using
     * ENABLE_ASYNC_REST_RESPONSE flag, because this method will be deprecated.
     * \param code Response code to be sent.
     * \return True if delayed response is enabled.
     */
    bool send_delayed_post_response(sn_coap_msg_code_e code = COAP_MSG_CODE_RESPONSE_CHANGED);

    /** \internal
     * \brief Provides the value of the token of the delayed post response.
     * \param[out] token A pointer to the token value.
     * \param[out] token_length The length of the token pointer.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    void get_delayed_token(uint8_t *&token, uint8_t &token_length);

#endif //DISABLE_DELAYED_RESPONSE

    /**
     * \brief Removes a resource with a given name.
     * \param instance_id The instance ID of the resource to be removed, default is 0.
     * \return True if removed, else false.
     */
    bool remove_resource_instance(uint16_t instance_id = 0);

    /**
     * \brief Returns a resource instance with a given name.
     * \param instance_id The instance ID of the requested resource, default is 0
     * \return M2MResourceInstance object if found, else NULL.
     */
    M2MResourceInstance* resource_instance(uint16_t instance_id = 0) const;

    /**
     * \brief Returns a list of resources.
     * \return A list of resources.
     */
    const M2MResourceInstanceList& resource_instances() const;

    /**
     * \brief Returns the total number of resources.
     * \return The total number of resources.
     */
    uint16_t resource_instance_count() const;

    /**
     * \brief Returns the Observation Handler object.
     * \return M2MObservationHandler object.
     *
     * \deprecated Internal API, subject to be modified or removed.
    */
    virtual M2MObservationHandler* observation_handler() const;

    /**
     * \brief Sets the observation handler
     * \param handler Observation handler
     *
     * \deprecated Internal API, subject to be modified or removed.
    */
    virtual void set_observation_handler(M2MObservationHandler *handler);

#if defined (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS) && (MBED_CONF_MBED_CLIENT_ENABLE_OBSERVATION_PARAMETERS == 1)
    /**
     * \brief Parses the received query for a notification
     * attribute.
     * \return True if required attributes are present, else false.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual bool handle_observation_attribute(const char *query);
#endif

    /**
     * \brief Adds the observation level for the object.
     * \param observation_level The level of observation.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual void add_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Removes the observation level from an object.
     * \param observation_level The level of observation.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual void remove_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Handles the GET request for registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \return sn_coap_hdr_s The message that needs to be sent to the server.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual sn_coap_hdr_s* handle_get_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler = NULL);
    /**
     * \brief Handles the PUT request for registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \param execute_value_updated True executes the "value_updated" callback.
     * \return sn_coap_hdr_s The message that needs to be sent to the server.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual sn_coap_hdr_s* handle_put_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated);
    /**
     * \brief Handles the POST request for registered objects.
     * \param nsdl An NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler A handler object for sending
     * observation callbacks.
     * \param execute_value_updated True executes the "value_updated" callback.
     * \return sn_coap_hdr_s The message that needs to be sent to the server.
     *
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual sn_coap_hdr_s* handle_post_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated,
                                               sn_nsdl_addr_s *address = NULL);

    /**
     * \deprecated Internal API, subject to be modified or removed.
     */
    M2MObjectInstance& get_parent_object_instance() const;

    /**
     * \brief Returns the instance ID of the object where the resource exists.
     * \return Object instance ID.
    */
    virtual uint16_t object_instance_id() const;

    /**
     * \brief Returns the name of the object where the resource exists.
     * \return Object name.
    */
    virtual const char* object_name() const;

    virtual M2MResource& get_parent_resource() const;

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    /**
     * \brief save the status of the manifest verification.
     */
    void set_manifest_check_status(bool status);

    /**
     * \brief return the status of the manifest verification for subdevice.
     * \return manifest status
     */
    bool get_manifest_check_status();
#endif

private:
    M2MObjectInstance &_parent;

    M2MResourceInstanceList     _resource_instance_list; // owned

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    bool                        _status;
#endif

#ifndef DISABLE_DELAYED_RESPONSE
    uint8_t                     *_delayed_token;
    uint8_t                     _delayed_token_len;
    bool                        _delayed_response;
#endif

friend class Test_M2MResource;
friend class Test_M2MObjectInstance;
friend class Test_M2MObject;
friend class Test_M2MDevice;
friend class Test_M2MSecurity;
friend class Test_M2MServer;
friend class Test_M2MReportHandler;
friend class Test_M2MNsdlInterface;
friend class Test_M2MInterfaceFactory;
friend class Test_M2MTLVSerializer;
friend class Test_M2MTLVDeserializer;
friend class Test_M2MBase;
friend class Test_M2MResourceInstance;
friend class TestFactory;
friend class Test_M2MInterfaceImpl;
friend class Test_M2MDiscover;
};

/**
 *  \brief M2MResource::M2MExecuteParameter.
 *  This class handles the "Execute" operation arguments.
 */
class M2MResource::M2MExecuteParameter {

private:

    /**
     * \brief Constructor, since there is no implementation, it prevents invalid use of it
     */
    M2MExecuteParameter();

#ifdef MEMORY_OPTIMIZED_API
    M2MExecuteParameter(const char *object_name, const char *resource_name, uint16_t object_instance_id);
#else
    /**
     * \deprecated This is a deprecated constructor. Subject to be removed.
     */
    M2MExecuteParameter(const String &object_name, const String &resource_name, uint16_t object_instance_id);
#endif
public:

    /**
     * \brief Returns the value of an argument.
     * \return uint8_t * The argument value.
     */
    const uint8_t *get_argument_value() const;

    /**
     * \brief Returns the length of the value argument.
     * \return uint8_t The argument value length.
     */
    uint16_t get_argument_value_length() const;

    /**
     * \brief Returns the name of the object where the resource exists.
     * \return Object name.
    */
#ifdef MEMORY_OPTIMIZED_API
    const char* get_argument_object_name() const;
#else
    const String& get_argument_object_name() const;
#endif

    /**
     * \brief Returns the resource name.
     * \return Resource name.
    */
#ifdef MEMORY_OPTIMIZED_API
    const char* get_argument_resource_name() const;
#else
    const String& get_argument_resource_name() const;
#endif

    /**
     * \brief Returns the instance ID of the object where the resource exists.
     * \return Object instance ID.
    */
    uint16_t get_argument_object_instance_id() const;

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    /** \brief Storing the instance of the resource class.
     * \param res Resource pointer to be stored.
     */
    void set_resource(M2MResource* res);

    /**
    * \brief Returns the Resource pointer.
    * \return M2MResource pointer.
     */
    M2MResource * get_resource();

#endif

private:
    // pointers to const data, not owned by this instance

#ifdef MEMORY_OPTIMIZED_API
    const char      *_object_name;
    const char      *_resource_name;
#else
    const String    &_object_name;
    const String    &_resource_name;
#endif
    const uint8_t   *_value;
    uint16_t        _value_length;
    uint16_t        _object_instance_id;
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    M2MResource     *_resource;
#endif

friend class Test_M2MResource;
friend class M2MResource;
};

#endif // M2M_RESOURCE_H
