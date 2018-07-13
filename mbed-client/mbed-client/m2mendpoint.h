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
#ifndef M2M_ENDPOINT_H
#define M2M_ENDPOINT_H

#include "mbed-client/m2mvector.h"
#include "mbed-client/m2mbase.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mstring.h"

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION

//FORWARD DECLARATION
typedef Vector<M2MObject *> M2MObjectList;

/*! \file M2MEndpoint.h
 *  \brief M2MEndpoint.
 *  This class can be used to represent an LwM2M Device endpoint, it contains a list of LwM2M objects.
 *  It implements the M2MBase interface so it can be passed to the m2minterface for registering to server.
 */

class M2MEndpoint : public M2MBase
{

friend class M2MInterfaceFactory;
friend class M2MNsdlInterface;
friend class TestFactory;
friend class Test_M2MObject;

protected :

    /**
     * \brief Constructor
     * \param name The name of the object.
     * \param path Path of the object like 3/0/1
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     */
    M2MEndpoint(const String &object_name,
              char *path);

    // Prevents the use of default constructor.
    M2MEndpoint();

    // Prevents the use of assignment operator.
    M2MEndpoint& operator=( const M2MEndpoint& /*other*/ );

    // Prevents the use of copy constructor.
    M2MEndpoint( const M2MEndpoint& /*other*/ );

    /*
     * \brief Data has been changed and it needs to be updated to Mbed Cloud.
     */
    virtual void set_changed();

    /*
     * \brief Clears the changed flag. This can be done when the data has been updated into Mbed Cloud.
     */
    void clear_changed();

    /*
     * \brief Returns current changed status.
     */
    bool get_changed() const;


public:

    /**
     * \brief Destructor
     */
    virtual ~M2MEndpoint();

    /**
     * \brief Creates a new object for a given mbed Client endpoint instance. With this,
     * the client can respond to server's GET methods with the provided value.
     * \return M2MObject. An object for managing object instances and resources.
     */
    M2MObject* create_object(const String &name);

    /**
     * \brief Removes the object with the given id.
     * \param object_id The ID of the object to be removed, default is 0.
     * \return True if removed, else false.
     */
    bool remove_object(const String &name);

    /**
     * \brief Returns the object with the the given ID.
     * \param instance_id The ID of the requested object ID, default is 0.
     * \return Object reference if found, else NULL.
     */
    M2MObject* object(const String &name) const;

    /**
     * \brief Returns a list of objects.
     * \return A list of objects.
     */
    const M2MObjectList& objects() const;

    /**
     * \brief Returns the total number of objects-
     * \return The total number of the objects.
     */
    uint16_t object_count() const;

    /**
     * \brief Returns the Observation Handler object.
     * \return M2MObservationHandler object.
    */
    virtual M2MObservationHandler* observation_handler() const;

    /**
     * \brief Sets the observation handler
     * \param handler Observation handler
    */
    virtual void set_observation_handler(M2MObservationHandler *handler);

    /**
     * \brief Adds the observation level for the object.
     * \param observation_level The level of observation.
     */
    virtual void add_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Removes the observation level from the object.
     * \param observation_level The level of observation.
     */
    virtual void remove_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Handles GET request for the registered objects.
     * \param nsdl The NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler The handler object for sending
     * observation callbacks.
     * \return sn_coap_hdr_s  The message that needs to be sent to server.
     */
    virtual sn_coap_hdr_s* handle_get_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler = NULL);

    /**
     * \brief Handles PUT request for the registered objects.
     * \param nsdl The NSDL handler for the CoAP library.
     * \param received_coap_header The received CoAP message from the server.
     * \param observation_handler The handler object for sending
     * observation callbacks.
     * \param execute_value_updated True will execute the "value_updated" callback.
     * \return sn_coap_hdr_s The message that needs to be sent to server.
     */
    virtual sn_coap_hdr_s* handle_put_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated);

    /**
     * \brief Handles GET request for the registered objects.
     * \param nsdl The NSDL handler for the CoAP library.
     * \param received_coap_header The received CoAP message from the server.
     * \param observation_handler The handler object for sending
     * observation callbacks.
     * \param execute_value_updated True will execute the "value_updated" callback.
     * \return sn_coap_hdr_s The message that needs to be sent to server.
     */
    virtual sn_coap_hdr_s* handle_post_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated,
                                               sn_nsdl_addr_s *address = NULL);

    /**
     * \brief Set the user defined context for this M2MEndpoint.
     * \param ctx pointer to allocated context, lifecycle must be handled outside of M2MEndpoint.
     */
    void set_context(void *ctx);

    /**
     * \brief Get the user defined context set for this M2MEndpoint.
     * \return The user defined context or NULL if not set. The lifecycle of the user defined context
     * is handled outside of M2MEndpoint.
     */
    void* get_context() const;

protected :


private:

    M2MObjectList     _object_list; // owned
    M2MObservationHandler    *_observation_handler; // Not owned
    void             *_ctx; // user defined context
    bool             _changed; // True if modifications have been done to this endpoint since last registration update.
                               // False otherwise.

friend class Test_M2MEndpoint;
friend class Test_M2MInterfaceImpl;
friend class Test_M2MNsdlInterface;
friend class Test_M2MTLVSerializer;
friend class Test_M2MTLVDeserializer;
friend class Test_M2MDevice;
friend class Test_M2MFirmware;
friend class Test_M2MBase;
friend class Test_M2MResource;
friend class Test_M2MSecurity;
friend class Test_M2MServer;
friend class Test_M2MResourceInstance;
};

#endif // MBED_CLOUD_CLIENT_EDGE_EXTENSION

#endif // M2M_ENDPOINT_H
