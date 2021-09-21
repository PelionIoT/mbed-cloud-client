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
#ifndef M2M_OBJECT_H
#define M2M_OBJECT_H

#include "mbed-client/m2mvector.h"
#include "mbed-client/m2mbase.h"
#include "mbed-client/m2mobjectinstance.h"

//FORWARD DECLARATION
typedef Vector<M2MObjectInstance *> M2MObjectInstanceList;

class M2MEndpoint;

/** \file m2mobject.h \brief header M2MObject */

/** The base class for LwM2M Objects.
 *
 * Use this class to define LwM2M objects.
 * This class also holds all object instances associated with the given object.
 */
class M2MObject : public M2MBase {

    friend class M2MInterfaceFactory;
    friend class M2MEndpoint;
    friend class TestFactory;

protected :

    /**
     * \brief Constructor
     * \param object_name The name of the object.
     * \param path Path of the object, such as 3/0/1
     * \param external_blockwise_store If true, CoAP blocks are passed to application through callbacks,
     *        otherwise handled in mbed-client-c.
     */
    M2MObject(const String &object_name,
              char *path,
              bool external_blockwise_store = false);

    // Prevents the use of default constructor.
    M2MObject();

    // Prevents the use of assignment operator.
    M2MObject &operator=(const M2MObject & /*other*/);

    // Prevents the use of copy constructor.
    M2MObject(const M2MObject & /*other*/);

    /**
     * \brief Constructor
     * \param name The name of the object.
     */
    M2MObject(const M2MBase::lwm2m_parameters_s *static_res);

public:

    /**
     * \brief Destructor
     */
    virtual ~M2MObject();

    /**
     * \brief Creates a new object instance for a given mbed Client Interface object. With this,
     * the client can respond to server's GET methods with the provided value.
     * \return M2MObjectInstance. An object instance for managing other client operations.
     */
    M2MObjectInstance *create_object_instance(uint16_t instance_id = 0);

    /**
     * \brief Creates a new object instance for a given mbed Client Interface object. With this,
     * the client can respond to server's GET methods with the provided value.
     * \return M2MObjectInstance. An object instance for managing other client operations.
     *
     * \deprecated Internal lwm2m_parameter_s structure is deprecated. Please use M2MObject::create_object_instance(uint16_t) instead.
     */
    M2MObjectInstance *create_object_instance(const lwm2m_parameters_s *s);

    /**
     * \brief Removes the object instance resource with the given instance id.
     * \param instance_id The instance ID of the object instance to be removed, default is 0.
     * \return True if removed, else false.
     */
    bool remove_object_instance(uint16_t instance_id = 0);

    /**
     * \brief Returns the object instance with the the given instance ID.
     * \param instance_id The instance ID of the requested object instance ID, default is 0.
     * \return Object instance reference if found, else NULL.
     */
    M2MObjectInstance *object_instance(uint16_t instance_id = 0) const;

    /**
     * \brief Returns a list of object instances.
     * \return A list of object instances.
     */
    const M2MObjectInstanceList &instances() const;

    /**
     * \brief Returns the total number of object instances-
     * \return The total number of the object instances.
     */
    uint16_t instance_count() const;

    /**
     * \brief Returns instance id to be used for new instances.
     * \return The instance id of last instance in the list + 1
     */
    uint16_t new_instance_id() const;

    /**
     * \brief Returns the Observation Handler object.
     * \return M2MObservationHandler object.
     * \deprecated Internal API, subject to be modified or removed.
    */
    virtual M2MObservationHandler *observation_handler() const;

    /**
     * \brief Sets the observation handler
     * \param handler Observation handler
     * \deprecated Internal API, subject to be modified or removed.
    */
    virtual void set_observation_handler(M2MObservationHandler *handler);

    /**
     * \brief Adds the observation level for the object.
     * \param observation_level The level of observation.
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual void add_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Removes the observation level from the object.
     * \param observation_level The level of observation.
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual void remove_observation_level(M2MBase::Observation observation_level);

    /**
     * \brief Handles GET request for the registered objects.
     * \param nsdl The NSDL handler for the CoAP library.
     * \param received_coap_header The CoAP message received from the server.
     * \param observation_handler The handler object for sending
     * observation callbacks.
     * \return sn_coap_hdr_s  The message that needs to be sent to server.
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual sn_coap_hdr_s *handle_get_request(nsdl_s *nsdl,
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
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual sn_coap_hdr_s *handle_put_request(nsdl_s *nsdl,
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
     * \deprecated Internal API, subject to be modified or removed.
     */
    virtual sn_coap_hdr_s *handle_post_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated,
                                               sn_nsdl_addr_s *address = NULL);

    /**
     * \deprecated Internal API, subject to be modified or removed.
     */
    void notification_update(uint16_t obj_instance_id);

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    void set_endpoint(M2MEndpoint *endpoint);

    M2MEndpoint *get_endpoint() const;
#endif

protected :
    /**
     * \brief Returns the owner object. Can return NULL if the object has no parent.
     */
    virtual M2MBase *get_parent() const;

private:

    M2MObjectInstanceList     _instance_list; // owned

    M2MObservationHandler    *_observation_handler; // Not owned

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    M2MEndpoint              *_endpoint; // Parent endpoint
#endif

    friend class Test_M2MObject;
    friend class Test_M2MEndpoint;
    friend class Test_M2MInterfaceImpl;
    friend class Test_M2MInterfaceFactory;
    friend class Test_M2MNsdlInterface;
    friend class Test_M2MTLVSerializer;
    friend class Test_M2MTLVDeserializer;
    friend class Test_M2MDevice;
    friend class Test_M2MBase;
    friend class Test_M2MObjectInstance;
    friend class Test_M2MResource;
    friend class Test_M2MSecurity;
    friend class Test_M2MServer;
    friend class Test_M2MReportHandler;
    friend class Test_M2MResourceInstance;
    friend class Test_M2MDiscover;
    friend class Test_M2MDynLog;
};

#endif // M2M_OBJECT_H
