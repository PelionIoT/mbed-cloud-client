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
#ifndef M2M_INTERFACE_FACTORY_H
#define M2M_INTERFACE_FACTORY_H

#include <stdlib.h>
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2minterfaceobserver.h"

//FORWARD DECLARATION
class M2MDevice;
class M2MServer;
class M2MInterfaceImpl;
class M2MFirmware;

/** \file m2minterfacefactory.h \brief header for M2MInterfaceFactory. */

/**  This is a factory class that allows you to create an M2MInterface
 *   object.
 */

class  M2MInterfaceFactory {
private:
    // Prevents the use of an assignment operator by accident.
    M2MInterfaceFactory& operator=( const M2MInterfaceFactory& /*other*/ );

    // Prevents the use of a copy constructor by accident.
    M2MInterfaceFactory( const M2MInterfaceFactory& /*other*/ );


public:

    /**
     * \brief Creates an interface object for the mbed Client Inteface. With this, the
     * client can handle client operations like Bootstrapping, Client
     * Registration, Device Management and Information Reporting.
     * \param endpoint_name The endpoint name of mbed Client.
     * \param endpoint_type The endpoint type of mbed Client, default is empty.
     * \param life_time The lifetime of the endpoint in seconds,
     *        if -1 it is optional.
     * \param listen_port The listening port for the endpoint, default is 5683.
     * \param domain The domain of the endpoint, default is empty.
     * \param mode The binding mode of the endpoint, default is NOT_SET.
     * \param stack The underlying network stack to be used for the connection,
     * default is LwIP_IPv4.
     * \param context_address The context address for M2M-HTTP, not used currently.
     * \return M2MInterfaceImpl An object for managing other client operations.
     */
    static M2MInterface *create_interface(M2MInterfaceObserver &observer,
                                              const String &endpoint_name,
                                              const String &endpoint_type = "",
                                              const int32_t life_time = -1,
                                              const uint16_t listen_port = 5683,
                                              const String &domain = "",
                                              M2MInterface::BindingMode mode = M2MInterface::NOT_SET,
                                              M2MInterface::NetworkStack stack = M2MInterface::LwIP_IPv4,
                                              const String &context_address = "");

    /**
     * \brief Creates a security object for the mbed Client Inteface. With this, the
     * client can manage Bootstrapping and Client Registration.
     * \param ServerType The type of the Security Object, bootstrap or LWM2M server.
     * \return M2MSecurity An object for managing other client operations.
     */
    static M2MSecurity *create_security(M2MSecurity::ServerType server_type);

    /**
     * \brief Creates a server object for the mbed Client Inteface. With this, the
     * client can manage the server resources used for client operations
     * such as Client Registration, server lifetime.
     * \return M2MServer An object for managing server client operations.
     */
    static M2MServer *create_server();

    /**
     * \brief Creates a device object for the mbed Client Inteface. With this, the
     * client can manage the device resources used for client operations
     * such as Client Registration, Device Management and Information Reporting.
     * \param name The name of the device object.
     * \return M2MDevice An object for managing other client operations.
     */
    static M2MDevice *create_device();

    /**
     * \brief Creates a firmware object for the mbed Client Inteface. With this, the
     * client can manage the firmware resources used for the client operations
     * such as Client Registration, Device Management and Information Reporting.
     * \return M2MFirmware An object for managing other client operations.
     */
    static M2MFirmware *create_firmware() m2m_deprecated;

    /**
     * \brief Creates a generic object for the mbed Client Inteface. With this, the
     * client can manage its own customized resources used for registering
     * Device Management and Information Reporting for those resources.
     * \param name The name of the object.
     * \return M2MObject An object for managing other mbed Client operations.
     */
    static M2MObject *create_object(const String &name);

    /**
     * \brief Creates a M2M resource and places it to the given object list.
     * \param m2m_obj_list Object list where the newly created resource is added.
     * \param object_id The OMALwM2M object identifier.
     * \param object_instance_id The OMALwM2M object instance identifier.
     * \param resource_id The OMALwM2M resource identifier.
     * \param resource_type The OMALwM2M resource type.
     * \param allowed Defines possible REST operations to the requested resource.
     * \param multiple_instance The resource can have
     *        multiple instances, default is false.
     * \param external_blockwise_store If true CoAP blocks are passed to application through callbacks
     *        otherwise handled in mbed-client-c.
     * \return Returns pointer to the created M2MResource, or a NULL on failure.
     */
    static M2MResource *create_resource(M2MObjectList &m2m_obj_list,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id,
                                        const M2MResourceInstance::ResourceType resource_type,
                                        const M2MBase::Operation allowed,
                                        bool multiple_instance = false,
                                        bool external_blockwise_store = false);

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    /**
     * \brief Creates a endpoint object for the mbed Client Inteface. With this, the
     * client can manage multiple endpoints and their resources. Common directory path "d/"
     * will be prepended to the endpoint path, resulting in the endpoint having final path of
     * "d/name".
     * \param name The name of the object.
     * \return M2MObject An object for managing other mbed Client operations.
     */
    static M2MEndpoint* create_endpoint(const String &name);
#endif

private:
    /**
     * \brief Checks given m2m_object_list for requested M2MObject and creates it if necessary.
     * \param object_list The object list.
     * \param object_id The OMALwM2M object identifier.
     * \param object_created This boolean flag is set to true if an object was
     * created and false if existing object was found.
     * \return Returns pointer to the requested M2MObject, or a NULL on failure.
     */
    static M2MObject* find_or_create_object(M2MObjectList &object_list,
                                            const uint16_t object_id,
                                            bool &object_created);

    /**
     * \brief Checks the given M2MObject for requested M2MObjectInstance and creates it if necessary.
     * \param object The M2MObject.
     * \param object_instance_id The OMALwM2M object instance identifier.
     * \param object_instance_created This boolean flag is set to true if an object
     * instance was created and false if existing object instance was found.
     * \return Returns pointer to the requested M2MObjectInstance, or a NULL on failure.
     */
    static M2MObjectInstance* find_or_create_object_instance(M2MObject &object,
                                                             const uint16_t object_instance_id,
                                                             bool &object_instance_created);

    /**
     * \brief Checks the given M2MObjectInstance for requested M2MResource and creates it if necessary.
     * \param object_instance The M2MObjectInstance.
     * \param resource_id The OMAL2M2M resource identifier.
     * \param resource_type The OMALwM2M resource type.
     * \param observable Flag describing if the created resource should be observable.
     * \return Returns pointer to the M2MResource, or a NULL on failure.
     */
    static M2MResource* find_or_create_resource(M2MObjectInstance &object_instance,
                                                const uint16_t resource_id,
                                                const M2MResourceInstance::ResourceType resource_type,
                                                bool multiple_instance,
                                                bool external_blockwise_store);

    friend class Test_M2MInterfaceFactory;
};

#endif // M2M_INTERFACE_FACTORY_H
