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
#ifndef M2M_SECURITY_H
#define M2M_SECURITY_H

#include "mbed-client/m2mobject.h"

// FORWARD DECLARATION
class M2MResource;

/*! \file m2msecurity.h
 *  \brief M2MSecurity.
 *  This class represents an interface for the Security Object model of the LWM2M framework.
 *  It handles the security object instances and all corresponding
 *  resources.
 */

class  M2MSecurity : public M2MObject {

friend class M2MInterfaceFactory;
friend class M2MNsdlInterface;

public:

    /**
     * \brief An enum defining all resources associated with a
     * Security Object in the LWM2M framework.
     */
    typedef enum {
        M2MServerUri,
        BootstrapServer,
        SecurityMode,
        PublicKey,
        ServerPublicKey,
        Secretkey,
        SMSSecurityMode,
        SMSBindingKey,
        SMSBindingSecretKey,
        M2MServerSMSNumber,
        ShortServerID,
        ClientHoldOffTime,
        OpenCertificateChain,
        CloseCertificateChain,
        ReadDeviceCertificateChain
    } SecurityResource;

    /**
     * \brief An enum defining the type of the security attribute
     * used by the Security Object.
     */
    typedef enum {
        SecurityNotSet = -1,
        Psk = 0,
        Certificate = 2,
        NoSecurity = 3,
        EST = 4
    } SecurityModeType;

    /**
     * \brief An enum defining an interface operation that can be
     * handled by the Security Object.
     */
    typedef enum {
        M2MServer = 0x0,
        Bootstrap = 0x1
    } ServerType;

private:

    /**
     * \brief Constructor
     * \param server_type The type of the security object created. Either bootstrap or LWM2M server.
     */
    M2MSecurity(ServerType server_type);


    /**
     * \brief Destructor
     */
    virtual ~M2MSecurity();

    // Prevents the use of default constructor.
    M2MSecurity();

    // Prevents the use of assignment operator.
    M2MSecurity& operator=( const M2MSecurity& /*other*/ );

    // Prevents the use of copy constructor
    M2MSecurity( const M2MSecurity& /*other*/ );

public:

    /**
     * \brief Get the singleton instance of M2MSecurity
     */
    static M2MSecurity* get_instance();

    /**
     * \brief Delete the singleton instance of M2MSecurity
     */
    static void delete_instance();

    /**
     * \brief Creates a new object instance.
     * \param server_type Server type for new object instance.
     * \return M2MObjectInstance if created successfully, else NULL.
     */
    M2MObjectInstance* create_object_instance(ServerType server_type);

    /**
     * \brief Remove all security object instances.
     */
    void remove_security_instances();

    /**
     * \brief Creates a new resource for a given resource enum.
     * \param rescource With this function, the following resources can be created:
     * ' BootstrapServer', 'SecurityMode', 'SMSSecurityMode',
     * 'M2MServerSMSNumber', 'ShortServerID', 'ClientHoldOffTime'.
     * \param value The value to be set on the resource, in integer format.
     * \param instance_id Instance id of the security instance where resource should be created.
     * \return M2MResource if created successfully, else NULL.
     */
    M2MResource* create_resource(SecurityResource rescource, uint32_t value, uint16_t instance_id);

    /**
     * \brief Deletes a resource with a given resource enum.
     * Mandatory resources cannot be deleted.
     * \param resource The resource to be deleted.
     * \param instance_id Instance id of the security instance where resource should be deleted.
     * \return True if deleted, else false.
     */
    bool delete_resource(SecurityResource rescource, uint16_t instance_id);

    /**
     * \brief Sets the value of a given resource enum.
     * \param resource With this function, a value can be set for the following resources:
     * 'M2MServerUri', 'SMSBindingKey', 'SMSBindingSecretKey'.
     * \param value The value to be set on the resource, in string format.
     * \param instance_id Instance id of the security instance where resource value should be set.
     * \return True if successfully set, else false.
     */
    bool set_resource_value(SecurityResource resource,
                            const m2m::String &value,
                            uint16_t instance_id);

    /**
     * \brief Sets the value of a given resource enum.
     * \param resource With this function, a value can be set for the following resourecs:
     * 'BootstrapServer', 'SecurityMode', 'SMSSecurityMode',
     * 'M2MServerSMSNumber', 'ShortServerID', 'ClientHoldOffTime'.
     * \param value The value to be set on the resource, in integer format.
     * \param instance_id Instance id of the security instance where resource value should be set.
     * \return True if successfully set, else false.
     */
    bool set_resource_value(SecurityResource resource,
                            uint32_t value,
                            uint16_t instance_id);

    /**
     * \brief Sets the value of a given resource enum.
     * \param resource With this function, a value can be set for the follwing resources:
     * 'PublicKey', 'ServerPublicKey', 'Secretkey'.
     * \param value The value to be set on the resource, in uint8_t format.
     * \param length The size of the buffer value to be set on the resource.
     * \param instance_id Instance id of the security instance where resource value should be set.
     * \return True if successfully set, else false.
     */
    bool set_resource_value(SecurityResource resource,
                            const uint8_t *value,
                            const uint16_t length,
                            uint16_t instance_id);

    /**
     * \brief Returns the value of a given resource enum, in string format.
     * \param resource With this function, the following resources can return a value:
     * 'M2MServerUri','SMSBindingKey', 'SMSBindingSecretKey'.
     * \param instance_id Instance id of the security instance where resource value should be retrieved.
     * \return The value associated with the resource. If the resource is not valid an empty string is returned.
     */
    m2m::String resource_value_string(SecurityResource resource, uint16_t instance_id) const;

    /**
     * \brief Populates the data buffer and returns the size of the buffer.
     * \param resource With this function, the following resources can return a value:
     * 'PublicKey', 'ServerPublicKey', 'Secretkey',
     * 'OpenCertificateChain', 'CloseCertificateChain' 'ReadDeviceCertificateChain'.
     * \param [OUT]data A copy of the data buffer that contains the value. The caller
     * is responsible for freeing this buffer.
     * \param instance_id Instance id of the security instance where resource value should be retrieve.
     * \param buffer_len[IN/OUT] Length of the buffer.
     * \return Error code, 0 on success otherwise < 0
     */
    int resource_value_buffer(SecurityResource resource,
                              uint8_t *&data,
                              uint16_t instance_id,
                              size_t *buffer_len) const;

    /**
     * \brief Returns a pointer to the value and size of the buffer.
     * \param resource With this function, the following resources can return a value:
     * 'PublicKey', 'ServerPublicKey', 'Secretkey'.
     * \param [OUT]data A pointer to the data buffer that contains the value.
     * \param instance_id Instance id of the security instance where resource value should be retrieved.
     * \return The size of the populated buffer.
     */
    uint32_t resource_value_buffer(SecurityResource resource,
                                   const uint8_t *&data,
                                   uint16_t instance_id) const;

    /**
     * \brief Get a size of the buffer.
     * \param resource With this function, the following resources can return the size:
     * 'PublicKey', 'ServerPublicKey', 'Secretkey'.
     * \param instance_id Instance id of the security instance where resource value should be retrieved.
     * \param [OUT]buffer_len The size of the buffer.
     * \return Error code, 0 on success otherwise < 0
     */
    int resource_value_buffer_size(SecurityResource resource,
                                   uint16_t instance_id,
                                   size_t *buffer_len) const;

    /**
     * \brief Returns the value of a given resource name, in integer format.
     * \param resource With this function, the following resources can return a value:
     * 'BootstrapServer', 'SecurityMode', 'SMSSecurityMode',
     * 'M2MServerSMSNumber', 'ShortServerID', 'ClientHoldOffTime'.
     * \param instance_id Instance id of the security instance where resource should be created.
     * \return The value associated with the resource. If the resource is not valid 0 is returned.
     */
    uint32_t resource_value_int(SecurityResource resource,
                                uint16_t instance_id) const;

    /**
     * \brief Returns whether a resource instance with a given resource enum exists or not
     * \param resource Resource enum.
     * \param instance_id Instance id of the security instance where resource should be checked.
     * \return True if at least one instance exists, else false.
     */
    bool is_resource_present(SecurityResource resource,
                             uint16_t instance_id) const;

    /**
     * \brief Returns the total number of resources for a security object.
     * \param instance_id Instance id of the security instance where resources should be counted.
     * \return The total number of resources.
     */
    uint16_t total_resource_count(uint16_t instance_id) const;

    /**
     * \brief Returns the type of the Security Object. It can be either
     * Bootstrap or M2MServer.
     * \param instance_id Instance id of the security instance where resource should be created.
     * \return ServerType The type of the Security Object.
     */
    ServerType server_type(uint16_t instance_id) const;

    /**
     * \brief Returns first bootstrap or lwm2m server security object instance id.
     * \param server_type Which server type security instance to return.
     * \return Object instance id, or -1 if no such instance exists.
     */
    int32_t get_security_instance_id(ServerType server_type) const;

    M2MResource* get_resource(SecurityResource resource, uint16_t instance_id = 0) const;
private:


    void clear_resources(uint16_t instance_id = 0);

protected:
    static M2MSecurity*          _instance;

    friend class Test_M2MSecurity;
    friend class Test_M2MInterfaceImpl;
    friend class Test_M2MConnectionSecurityImpl;
    friend class Test_M2MConnectionHandlerPimpl_linux;
    friend class Test_M2MConnectionHandlerPimpl_mbed;
    friend class Test_M2MConnectionSecurityPimpl;
    friend class Test_M2MNsdlInterface;
    friend class Test_M2MConnectionHandlerPimpl_classic;
};

#endif // M2M_SECURITY_H


