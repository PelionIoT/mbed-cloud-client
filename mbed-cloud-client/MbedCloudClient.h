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


#ifndef __MBED_CLOUD_CLIENT_H__
#define __MBED_CLOUD_CLIENT_H__

#include <map>
#include <string>
#include <vector>
#include "include/ServiceClient.h"
#include "mbed-cloud-client/MbedCloudClientConfig.h"

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
// This overly long path is needed to have build compatibility with previous
// version. A #include can't just point to a file which is not in application's
// include path and we should not force application to add every internal directory
// of MCC to their paths.
// On next phase, the cmake is used to publish the API paths via
// target_include_directories(), but that requires a bit more cleanups.
#include "certificate-enrollment-client/certificate-enrollment-client/ce_defs.h"
#endif // MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT

using namespace std;
class SimpleM2MResourceBase;

/**
 * \brief MbedCloudClientCallback
 * A callback class for informing updated object and resource value from the
 * LWM2M server to the user of the MbedCloudClient class. The user MUST instantiate the
 * class derived out of this and pass the object to MbedCloudClient::set_update_callback().
 */
class MbedCloudClientCallback {

public:

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LWM2M Cloud server.
    * \param base The object whose value is updated.
    * \param type The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type) = 0;
};



/*! \file MbedCloudClient.h
 *  \brief MbedCloudClient.
 *  This class provides an interface for handling all the mbed Cloud Client Interface operations
 *  including device provisioning, identity setup, device resource management defined in the OMA
 *  LWM2M specifications, and update firmware.
 *  Device resource management includes Bootstrapping, Client Registration, Device Management &
 *  Service Enablement and Information Reporting.
 */

class MbedCloudClient : public ServiceClientCallback {

public:

    /**
     * \brief An enum defining different kinds of errors
     * that can occur during various client operations.
     */
    typedef enum {
        ConnectErrorNone                        = 0x0, // Range reserved for Connector Error from 0x30 - 0x3FF
        ConnectAlreadyExists,
        ConnectBootstrapFailed,
        ConnectInvalidParameters,
        ConnectNotRegistered,
        ConnectTimeout,
        ConnectNetworkError,
        ConnectResponseParseFailed,
        ConnectUnknownError,
        ConnectMemoryConnectFail,
        ConnectNotAllowed,
        ConnectSecureConnectionFailed,
        ConnectDnsResolvingFailed,
        ConnectorFailedToStoreCredentials,
        ConnectorFailedToReadCredentials,
        ConnectorInvalidCredentials,
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
        UpdateWarningNoActionRequired           = UpdateClient::WarningBase, // Range reserved for Update Error from 0x0400 - 0x04FF
        UpdateWarningCertificateNotFound        = UpdateClient::WarningCertificateNotFound,
        UpdateWarningIdentityNotFound           = UpdateClient::WarningIdentityNotFound,
        UpdateWarningCertificateInvalid         = UpdateClient::WarningCertificateInvalid,
        UpdateWarningSignatureInvalid           = UpdateClient::WarningSignatureInvalid,
        UpdateWarningVendorMismatch             = UpdateClient::WarningVendorMismatch,
        UpdateWarningClassMismatch              = UpdateClient::WarningClassMismatch,
        UpdateWarningDeviceMismatch             = UpdateClient::WarningDeviceMismatch,
        UpdateWarningURINotFound                = UpdateClient::WarningURINotFound,
        UpdateWarningRollbackProtection         = UpdateClient::WarningRollbackProtection,
        UpdateWarningUnknown                    = UpdateClient::WarningUnknown,
        UpdateErrorUserActionRequired           = UpdateClient::ErrorBase,
        UpdateErrorWriteToStorage               = UpdateClient::ErrorWriteToStorage,
        UpdateErrorInvalidHash                  = UpdateClient::ErrorInvalidHash,
        UpdateFatalRebootRequired,
#endif
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
        // Certificate Enrollment error 0x0500 - 0x05ff. Defined in ce_status.h 
        EnrollmentErrorBase = CE_STATUS_RANGE_BASE,
        EnrollmentErrorEnd = CE_STATUS_RANGE_END
#endif // MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
    }Error;

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    /**
     * \brief Enum defining authorization requests from the Update client.
     */
    enum {
        UpdateRequestInvalid                    = UpdateClient::RequestInvalid,
        UpdateRequestDownload                   = UpdateClient::RequestDownload,
        UpdateRequestInstall                    = UpdateClient::RequestInstall
    };
#endif

    /**
     * \brief Constructor
     */
    MbedCloudClient();

    /**
     * \brief Destructor
     */
    virtual ~MbedCloudClient();

    /**
     * \brief Adds a list of objects that the application wants to register to the
     * LWM2M server. This function MUST be called before calling the setup()
     * API. Otherwise, the application gets the error ConnectInvalidParameters, when
     * calling setup().
     * \param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     */
    void add_objects(const M2MObjectList& object_list);

    /**
     * \brief Adds a list of M2MBase interface implementing objects that the application wants
     * to register to the LWM2M server. This function MUST be called before calling the setup()
     * API. Otherwise, the application gets the error ConnectInvalidParameters, when
     * calling setup().
     * \param base_list Object implementing the M2MBase interface that contain information about the
     * client attempting to register to the LWM2M server.
     */
    void add_objects(const M2MBaseList& base_list);

    void remove_object(M2MBase *object);
    /**
     * \brief Sets the callback function that is called when there is
     * any new update on any Object/ObjectInstance/Resource from the LWM2M server,
     * typically on receiving PUT commands on the registered objects.
     * \param callback Passes the class object that implements the callback
     * function to handle the incoming PUT request on a given object.
     */
    void set_update_callback(MbedCloudClientCallback *callback);

    /**
     * \brief Initiates the Cloud Client set up on the Cloud service. This
     * function manages device provisioning (first time usage), bootstrapping
     * (first time usage) and registering the client application to the Cloud
     * service.
     * \param iface A handler to the network interface on mbedOS, can be NULL on
     * other platforms.
     */
    bool setup(void* iface);

    /**
     * \brief Sets the callback function that is called when the client is registered
     * successfully to the Cloud. This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when the client
     * is registered.
     */
    void on_registered(void(*fn)(void));

    /**
    * \brief Sets the callback function that is called when the client is registered
    * successfully to the Cloud. This is an overloaded function for a class function.
    * \param object A function pointer to the function that is called when the client
    * is registered.
    */
    template<typename T>
    void on_registered(T *object, void (T::*member)(void));

    /**
     * \brief Sets the callback function that is called when there is any error
     * occuring in the client functionality. The error code can be mapped from the
     * MbedCloudClient::Error enum. This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when there
     * is any error in the client.
     */
    void on_error(void(*fn)(int));

    /**
     * \brief Sets the callback function that is called when there is an error
     * occuring in the client functionality. The error code can be mapped from
     * MbedCloudClient::Error enum. This is an overloaded function for a class function.
     * \param object A function pointer to the function that is called when there
     * is an error in the client.
     */
    template<typename T>
    void on_error(T *object, void (T::*member)(int));

    /**
     * \brief Sets the callback function that is called when the client is unregistered
     * successfully from the Cloud. This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when the client
     * is unregistered.
     */
    void on_unregistered(void(*fn)(void));

    /**
    * \brief Sets the callback function that is called when the client is unregistered
    * successfully from the Cloud. This is an overloaded function for a class function.
    * \param object A function pointer to the function that is called when the client
    * is unregistered.
    */
    template<typename T>
    void on_unregistered(T *object, void (T::*member)(void));

    /**
     * \brief Sets the callback function that is called when the client registration
     * is updated successfully to the Cloud. This is used for a statically defined function.
     * \param fn A function pointer to the function that is called when the client
     * registration is updated.
     */
    void on_registration_updated(void(*fn)(void));

    /**
     * \brief Sets the callback function that is called when the client registration
     * is updated successfully to the Cloud. This is an overloaded function for a class
     * function.
     * \param object A function pointer to the function that is called when the client
     * registration is updated.
     */
    template<typename T>
        void on_registration_updated(T *object, void (T::*member)(void));

    /**
    * \brief Sends a registration update message to the Cloud when the client is registered
    * successfully to the Cloud and there is no internal connection error.
    * If the client is not connected and there is some other internal network
    * transaction ongoing, this function triggers an error MbedCloudClient::ConnectNotAllowed.
    * \deprecated
    */
    void keep_alive() m2m_deprecated;

    /**
    * \brief Sends a registration update message to the Cloud when the client is registered
    * successfully to the Cloud and there is no internal connection error.
    * If the client is not connected and there is some other internal network
    * transaction ongoing, this function triggers an error MbedCloudClient::ConnectNotAllowed.
    */
    void register_update();

    /**
    * \brief Closes the connection towards Cloud and unregisters the client.
    * This function triggers the on_unregistered() callback if set by the application.
    */
    void close();

    /**
     * \brief Returns pointer to the ConnectorClientEndpointInfo object.
     * \return ConnectorClientEndpointInfo pointer.
     */
    const ConnectorClientEndpointInfo *endpoint_info() const;

    /**
     * \brief Sets the function that is called for indicating that the client
     * is going to sleep when the binding mode is selected with queue mode.
     * \param callback A function pointer that is called when the client
     * goes to sleep.
     */
    void set_queue_sleep_handler(callback_handler handler);

    /**
     * \brief Sets the function callback that is called by client to
     * fetch a random number from an application to ensure strong entropy.
     * \param random_callback A function pointer that is called by client
     * while performing a secure handshake.
     * The function signature should be uint32_t (*random_number_callback)(void);
     */
    void set_random_number_callback(random_number_cb callback);

    /**
     * \brief Sets the function callback that is called by client to
     * provide an entropy source from an application to ensure strong entropy.
     * \param entropy_callback A function pointer that is called by mbed Client
     * while performing a secure handshake.
     * Function signature, if using mbed-client-mbedtls, should be
     * int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output,
     *                                     size_t len, size_t *olen);
     */
    void set_entropy_callback(entropy_cb callback);

    /**
     * \brief Set resource value in the Device Object
     *
     * \param resource Device enum to have value set.
     * \param value String object.
     * \return True if successful, false otherwise.
     */
    bool set_device_resource_value(M2MDevice::DeviceResource resource,
                                   const std::string &value);

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
    /**
     * \brief Registers a callback function for authorizing firmware downloads and reboots.
     * \param handler Callback function.
     */
    void set_update_authorize_handler(void (*handler)(int32_t request));

    /**
     * \brief Authorize request passed to authorization handler.
     * \param request Request being authorized.
     */
    void update_authorize(int32_t request);

    /**
     * \brief Registers a callback function for monitoring download progress.
     * \param handler Callback function.
     */
    void set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total));
#endif

    /**
     * @brief Return error description for the latest error code
     * @return Error description string
     */
    const char *error_description() const;

    /**
     * @brief Sends the CoAP GET request to the server.
     * API must be called again with the updated offset to complete the whole transfer.
     * @type Download type.
     * @uri Uri path to the data.
     * @offset Data offset.
     * @get_data_cb Callback which is triggered once there is data available.
     * @get_data_error_cb Callback which is trigged in case of any error.
    */
    void send_get_request(DownloadType type,
                          const char *uri,
                          const size_t offset,
                          get_data_cb data_cb,
                          get_data_error_cb error_cb,
                          void *context);

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
    /**
    * \brief Initiate a renewal for a specific certificate.
    * The process will generate new keys in order to create a CSR. The CSR is then sent to the EST service to retrieve the renewed certificate.
    * The new certificate is then safely stored in the device, along with its corresponding private key.
    * Note: The certificate to be removed *must* already exist in the device.
    * \param cert_name A null terminated C string indicating the name of the certificate to be renewed.
    * \return CE_STATUS_SUCCESS if the asynchronous operation has started successfully. In this case, user callback will be executed at the end of the operation, indicating completion status.
    *         If any other ce_status_e:: status is returned - operation encountered some error prior to the start of the asynchronous stage and user callback will NOT be executed.
    */
    ce_status_e certificate_renew(const char *cert_name);

    /**
    * \brief Sets the callback function that is called when the certificate renewal process has completed.
    * Must be called before any certificate renewal operation.
    * \param user_cb A function pointer to the user callback. If `user_cb` is NULL - no callback is called when the process has completed.
    */
    void on_certificate_renewal(cert_renewal_cb_f user_cb);
#endif // MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
    /**
     * @brief Returns the pointer to the inner object list.
     * The list is not allowed to be modified and is owned by the Mbed Cloud Client instance.
     * @return The inner object list pointer.
     */
    const M2MBaseList *get_object_list() const;
#endif // MBED_CLOUD_CLIENT_EDGE_EXTENSION

protected: // from ServiceClientCallback

    /**
    * \brief Indicates that the setup or close operation is complete
    * with success or failure.
    * \param status Indicates success or failure in terms of status code.
    */
    virtual void complete(ServiceClientCallbackStatus status);

    /**
    * \brief Indicates an error condition from the underlying clients like
    * identity, connector or update client.
    * \param error Indicates an error code translated to MbedCloudClient::Error.
    * \param reason, Indicates human readable text for error description.
    */
    virtual void error(int error, const char *reason);

    /**
    * \brief A callback indicating that the value of the resource object is updated
    *  by the LWM2M Cloud server.
    * \param base The object whose value is updated.
    * \param type The type of the object.
    */
    virtual void value_updated(M2MBase *base, M2MBase::BaseType type);

private:

    /**
    * \brief Registers the update callback functions for SimpleM2MResourceBase
    * objects.
    * \param route The URI path of the registered resource such as "/Test/0/res/".
    * \param resource Object of the SimpleM2MResourceBase.
    */
    void register_update_callback(string route, SimpleM2MResourceBase* resource);

private:

    ServiceClient                                   _client;
    MbedCloudClientCallback                         *_value_callback;
    map<string, M2MObject*>                         _objects;
    map<string, M2MResource*>                       _resources;
    M2MBaseList                                     _object_list;
    map<string, SimpleM2MResourceBase*>             _update_values;
    FP0<void>                                       _on_registered;
    FP0<void>                                       _on_unregistered;
    FP0<void>                                       _on_registration_updated;
    FP1<void,int>                                   _on_error;
    const char                                      *_error_description;


friend class SimpleM2MResourceBase;
};

template<typename T>
void MbedCloudClient::on_registered(T *object, void (T::*member)(void))
{
    FP0<void> fp(object, member);
    _on_registered = fp;
}

template<typename T>
void MbedCloudClient::on_error(T *object, void (T::*member)(int))
{
    FP1<void, int> fp(object, member);
    _on_error = fp;
}

template<typename T>
void MbedCloudClient::on_unregistered(T *object, void (T::*member)(void))
{
    FP0<void> fp(object, member);
    _on_unregistered = fp;
}

template<typename T>
void MbedCloudClient::on_registration_updated(T *object, void (T::*member)(void))
{
    FP0<void> fp(object, member);
    _on_registration_updated = fp;
}
#endif // __MBED_CLOUD_CLIENT_H__
