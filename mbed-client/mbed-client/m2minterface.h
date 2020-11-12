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
#ifndef M2M_INTERFACE_H
#define M2M_INTERFACE_H

#include <stdint.h>
#include "mbed-client/m2mvector.h"
#include "mbed-client/m2mconfig.h"
#include "mbed-client/functionpointer.h"

#include "sn_coap_protocol.h"
#include "nsdl-c/sn_nsdl_lib.h"

/** \file m2minterface.h \brief header for M2MInterface */

//FORWARD DECLARATION
class M2MSecurity;
class M2MObject;
class M2MBase;
class M2MInterfaceObserver;

typedef Vector<M2MObject*> M2MObjectList;
typedef Vector<M2MBase*> M2MBaseList;
typedef FP callback_handler;

typedef enum request_error_e {
    FAILED_TO_SEND_MSG = 0, // Message sending has failed
    FAILED_TO_ALLOCATE_MEMORY = 1, // Can't allocate memory for the request
    ERROR_NOT_REGISTERED = 2 // Not registered, request will NOT to be stored for resending purposes
} request_error_t;

typedef request_error_e get_data_req_error_e;
typedef request_error_t get_data_req_error_t;

/*!
 * @brief A callback function to receive data from GET request.
 *        Transfer is completed once total size equals to received size.
 *        Caller needs to take care of counting how many bytes it has received.
 * @param buffer Buffer containing the payload.
 * @param buffer_size Size of the payload.
 * @param total_size Total size of the package. This information is available only in first package.
 *                   Caller must store this information to detect when the download has completed.
 * @param last_block True when this is the last block received, false if more blocks will come.
 * @param context Application context
*/
typedef void (*request_data_cb)(const uint8_t *buffer,
                                size_t buffer_size,
                                size_t total_size,
                                bool last_block,
                                void *context);
typedef request_data_cb get_data_cb; // For backward compatibility

/*!
 * @brief A callback function to receive errors from GET transfer.
 * @param error_code
 * @param context Application context
*/
typedef void (*request_error_cb)(request_error_t error_code, void *context);
typedef request_error_cb get_data_error_cb; // For backward compatibility


/** This class handles LwM2M Client logic related to communicating with
 * all four interfaces defined in LwM2M.
 *
 * LwM2M defines four interfaces:
 * * Bootstrap
 * * Client Registration
 * * Device management and service enablement
 * * Information Reporting
 *
 */

class M2MInterface {

public:

    /**
     * \brief An enum defining different kinds of errors
     * that can occur during various client operations.
     */
    typedef enum {
        ErrorNone = 0,
        AlreadyExists,
        BootstrapFailed,
        InvalidParameters,
        NotRegistered,
        Timeout,
        NetworkError,
        ResponseParseFailed,
        UnknownError,
        MemoryFail,
        NotAllowed,
        SecureConnectionFailed,
        DnsResolvingFailed,
        UnregistrationFailed,
        ESTEnrollmentFailed,
        FailedToStoreCredentials,
        FailedToReadCredentials
    }Error;

    /**
     * \brief An enum defining different kinds of binding
     * modes handled for client operations.
     */
    typedef enum {
        NOT_SET = 0,
        UDP = 0x01,
        UDP_QUEUE = 0x03,
        SMS = 0x04,
        SMS_QUEUE =0x06,
        UDP_SMS_QUEUE = 0x07,
        TCP = 0x09, //not real value, spec does not have one!
                    //this has nsdl binding mode bit UDP set
        TCP_QUEUE = 0x0b //not real value, spec does not have one!
                         //this has nsdl binding mode bits, UDP and UDP_QUEUE set
    }BindingMode;

    /**
     * \brief An enum defining different kinds of network
     * stacks that can be used by mbed Client.
     */
    typedef enum {
        Uninitialized = 0,
        LwIP_IPv4,
        LwIP_IPv6,
        Reserved,
        Nanostack_IPv6,
        ATWINC_IPv4,
        Unknown
    }NetworkStack;

public:

    virtual ~M2MInterface(){}

#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    /**
     * \brief Initiates bootstrapping of the client with the provided Bootstrap
     * Server information.
     * NOTE: This API is not supported for developers!!
     * \param security_object A security object that contains information
     * required for successful bootstrapping of the client.
     */
    virtual void bootstrap(M2MSecurity *security_object) = 0;

    /**
     * \brief Cancels an ongoing bootstrapping operation of the client. If the client has
     * already successfully bootstrapped, this function deletes the existing
     * bootstrap information from the client.
     * NOTE: This API is not supported for developers!!
     */
    virtual void cancel_bootstrap() = 0;

    /**
     * \brief Finishes bootstrap in cases where client will be the one to finish it.
     */
    virtual void finish_bootstrap() = 0;
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
    virtual void register_object(M2MSecurity *security_object, const M2MBaseList &list, bool full_registration = false) = 0;

    /**
     * \brief Initiates the registration of a provided security object to the
     * corresponding LWM2M server.
     * \param security_object The security object that contains information
     * required for registering to the LWM2M server.
     * If the client wants to register to multiple LWM2M servers, it must call
     * this function once for each of the LWM2M server objects separately.
     * \param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     */
    virtual void register_object(M2MSecurity *security_object, const M2MObjectList &object_list) = 0;

    /**
      * \brief Removes an object from M2MInterface.
      * Does not call delete on the object though.
      * \return true if the object was found and false if the object was not found.
      */
    virtual bool remove_object(M2MBase *base) = 0;

    /**
     * \brief Updates or refreshes the client's registration on the LWM2M
     * server.
     * \param security_object A security object from which the device object
     * needs to update the registration. If there is only one LWM2M server registered,
     * this parameter can be NULL.
     * \param lifetime The lifetime of the endpoint client in seconds. If the same value
     * has to be passed, set the default value to 0.
     */
    virtual void update_registration(M2MSecurity *security_object, const uint32_t lifetime = 0) = 0;

    /**
     * \brief Updates or refreshes the client's registration on the LWM2M
     * server. Use this function to publish new objects to LWM2M server.
     * \param security_object The security object from which the device object
     * needs to update the registration. If there is only one LWM2M server registered,
     * this parameter can be NULL.
     * \param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     * \param lifetime The lifetime of the endpoint client in seconds. If the same value
     * has to be passed, set the default value to 0.
     */
    virtual void update_registration(M2MSecurity *security_object, const M2MBaseList &list,
                                     const uint32_t lifetime = 0) = 0;

    /**
     * \brief Updates or refreshes the client's registration on the LWM2M
     * server. Use this function to publish new objects to LWM2M server.
     * \param security_object The security object from which the device object
     * needs to update the registration. If there is only one LWM2M server registered,
     * this parameter can be NULL.
     * \param object_list Objects that contain information about the
     * client attempting to register to the LWM2M server.
     * \param lifetime The lifetime of the endpoint client in seconds. If the same value
     * has to be passed, set the default value to 0.
     */
    virtual void update_registration(M2MSecurity *security_object, const M2MObjectList &object_list,
                                     const uint32_t lifetime = 0) = 0;

    /**
     * \brief Unregisters the registered object from the LWM2M server.
     * \param security_object The security object from which the device object
     * needs to be unregistered. If there is only one LWM2M server registered,
     * this parameter can be NULL.
     */
    virtual void unregister_object(M2MSecurity* security_object = NULL) = 0;

    /**
     * \brief Sets the function that is called for indicating that the client
     * is going to sleep when the binding mode is selected with queue mode.
     * \param callback A function pointer that is called when the client
     * goes to sleep.
     */
    virtual void set_queue_sleep_handler(callback_handler handler) = 0;

    /**
     * \brief Sets the function callback that is called by mbed Client to
     * fetch a random number from an application to ensure strong entropy.
     * \param random_callback A function pointer that is called by mbed Client
     * while performing a secure handshake.
     * The function signature should be uint32_t (*random_number_callback)(void);
     */
    virtual void set_random_number_callback(random_number_cb callback) = 0;

    /**
     * \brief Sets the function callback that is called by mbed Client to
     * provide an entropy source from an application to ensure strong entropy.
     * \param entropy_callback A function pointer that is called by mbed Client
     * while performing a secure handshake.
     * Function signature, if using mbed-client-mbedtls, should be
     * int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output,
     *                                     size_t len, size_t *olen);
     */
    virtual void set_entropy_callback(entropy_cb callback) = 0;

    /**
     * \brief Sets the network interface handler that is used by mbed Client to connect
     * to a network over IP.
     * \param handler A network interface handler that is used by mbed Client to connect.
     *  This API is optional but it provides a mechanism for different platforms to
     * manage the usage of underlying network interface by the client.
     */
    virtual void set_platform_network_handler(void *handler = NULL) = 0;

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
    virtual void set_platform_network_handler(void *handler = NULL, bool credentials_available = 0) = 0;

    /**
     * @brief Updates the endpoint name.
     * @param name New endpoint name
     */
    virtual void update_endpoint(const String &name) = 0;

    /**
     * @brief Updates the domain name.
     * @param domain New domain name
     */
    virtual void update_domain(const String &domain) = 0;


    /**
     * @brief Return internal endpoint name
     * @return internal endpoint name
     */
    virtual const String internal_endpoint_name() const = 0;

    /**
     * @brief Return error description for the latest error code
     * @return Error description string
     */
    virtual const char *error_description() const = 0;

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
                                  get_data_cb,
                                  get_data_error_cb,
                                  void *context) = 0;

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
                                   void *context) = 0;

    /**
     * @brief Set custom uri query paramaters used in LWM2M registration.
     * @uri_query_params Uri query params. Parameters must be in key-value format:
     * "a=100&b=200". Maximum length can be up to 64 bytes.
     * @return False if maximum length exceeded otherwise True.
    */
    virtual bool set_uri_query_parameters(const char *uri_query_params) = 0;

    /**
     * \brief Pauses client's timed functionality and closes network connection
     * to the Cloud. After successful call the operation is continued
     * by calling register_object().
     *
     * \note This operation does not unregister client from the Cloud.
     * Closes the socket and removes interface from the interface list.
     */
    virtual void pause() = 0;

    virtual nsdl_s* get_nsdl_handle() const = 0;

    virtual uint16_t stagger_wait_time(bool boostrap) const = 0;
};

#endif // M2M_INTERFACE_H
