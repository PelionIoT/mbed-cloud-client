/*
 * Copyright (c) 2015 - 2017 ARM Limited. All rights reserved.
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

#ifndef __M2M_CONNECTION_SECURITY_PIMPL_H__
#define __M2M_CONNECTION_SECURITY_PIMPL_H__

#include "mbed-client/m2mconnectionsecurity.h"
#include "mbed-client/m2mtimerobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconfig.h"

#include "pal.h"

#include <time.h>

/**
 * @brief The M2MConnectionSecurityPimpl class
 */
class M2MConnectionSecurityPimpl{

private:

    enum{
        INIT_NOT_STARTED = 0,
        INIT_CONFIGURING,
        INIT_DONE
    };

    // Prevents the use of assignment operator by accident.
    M2MConnectionSecurityPimpl& operator=( const M2MConnectionSecurityPimpl& /*other*/ );
    // Prevents the use of copy constructor by accident
    M2MConnectionSecurityPimpl( const M2MConnectionSecurityPimpl& /*other*/ );

public:

    /**
     * @brief Constructor
     */
    M2MConnectionSecurityPimpl(M2MConnectionSecurity::SecurityMode mode);

    /**
    * @brief Destructor
    */
    virtual ~M2MConnectionSecurityPimpl();

    /**
     * \brief Resets the socket connection states.
     */
    void reset();

    /**
     * \brief Initiatlizes the socket connection states.
     */
    int init(const M2MSecurity *security, uint16_t security_instance_id);

    /**
     * \brief Connects the client to the server.
     * \param connHandler The ConnectionHandler object that maintains the socket.
     * \return Returns the state of the connection. Successful or not.
     *         If 2MConnectionHandler::CONNECTION_ERROR_WANTS_READ is returned
     *         this function must be called again later to continue the handshake.
     */
    int connect(M2MConnectionHandler* connHandler);

    /**
     * \brief Sends data to the server.
     * \param message The data to be sent.
     * \param len The length of the data.
     * @return Indicates whether the data is sent successfully or not.
     */
    int send_message(unsigned char *message, int len);

    /**
     * \brief Reads the data received from the server.
     * \param message The data to be read.
     * \param len The length of the data.
     * \return Indicates whether the data is read successfully or not.
     */
    int read(unsigned char* buffer, uint16_t len);

    /**
     * This function is no longer used.
     */
    void set_random_number_callback(random_number_cb callback);

    /**
     * \brief Sets the function callback that will be called by mbed-client for
     * providing entropy source from application for ensuring strong entropy.
     * \param entropy_callback A function pointer that will be called by mbed-client
     * while performing secure handshake.
     * Function signature , if using mbed-client-mbedtls should be
     * int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output,
     *                                     size_t len, size_t *olen);
     *
     * NOTE: This function is only used if MBED_CLOUD_CLIENT_CUSTOM_MBEDTLS_ENTROPY is defined
     *       and mbed TLS is used.
     */
    void set_entropy_callback(entropy_cb callback);

    /**
     * \brief Set socket information for this secure connection.
     * \param socket Socket used with this TLS session.
     * \param address Pointer to the address of the server.
     * \return Indicates whether the data is read successfully or not.
     */
    void set_socket(palSocket_t socket, palSocketAddress_t *address);

    /**
     * \brief Set dtls socket callback function pointer.
     * \param socket Callback function pointer.
     * \param argument Argument to be passed back to function.
     * \return Indicates whether the call is successful or not.
     */
    int set_dtls_socket_callback(void(*foo)(void*), void *argument);

    void update_network_rtt_estimate(uint8_t rtt_estimate);

private:

    /**
    *  \brief Returns certificate expiration time in epoch format.
    *  \param certificate, The certificate to be extracted.
    *  \param cert_len, Length of the certificate.
    *  \return epoch time or 0 if failure.
    */
    uint32_t certificate_expiration_time(const unsigned char *certificate, const uint32_t cert_len);

    /**
    *  \brief Returns certificate validFrom time in epoch format.
    *  \param certificate, The certificate to be extracted.
    *  \param cert_len, Length of the certificate.
    *  \return epoch time or 0 if failure.
    */
    uint32_t certificate_validfrom_time(const unsigned char *certificate, const uint32_t cert_len);

private:

    uint8_t                             _init_done;
    palTLSConfHandle_t                  _conf;
    palTLSHandle_t                      _ssl;
    M2MConnectionSecurity::SecurityMode _sec_mode;
    palTLSSocket_t                      _tls_socket;
    entropy_cb                          _entropy;
    uint8_t                            _network_rtt_estimate;

    friend class Test_M2MConnectionSecurityPimpl;
};

#endif //__M2M_CONNECTION_SECURITY_PIMPL_H__
