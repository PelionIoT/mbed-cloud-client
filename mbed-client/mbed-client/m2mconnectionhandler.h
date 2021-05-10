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
#ifndef M2M_CONNECTION_HANDLER_H__
#define M2M_CONNECTION_HANDLER_H__

#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconfig.h"
#include "mbed-client/m2minterface.h"
#include "nsdl-c/sn_nsdl.h"

class M2MConnectionSecurity;
class M2MConnectionHandlerPimpl;

/** \file m2mconnectionhandler.h \brief header for M2MConnectionHandler */

/** This class handles the socket connection for the LWM2M Client. */
class M2MConnectionHandler {
public:

    /**
     * @enum ConnectionError
     * This enum defines an error that can come from the
     * socket read and write operation.
     */
    typedef enum {
        ERROR_NONE = 0,
        ERROR_GENERIC = -1,
        CONNECTION_ERROR_WANTS_READ = -2,
        CONNECTION_ERROR_WANTS_WRITE = -3,
        SSL_PEER_CLOSE_NOTIFY = -4,
        MEMORY_ALLOCATION_FAILED = -5,
        SSL_CONNECTION_ERROR = -6,
        SOCKET_READ_ERROR = -7,
        SOCKET_SEND_ERROR = -8,
        SOCKET_ABORT = -9,
        DNS_RESOLVING_ERROR = -10,
        SSL_HANDSHAKE_ERROR = -11,
        FAILED_TO_READ_CREDENTIALS = -12,
        SOCKET_TIMEOUT = -13,
    } ConnectionError;

    /**
     * @enum SocketPriority
     * This enum defines priority for the socket.
     * Used for setting traffic class socket option.
     */
    typedef enum {
        DEFAULT_PRIORITY = 0,
        HIGH_PRIORITY = 10,
        ALERT_PRIORITY = 46
    } SocketPriority;

public:

    /**
    * \brief Constructor
    */
    M2MConnectionHandler(M2MConnectionObserver &observer,
                         M2MConnectionSecurity *sec,
                         M2MInterface::BindingMode mode,
                         M2MInterface::NetworkStack stack);

    /**
    * \brief Destructor
    */
    ~M2MConnectionHandler();

    /**
    * \brief This binds the socket connection.
    * \param listen_port The port to be listened to for an incoming connection.
    * \return True if successful, else false.
    */
    bool bind_connection(const uint16_t listen_port);

    /**
    * \brief This resolves the server address. The output is
    * returned through a callback.
    * \param String The server address.
    * \param uint16_t The server port.
    * \param ServerType The server type to be resolved.
    * \param security The M2MSecurity object that determines which
    * type of secure connection is used by the socket.
    * \param is_server_ping Defines whether the call is for Server ping or not.
    * \return True if the address is valid, else false.
    */
    bool resolve_server_address(const String &server_address,
                                const uint16_t server_port,
                                M2MConnectionObserver::ServerType server_type,
                                const M2MSecurity *security,
                                bool is_server_ping = false);

    /**
    * \brief Sends data to the connected server.
    * \param data_ptr The data to be sent.
    * \param data_len The length of data to be sent.
    * \param address_ptr The address structure to which the data needs to be sent.
    * \return True if data is sent successfully, else false.
    */
    bool send_data(uint8_t *data_ptr,
                   uint16_t data_len,
                   sn_nsdl_addr_s *address_ptr);

    /**
    * \brief Listens to the incoming data from a remote server.
    * \return True if successful, else false.
    */
    bool start_listening_for_data();

    /**
    * \brief Stops listening to the incoming data.
    */
    void stop_listening();

    /**
    * \brief Closes the open connection.
    * \note This must be called from the same event loop context!
    */
    void force_close();

    /**
    * \brief Error handling for DTLS connectivity.
    * \param error An error code from the TLS library.
    */
    void handle_connection_error(int error);

    /**
     * \brief Sets the network interface handler that is used by the client to connect
     * to a network over IP.
     * \param handler A network interface handler that is used by the client to connect.
     *  This API is optional but it provides a mechanism for different platforms to
     * manage the usage of underlying network interface by client.
     */
    void set_platform_network_handler(void *handler = NULL);

    /**
    * \brief Claims mutex to prevent thread clashes
    * in multithreaded environment.
    */
    void claim_mutex();

    /**
    * \brief Releases mutex to prevent thread clashes
    * in multithreaded environment.
    */
    void release_mutex();

    /**
     * \brief Unregisters the network interface handler that is set in 'set_platform_network_handler'.
     */
    void unregister_network_handler();

    /**
     * \brief Set socket priority.
     * \return true if socket option was set correctly.
     */
    bool set_socket_priority(M2MConnectionHandler::SocketPriority priority);

    /**
     * \brief Stores CID persistently for DTLS connections.
     */
    void store_cid();

    /**
     * \brief Removes CID for DTLS connections.
     */
    void remove_cid();

    /**
     * \brief Status of CID availability in client.
     * \return true if CID is available else false.
     */
    bool is_cid_available();

    /**
     * \brief Internal test function. Set CID for current tls session.
     * \param data_ptr CID
     * \param data_len length of the CID
     */
    void set_cid_value(const uint8_t *data_ptr, const size_t data_len);

private:

    M2MConnectionObserver                       &_observer;
    M2MConnectionHandlerPimpl                   *_private_impl;

    friend class Test_M2MConnectionHandler;
    friend class Test_M2MConnectionHandler_mbed;
    friend class Test_M2MConnectionHandler_linux;
    friend class M2MConnection_TestObserver;
};

#endif //M2M_CONNECTION_HANDLER_H__

