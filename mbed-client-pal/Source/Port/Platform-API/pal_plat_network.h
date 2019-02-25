/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/


#ifndef _PAL_PLAT_SOCKET_H
#define _PAL_PLAT_SOCKET_H

#include "pal.h"
#include "pal_network.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_plat_network.h
 *  \brief PAL network - platform.
 *   This file contains the network APIs that need to be implemented in the platform layer.
 *
 * **PAL network socket API** /n
 * PAL network socket configuration options:
 * - define PAL_NET_TCP_AND_TLS_SUPPORT if TCP is supported by the platform and is required.
 * - define PAL_NET_ASYNCHRONOUS_SOCKET_API if asynchronous socket API is supported by the platform. Currently **mandatory**.
 * - define PAL_NET_DNS_SUPPORT if DNS name resolution is supported.
 */

/*! \brief Initialize sockets.
 *
 * Must be called before other socket functions. By default, is called from PAL init.
 * @param[in] context Optional context. If not available or applicable, use NULL.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_socketsInit(void* context);

/*! \brief Register a network interface for use with PAL sockets.
 *
 * Must be called before other socket functions. Most APIs will not work before an interface is added.
 * @param[in] networkInterfaceContext The context of the network interface to be added. This is OS-specific. \n
              In mbed OS, this is the NetworkInterface object pointer for the network adapter and assumes a connect has already been called on this. \n
              If not available, use NULL. This is not required on some OSs.
 * @param[out] interfaceIndex Contains the index assigned to the interface if it has been assigned successfully. This index can be used when creating a socket to bind the socket to the interface.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_registerNetworkInterface(void* networkInterfaceContext, uint32_t* interfaceIndex);

/*! Unregister a network interface.
* @param interfaceIndex Index of the network interface to be removed.
\return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
*/
palStatus_t pal_plat_unregisterNetworkInterface(uint32_t interfaceIndex);

/*! \brief Socket termination.
 *
 * This can be called when sockets are no longer needed, to free socket resources.
 * @param[in] context Optional context. If not available, use NULL.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
*/
palStatus_t pal_plat_socketsTerminate(void* context);

/*! \brief Get a network socket.
 * @param[in] domain The domain of the created socket. See `palSocketDomain_t` for supported types.
 * @param[in] type The type of the created socket. See `palSocketType_t` for supported types.
 * @param[in] nonBlockingSocket If true, the socket is non-blocking.
 * @param[in] interfaceNum The number of the network interface used for this socket. Select `PAL_NET_DEFAULT_INTERFACE` for the default interface.
 * @param[out] socket The socket is returned through this output parameter.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* socket);

/*! \brief Set options for a network socket.
 *
 * See `palSocketOptionName_t` for supported options.
 * @param[in] socket The socket to configure.
 * @param[in] optionName The name of the option to be set. See enum `palSocketOptionName_t` for supported types.
 * @param[in] optionValue The buffer holding the value to set for the given option.
 * @param[in] optionLength The size of the buffer provided for `optionValue` in bytes.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength);

/*! \brief Check if a socket is non-blocking.
 * @param[in] socket The socket for which to check non-blocking status.
 * @param[out] isNonBlocking The non-blocking status for the socket. Is `true` if non-blocking, otherwise `false`.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking);

/*! \brief Bind a socket to a local address.
 * @param[in] socket The socket to bind.
 * @param[in] myAddress The address to bind to.
 * @param[in] addressLength The length of the address passed in `myAddress`.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength);

/*! \brief Receive a payload from a socket.
 * @param[in] socket The socket to receive from. The socket passed to this function should be of type `PAL_SOCK_DGRAM`, unless your specific implementation supports other types as well.
 * @param[out] buffer The buffer for the payload data.
 * @param[in] length The length of the buffer for the payload data in bytes.
 * @param[out] from The address that sent the payload. This value is optional, pass NULL when not used.
 * @param[in, out] fromLength The length of the `from` address. When completed, this contains the amount of data actually written to the `from` address. This value is optional, pass NULL when not used.
 * @param[out] bytesReceived The actual amount of payload data received in the buffer.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived);

/*! \brief Send a payload to an address using a specific socket.
 * @param[in] socket The socket to use for sending the payload. The socket passed to this function should be of type `PAL_SOCK_DGRAM`, unless your specific implementation supports other types as well.
 * @param[in] buffer The buffer for the payload data.
 * @param[in] length The length of the buffer for the payload data.
 * @param[in] to The address to which the payload should be sent.
 * @param[in] toLength The length of the `to` address.
 * @param[out] bytesSent The actual amount of payload data sent.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent);

/*! \brief Close a network socket.
 * \note The function recieves `palSocket_t*` and not `palSocket_t` so that it can zero the socket to avoid re-use.
 * @param[in,out] socket Pointer to the socket to release and zero.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_close(palSocket_t* socket);

/*! \brief Get the number of current network interfaces.
 *
 * The function counts interfaces that have been successfully registered.
 * @param[out] numInterfaces The number of interfaces after a successful call.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_getNumberOfNetInterfaces(uint32_t* numInterfaces);

/*! \brief Get information regarding a socket at a specific interface number.
 * @param[in] interfaceNum The number of the interface to get information from.
 * @param[out] interfaceInfo The information for the given interface number.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t* interfaceInfo);

#if PAL_NET_TCP_AND_TLS_SUPPORT // The functionality below is supported only if TCP is supported.

/*! \brief Use a socket to listen to incoming connections.
 *
 * You may also limit the queue of incoming connections.
 * @param[in] socket The socket to listen to. The docket passed to this function should be of type `PAL_SOCK_STREAM_SERVER`, unless your specific implementation supports other types as well.
 * @param[in] backlog The number of pending connections that can be saved for the socket.
 * \return PAL_SUCCESS (0) in case of success. A specific negative error code in case of failure.
 */
palStatus_t pal_plat_listen(palSocket_t socket, int backlog);

/*! \brief Accept a connection on a socket.
 * @param[in] socket The socket on which to accept the connection. The socket needs to be created and bound, and `pal_plat_listen` must have been called on it. The socket passed to this function should be of type `PAL_SOCK_STREAM_SERVER`, unless your specific implementation supports other types as well.
 * @param[out] address The source address of the incoming connection.
 * @param[in, out] addressLen The length of the address field on input, the length of the data returned on output.
 * @param[out] acceptedSocket The socket of the accepted connection is returned if the connection is accepted successfully.
 * \return PAL_SUCCESS (0) in case of success, a specific negative error code in case of failure.
 */
palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket);

/*! \brief Open a connection from a socket to a specific address.
 * @param[in] socket The socket to use for the connection to the given address. The socket passed to this function should be of type `PAL_SOCK_STREAM`, unless your specific implementation supports other types as well.
 * @param[in] address The destination address of the connection.
 * @param[in] addressLen The length of the address field.
 * \return PAL_SUCCESS (0) in case of success, a specific negative error code in case of failure.
 */
palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen);

/*! \brief Receive data from a connected socket.
 * @param[in] socket The connected socket on which to receive data. Sockets passed to this function should be of type PAL_SOCK_STREAM, unless your specific implementation supports other types as well.
 * @param[out] buf The output buffer for the message data.
 * @param[in] len The length of the input data buffer in bytes.
 * @param[out] recievedDataSize The length of the data actually received in bytes.
 * \return PAL_SUCCESS (0) in case of success, a specific negative error code in case of failure.
 */
palStatus_t pal_plat_recv(palSocket_t socket, void* buf, size_t len, size_t* recievedDataSize);

/*! \brief Send a buffer via a specific connected socket.
 * @param[in] socket The connected socket on which to send data. The socket passed to this function should be of type `PAL_SOCK_STREAM`, unless your specific implementation supports other types as well.
 * @param[in] buf The output buffer for the message data.
 * @param[in] len The length of the output data buffer in bytes.
 * @param[out] sentDataSize The length of the data sent in bytes.
 * \return PAL_SUCCESS (0) in case of success, a specific negative error code in case of failure.
 */
palStatus_t pal_plat_send(palSocket_t socket, const void* buf, size_t len, size_t* sentDataSize);

#endif //PAL_NET_TCP_AND_TLS_SUPPORT

#if PAL_NET_ASYNCHRONOUS_SOCKET_API

/*! \brief Get an asynchronous network socket.
 * @param[in] domain The domain of the created socket. See enum `palSocketDomain_t` for supported types.
 * @param[in] type The type of the created socket. See enum `palSocketType_t` for supported types.
 * @param[in] callback A callback function that is called when any supported event takes place in the given asynchronous socket.
 * @param[in] callbackArgument the argument with which the specified callback will be called when any supported event takes place in the given asynchronous socket.
 * @param[out] socket This output parameter returns the socket.
 * \return PAL_SUCCESS (0) in case of success, a specific negative error code in case of failure.
 */
palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument , palSocket_t* socket);

#endif

#if PAL_NET_DNS_SUPPORT
#if (PAL_DNS_API_VERSION == 0) || (PAL_DNS_API_VERSION == 1)

/*! \brief This function translates a URL to a `palSocketAddress_t` that can be used with PAL sockets.
 * @param[in] url The URL to be translated to a `palSocketAddress_t`.
 * @param[out] address The address for the output of the translation.
 * @param[out] addressLength The length of the output address.
 */
palStatus_t pal_plat_getAddressInfo(const char* url, palSocketAddress_t* address, palSocketLength_t* addressLength);

#elif (PAL_DNS_API_VERSION == 2)

/*! \brief This function translates a URL to a `palSocketAddress_t` that can be used with PAL sockets.
 * @param[in] info address of `pal_asyncAddressInfo_t`.
 */
palStatus_t pal_plat_getAddressInfoAsync(pal_asyncAddressInfo_t* info);

/*! \brief This function is cancelation for `pal_plat_getAddressInfoAsync()`.
 * @param[in] queryHandle ID of ongoing DNS query.
 */
palStatus_t pal_plat_cancelAddressInfoAsync(palDNSQuery_t queryHandle);
#else
    #error "Please specify the platform PAL_DNS_API_VERSION 0, 1, or 2."
#endif //  PAL_DNS_API_VERSION

#endif // PAL_NET_DNS_SUPPORT


#ifdef __cplusplus
}
#endif
#endif //_PAL_PLAT_SOCKET_H
