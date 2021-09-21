// ----------------------------------------------------------------------------
// Copyright 2016-2021 Pelion.
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

#ifndef _PAL_SOCKET_H
#define _PAL_SOCKET_H

#ifndef _PAL_H
#error "Please do not include this file directly, use pal.h instead"
#endif


#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_network.h
*  \brief PAL network.
*   This file contains the network APIs and it is a part of the PAL service API.
*
*   It provides network functionalities for UDP and TCP sockets and connections.
*
* **PAL network socket API** \n
* PAL network socket configuration options:
* + Set \c PAL_NET_TCP_AND_TLS_SUPPORT to true if TCP is supported by the platform and is required.
* + Set \c PAL_NET_DNS_SUPPORT to true if DNS hostname lookup API is supported.
*/

typedef uint32_t palSocketLength_t; /*!< \brief The length of data. */
typedef void *palSocket_t; /*!< \brief PAL socket handle type. */

#define  PAL_NET_MAX_ADDR_SIZE 32 // check if we can make this more efficient

typedef struct palSocketAddress {
    unsigned short    addressType;    /*!< \brief Address family for the socket. */
    char              addressData[PAL_NET_MAX_ADDR_SIZE];  /*!< \brief Address based on the protocol used. */
} palSocketAddress_t; /*!< \brief Address data structure with enough room to support IPV4 and IPV6. */

#if PAL_NET_DNS_SUPPORT
#if (PAL_DNS_API_VERSION == 3)
typedef void *palAddressInfo_t; /*!< \brief PAL address info handle type. */
#endif // (PAL_DNS_API_VERSION == 3)
#endif // PAL_NET_DNS_SUPPORT

typedef struct palNetInterfaceInfo {
    char interfaceName[16]; //15 + ‘\0’
    palSocketAddress_t address;
    uint32_t addressSize;
} palNetInterfaceInfo_t;

/*! \brief Network domains supported by PAL. */
typedef enum {
    PAL_AF_UNSPEC = 0,
    PAL_AF_INET = 2,    /*!< \brief Internet IP Protocol.   */
    PAL_AF_INET6 = 10, /*!< \brief IP version 6.    */
} palSocketDomain_t;

/*! \brief Network status event. */
typedef enum {
    PAL_NETWORK_STATUS_DISCONNECTED = 0,
    PAL_NETWORK_STATUS_CONNECTED = 1
} palNetworkStatus_t;

/*! \brief Socket types supported by PAL. */
typedef enum {
#if PAL_NET_TCP_AND_TLS_SUPPORT
    PAL_SOCK_STREAM = 1,    /*!< \brief Stream socket.   */
    PAL_SOCK_STREAM_SERVER = 99,    /*!< \brief Stream socket.   */
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    PAL_SOCK_DGRAM = 2  /*!< \brief Datagram socket.     */
} palSocketType_t;

/*! \brief Socket options supported by PAL. */
typedef enum {
    PAL_SO_REUSEADDR = 0x0004,  /*!< \brief Allow local address reuse. */
#if PAL_NET_TCP_AND_TLS_SUPPORT // Socket options below supported only if TCP is supported.
    PAL_SO_KEEPALIVE = 0x0008, /*!< \brief Keep TCP connection open even if idle using periodic messages. */
    PAL_SO_KEEPIDLE = 0x0009,  /*!< \brief The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes, if the socket option `SO_KEEPALIVE` has been set on this socket. */
    PAL_SO_KEEPINTVL = 0x0010, /*!< \brief The time (in seconds) between individual keepalive probes */
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    PAL_SO_SNDTIMEO = 0x1005,  /*!< \brief Send timeout. */
    PAL_SO_RCVTIMEO = 0x1006,  /*!< \brief Receive timeout. */
    PAL_SO_IPV6_MULTICAST_HOPS = 0x1007,  /*!< \brief Hop limit for subsequent multicast datagrams to be set to any value from 0 to 255. This ability is used to control the scope of the multicasts. */
    PAL_SO_IPV6_TRAFFIC_CLASS = 0x1008  /*!< \brief Use to set IPv6 traffic class priority. Default is 0. */
} palSocketOptionName_t;

/*! \brief Socket protocol level options supported by PAL. */
typedef enum {
    PAL_SOL_SOCKET = 0,
    PAL_SOL_IPPROTO_IPV6 = 1
} palSocketOptionLevelName_t;

#define PAL_NET_DEFAULT_INTERFACE 0xFFFFFFFF

#define PAL_IPV4_ADDRESS_SIZE 4
#define PAL_IPV6_ADDRESS_SIZE 16

typedef uint8_t palIpV4Addr_t[PAL_IPV4_ADDRESS_SIZE];
typedef uint8_t palIpV6Addr_t[PAL_IPV6_ADDRESS_SIZE];

typedef void(*connectionStatusCallback)(palNetworkStatus_t status, void *client_arg);

/*! \brief Register a network interface for use with PAL sockets.
 *
 * Must be called before other socket functions. Most APIs will not work before an interface is added.
 * @param[in] networkInterfaceContext The network interface to be added. This value is OS-specific.
 * @param[out] interfaceIndex Contains the index assigned to the interface in case it has been assigned successfully. When creating a socket, this index can be used to bind the socket to the interface.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 * \note In mbed OS the \c networkInterfaceContext is the `NetworkInterface` object pointer for the network adapter, assuming that connect has already been called on this interface object.
 *
 * \note In Linux the \c networkInterfaceContext is the string name of the network interface (e.g. \c eth0 ).
 *
 * \note If a context is not applicable on a target configuration, use \c NULL .
 */
palStatus_t pal_registerNetworkInterface(void *networkInterfaceContext, uint32_t *interfaceIndex);

/*! \brief Unregister a network interface.
 * @param interfaceIndex Index of the network interface to be removed.
 * \return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
 */
palStatus_t pal_unregisterNetworkInterface(uint32_t interfaceIndex);

/*! \brief Set a port to an address data structure.
 * @param[in,out] address The address data structure to configure.
 * @param[in] port The port number to set.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 * \note To set the socket correctly, the `addressType` field of the address must be set correctly.
 *       You can set it either directly, or using the `pal_setSockAddrIPV4Addr` or `pal_setSockAddrIPV6Addr` functions.
 */
palStatus_t pal_setSockAddrPort(palSocketAddress_t *address, uint16_t port);

/*! \brief Set an IPv4 address to an address data structure and set `addressType` as IPv4.
 * @param[in,out] address The address data structure to configure.
 * @param[in] ipV4Addr The address value to set.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_setSockAddrIPV4Addr(palSocketAddress_t *address, palIpV4Addr_t ipV4Addr);

/*! \brief Get an IPv4 address from an address data structure.
 * @param[in] address The address data structure to query.
 * @param[out] ipV4Addr The IPv4 address to get.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getSockAddrIPV4Addr(const palSocketAddress_t *address, palIpV4Addr_t ipV4Addr);

/*! \brief Set an IPv6 address to an address data structure and set the `addressType` as IPv6.
 * @param[in,out] address The address data structure to configure.
 * @param[in] ipV6Addr The address value to set.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_setSockAddrIPV6Addr(palSocketAddress_t *address, palIpV6Addr_t ipV6Addr);

/*! \brief Get an IPv6 address from an address data structure.
 * @param[in] address The address data structure to query.
 * @param[out] ipV6Addr The address to get.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getSockAddrIPV6Addr(const palSocketAddress_t *address, palIpV6Addr_t ipV6Addr);

/*! \brief Set a NAT64 address from an IPv4 address data structure and set `addressType` as IPv6.
 * @param[in,out] address The address data structure to configure.
 * @param[in] ipV4Addr The address value to set.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_setSockAddrNAT64Addr(palSocketAddress_t *address, palIpV4Addr_t ipV4Addr);

/*! \brief Get a port from an address data structure.
 * @param[in] address The address data structure to query.
 * @param[out] port The port to get.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getSockAddrPort(const palSocketAddress_t *address, uint16_t *port);

/*! \brief Set the value for a socket option on a network socket.
 * @param[in] socket The socket to configure.
 * @param[in] optionName The identification of the socket option to set. See \c palSocketOptionName_t for supported options.
 * @param[in] optionValue The buffer holding the option value to set for the option.
 * @param[in] optionLength  The size of the buffer provided for `optionValue`.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_setSocketOptions(palSocket_t socket, int optionName, const void *optionValue, palSocketLength_t optionLength);

/*! \brief Set the value for a socket option on a network socket.
 * @param[in] socket The socket to configure.
 * @param[in] optionLevel Specifies the protocol level at which the option resides. See \c palSocketOptionLevelName_t for supported levels.
 * @param[in] optionName The identification of the socket option to set. See \c palSocketOptionName_t for supported options.
 * @param[in] optionValue The buffer holding the option value to set for the option.
 * @param[in] optionLength  The size of the buffer provided for `optionValue`.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_setSocketOptionsWithLevel(palSocket_t socket, palSocketOptionLevelName_t optionLevel, int optionName, const void *optionValue, palSocketLength_t optionLength);

/*! \brief Check if a socket is non-blocking.
 * @param[in] socket The socket to check.
 * @param[out] isNonBlocking `True` if the socket is non-blocking, otherwise `false`.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_isNonBlocking(palSocket_t socket, bool *isNonBlocking);

/*! \brief Bind a socket to a local address.
 * @param[in] socket The socket to bind.
 * @param[in] myAddress The address to bind to.
 * @param[in] addressLength The length of the address passed in `myAddress`.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_bind(palSocket_t socket, palSocketAddress_t *myAddress, palSocketLength_t addressLength);

/*! \brief Receive a payload from a specific socket.
 * @param[in] socket The socket to receive from. The socket passed to this function should usually be of type `PAL_SOCK_DGRAM`, though your specific implementation may support other types as well.
 * @param[out] buffer The buffer for the payload data.
 * @param[in] length The length of the buffer for the payload data.
 * @param[out] from The address that sent the payload.
 * @param[in, out] fromLength The length of `from` on input, the length of the data returned on output.
 * @param[out] bytesReceived The actual amount of payload data received in the buffer.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_receiveFrom(palSocket_t socket, void *buffer, size_t length, palSocketAddress_t *from, palSocketLength_t *fromLength, size_t *bytesReceived);

/*! \brief Send a payload to an address using a specific socket.
 * @param[in] socket The socket to use for sending the payload. The socket passed to this function should usually be of type `PAL_SOCK_DGRAM`, though your specific implementation may support other types as well.
 * @param[in] buffer The buffer for the payload data.
 * @param[in] length The length of the buffer for the payload data.
 * @param[in] to The address to which the payload should be sent.
 * @param[in] toLength The length of the `to` address.
 * @param[out] bytesSent The actual amount of payload data sent.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_sendTo(palSocket_t socket, const void *buffer, size_t length, const palSocketAddress_t *to, palSocketLength_t toLength, size_t *bytesSent);

/*! \brief Close a network socket.
 * @param[in,out] socket The socket to be closed.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 * \note Receives `palSocket_t*`, \e not `palSocket_t`, so that it can zero the socket to avoid re-use.
 */
palStatus_t pal_close(palSocket_t *socket);

/*! \brief Get the number of current network interfaces.
 * @param[out] numInterfaces The number of interfaces.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getNumberOfNetInterfaces(uint32_t *numInterfaces);

/*! \brief Get information regarding the socket at the interface index number given. This number is returned when registering the socket.
 * @param[in] interfaceNum The number of the interface to get information for.
 * @param[out] interfaceInfo The information for the given interface number.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t *interfaceInfo);

/*! \brief Set listener for connection status events.
 * @param[in] interfaceNum Index of the network interface to be listen.
 * @param[in] callback Callback that is called when network interface status change.
 * @param[in] client_arg The argument which is passed to the callback function.
 * \return PAL_SUCCESS (0) in case of success, a specific negative error code in case of failure.
 */
palStatus_t pal_setConnectionStatusCallback(uint32_t interfaceNum, connectionStatusCallback callback, void *client_arg);

#define PAL_NET_SOCKET_SELECT_MAX_SOCKETS 8
#define PAL_NET_SOCKET_SELECT_RX_BIT (1)
#define PAL_NET_SOCKET_SELECT_TX_BIT (2)
#define PAL_NET_SOCKET_SELECT_ERR_BIT (4)

#define PAL_NET_SELECT_IS_RX(socketStatus, index)   ((socketStatus[index] & PAL_NET_SOCKET_SELECT_RX_BIT) != 0) /*!< Check if RX bit is set in select result for a given socket index. */
#define PAL_NET_SELECT_IS_TX(socketStatus, index)   ((socketStatus[index] & PAL_NET_SOCKET_SELECT_TX_BIT) != 0) /*!< Check if TX bit is set in select result for a given socket index. */
#define PAL_NET_SELECT_IS_ERR(socketStatus, index)  ((socketStatus[index] & PAL_NET_SOCKET_SELECT_ERR_BIT) != 0) /*!< Check if ERR bit is set in select result for a given socket index. */

/*! \brief The type of the callback function passed when creating asynchronous sockets.
 * @param[in] argument The user provided argument passed to the callback function.
 */
typedef void(*palAsyncSocketCallback_t)(void *);

#if PAL_NET_TCP_AND_TLS_SUPPORT // The functionality below is supported only if TCP is supported.

#if PAL_NET_SERVER_SOCKET_API

/*! \brief Use a specific socket to listen for incoming connections. This may also limit the queue of incoming connections.
 * @param[in] socket The socket to listen to. The sockets passed to this function should usually be of type `PAL_SOCK_STREAM_SERVER`, though your specific implementation may support other types as well.
 * @param[in] backlog The amount of pending connections that can be saved for the socket.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_listen(palSocket_t socket, int backlog);

/*! \brief Accept a connection on a specific socket.
 * @param[in] socket The socket on which to accept the connection. The socket must be already created and bound, and listen must have been called on it. The socket passed to this function should usually be of type `PAL_SOCK_STREAM_SERVER`, though your specific the implementation may support other types as well.
 * @param[out] address The source address of the incoming connection.
 * @param[in,out] addressLen The length of `address` on input, the length of the data returned on output.
 * @param[out] acceptedSocket The socket of the accepted connection.
 * @param[in] callback The callback function to be attached to the asynchronous accepted socket.
 * @param[in] callbackArgument The callback argument to be attached to the asynchronous accepted socket.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_accept(palSocket_t socket, palSocketAddress_t *address, palSocketLength_t *addressLen, palSocket_t *acceptedSocket, palAsyncSocketCallback_t callback, void *callbackArgument);

#endif // PAL_NET_SERVER_SOCKET_API

/*! \brief Open a connection from a socket to a specific address.
 * @param[in] socket The socket to use for a connection to the address. The socket passed to this function should usually be of type `PAL_SOCK_STREAM`, though your specific implementation may support other types as well.
 * @param[in] address The destination address of the connection.
 * @param[in] addressLen The length of the `address` field.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_connect(palSocket_t socket, const palSocketAddress_t *address, palSocketLength_t addressLen);

/*! \brief Receive data from a connected socket.
 * @param[in] socket The connected socket on which to receive data. The socket passed to this function should usually be of type `PAL_SOCK_STREAM`, though your specific implementation may support other types as well.
 * @param[out] buf The output buffer for the message data.
 * @param[in] len The length of the input data buffer.
 * @param[out] recievedDataSize The length of the data actually received.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_recv(palSocket_t socket, void *buf, size_t len, size_t *recievedDataSize);

/*! \brief Send a buffer via a connected socket.
 * @param[in] socket The connected socket on which to send data. The socket passed to this function should usually be of type `PAL_SOCK_STREAM`, though your specific implementation may support other types as well.
 * @param[in] buf The output buffer for the message data.
 * @param[in] len The length of the input data buffer.
 * @param[out] sentDataSize The length of the data sent.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_send(palSocket_t socket, const void *buf, size_t len, size_t *sentDataSize);


#endif //PAL_NET_TCP_AND_TLS_SUPPORT

/*! \brief Get an asynchronous network socket.
 * @param[in] domain The domain for the created socket. See enum `palSocketDomain_t` for supported types.
 * @param[in] type The type for the socket. See enum `palSocketType_t` for supported types.
 * @param[in] nonBlockingSocket If `true`, the socket is non-blocking.
 * @param[in] interfaceNum The number of the network interface used for this socket. Select `PAL_NET_DEFAULT_INTERFACE` for the default interface.
 * @param[in] callback A callback function that is called when any supported event happens in the given asynchronous socket. See `palAsyncSocketCallback_t` enum for the types of events supported.
 * @param[out] socket The socket is returned through this output parameter.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, palSocket_t *socket);

/*! \brief Get an asynchronous network socket that passes the provided `callbackArgument` to a specified callback when it is triggered.
 * @param[in] domain The domain for the created socket. See enum `palSocketDomain_t` for supported types.
 * @param[in] type The type for the created socket. See enum `palSocketType_t` for supported types.
 * @param[in] nonBlockingSocket If `true`, the socket is created as non-blocking.
 * @param[in] interfaceNum The number of the network interface used for this socket. Select `PAL_NET_DEFAULT_INTERFACE` for the default interface.
 * @param[in] callback A callback function that is called when any supported event happens in the given asynchronous socket.
 * @param[in] callbackArgument The argument with which the specified callback function is called.
 * @param[out] socket The socket is returned through this output parameter.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_asynchronousSocketWithArgument(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void *callbackArgument, palSocket_t *socket);


#if PAL_NET_DNS_SUPPORT
#if (PAL_DNS_API_VERSION == 0) || (PAL_DNS_API_VERSION == 1)

/*! \brief This function translates a hostname to `palSocketAddress_t` which can be used with PAL sockets.
 *
 * Supports both IP address as a string, and hostnames (using DNS lookup).
 * @param[in] hostname The hostname (or IP address string) to be translated to a `palSocketAddress_t`.
 * @param[out] address The address for the output of the translation.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getAddressInfo(const char *hostname, palSocketAddress_t *address, palSocketLength_t *addressLength);

#if (PAL_DNS_API_VERSION == 1)

/*! \brief Prototype of the callback function invoked when querying address info asynchronously using `pal_getAddressInfoAsync`.
 * @param[in] hostname The user-provided hostname (or IP address string) that was requested to be translated.
 * @param[in] address The address for the output of the translation.
 * @param[in] addressLength The length of the address for the output of the translation in bytes.
 * @param[in] status The status of the operation - PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 * @param[in] callbackArgument The user callback argument.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
typedef void(*palGetAddressInfoAsyncCallback_t)(const char *hostname, palSocketAddress_t *address, palSocketLength_t *addressLength, palStatus_t status, void *callbackArgument);

/*! \brief This function translates a hostname to `palSocketAddress_t` which can be used with PAL sockets.
 *
 * Supports both IP address as a string, and hostname (using DNS lookup).
 * \note This function is non-blocking.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[out] address The address for the output of the translation.
 * @param[out] addressLength The length of the address for the output of the translation in bytes.
 * @param[in] callback The user-provided callback to be invoked once the function has completed.
 * @param[in] callbackArgument The user-provided callback argument which will be passed back to the callback function.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getAddressInfoAsync(const char *hostname, palSocketAddress_t *address, palSocketLength_t *addressLength, palGetAddressInfoAsyncCallback_t callback, void *callbackArgument);
#endif
#elif (PAL_DNS_API_VERSION == 2) || (PAL_DNS_API_VERSION == 3)
#if (PAL_DNS_API_VERSION == 2)
typedef int32_t palDNSQuery_t; /*!< \brief PAL DNS query handle. Can be used to cancel the asynchronous DNS query. */

/*! \brief Prototype of the callback function invoked when querying address info asynchronously using `pal_getAddressInfoAsync`.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[out] address The address for the output of the translation.
 * @param[out] status The status of the operation - PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 * @param[in] callbackArgument The user callback argument.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
typedef void(*palGetAddressInfoAsyncCallback_t)(const char *hostname, palSocketAddress_t *address, palStatus_t status, void *callbackArgument);

/*! \brief Structure used by pal_getAddressInfoAsync.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[out] address The address for the output of the translation.
 * @param[in] callback The user-provided callback.
 * @param[in] callbackArgument The user callback argument of `pal_GetAddressInfoAsyncCallback_t`.
 * @param[out] queryHandle Handler ID, which can be used for a cancellation request.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
typedef struct pal_asyncAddressInfo {
    char *hostname;
    palSocketAddress_t *address;
    palGetAddressInfoAsyncCallback_t callback;
    void *callbackArgument;
    palDNSQuery_t *queryHandle;
} pal_asyncAddressInfo_t;

/*! \brief This function translates a hostname to `palSocketAddress_t` which can be used with PAL sockets.
 *
 * Supports both IP address as a string, and hostname (using DNS lookup).
 * \note The function is non-blocking.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[out] address The address for the output of the translation.
 * @param[in] callback The user-provided callback to be invoked once the function has completed.
 * @param[in] callbackArgument The user callback argument of `pal_GetAddressInfoAsyncCallback_t`.
 * @param[out] queryHandle DNS query handler. Caller must take care of allocation. If not used, then set as `NULL`.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getAddressInfoAsync(const char *hostname,
                                    palSocketAddress_t *address,
                                    palGetAddressInfoAsyncCallback_t callback,
                                    void *callbackArgument,
                                    palDNSQuery_t *queryHandle);

#elif (PAL_DNS_API_VERSION == 3)
typedef uintptr_t palDNSQuery_t; /*!< \brief PAL DNS query handle. Can be used to cancel the asynchronous DNS query. */

/*! \brief This function puts the palSocketAddress_t from the given index in palAddressInfo_t to the given addr
 * @param[in] addrInfo The palAddressInfo_t which (if any) palSocketAddress_t is get.
 * @param[in] index Index of the address in addrInfo to fetch.
 * @param[out] addr palSocketAddress_t is put to this instance is any if found.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getDNSAddress(palAddressInfo_t *addrInfo, uint16_t index, palSocketAddress_t *addr);

/*! \brief Return the number of dns addresses in the given addrInfo
 * @param[in] addrInfo The palAddressInfo_t to be used for countung dns addresses.
 * \return Number of DNS addresses in the given addrInfo.
 */
int pal_getDNSCount(palAddressInfo_t *addrInfo);

/*! \brief Free the given addrInfo.
 * @param[in] addrInfo OS specific palAddressInfo_t which holds dns addresses.
 */
void pal_freeAddrInfo(palAddressInfo_t *addrInfo);

/*! \brief This function free's the thread needed in pal_getAddressInfoAsync
 * @param[out] handle PAL DNS query handle, used to cancel the asynchronous DNS query.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
*/
palStatus_t pal_free_addressinfoAsync(palDNSQuery_t handle);

/*! \brief Prototype of the callback function invoked when querying address info asynchronously using `pal_getAddressInfoAsync`.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[out] addrInfo OS specific palAddressInfo_t which holds dns addresses.
 * @param[out] status The status of the operation - PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 * @param[in] callbackArgument The user callback argument.
 */
typedef void(*palGetAddressInfoAsyncCallback_t)(const char *hostname, palAddressInfo_t *addrInfo, palStatus_t status, void *callbackArgument);

/*! \brief Structure used by pal_getAddressInfoAsync.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[out] addrInfo OS specific palAddressInfo_t which holds dns addresses.
 * @param[in] callback The user-provided callback.
 * @param[in] callbackArgument The user callback argument of `pal_GetAddressInfoAsyncCallback_t`.
 * @param[out] queryHandle Handler ID, which can be used for a cancellation request.
 */
typedef struct pal_asyncAddressInfo
{
    char* hostname;
    palAddressInfo_t *addrInfo;
    palGetAddressInfoAsyncCallback_t callback;
    void* callbackArgument;
    palDNSQuery_t *queryHandle;
} pal_asyncAddressInfo_t;

/*! \brief This function translates a hostname to `palSocketAddress_t`(s) which can be used with PAL sockets.
 *
 * Supports both IP address as a string, and hostname (using DNS lookup).
 * \note The function is non-blocking.
 * @param[in] hostname The user-provided hostname (or IP address string) to be translated.
 * @param[in] callback The user-provided callback to be invoked once the function has completed.
 * @param[in] callbackArgument The user callback argument of `pal_GetAddressInfoAsyncCallback_t`.
 * @param[out] queryHandle DNS query handler. Caller must take care of allocation. If not used, then set as `NULL`.
 * \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
 */
palStatus_t pal_getAddressInfoAsync(const char* hostname,
                                     palGetAddressInfoAsyncCallback_t callback,
                                     void* callbackArgument,
                                     palDNSQuery_t* queryHandle);

#endif

/*! \brief This function is a cancellation for `pal_getAddressInfoAsync`.
* @param[in] queryHandle Id of the ongoing DNS query.
* \return PAL_SUCCESS (0) in case of success, or a specific negative error code in case of failure.
*/
palStatus_t pal_cancelAddressInfoAsync(palDNSQuery_t queryHandle);
#else
    #error "Please specify the platform PAL_DNS_API_VERSION 0, 1, 2 or 3"
#endif //  PAL_DNS_API_VERSION
#endif  // PAL_NET_DNS_SUPPORT

/*! \brief This function returns the round-trip estimate for packet in seconds.
 *
 * This value can be used to control client retransmission and responsiveness in high latency networks based
 * on the network information the stack has.
 * This feature is currently only supported for Mbed OS Wi-SUN stack as a dynamic feature. Other platforms/stacks return
 * PAL_DEFAULT_RTT_ESTIMATE.
 * This API limits the RTT to uint8_t due to most of the callers only supporting uint8_t or uint16_t types.
 * @param[out] rtt_estimate The round-trip estimate in seconds.
 */

uint8_t pal_getRttEstimate();

/*! \brief This function returns the stagger estimate for registration in seconds.
 *
 * This value can be used to delay the registration of the client after interface GLOBAL_UP
 * to stagger the traffic in a multidevice network with limited bandwidth.
 * This feature is currently only supported for Mbed OS Wi-SUN stack as a dynamic feature. Other platforms/stacks return
 * PAL_DEFAULT_STAGGER_ESTIMATE.
 * @param[in] estimate for the amount of data in KiB to be transferred.
 * @param[out] stagger_estimate The randomized stagger estimate in seconds.
 */

uint16_t pal_getStaggerEstimate(uint16_t data_amount);

/*! \brief This function sets an application defined override value for the stagger estimate for registration in seconds.
 *
 * This value can be used to set a delay for the registration of the client after interface GLOBAL_UP
 * to stagger the traffic in a multidevice network with limited bandwidth.
 * When set to any value larger than 0, this overrides any compile-time values set by PAL_DEFAULT_STAGGER_ESTIMATE or provided by network stack.
 * If value is 0, this override is disabled.
 * @param[in] stagger value in seconds.
 */

void pal_setFixedStaggerEstimate(uint16_t stagger_estimate);

#ifdef __cplusplus
}
#endif
#endif //_PAL_SOCKET_H
