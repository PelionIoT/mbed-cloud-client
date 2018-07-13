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


#ifndef _PAL_SOCKET_H
#define _PAL_SOCKET_H

#ifndef _PAL_H
    #error "Please do include call this file directly, use pal.h instead"
#endif


#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_network.h
*  \brief PAL network.
*   This file contains the network APIs and it is a part of the PAL service API.
*   It provides network functionalities for UDP and TCP sockets and connections.
*/

//! PAL network socket API \n
//! PAL network sockets configurations options: \n
//! Set PAL_NET_TCP_AND_TLS_SUPPORT to true if TCP is supported by the platform and is required. \n
//! Set PAL_NET_ASYNCHRONOUS_SOCKET_API to true if asynchronous socket API is supported by the platform and is required: Currently MANDATORY.
//! Set PAL_NET_DNS_SUPPORT to true if DNS URL lookup API is supported.

typedef uint32_t palSocketLength_t; /*! The length of data. */
typedef void* palSocket_t; /*! PAL socket handle type. */

#define  PAL_NET_MAX_ADDR_SIZE 32 // check if we can make this more efficient

typedef struct palSocketAddress {
    unsigned short    addressType;    /*! Address family for the socket. */
    char              addressData[PAL_NET_MAX_ADDR_SIZE];  /*! Address (based on protocol). */
} palSocketAddress_t; /*! Address data structure with enough room to support IPV4 and IPV6. */

typedef struct palNetInterfaceInfo{
    char interfaceName[16]; //15 + ‘\0’
    palSocketAddress_t address;
    uint32_t addressSize;
} palNetInterfaceInfo_t;

typedef enum {
    PAL_AF_UNSPEC = 0,
    PAL_AF_INET = 2,    /*! Internet IP Protocol.   */
    PAL_AF_INET6 = 10, /*! IP version 6.    */
} palSocketDomain_t;/*! Network domains supported by PAL. */

typedef enum {
#if PAL_NET_TCP_AND_TLS_SUPPORT
    PAL_SOCK_STREAM = 1,    /*! Stream socket.   */
    PAL_SOCK_STREAM_SERVER = 99,    /*! Stream socket.   */
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    PAL_SOCK_DGRAM = 2  /*! Datagram socket.     */
} palSocketType_t;/*! Socket types supported by PAL. */


typedef enum {
    PAL_SO_REUSEADDR = 0x0004,  /*! Allow local address reuse. */
#if PAL_NET_TCP_AND_TLS_SUPPORT // Socket options below supported only if TCP is supported.
    PAL_SO_KEEPALIVE = 0x0008, /*! Keep TCP connection open even if idle using periodic messages. */
    PAL_SO_KEEPIDLE = 0x0009,  /*! The time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes, if the socket option SO_KEEPALIVE has been set on this socket. */
    PAL_SO_KEEPINTVL = 0x0010, /*! The time (in seconds) between individual keepalive probes */
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    PAL_SO_SNDTIMEO = 0x1005,  /*! Send timeout. */
    PAL_SO_RCVTIMEO = 0x1006,  /*! Receive timeout. */
} palSocketOptionName_t;/*! Socket options supported by PAL. */

#define PAL_NET_DEFAULT_INTERFACE 0xFFFFFFFF

#define PAL_IPV4_ADDRESS_SIZE 4
#define PAL_IPV6_ADDRESS_SIZE 16

typedef uint8_t palIpV4Addr_t[PAL_IPV4_ADDRESS_SIZE];
typedef uint8_t palIpV6Addr_t[PAL_IPV6_ADDRESS_SIZE];


/*! Register a network interface for use with PAL sockets. Must be called before other socket functions. Most APIs will not work before a single interface is added.
* @param[in] networkInterfaceContext The network interface to be added ( this is an OS specific value). In mbed OS the networkInterfaceContext is the `NetworkInterface` object pointer for the network adapter [**Note:** We assume that connect has already been called on this interface object]. In Linux the networkInterfaceContext is the string name of the network interface (e.g. "eth0"). For more examples see the PAL palTestGetNetWorkInterfaceContext function implementations in the platform bring-up examples (found in Examples\PlatformBSP). The palTestGetNetWorkInterfaceContext function illustrates the expected value for networkInterfaceContext for that target. If a context is not applicable on a target configuration use NULL.
* @param[out] interfaceIndex Contains the index assigned to the interface in case it has been assigned successfully. This index can be used, when creating a socket, to bind the socket to the interface.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_registerNetworkInterface(void* networkInterfaceContext, uint32_t* interfaceIndex);

/*! Set a port to `palSocketAddress_t`. \n
* You can set it either directly or via the `palSetSockAddrIPV4Addr` or `palSetSockAddrIPV6Addr` functions.
* @param[in,out] address The address to set.
* @param[in] port The port number to set.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
\note To set the socket correctly, the `addressType` field of the address must be set correctly.
*/
palStatus_t pal_setSockAddrPort(palSocketAddress_t* address, uint16_t port);


/*! Set an IPv4 address to `palSocketAddress_t` and `addressType` to IPv4.
* @param[in,out] address The address to set.
* @param[in] ipV4Addr The address value to set.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_setSockAddrIPV4Addr(palSocketAddress_t* address, palIpV4Addr_t ipV4Addr);

/*! Get an IPv4 address from `palSocketAddress_t`.
* @param[in] address The address to set.
* @param[out] ipV4Addr The address that is set in `address`.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_getSockAddrIPV4Addr(const palSocketAddress_t* address, palIpV4Addr_t ipV4Addr);


/*! Set an IPv6 address to `palSocketAddress_t` and the `addressType` to IPv6.
* @param[in,out] address The address to set.
* @param[in] ipV6Addr The address value to set.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_setSockAddrIPV6Addr(palSocketAddress_t* address, palIpV6Addr_t ipV6Addr);

/*! Get an IPv6 address from `palSocketAddress_t`.
* @param[in] address The address to set.
* @param[out] ipV6Addr The address that is set in `address`.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_getSockAddrIPV6Addr(const palSocketAddress_t* address, palIpV6Addr_t ipV6Addr);


/*! Get a port from `palSocketAddress_t`.
* @param[in] address The address to set.
* @param[out] port The port that is set in `address`.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_getSockAddrPort(const palSocketAddress_t* address, uint16_t* port);

/*! Get a network socket.
* @param[in] domain The domain for the created socket (see `palSocketDomain_t` for supported types).
* @param[in] type The type of the created socket (see `palSocketType_t` for supported types).
* @param[in] nonBlockingSocket If true, the socket is created as non-blocking (with O_NONBLOCK set).
* @param[in] interfaceNum The number of the network interface used for this socket (info in interfaces supported via `pal_getNumberOfNetInterfaces` and `pal_getNetInterfaceInfo`). Select PAL_NET_DEFAULT_INTERFACE for the default interface.
* @param[out] socket The socket is returned through this output parameter.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* socket);

/*!  Set the value for a given socket option on a given network socket.
* @param[in] socket The socket for which to get options.
* @param[in] optionName The identification of the socket option for which we are getting the value (see enum palSocketOptionName_t for supported types).
* @param[in] optionValue The buffer holding the option value to set for the given option.
* @param[in] optionLength  The size of the buffer provided for `optionValue`.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength);

/*! Check if a given socket is non-blocking.
* @param[in] socket The socket to check.
* @param[out] isNonBlocking True if the socket is non-blocking, otherwise false.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_isNonBlocking(palSocket_t socket, bool* isNonBlocking);

/*! Bind a given socket to a local address.
* @param[in] socket The socket to bind.
* @param[in] myAddress The address to bind to.
* @param[in] addressLength The length of the address passed in `myAddress`.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength);

/*! Receive a payload from the given socket.
* @param[in] socket The socket to receive from. [The sockets passed to this function should be of type PAL_SOCK_DGRAM (the implementation may support other types as well).]
* @param[out] buffer The buffer for the payload data.
* @param[in] length The length of the buffer for the payload data.
* @param[out] from The address that sent the payload.
* @param[in, out] fromLength The length of the `from` address. Contains the amount of data actually written to the `from` address.
* @param[out] bytesReceived The actual amount of payload data received in the buffer.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived);

/*! Send a payload to the given address using the given socket.
* @param[in] socket The socket to use for sending the payload. [The sockets passed to this function should be of type PAL_SOCK_DGRAM (the implementation may support other types as well).]
* @param[in] buffer The buffer for the payload data.
* @param[in] length The length of the buffer for the payload data.
* @param[in] to The address to which the payload should be sent.
* @param[in] toLength The length of the `to` address.
* @param[out] bytesSent The actual amount of payload data sent.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent);

/*! Close a network socket.
* @param[in,out] The socket to be closed.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
\note Receives `palSocket_t*`, NOT `palSocket_t`, so that it can zero the socket to avoid re-use.
*/
palStatus_t pal_close(palSocket_t* socket);

/*! Get the number of current network interfaces.
* @param[out] numInterfaces The number of interfaces.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_getNumberOfNetInterfaces(uint32_t* numInterfaces);

/*! Get information regarding the socket at the index/interface number given (this number is returned when registering the socket).
* @param[in] interfaceNum The number of the interface to get information for.
* @param[out] interfaceInfo Set to the information for the given interface number.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t* interfaceInfo);


#define PAL_NET_SOCKET_SELECT_MAX_SOCKETS 8
#define PAL_NET_SOCKET_SELECT_RX_BIT (1)
#define PAL_NET_SOCKET_SELECT_TX_BIT (2)
#define PAL_NET_SOCKET_SELECT_ERR_BIT (4)

#define PAL_NET_SELECT_IS_RX(socketStatus, index)   ((socketStatus[index] & PAL_NET_SOCKET_SELECT_RX_BIT) != 0) /*! Check if RX bit is set in select result for a given socket index. */
#define PAL_NET_SELECT_IS_TX(socketStatus, index)   ((socketStatus[index] & PAL_NET_SOCKET_SELECT_TX_BIT) != 0) /*! Check if TX bit is set in select result for a given socket index. */
#define PAL_NET_SELECT_IS_ERR(socketStatus, index)  ((socketStatus[index] & PAL_NET_SOCKET_SELECT_ERR_BIT) != 0) /*! Check if ERR bit is set in select result for a given socket index. */

#if PAL_NET_TCP_AND_TLS_SUPPORT // The functionality below is supported only if TCP is supported.


/*! Use the given socket to listen for incoming connections. This may also limit the queue of incoming connections.
* @param[in] socket The socket to listen to. [The sockets passed to this function should be of type PAL_SOCK_STREAM_SERVER (the implementation may support other types as well).]
* @param[in] backlog The amount of pending connections that can be saved for the socket.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_listen(palSocket_t socket, int backlog);

/*! Accept a connection on the given socket.
* @param[in] socket The socket on which to accept the connection. (The socket must be already created and bound and listen has must have been called on it.) [The sockets passed to this function should be of type PAL_SOCK_STREAM_SERVER (the implementation may support other types as well).]
* @param[out] address The source address of the incoming connection.
* @param[in, out] addressLen The length of the address field on input, the length of the data returned on output.
* @param[out] acceptedSocket The socket of the accepted connection.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket);

/*! Open a connection from the given socket to the given address.
* @param[in] socket The socket to use for connection to the given address. [The sockets passed to this function should be of type PAL_SOCK_STREAM (the implementation may support other types as well).]
* @param[in] address The destination address of the connection.
* @param[in] addressLen The length of the address field.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen);

/*! Receive data from the given connected socket.
* @param[in] socket The connected socket on which to receive data. [The sockets passed to this function should be of type PAL_SOCK_STREAM (the implementation may support other types as well).]
* @param[out] buf The output buffer for the message data.
* @param[in] len The length of the input data buffer.
* @param[out] recievedDataSize The length of the data actually received.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_recv(palSocket_t socket, void* buf, size_t len, size_t* recievedDataSize);

/*! Send a given buffer via the given connected socket.
* @param[in] socket The connected socket on which to send data. [The sockets passed to this function should be of type PAL_SOCK_STREAM (the implementation may support other types as well).]
* @param[in] buf The output buffer for the message data.
* @param[in] len The length of the input data buffer.
* @param[out] sentDataSize The length of the data sent.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_send(palSocket_t socket, const void* buf, size_t len, size_t* sentDataSize);


#endif //PAL_NET_TCP_AND_TLS_SUPPORT


#if PAL_NET_ASYNCHRONOUS_SOCKET_API

/*! The type of the callback funciton passed when creating asynchronous sockets.
* @param[in] argument The user provided argument passed to the callback function.
*/
typedef void(*palAsyncSocketCallback_t)(void*);

/*! Get an asynchronous network socket.
* @param[in] domain The domain for the created socket (see enum `palSocketDomain_t` for supported types).
* @param[in] type The type for the created socket (see enum `palSocketType_t` for supported types).
* @param[in] nonBlockingSocket If true, the socket is created as non-blocking (with O_NONBLOCK set).
* @param[in] interfaceNum The number of the network interface used for this socket (info in interfaces supported via `pal_getNumberOfNetInterfaces` and `pal_getNetInterfaceInfo`). Select PAL_NET_DEFAULT_INTERFACE for the default interface.
* @param[in] callback A callback function that is called when any supported event happens in the given asynchronous socket (see `palAsyncSocketCallbackType` enum for the types of events supported).
* @param[out] socket The socket is returned through this output parameter.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, palSocket_t* socket);

/*! Get an asynchronous network socket that passes the provided `callbackArgument` to the provided callback on callback events.
* @param[in] domain The domain for the created socket (see enum `palSocketDomain_t` for supported types).
* @param[in] type The type for the created socket (see enum `palSocketType_t` for supported types).
* @param[in] nonBlockingSocket If true, the socket is created as non-blocking (with O_NONBLOCK set).
* @param[in] interfaceNum The number of the network interface used for this socket (info in interfaces supported via `pal_getNumberOfNetInterfaces` and `pal_getNetInterfaceInfo`). Select PAL_NET_DEFAULT_INTERFACE for the default interface.
* @param[in] callback A callback function that is called when any supported event happens in the given asynchronous socket.
* @param[in] callbackArgument The argument with which the callback function is called when any supported event happens in the given asynchronous socket.
* @param[out] socket The socket is returned through this output parameter.
\return PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure.
*/
palStatus_t pal_asynchronousSocketWithArgument(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback,void* callbackArgument, palSocket_t* socket);



#endif

#if PAL_NET_DNS_SUPPORT

/*! This function translates from a URL to `palSocketAddress_t` which can be used with PAL sockets. It supports both IP address as strings and URLs (using DNS lookup).
* @param[in] url The URL (or IP address string) to be translated to a `palSocketAddress_t`.
* @param[out] address The address for the output of the translation.
*/
palStatus_t pal_getAddressInfo(const char* url, palSocketAddress_t* address, palSocketLength_t* addressLength);

/*! Prototype of the callback function invoked when querying address info asynchronously (pal_getAddressInfoAsync).
* @param[in] url The user provided url (or IP address string) that was requested to be translated
* @param[in] address The address for the output of the translation
* @param[in] addressLength The length of the address for the output of the translation in bytes
* @param[in] status The status of the operation - PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure
* @param[in] callbackArgument The user callback argument
*/
#ifndef PAL_DNS_API_V2
typedef void(*palGetAddressInfoAsyncCallback_t)(const char* url, palSocketAddress_t* address, palSocketLength_t* addressLength, palStatus_t status, void* callbackArgument);

/*! This function translates from a URL to `palSocketAddress_t` which can be used with PAL sockets. It supports both IP address as strings and URLs (using DNS lookup). \n
\note The function is a non-blocking function.
* @param[in] url The user provided url (or IP address string) to be translated
* @param[out] address The address for the output of the translation
* @param[out] addressLength The length of the address for the output of the translation in bytes
* @param[in] callback The user provided callback to be invoked once the function has completed
* @param[in] callbackArgument The user provided callback argument which will be passed back to the (user provided) callback function
*/
palStatus_t pal_getAddressInfoAsync(const char* url, palSocketAddress_t* address, palSocketLength_t* addressLength, palGetAddressInfoAsyncCallback_t callback, void* callbackArgument);
#else
typedef int32_t palDNSQuery_t; /*! PAL DNS query handle, may be used to cancel the asynchronous DNS query. */

/*! Prototype of the callback function invoked when querying address info asynchronously (pal_getAddressInfoAsync).
* @param[in] url The user provided url (or IP address string) that was requested to be translated
* @param[out] address The address for the output of the translation
* @param[out] status The status of the operation - PAL_SUCCESS (0) in case of success or a specific negative error code in case of failure
* @param[in] callbackArgument The user callback argument
*/
typedef void(*palGetAddressInfoAsyncCallback_t)(const char* url, palSocketAddress_t* address, palStatus_t status, void* callbackArgument);

/*! structure used by pal_getAddressInfoAsync
* @param[in] url The user provided url (or IP address string) that was requested to be translated
* @param[out] address The address for the output of the translation
* @param[in] callback address of palGetAddressInfoAsyncCallback_t.
* @param[in] callbackArgument The user callback argument of palGetAddressInfoAsyncCallback_t
* @param[out] queryHandle handler ID, which can be used for calcel request.
*/
typedef struct pal_asyncAddressInfo
{
    char* url;
    palSocketAddress_t* address;
    palGetAddressInfoAsyncCallback_t callback;
    void* callbackArgument;
    palDNSQuery_t *queryHandle;
} pal_asyncAddressInfo_t;

/*! This function translates from a URL to `palSocketAddress_t` which can be used with PAL sockets. It supports both IP address as strings and URLs (using DNS lookup). \n
\note The function is a non-blocking function.
* @param[in] url The user provided url (or IP address string) to be translated
* @param[out] address The address for the output of the translation
* @param[in] callback The user provided callback to be invoked once the function has completed
* @param[out] queryHandle DNS query handler. Caller must take of care allocation. If not used then use NULL.
*/
palStatus_t pal_getAddressInfoAsync(const char* url, 
                                     palSocketAddress_t* address, 
                                     palGetAddressInfoAsyncCallback_t callback, 
                                     void* callbackArgument, 
                                     palDNSQuery_t* queryHandle);

/*! This function is cancelation for pal_getAddressInfoAsync. 
* @param[in] queryHandle Id of ongoing DNS query.
*/
palStatus_t pal_cancelAddressInfoAsync(palDNSQuery_t queryHandle);
#endif  // #ifndef PAL_DNS_API_V2

#endif  // PAL_NET_DNS_SUPPORT

#ifdef __cplusplus
}
#endif
#endif //_PAL_SOCKET_H


