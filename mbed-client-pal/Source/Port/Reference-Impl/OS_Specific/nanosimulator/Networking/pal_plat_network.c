/*******************************************************************************
 * Copyright 2020 ARM Ltd.
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

#include <stdbool.h>

#ifdef __linux__
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "ip6string.h"
#include "ns_address.h"
#include "pal.h"
#include "pal_plat_network.h"
#include "socket_api.h"
#include "net_interface.h"

#define TRACE_GROUP "PAL"
#define NUMBER_OF_SOCKETS 4

static struct {
    palAsyncSocketCallback_t callback;
    void *callbackArgument;
    int8_t socket_id;
    bool inUse;
    uint8_t *payload;
    int16_t payload_len;
    ns_address_t address;
} sock_control[NUMBER_OF_SOCKETS];


static int8_t get_socket_handle(const palSocket_t* socket, int8_t* index)
{
    for (int i = 0; i < NUMBER_OF_SOCKETS; i++) {
        if (sock_control[i].socket_id == (intptr_t)socket) {
            *index = i;
            return sock_control[i].socket_id;
        }
    }

    PAL_LOG_ERR("Socket handle not found!");

    return -1;
}

void socket_callback(void *raw_param)
{
    const socket_callback_t *cb_event = (const socket_callback_t*)raw_param;
    if (cb_event != NULL && cb_event->event_type == SOCKET_DATA) {
        int8_t index;
        int8_t socket_handle = get_socket_handle((const palSocket_t*)cb_event->socket_id, &index);
        if (socket_handle == -1) {
            PAL_LOG_ERR("socket_callback - socket id not found!");
        } else {
            static ns_address_t addr;
            free(sock_control[index].payload);
            sock_control[index].payload_len = 0;

            if (cb_event->d_len > 0) {
                sock_control[index].payload = malloc(cb_event->d_len);
                if (sock_control[index].payload) {
                    if (cb_event->d_len == socket_read(cb_event->socket_id, &addr, sock_control[index].payload, cb_event->d_len)) {
                        sock_control[index].payload_len = cb_event->d_len;
                        sock_control[index].address.identifier = addr.identifier;
                        sock_control[index].address.type = addr.type;
                        memcpy(sock_control[index].address.address, addr.address, 16);
                    }

                    if (sock_control[index].callback) {
                        sock_control[index].callback(sock_control[index].callbackArgument);
                    } else {
                        PAL_LOG_ERR("socket_callback - callback not set!");
                    }
                }
            }
        }
    }
}

static int8_t address_nanostack2pal(const ns_address_t *ns_addr, palSocketAddress_t *pal_addr)
{

    palIpV6Addr_t addr;
    memcpy(addr, ns_addr->address, 16);
    if (pal_setSockAddrIPV6Addr(pal_addr, addr) != PAL_SUCCESS) {
        return 0;
    }

    if (pal_setSockAddrPort(pal_addr, ns_addr->identifier) != PAL_SUCCESS) {
        return 0;
    }

    return sizeof(addr);
}

static int8_t address_pal2nanostack(const palSocketAddress_t *pal_addr, ns_address_t *ns_addr)
{
    uint16_t port;

    if (pal_getSockAddrPort (pal_addr, &port) != PAL_SUCCESS) {
        return 0;
    }

    if (pal_addr->addressType == PAL_AF_INET6) {
        palIpV6Addr_t addr;
        if (pal_getSockAddrIPV6Addr(pal_addr, addr) == PAL_SUCCESS) {
            ns_addr->type = ADDRESS_IPV6;
            ns_addr->identifier = port;
            memcpy(ns_addr->address, &addr, sizeof(addr));
            return (sizeof (addr));
        } else {
            return 0;
        }
    }

    return 0;
}

palStatus_t pal_plat_socketsInit(void* context)
{
    (void)context;

    memset(sock_control, 0, sizeof(sock_control));

    return PAL_SUCCESS;
}

palStatus_t pal_plat_registerNetworkInterface(void* context, uint32_t* interfaceIndex)
{
    (void)context;
    (void)interfaceIndex;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_unregisterNetworkInterface(uint32_t interfaceIndex)
{
    (void)interfaceIndex;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_socketsTerminate(void* context)
{
    (void)context;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* socket)
{
    (void)interfaceNum;
    (void)type;
    (void)nonBlockingSocket;
    (void)interfaceNum;
    (void)socket;

    PAL_LOG_ERR("Not supported. Use pal_plat_asynchronousSocket directly!");

    return PAL_ERR_NOT_SUPPORTED;
}

palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    return pal_plat_setSocketOptionsWithLevel(socket, PAL_SOL_IPPROTO_IPV6, optionName, optionValue, optionLength);
}

palStatus_t pal_plat_setSocketOptionsWithLevel(palSocket_t socket, palSocketOptionLevelName_t optionLevel, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    int8_t index;
    int8_t socket_handle = get_socket_handle(socket, &index);

    if (socket_handle == -1) {
        PAL_LOG_ERR("pal_plat_setSocketOptionsWithLevel - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    int level;
    if (optionLevel == PAL_SOL_SOCKET) {
        level = SOCKET_SOL_SOCKET;
    } else if (optionLevel == PAL_SOL_IPPROTO_IPV6) {
        level = SOCKET_IPPROTO_IPV6;
    } else {
        return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    }

    if (PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED != level) {
        int optionVal;
        if (optionName == PAL_SO_IPV6_MULTICAST_HOPS) {
            optionVal = SOCKET_IPV6_MULTICAST_HOPS;
        } else {
            return PAL_ERR_SOCKET_GENERIC;
        }

        int8_t res = socket_setsockopt(socket, level, optionVal, optionValue, optionLength);
        if (res < 0) {
            PAL_LOG_ERR("pal_plat_setSocketOptionsWithLevel - socket_setsockopt fails: %d", res);
            return PAL_ERR_SOCKET_GENERIC;
        }
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    *isNonBlocking = true;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
    if (myAddress == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    ns_address_t local_addr;

    if (address_pal2nanostack(myAddress, &local_addr) == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    int8_t index;
    int8_t socket_handle = get_socket_handle(socket, &index);

    if (socket_handle == -1) {
        PAL_LOG_ERR("pal_plat_bind - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    int8_t res = socket_bind(socket_handle, &local_addr);
    if (res < 0) {
        PAL_LOG_ERR("pal_plat_bind - socket_bind fails: %d", res);
        return PAL_ERR_SOCKET_GENERIC;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    if ((bytesReceived == NULL) || (from == NULL) || (fromLength == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    int8_t index;
    int8_t socket_handle = get_socket_handle(socket, &index);

    if (socket_handle == -1) {
        PAL_LOG_ERR("pal_plat_receiveFrom - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    *bytesReceived = sock_control[index].payload_len;
    if (sock_control[index].payload_len > 0) {
        memcpy(buffer, sock_control[index].payload, sock_control[index].payload_len);
        *fromLength = address_nanostack2pal(&sock_control[index].address, from);
        if (*fromLength == 0) {
            PAL_LOG_ERR("pal_plat_receiveFrom - failed to store address!");
            return PAL_ERR_SOCKET_GENERIC;
        }
        free(sock_control[index].payload);
        sock_control[index].payload = NULL;
        sock_control[index].payload_len = 0;
        return PAL_SUCCESS;
    } else {
        return PAL_ERR_SOCKET_WOULD_BLOCK;
    }
}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
    if ((bytesSent == NULL) || (to == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    int8_t index;
    int8_t socket_handle = get_socket_handle(socket, &index);

    if (socket_handle == -1) {
        PAL_LOG_ERR("pal_plat_sendTo - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    ns_address_t ns_addr;
    if (address_pal2nanostack(to, &ns_addr) == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    int16_t ret = socket_sendto(socket_handle, &ns_addr, (void*)buffer, length);

    if (ret < 0) {
        PAL_LOG_ERR("pal_plat_sendTo - socket_sendto failed: %d", ret);
        return PAL_ERR_SOCKET_GENERIC;
    }

    *bytesSent = length;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    int8_t index;
    int8_t socket_index = get_socket_handle(*socket, &index);

    if (socket_index == -1) {
        PAL_LOG_ERR("pal_plat_close - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    int8_t res = socket_close(socket_index);

    sock_control[index].inUse = false;
    sock_control[index].socket_id = -1;
    sock_control[index].callback = NULL;
    sock_control[index].callbackArgument = NULL;

    free(sock_control[index].payload);
    sock_control[index].payload = NULL;
    sock_control[index].payload_len = 0;

    if (res < 0) {
        PAL_LOG_ERR("pal_plat_close - failed to close socket: %d", res);
        return PAL_ERR_SOCKET_GENERIC;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNumberOfNetInterfaces(uint32_t* numInterfaces)
{
    if (numInterfaces == NULL) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    *numInterfaces = 1;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t * interfaceInfo)
{
    (void)interfaceNum;
    (void)interfaceInfo;

    return PAL_SUCCESS;
}

#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.

palStatus_t pal_plat_listen(palSocket_t socket, int backlog)
{
    int8_t index;
    int8_t socket_index = get_socket_handle(socket, &index);

    if (socket_index == -1) {
        PAL_LOG_ERR("pal_plat_listen - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    if (socket_listen(socket_index, backlog) < 0) {
        PAL_LOG_ERR("pal_plat_listen - socket_listen failed!");
        return PAL_ERR_SOCKET_GENERIC;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    if (acceptedSocket == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    int8_t index;
    int8_t socket_index = get_socket_handle(socket, &index);

    if (socket_index == -1) {
        PAL_LOG_ERR("pal_plat_accept - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    ns_address_t addr;

    int8_t ret = socket_accept(socket_index, &addr, callback);
    if (ret >= 0) {
        *acceptedSocket = (palSocket_t)ret;
        *addressLen = address_nanostack2pal(&addr, address);
    } else {
        PAL_LOG_ERR("pal_plat_accept - socket_accept failed: %d", ret);
        return PAL_ERR_SOCKET_GENERIC;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    if (address == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    int8_t index;
    int8_t socket_index = get_socket_handle(socket, &index);

    if (socket_index == -1) {
        PAL_LOG_ERR("pal_plat_connect - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    ns_address_t ns_addr;
    if (address_pal2nanostack(address, &ns_addr) == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    int8_t ret = socket_connect(socket_index, &ns_addr, 0);

    if (ret == 0) {
        return PAL_SUCCESS;
    } else if (ret == -1) {
        return PAL_ERR_SOCKET_INVALID_VALUE;
    } else if (ret == -2) {
        return PAL_ERR_SOCKET_ALLOCATION_FAILED;
    }  else if (ret == -4) {
        return PAL_ERR_SOCKET_ALREADY_CONNECTED;
    } else if (ret == -5) {
        return PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED;
    } else {
        return  PAL_ERR_SOCKET_GENERIC;
    }
}

palStatus_t pal_plat_recv(palSocket_t socket, void *buffer, size_t len, size_t* receivedDataSize)
{
    if (receivedDataSize == NULL) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    int8_t index;
    int8_t socket_handle = get_socket_handle(socket, &index);

    if (socket_handle == -1) {
        PAL_LOG_ERR("pal_plat_recv - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    ns_address_t source_addr;
    int16_t res = socket_read(socket_handle, &source_addr, buffer, len);

    if (res > 0) {
        *receivedDataSize = res;
    } else if (res == 0) {
        return PAL_ERR_SOCKET_WOULD_BLOCK;
    } else {
        PAL_LOG_ERR("pal_plat_receiveFrom - socket_read fails: %d", res);
        return PAL_ERR_SOCKET_GENERIC;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t *sentDataSize)
{
    if (sentDataSize == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    int8_t index;
    int8_t socket_handle = get_socket_handle(socket, &index);

    if (socket_handle == -1) {
        PAL_LOG_ERR("pal_plat_send - socket id not found!");
        return PAL_ERR_ITEM_NOT_EXIST;
    }

    int16_t ret = socket_send(socket_handle, (void*)buf, len);

    PAL_LOG_DBG("pal_plat_send - socket_send return %d", ret);

    if (ret == 0) {
        *sentDataSize = len;
        return PAL_SUCCESS;
    } else if (ret == -1) {
        return PAL_ERR_SOCKET_INVALID_VALUE;
    } else if (ret == -2) {
        return PAL_ERR_SOCKET_ALLOCATION_FAILED;
    } else if (ret == -5) {
        return PAL_ERR_SOCKET_NOT_CONNECTED;
    } else {
        return PAL_ERR_SOCKET_GENERIC;
    }
}

#endif //PAL_NET_TCP_AND_TLS_SUPPORT

palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain,
                                        palSocketType_t type,
                                        bool nonBlockingSocket,
                                        uint32_t interfaceNum,
                                        palAsyncSocketCallback_t callback,
                                        void* callbackArgument,
                                        palSocket_t* socket)
{
    uint8_t protocol;
    int8_t socket_id;

    if (socket == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    if (domain != PAL_AF_INET6) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    switch (type) {
        case PAL_SOCK_STREAM:
        case PAL_SOCK_STREAM_SERVER:
            protocol = SOCKET_TCP;
            break;

        case PAL_SOCK_DGRAM:
            protocol = SOCKET_UDP;
            break;

        default:
            return PAL_ERR_INVALID_ARGUMENT;
    }

    // TODO! Interface num used for setting the port number! Need to check why binding didn't work
    socket_id = socket_open(protocol, interfaceNum, socket_callback);

    bool socket_created = false;
    if (socket_id) {
        for (int i = 0; i < NUMBER_OF_SOCKETS; i++) {
            if (!sock_control[i].inUse) {
                sock_control[i].socket_id = socket_id;
                sock_control[i].callbackArgument = callbackArgument;
                sock_control[i].callback = callback;
                sock_control[i].inUse = true;
                socket_created = true;
                break;
            }
        }

        if (!socket_created) {
            PAL_LOG_ERR("pal_plat_asynchronousSocket - socket limit reached!");
            return PAL_ERR_NO_MEMORY;
        }

    } else {
        PAL_LOG_ERR("pal_plat_asynchronousSocket - socket_open fail: %d", socket_id);
        return PAL_ERR_SOCKET_GENERIC;
    }

    *socket = (palSocket_t)socket_id;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *arg)
{
    (void)interfaceIndex;
    (void)callback;
    (void)arg;

    return PAL_ERR_NOT_SUPPORTED;
}

#ifdef __linux__
PAL_PRIVATE palStatus_t translateErrorToPALError(int errnoValue)
{
    palStatus_t status;
    switch (errnoValue)
    {
    case EAI_MEMORY:
        status = PAL_ERR_NO_MEMORY;
        break;
    case EWOULDBLOCK:
        status = PAL_ERR_SOCKET_WOULD_BLOCK;
        break;
    case ENOTSOCK:
        status = PAL_ERR_SOCKET_INVALID_VALUE;
        break;
    case EPERM:
    case EACCES:
        status = PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED;
        break;
    case ETIMEDOUT:
        status = PAL_ERR_TIMEOUT_EXPIRED;
        break;
    case EISCONN:
        status = PAL_ERR_SOCKET_ALREADY_CONNECTED;
        break;
    case EAI_FAMILY:
        status = PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
        break;
    case EINPROGRESS:
        status = PAL_ERR_SOCKET_IN_PROGRES;
        break;
    case EALREADY:
        status = PAL_ERR_SOCKET_ALREADY_CONNECTED;
        break;
    case EINVAL:
        status = PAL_ERR_SOCKET_INVALID_VALUE;
        break;
    case EADDRINUSE:
        status = PAL_ERR_SOCKET_ADDRESS_IN_USE;
        break;
    case ECONNABORTED:
        status = PAL_ERR_SOCKET_CONNECTION_ABORTED;
        break;
    case ECONNRESET:
    case ECONNREFUSED:
        status = PAL_ERR_SOCKET_CONNECTION_RESET;
        break;
    case ENOBUFS:
    case ENOMEM:
        status = PAL_ERR_SOCKET_NO_BUFFERS;
        break;
    case EINTR:
        status = PAL_ERR_SOCKET_INTERRUPTED;
        break;
    case EAI_AGAIN:
    case EAI_NONAME:
        status = PAL_ERR_SOCKET_DNS_ERROR;
        break;
    default:
        PAL_LOG_ERR("translateErrorToPALError() cannot translate %d", errnoValue);
        status = PAL_ERR_SOCKET_GENERIC;
        break;
    }
    return status;
}
#endif // __linux__

#if PAL_NET_DNS_SUPPORT

palStatus_t pal_plat_getAddressInfo(const char *url, palSocketAddress_t *address, palSocketLength_t* length)
{
    if ((url == NULL) || (address == NULL) || (length == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

#ifdef __linux__
    palStatus_t result = PAL_SUCCESS;
    char ip_addr[INET6_ADDRSTRLEN];

    struct addrinfo *addr_result;
    struct addrinfo hints;

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_INET6;
    int res = getaddrinfo(url, NULL, &hints, &addr_result);
    if(res < 0) {
        // getaddrinfo returns EAI-error. In case of EAI_SYSTEM, the error
        // is 'Other system error, check errno for details'
        // (http://man7.org/linux/man-pages/man3/getaddrinfo.3.html#RETURN_VALUE)
        if (res == EAI_SYSTEM) {
            result = translateErrorToPALError(errno);
        } else  {
            // errno values are positive, getaddrinfo errors are negative so they can be mapped
            // in the same place.
            result = translateErrorToPALError(res);
        }
    } else {
        if (addr_result != NULL) {
            int error = getnameinfo((struct sockaddr*)addr_result->ai_addr, addr_result->ai_addrlen, ip_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (error == 0) {
                ns_address_t ns_address;
                int8_t ns_addr_len = strlen(ip_addr);
                stoip6(ip_addr, ns_addr_len, &ns_address.address);

                ns_addr_len = address_nanostack2pal(&ns_address, address);
                if (ns_addr_len > 0) {
                    *length = ns_addr_len;
                } else {
                    result = PAL_ERR_INVALID_ARGUMENT;
                }
            } else {
                result = translateErrorToPALError(error);
            }
        } else {
            result = PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
        }

        freeaddrinfo(addr_result);
    }

    return result;
#else

    int addr_len = strlen(url);

    if (addr_len == 0) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    ns_address_t ns_address;
    stoip6(url, addr_len, &ns_address.address);

    addr_len = address_nanostack2pal(&ns_address, address);
    if (addr_len > 0) {
        *length = addr_len;
        return PAL_SUCCESS;
    } else {
        return PAL_ERR_INVALID_ARGUMENT;
    }

#endif // __linux__
}

#endif // PAL_NET_DNS_SUPPORT

uint8_t pal_plat_getRttEstimate()
{
    return PAL_DEFAULT_RTT_ESTIMATE;
}

uint16_t pal_plat_getStaggerEstimate(uint16_t data_amount)
{
    (void) data_amount;
    return PAL_DEFAULT_STAGGER_ESTIMATE;
}

