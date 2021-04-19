/* Copyright (c) 2021 Pelion IoT
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
 */

#include "pal.h"
#include "pal_plat_network.h"

#include "fd_work_poll.h"

#include <zephyr.h>
#include <zephyr/types.h>

#ifdef CONFIG_NET_SOCKETS_POSIX_NAMES
#include <net/socket.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <poll.h>
#endif
#include <unistd.h>

#if 1
#define TRACE_GROUP "PAL"

#define DEBUG_DEBUG PAL_LOG_DBG
#define DEBUG_ERROR PAL_LOG_ERR
#else
#include <logging/log.h>

#ifndef CONFIG_PELION_PAL_PLAT_NETWORK_LOG_LEVEL
#define CONFIG_PELION_PAL_PLAT_NETWORK_LOG_LEVEL 2 /* Warning */
#endif

LOG_MODULE_REGISTER(pal_plat_network, CONFIG_PELION_PAL_PLAT_NETWORK_LOG_LEVEL);

#define DEBUG_DEBUG LOG_DBG
#define DEBUG_ERROR LOG_ERR
#endif

#define PAL_SOCKET_FREE (-1)

typedef struct {
    int fd;
    struct pollfd pollin;
    struct pollfd pollout;
    fd_work_poll_t workin;
    fd_work_poll_t workout;
    palAsyncSocketCallback_t callback;
    void* callbackArgument;
} pal_socket_t;

static pal_socket_t pal_sockets[PAL_SOCKET_MAX] = { 0 };

/******************************************************************************/
/* Required */
/******************************************************************************/

static void pal_workin_callback(fd_work_poll_t* input)
{
    DEBUG_DEBUG("pal_workin_callback");

    /**
     * Get the encapsulating container which contains variables carried across
     * work queue invocations.
     */
    pal_socket_t* pointer = CONTAINER_OF(input, pal_socket_t, workin);

    /* invoke callback function with argument if one has been defined
     * and socket hasn't been closed in the mean time.
     */
    if ((pointer->fd != PAL_SOCKET_FREE) && (pointer->callback)) {
        pointer->callback(pointer->callbackArgument);
    }
}


static void pal_workout_callback(fd_work_poll_t* input)
{
    DEBUG_DEBUG("pal_workout_callback");

    /**
     * Get the encapsulating container which contains variables carried across
     * work queue invocations.
     */
    pal_socket_t* pointer = CONTAINER_OF(input, pal_socket_t, workout);

    /* invoke callback function with argument if one has been defined
     * and socket hasn't been closed in the mean time.
     */
    if ((pointer->fd != PAL_SOCKET_FREE) && (pointer->callback)) {
        pointer->callback(pointer->callbackArgument);
    }
}

palStatus_t pal_plat_socketsInit(void* context)
{
    DEBUG_DEBUG("pal_plat_socketsInit");

    /* initialize pre-allocated socket structure */
    for (size_t index = 0; index < PAL_SOCKET_MAX; index++) {

        pal_sockets[index].fd = PAL_SOCKET_FREE;

        pal_sockets[index].pollin.events = POLLIN;
        pal_sockets[index].pollout.events = POLLOUT;

        fd_work_poll_init(&pal_sockets[index].workin, pal_workin_callback);
        fd_work_poll_init(&pal_sockets[index].workout, pal_workout_callback);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument , palSocket_t* handle)
{
    DEBUG_DEBUG("pal_plat_asynchronousSocket");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle) {

        result = PAL_ERR_SOCKET_ALLOCATION_FAILED;

        /* switch from PAL types to Zephyr types */
        switch (domain) {
            case PAL_AF_INET:
                domain = AF_INET;
                break;
            case PAL_AF_INET6:
                domain = AF_INET6;
                break;
            default:
                domain = AF_UNSPEC;
                break;
        }

        int proto = 0;
        switch (type) {
            case PAL_SOCK_DGRAM:
                type = SOCK_DGRAM;
                proto = IPPROTO_UDP;
                break;
            case PAL_SOCK_STREAM:
            case PAL_SOCK_STREAM_SERVER:
                type = SOCK_STREAM;
                proto = IPPROTO_TCP;
                break;
            default:
                /* should not happen */
                assert(false);
                break;
        }

        /* find valid index in pre-allocated socket structs */
        int current = PAL_SOCKET_FREE;

        for (size_t index = 0; index < PAL_SOCKET_MAX; index++) {
            if (pal_sockets[index].fd == PAL_SOCKET_FREE) {
                current = index;
                break;
            }
        }

        DEBUG_DEBUG("current: %d", current);

        if (current != PAL_SOCKET_FREE) {

            /* create socket */
            int fd = socket(domain, type, proto);

            DEBUG_DEBUG("socket: %d", fd);

            if (fd != -1) {

                /* set flags */
                if (nonBlockingSocket) {

                    int flags = fcntl(fd, F_GETFL, 0);
                    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                }

                /* store arguments in internal data structure */
                pal_socket_t* pointer = &pal_sockets[current];

                pointer->fd = fd;
                pointer->pollin.fd = fd;
                pointer->pollout.fd = fd;
                pointer->callback = callback;
                pointer->callbackArgument = callbackArgument;

                /* use pointer to structure as PAL socket handle */
                *handle = (palSocket_t) pointer;

                result = PAL_SUCCESS;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_connect(palSocket_t handle, const palSocketAddress_t* palAddress, palSocketLength_t addressLen)
{
    DEBUG_DEBUG("pal_plat_connect");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (palAddress) {

        /* convert PAL address to Zephyr address */
#if PAL_SUPPORT_IP_V4
        struct sockaddr_in address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr_in);

        address.sin_family = AF_INET;
        pal_getSockAddrPort(palAddress, &address.sin_port);
        pal_getSockAddrIPV4Addr(palAddress, address.sin_addr.s4_addr);

        /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
        address.sin_port = htons(address.sin_port);
#else
        struct sockaddr_in6 address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr_in6);

        address.sin6_family = AF_INET6;
        pal_getSockAddrPort(palAddress, &address.sin6_port);
        pal_getSockAddrIPV6Addr(palAddress, address.sin6_addr.s6_addr);

        /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
        address.sin6_port = htons(address.sin6_port);
#endif

        /* get filedescriptor from PAL socket handle */
        pal_socket_t* pointer = (pal_socket_t*) handle;

        /* connect to remote server, this call appears to be syncrhonous on Zephyr? */
        int retval = connect(pointer->fd, (struct sockaddr*) &address, addrlen);

        if(retval == 0) {

            /* provide callback for when data can be read */
            fd_work_poll_submit(&pointer->workin, &pointer->pollin, 1, K_FOREVER);

            result = PAL_SUCCESS;

        } else {

            /* only error codes used by PDMC*/
            switch (errno) {

                case EINPROGRESS:
                    /* As per man connect says, poll for writability for non-blocking socket */
                    fd_work_poll_submit(&pointer->workout, &pointer->pollout, 1, K_FOREVER);
                    result = PAL_ERR_SOCKET_IN_PROGRES;
                    break;

                case EWOULDBLOCK:
                    result = PAL_ERR_SOCKET_WOULD_BLOCK;
                    break;

                case EISCONN:
                case EALREADY:
                    result = PAL_ERR_SOCKET_ALREADY_CONNECTED;
                    break;

                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t handle, bool* isNonBlocking)
{
    DEBUG_DEBUG("pal_plat_isNonBlocking");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle && isNonBlocking) {

        /* get PAL socket data structure */
        pal_socket_t* pointer = (pal_socket_t*) handle;

        /* get the socket's configuration flags */
        int flags = fcntl(pointer->fd, F_GETFL, 0);

        if (flags & O_NONBLOCK) {
            *isNonBlocking = true;
        } else {
            *isNonBlocking = false;
        }

        result = PAL_SUCCESS;
    }

    return result;
}

palStatus_t pal_plat_send(palSocket_t handle, const void* buf, size_t len, size_t* sentDataSize)
{
    DEBUG_DEBUG("pal_plat_send");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle && buf && sentDataSize) {

        /* get PAL socket data structure */
        pal_socket_t* pointer = (pal_socket_t*) handle;

        /* send data */
        ssize_t retval = send(pointer->fd, buf, len, 0);

        /* check return value */
        if (retval != -1) {

            /* provide callback for when more data can be sent */
            fd_work_poll_submit(&pointer->workout, &pointer->pollout, 1, K_FOREVER);

            /* successful send, report number of bytes sent and set return status */
            *sentDataSize = retval;
            result = PAL_SUCCESS;

        } else {

            /* data not sent, set return status, note caller only looks for
             * ENOBUFS, ENOMEM, and EWOULDBLOCK.
             */
            switch (errno) {
                case ENOBUFS:
                case ENOMEM:
                    result = PAL_ERR_NO_MEMORY;
                    break;

                case EWOULDBLOCK:

                    /* provide callback for when more data can be sent */
                    fd_work_poll_submit(&pointer->workout, &pointer->pollout, 1, K_FOREVER);

                    result = PAL_ERR_SOCKET_WOULD_BLOCK;
                    break;

                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_recv(palSocket_t handle, void* buf, size_t len, size_t* recievedDataSize)
{
    DEBUG_DEBUG("pal_plat_recv");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle && buf && recievedDataSize) {

        /* get PAL socket data structure */
        pal_socket_t* pointer = (pal_socket_t*) handle;

        /* read data from network stack */
        ssize_t retval = recv(pointer->fd, buf, len, 0);

        /* positive return value indicate number of bytes received */
        if (retval > 0) {

            /* invoke callback when more data is available to read */
            fd_work_poll_submit(&pointer->workin, &pointer->pollin, 1, K_FOREVER);

            /* successful receive, set number of bytes received and return value */
            *recievedDataSize = retval;
            result = PAL_SUCCESS;

        /* for stream connections, zero means end-of-file and the connection has been closed */
        } else if (retval == 0) {

            result = PAL_ERR_SOCKET_CONNECTION_CLOSED;

        /* negative return value indicates an error */
        } else {

            /* note caller only uses EWOULDBLOCK */
            switch (errno) {
                case EWOULDBLOCK:

                    /* invoke callback when more data is available to read */
                    fd_work_poll_submit(&pointer->workin, &pointer->pollin, 1, K_FOREVER);

                    result = PAL_ERR_SOCKET_WOULD_BLOCK;
                    break;

                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_bind(palSocket_t handle, palSocketAddress_t* palAddress, palSocketLength_t addressLength)
{
    DEBUG_DEBUG("pal_plat_bind");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle && palAddress) {

        /* convert PAL address to Zephyr address */
#if PAL_SUPPORT_IP_V4
        struct sockaddr_in address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr_in);

        address.sin_family = AF_INET;
        pal_getSockAddrPort(palAddress, &address.sin_port);
        pal_getSockAddrIPV4Addr(palAddress, address.sin_addr.s4_addr);

        /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
        address.sin_port = htons(address.sin_port);
#else
        struct sockaddr_in6 address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr_in6);

        address.sin6_family = AF_INET6;
        pal_getSockAddrPort(palAddress, &address.sin6_port);
        pal_getSockAddrIPV6Addr(palAddress, address.sin6_addr.s6_addr);

        /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
        address.sin6_port = htons(address.sin6_port);
#endif

        /* get PAL socket data structure */
        pal_socket_t* pointer = (pal_socket_t*) handle;

        int retval = bind(pointer->fd, (struct sockaddr*) &address, addrlen);

        if (retval == 0) {

            /* provide callback for when data can be read */
            fd_work_poll_submit(&pointer->workin, &pointer->pollin, 1, K_FOREVER);

            result = PAL_SUCCESS;

        } else {

            /* return value not used by caller, return generic error */
            switch (errno) {
                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_sendTo(palSocket_t handle, const void* buffer, size_t length, const palSocketAddress_t* palAddress, palSocketLength_t toLength, size_t* bytesSent)
{
    DEBUG_DEBUG("pal_plat_sendTo");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle && buffer && palAddress && bytesSent) {

        /* convert PAL address to Zephyr address */
#if PAL_SUPPORT_IP_V4
        struct sockaddr_in address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr_in);

        address.sin_family = AF_INET;
        pal_getSockAddrPort(palAddress, &address.sin_port);
        pal_getSockAddrIPV4Addr(palAddress, address.sin_addr.s4_addr);

        /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
        address.sin_port = htons(address.sin_port);
#else
        struct sockaddr_in6 address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr_in6);

        address.sin6_family = AF_INET6;
        pal_getSockAddrPort(palAddress, &address.sin6_port);
        pal_getSockAddrIPV6Addr(palAddress, address.sin6_addr.s6_addr);

        /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
        address.sin6_port = htons(address.sin6_port);
#endif

        pal_socket_t* pointer = (pal_socket_t*) handle;

        ssize_t retval = sendto(pointer->fd, buffer, length, 0, (struct sockaddr*) &address, addrlen);

        if (retval != -1) {

            /* provide callback for when more data can be sent */
            fd_work_poll_submit(&pointer->workout, &pointer->pollout, 1, K_FOREVER);

            /* successful send, report number of bytes sent and set return status */
            *bytesSent = retval;
            result = PAL_SUCCESS;

        } else {

            /* data not sent, set return status, note caller only looks for
             * ENOBUFS, ENOMEM, and EWOULDBLOCK.
             */
            switch (errno) {
                case ENOBUFS:
                case ENOMEM:
                    result = PAL_ERR_NO_MEMORY;
                    break;

                case EWOULDBLOCK:

                    /* provide callback for when more data can be sent */
                    fd_work_poll_submit(&pointer->workout, &pointer->pollout, 1, K_FOREVER);

                    result = PAL_ERR_SOCKET_WOULD_BLOCK;
                    break;

                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_receiveFrom(palSocket_t handle, void* buffer, size_t length, palSocketAddress_t* palAddress, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    DEBUG_DEBUG("pal_plat_receiveFrom");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle && buffer && palAddress && fromLength && bytesReceived) {

        struct sockaddr address = { 0 };
        socklen_t addrlen = sizeof(struct sockaddr);

        pal_socket_t* pointer = (pal_socket_t*) handle;

        ssize_t retval = recvfrom(pointer->fd, buffer, length, 0, &address, &addrlen);

        if (retval != -1) {

            /* convert Zephyr address to PAL address */

#if PAL_SUPPORT_IP_V4
            /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
            net_sin(&address)->sin_port = htons(net_sin(&address)->sin_port);

            pal_setSockAddrPort(palAddress, net_sin(&address)->sin_port);
            pal_setSockAddrIPV4Addr(palAddress, net_sin(&address)->sin_addr.s4_addr);

#else
            /* FIXME: pal_getSockAddrPort is returning wrong endian, use htons workaround */
            net_sin6(&address)->sin6_port = htons(net_sin6(&address)->sin6_port);

            pal_setSockAddrPort(palAddress, net_sin6(&address)->sin6_port);
            pal_setSockAddrIPV6Addr(palAddress, net_sin6(&address)->sin6_addr.s6_addr);
#endif

            /* invoke callback when more data is available to read */
            fd_work_poll_submit(&pointer->workin, &pointer->pollin, 1, K_FOREVER);

            /* successful receive, report number of bytes and set return status */
            *bytesReceived = retval;
            result = PAL_SUCCESS;

        } else {

            /* note caller only uses EWOULDBLOCK */
            switch (errno) {
                case EWOULDBLOCK:

                    /* invoke callback when more data is available to read */
                    fd_work_poll_submit(&pointer->workin, &pointer->pollin, 1, K_FOREVER);

                    result = PAL_ERR_SOCKET_WOULD_BLOCK;
                    break;

                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_close(palSocket_t* handle)
{
    DEBUG_DEBUG("pal_plat_close");

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (handle) {

        /* get PAL socket data structure */
        pal_socket_t* pointer = (pal_socket_t*) *handle;

        /* mark internal socket structure as free before closing socket to
         * suppress any late callbacks.
         */
        int fd = pointer->fd;
        pointer->fd = PAL_SOCKET_FREE;

        /* cancel any pending work */
        fd_work_poll_cancel(&pointer->workin);
        fd_work_poll_cancel(&pointer->workout);

        /* close socket using local file descriptor copy */
        int retval = close(fd);

        DEBUG_DEBUG("close socket: %d %d", fd, retval);

        /* negative return value indicates error */
        if (retval == 0) {

            result = PAL_SUCCESS;
        } else {

            /* caller doesn't look at return value, return generic error */
            switch (errno) {
                default:
                    result = PAL_ERR_SOCKET_GENERIC;
                    break;
            }
        }
    }

    return result;
}

palStatus_t pal_plat_getAddressInfo(const char* hostname, palSocketAddress_t* address, palSocketLength_t* addressLength)
{
    DEBUG_DEBUG("pal_plat_getAddressInfo");

    // addressLength not used in caller function

    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    if (hostname && address && addressLength) {

        struct addrinfo *info = NULL;
        struct addrinfo hints = { 0 };

#if (PAL_SUPPORT_IP_V4 || PAL_SUPPORT_NAT64)
        hints.ai_family = AF_INET;
#else // PAL_SUPPORT_IP_V6
        hints.ai_family = AF_INET6;
#endif

        /* use synchronous DNS lookup */
        int retval = getaddrinfo(hostname, NULL, &hints, &info);

        if (retval == 0) {

            /* convert Zephyr address to PAL address */
            if (info->ai_family == AF_INET) {

#if !PAL_SUPPORT_IP_V4 && PAL_SUPPORT_NAT64
                /* got IPv4 address on IPv6 network, convert to NAT64 address */
                result = pal_setSockAddrNAT64Addr(address, net_sin(info->ai_addr)->sin_addr.s4_addr);
#else
                result = pal_setSockAddrIPV4Addr(address, net_sin(info->ai_addr)->sin_addr.s4_addr);
#endif
            } else if (info->ai_family == AF_INET6) {

                result = pal_setSockAddrIPV6Addr(address, net_sin6(info->ai_addr)->sin6_addr.s6_addr);

            } else {
                DEBUG_ERROR("Invalid IP address family %d", info->ai_family);
                assert(0);
            }

        } else {

            result = PAL_ERR_SOCKET_DNS_ERROR;
        }
    }

    return result;
}

/******************************************************************************/
/* Feature dependant */

// for blocking sockets
palStatus_t pal_plat_setSocketOptions(palSocket_t handle, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    DEBUG_DEBUG("pal_plat_setSocketOptions");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}


// for pause/resume low power feature
palStatus_t pal_plat_registerNetworkInterface(void* networkInterfaceContext, uint32_t* interfaceIndex)
{
    DEBUG_DEBUG("pal_plat_registerNetworkInterface");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}

palStatus_t pal_plat_unregisterNetworkInterface(uint32_t interfaceIndex)
{
    DEBUG_DEBUG("pal_plat_unregisterNetworkInterface");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}

// for cleanup
palStatus_t pal_plat_socketsTerminate(void* context)
{
    DEBUG_DEBUG("pal_plat_socketsTerminate");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}


// for factory provisioning over network and mesh update
palStatus_t pal_plat_listen(palSocket_t handle, int backlog)
{
    DEBUG_DEBUG("pal_plat_listen");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}

palStatus_t pal_plat_accept(palSocket_t handle, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    DEBUG_DEBUG("pal_plat_accept");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}


// for mesh update
palStatus_t pal_plat_setSocketOptionsWithLevel(palSocket_t handle, palSocketOptionLevelName_t optionLevel, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    DEBUG_DEBUG("pal_plat_setSocketOptionsWithLevel");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}

uint8_t pal_plat_getRttEstimate()
{
    DEBUG_DEBUG("pal_plat_getRttEstimate");

    return PAL_DEFAULT_RTT_ESTIMATE;
}

uint16_t pal_plat_getStaggerEstimate(uint16_t data_amount)
{
    DEBUG_DEBUG("pal_plat_getStaggerEstimate");

    return PAL_DEFAULT_STAGGER_ESTIMATE;
}


/******************************************************************************/
/* Unused */

palStatus_t pal_plat_getNumberOfNetInterfaces(uint32_t* numInterfaces)
{
    DEBUG_DEBUG("pal_plat_getNumberOfNetInterfaces");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t* interfaceInfo)
{
    DEBUG_DEBUG("pal_plat_getNetInterfaceInfo");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *client_arg)
{
    DEBUG_DEBUG("pal_plat_setConnectionStatusCallback");

    return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
}
