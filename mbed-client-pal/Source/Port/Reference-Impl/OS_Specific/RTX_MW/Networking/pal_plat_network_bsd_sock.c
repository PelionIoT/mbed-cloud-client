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

#include "RTE_Components.h"

#ifdef RTE_Network_Socket_BSD

#include "pal.h"
#include "pal_plat_network.h"
#include "pal_rtos.h"

#include "rl_net.h"
#include "cmsis_os2.h"
#include "rtx_os.h"
#include "Net_Config_BSD.h"

#define TRACE_GROUP "PAL"

// BSD Events
#define BSD_EVT_CONNECT         0x01    // Socket Connected
#define BSD_EVT_CLOSE           0x02    // Socket Closed / Aborted
#define BSD_EVT_ACK             0x04    // Sending Data Acked
#define BSD_EVT_DATA            0x08    // Data Received
#define BSD_EVT_TIMEOUT         0x10    // Receive socket timeout
#define BSD_EVT_KILL            0x20    // Socket was killed locally
#define BSD_EVT_SEND            0x40    // Suspend Socket sending thread

#if defined (BSD_NUM_SOCKS) && (BSD_NUM_SOCKS < 3)
#error "Pelion Device Management Client requires at least 3 BSD sockets! Number of BSD sockets can be configured in Net_Config_BSD.h"
#endif

extern void net_bsd_notify(int32_t sock, uint8_t event);

static struct {
    bool nonBlocking;
    palAsyncSocketCallback_t callback;
    void *callbackArgument;
} sock_control[BSD_NUM_SOCKS];

static palStatus_t error_bsd2pal(int32_t bsd_error) {

    palStatus_t status;

    switch (bsd_error) {
        case BSD_ESOCK:
          status = PAL_ERR_SOCKET_INVALID_VALUE;
          break;
        case BSD_EINVAL:
          status = PAL_ERR_INVALID_ARGUMENT;
          break;
        case BSD_ENOTSUP:
          status = PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
          break;
        case BSD_ENOMEM:
          status = PAL_ERR_NO_MEMORY;
          break;
        case BSD_EWOULDBLOCK:
        case BSD_ETIMEDOUT:
          status = PAL_ERR_SOCKET_WOULD_BLOCK;
          break;
        case BSD_EINPROGRESS:
        case BSD_EALREADY:
          status = PAL_ERR_SOCKET_IN_PROGRES;
          break;
        case BSD_ENOTCONN:
          status = PAL_ERR_SOCKET_NOT_CONNECTED;
          break;
        case BSD_EISCONN:
          status = PAL_ERR_SOCKET_ALREADY_CONNECTED;
          break;
        case BSD_ECONNREFUSED:
        case BSD_ECONNRESET:
          status = PAL_ERR_SOCKET_CONNECTION_RESET;
          break;
        case BSD_ECONNABORTED:
          status = PAL_ERR_SOCKET_CONNECTION_ABORTED;
          break;
        case BSD_EADDRINUSE:
          status = PAL_ERR_SOCKET_ADDRESS_IN_USE;
          break;
        case BSD_EDESTADDRREQ:
          status = PAL_ERR_SOCKET_INVALID_ADDRESS;
          break;
        case BSD_EHOSTNOTFOUND:
          status = PAL_ERR_SOCKET_DNS_ERROR;
          break;

        default:
          status = PAL_ERR_SOCKET_GENERIC;
          break;
    }

    return (status);
}

static int32_t address_pal2bsd(const palSocketAddress_t *palAddr, SOCKADDR *bsdAddr) {
    uint16_t port;

    if (pal_getSockAddrPort (palAddr, &port) != PAL_SUCCESS) {
        return 0;
    }

    if (palAddr->addressType == PAL_AF_INET) {
        SOCKADDR_IN *addr4 = (SOCKADDR_IN *)bsdAddr;
        addr4->sin_family = AF_INET;
        addr4->sin_port   = htons (port);
        pal_getSockAddrIPV4Addr (palAddr, &addr4->sin_addr.s_b1);
        return sizeof (*addr4);
    }

#if defined(RTE_Network_IPv6)
    if (palAddr->addressType == PAL_AF_INET6) {
        SOCKADDR_IN6 *addr6 = (SOCKADDR_IN6 *)bsdAddr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port   = htons (port);
        addr6->sin6_flowinfo = 0;
        pal_getSockAddrIPV6Addr (palAddr, &addr6->sin6_addr.s6_b[0]);
        return sizeof (*addr6);
    }
#endif

  return (0);
}

static int32_t address_bsd2pal(const SOCKADDR *bsdAddr, palSocketAddress_t *palAddr) {

    uint16_t port;

    if (pal_getSockAddrPort (palAddr, &port) != PAL_SUCCESS) {
        return 0;
    }

    if (bsdAddr->sa_family == AF_INET) {
        SOCKADDR_IN *addr4 = (SOCKADDR_IN *)bsdAddr;
        palAddr->addressType = PAL_AF_INET;
        pal_setSockAddrPort (palAddr, htons (addr4->sin_port));
        pal_setSockAddrIPV4Addr (palAddr, &addr4->sin_addr.s_b1);
        return sizeof(*addr4);
    }

#if defined(RTE_Network_IPv6)
    if (bsdAddr->sa_family == AF_INET6) {
        SOCKADDR_IN6 *addr6 = (SOCKADDR_IN6 *)bsdAddr;
        palAddr->addressType = PAL_AF_INET6;
        pal_setSockAddrPort (palAddr, htons (addr6->sin6_port));
        pal_setSockAddrIPV6Addr (palAddr, &addr6->sin6_addr.s6_b[0]);
        return sizeof *addr6);
    }
#endif

    return 0;
}

palStatus_t pal_plat_socketsInit(void* context)
{
    (void)context;

    /* Verify that the Network Component is not already running */
    if (netSYS_GetHostName () == NULL) {
        if (netInitialize () != netOK) {
            return (PAL_ERR_NOT_INITIALIZED);
        }

        memset (sock_control, 0, sizeof(sock_control));
        /* Small delay for Network to setup */
        osDelay (500);
    }

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

palStatus_t pal_plat_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* sockt)
{
    int32_t sock,family,sock_type;
    (void)interfaceNum;

    if (sockt == NULL) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    switch (domain) {
        case PAL_AF_INET:
            family = AF_INET;
            break;
        case PAL_AF_INET6:
            family = AF_INET6;
            break;
        default:
            return PAL_ERR_INVALID_ARGUMENT;
    }

    switch (type) {
        case PAL_SOCK_STREAM:
        case PAL_SOCK_STREAM_SERVER:
            sock_type = SOCK_STREAM;
            break;

        case PAL_SOCK_DGRAM:
            sock_type = SOCK_DGRAM;
            break;

        default:
            return PAL_ERR_INVALID_ARGUMENT;
    }

    sock = socket (family, sock_type, 0);
    if (sock < 0) {
        if (sock == BSD_ENOMEM) {
            return PAL_ERR_SOCKET_ALLOCATION_FAILED;
        }

        return error_bsd2pal(sock);
    }

    if (sock >= BSD_NUM_SOCKS) {
        closesocket(sock);
        return PAL_ERR_SOCKET_ALLOCATION_FAILED;
    }

    sock_control[sock-1].nonBlocking = nonBlockingSocket;
    sock_control[sock-1].callback    = NULL;
    sock_control[sock-1].callbackArgument = 0;

    if (nonBlockingSocket) {
        unsigned long nb = 1;
        ioctlsocket(sock, FIONBIO, &nb);
    }

    *sockt = (palSocket_t)sock;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    int32_t res,optname;

    switch (optionName) {
        case PAL_SO_SNDTIMEO:
            optname = SO_SNDTIMEO;
            break;
        case PAL_SO_RCVTIMEO:
            optname = SO_RCVTIMEO;
            break;
        case PAL_SO_KEEPALIVE:
          optname = SO_KEEPALIVE;
          break;
        default:
          return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    }

    res = setsockopt((intptr_t)socket, SOL_SOCKET, optname, optionValue, optionLength);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    if (isNonBlocking == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    if ((intptr_t)socket >= BSD_NUM_SOCKS) {
        return PAL_ERR_SOCKET_INVALID_VALUE;
    }

    *isNonBlocking = sock_control[(intptr_t)socket-1].nonBlocking;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
#if defined(RTE_Network_IPv6)
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN6)];
#else
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN)];
#endif
    int32_t res,len;

    if (myAddress == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    len = address_pal2bsd (myAddress, (SOCKADDR *)&sockaddr_storage);

    if (len == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    res = bind ((intptr_t)socket, (SOCKADDR *)&sockaddr_storage, len);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}


palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
#if defined(RTE_Network_IPv6)
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN6)];
#else
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN)];
#endif
    int32_t res,len;

    if ((bytesReceived == NULL) || (from == NULL) || (fromLength == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    res = recvfrom ((intptr_t)socket, buffer, length, 0, (SOCKADDR *)&sockaddr_storage, &len);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    len = address_bsd2pal ((SOCKADDR *)&sockaddr_storage, from);

    *fromLength = len;
    *bytesReceived = res;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
#if defined(RTE_Network_IPv6)
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN6)];
#else
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN)];
#endif
    int32_t res,len;

    if ((bytesSent == NULL) || (to == NULL)) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    len = address_pal2bsd (to, (SOCKADDR *)&sockaddr_storage);

    if (len == 0) {
        return (PAL_ERR_SOCKET_INVALID_ADDRESS);
    }

    res = sendto ((intptr_t)socket, buffer, length, 0, (SOCKADDR *)&sockaddr_storage, len);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    *bytesSent = res;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    int32_t res;

    res = closesocket ((intptr_t)socket);
    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNumberOfNetInterfaces( uint32_t* numInterfaces)
{
    if (numInterfaces == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
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
    int32_t res;

    res = listen((intptr_t)socket, backlog);
    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}
palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
#if defined(RTE_Network_IPv6)
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN6)];
#else
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN)];
#endif
    int32_t sock,len;

    if (acceptedSocket == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    len  = sizeof (sockaddr_storage);
    sock = accept ((intptr_t)socket, (SOCKADDR *)&sockaddr_storage, &len);

    if (sock < 0) {
        return error_bsd2pal(sock);
    }

    if (sock > 0) {
        *acceptedSocket = (palSocket_t)sock;
        if ((address != NULL) && (addressLen != NULL)) {
            len = address_bsd2pal ((SOCKADDR *)&sockaddr_storage, address);
            *addressLen = len;
        }
        return PAL_SUCCESS;
    }

    return 0;
}

palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
#if defined(RTE_Network_IPv6)
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN6)];
#else
    uint8_t sockaddr_storage[sizeof(SOCKADDR_IN)];
#endif
    int32_t res,len;

    if (address == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    len = address_pal2bsd (address, (SOCKADDR *)&sockaddr_storage);
    if (len == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    res = connect ((intptr_t)socket, (SOCKADDR *)&sockaddr_storage, len);
    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_recv(palSocket_t socket, void *buffer, size_t len, size_t* recievedDataSize)
{
    int32_t res;

    if (recievedDataSize == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    res = recv((intptr_t)socket, buffer, len, 0);
    if (res < 0) {
        return (error_bsd2pal (res));
    }

    *recievedDataSize = res;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t *sentDataSize)
{
    int32_t res;

    if (sentDataSize == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    res = send ((intptr_t)socket, buf, len, 0);
    if (res < 0) {
        return error_bsd2pal(res);
    }

    *sentDataSize = res;

    return PAL_SUCCESS;
}

#endif //PAL_NET_TCP_AND_TLS_SUPPORT


palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument, palSocket_t* socket)
{
    palStatus_t result;
    int32_t     sock;

    result = pal_plat_socket(domain, type, nonBlockingSocket, interfaceNum, socket);
    if (result != PAL_SUCCESS) {
        return result;
    }

    sock = *(int32_t *)socket;
    sock_control[sock-1].callback         = callback;
    sock_control[sock-1].callbackArgument = callbackArgument;

    return PAL_SUCCESS;
}

// Generate callbacks for asynchronous sockets
void net_bsd_notify (int32_t sock, uint8_t evt) {    
    PAL_LOG_DBG("net_bsd_notify - socket: %d, event type: %d", sock, evt);
    evt &= ~BSD_EVT_SEND;
    if ((evt != 0) && (sock_control[sock-1].callback != NULL)) {                
        sock_control[sock-1].callback(sock_control[sock-1].callbackArgument);
    }
}

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *arg)
{
    (void)interfaceIndex;
    (void)callback;
    (void)arg;

    return PAL_ERR_NOT_SUPPORTED;
}

#if PAL_NET_DNS_SUPPORT

palStatus_t pal_plat_getAddressInfo(const char *url, palSocketAddress_t *address, palSocketLength_t* length)
{
    netStatus stat;
    NET_ADDR  addr;

    if ((url == NULL) || (address == NULL) || (length == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    //  if (*length < sizeof(palSocketAddress_t)) {
    //    return (PAL_ERR_INVALID_ARGUMENT);
    //  }
    // Do name resolution with both IPv4 and IPv6

    stat = netDNSc_GetHostByNameX (url, NET_ADDR_IP4, &addr);
#if defined(RTE_Network_IPv6)
    if (stat == netDnsResolverError) {
        /* Failed for IPv4, retry for IPv6 */
        stat = netDNSc_GetHostByNameX (url, NET_ADDR_IP6, &addr);
    }
#endif

    switch (stat) {
        case netOK:
            break;
        case netInvalidParameter:
            return PAL_ERR_INVALID_ARGUMENT;
        case netTimeout:
            return PAL_ERR_TIMEOUT_EXPIRED;
        case netDnsResolverError:
            return PAL_ERR_SOCKET_DNS_ERROR;
        default:
            return PAL_ERR_GENERIC_FAILURE;
    }

    // Copy resolved IP address
    switch (addr.addr_type) {
    case NET_ADDR_IP4:
        address->addressType = PAL_AF_INET;
        pal_setSockAddrIPV4Addr (address, addr.addr);
        break;
#if defined(RTE_Network_IPv6)
    case NET_ADDR_IP6:
        address->addressType = PAL_AF_INET6;
        pal_setSockAddrIPV6Addr (address, addr.addr);
        break;
#endif
    default:
        return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    }

    pal_setSockAddrPort (address, 0);
    *length = PAL_NET_MAX_ADDR_SIZE;

    return PAL_SUCCESS;
}

#endif

#endif // RTE_Network_Socket_BSD

uint8_t pal_plat_getRttEstimate()
{
    return PAL_DEFAULT_RTT_ESTIMATE;
}

uint16_t pal_plat_getStaggerEstimate(uint16_t data_amount)
{
    (void) data_amount;
    return PAL_DEFAULT_STAGGER_ESTIMATE;
}

