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

#ifdef RTE_IoT_Socket_WiFi

#include <stdio.h>

#include "cmsis_os2.h"
#include "iot_socket.h"
#include "pal.h"
#include "pal_plat_network.h"
#include "pal_rtos.h"

#define TRACE_GROUP "PAL"

#ifndef BSD_NUM_SOCKS
#define BSD_NUM_SOCKS           4      // Maximum Number of BSD Sockets
#endif

static const uint32_t RECEIVE_POLL_TIMEOUT = 1000;
static osMutexId_t socket_callback_mutex_id;

static struct {
    bool nonBlocking;
    palAsyncSocketCallback_t callback;
    void *callbackArgument;
    osThreadId_t threadId;
} sock_control[BSD_NUM_SOCKS];

// Mutex responsible for protecting SPI media access
static const osMutexAttr_t callback_mutex_attr = {
  "Mutex_Socket_Callback_Lock",         // Mutex name
  osMutexPrioInherit,                   // attr_bits
  NULL,                                 // Memory for control block
  0U                                    // Size for control block
};

static void invoke_socket_callback(int32_t sock)
{
    if (sock_control[sock].callback) {
        osMutexAcquire(socket_callback_mutex_id, osWaitForever);
        sock_control[sock].callback(sock_control[sock].callbackArgument);
        osMutexRelease(socket_callback_mutex_id);
    } else {
        PAL_LOG_ERR("socket callback not set!");
    }
}

static void _receive_poll_thread(void *argument)
{
    int32_t sock = (int32_t)argument;
    int32_t status;
    uint32_t type;
    bool connected = false;

    // Needed only in blocking mode.
    if (!sock_control[sock].nonBlocking) {
        status = iotSocketSetOpt (sock, IOT_SOCKET_SO_RCVTIMEO, &RECEIVE_POLL_TIMEOUT, sizeof(RECEIVE_POLL_TIMEOUT));
        if (status < 0) {
            PAL_LOG_ERR("Failed to set IOT_SOCKET_SO_RCVTIMEO!");
        }
    }

    iotSocketGetOpt(sock, IOT_SOCKET_SO_TYPE, &type, sizeof(type));

    /* Continuously poll the network connection for events. */
    while (true) {
        status = iotSocketRecv(sock, NULL, 0);
        // Inform upper level to issue a read again.
        // status == 0 means there is data available in socket so callback can be called immediately.
        if (status == 0) {
            invoke_socket_callback(sock);
        } else if (status == IOT_SOCKET_EAGAIN) {
            // Pass first EGAIN event to upper layer to complete TCP connect()
            if (type == IOT_SOCKET_SOCK_STREAM && sock_control[sock].nonBlocking && !connected) {
                invoke_socket_callback(sock);
                connected = true;
            }
            osDelay(RECEIVE_POLL_TIMEOUT / 2);
        } else {
            PAL_LOG_ERR("Error polling network connection!");
            invoke_socket_callback(sock);
            sock_control[sock].threadId = 0;
            break;
        }
    }
}

static int32_t address_pal2iotsock(const palSocketAddress_t *palAddr, uint8_t* ip_address, uint16_t *port) {

    if (pal_getSockAddrPort (palAddr, port) != PAL_SUCCESS) {
        return 0;
    }

    if (palAddr->addressType == PAL_AF_INET) {
        palIpV4Addr_t ipV4Addr;
        if (pal_getSockAddrIPV4Addr(palAddr, ipV4Addr) == PAL_SUCCESS) {
            memcpy(ip_address, &ipV4Addr, sizeof(ipV4Addr));
            return (sizeof (ipV4Addr));
        } else {
            return 0;
        }
    }

    return 0;
}

static int32_t address_iotsock2pal(uint8_t *ip_address, const uint16_t port, palSocketAddress_t *palAddr)
{

    palAddr->addressType = PAL_AF_INET;
    pal_setSockAddrPort (palAddr, port);
    pal_setSockAddrIPV4Addr (palAddr, ip_address);
    return sizeof(palAddr);

}

static palStatus_t error_bsd2pal(int32_t bsd_error)
{
    PAL_LOG_DBG("error_bsd2pal - error %d", bsd_error);
    palStatus_t status;

    switch (bsd_error) {
        case IOT_SOCKET_ESOCK:
          status = PAL_ERR_SOCKET_INVALID_VALUE;
          break;
        case IOT_SOCKET_EINVAL:
          status = PAL_ERR_INVALID_ARGUMENT;
          break;
        case IOT_SOCKET_ENOTSUP:
          status = PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
          break;
        case IOT_SOCKET_ENOMEM:
          status = PAL_ERR_NO_MEMORY;
          break;
        case IOT_SOCKET_EAGAIN:
        case IOT_SOCKET_ETIMEDOUT:
          status = PAL_ERR_SOCKET_WOULD_BLOCK;
          break;
        case IOT_SOCKET_EINPROGRESS:
        case IOT_SOCKET_EALREADY:
          status = PAL_ERR_SOCKET_IN_PROGRES;
          break;
        case IOT_SOCKET_ENOTCONN:
          status = PAL_ERR_SOCKET_NOT_CONNECTED;
          break;
        case IOT_SOCKET_EISCONN:
          status = PAL_ERR_SOCKET_ALREADY_CONNECTED;
          break;
        case IOT_SOCKET_ECONNREFUSED:
        case IOT_SOCKET_ECONNRESET:
          status = PAL_ERR_SOCKET_CONNECTION_RESET;
          break;
        case IOT_SOCKET_ECONNABORTED:
          status = PAL_ERR_SOCKET_CONNECTION_ABORTED;
          break;
        case IOT_SOCKET_EADDRINUSE:
          status = PAL_ERR_SOCKET_ADDRESS_IN_USE;
          break;
        case IOT_SOCKET_EHOSTNOTFOUND:
          status = PAL_ERR_SOCKET_DNS_ERROR;
          break;

        default:
          status = PAL_ERR_SOCKET_GENERIC;
          break;
    }

    return status;
}

palStatus_t pal_plat_socketsInit(void* context)
{
    (void)context;

    memset (sock_control, 0, sizeof(sock_control));
    palStatus_t status = PAL_SUCCESS;
    socket_callback_mutex_id = osMutexNew(&callback_mutex_attr);

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
    int32_t sock, family, sock_type, res, protocol;
    (void)interfaceNum;

    if (sockt == NULL) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    switch (domain) {
        case PAL_AF_INET:
            family = IOT_SOCKET_AF_INET;
            break;
        case PAL_AF_INET6:
            //family = IOT_SOCKET_AF_INET6;
            return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
            //break;
        default:
            return PAL_ERR_INVALID_ARGUMENT;
    }

    switch (type) {
        case PAL_SOCK_STREAM:
        case PAL_SOCK_STREAM_SERVER:
            sock_type = IOT_SOCKET_SOCK_STREAM;
            protocol = IOT_SOCKET_IPPROTO_TCP;
            break;

        case PAL_SOCK_DGRAM:
            sock_type = IOT_SOCKET_SOCK_DGRAM;
            protocol = IOT_SOCKET_IPPROTO_UDP;
            break;

        default:
            return (PAL_ERR_INVALID_ARGUMENT);
    }

    sock = iotSocketCreate(family, sock_type, protocol);
    if (sock < 0) {
        if (sock == IOT_SOCKET_ENOMEM) {
            PAL_LOG_ERR("pal_plat_socket - failed to create socket, memory fail!");
            return PAL_ERR_SOCKET_ALLOCATION_FAILED;
        }

        return error_bsd2pal(sock);
    }

    if (sock >= BSD_NUM_SOCKS) {
        PAL_LOG_ERR("pal_plat_socket - socket limit reached!");
        iotSocketClose(sock);
        return PAL_ERR_SOCKET_ALLOCATION_FAILED;
    }

    sock_control[sock].nonBlocking = nonBlockingSocket;
    sock_control[sock].callback    = NULL;
    sock_control[sock].callbackArgument = 0;
    sock_control[sock].threadId = 0;

    if (nonBlockingSocket) {
        uint32_t nbio = 1;
        res = iotSocketSetOpt((intptr_t)sock, IOT_SOCKET_IO_FIONBIO, &nbio, sizeof(nbio));
        if (res < 0) {
            return error_bsd2pal(res);
        }
    }

    // Increase index by one since M2MConnectionHandler does not allow socket id
    // to be zero.
    sock++;
    *sockt = (palSocket_t)sock;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    int32_t res;

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    switch (optionName) {
        case PAL_SO_SNDTIMEO:
            res = iotSocketSetOpt(socket_index, IOT_SOCKET_SO_SNDTIMEO, optionValue, optionLength);
            break;
        case PAL_SO_RCVTIMEO:
            res = iotSocketSetOpt(socket_index, IOT_SOCKET_SO_RCVTIMEO, optionValue, optionLength);
            break;
        case PAL_SO_KEEPALIVE:
            res = iotSocketSetOpt(socket_index, IOT_SOCKET_SO_KEEPALIVE, optionValue, optionLength);
          break;
        default:
          return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    }

    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_setSocketOptionsWithLevel(palSocket_t socket, palSocketOptionLevelName_t optionLevel, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    (void)socket;
    (void)optionLevel;
    (void)optionName;
    (void)optionValue;
    (void)optionLength;

    return PAL_ERR_NOT_SUPPORTED;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    if (isNonBlocking == NULL) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    if (socket_index >= BSD_NUM_SOCKS) {
        return (PAL_ERR_SOCKET_INVALID_VALUE);
    }

    *isNonBlocking = sock_control[socket_index].nonBlocking;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{

/*Generic ISM43362 Module limitations:
 *  - configuration of local port for client socket is not supported
*/
#ifdef RTE_Drivers_WiFi_ISM43362_SPI
    return PAL_SUCCESS;
#endif

    int32_t res, len;

    if (myAddress == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    uint8_t ip_address[PAL_IPV4_ADDRESS_SIZE];
    uint16_t port;

    len = address_pal2iotsock(myAddress, ip_address, &port);

    if (len == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    res = iotSocketBind(socket_index, ip_address, len, port);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    if ((bytesReceived == NULL) || (from == NULL) || (fromLength == NULL)) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    uint8_t ip_address[PAL_IPV4_ADDRESS_SIZE];
    uint16_t port;
    uint32_t ip_len;

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    int32_t res = iotSocketRecvFrom(socket_index, buffer, length, ip_address, &ip_len, &port);

    // Start receive thread for polling socket events
    if (!sock_control[socket_index].threadId) {
        sock_control[socket_index].threadId = osThreadNew(_receive_poll_thread, (void *)socket_index, NULL);
    }

    if (res < 0) {
        return error_bsd2pal(res);
    }

    *fromLength = address_iotsock2pal(ip_address, port, from);

    *bytesReceived = res;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
    if ((bytesSent == NULL) || (to == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    uint8_t ip_address[PAL_IPV4_ADDRESS_SIZE];
    uint16_t port;

    int32_t len = address_pal2iotsock(to, ip_address, &port);

    if (len == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    int32_t res = iotSocketSendTo(socket_index, buffer, length, ip_address, len, port);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    *bytesSent = res;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    int32_t res;
    PAL_LOG_DBG("pal_plat_close");

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)*socket - 1;

    res = iotSocketClose(socket_index);

    if (socket_callback_mutex_id != NULL) {
        if (osMutexDelete(socket_callback_mutex_id) == osOK) {
            socket_callback_mutex_id = NULL;
        }
    }

    sock_control[socket_index].callback = NULL;
    sock_control[socket_index].callbackArgument = NULL;
    sock_control[socket_index].nonBlocking = 0;
    sock_control[socket_index].threadId = 0;

    if (res < 0) {
        return error_bsd2pal(res);
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
    int32_t res;

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    res = iotSocketListen(socket_index, backlog);
    if (res < 0) {
        return error_bsd2pal(res);
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    int32_t sock;

    if (acceptedSocket == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    uint8_t ip_address[PAL_IPV4_ADDRESS_SIZE];
    uint16_t port;
    uint32_t ip_len;

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    sock = iotSocketAccept(socket_index, ip_address, &ip_len, &port);

    if (sock < 0) {
        return error_bsd2pal(sock);
    }

    // Increase index by one since M2MConnectionHandler does not allow socket id to be zero
    sock++;

    if (sock > 0) {
        *acceptedSocket = (palSocket_t)sock;
        if ((address != NULL) && (addressLen != NULL)) {
            address_iotsock2pal(ip_address, port, address);
            *addressLen = ip_len;
        }
        return PAL_SUCCESS;
    }

    return 0;
}

palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    int32_t res,len;

    if (address == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    uint8_t ip_address[PAL_IPV4_ADDRESS_SIZE];
    uint16_t port;

    len = address_pal2iotsock(address, ip_address, &port);

    if (len == 0) {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    res = iotSocketConnect(socket_index, ip_address, len, port);

    // Start receive thread for polling socket events
    if (!sock_control[socket_index].threadId) {
        sock_control[socket_index].threadId = osThreadNew(_receive_poll_thread, (void *)socket_index, NULL);
    }

    if (res < 0) {
        return error_bsd2pal(res);
    }


    return PAL_SUCCESS;
}

palStatus_t pal_plat_recv(palSocket_t socket, void *buffer, size_t len, size_t* receivedDataSize)
{
    int32_t res;

    if (receivedDataSize == NULL) {
        return (PAL_ERR_INVALID_ARGUMENT);
    }

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    res = iotSocketRecv(socket_index, buffer, len);

    if (res < 0) {
        return error_bsd2pal(res);
    }

    *receivedDataSize = res;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t *sentDataSize)
{
    int32_t res;

    if (sentDataSize == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    // map to right socket descriptor
    int32_t socket_index = (intptr_t)socket - 1;

    res = iotSocketSend(socket_index, buf, len);

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
    sock_control[sock - 1].callback         = callback;
    sock_control[sock - 1].callbackArgument = callbackArgument;

    return PAL_SUCCESS;
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
    int32_t stat;
    uint8_t ip_address[PAL_IPV4_ADDRESS_SIZE];
    uint32_t len = sizeof(length);

    if ((url == NULL) || (address == NULL) || (length == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    stat = iotSocketGetHostByName(url, IOT_SOCKET_AF_INET, ip_address, &len);

    switch (stat) {
        case 0:
            break;
        case IOT_SOCKET_EINVAL:
            return PAL_ERR_INVALID_ARGUMENT;
        case IOT_SOCKET_ETIMEDOUT :
            return PAL_ERR_TIMEOUT_EXPIRED;
        case IOT_SOCKET_EHOSTNOTFOUND:
            return PAL_ERR_SOCKET_DNS_ERROR;
        default:
            return PAL_ERR_GENERIC_FAILURE;
    }

    address->addressType = PAL_AF_INET;
    pal_setSockAddrIPV4Addr (address, ip_address);

    pal_setSockAddrPort (address, 0);
    *length = PAL_NET_MAX_ADDR_SIZE;

    return PAL_SUCCESS;
}

#endif // PAL_NET_DNS_SUPPORT
#endif // RTE_IoT_Socket_WiFi

uint8_t pal_plat_getRttEstimate()
{
    return PAL_DEFAULT_RTT_ESTIMATE;
}

uint16_t pal_plat_getStaggerEstimate(uint16_t data_amount)
{
    (void) data_amount;
    return PAL_DEFAULT_STAGGER_ESTIMATE;
}

