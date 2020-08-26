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

/** \file
 *  \note       Current SX-ULPGN TCP sockets driver realization does not support non-blocking mode.
 *              Thus we realized WATCHDOG timer for triggering fake socket callback.
 *              If no send/recv operations happens timer periodically triggers callback - then
 *              upper layer tries to read some data.
 */

#include "pal.h"
#include "pal_plat_rtos.h"
#include "pal_plat_network.h"

#include "FreeRTOS.h"
#include "timers.h"
#include "sx_ulpgn_driver.h"


#ifndef PAL_PLAT_SOCKETS_DEBUG
    #define PAL_PLAT_SOCKETS_DEBUG 0        ///< Enable/disable sockets debug printouts
#endif

#if (PAL_PLAT_SOCKETS_DEBUG == 1) && (MBED_CONF_MBED_TRACE_ENABLE == 1)
    #include "mbed_trace.h"
    #define TRACE_GROUP             "NET"   ///< mbed trace group caption
#else
    #define PAL_LOG_ERR( ARGS...)
    #define PAL_LOG_WARN( ARGS...)
    #define PAL_LOG_INFO( ARGS...)
    #define PAL_LOG_DBG( ARGS...)
#endif


#define SOCKET_DEFAULT_TIMEOUT  100         ///< Socket receive/send default timeout, ms
#define SOCKET_WATCHDOG_PERIOD  250         ///< WATCHDOG period for generating socket events, ms

#define SX_ULPGN_WOULD_BLOCK    (-3)        ///< Status returned by SX-ULPGN Wi-Fi dongle driver, when socket opened and no data received

PAL_PRIVATE void* s_pal_networkInterfacesSupported[PAL_MAX_SUPORTED_NET_INTERFACES] = { 0 };
PAL_PRIVATE  uint32_t s_pal_numberOFInterfaces = 0;

/// Callback timer handlers
static TimerHandle_t callback_timer[CREATEABLE_SOCKETS] = {NULL, NULL, NULL, NULL};

/// Socket information struct
typedef struct palSXSocketInfo {
    uint8_t id;                         ///< Socket index, from 0 to CREATEABLE_SOCKETS
    uint8_t nonBlocking;                ///< Socket mode: 1 - nonBlocking, 0 - blocking
    uint32_t rxTimeout;                 ///< Receive timeout, ms
    uint32_t txTimeout;                 ///< Send timeout, ms
    palAsyncSocketCallback_t callback;  ///< Socket event callback
    void* callbackArgument;             ///< Socket event callback argument
} palSXSocketInfo_t;


/** \brief      Check socket status in scope of receive/transmit functions.
 *  \param[in]  socket Pointer to socket control struct
 *  \return     PAL_SUCCESS - if socket status Connected, PAL error code otherwise.
 */
static palStatus_t pal_plat_isSocketConnected(palSocket_t socket);

/** \brief
 *  \param[in]  xTimer  Called timer handler
 */
void socketEventCallback(TimerHandle_t xTimer);

/** \brief      Reset WATCHDOG timer for socket event callback call after send/recv event.
 *  \param[in]  *socket_info    Pointer to socket info struct
 *  \return     PAL_SUCCESS - if timer reset success, PAL error code otherwise.
 */
static palStatus_t _resetCallbackWatchdog(palSXSocketInfo_t *socket_info);

palStatus_t pal_plat_socketsInit(void* context)
{
    palStatus_t result = PAL_SUCCESS;

    if (0 != is_sx_ulpgn_wifi_connect())
    {
        result = PAL_ERR_SOCKET_NOT_CONNECTED;
    }
    return result;
}

palStatus_t pal_plat_registerNetworkInterface(void* context, uint32_t* interfaceIndex)
{
    palStatus_t result = PAL_SUCCESS;
    uint32_t index = 0;
    bool found = false;

    for (index = 0; index < s_pal_numberOFInterfaces; index++)
    {
        if (s_pal_networkInterfacesSupported[index] == context)
        {
            found = true;
            *interfaceIndex = index;
            break;
        }
    }
    if (false == found)
    {
        if (s_pal_numberOFInterfaces < PAL_MAX_SUPORTED_NET_INTERFACES)
        {
            s_pal_networkInterfacesSupported[s_pal_numberOFInterfaces] = context;
            *interfaceIndex = s_pal_numberOFInterfaces;
            ++s_pal_numberOFInterfaces;
        }
        else
        {
            result = PAL_ERR_SOCKET_MAX_NUMBER_OF_INTERFACES_REACHED;
        }
    }
    return result;
}

palStatus_t pal_plat_unregisterNetworkInterface(uint32_t interfaceIndex)
{
    if (interfaceIndex < PAL_MAX_SUPORTED_NET_INTERFACES &&
        s_pal_networkInterfacesSupported[interfaceIndex])
    {
        s_pal_networkInterfacesSupported[interfaceIndex] = NULL;
        --s_pal_numberOFInterfaces;
        return PAL_SUCCESS;
    }
    else
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
}

palStatus_t pal_plat_socketsTerminate(void* context)
{
    palStatus_t result = PAL_SUCCESS;
    palSXSocketInfo_t *socket_info = NULL;

    for (uint8_t i = 0; i < CREATEABLE_SOCKETS; i++)
    {
        if (callback_timer[i] != NULL)
        {
            socket_info = (palSXSocketInfo_t*)pvTimerGetTimerID(callback_timer[i]);
            result = pal_plat_close(&socket_info);

            if (PAL_SUCCESS != result)
            {
                break;
            }
        }
    }
    return result;
}

palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    palStatus_t result = PAL_SUCCESS;
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t *)socket;

    switch(optionName)
    {
    case PAL_SO_SNDTIMEO:
        if (sizeof(uint32_t) == optionLength)
        {
            socket_info->txTimeout = *((uint32_t*)optionValue);
        }
        else
        {
            result = PAL_ERR_SOCKET_INVALID_VALUE;
        }
        break;
    case PAL_SO_RCVTIMEO:
        if (sizeof(uint32_t) == optionLength)
        {
            socket_info->rxTimeout = *((uint32_t*)optionValue);
            if (sx_ulpgn_serial_tcp_recv_timeout_set(socket_info->id, socket_info->rxTimeout) != 0)
            {
                PAL_LOG_ERR("pal_plat_setSocketOptions() - error setting receive timeout");
                result = PAL_ERR_SOCKET_GENERIC;
            }
        }
        else
        {
            result = PAL_ERR_SOCKET_INVALID_VALUE;
        }
        break;
    default:
        result = PAL_ERR_SOCKET_INVALID_VALUE;
    }
    return result;
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
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t *)socket;

    *isNonBlocking = (bool)socket_info->nonBlocking;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    palStatus_t result = PAL_SUCCESS;
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t *)*socket;

    // delete watchdog, used for socket event simulation
    xTimerStop(callback_timer[socket_info->id], 0);
    xTimerDelete(callback_timer[socket_info->id], 0);
    callback_timer[socket_info->id] = NULL;

    // flush socket recv buffer
    // without flushing, data stay in wi-fi driver buffer to next socket use
    uint8_t tmp_buff[128];
    while (sx_ulpgn_tcp_recv(socket_info->id, tmp_buff, 128, SOCKET_DEFAULT_TIMEOUT) > 0)
    {
        tmp_buff[0] = 0;        // prevent while() excluding after optimisation
    };

    if (0 != sx_ulpgn_tcp_disconnect(socket_info->id))
    {
        result = PAL_ERR_SOCKET_GENERIC;
    }
    if (PAL_SUCCESS == result)
    {
        PAL_LOG_INFO("pal_plat_close() - socket %d closed\n", socket_info->id);

        pal_plat_free(socket_info);
        *socket = NULL;
    }
    return result;
}

palStatus_t pal_plat_getNumberOfNetInterfaces( uint32_t* numInterfaces)
{
    *numInterfaces = s_pal_numberOFInterfaces;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t * interfaceInfo)
{
    palStatus_t result = PAL_SUCCESS;
    uint32_t numInterfaces = 0;
    uint8_t ipv4[4];

    if (PAL_NET_DEFAULT_INTERFACE == interfaceNum)
    {
        interfaceNum = 0;
    }
    result = pal_plat_getNumberOfNetInterfaces(&numInterfaces);

    if (PAL_SUCCESS == result)
    {
        if (interfaceNum < numInterfaces)
        {
            if (0 != sx_ulpgn_get_ip(ipv4))
            {
                result = PAL_ERR_SOCKET_GENERIC;
            }
        }
    }
    if (PAL_SUCCESS == result)
    {
        result = pal_setSockAddrIPV4Addr(&interfaceInfo->address, ipv4);
        if (PAL_SUCCESS == result)
        {
            interfaceInfo->addressSize = PAL_IPV4_ADDRESS_SIZE;
        }
    }
    return result;
}

palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_listen(palSocket_t socket, int backlog)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t * address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    palStatus_t result = PAL_SUCCESS;
    palIpV4Addr_t ipv4;
    uint16_t port;
    int32_t socket_status;
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t*)socket;

    socket_status = sx_ulpgn_get_tcp_socket_status(socket_info->id);
    switch (socket_status)
    {
    case ULPGN_SOCKET_STATUS_CLOSED:
        result = PAL_ERR_SOCKET_CONNECTION_CLOSED;
        break;
    case ULPGN_SOCKET_STATUS_SOCKET:        // created
        result = PAL_SUCCESS;
        break;
    case ULPGN_SOCKET_STATUS_CONNECTED:
        result = PAL_ERR_SOCKET_ALREADY_CONNECTED;
        break;
    case ULPGN_SOCKET_STATUS_BOUND:
    case ULPGN_SOCKET_STATUS_LISTEN:
    default:
        result = PAL_ERR_SOCKET_GENERIC;
        break;
    }
    if (PAL_SUCCESS == result)
    {
        result = pal_getSockAddrIPV4Addr(address, ipv4);
    }
    if (PAL_SUCCESS == result)
    {
        result = pal_getSockAddrPort(address, &port);
    }
    if (PAL_SUCCESS == result)
    {
        uint32_t sw_ipv4 = *(uint32_t*)ipv4;
        sw_ipv4 = PAL_NTOHL(sw_ipv4);

        result = sx_ulpgn_tcp_connect(socket_info->id, sw_ipv4, port);
        if (0 != result)
        {
            result = PAL_ERR_SOCKET_GENERIC;
        }
    }
    if (PAL_SUCCESS == result)
    {
        // create WATCHDOG timer for socket event generating
        TimerHandle_t timer = xTimerCreate(
            NULL,                       // timer name
            SOCKET_WATCHDOG_PERIOD,     // call after time period, ms
            0,                          // one time run
            (void *)socket_info,        // socket info stored as timer id
            socketEventCallback
        );
        if (timer != NULL)
        {
            if (xTimerStart(timer, 0) != pdFAIL)
            {
                callback_timer[socket_info->id] = timer;
            }
            else
            {
                result = PAL_ERR_SOCKET_GENERIC;
            }
        }
        else
        {
            result = PAL_ERR_SOCKET_GENERIC;
        }
    }
    if (PAL_SUCCESS == result)
    {
        PAL_LOG_INFO("pal_plat_connect() - socket %d connected to %d.%d.%d.%d:%d\n", \
                 socket_info->id, ipv4[0], ipv4[1], ipv4[2], ipv4[3], port);
    }
    return result;
}

palStatus_t pal_plat_recv(palSocket_t socket, void *buf, size_t len, size_t* recievedDataSize)
{
    palStatus_t result = PAL_SUCCESS;
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t*)socket;
    int32_t received_bytes;

    result = pal_plat_isSocketConnected(socket);

    if (PAL_SUCCESS == result)
    {
        received_bytes = sx_ulpgn_tcp_recv(socket_info->id, buf, len, socket_info->rxTimeout);

        if (received_bytes < 0)
        {
            if (received_bytes == SX_ULPGN_WOULD_BLOCK)
            {
                // no data in recv buffer, return would block
                *recievedDataSize = 0;
                result = PAL_ERR_SOCKET_WOULD_BLOCK;

                PAL_LOG_DBG("pal_plat_recv() - socket %d would block", socket_info->id);
            }
            else
            {
                // other socket error
                result = PAL_ERR_SOCKET_GENERIC;

                PAL_LOG_ERR("pal_plat_recv() - receiving error (%d)", received_bytes);
            }
        }
        else
        {
            *recievedDataSize = received_bytes;

            if (received_bytes > 0)
            {
                // not end of the receiving, reset socket events WATCHDOG
                result = _resetCallbackWatchdog(socket_info);

                PAL_LOG_DBG("pal_plat_recv() - socket %d received %d bytes", socket_info->id, received_bytes);
            }
            else
            {
                // received 0 bytes, socket closed or session aborted
                PAL_LOG_INFO("pal_plat_recv() - socket %d - connection closed", socket_info->id);
            }
        }
    }
    return result;
}

palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t* sentDataSize)
{
    palStatus_t result = PAL_SUCCESS;
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t*)socket;
    int32_t sended_bytes;

    result = pal_plat_isSocketConnected(socket);

    if (PAL_SUCCESS == result)
    {
        sended_bytes = sx_ulpgn_tcp_send(socket_info->id, buf, len, socket_info->txTimeout);
        if (sended_bytes < 0)
        {
            result = PAL_ERR_SOCKET_GENERIC;
        }
    }
    if (PAL_SUCCESS == result)
    {
        *sentDataSize = sended_bytes;

        // data sended, reset callback WATCHDOG timer
        result = _resetCallbackWatchdog(socket_info);

        PAL_LOG_DBG("pal_plat_send() - socket %d sent %d bytes", socket_info->id, sended_bytes);
    }
    return result;
}

palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument, palSocket_t* socket)
{
    palStatus_t result = PAL_SUCCESS;
    palSXSocketInfo_t *new_socket;

    // implemented only for TCPv4, non-blocking
    /// \todo Add support of blocking mode (skipped, because currently not used in client)
    if ((PAL_AF_INET != domain) || (PAL_SOCK_STREAM != type) || (false == nonBlockingSocket))
    {
        result = PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    }
    if (PAL_SUCCESS == result)
    {
        new_socket = pal_plat_malloc(sizeof(palSXSocketInfo_t));
        new_socket->id = sx_ulpgn_get_avail_socket();

        new_socket->nonBlocking = (uint8_t)nonBlockingSocket;

        new_socket->rxTimeout = SOCKET_DEFAULT_TIMEOUT;
        new_socket->txTimeout = SOCKET_DEFAULT_TIMEOUT;

        new_socket->callback = callback;
        new_socket->callbackArgument = callbackArgument;

        *socket = (palSocket_t)new_socket;
    }
    if (255 == new_socket->id)
    {
        result = PAL_ERR_SOCKET_ALLOCATION_FAILED;
    }
    if (PAL_SUCCESS == result)
    {
        // 0 - TCP, 4 - TCPv4
        if (0 != sx_ulpgn_socket_create(new_socket->id, 0, 4))
        {
            result = PAL_ERR_SOCKET_ALLOCATION_FAILED;
        }
    }
    if (PAL_SUCCESS == result)
    {
        PAL_LOG_INFO("pal_plat_asynchronousSocket() - created socket with id %d\n", new_socket->id);
    }
    return result;
}

palStatus_t pal_plat_getAddressInfo(const char *hostname, palSocketAddress_t *address, palSocketLength_t* length)
{
    palStatus_t result = PAL_SUCCESS;
    uint8_t ipv4[PAL_IPV4_ADDRESS_SIZE];

    if (0 != sx_ulpgn_dns_query(hostname, ipv4))
    {
        result = PAL_ERR_SOCKET_DNS_ERROR;
    }
    else
    {
        address->addressType = PAL_AF_INET;
        *length = PAL_IPV4_ADDRESS_SIZE;
        result = pal_setSockAddrIPV4Addr(address, ipv4);  // convert to PAL internal address format
    }
    return result;
}

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *arg)
{
    (void)interfaceIndex;
    (void)callback;
    (void)arg;

    return PAL_ERR_NOT_SUPPORTED;
}

static palStatus_t pal_plat_isSocketConnected(palSocket_t socket)
{
    palStatus_t result = PAL_SUCCESS;
    int32_t socket_status;
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t*)socket;

    socket_status = sx_ulpgn_get_tcp_socket_status(socket_info->id);
    switch (socket_status)
    {
    case ULPGN_SOCKET_STATUS_CLOSED:
        result = PAL_ERR_SOCKET_CONNECTION_CLOSED;
        break;
    case ULPGN_SOCKET_STATUS_SOCKET:                // created
        result = PAL_ERR_SOCKET_NOT_CONNECTED;
        break;
    case ULPGN_SOCKET_STATUS_CONNECTED:
        result = PAL_SUCCESS;
        break;
    case ULPGN_SOCKET_STATUS_BOUND:
    case ULPGN_SOCKET_STATUS_LISTEN:
    default:
        result = PAL_ERR_SOCKET_GENERIC;
        break;
    }
    return result;
}

void socketEventCallback(TimerHandle_t xTimer)
{
    palSXSocketInfo_t *socket_info = (palSXSocketInfo_t*)pvTimerGetTimerID(xTimer);

    if (xTimerStop(xTimer, 0) != pdPASS)
    {
        PAL_LOG_ERR("socketEventCallback() - timer stop error");
    }
    if (socket_info->callback != NULL)
    {
        PAL_LOG_WARN("socketEventCallback() - native callback executed for socket %d", socket_info->id);
        socket_info->callback(socket_info->callbackArgument);
    }
    if (xTimerReset(xTimer, 0) != pdPASS)
    {
        PAL_LOG_ERR("socketEventCallback() - timer reset error");
    }
}

static palStatus_t _resetCallbackWatchdog(palSXSocketInfo_t *socket_info)
{
    palStatus_t result = PAL_SUCCESS;

    // callback already planned, reset timer period
    if (xTimerReset(callback_timer[socket_info->id], 0) != pdPASS)
    {
        result = PAL_ERR_SOCKET_GENERIC;
    }
    return result;
}

uint8_t pal_plat_getRttEstimate()
{
    return PAL_DEFAULT_RTT_ESTIMATE;
}

uint16_t pal_plat_getStaggerEstimate(uint16_t data_amount)
{
    (void) data_amount;
    return PAL_DEFAULT_STAGGER_ESTIMATE;
}
