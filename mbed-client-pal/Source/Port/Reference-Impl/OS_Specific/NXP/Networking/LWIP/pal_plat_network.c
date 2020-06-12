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

#include "pal.h"
#include "pal_plat_network.h"

#include "lwip/api.h" // include LWIP sockets header
#include "lwip/netdb.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"

#define TRACE_GROUP "PAL"

#if PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_ANY
    #error "Supports only IPv4 for now"
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV6_ONLY
    #error "No support for IPv6 for now"
#endif

/* Static arena of sockets */
//TODO: do we need to protect this agains multitheaded aceess?
 typedef struct palLwipSocketNetConnInfo {
    bool inUse;
    struct netconn *connection;
    struct netbuf *buffer;
    uint32_t offset;
    palAsyncSocketCallback_t callback;
    void *callbackArgument;
 } palLwipNetConnInfo_t;

PAL_PRIVATE palLwipNetConnInfo_t palInternalSocketInfo[MEMP_NUM_NETCONN] = {0};

// number taken from LWIP documentaiton reccomendations (http://www.ece.ualberta.ca/~cmpe401/docs/lwip.pdf)
#define PAL_MAX_SEND_BUFFER_SIZE 1000

PAL_PRIVATE void* s_pal_networkInterfacesSupported[PAL_MAX_SUPORTED_NET_INTERFACES] = { 0 };

PAL_PRIVATE  uint32_t s_pal_numberOFInterfaces = 0;


 /*! \brief This function is a workaround for LWIP non-blocking receive.
  *
  * When calling `netconn_recv() on a non-blocking connection with a receive timeout of `0`, the `netconn_recv` function will block indefinitely (unless data arrives). this is not correct behavior.
  * To work around this issue for a non-blocking connection, we set the recieve timeout to 1 and set it back to the previous timeout value after the call.
  * \note This is only for **non-blocking** connections. All other sockets are left untouched.
 * @param[in] conn The handler.
 * @param[out] newbuf The output buffer.
 \return The status form the `netconn_recv` call.
 */
PAL_PRIVATE int pal_plat_netconReceive(struct netconn* conn, struct netbuf **newBuf)
{
    int backupTimeout;
    int result = PAL_SUCCESS;
    bool isNonBlocking = netconn_is_nonblocking(conn);
    if(isNonBlocking)
    {
        backupTimeout = netconn_get_recvtimeout(conn);
        netconn_set_recvtimeout(conn, 1);
        result = netconn_recv(conn, newBuf);
        netconn_set_recvtimeout(conn, backupTimeout);
    }
    else
    {
        result = netconn_recv(conn, newBuf);
    }

    return result;
}

// wrapper for callbacks because function signature is different.
void palNetConAsyncCallback(struct netconn * connection, enum netconn_evt event, u16_t len)
{
    int index = 0;
    for (index = 0; index < MEMP_NUM_NETCONN; index++)
    {
        if ( (true == palInternalSocketInfo[index].inUse ) && (palInternalSocketInfo[index].connection == connection))
        {
            if (NULL != palInternalSocketInfo[index].callback)
            {
                palInternalSocketInfo[index].callback(palInternalSocketInfo[index].callbackArgument);
            }
            break;
        }
    }
}

palStatus_t pal_plat_socketsInit(void* context)
{
    (void)context; // parameter not used in this case - this avoids the warning
    return PAL_SUCCESS;
}


palStatus_t pal_plat_registerNetworkInterface(void* context, uint32_t* interfaceIndex)
{
    palStatus_t result = PAL_SUCCESS;
    uint32_t index = 0;
    bool found = false;

    for (index = 0; index < s_pal_numberOFInterfaces; index++) // if specific context already registered return exisitng index instead of registering again.
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
        s_pal_networkInterfacesSupported[interfaceIndex]) {
        s_pal_networkInterfacesSupported[interfaceIndex] = NULL;
        --s_pal_numberOFInterfaces;
        return PAL_SUCCESS;
    } else {
        return PAL_ERR_INVALID_ARGUMENT;
    }
}

palStatus_t pal_plat_socketsTerminate(void* context)
{
    (void)context; // replace with macro
    // clean up static sockets array ? (close all sockets?)
    return PAL_SUCCESS;
}


PAL_PRIVATE palStatus_t translateErrnoToPALError(int errnoValue)
{
    palStatus_t status;
    switch (errnoValue)
    {
    case ERR_MEM:
        status = PAL_ERR_NO_MEMORY;
        break;
    case ERR_BUF:
        status = PAL_ERR_SOCKET_NO_BUFFERS;
        break;
    case ERR_TIMEOUT:
        status = PAL_ERR_SOCKET_WOULD_BLOCK;
        break;
    case ERR_RTE:
        status = PAL_ERR_SOCKET_HOST_UNREACHABLE;
        break;
    case ERR_INPROGRESS:
        status = PAL_ERR_SOCKET_IN_PROGRES;
        break;
    case ERR_VAL:
        status = PAL_ERR_SOCKET_INVALID_VALUE;
        break;
    case ERR_WOULDBLOCK:
        status = PAL_ERR_SOCKET_WOULD_BLOCK;
        break;
    case ERR_USE:
        status = PAL_ERR_SOCKET_ADDRESS_IN_USE;
        break;
    case ERR_ISCONN:
        status = PAL_ERR_SOCKET_ALREADY_CONNECTED;
        break;
    case ERR_ABRT:
        status = PAL_ERR_SOCKET_CONNECTION_ABORTED;
        break;
    case ERR_RST:
        status = PAL_ERR_SOCKET_CONNECTION_RESET;
        break;
    case ERR_CONN:
        status = PAL_ERR_SOCKET_NOT_CONNECTED;
        break;
    case ERR_ARG:
        status = PAL_ERR_INVALID_ARGUMENT;
        break;
    case ERR_CLSD:
        status = PAL_ERR_SOCKET_CONNECTION_CLOSED;
        break;
    case ERR_IF:
        status = PAL_ERR_SOCKET_INPUT_OUTPUT_ERROR;
        break;

    default:
        PAL_LOG_ERR("translateErrorToPALError() cannot translate %d", errnoValue);
        status = PAL_ERR_SOCKET_GENERIC;
        break;
    }
    return status;
}


palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    palStatus_t result = PAL_SUCCESS;
    struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;

    if (PAL_SO_REUSEADDR == optionName)
    {
        ip_set_option(conn->pcb.ip, SOF_REUSEADDR);
    }
#if PAL_NET_TCP_AND_TLS_SUPPORT // socket options below supported only if TCP is supported.
    else  if ((PAL_SO_KEEPALIVE == optionName) && (NETCONN_TCP == conn->type) && (conn->pcb.tcp != NULL))
    {
        if (*(int*)optionValue != 0)
        {
            ip_set_option(conn->pcb.ip, SOF_KEEPALIVE);
        }
        else
        {
            ip_reset_option(conn->pcb.ip, SOF_KEEPALIVE);
        }
    }
#if LWIP_TCP_KEEPALIVE // follwing options only supported if LWIP_TCP_KEEPALIVE is set to 1.
    else  if ((PAL_SO_KEEPIDLE == optionName) && (NETCONN_TCP == conn->type) && (conn->pcb.tcp != NULL))
    {
        conn->pcb.tcp->keep_idle = (*(int*)optionValue) * 1000;
    }
    else  if ((PAL_SO_KEEPINTVL == optionName) && (NETCONN_TCP == conn->type) && (conn->pcb.tcp != NULL))
    {
        conn->pcb.tcp->keep_intvl = (*(int*)optionValue) * 1000;
    }

#endif

#endif //PAL_NET_TCP_AND_TLS_SUPPORT
#ifdef LWIP_SO_SNDTIMEO
    else if (PAL_SO_SNDTIMEO == optionName)
    {
        netconn_set_sendtimeout(conn, *((const int *)optionValue));
    }
#endif
#ifdef LWIP_SO_RCVTIMEO
    else if (PAL_SO_RCVTIMEO == optionName)
    {
        netconn_set_recvtimeout(conn, *((const int *)optionValue));
    }
#endif
    else
    {
        result = PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    }
    return result;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;

    if (netconn_is_nonblocking(conn))
    {
        *isNonBlocking = true;
    }
    else
    {
        *isNonBlocking = false;
    }
    return PAL_SUCCESS;

}


palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
    int result = PAL_SUCCESS;
    struct netconn* conn = NULL;
    err_t error = 0;
    palIpV4Addr_t ipv4 = { 0 };
    uint16_t port = 0;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;


    result = pal_getSockAddrIPV4Addr(myAddress, ipv4);
    if (PAL_SUCCESS == result)
    {
        result = pal_getSockAddrPort(myAddress, &port);
        if (PAL_SUCCESS == result)
        {

            error = netconn_bind(conn, (ip_addr_t *)ipv4, port);
            if (ERR_OK != error)
            {
                result = translateErrnoToPALError(error);
            }
        }
    }

    return result;
}


palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    int result = PAL_SUCCESS;
    struct netbuf *newBuf = NULL;
    palLwipNetConnInfo_t* socketInfo = (palLwipNetConnInfo_t*)socket;
    struct netconn* conn = NULL;
    ip_addr_t* fromAddr;
    unsigned short fromPort;
    size_t bufferLength = 0;
    *bytesReceived = 0;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = socketInfo->connection;


    if (NULL != socketInfo->buffer)
    {
        newBuf = socketInfo->buffer;
        result = ERR_OK;
    }
    else
    {
        result = pal_plat_netconReceive(conn, &newBuf);
        if (ERR_OK != result) // Receive data
        {
            result = translateErrnoToPALError(result);
        }
    }

    if ((ERR_OK == result) &&(NULL != newBuf) )
    {

        bufferLength = netbuf_len(newBuf);
        if (bufferLength <= length)
        {
            netbuf_copy(newBuf, buffer, bufferLength);
            *bytesReceived = bufferLength;
        }
        else // more data recieved than buffer
        {
            netbuf_copy(newBuf, buffer, length);
            *bytesReceived = length;
        }
        if (NULL != from)
        {
            fromAddr = netbuf_fromaddr(newBuf);
            fromPort = netbuf_fromport(newBuf);
            result = pal_setSockAddrIPV4Addr(from, *((palIpV4Addr_t*) &(fromAddr->u_addr.ip4.addr)));
            if (PAL_SUCCESS == result)
            {
                result = pal_setSockAddrPort(from, fromPort);
                if ((PAL_SUCCESS == result) && (NULL != fromLength))
                {
                    *fromLength = PAL_IPV4_ADDRESS_SIZE;
                }
            }
        }
    }
    else if(ERR_OK == result)// if we got NULL this means the conneciton was closed
    {
        if (NULL != fromLength)
        {
            *fromLength = 0;
        }
        result = PAL_ERR_SOCKET_CONNECTION_CLOSED;
    }

    if (NULL != socketInfo->buffer)
    {
        socketInfo->buffer = NULL;
        socketInfo->offset = 0;
        // deleted below through newBuf
    }

    if (NULL !=newBuf )
        netbuf_delete(newBuf);
    return result;

}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
    int result = 0;
    struct netconn* conn = NULL;
    struct netbuf *localNetbuf;
    ip_addr_t toAddr;
    palIpV4Addr_t ipv4;
    unsigned short toPort;
    *bytesSent = 0;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;

    // netconn documentaiton (http://www.ece.ualberta.ca/~cmpe401/docs/lwip.pdf) says buffers over the size of the MTU should nto be sent. since this isn not always known 1000bytes is a good heuristic


    if (length > PAL_MAX_SEND_BUFFER_SIZE)
    {
        result = PAL_ERR_SOCKET_SEND_BUFFER_TOO_BIG;
        goto finish;
    }

    localNetbuf = netbuf_new();
    if (NULL == localNetbuf)
    {
        result = PAL_ERR_NO_MEMORY;
        goto finish;
    }

    result = netbuf_ref(localNetbuf, buffer, length);
    if (PAL_SUCCESS == result)
    {
        result = pal_getSockAddrPort(to, &toPort);
        if (PAL_SUCCESS == result)
        {
            result = pal_getSockAddrIPV4Addr(to, ipv4);
            if (PAL_SUCCESS == result)
            {
                toAddr.u_addr.ip4.addr = ipv4[0] | (ipv4[1] << 8) | (ipv4[2] << 16) | (ipv4[3] << 24);

                result = netconn_connect(conn, &toAddr, toPort);
                if (ERR_OK == result)
                {
                    result = netconn_send(conn, localNetbuf);
                    if (ERR_OK != result)
                    {
                        result = translateErrnoToPALError(result);
                    }
                }
                else
                {
                    result = translateErrnoToPALError(result);
                }
            }
        }
    }

    netbuf_delete(localNetbuf);
    *bytesSent = length;

finish:

    return result;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    int result = 0;
    palLwipNetConnInfo_t* socketInfo = NULL;
    struct netconn* conn = NULL;

    if (NULL == *socket) // socket already closed - return success.
    {
        PAL_LOG_DBG("socket close called on socket which was already closed");
        return PAL_SUCCESS;
    }
    socketInfo = (palLwipNetConnInfo_t*)*socket;
    conn = socketInfo->connection;
    if (NETCONN_TCP == conn->type)
    {
        result = netconn_close(conn);
        if (ERR_OK == result)
        {

            *socket = NULL;
        }
        else
        {
            result = translateErrnoToPALError(result);
        }
    }
    else
    {
        *socket = NULL;
    }

    socketInfo->inUse = false;
    socketInfo->offset = 0;
    socketInfo->connection = NULL;
    socketInfo->callback = NULL;
    if (NULL != socketInfo->buffer )
    {
        netbuf_delete(socketInfo->buffer);
        socketInfo->buffer = NULL;
    }
    netconn_delete(conn);
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

    uint16_t port = 0;
    uint32_t numInterfaces = 0;

    result = pal_plat_getNumberOfNetInterfaces(&numInterfaces);
    if (PAL_SUCCESS != result)
    {
        return result;
    }
    if (interfaceNum == -1) // default interface number is 0;
    {
    interfaceNum = 0;
    }
    if (interfaceNum <numInterfaces) // only "default" interface supported at this point
    {
        struct netif* fsl_netif0 = (struct netif*)s_pal_networkInterfacesSupported[interfaceNum] ;
        result = pal_setSockAddrIPV4Addr(&interfaceInfo->address, *((palIpV4Addr_t*) &(fsl_netif0->ip_addr.u_addr.ip4.addr)));
        if (PAL_SUCCESS == result)
        {
            result = pal_setSockAddrPort(&interfaceInfo->address, port);
        }
    }

    return result;
}

typedef struct palSocketSelectInfo
{
    struct netconn * connection;
    uint32_t selectStatus;
} palSocketSelectInfo_t;

PAL_PRIVATE palSocketSelectInfo_t s_select_state[PAL_NET_SOCKET_SELECT_MAX_SOCKETS] ;
PAL_PRIVATE palSemaphoreID_t s_palSelectSemaphore = 0;

void palNetConSelectCallback(struct netconn * connection, enum netconn_evt event, u16_t len)
{
    uint32_t index = 0;

    for (index = 0; index < MEMP_NUM_NETCONN; index++)
    {
        if ((palInternalSocketInfo[index].inUse) && (palInternalSocketInfo[index].connection == connection) && (NULL != palInternalSocketInfo[index].callback))
        {
            palInternalSocketInfo[index].callback(palInternalSocketInfo[index].callbackArgument);
            break;
        }
    }

    for (index = 0; index < PAL_NET_SOCKET_SELECT_MAX_SOCKETS; index++)
    {
        if (connection == s_select_state[index].connection)
        {
            s_select_state[index].selectStatus = 1; // add different flag per event.
            /*
            NETCONN_EVT_RCVPLUS,
            NETCONN_EVT_RCVMINUS,
            NETCONN_EVT_SENDPLUS,
            NETCONN_EVT_SENDMINUS,
            NETCONN_EVT_ERROR
            */
            break;
        }
    }
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}


#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.

#if PAL_NET_SERVER_SOCKET_API

palStatus_t pal_plat_listen(palSocket_t socket, int backlog)
{
    palStatus_t result = PAL_SUCCESS;
    struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a valid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;
    result = netconn_listen_with_backlog(conn, backlog);
    if (ERR_OK != result )
    {
        result = translateErrnoToPALError(result);
    }
    return result;
}


palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t * address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    palStatus_t result = PAL_SUCCESS;
    struct netconn * new_conn = NULL;
    ip_addr_t addr;
    uint16_t port;
    palLwipNetConnInfo_t* socketInfo = NULL;
    uint32_t index = 0;
    struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;



    for (index = 0; index < MEMP_NUM_NETCONN; index++) // allocate socket info structure.
    {
        if (false == palInternalSocketInfo[index].inUse)
        {
            palInternalSocketInfo[index].inUse = true;
            socketInfo = &palInternalSocketInfo[index];
            break;
        }
    }
    if (NULL == socketInfo)
     {
        result = PAL_ERR_NO_MEMORY;
    }
    else
    {
        result = netconn_accept(conn, &new_conn);
        if (ERR_OK != result)
        {
            palInternalSocketInfo[index].inUse = false; // free resource since accept failed
            result =  translateErrnoToPALError(result);
        }
        else
        {

            socketInfo->connection = new_conn;
            socketInfo->callback = callback;
            socketInfo->callbackArgument = callbackArgument;
            socketInfo->buffer = NULL;
            *acceptedSocket = (palSocket_t)socketInfo;

            result = netconn_getaddr(new_conn, &addr, &port, 0);
            if (ERR_OK != result) // failed to get peer address
            {
                result = translateErrnoToPALError(result);
            }
            else
            {
                result = pal_setSockAddrIPV4Addr(address, *((palIpV4Addr_t*) &(addr.u_addr.ip4.addr)));
                if (result == PAL_SUCCESS)
                {
                    pal_setSockAddrPort(address, port);
                    if (result == PAL_SUCCESS)
                    {
                        *addressLen = PAL_IPV6_ADDRESS_SIZE;
                    }
                }
            }
        }
    }
    return result;
}
#endif // PAL_NET_SERVER_SOCKET_API

palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    int result = 0;
    palIpV4Addr_t ipv4;
    uint16_t port;
    ip_addr_t netconn_address = {0};
    struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;


    if ((NETCONN_TCP == conn->type) && (conn->pcb.tcp != NULL)) // only TRY to connect if socket state is 0.(closed)
    {
        if ((conn->pcb.tcp->state >= 4))//TCP state 4 and above is conn ESTABLISHED or connected
        {
            result = PAL_ERR_SOCKET_ALREADY_CONNECTED;
        }
        else if (conn->pcb.tcp->state > 0)//TCP state 1 and above is connecting
        {
            result = PAL_ERR_SOCKET_IN_PROGRES;
        }
        else // socket is not connect or connecting - try to connect.
        {
            result = pal_getSockAddrIPV4Addr(address, ipv4);
            if (PAL_SUCCESS != result)
                return result;
            result = pal_getSockAddrPort(address, &port);
            if (PAL_SUCCESS != result)
                return result;
            netconn_address.u_addr.ip4.addr = ipv4[0] | (ipv4[1] << 8) | (ipv4[2] << 16) | (ipv4[3] << 24);

            result = netconn_connect(conn, &netconn_address, port);
            if (ERR_OK != result) // failed to get peer address
            {
                result = translateErrnoToPALError(result);
            }
        }
    }
    else
    {
        result = PAL_ERR_INVALID_ARGUMENT;
    }

    return result;
}



palStatus_t pal_plat_recv(palSocket_t socket, void *buf, size_t len, size_t* recievedDataSize)
{
    int result = 0;
    struct netbuf *newBuf = NULL;
    palLwipNetConnInfo_t* socketInfo = (palLwipNetConnInfo_t*)socket;
    size_t bufferSize = 0;
    struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;


    if (NULL != socketInfo->buffer) // part of previous buffer not read yet.
    {
        uint32_t copied = netbuf_copy_partial(socketInfo->buffer, buf, (u16_t)len, socketInfo->offset);
        socketInfo->offset += copied;
        *recievedDataSize = copied;
    }
    else
    {
        result = pal_plat_netconReceive(conn, &newBuf);
        if (ERR_OK != result)
        {
              return translateErrnoToPALError(result);
        }
        else
        {
            if (NULL != newBuf)
            {
                socketInfo->buffer = newBuf;
                bufferSize = netbuf_len(newBuf);

                if (bufferSize <= len)
                {
                      *recievedDataSize = bufferSize;
                      netbuf_copy(newBuf, buf, bufferSize);
                      socketInfo->offset = bufferSize;
                 }
                 else
                 {
                     *recievedDataSize = len;
                     netbuf_copy(newBuf, buf, len);
                     socketInfo->offset = len;
                }
         }
         else
         {
             result = PAL_ERR_SOCKET_CONNECTION_CLOSED;
         }

        }
    }
    if ((NULL != socketInfo->buffer) && (socketInfo->offset >= netbuf_len( socketInfo->buffer)))
    {
        netbuf_delete(socketInfo->buffer);
        socketInfo->buffer = NULL;
        socketInfo->offset = 0;
    }

    return result;
}


palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t* sentDataSize)
{
    int result = 0;
    size_t localSent;
    size_t* actualSent = sentDataSize;
     struct netconn* conn = NULL;
    if (NULL == socket) // NULL is not a vlaid socket.
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    conn = ((palLwipNetConnInfo_t*)socket)->connection;

    if (NULL == actualSent)
    {
    actualSent =  &localSent;
    }

    // netconn documentaiton (http://www.ece.ualberta.ca/~cmpe401/docs/lwip.pdf) says buffers over the size of the MTU should not be sent.since this is not always known 1000bytes is a good heuristic
    if (len > PAL_MAX_SEND_BUFFER_SIZE)
    {
        return PAL_ERR_SOCKET_SEND_BUFFER_TOO_BIG;
    }
    result = netconn_write_partly(conn, buf, len, NETCONN_COPY, actualSent);
    if (ERR_OK != result )
    {
        result = translateErrnoToPALError(result);
    }
    else
    {
        *sentDataSize = len;
    }

    return result;
}

#endif //PAL_NET_TCP_AND_TLS_SUPPORT


palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument, palSocket_t* socket)
{

    int result = PAL_SUCCESS;
    uint32_t index = 0;
    palLwipNetConnInfo_t* socketInfo = NULL;
    if (domain != PAL_AF_INET)
        return PAL_ERR_NOT_IMPLEMENTED;
    enum netconn_type connType = NETCONN_INVALID;
    if ((PAL_SOCK_STREAM == type) || (PAL_SOCK_STREAM_SERVER == type))
    {
        connType = NETCONN_TCP;
    }
    else if (PAL_SOCK_DGRAM == type)
    {
        connType = NETCONN_UDP;
    }
    else
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    for (index = 0; index < MEMP_NUM_NETCONN; index++) // allocate socket info structure.
    {
        if (false == palInternalSocketInfo[index].inUse)
        {
            palInternalSocketInfo[index].inUse = true;
            palInternalSocketInfo[index].connection = NULL;
            palInternalSocketInfo[index].callback = callback;
            palInternalSocketInfo[index].callbackArgument = callbackArgument;
            socketInfo = &palInternalSocketInfo[index];
            break;
        }
    }

    if (NULL == socketInfo)
    {
        result = PAL_ERR_NO_MEMORY;
    }
    else
    {
        struct netconn * con = netconn_new_with_callback(connType, palNetConAsyncCallback);
        if (NULL == con)
        {
            result = PAL_ERR_NO_MEMORY;
        }
        else
        {
            socketInfo->connection = con;
            socketInfo->buffer = NULL;
            // TODO(nirson01) : add binding to specific network interface  (interfaceNum)
            if (nonBlockingSocket)
            {
                netconn_set_nonblocking(con, 1);
            }
            *socket = (palSocket_t)socketInfo;
        }
    }

    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastrucature is finalized)
}


#if PAL_NET_DNS_SUPPORT

palStatus_t pal_plat_getAddressInfo(const char *hostname, palSocketAddress_t *address, palSocketLength_t* length)
{

    palStatus_t result = PAL_SUCCESS;
    ip_addr_t addr = {0};

    result = netconn_gethostbyname(hostname, &addr);

    if (ERR_OK != result)
    {
        result =  translateErrnoToPALError(result);
    }
    else
    {
        if (0 == addr.u_addr.ip4.addr ) // invalid 0 address
        {
            result = PAL_ERR_SOCKET_DNS_ERROR;
        }
        else
        {
            result = pal_setSockAddrIPV4Addr(address, *((palIpV4Addr_t*) &(addr.u_addr.ip4.addr)));
            if (PAL_SUCCESS == result)
            {
                result = pal_setSockAddrPort(address, 0); // we have no port fo the lookup -  zero it to avoif mistakes.
                *length = PAL_NET_MAX_ADDR_SIZE;
            }
        }
    }
    return result;

}

#endif

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *arg)
{
    (void)interfaceIndex;
    (void)callback;
    (void)arg;

    return PAL_ERR_NOT_SUPPORTED;
}
