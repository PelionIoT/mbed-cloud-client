/*******************************************************************************
 * Copyright 2016-2021 Pelion.
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
#include "pal_network.h"
#include "pal_plat_network.h"

#define TRACE_GROUP "PAL"

static uint16_t _stagger_override_value = 0;

typedef struct pal_in_addr {
    uint32_t s_addr; // that's a 32-bit int (4 bytes)
} pal_in_addr_t;

#if PAL_SUPPORT_IP_V4
typedef struct pal_socketAddressInternal {
    short int          pal_sin_family;  // address family
    unsigned short int pal_sin_port;    // port
    pal_in_addr_t     pal_sin_addr;    // ipv4 address
    unsigned char      pal_sin_zero[8]; //
} pal_socketAddressInternal_t;
#endif

#if PAL_SUPPORT_IP_V6
typedef struct pal_socketAddressInternal6{
    uint16_t       pal_sin6_family;   // address family,
    uint16_t       pal_sin6_port;     // port number, Network Byte Order
    uint32_t       pal_sin6_flowinfo; // IPv6 flow information
    palIpV6Addr_t pal_sin6_addr;     // IPv6 address
    uint32_t       pal_sin6_scope_id; // Scope ID
} pal_socketAddressInternal6_t;
#endif

#if PAL_NET_DNS_SUPPORT

// structure used by pal_getAddressInfoAsync
#if (PAL_DNS_API_VERSION == 1)
typedef struct pal_asyncAddressInfo
{
    char* hostname;
    palSocketAddress_t* address;
    palSocketLength_t* addressLength;
    palGetAddressInfoAsyncCallback_t callback;
    void* callbackArgument;
} pal_asyncAddressInfo_t;
#endif // PAL_DNS_API_VERSION
#endif // PAL_NET_DNS_SUPPORT

palStatus_t pal_registerNetworkInterface(void* networkInterfaceContext, uint32_t* interfaceIndex)
{
    PAL_VALIDATE_ARGUMENTS((networkInterfaceContext == NULL) || (interfaceIndex == NULL));
    palStatus_t result = pal_plat_registerNetworkInterface(networkInterfaceContext, interfaceIndex);
    return result;
}

palStatus_t pal_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *client_arg)
{
    return pal_plat_setConnectionStatusCallback(interfaceIndex, callback, client_arg);
}

palStatus_t pal_unregisterNetworkInterface(uint32_t interfaceIndex)
{
    PAL_VALIDATE_ARGUMENTS(interfaceIndex > PAL_MAX_SUPORTED_NET_INTERFACES - 1);
    return pal_plat_unregisterNetworkInterface(interfaceIndex);
}

palStatus_t pal_setSockAddrPort(palSocketAddress_t* address, uint16_t port)
{
    palStatus_t result = PAL_SUCCESS;
    bool found = false;
    PAL_VALIDATE_ARGUMENTS(NULL == address);

#if PAL_SUPPORT_IP_V4
    if (address->addressType == PAL_AF_INET)
    {
        pal_socketAddressInternal_t* innerAddr = (pal_socketAddressInternal_t*)address;
        // Set Linux format
        innerAddr->pal_sin_port = PAL_HTONS(port);
        found = true;
    }
#endif

#if PAL_SUPPORT_IP_V6
    if (address->addressType == PAL_AF_INET6)
    {
        pal_socketAddressInternal6_t * innerAddr = (pal_socketAddressInternal6_t*)address;
        // Set Linux format
        innerAddr->pal_sin6_port = PAL_HTONS(port);
        found = true;
    }
#endif
    if (false == found)
    {
        result =  PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    }

    return result;
}



#if PAL_SUPPORT_IP_V4
palStatus_t pal_setSockAddrIPV4Addr(palSocketAddress_t* address, palIpV4Addr_t ipV4Addr)
{
    PAL_VALIDATE_ARGUMENTS((NULL == address) || (NULL == ipV4Addr));

    pal_socketAddressInternal_t* innerAddr = (pal_socketAddressInternal_t*)address;
    innerAddr->pal_sin_family = PAL_AF_INET;
    innerAddr->pal_sin_addr.s_addr = (ipV4Addr[0]) | (ipV4Addr[1] << 8) | (ipV4Addr[2] << 16) | (ipV4Addr[3] << 24);
    return PAL_SUCCESS;
}

palStatus_t pal_getSockAddrIPV4Addr(const palSocketAddress_t* address, palIpV4Addr_t ipV4Addr)
{
    PAL_VALIDATE_ARGUMENTS(NULL == address);
    PAL_VALIDATE_CONDITION_WITH_ERROR((address->addressType != PAL_AF_INET),PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY);
    palStatus_t result = PAL_SUCCESS;

    if (address->addressType == PAL_AF_INET)
    {
        pal_socketAddressInternal_t* innerAddr = (pal_socketAddressInternal_t*)address;
        ipV4Addr[0] = (innerAddr->pal_sin_addr.s_addr) & 0xFF;
        ipV4Addr[1] = (innerAddr->pal_sin_addr.s_addr >> 8) & 0xFF;
        ipV4Addr[2] = (innerAddr->pal_sin_addr.s_addr >> 16) & 0xFF;
        ipV4Addr[3] = (innerAddr->pal_sin_addr.s_addr >> 24) & 0xFF;

    }

    return result;
}
#else
palStatus_t pal_setSockAddrIPV4Addr(palSocketAddress_t* address, palIpV4Addr_t ipV4Addr)
{
    return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
}
palStatus_t pal_getSockAddrIPV4Addr(const palSocketAddress_t* address, palIpV4Addr_t ipV4Addr)
{
    return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
}

#endif


#if PAL_SUPPORT_IP_V6
palStatus_t pal_getSockAddrIPV6Addr(const palSocketAddress_t* address, palIpV6Addr_t ipV6Addr)
{
    palStatus_t result = PAL_SUCCESS;
    int index = 0;
    PAL_VALIDATE_ARGUMENTS (NULL == address);
    PAL_VALIDATE_CONDITION_WITH_ERROR((address->addressType != PAL_AF_INET6),PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY);

    pal_socketAddressInternal6_t * innerAddr = (pal_socketAddressInternal6_t*)address;
    for (index = 0; index < PAL_IPV6_ADDRESS_SIZE; index++) // TODO: use mem copy?
    {
        ipV6Addr[index] = innerAddr->pal_sin6_addr[index];
    }


    return result;
}

palStatus_t pal_setSockAddrIPV6Addr(palSocketAddress_t* address, palIpV6Addr_t ipV6Addr)
{
    int index;
    PAL_VALIDATE_ARGUMENTS((NULL == address) || (NULL == ipV6Addr));

    pal_socketAddressInternal6_t* innerAddr = (pal_socketAddressInternal6_t*)address;
    innerAddr->pal_sin6_family = PAL_AF_INET6;
    for (index = 0; index < PAL_IPV6_ADDRESS_SIZE; index++) // TODO: use mem copy?
    {
        innerAddr->pal_sin6_addr[index] = ipV6Addr[index];
    }
    return PAL_SUCCESS;
}
#else
palStatus_t pal_setSockAddrIPV6Addr(palSocketAddress_t* address, palIpV6Addr_t ipV6Addr)
{
    return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
}

palStatus_t pal_getSockAddrIPV6Addr(const palSocketAddress_t* address, palIpV6Addr_t ipV6Addr)
{
    return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
}

#endif

#if (PAL_SUPPORT_NAT64 && PAL_SUPPORT_IP_V6)
palStatus_t pal_setSockAddrNAT64Addr(palSocketAddress_t* address, palIpV4Addr_t ipV4Addr)
{
    PAL_VALIDATE_ARGUMENTS((NULL == address) || (NULL == ipV4Addr));

    pal_socketAddressInternal6_t* innerAddr = (pal_socketAddressInternal6_t*)address;
    innerAddr->pal_sin6_family = PAL_AF_INET6;

    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[0] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[1] = 0x64;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[2] = 0xFF;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[3] = 0x9B;

    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[4] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[5] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[6] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[7] = 0x00;

    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[8] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[9] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[10] = 0x00;
    ((volatile uint8_t*) innerAddr->pal_sin6_addr)[11] = 0x00;

    innerAddr->pal_sin6_addr[12] = ipV4Addr[0];
    innerAddr->pal_sin6_addr[13] = ipV4Addr[1];
    innerAddr->pal_sin6_addr[14] = ipV4Addr[2];
    innerAddr->pal_sin6_addr[15] = ipV4Addr[3];

    return PAL_SUCCESS;
}
#else
palStatus_t pal_setSockAddrNAT64Addr(palSocketAddress_t* address, palIpV4Addr_t ipV4Addr)
{
    return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
}
#endif

palStatus_t pal_getSockAddrPort(const palSocketAddress_t* address, uint16_t* port)
{
    bool found = false;
    palStatus_t result = PAL_SUCCESS;

    PAL_VALIDATE_ARGUMENTS ((NULL == address) || (NULL == port));

#if PAL_SUPPORT_IP_V4

    if (address->addressType == PAL_AF_INET)
    {
        pal_socketAddressInternal_t* innerAddr = (pal_socketAddressInternal_t*)address;
        // Set numeric formal
        *port = PAL_NTOHS(innerAddr->pal_sin_port);
        found = true;
    }
#endif
#if PAL_SUPPORT_IP_V6
    if (address->addressType == PAL_AF_INET6)
    {
        pal_socketAddressInternal6_t * innerAddr = (pal_socketAddressInternal6_t*)address;
        // Set numeric formal
        *port = PAL_NTOHS(innerAddr->pal_sin6_port);
        found = true;
    }
#endif
    if (false == found)
    {
        result =  PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    }

    return result;
}


palStatus_t pal_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{

    PAL_VALIDATE_ARGUMENTS (NULL == optionValue);

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_setSocketOptions( socket,  optionName, optionValue,  optionLength);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}
palStatus_t pal_setSocketOptionsWithLevel(palSocket_t socket, palSocketOptionLevelName_t optionLevel, int optionName, const void* optionValue, palSocketLength_t optionLength)
{

    PAL_VALIDATE_ARGUMENTS (NULL == optionValue);

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_setSocketOptionsWithLevel(socket, optionLevel, optionName, optionValue, optionLength);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}

palStatus_t pal_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    PAL_VALIDATE_ARGUMENTS (NULL == isNonBlocking);

    palStatus_t result = pal_plat_isNonBlocking(socket, isNonBlocking);;
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{

    PAL_VALIDATE_ARGUMENTS(NULL == myAddress);

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_bind(socket, myAddress, addressLength);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{

    PAL_VALIDATE_ARGUMENTS((NULL == buffer) || (NULL == bytesReceived));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_receiveFrom(socket,  buffer,  length,  from, fromLength, bytesReceived);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{

    PAL_VALIDATE_ARGUMENTS((NULL == buffer) || (NULL == bytesSent) || (NULL == to));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_sendTo(socket, buffer, length, to, toLength, bytesSent);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_close(palSocket_t* socket)
{

    PAL_VALIDATE_ARGUMENTS(NULL == socket);

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_close(socket);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_getNumberOfNetInterfaces( uint32_t* numInterfaces)
{

    PAL_VALIDATE_ARGUMENTS(NULL == numInterfaces);

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_getNumberOfNetInterfaces(numInterfaces);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t * interfaceInfo)
{
    PAL_VALIDATE_ARGUMENTS(NULL == interfaceInfo)

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_getNetInterfaceInfo(interfaceNum, interfaceInfo);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.

#if PAL_NET_SERVER_SOCKET_API

palStatus_t pal_listen(palSocket_t socket, int backlog)
{
    palStatus_t result = pal_plat_listen(socket, backlog);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}

palStatus_t pal_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == acceptedSocket) || (NULL == address)|| (NULL == addressLen));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_accept(socket,  address, addressLen,  acceptedSocket, callback, callbackArgument);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}

#endif // PAL_NET_SERVER_SOCKET_API

palStatus_t pal_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    PAL_VALIDATE_ARGUMENTS(NULL == address);

    palStatus_t result = PAL_SUCCESS;

    result = pal_plat_connect( socket, address, addressLen);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_recv(palSocket_t socket, void* buf, size_t len, size_t* recievedDataSize)
{
    PAL_VALIDATE_ARGUMENTS((NULL == recievedDataSize) ||  (NULL == buf));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_recv(socket, buf, len, recievedDataSize);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_send(palSocket_t socket, const void* buf, size_t len, size_t* sentDataSize)
{

    PAL_VALIDATE_ARGUMENTS((NULL == buf) || (NULL == sentDataSize));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_send( socket, buf, len, sentDataSize);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


#endif //PAL_NET_TCP_AND_TLS_SUPPORT

palStatus_t pal_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, palSocket_t* socket)
{
    PAL_VALIDATE_ARGUMENTS((NULL == socket) || (NULL == callback) || (nonBlockingSocket == false));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_asynchronousSocket(domain,  type,  nonBlockingSocket,  interfaceNum,  callback, NULL, socket);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}

palStatus_t pal_asynchronousSocketWithArgument(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument, palSocket_t* socket)
{
    PAL_VALIDATE_ARGUMENTS((NULL == socket) || (NULL == callback) || (nonBlockingSocket == false));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_asynchronousSocket(domain, type, nonBlockingSocket, interfaceNum, callback, callbackArgument, socket);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}

#if PAL_NET_DNS_SUPPORT
#if (PAL_DNS_API_VERSION == 0) || (PAL_DNS_API_VERSION == 1)
palStatus_t pal_getAddressInfo(const char *hostname, palSocketAddress_t *address, palSocketLength_t* addressLength)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == hostname) || (NULL == address) || (NULL == addressLength));

    palStatus_t result = PAL_SUCCESS;
    result = pal_plat_getAddressInfo(hostname, address, addressLength);
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}
#endif

// the function invoked by the thread created in pal_getAddressInfoAsync
#if (PAL_DNS_API_VERSION == 1)
PAL_PRIVATE void getAddressInfoAsyncThreadFunc(void const* arg)
{
    pal_asyncAddressInfo_t* info = (pal_asyncAddressInfo_t*)arg;
    palStatus_t status = pal_getAddressInfo(info->hostname, info->address, info->addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("getAddressInfoAsyncThreadFunc: pal_getAddressInfo failed\n");
    }
    info->callback(info->hostname, info->address, info->addressLength, status, info->callbackArgument); // invoke callback
    free(info);
}

palStatus_t pal_getAddressInfoAsync(const char* hostname,
                                    palSocketAddress_t* address,
                                    palSocketLength_t* addressLength,
                                    palGetAddressInfoAsyncCallback_t callback,
                                    void* callbackArgument)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == hostname) || (NULL == address) || (NULL == addressLength) || (NULL == callback))

    palStatus_t status;
    palThreadID_t threadID = NULLPTR;

    pal_asyncAddressInfo_t* info = (pal_asyncAddressInfo_t*)malloc(sizeof(pal_asyncAddressInfo_t)); // thread function argument allocation
    if (NULL == info) {
        status = PAL_ERR_NO_MEMORY;
    }
    else {
        info->hostname = (char*)hostname;
        info->address = address;
        info->addressLength = addressLength;
        info->callback = callback;
        info->callbackArgument = callbackArgument;

        status = pal_osThreadCreateWithAlloc(getAddressInfoAsyncThreadFunc, info, PAL_osPriorityReservedDNS, PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE, NULL, &threadID);
        if (PAL_SUCCESS != status) {
            free(info); // free memory allocation in case thread creation failed
        }
    }
    return status;
}

#elif (PAL_DNS_API_VERSION == 2) || (PAL_DNS_API_VERSION == 3)
#if !defined(__MBED__) && (PAL_DNS_API_VERSION == 2)
#error "PAL_DNS_API_VERSION 2 is only supported with mbed-os"
#endif
palStatus_t pal_getAddressInfoAsync(const char* hostname,
#if (PAL_DNS_API_VERSION == 2)
                                    palSocketAddress_t* address,
#endif
                                    palGetAddressInfoAsyncCallback_t callback,
                                    void* callbackArgument,
                                    palDNSQuery_t* queryHandle)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == hostname) || (NULL == callback))
#if (PAL_DNS_API_VERSION == 2)
    PAL_VALIDATE_ARGUMENTS (NULL == address)
#endif
    palStatus_t status;

    pal_asyncAddressInfo_t* info = (pal_asyncAddressInfo_t*)malloc(sizeof(pal_asyncAddressInfo_t));
    if (NULL == info) {
        status = PAL_ERR_NO_MEMORY;
    }
    else {
        info->hostname = (char*)hostname;
#if (PAL_DNS_API_VERSION == 2)
        info->address = address;
#endif
        info->callback = callback;
        info->callbackArgument = callbackArgument;
        info->queryHandle = queryHandle;
        status = pal_plat_getAddressInfoAsync(info);
        if (status != PAL_SUCCESS) {
            free(info);
        }
    }
    return status;
}

palStatus_t pal_cancelAddressInfoAsync(palDNSQuery_t queryHandle)
{
    return pal_plat_cancelAddressInfoAsync(queryHandle);
}

#if (PAL_DNS_API_VERSION == 3)
palStatus_t pal_getDNSAddress(palAddressInfo_t *addrInfo, uint16_t index, palSocketAddress_t *addr)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == addrInfo) || (NULL == addr))
    PAL_VALIDATE_ARGUMENTS (pal_getDNSCount(addrInfo) <= index)
    return pal_plat_getDNSAddress(addrInfo, index, addr);
}

int pal_getDNSCount(palAddressInfo_t *addrInfo)
{
    return pal_plat_getDNSCount(addrInfo);
}

void pal_freeAddrInfo(palAddressInfo_t* addrInfo)
{
    pal_plat_freeAddrInfo(addrInfo);
}

palStatus_t pal_free_addressinfoAsync(palDNSQuery_t handle)
{
    return pal_plat_free_addressinfoAsync(handle);
}
#endif
#endif //  PAL_DNS_API_VERSION
#endif // PAL_NET_DNS_SUPPORT

uint8_t pal_getRttEstimate()
{
    return pal_plat_getRttEstimate();
}

uint16_t pal_getStaggerEstimate(uint16_t data_amount)
{
    if (_stagger_override_value > 0) {
        PAL_LOG_INFO("Using override for stagger of %d.", _stagger_override_value);
        return _stagger_override_value;
    } else {
        return pal_plat_getStaggerEstimate(data_amount);
    }
}

void pal_setFixedStaggerEstimate(uint16_t stagger_estimate)
{
    _stagger_override_value = stagger_estimate;
}
