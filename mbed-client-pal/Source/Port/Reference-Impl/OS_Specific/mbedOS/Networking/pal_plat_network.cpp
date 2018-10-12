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


#include "pal.h"
#include "pal_plat_network.h"

#include "mbed.h"

#define TRACE_GROUP "PAL"

typedef void(*palSelectCallbackFunction_t)();

#if defined (__CC_ARM) || defined(__IAR_SYSTEMS_ICC__)

void palSelectCallbackNull(void* arg)
{
}

#define NULL_FUNCTION palSelectCallbackNull


#elif defined (__GNUC__)

#define NULL_FUNCTION NULL

#endif


#define PAL_SOCKET_OPTION_ERROR (-1)


typedef enum {
    PAL_PLAT_SOCKET_NOT_CONNECTED = 0,
    PAL_PLAT_SOCKET_CONNECTING = 1,
    PAL_PLAT_SOCKET_CONNECTED = 2

} palConnectState;


void palConnectCallBack()
{
}

        class PALSocketWrapper
        {
        public:
            PALSocketWrapper() : initialized(false), activeSocket(NULL), isNonBlockingOnCreation(false), callbackFunction(NULL_FUNCTION), callbackArgument(NULL), selectCallbackFunction(NULL), connectState(PAL_PLAT_SOCKET_NOT_CONNECTED), socketTypeVal(PAL_SOCK_DGRAM), attachCallbackObject(NULL), rxBuffer(0), rxBufferSet(false)
        {

            }
            nsapi_error_t initialize(Socket* socket, palSocketType_t socketType,bool isNonBlocking, palAsyncSocketCallback_t callback, void* argument);
            palAsyncSocketCallback_t getCallback( ) const;
            void* getCallbackArgument() const ;
            bool isNonBlocking() const ;
            bool isConnected() const ;
            void attachCallback();
            Socket* getActiveSocket();
            palSocketType_t getSocketType() const;
            char getAndResetRxBuffer();
            bool isRxBufferSet() const;
            palStatus_t setRxBuffer(char data);
            void updateCallback(/*palAsyncSocketCallback_t callback, void* argument,*/ palSelectCallbackFunction_t selectCallback);
            virtual ~PALSocketWrapper()
            {
                if (NULL != activeSocket  )
                {
                    activeSocket->close();
                    delete activeSocket;
                }
            }

            // nsapi socket funcitons exposed:
            nsapi_error_t close();
            nsapi_error_t bind(const SocketAddress &address);
            void set_blocking(bool blocking);
            void set_timeout(int timeout);
            nsapi_error_t setsockopt(int level, int optname, const void *optval, unsigned optlen);
            nsapi_error_t getsockopt(int level, int optname, void *optval, unsigned *optlen);
            void attach(mbed::Callback<void()> func);
            //void sigio(mbed::Callback<void()> func); // switch attach to sigio for verison 5.4
            // nsapi UDP socket funcitons exposed:
            nsapi_size_or_error_t recvfrom(SocketAddress *address, void *data, nsapi_size_t size);
            nsapi_size_or_error_t sendto(const SocketAddress &address, const void *data, nsapi_size_t size);
            //nsapi TCP socket funcitons exposed:
            nsapi_error_t connect(const SocketAddress &address);
            nsapi_size_or_error_t send(const void *data, nsapi_size_t size);
            nsapi_size_or_error_t recv(void *data, nsapi_size_t size);
            //nsapi TCP server socket funcitons exposed:
            nsapi_error_t listen(int backlog = 1);
            nsapi_error_t accept(TCPSocket *connection, SocketAddress *address = NULL);


        private:
            bool initialized;
            Socket* activeSocket;
            bool isNonBlockingOnCreation;
            palAsyncSocketCallback_t callbackFunction;
            void* callbackArgument;
            palSelectCallbackFunction_t selectCallbackFunction;
            palConnectState connectState;
            palSocketType_t socketTypeVal;
            Callback<void()> attachCallbackObject;
            events::EventQueue* shared_event_queue;
            char rxBuffer;
            bool rxBufferSet;
        };

        void PALSocketWrapper::updateCallback( palSelectCallbackFunction_t selectCallback )
        {
            bool shouldSetCallback = false;
            if ((NULL == selectCallbackFunction) && (NULL == callbackFunction)) //callback already set - no need to set again
            {
                shouldSetCallback = true;
            }

            selectCallbackFunction = selectCallback;

            if ((NULL != selectCallbackFunction) || (NULL != callbackFunction))
            {
                if (shouldSetCallback)
                {
                    Callback<void()> mycall(this, &PALSocketWrapper::attachCallback);
                    activeSocket->sigio(mycall);
                }
            }
            else
            {
                activeSocket->sigio(NULL);
            }
        }

        Socket* PALSocketWrapper::getActiveSocket()
        {
            return activeSocket;
        }

        char PALSocketWrapper::getAndResetRxBuffer()
        {
            rxBufferSet = false;
            return rxBuffer;
        }

        bool PALSocketWrapper::isRxBufferSet() const
        {
            return rxBufferSet;
        }

        palStatus_t PALSocketWrapper::setRxBuffer( char data)
        {
            PAL_VALIDATE_CONDITION_WITH_ERROR((true == rxBufferSet), PAL_ERR_SOCKET_GENERIC);

            rxBuffer = data;
            rxBufferSet = true;

            return PAL_SUCCESS;
        }

        palAsyncSocketCallback_t PALSocketWrapper::getCallback() const
        {
            return callbackFunction;
        }

        palSocketType_t  PALSocketWrapper::getSocketType() const
        {
            return socketTypeVal;
        }


        void * PALSocketWrapper::getCallbackArgument() const
        {
            return callbackArgument;
        }

        bool PALSocketWrapper::isNonBlocking() const
        {
            return isNonBlockingOnCreation;
        }

        bool PALSocketWrapper::isConnected() const
        {
            return ((PAL_PLAT_SOCKET_CONNECTED == connectState) && (PAL_SOCK_STREAM == socketTypeVal));
        }

        void PALSocketWrapper::attachCallback()
        {
            if (NULL != callbackFunction)
            {
                // Since the socket callback may be called from interrupt context, depending on the
                // network interface used, we need to debounce the client callback to happen from
                // a thread context to keep client side implementation platform agnostic.
                assert(shared_event_queue);
                shared_event_queue->call(callbackFunction, callbackArgument);
            }
            if (NULL != selectCallbackFunction)
            {
                // Note: this is not tested yet
                assert(shared_event_queue);
                shared_event_queue->call(selectCallbackFunction);
            }
            if (PAL_PLAT_SOCKET_CONNECTING == connectState)
            {
                connectState = PAL_PLAT_SOCKET_CONNECTED;// if we got a callback while connecting assume we are connected
                if (palConnectCallBack == selectCallbackFunction)
                {
                    selectCallbackFunction = NULL;
                }
            }
        }

        nsapi_error_t  PALSocketWrapper::initialize(Socket* socket, palSocketType_t socketType, bool isNonBlocking, palAsyncSocketCallback_t callback, void* argument)
        {
        // check that we got a valid socket and the socket type is supported
            PAL_VALIDATE_CONDITION_WITH_ERROR(((true == initialized) || (NULL == socket) ||
                                              ((socketType != PAL_SOCK_STREAM) && (socketType != PAL_SOCK_STREAM_SERVER) &&
                                               (socketType != PAL_SOCK_DGRAM))),NSAPI_ERROR_PARAMETER);


            // Pre fetch and store the shared queue used for bouncing the callbacks out of interrupt
            // context, as the user of it may be ran from interrupt and it can't go and start
            // creating worker threads from there.
            // Note: the code uses mbed_highprio_event_queue() instead of mbed_event_queue()
            // as the high priority queue and its thread is likely there already thanks to
            // arm_hal_timer.cpp. Technically the client side does not really care, if the events
            // were delayed a bit by other events or not.
            shared_event_queue = mbed_highprio_event_queue();
            PAL_VALIDATE_CONDITION_WITH_ERROR((shared_event_queue == NULL),NSAPI_ERROR_UNSUPPORTED);

            Callback<void()> mycall(this, &PALSocketWrapper::attachCallback);
            attachCallbackObject = mycall;
            activeSocket = socket;
            socketTypeVal = socketType;
            isNonBlockingOnCreation = isNonBlocking;
            activeSocket->set_blocking(!isNonBlocking);
            if (NULL != callback)
            {
                callbackFunction = callback;
                callbackArgument = argument;
                activeSocket->sigio(attachCallbackObject);
            }

            initialized = true;
            return NSAPI_ERROR_OK;
        }

        nsapi_error_t PALSocketWrapper::close()
        {
            nsapi_error_t status= NSAPI_ERROR_OK;
            if (NULL != activeSocket)
            {
                status = activeSocket->close();
                delete activeSocket;
                activeSocket = NULL;
            }
            return  status;
        }

        nsapi_error_t PALSocketWrapper::bind(const SocketAddress &address)
        {
            nsapi_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR((false == initialized), NSAPI_ERROR_PARAMETER);
            status= activeSocket->bind(address);
            return  status;
        }

        void PALSocketWrapper::set_blocking(bool blocking)
        {
            activeSocket->set_blocking(blocking);
        }

        void PALSocketWrapper::set_timeout(int timeout)
        {
            activeSocket->set_timeout(timeout);
        }

        nsapi_error_t PALSocketWrapper::setsockopt(int level, int optname, const void *optval, unsigned optlen)
        {
            nsapi_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR((false == initialized),NSAPI_ERROR_PARAMETER);
            status = activeSocket->setsockopt(level,  optname, optval,  optlen);
            return  status;
        }

        nsapi_error_t PALSocketWrapper::getsockopt(int level, int optname, void *optval, unsigned *optlen)
        {
            nsapi_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR((false == initialized),NSAPI_ERROR_PARAMETER);
            status = activeSocket->getsockopt( level,  optname,  optval,  optlen);
            return  status;
        }

        void PALSocketWrapper::attach(mbed::Callback<void()> func)
        {
            activeSocket->sigio(func);
        }
        //void sigio(mbed::Callback<void()> func); // switch attach to sigio for verison 5.4
        // nsapi UDP socket funcitons exposed:
        nsapi_size_or_error_t PALSocketWrapper::recvfrom(SocketAddress *address, void *data, nsapi_size_t size)
        {
            nsapi_size_or_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_DGRAM != socketTypeVal)), NSAPI_ERROR_PARAMETER); // udp sockets only

            status = ((UDPSocket*)activeSocket)->recvfrom(address, data,  size);
            return  status;
        }

        nsapi_size_or_error_t PALSocketWrapper::sendto(const SocketAddress &address, const void *data, nsapi_size_t size)
        {
            nsapi_size_or_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_DGRAM != socketTypeVal)), NSAPI_ERROR_PARAMETER); // udp sockets only
            status = ((UDPSocket*)activeSocket)->sendto(address, data, size);
            return  status;
        }

        //nsapi TCP socket funcitons exposed:
        nsapi_error_t PALSocketWrapper::connect(const SocketAddress &address)
        {
            nsapi_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_STREAM != socketTypeVal)), NSAPI_ERROR_PARAMETER);  // tcp sockets only

            connectState = PAL_PLAT_SOCKET_CONNECTING;
            updateCallback(palConnectCallBack); // make sure callback is enabled to see if we get callback to signal connections end
            status = ((TCPSocket*)activeSocket)->connect(address);
            if (status >= 0 || status == NSAPI_ERROR_IS_CONNECTED)
            {
                connectState = PAL_PLAT_SOCKET_CONNECTED;
                updateCallback(NULL); // make sure callback is enabled to see if we get callback to signal connections end
            }
            else if ((NSAPI_ERROR_WOULD_BLOCK != status) && (NSAPI_ERROR_IN_PROGRESS != status) && (NSAPI_ERROR_ALREADY != status))
            {
                connectState = PAL_PLAT_SOCKET_NOT_CONNECTED;
            }
            return  status;
        }

        nsapi_size_or_error_t PALSocketWrapper::send(const void *data, nsapi_size_t size)
        {
            nsapi_size_or_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_STREAM != socketTypeVal)), NSAPI_ERROR_PARAMETER); // tcp sockets only

            status = ((TCPSocket*)activeSocket)->send( data, size);
            return  status;
        }

        nsapi_size_or_error_t PALSocketWrapper::recv(void *data, nsapi_size_t size)
        {
            nsapi_size_or_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_STREAM != socketTypeVal)),NSAPI_ERROR_PARAMETER); // tcp sockets only
            status = ((TCPSocket*)activeSocket)->recv(data, size);
            return  status;
        }
        //nsapi TCP server socket funcitons exposed:
        nsapi_error_t PALSocketWrapper::listen(int backlog )
        {
            nsapi_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_STREAM_SERVER != socketTypeVal)), NSAPI_ERROR_PARAMETER); // udp sockets only
            status = ((TCPServer*)activeSocket)->listen(backlog);
            return  status;
        }

        nsapi_error_t PALSocketWrapper::accept(TCPSocket *connection, SocketAddress *address)
        {
            nsapi_error_t status = NSAPI_ERROR_OK;
            PAL_VALIDATE_CONDITION_WITH_ERROR(((false == initialized) || (PAL_SOCK_STREAM_SERVER != socketTypeVal)),NSAPI_ERROR_PARAMETER); // udp sockets only

            status = ((TCPServer*)activeSocket)->accept(connection, address);
            return  status;
        }




PAL_PRIVATE NetworkInterface* s_pal_networkInterfacesSupported[PAL_MAX_SUPORTED_NET_INTERFACES] = { 0 };

PAL_PRIVATE  uint32_t s_pal_numberOFInterfaces = 0;

PAL_PRIVATE  uint32_t s_pal_network_initialized = 0;

PAL_PRIVATE palStatus_t translateErrorToPALError(int errnoValue)
{
    palStatus_t status;
    switch (errnoValue)
    {
    case NSAPI_ERROR_NO_MEMORY:
        status = PAL_ERR_NO_MEMORY;
        break;
    case NSAPI_ERROR_PARAMETER:
        status = PAL_ERR_SOCKET_INVALID_VALUE;
        break;
    case NSAPI_ERROR_WOULD_BLOCK:
        status = PAL_ERR_SOCKET_WOULD_BLOCK;
        break;
    case NSAPI_ERROR_DNS_FAILURE:
        status = PAL_ERR_SOCKET_DNS_ERROR;
        break;
    case NSAPI_ERROR_DHCP_FAILURE:
        status = PAL_ERR_SOCKET_HDCP_ERROR;
        break;
    case NSAPI_ERROR_AUTH_FAILURE:
        status = PAL_ERR_SOCKET_AUTH_ERROR;
        break;
    case NSAPI_ERROR_NO_ADDRESS:
        status = PAL_ERR_SOCKET_INVALID_ADDRESS;
        break;
    case NSAPI_ERROR_NO_CONNECTION:
        status = PAL_ERR_SOCKET_NOT_CONNECTED;
        break;
    case NSAPI_ERROR_DEVICE_ERROR:
        status = PAL_ERR_SOCKET_INPUT_OUTPUT_ERROR;
        break;
    case NSAPI_ERROR_UNSUPPORTED:
        status = PAL_ERR_NOT_SUPPORTED;
        break;
    case NSAPI_ERROR_NO_SOCKET:
        status = PAL_ERR_SOCKET_ALLOCATION_FAILED;
        break;
    case NSAPI_ERROR_IN_PROGRESS:
    case NSAPI_ERROR_ALREADY:
        status = PAL_ERR_SOCKET_IN_PROGRES;
        break;
    case NSAPI_ERROR_IS_CONNECTED:
        status = PAL_SUCCESS;
        break;
    default:
        PAL_LOG_ERR("translateErrorToPALError() cannot translate %d", errnoValue);
        status = PAL_ERR_SOCKET_GENERIC;
        break;
    }
    return status;
}

palStatus_t pal_plat_socketsInit(void* context)
{
    (void)context; // replace with macro
    int result = PAL_SUCCESS;
    if (s_pal_network_initialized == 1)
    {
        return PAL_SUCCESS; // already initialized.
    }

    s_pal_network_initialized = 1;

    return result;
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
            s_pal_networkInterfacesSupported[s_pal_numberOFInterfaces] = (NetworkInterface*)context;
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

palStatus_t pal_plat_socketsTerminate(void* context)
{
    (void)context; // replace with macro
    return PAL_SUCCESS;
}

PAL_PRIVATE int translateNSAPItoPALSocketOption(int option)
{
    int optionVal = PAL_SOCKET_OPTION_ERROR;
    switch (option)
    {
    case PAL_SO_REUSEADDR:
        optionVal = NSAPI_REUSEADDR;
        break;
#if PAL_NET_TCP_AND_TLS_SUPPORT // socket options below supported only if TCP is supported.
    case PAL_SO_KEEPALIVE:
        optionVal = NSAPI_KEEPALIVE;
        break;
    case PAL_SO_KEEPIDLE:
        optionVal = NSAPI_KEEPIDLE;
        break;
    case PAL_SO_KEEPINTVL:
        optionVal = NSAPI_KEEPINTVL;
        break;
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    case PAL_SO_SNDTIMEO:
    case PAL_SO_RCVTIMEO:
    default:
        optionVal = PAL_SOCKET_OPTION_ERROR;
    }
    return optionVal;
}


PAL_PRIVATE palStatus_t palSockAddrToSocketAddress(const palSocketAddress_t* palAddr, int length, SocketAddress& output)
{
    palStatus_t result = PAL_SUCCESS;
    uint16_t port = 0;
    nsapi_version_t version = NSAPI_IPv4;

    result = pal_getSockAddrPort(palAddr, &port);
    if (result != PAL_SUCCESS)
    {
        return result;
    }
    output.set_port(port);

#if PAL_SUPPORT_IP_V4
    if (PAL_AF_INET == palAddr->addressType)
    {
        palIpV4Addr_t ipV4Addr;
        version = NSAPI_IPv4;
        result = pal_getSockAddrIPV4Addr(palAddr, ipV4Addr);
        if (result == PAL_SUCCESS)
        {
            output.set_ip_bytes(&ipV4Addr, version);
        }
    }
#endif
#if PAL_SUPPORT_IP_V6
    if (PAL_AF_INET6 == palAddr->addressType)
    {
        palIpV6Addr_t ipV6Addr;
        version = NSAPI_IPv6;
        result = pal_getSockAddrIPV6Addr(palAddr, ipV6Addr);
        if (result == PAL_SUCCESS)
        {
            output.set_ip_bytes(&ipV6Addr, version);
        }
    }
#endif

    return result;
}

#if (PAL_DNS_API_VERSION != 2)
PAL_PRIVATE palStatus_t socketAddressToPalSockAddr(SocketAddress& input, palSocketAddress_t* out, palSocketLength_t* length)
#else
PAL_PRIVATE palStatus_t socketAddressToPalSockAddr(SocketAddress& input, palSocketAddress_t* out)
#endif
{
    palStatus_t result = PAL_SUCCESS;
    int index = 0;
    bool found = false;

#if PAL_SUPPORT_IP_V4
    if (input.get_ip_version() == NSAPI_IPv4)
    {
        palIpV4Addr_t addr;
        found = true;
        const void* tmp = input.get_ip_bytes();
        for (index = 0; index < PAL_IPV4_ADDRESS_SIZE; index++)
        {
            addr[index] = ((const uint8_t*)tmp)[index];
        }
        result = pal_setSockAddrIPV4Addr(out, addr);
#if (PAL_DNS_API_VERSION != 2)
        *length = PAL_NET_MAX_ADDR_SIZE;  // TODO: check
#endif

    }
#endif
#if PAL_SUPPORT_IP_V6
    if (input.get_ip_version() == NSAPI_IPv6)
    {
        palIpV6Addr_t addr;
        found = true;
        const void* tmp = input.get_ip_bytes();
        for (index = 0; index < PAL_IPV6_ADDRESS_SIZE; index++)
        {
            addr[index] = ((const uint8_t*)tmp)[index];
        }
        result = pal_setSockAddrIPV6Addr(out, addr);
#if (PAL_DNS_API_VERSION != 2)
        *length = PAL_NET_MAX_ADDR_SIZE;  // TODO: check
#endif
    }
#endif
    if (false == found )
    {
        result = PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    }

    if (result == PAL_SUCCESS)
    {
        result = pal_setSockAddrPort(out, input.get_port());
    }
    return result;
}




palStatus_t pal_plat_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* socket)
{
    int result = PAL_SUCCESS;
    PALSocketWrapper* socketObj = NULL;
    Socket* internalSocket = NULL;

    PAL_VALIDATE_ARGUMENTS((NULL == socket))

    if (PAL_NET_DEFAULT_INTERFACE == interfaceNum)
    {
        interfaceNum = 0;
    }

    if ((s_pal_numberOFInterfaces > interfaceNum) && (PAL_SOCK_DGRAM == type) && ((PAL_AF_INET == domain) || (PAL_AF_INET6 == domain) || (PAL_AF_UNSPEC == domain))) // check correct parameters for UDP socket
    {
        internalSocket = new UDPSocket(s_pal_networkInterfacesSupported[interfaceNum]);
    }
#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.
    else if ((s_pal_numberOFInterfaces > interfaceNum) && (PAL_SOCK_STREAM == type) && ((PAL_AF_INET == domain) || (PAL_AF_INET6 == domain) || (PAL_AF_UNSPEC == domain))) // check correct parameters for TCP socket
    {
        internalSocket = new TCPSocket(s_pal_networkInterfacesSupported[interfaceNum]);
    }
    else if ((s_pal_numberOFInterfaces > interfaceNum) && (PAL_SOCK_STREAM_SERVER == type) && ((PAL_AF_INET == domain) || (PAL_AF_INET6 == domain) || (PAL_AF_UNSPEC == domain))) // check correct parameters for TCP Server socket
    {
        internalSocket = new TCPServer(s_pal_networkInterfacesSupported[interfaceNum]);
    }
#endif
    else
    {
        result =  PAL_ERR_INVALID_ARGUMENT;
    }

    if ((PAL_SUCCESS == result ) && (NULL == internalSocket))
    {
        result = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == result)
    {

        socketObj = new PALSocketWrapper();
        if (NULL != socketObj)
        {
            if (0 == socketObj->initialize(internalSocket, type, nonBlockingSocket, NULL, NULL))
            {
                *socket = (palSocket_t)socketObj;
            }
            else
            {
                result = PAL_ERR_INVALID_ARGUMENT;
            }

        }
        else
        {
            delete internalSocket;
            result = PAL_ERR_NO_MEMORY;
        }

    }

    if (PAL_SUCCESS != result) //cleanup
    {
        if (NULL != internalSocket)
        {
            delete internalSocket;
        }
        if (NULL != socketObj)
        {
            delete socketObj;
        }
    }
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}


palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
    int result = PAL_SUCCESS;
    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    int socketOption = PAL_SOCKET_OPTION_ERROR;

    PAL_VALIDATE_ARGUMENTS(NULL == socket);

    socketOption = translateNSAPItoPALSocketOption(optionName);
    if (PAL_SOCKET_OPTION_ERROR != socketOption)
    {
        if (PAL_SO_REUSEADDR == optionName)
        {
            result = socketObj->setsockopt(NSAPI_SOCKET, socketOption, optionValue, optionLength);
        }
#if PAL_NET_TCP_AND_TLS_SUPPORT
        else if (PAL_SO_KEEPIDLE == optionName ||
                 PAL_SO_KEEPINTVL == optionName )
        {
                // Timeouts are in milliseconds
                uint32_t timeout = (*(int *)optionValue) * 1000;
                result = socketObj->setsockopt(NSAPI_SOCKET, socketOption, (void*)&timeout, sizeof(timeout));
        }
#endif
        else
        {
            result = socketObj->setsockopt(NSAPI_SOCKET, socketOption, optionValue, optionLength);
        }

        if (result < 0)
        {
            result = translateErrorToPALError(result);
        }
    }
    else
    {
        if ((PAL_SO_SNDTIMEO == optionName) || (PAL_SO_RCVTIMEO == optionName)) // timeouts in MBED API are not managed though socket options, bun instead via a different funciton call
        {
            int timeout = *((int*)optionValue);
            // SO_xxxTIMEO should only affect blocking sockets - it only limits the block,
            // whereas NSAPI's set_timeout is coupled with the blocking setting
            if (!socketObj->isNonBlocking()) {
                socketObj->set_timeout(timeout);
            }
        }
        else
        {
            result = PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
        }
    }


    return result;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    PALSocketWrapper* socketObj =  NULL;
    PAL_VALIDATE_ARGUMENTS(NULL == socket);

    socketObj =  (PALSocketWrapper*)socket;

    *isNonBlocking = socketObj->isNonBlocking();

    return PAL_SUCCESS;

}

palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
    int result = PAL_SUCCESS;
    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    SocketAddress internalAddr;

    PAL_VALIDATE_ARGUMENTS ((NULL == socket));

    result = palSockAddrToSocketAddress(myAddress, addressLength, internalAddr);
    if (result == 0)
    {
        result = socketObj->bind(internalAddr);
        if (result < 0)
        {
            result =  translateErrorToPALError(result);
        }
    }

    return result;
}


palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    int result = PAL_SUCCESS;
    int status = 0;
    *bytesReceived = 0;
    SocketAddress sockAddr;
    PALSocketWrapper* socketObj;
    uint8_t* internalBufferPtr = (uint8_t*)buffer;
    uint32_t bufferUsed = 0;

    PAL_VALIDATE_ARGUMENTS((NULL == socket));

    socketObj = (PALSocketWrapper*)socket;

    if (true == socketObj->isRxBufferSet())
    {
        internalBufferPtr[0] = socketObj->getAndResetRxBuffer();
        internalBufferPtr++;
        length--;
        bufferUsed += 1;
    }

    if (length > 0)
    {
        status = socketObj->recvfrom(&sockAddr, internalBufferPtr, length);
        if (status < 0)
        {
            result = translateErrorToPALError(status);
        }
        else if (status == 0)
        {
            result = PAL_ERR_SOCKET_CONNECTION_CLOSED;
        }
        else // only return address / bytesReceived in case of success
        {
#if (PAL_DNS_API_VERSION != 2)
            if ((NULL != from) && (NULL != fromLength))
            {
                result = socketAddressToPalSockAddr(sockAddr, from, fromLength);
            }
#else
            if (NULL != from)
            {
                result = socketAddressToPalSockAddr(sockAddr, from);
            }
#endif
            *bytesReceived = status + bufferUsed;
        }
    }
    else
    {
        *bytesReceived = bufferUsed;
    }

    return result;

}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
    int result = PAL_SUCCESS;
    int status = 0;
    SocketAddress sockAddr;

    PAL_VALIDATE_ARGUMENTS((NULL == socket));

    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;

    *bytesSent = 0;
    result = palSockAddrToSocketAddress(to, toLength, sockAddr);
    if (result == 0)
    {
        status = socketObj->sendto(sockAddr, buffer, length);
        if (status < 0)
        {
            result = translateErrorToPALError(status);
        }
        else
        {
            *bytesSent = status;
        }
    }

    return result;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    int result = PAL_SUCCESS;
    if (NULL == *socket)
    {
        PAL_LOG_DBG("socket close called on socket which was already closed");
        return result; // socket already closed (or not opened) - no need to close.
    }
    PALSocketWrapper* socketObj = (PALSocketWrapper*)*socket;
    result = socketObj->close();
    if (result < 0)
    {
        result =  translateErrorToPALError(result);
    }
    delete socketObj;
    *socket = NULL;
    return result;
}

palStatus_t pal_plat_getNumberOfNetInterfaces( uint32_t* numInterfaces)
{
    *numInterfaces =  s_pal_numberOFInterfaces;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t * interfaceInfo)
{
    palStatus_t result = PAL_SUCCESS;
    const char* address = NULL;
    SocketAddress addr;
    PAL_VALIDATE_ARGUMENTS((interfaceNum >= s_pal_numberOFInterfaces));

    address = s_pal_networkInterfacesSupported[interfaceNum]->get_ip_address(); // ip address returned is a null terminated string
    if (NULL != address)
    {
        addr.set_ip_address(address);
#if (PAL_DNS_API_VERSION != 2)
        result = socketAddressToPalSockAddr(addr, &interfaceInfo->address, &interfaceInfo->addressSize);
#else
        result = socketAddressToPalSockAddr(addr, &interfaceInfo->address);
#endif
    }


    return result;
}

typedef void(*palSelectCallbackFunction_t)();

PAL_PRIVATE palSemaphoreID_t s_palSelectSemaphore = 0;

uint32_t s_select_event_happened[PAL_NET_SOCKET_SELECT_MAX_SOCKETS];

// select callbacks definition
// TODO: nirson01 change to define these using a macro.
void palSelectCallback0()
{
    s_select_event_happened[0]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback1()
{
    s_select_event_happened[1]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback2()
{
    s_select_event_happened[2]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback3()
{
    s_select_event_happened[3]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback4()
{
    s_select_event_happened[4]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback5()
{
    s_select_event_happened[5]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback6()
{
    s_select_event_happened[6]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}
void palSelectCallback7()
{
    s_select_event_happened[7]++;
    pal_osSemaphoreRelease(s_palSelectSemaphore);
}

palSelectCallbackFunction_t s_palSelectPalCallbackFunctions[PAL_NET_SOCKET_SELECT_MAX_SOCKETS] = { palSelectCallback0, palSelectCallback1, palSelectCallback2, palSelectCallback3, palSelectCallback4, palSelectCallback5, palSelectCallback6, palSelectCallback7 };


#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.


palStatus_t pal_plat_listen(palSocket_t socket, int backlog)
{
    int result = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS(NULL == socket);

    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    result = socketObj->listen(backlog);
    if (result < 0)
    {
        return translateErrorToPALError(result);
    }
    return PAL_SUCCESS;
}


palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t * address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket)
{
    int result = PAL_SUCCESS;

    SocketAddress incomingAddr;

    PAL_VALIDATE_ARGUMENTS ((NULL == socket));

    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    result = socketObj->accept( (TCPSocket*)(*(PALSocketWrapper**)acceptedSocket)->getActiveSocket(), &incomingAddr);
    if (result < 0)
    {
        result = translateErrorToPALError(result);
    }
    else
    {
#if (PAL_DNS_API_VERSION != 2)
        result = socketAddressToPalSockAddr(incomingAddr, address, addressLen);
#else
        result = socketAddressToPalSockAddr(incomingAddr, address);
#endif
    }
    return result;
}


palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    int result = PAL_SUCCESS;
    SocketAddress internalAddr;
    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    PAL_VALIDATE_ARGUMENTS ((NULL == socket));

    result = palSockAddrToSocketAddress(address, addressLen,  internalAddr);
    if (result == PAL_SUCCESS)
    {
        result = socketObj->connect(internalAddr);
        if (result < 0)
        {
            result =  translateErrorToPALError(result);
        }
    }

    return result;
}

palStatus_t pal_plat_recv(palSocket_t socket, void *buf, size_t len, size_t* recievedDataSize)
{
    int result = PAL_SUCCESS;
    int status = 0;
    uint8_t* internalBufferPtr = (uint8_t*)buf;
    uint32_t bufferUsed = 0;

    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    PAL_VALIDATE_ARGUMENTS ((NULL == socket));

    if (true == socketObj->isRxBufferSet())
    {
        internalBufferPtr[0] = socketObj->getAndResetRxBuffer();
        internalBufferPtr++;
        len--;
        bufferUsed += 1;
    }

    if (len > 0)
    {
        status = socketObj->recv(internalBufferPtr, len);
        if (status < 0)
        {
            result = translateErrorToPALError(status);
        }
        else if (status == 0) {
            return PAL_ERR_SOCKET_CONNECTION_CLOSED;
        }
    }
    *recievedDataSize = status + bufferUsed;
    return result;
}

palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t* sentDataSize)
{
    palStatus_t result = PAL_SUCCESS;
    int status = 0;

    PALSocketWrapper* socketObj = (PALSocketWrapper*)socket;
    PAL_VALIDATE_ARGUMENTS ((NULL == socket));

    status = socketObj->send(buf, len);

    if (status < 0)
    {
        PAL_LOG_DBG("pal_plat_send status %d",status);
        result = translateErrorToPALError(status);
    }
    else
    {
        *sentDataSize = status;
    }
    return result;
}

#endif //PAL_NET_TCP_AND_TLS_SUPPORT


#if PAL_NET_ASYNCHRONOUS_SOCKET_API


palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* arg,  palSocket_t* socket)
{
    int result = PAL_SUCCESS;
    PALSocketWrapper * socketObj = NULL;
    Socket* internalSocket = NULL;

    PAL_VALIDATE_ARGUMENTS((NULL == socket));

    if (PAL_NET_DEFAULT_INTERFACE == interfaceNum)
    {
        interfaceNum = 0;
    }

    if ((s_pal_numberOFInterfaces > interfaceNum) && (PAL_SOCK_DGRAM == type) && ((PAL_AF_INET == domain) || (PAL_AF_INET6 == domain) || (PAL_AF_UNSPEC == domain))) //check that we got correct parameters for UDP socket
    {
        internalSocket = new UDPSocket(s_pal_networkInterfacesSupported[interfaceNum]);
    }
#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.
    else if ((s_pal_numberOFInterfaces > interfaceNum) && (PAL_SOCK_STREAM == type) && ((PAL_AF_INET == domain) || (PAL_AF_INET6 == domain) || (PAL_AF_UNSPEC == domain))) //check that we got correct parameters for TCP socket
    {
        internalSocket = new TCPSocket(s_pal_networkInterfacesSupported[interfaceNum]);
    }
    else if ((s_pal_numberOFInterfaces > interfaceNum) && (PAL_SOCK_STREAM_SERVER == type) && ((PAL_AF_INET == domain) || (PAL_AF_INET6 == domain) || (PAL_AF_UNSPEC == domain))) //check that we got correct parameters for TCP Server socket
    {
        internalSocket = new TCPServer(s_pal_networkInterfacesSupported[interfaceNum]);
    }
#endif
    else
    {
        result = PAL_ERR_INVALID_ARGUMENT;
    }

    if ((PAL_SUCCESS == result) && (NULL == internalSocket))
    {
        result = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == result)
    {
        socketObj = new PALSocketWrapper();
        if (NULL != socketObj)
        {
            if (0 == socketObj->initialize(internalSocket, type, nonBlockingSocket, callback, arg))
            {
                *socket = (palSocket_t)socketObj;
            }
            else
            {
                result = PAL_ERR_INVALID_ARGUMENT;
            }
        }
        else
        {
            delete internalSocket;
            result = PAL_ERR_NO_MEMORY;
        }
    }

    if (PAL_SUCCESS != result) //cleanup
    {
        if (NULL != internalSocket)
        {
            delete internalSocket;
        }
        if (NULL != socketObj)
        {
            delete socketObj;
        }
    }
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
}

#endif

#if PAL_NET_DNS_SUPPORT
#if (PAL_DNS_API_VERSION == 0) || (PAL_DNS_API_VERSION == 1)
palStatus_t pal_plat_getAddressInfo(const char *url, palSocketAddress_t *address, palSocketLength_t* length)
{
    palStatus_t result = PAL_SUCCESS;
    SocketAddress translatedAddress; // by default use the fist supported net interface - TODO: do we need to select a different interface?

#if PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_ANY
    result = s_pal_networkInterfacesSupported[0]->gethostbyname(url, &translatedAddress);
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV4_ONLY
    result = s_pal_networkInterfacesSupported[0]->gethostbyname(url, &translatedAddress, NSAPI_IPv4);
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV6_ONLY
    result = s_pal_networkInterfacesSupported[0]->gethostbyname(url, &translatedAddress, NSAPI_IPv6);
#else
#error PAL_NET_DNS_IP_SUPPORT is not defined to a valid value.
#endif

    if (result == 0) {
        result = socketAddressToPalSockAddr(translatedAddress, address, length);
    }
    else { // error happened
        result = translateErrorToPALError(result);
    }
    return result;
}

#elif (PAL_DNS_API_VERSION == 2)
void pal_plat_getAddressInfoAsync_callback(void *data, nsapi_error_t result, SocketAddress *address)
{
    palStatus_t status = PAL_SUCCESS;
    pal_asyncAddressInfo_t* info = (pal_asyncAddressInfo_t*)(data);

    if (result == NSAPI_ERROR_OK) {
        status = socketAddressToPalSockAddr(*address, info->address);
    }
    else { // error happened
        status = translateErrorToPALError(result);
    }

    info->callback(info->url, info->address, status, info->callbackArgument); // invoke callback
    free(info);
}

palStatus_t pal_plat_getAddressInfoAsync(pal_asyncAddressInfo* info)
{
    PAL_LOG_DBG("pal_plat_getAddressInfoAsync");
    palStatus_t result;
#if PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_ANY
    const nsapi_version_t version = NSAPI_UNSPEC;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV4_ONLY
    const nsapi_version_t version = NSAPI_IPv4;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV6_ONLY
    const nsapi_version_t version = NSAPI_IPv6;
#else
#error PAL_NET_DNS_IP_SUPPORT is not defined to a valid value.
#endif

    result = s_pal_networkInterfacesSupported[0]->gethostbyname_async(info->url, mbed::Callback<void(nsapi_error_t, SocketAddress *)>(pal_plat_getAddressInfoAsync_callback,(void*)info), version);
    PAL_LOG_DBG("pal_plat_getAddressInfoAsync result %d", result);
    if (result < 0) {
        result = translateErrorToPALError(result);
    }
    else {
        /* Skip over setting queryHandle when:
         * 1. info->queryHandle not allocated  
         * 2. if result is zero then callback pal_plat_getAddressInfoAsync_callback will be called immediately and address info has been deallocated. */
        if ( (info->queryHandle != NULL) && result) {
            *(info->queryHandle) = result;
        }
        result = PAL_SUCCESS;
    }
    return result;
}

palStatus_t pal_plat_cancelAddressInfoAsync(palDNSQuery_t queryHandle)
{
    palStatus_t status = s_pal_networkInterfacesSupported[0]->gethostbyname_async_cancel(queryHandle);
    if (PAL_SUCCESS != status) {
        PAL_LOG_ERR("pal_cancelAddressInfoAsync failed with %ld", status);
    }
    return status;
}
#else
    #error "Please specify the platform PAL_DNS_API_VERSION 0, 1 or 2."
#endif //  PAL_DNS_API_VERSION
#endif


