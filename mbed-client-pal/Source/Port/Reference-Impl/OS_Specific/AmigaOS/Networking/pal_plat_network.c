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

#define _GNU_SOURCE // This is for ppoll found in poll.h
#include "pal.h"
#include "pal_plat_network.h"
#include "pal_rtos.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
//#include <net/if.h>
#include <netdb.h>
//#include <ifaddrs.h>
#include <errno.h>
#if PAL_NET_ASYNCHRONOUS_SOCKET_API
#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#endif

#define TRACE_GROUP "PAL"

#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
//#include <netinet/tcp.h>
#define SOL_TCP 6
#endif

// invalid socket based on posix
#define PAL_LINUX_INVALID_SOCKET (-1)

PAL_PRIVATE void* s_pal_networkInterfacesSupported[PAL_MAX_SUPORTED_NET_INTERFACES] = { 0 };
PAL_PRIVATE uint32_t s_pal_numberOFInterfaces = 0;
PAL_PRIVATE  uint32_t s_pal_network_initialized = 0;

PAL_PRIVATE palStatus_t translateErrorToPALError(int errnoValue)
{
    palStatus_t status;
    switch (errnoValue)
    {
    // case EAI_MEMORY:
    //     status = PAL_ERR_NO_MEMORY;
    //     break;
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
    default:
        PAL_LOG_ERR("translateErrorToPALError() cannot translate %d", errnoValue);
        status = PAL_ERR_SOCKET_GENERIC;
        break;
    }
    return status;
}

#if PAL_NET_ASYNCHRONOUS_SOCKET_API
/* We don't have poll.h in CLIB2 (or in any other lib for that matter) */
struct pollfd {
    int fd;
    //short events; /* not used */
    short revents; /* not used */
};

/* Type used for the number of file descriptors.  */
typedef unsigned long int nfds_t;

static palThreadID_t s_pollThread = NULLPTR;
static palMutexID_t s_mutexSocketCallbacks = 0;
static palMutexID_t s_mutexSocketEventFilter = 0;
static palSemaphoreID_t s_socketCreateSemaphore = 0;
static palSemaphoreID_t s_socketCallbackSemaphore = 0;
// Replace s_socketCallbackSignalSemaphore with message port that waits for (Wait) signals from:
// - sockets directly: s_palIOCounter++; (ditch the variable as well)
//   * preworkfor this: need to use SocketBaseTags to enable signals from sockets? -> need to implement in CLIB2 (PAIN)
//   * alternatively SetSocketSignals OR try without either and see if there will be any signals -> need to implement in CLIB2 (PAIN)
//   * seems to be the problem is we can't get signal of IO activity, only option is to wait for it
//   * -> can we do with only PPOL instead? Just signal break that when needed? Problem is when there are no sockets, but maybe that can be worked around?
// - sigusr2 (SIGUSR1: pal_plat_socketsTerminate, pal_plat_close, pal_plat_asynchronousSocket): s_palUSR1Counter++; (ditch this as well)
// why are copies needed in async thread? Is that because they may be modified during ppoll?

// These must be updated only when protected by s_mutexSocketCallbacks
static palAsyncSocketCallback_t s_callbacks[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {0};
static void* s_callbackArgs[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = { 0 };
static struct pollfd s_fds[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {{0}};
static struct fd_set s_fdset;
static uint32_t s_callbackFilter[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {0};
static nfds_t s_nfds = 0;
static volatile bool s_socketThreadTerminateSignaled = false;

struct create_socket {
    palSocketDomain_t domain;
    palSocketType_t type;
    bool nonBlockingSocket;
    uint32_t interfaceNum;
    palSocket_t* socket;
    palStatus_t result;
};

static struct create_socket s_async_socket;


static const unsigned int PAL_SOCKETS_TERMINATE = 10000;

PAL_PRIVATE void clearSocketFilter( int socketFD)
{
    palStatus_t result = PAL_SUCCESS;
    int i = 0;
    result = pal_osMutexWait(s_mutexSocketEventFilter, PAL_RTOS_WAIT_FOREVER);
    if (PAL_SUCCESS != result)
    {
        PAL_LOG_ERR("error waiting for mutex"); // we want to zero the flag even if this fails beacuse it is better to get an extra event than miss one.
    }
    for (i = 0; i < PAL_NET_TEST_MAX_ASYNC_SOCKETS; i++)
    {

        if (s_fds[i].fd == socketFD)
        {
            s_callbackFilter[i] = 0;
            break;
        }
    }
    result = pal_osMutexRelease(s_mutexSocketEventFilter);
    if (PAL_SUCCESS != result)
    {
        PAL_LOG_ERR("error releasing mutex");
    }
}

// Thread function.
PAL_PRIVATE void asyncSocketManager(void const* arg)
{
    PAL_UNUSED_ARG(arg); // unused
    int res;
    palAsyncSocketCallback_t callbacks[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {0};
    void* callbackArgs[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {0};
    struct pollfd fds[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {{0}};
    struct fd_set fd_read_set;
    struct fd_set fd_write_set;
    struct fd_set fd_except_set;
    // SIGBREAKF_CTRL_D = remove socket
    // SIGBREAKF_CTRL_E = add socket
    // SIGBREAKF_CTRL_F = kill it
    ULONG bmask = SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
    nfds_t nfds = 0;

    FD_ZERO(&fd_read_set);
    FD_ZERO(&fd_write_set);
    FD_ZERO(&fd_except_set);

    palStatus_t result = PAL_SUCCESS;

    // // Tell the calling thread that we have finished initialization
    result = pal_osSemaphoreRelease(s_socketCallbackSemaphore);
    if (result != PAL_SUCCESS)
    {
        PAL_LOG_ERR("Error in async socket manager on semaphore release");
    }

    printf("finished initialization\n");

    while (result == PAL_SUCCESS) //As long as all goes well loop forever
    {
        printf("wait for mutex\n");

        // Critical section to update globals
        result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
        if (PAL_SUCCESS != result)
        {
            PAL_LOG_ERR("Error in async socket manager on mutex wait");
            break;
        }

        // Update the list of sockets to watch from the global list
        nfds = s_nfds;
        if(nfds)
        {
            memcpy(callbacks, s_callbacks, nfds*sizeof(callbacks[0]));
            memcpy(callbackArgs, s_callbackArgs, nfds * sizeof(void*));
            memcpy(fds, s_fds, nfds*sizeof(fds[0]));
            memcpy(&fd_read_set, &s_fdset, sizeof(struct fd_set));
            memcpy(&fd_write_set, &s_fdset, sizeof(struct fd_set));
            memcpy(&fd_except_set, &s_fdset, sizeof(struct fd_set));

            for (int i=0; i < nfds; i++)
            {
                fds[i].revents = 0;
                s_callbackFilter[i] = 0;
            }
        }
        result = pal_osMutexRelease(s_mutexSocketCallbacks);
        if (result != PAL_SUCCESS)
        {
            PAL_LOG_ERR("Error in async socket manager on mutex release");
            break;
        }

        printf("wait for socket signals n: %u bmask: %u\n", nfds, bmask);
        // block until a SIGIO signal is received or break signal
        //if (lastUSRCounter == s_palUSR1Counter) // no updates to the sockets that need to be polled (wait for next IO)  - if there were updates skip waiting and proceeed to poll
        res = waitselect(nfds + 1, &fd_read_set, &fd_write_set, &fd_except_set, NULL, &bmask);

        // Check for thread termination request
        if(bmask & SIGBREAKF_CTRL_F)
        {
            if(s_nfds == PAL_SOCKETS_TERMINATE)
            {
                printf("terminate signaled\n");
                s_nfds = 0; // Reset s_ndfs
                s_socketThreadTerminateSignaled = true; // mark that the thread has receieved the termination request
                bmask = SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
                // Break out of while(1)
                break;
            }
        }

        /* add socket signaled */
        if(bmask & SIGBREAKF_CTRL_E)
        {
            printf("Create socket\n");
            //Async socket needs to be created here for signals to work
            // s_async_socket.result = pal_plat_socket(s_async_socket.domain,  s_async_socket.type,  s_async_socket.nonBlockingSocket,  s_async_socket.interfaceNum, s_async_socket.socket);

            // int flags = fcntl((intptr_t)*(s_async_socket.socket), F_GETFL, 0);
            // assert(flags >= 0);

            // flags |= O_ASYNC;

            // int err = fcntl((intptr_t)*(s_async_socket.socket), F_SETFL, flags);

            // if (err == -1)
            // {
            //     s_async_socket.result = translateErrorToPALError(errno);
            // }

            //Signal async create socket that socket has been created
            pal_osSemaphoreRelease(s_socketCreateSemaphore);
            // Restore signal mask
            bmask = SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
        }

        if(bmask & SIGBREAKF_CTRL_D)
        {
            printf("Close socket\n");
            // Restore signal mask
            bmask = SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
        }

        printf("got signals\n");
        // Notes:
        // If a POLLIN event occurred and recv from the socket results in 0 bytes being read, it means that
        // the remote socket was closed. Unless this is dealt with in the callback (for example by closing the
        // socket) the next call to ppoll will also immediately return with the same result.
        if(res >0 || errno == EINTR)
        {
            printf("in signal handler\n");
            unsigned int i;
            errno = 0;
            // Some event was triggered, so iterate over all watched fds's and call the relevant callbacks.
            for( i = 0; i < nfds; i++)
            {
                if(FD_ISSET(fds[i].fd, &fd_read_set) || FD_ISSET(fds[i].fd, &fd_write_set) || FD_ISSET(fds[i].fd, &fd_except_set))
                {
                    printf("found socket %u\n", i);
                    //if ((fds[i].revents != filter) && ((fds[i].revents != POLLOUT) || (fds[i].revents != s_callbackFilter[i])) ) // this is handlign for a special scenario when a specific event which shouldnt happen is sent to all unconnected sockets in Linux triggering an unwanted callback.
                    if (!(FD_ISSET(fds[i].fd, &fd_write_set) && FD_ISSET(fds[i].fd, &fd_except_set)))
                    {
                        printf("callback triggered\n");
                        callbacks[i](callbackArgs[i]);
                    }
                    result = pal_osMutexWait(s_mutexSocketEventFilter, PAL_RTOS_WAIT_FOREVER);
                    if (PAL_SUCCESS != result)
                    {
                        PAL_LOG_ERR("error waiting for mutex");
                    }
                    else
                    {
                        //s_callbackFilter[i] = fds[i].revents;
                        result = pal_osMutexRelease(s_mutexSocketEventFilter);
                        if (PAL_SUCCESS != result)
                        {
                            PAL_LOG_ERR("error releasing mutex");
                        }
                    }
                }
            }
        }
        else if (res == 0)
        {
            printf("waitselect abort by signal\n");
            // Broken out by signal
        }
        else
        {
            PAL_LOG_ERR("Error in async socket manager");
        }
    }  // while

    //Remove this when implementation is finished
    //s_socketThreadTerminateSignaled = true;
}
#endif // PAL_NET_ASYNCHRONOUS_SOCKET_API

palStatus_t pal_plat_socketsInit(void* context)
{
    PAL_UNUSED_ARG(context);
    palStatus_t result = PAL_SUCCESS;

    if (s_pal_network_initialized == 1)
    {
        return PAL_SUCCESS; // already initialized.
    }


#if PAL_NET_ASYNCHRONOUS_SOCKET_API

    FD_ZERO(&s_fdset);

    result = pal_osMutexCreate(&s_mutexSocketCallbacks);
    if (result != PAL_SUCCESS)
    {
        return result;
    }

    result = pal_osMutexCreate(&s_mutexSocketEventFilter);
    if (PAL_SUCCESS != result)
    {
        return result;
    }

    // Sleep at first wait
    result = pal_osSemaphoreCreate(0, &s_socketCallbackSemaphore);
    if (result != PAL_SUCCESS)
    {
        if (pal_osMutexDelete(&s_mutexSocketCallbacks) != PAL_SUCCESS) //cleanup allocated resources
        {
            // TODO print error using logging mechanism when available.
        }
        return result;
    }

    result = pal_osSemaphoreCreate(0, &s_socketCreateSemaphore);
    if (result != PAL_SUCCESS)
    {
        if (pal_osMutexDelete(&s_mutexSocketCallbacks) != PAL_SUCCESS) //cleanup allocated resources
        {
            // TODO print error using logging mechanism when available.
        }
        return result;
    }

    s_socketThreadTerminateSignaled = false;
    result = pal_osThreadCreateWithAlloc(asyncSocketManager, NULL, PAL_osPriorityReservedSockets, PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE, NULL, &s_pollThread);
    if (PAL_SUCCESS != result)
    {
        if (PAL_ERR_RTOS_PRIORITY == result)
        {
            result = PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED;
        }
        else
        {
            result = PAL_ERR_SOCKET_GENERIC;
        }
    }
    else
    {
        // Wait here for the thread to be initialized.
        result = pal_osSemaphoreWait(s_socketCallbackSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);
        if (PAL_SUCCESS != result)
        {
            goto end;
        }
        result = pal_osSemaphoreDelete(&s_socketCallbackSemaphore);
        if (PAL_SUCCESS != result)
        {
            goto end;
        }
    }
#endif

end:
    if (PAL_SUCCESS == result)
    {
        s_pal_network_initialized = 1;
    }


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
    s_pal_networkInterfacesSupported[interfaceIndex] = NULL;
    --s_pal_numberOFInterfaces;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_socketsTerminate(void* context)
{
    PAL_UNUSED_ARG(context);
    palStatus_t result = PAL_SUCCESS;
    palStatus_t firstError = PAL_SUCCESS;

    printf("in pal_plat_socketsTerminate\n");

#if PAL_NET_ASYNCHRONOUS_SOCKET_API
    // Critical section to update globals

    printf("waiting for mutuex\n");

    result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }

    printf("got mutuex!\n");

    s_nfds = PAL_SOCKETS_TERMINATE;
    // Tell the poll thread to interrupt so that it can check for termination.
    if(s_pollThread != NULLPTR)
    {
        printf("singlaing to termineit!\n");
        Signal((struct Task *)s_pollThread, SIGBREAKF_CTRL_F);
    }

    result = pal_osMutexRelease(s_mutexSocketCallbacks);
    if ((PAL_SUCCESS != result) && (PAL_SUCCESS == firstError))
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }

    while (!s_socketThreadTerminateSignaled)
    {
        pal_osDelay(10);
    }

    result = pal_osMutexDelete(&s_mutexSocketEventFilter);
    if ((PAL_SUCCESS != result) && (PAL_SUCCESS == firstError))
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }

    result = pal_osMutexDelete(&s_mutexSocketCallbacks);
    if ((PAL_SUCCESS != result ) && (PAL_SUCCESS == firstError))
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }

    result = pal_osMutexDelete(&s_socketCreateSemaphore);
    if ((PAL_SUCCESS != result ) && (PAL_SUCCESS == firstError))
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }

#endif // PAL_NET_ASYNCHRONOUS_SOCKET_API

    s_pal_network_initialized = 0;

    return firstError;
}

palStatus_t pal_plat_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* sockt)
{
    int result = PAL_SUCCESS;
    intptr_t sockfd;

    PAL_VALIDATE_ARGUMENTS(interfaceNum >= s_pal_numberOFInterfaces && PAL_NET_DEFAULT_INTERFACE != interfaceNum);

    // These are the same in Linux
    if(type == PAL_SOCK_STREAM_SERVER)
    {
        type = PAL_SOCK_STREAM;
    }

    PAL_ASSERT_STATIC(AF_INET == PAL_AF_INET);
    //PAL_ASSERT_STATIC(AF_INET6 == PAL_AF_INET6);
    PAL_ASSERT_STATIC(AF_UNSPEC == PAL_AF_UNSPEC);
    PAL_ASSERT_STATIC(SOCK_DGRAM == (unsigned int)PAL_SOCK_DGRAM);
    PAL_ASSERT_STATIC(SOCK_STREAM == (unsigned int)PAL_SOCK_STREAM);

    sockfd = socket(domain, type, 0);
    // Note - though it is not an error, if we get sockfd == 0 then we probably (accidentally closed fd 0 somewhere else)
    if (sockfd == -1)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        if (nonBlockingSocket)
        {
            fcntl( sockfd, F_SETFL, fcntl(sockfd, F_GETFL ) | O_NONBLOCK );
        }
        *sockt = (palSocket_t)sockfd;
    }
    return result;
}


// Assume input timeout value is in milliseconds.
palStatus_t pal_plat_setSocketOptions(palSocket_t socket, int optionName, const void* optionValue, palSocketLength_t optionLength)
{
       int result = PAL_SUCCESS;
    int linuxName;
    PAL_UNUSED_ARG(optionLength);


    struct timeval timeout;
    timeout.tv_sec =  0;
    timeout.tv_usec = 0;

    switch (optionName)
    {
    case PAL_SO_SNDTIMEO:
        linuxName = SO_SNDTIMEO;
        timeout.tv_sec = (*(int *)optionValue)/1000 ;
        timeout.tv_usec = ((*(int *)optionValue)%1000)*1000 ;
        break;
    case PAL_SO_RCVTIMEO:
        linuxName = SO_RCVTIMEO;
        timeout.tv_sec = (*(int *)optionValue)/1000 ;
        timeout.tv_usec = ((*(int *)optionValue)%1000)*1000 ;
        break;
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
    case PAL_SO_KEEPALIVE:
        linuxName = SO_KEEPALIVE;
        break;
#endif
    case PAL_SO_REUSEADDR:
        linuxName = SO_REUSEADDR;
        break;
    default:
        // Unsupported option
        result = PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    }

    if (PAL_SUCCESS == result)
    {
        if (PAL_SO_SNDTIMEO == optionName || PAL_SO_RCVTIMEO == optionName)
        {
            result = setsockopt ((intptr_t)socket, SOL_SOCKET, linuxName, &timeout, sizeof(timeout));
        }
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
        else if (PAL_SO_KEEPIDLE == optionName || PAL_SO_KEEPINTVL == optionName)
        {
            result = setsockopt ((intptr_t)socket, SOL_TCP, linuxName, (int *)optionValue, optionLength);
        }
#endif
        else
        {
            result = setsockopt ((intptr_t)socket, SOL_SOCKET, linuxName, (int *)optionValue, optionLength);
        }

        if(-1 == result)
        {
            result = translateErrorToPALError(errno);
        }
    }

    return result;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t socket, bool* isNonBlocking)
{
    int flags = fcntl((intptr_t)socket, F_GETFL);

    if (0 != (flags & O_NONBLOCK))
    {
        *isNonBlocking = true;
    }
    else
    {
        *isNonBlocking = false;
    }
    return PAL_SUCCESS;
}

PAL_PRIVATE palStatus_t pal_plat_SockAddrToSocketAddress(const palSocketAddress_t* palAddr, struct sockaddr* output)
{
    palStatus_t result = PAL_SUCCESS;
    uint16_t port = 0;
    bool found = false;

    result = pal_getSockAddrPort(palAddr, &port);
    if (result != PAL_SUCCESS)
    {
        return result;
    }

#if PAL_SUPPORT_IP_V4
    if (PAL_AF_INET == palAddr->addressType)
    {
        palIpV4Addr_t ipV4Addr = { 0 };
        struct sockaddr_in* ip4addr = (struct sockaddr_in*)output;
        ip4addr->sin_family = AF_INET;
        ip4addr->sin_port = PAL_HTONS(port);
        result = pal_getSockAddrIPV4Addr(palAddr, ipV4Addr);
        if (result == PAL_SUCCESS)
        {
            memcpy(&ip4addr->sin_addr, ipV4Addr, sizeof(ip4addr->sin_addr));
        }
        found = true;
    }

#endif // PAL_SUPPORT_IP_V4
#if PAL_SUPPORT_IP_V6
    if (PAL_AF_INET6 == palAddr->addressType)
    {
        palIpV6Addr_t ipV6Addr = {0};
        struct sockaddr_in6* ip6addr = (struct sockaddr_in6*)output;
        ip6addr->sin6_family = AF_INET6;
        ip6addr->sin6_scope_id = 0; // we assume there will not be several interfaces with the same IP.
        ip6addr->sin6_flowinfo = 0;
        ip6addr->sin6_port = PAL_HTONS(port);
        result = pal_getSockAddrIPV6Addr(palAddr, ipV6Addr);
        if (result == PAL_SUCCESS)
        {
            memcpy(&ip6addr->sin6_addr, ipV6Addr, sizeof(ip6addr->sin6_addr));
        }
        found = true;
    }
#endif

    if (false == found)
    {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    return result;
}

PAL_PRIVATE palStatus_t pal_plat_socketAddressToPalSockAddr(struct sockaddr* input, palSocketAddress_t* out, palSocketLength_t* length)
{
    palStatus_t result = PAL_SUCCESS;
    bool found = false;

#if PAL_SUPPORT_IP_V4
    if (input->sa_family == AF_INET)
    {
        palIpV4Addr_t ipV4Addr;
        struct sockaddr_in* ip4addr = (struct sockaddr_in*)input;

        memcpy(ipV4Addr, &ip4addr->sin_addr, PAL_IPV4_ADDRESS_SIZE);
        result = pal_setSockAddrIPV4Addr(out, ipV4Addr);
        if (result == PAL_SUCCESS)
        {
            result = pal_setSockAddrPort(out, PAL_NTOHS(ip4addr->sin_port));
        }
        *length = sizeof(struct sockaddr_in);
        found = true;
    }
#endif //PAL_SUPPORT_IP_V4
#if PAL_SUPPORT_IP_V6
    if (input->sa_family == AF_INET6)
    {
        palIpV6Addr_t ipV6Addr;
        struct sockaddr_in6* ip6addr = (struct sockaddr_in6*)input;
        memcpy(ipV6Addr, &ip6addr->sin6_addr, PAL_IPV6_ADDRESS_SIZE);
        result = pal_setSockAddrIPV6Addr(out, ipV6Addr);
        if (result == PAL_SUCCESS)
        {
            result = pal_setSockAddrPort(out, PAL_NTOHS(ip6addr->sin6_port));
        }
        *length = sizeof(struct sockaddr_in6);
        found = true;
    }
#endif // PAL_SUPPORT_IP_V6

    if (false == found)
    { // we got unspeicified in one of the tests, so Don't fail , but don't translate address.  // re-chcking
        result = PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    }

    return result;
}

palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
    int result = PAL_SUCCESS;
    int res = 0;
    struct sockaddr_in internalAddr = {0} ;

    result = pal_plat_SockAddrToSocketAddress(myAddress, (struct sockaddr *)&internalAddr);
    if (result == PAL_SUCCESS)
    {
        res = bind((intptr_t)socket, (struct sockaddr *)&internalAddr, addressLength);
        if (res == -1)
        {
            result = translateErrorToPALError(errno);
        }
    }

    return result;
}


palStatus_t pal_plat_receiveFrom(palSocket_t socket, void* buffer, size_t length, palSocketAddress_t* from, palSocketLength_t* fromLength, size_t* bytesReceived)
{
    palStatus_t result = PAL_SUCCESS;
    ssize_t res;
    struct sockaddr_in internalAddr;
    socklen_t addrlen;

    clearSocketFilter((intptr_t)socket);
    addrlen = sizeof(struct sockaddr_in);
    res = recvfrom((intptr_t)socket, buffer, length, 0 ,(struct sockaddr *)&internalAddr, &addrlen);
    if(res == -1)
    {
        result = translateErrorToPALError(errno);
    }
    else // only return address / bytesReceived in case of success
    {
        if ((NULL != from) && (NULL != fromLength))
        {
            result = pal_plat_socketAddressToPalSockAddr((struct sockaddr *)&internalAddr, from, fromLength);
        }
        *bytesReceived = res;
    }

    return result;
}

palStatus_t pal_plat_sendTo(palSocket_t socket, const void* buffer, size_t length, const palSocketAddress_t* to, palSocketLength_t toLength, size_t* bytesSent)
{
    palStatus_t result = PAL_SUCCESS;
    ssize_t res;

    clearSocketFilter((intptr_t)socket);
    res = sendto((intptr_t)socket, buffer, length, 0, (struct sockaddr *)to, toLength);
    if(res == -1)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        *bytesSent = res;
    }

    return result;
}

palStatus_t pal_plat_close(palSocket_t* socket)
{
    palStatus_t result = PAL_SUCCESS;
    int res;
    unsigned int i,j;

    if  (*socket == (void *)PAL_LINUX_INVALID_SOCKET) // socket already closed - return success.
    {
        PAL_LOG_DBG("socket close called on socket which was already closed");
        return result;
    }
#if PAL_NET_ASYNCHRONOUS_SOCKET_API
    // Critical section to update globals
    result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        return result;
    }

    for(i= 0 ; i < s_nfds; i++)
    {
        // check if we have we found the socket being closed
        if (s_fds[i].fd == (intptr_t)*socket)
        {
            // Remove from async socket list
            // Close the gap in the socket data structures.
            for(j = i; j < s_nfds - 1; j++)
            {
                s_fds[j].fd = s_fds[j+1].fd;
                s_callbacks[j] = s_callbacks[j+1];
                s_callbackArgs[j] = s_callbackArgs[j+1];
            }
            // Blank out the last one
            s_fds[j].fd = 0;
            s_callbacks[j] = 0;
            s_callbackArgs[j] = 0;
            s_nfds--;
            // Tell the poll thread to remove the socket
            Signal((struct Task *)s_pollThread, SIGBREAKF_CTRL_D);
            break;
        }
    }
    result = pal_osMutexRelease(s_mutexSocketCallbacks);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        return result;
    }
#endif // PAL_NET_ASYNCHRONOUS_SOCKET_API
    // In Linux it is ok to close a socket while it is being polled, but may not be on other os's
    res = close((intptr_t) *socket);
    if(res == -1)
        result = translateErrorToPALError(errno);
    else
    {
        *socket = (void *)PAL_LINUX_INVALID_SOCKET;
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

    return result;
}


#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.
palStatus_t pal_plat_listen(palSocket_t socket, int backlog)
{
    palStatus_t result = PAL_SUCCESS;
    int res;

    res = listen((intptr_t)socket,backlog);
    if(res == -1)
    {
        result = translateErrorToPALError(errno);
    }
    return result;
}


palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t * address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket)
{
    intptr_t res = 0;
    palStatus_t result = PAL_SUCCESS;
    struct sockaddr_in internalAddr = {0} ;
    socklen_t internalAddrLen = sizeof(internalAddr);

    // XXX: the whole addressLen -concept is broken as the address is fixed size anyway.
    if (*addressLen < sizeof(palSocketAddress_t))
    {
        return PAL_ERR_SOCKET_INVALID_ADDRESS;
    }

    res = accept((intptr_t)socket,(struct sockaddr *)&internalAddr, &internalAddrLen);
    if(res == -1)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        *acceptedSocket = (palSocket_t*)res;
        *addressLen = sizeof(palSocketAddress_t);
        result = pal_plat_socketAddressToPalSockAddr((struct sockaddr *)&internalAddr, address, &internalAddrLen);
    }

    return result;
}


palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    int result = PAL_SUCCESS;
    int res;
    struct sockaddr_in internalAddr = {0} ;

    result = pal_plat_SockAddrToSocketAddress(address, (struct sockaddr *)&internalAddr);
    if (result == PAL_SUCCESS)
    {
        // clean filter to get the callback on first attempt
        clearSocketFilter((intptr_t)socket);

        res = connect((intptr_t)socket,(struct sockaddr *)&internalAddr, addressLen);
        if(res == -1)
        {
            result = translateErrorToPALError(errno);
        }
    }

    return result;
}

palStatus_t pal_plat_recv(palSocket_t socket, void *buffer, size_t len, size_t* recievedDataSize)
{
    palStatus_t result = PAL_SUCCESS;
    ssize_t res;

    clearSocketFilter((intptr_t)socket);
    res = recv((intptr_t)socket, buffer, len, 0);
    if(res ==  -1)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        if (0 == res)
        {
            result = PAL_ERR_SOCKET_CONNECTION_CLOSED;
        }
        *recievedDataSize = res;
    }
    return result;
}

palStatus_t pal_plat_send(palSocket_t socket, const void *buf, size_t len, size_t *sentDataSize)
{
    palStatus_t result = PAL_SUCCESS;
    ssize_t res;

    clearSocketFilter((intptr_t)socket);

    res = send((intptr_t)socket, buf, len, 0);
    if(res == -1)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        *sentDataSize = res;
    }

    return result;
}

#endif //PAL_NET_TCP_AND_TLS_SUPPORT

#if PAL_NET_ASYNCHRONOUS_SOCKET_API
palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument, palSocket_t* socket)
{
    int err;
    palStatus_t result;    

    //We pass this data structure to async manager thread which creates socket for us
    s_async_socket.domain = domain;
    s_async_socket.type = type;
    s_async_socket.nonBlockingSocket = nonBlockingSocket;
    s_async_socket.interfaceNum = interfaceNum;
    s_async_socket.socket = socket;

    // Tell the poll thread to create the socket    
    Signal((struct Task *)s_pollThread, SIGBREAKF_CTRL_E);

    // Wait for the socket to be created
    result = pal_osSemaphoreWait(s_socketCreateSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        return result;
    }

    // Pick up the result
    result = s_async_socket.result;

    // if (result == PAL_SUCCESS)
    // {
    //     // Critical section to update globals
    //     result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
    //     if (result != PAL_SUCCESS)
    //     {
    //         // TODO print error using logging mechanism when available.
    //         return result;
    //     }

    //     // make sure a recycled socket structure does not contain obsolete event filter
    //      clearSocketFilter((intptr_t)*socket);

    //     s_fds[s_nfds].fd = (intptr_t)*(s_async_socket.socket);
    //     FD_SET(s_fds[s_nfds].fd, &s_fdset);
    //     s_callbacks[s_nfds] = callback;
    //     s_callbackArgs[s_nfds] = callbackArgument;
    //     s_nfds++;
    //     result = pal_osMutexRelease(s_mutexSocketCallbacks);
    //     if (PAL_SUCCESS != result)
    //     {
    //         return result;
    //     }
    // }    

    return result;
}

#endif

#if PAL_NET_DNS_SUPPORT

palStatus_t pal_plat_getAddressInfo(const char *url, palSocketAddress_t *address, palSocketLength_t* length)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t localAddress = {0};
    palSocketAddress_t zeroAddress = {0};
    struct hostent * hn = NULL;
    struct sockaddr_in remotehost;
    unsigned int i = 0;

    hn = gethostbyname(url);
    if(NULL == hn)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        while( hn->h_addr_list[i] != NULL ) {

            memcpy(&remotehost.sin_addr, hn->h_addr_list[i], hn->h_length);
            remotehost.sin_family = AF_INET;

            result = pal_plat_socketAddressToPalSockAddr((struct sockaddr *)&remotehost, &localAddress, length);

            if (0 == memcmp(localAddress.addressData, zeroAddress.addressData, PAL_NET_MAX_ADDR_SIZE) ) // invalid 0 address
            {
                result = PAL_ERR_SOCKET_DNS_ERROR;
            }
            else
            {
                *address = localAddress;
                result = PAL_SUCCESS;
                break;
            }
            i++;
        }
    }

    return result;
}

#endif
