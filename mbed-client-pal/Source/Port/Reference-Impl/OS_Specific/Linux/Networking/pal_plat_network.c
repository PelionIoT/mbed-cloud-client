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
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>

#define TRACE_GROUP "PAL"

#if (PAL_NET_TCP_AND_TLS_SUPPORT == true)
#include <netinet/tcp.h>
#endif

// invalid socket based on posix
#define PAL_LINUX_INVALID_SOCKET (-1)


typedef struct palNetInterfaceName{
    char *interfaceName;
} palNetInterfaceName_t;

PAL_PRIVATE palNetInterfaceName_t s_palNetworkInterfacesSupported[PAL_MAX_SUPORTED_NET_INTERFACES];

PAL_PRIVATE  uint32_t s_palNumOfInterfaces = 0;
PAL_PRIVATE  uint32_t s_pal_network_initialized = 0;

PAL_PRIVATE palStatus_t translateErrorToPALError(int errnoValue)
{
    palStatus_t status;
    switch (errnoValue)
    {
    case EAI_MEMORY:
        status = PAL_ERR_NO_MEMORY;
        break;
    case EWOULDBLOCK:
#if EAGAIN != EWOULDBLOCK
    case EAGAIN:
#endif
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
    case EPIPE:
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


static pthread_t s_pollThread = NULLPTR;
static palMutexID_t s_mutexSocketCallbacks = 0;
static palMutexID_t s_mutexSocketEventFilter = 0;
static palSemaphoreID_t s_socketCallbackSemaphore = 0;
static palSemaphoreID_t s_socketCallbackSignalSemaphore = 0;

// These must be updated only when protected by s_mutexSocketCallbacks
static palAsyncSocketCallback_t s_callbacks[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {0};
static void* s_callbackArgs[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = { 0 };
static struct pollfd s_fds[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {{0,0,0}};
static uint32_t s_callbackFilter[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {0};
static nfds_t s_nfds = 0;
static volatile bool s_socketThreadTerminateSignaled = false;

// The below function is the signal handler API, doing nothing.
// The idea is to signal the asyncSocketManager thread with pthread_kill(s_pollThread, SIGUSR1) command
// which make the ppoll API to be interrupted.

static uint64_t s_palUSR1Counter =0;
static void sigusr2(int signo) {
    (void)signo;
    s_palUSR1Counter++;
    // Coverity fix - Unchecked return value. There is not much doable if semaphore release fail.
    // Function pal_osSemaphoreRelease already contains error trace.
    (void)pal_osSemaphoreRelease(s_socketCallbackSignalSemaphore);
}

static uint64_t s_palIOCounter =0;

static void sig_io_handler(int signo) {
    (void)signo;

    s_palIOCounter++;
    // Coverity fix - Unchecked return value. There is not much doable if semaphore release fail.
    // Function pal_osSemaphoreRelease already contains error trace.
    (void)pal_osSemaphoreRelease(s_socketCallbackSignalSemaphore);
}


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
    struct pollfd fds[PAL_NET_TEST_MAX_ASYNC_SOCKETS] = {{0,0,0}};
    nfds_t nfds = 0;
    struct sigaction s;
    sigset_t blockedSignals;
    palStatus_t result = PAL_SUCCESS;
    uint64_t lastIOCounter=0;
    uint64_t lastUSRCounter=0;

    const struct timespec timeout_zero = {0, 0};

    // After execv call, signal handler does not return and SIGIO/SIGUSR1 might be blocked in certain cases
    // We need to unblock SIG* to get it working again.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &set, NULL);

    // Initialize the signal handler. SIG_IGN and SIG_DFL do not work
    s.sa_handler = sigusr2;
    sigemptyset(&s.sa_mask);
    s.sa_flags = 0;
    sigaction(SIGUSR1, &s, NULL);

    s.sa_handler = sig_io_handler;
    sigemptyset(&s.sa_mask);
    s.sa_flags =  SA_RESTART ;
    sigaction(SIGIO, &s, NULL);

    // Block the timer signal from interrupting ppoll(), as it does not have a signal handler.
    // The timer signal is already blocked on all the threads created after pal_init(), but
    // the ppoll() will change that situation with the given sigmask.
    // Without this, the libc's default signal handler will kick in and kill the process.
    sigemptyset(&blockedSignals);
    sigaddset(&blockedSignals, PAL_TIMER_SIGNAL);

    s_pollThread = pthread_self(); // save the thread id for signal usage
    // Tell the calling thread that we have finished initialization
    result = pal_osSemaphoreRelease(s_socketCallbackSemaphore);
    if (result != PAL_SUCCESS)
    {
        PAL_LOG_ERR("Error in async socket manager on semaphore release");
    }


    while (result == PAL_SUCCESS) //As long as all goes well loop forever
    {
        // block until a SIGIO signal is received
        if (lastUSRCounter == s_palUSR1Counter) // no updates to the sockets that need to be polled (wait for next IO)  - if there were updates skip waiting and proceeed to poll
        {
            pal_osSemaphoreWait(s_socketCallbackSignalSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);
        }

        // Critical section to update globals
        result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
        if (PAL_SUCCESS != result)
        {
            PAL_LOG_ERR("Error in async socket manager on mutex wait");
            break;
        }

        // Check for thread termination request
        if(s_nfds == PAL_SOCKETS_TERMINATE)
        {
            result = pal_osMutexRelease(s_mutexSocketCallbacks);
            if (result != PAL_SUCCESS)
            {
                PAL_LOG_ERR("Error in async socket manager on mutex release during termination");
            }
            s_nfds = 0; // Reset s_ndfs
            s_socketThreadTerminateSignaled = true; // mark that the thread has receieved the termination request
            // Break out of while(1)
            break;
        }
        // Update the list of sockets to watch from the global list
        nfds = s_nfds;
        if(nfds)
        {
            memcpy(callbacks, s_callbacks, nfds*sizeof(callbacks[0]));
            memcpy(callbackArgs, s_callbackArgs, nfds * sizeof(void*));
            memcpy(fds, s_fds, nfds*sizeof(fds[0]));

            for (int i=0; i < nfds; i++)
            {
                fds[i].events = POLLIN|POLLOUT|POLLRDHUP|POLLERR;
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

        // Wait for a socket event or pthread_kill(s_pollThread, SIGUSR1) event
        lastUSRCounter = s_palUSR1Counter;
        res = ppoll(&fds[0], nfds, &timeout_zero, &blockedSignals);


        // Notes:
        // If a POLLIN event occurred and recv from the socket results in 0 bytes being read, it means that
        // the remote socket was closed. Unless this is dealt with in the callback (for example by closing the
        // socket) the next call to ppoll will also immediately return with the same result.
        if(res >0 || errno == EINTR)
        {
            unsigned int i;
            errno = 0;
            // Some event was triggered, so iterate over all watched fds's and call the relevant callbacks.
                if (lastIOCounter< s_palIOCounter)
                {
                    lastIOCounter = s_palIOCounter;
                    for( i = 0; i < nfds; i++)
                    {
                        if(fds[i].revents)
                        {
                            // Allow POLLOUT events for TCP connection completion
                            // Only filter out the combination of POLLOUT|POLLHUP which indicates a failed connection
                            uint32_t problematic_filter = POLLOUT|POLLHUP;
                            
                            // Always allow standalone POLLOUT (successful connection) and other legitimate events
                            if ((fds[i].revents != problematic_filter) && (fds[i].revents != s_callbackFilter[i]))
                            {
                                callbacks[i](callbackArgs[i]);
                            }
                            result = pal_osMutexWait(s_mutexSocketEventFilter, PAL_RTOS_WAIT_FOREVER);
                            if (PAL_SUCCESS != result)
                            {
                                PAL_LOG_ERR("error waiting for mutex");
                            }
                            else
                            {
                                s_callbackFilter[i] = fds[i].revents;
                                result = pal_osMutexRelease(s_mutexSocketEventFilter);
                                if (PAL_SUCCESS != result)
                                {
                                    PAL_LOG_ERR("error releasing mutex");
                                }
                            }


                        }
                    }
                }


        }
        else if (res == 0)
        {
            // Timeout
        }
        else
        {
            PAL_LOG_ERR("Error in async socket manager");
        }
    }  // while
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

palStatus_t pal_plat_socketsInit(void* context)
{
    PAL_UNUSED_ARG(context);
    palStatus_t result = PAL_SUCCESS;

    if (s_pal_network_initialized == 1)
    {
        return PAL_SUCCESS; // already initialized.
    }

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

    result = pal_osSemaphoreCreate(0, &s_socketCallbackSignalSemaphore);
    if (result != PAL_SUCCESS)
    {
        // todo: clean up the mess created so far
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

    s_socketThreadTerminateSignaled = false;
    palThreadID_t threadID = NULLPTR;
    result = pal_osThreadCreateWithAlloc(asyncSocketManager, NULL, PAL_osPriorityReservedSockets, PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE, NULL, &threadID);
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

    for (index = 0; index < s_palNumOfInterfaces; index++) // if specific context already registered return existing index instead of registering again.
    {
        if (strcmp(s_palNetworkInterfacesSupported[index].interfaceName, (const char *)context) == 0)
        {
            found = true;
            *interfaceIndex = index;
            break;
        }
    }
    if (false == found)
    {
        if (s_palNumOfInterfaces < PAL_MAX_SUPORTED_NET_INTERFACES)
        {
            s_palNetworkInterfacesSupported[s_palNumOfInterfaces].interfaceName = (char *)context;
            *interfaceIndex = s_palNumOfInterfaces;
            ++s_palNumOfInterfaces;
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
        s_palNetworkInterfacesSupported[interfaceIndex].interfaceName) {
        s_palNetworkInterfacesSupported[interfaceIndex].interfaceName = NULL;
        --s_palNumOfInterfaces;
        return PAL_SUCCESS;
    } else {
        return PAL_ERR_INVALID_ARGUMENT;
    }
}

palStatus_t pal_plat_socketsTerminate(void* context)
{
    PAL_UNUSED_ARG(context);
    palStatus_t result = PAL_SUCCESS;
    palStatus_t firstError = PAL_SUCCESS;

    // Critical section to update globals
    result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }

    s_nfds = PAL_SOCKETS_TERMINATE;
    result = pal_osSemaphoreRelease(s_socketCallbackSignalSemaphore);
    if ((PAL_SUCCESS != result) && (PAL_SUCCESS == firstError))
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
    }
    // Tell the poll thread to interrupt so that it can check for termination.
    if(s_pollThread != NULLPTR)
    {
        pthread_kill(s_pollThread, SIGUSR1);
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

    result = pal_osSemaphoreDelete(&s_socketCallbackSignalSemaphore);
    if ((PAL_SUCCESS != result) && (PAL_SUCCESS == firstError))
    {
        // TODO print error using logging mechanism when available.
        firstError = result;
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

    s_pal_network_initialized = 0;

    return firstError;
}

/*
 * NOTE!!!!
 * When creating socket in Linux, we ignore interfaceNum provided.
 * The socket should be bound to interface pal_plat_bind API (bind to address reflects the bound between
 * socket and interface).
 */
palStatus_t create_socket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palSocket_t* sockt)
{
    int result = PAL_SUCCESS;
    intptr_t sockfd;
    int sockBehavior = 0;

    PAL_VALIDATE_ARGUMENTS(interfaceNum >= s_palNumOfInterfaces && PAL_NET_DEFAULT_INTERFACE != interfaceNum);

    // These are the same in Linux
    if(type == PAL_SOCK_STREAM_SERVER)
    {
        type = PAL_SOCK_STREAM;
    }

    // Compile time check that PAL values are the same as Linux values
    PAL_ASSERT_STATIC(AF_INET == PAL_AF_INET);
    PAL_ASSERT_STATIC(AF_INET6 == PAL_AF_INET6);
    PAL_ASSERT_STATIC(AF_UNSPEC == PAL_AF_UNSPEC);
    PAL_ASSERT_STATIC(SOCK_DGRAM == (unsigned int)PAL_SOCK_DGRAM);
    PAL_ASSERT_STATIC(SOCK_STREAM == (unsigned int)PAL_SOCK_STREAM);

    if (nonBlockingSocket)
    {
        sockBehavior = SOCK_NONBLOCK;
    }

    // SOCK_NONBLOCK since Linux 2.6.27
    sockfd = socket(domain, type | sockBehavior , 0);
    // Note - though it is not an error, if we get sockfd == 0 then we probably (accidentally closed fd 0 somewhere else)
    if (sockfd == PAL_LINUX_INVALID_SOCKET)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        *sockt = (palSocket_t)sockfd;
    }
    return result; // TODO(nirson01) ADD debug print for error propagation(once debug print infrastructure is finalized)
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
    case PAL_SO_KEEPIDLE:
        linuxName = TCP_KEEPIDLE;
        break;
    case PAL_SO_KEEPINTVL:
        linuxName = TCP_KEEPINTVL;
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


palStatus_t pal_plat_bind(palSocket_t socket, palSocketAddress_t* myAddress, palSocketLength_t addressLength)
{
    int result = PAL_SUCCESS;
    int res = 0;
    struct sockaddr_storage internalAddr = {0} ;

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
    struct sockaddr_storage internalAddr;
    socklen_t addrlen;

    clearSocketFilter((intptr_t)socket);
    addrlen = sizeof(struct sockaddr_storage);
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
                s_fds[j].events = s_fds[j+1].events;
                s_callbacks[j] = s_callbacks[j+1];
                s_callbackArgs[j] = s_callbackArgs[j+1];
            }
            // Blank out the last one
            s_fds[j].fd = 0;
            s_callbacks[j] = 0;
            s_callbackArgs[j] = 0;
            s_nfds--;
            // Tell the poll thread to remove the socket
            pthread_kill(s_pollThread, SIGUSR1);
            break;
        }
    }
    result = pal_osMutexRelease(s_mutexSocketCallbacks);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        return result;
    }

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
    *numInterfaces =  s_palNumOfInterfaces;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t interfaceNum, palNetInterfaceInfo_t * interfaceInfo)
{
    palStatus_t result = PAL_SUCCESS;
    struct ifaddrs *ifap,*ifa;
    int res,n;
    uint32_t found = 0;

    PAL_VALIDATE_ARGUMENTS (interfaceNum >= s_palNumOfInterfaces);

    res = getifaddrs(&ifap);
    if(res < 0)
    {
        result = translateErrorToPALError(errno);
    }
    else
    {
        for (ifa = ifap, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
        {
            if (ifa->ifa_addr == NULL)
                continue;
            int family = ifa->ifa_addr->sa_family;
            if (strcmp(s_palNetworkInterfacesSupported[interfaceNum].interfaceName, ifa->ifa_name) == 0)
            {
                if (family == AF_INET || family == AF_INET6)
                {
                    found = 1;
                    if (family == AF_INET)
                    {
                        interfaceInfo->addressSize = sizeof(struct sockaddr_in);
                    }
                    else
                    {
                        interfaceInfo->addressSize = sizeof(struct sockaddr_in6);
                    }

                    snprintf(interfaceInfo->interfaceName,
                             sizeof(interfaceInfo->interfaceName),
                             s_palNetworkInterfacesSupported[interfaceNum].interfaceName,
                             strlen(s_palNetworkInterfacesSupported[interfaceNum].interfaceName));

                    result = pal_plat_socketAddressToPalSockAddr(ifa->ifa_addr, &interfaceInfo->address, &interfaceInfo->addressSize);

                    break;
                }
            }
        }
        // free what was allocated by getifaddrs
        freeifaddrs(ifap);
    }

    //interface not found error
    if (found != 1 && result == PAL_SUCCESS)
    {
        PAL_LOG_ERR("Cannot find network interface \"%s\"",
            s_palNetworkInterfacesSupported[interfaceNum].interfaceName);
        result = PAL_ERR_GENERIC_FAILURE;
    }

    return result;
}

PAL_PRIVATE palStatus_t registerAsyncSocketParams(palSocket_t socket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    palStatus_t result;

    // Critical section to update globals
    result = pal_osMutexWait(s_mutexSocketCallbacks, PAL_RTOS_WAIT_FOREVER);
    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        return result;
    }

    // make sure a recycled socket structure does not contain obsolete event filter
    clearSocketFilter((intptr_t)socket);

    s_fds[s_nfds].fd = (intptr_t)socket;
    s_fds[s_nfds].events = POLLIN|POLLERR;  // NOTE: POLLOUT is added in asyncSocketManager polling loop for all sockets
    s_callbacks[s_nfds] = callback;
    s_callbackArgs[s_nfds] = callbackArgument;
    s_nfds++;
    result = pal_osMutexRelease(s_mutexSocketCallbacks);

    if (result != PAL_SUCCESS)
    {
        // TODO print error using logging mechanism when available.
        return result;
    }

    // Tell the poll thread to add the new socket
    pthread_kill(s_pollThread, SIGUSR1);
    return result;
}

#if PAL_NET_TCP_AND_TLS_SUPPORT // functionality below supported only in case TCP is supported.

#if PAL_NET_SERVER_SOCKET_API

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


palStatus_t pal_plat_accept(palSocket_t socket, palSocketAddress_t * address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket, palAsyncSocketCallback_t callback, void* callbackArgument)
{
    intptr_t res = 0;
    palStatus_t result = PAL_SUCCESS;
    struct sockaddr_storage internalAddr = {0} ;
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
        result = registerAsyncSocketParams((palSocket_t)res, callback, callbackArgument);
        if(result != PAL_SUCCESS)
        {
            return result;
        }

        *acceptedSocket = (palSocket_t*)res;
        *addressLen = sizeof(palSocketAddress_t);
        result = pal_plat_socketAddressToPalSockAddr((struct sockaddr *)&internalAddr, address, &internalAddrLen);
    }

    return result;
}

#endif // PAL_NET_SERVER_SOCKET_API

palStatus_t pal_plat_connect(palSocket_t socket, const palSocketAddress_t* address, palSocketLength_t addressLen)
{
    int result = PAL_SUCCESS;
    int res;
    struct sockaddr_storage internalAddr = {0} ;

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
    res = send((intptr_t)socket, buf, len, MSG_NOSIGNAL);

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

palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonBlockingSocket, uint32_t interfaceNum, palAsyncSocketCallback_t callback, void* callbackArgument, palSocket_t* socket)
{

    int err;
    int flags;
    palStatus_t result = create_socket(domain,  type,  nonBlockingSocket,  interfaceNum, socket);

    // initialize the socket to be ASYNC so we get SIGIO's for it
    // XXX: this needs to be conditionalized as the blocking IO might have some use also.
    err = fcntl((intptr_t)*socket, F_SETOWN, getpid());
    assert(err != -1);

    flags = fcntl((intptr_t)*socket, F_GETFL, 0);
    assert(flags >= 0);

    flags |= O_ASYNC;

    err = fcntl((intptr_t)*socket, F_SETFL, flags);

    if (err == -1)
    {
        result = translateErrorToPALError(errno);
    }

    if (result == PAL_SUCCESS)
    {
        result = registerAsyncSocketParams(*socket, callback, callbackArgument);
    }

    return result;

}

#if PAL_NET_DNS_SUPPORT

palStatus_t pal_plat_getAddressInfo(const char *hostname, palSocketAddress_t *address, palSocketLength_t* length)
{
    palStatus_t result = PAL_SUCCESS;
    struct addrinfo *pAddrInf = NULL;
    struct addrinfo hints = {0};
    int res;
    int supportedAddressType1;
    int supportedAddressType2;

#if PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_ANY
    supportedAddressType1 = AF_INET;
    supportedAddressType2 = AF_INET6;
    hints.ai_family = AF_UNSPEC;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV4_ONLY
    supportedAddressType1 = AF_INET;
    supportedAddressType2 = AF_INET;
    hints.ai_family = AF_INET;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV6_ONLY
    supportedAddressType1 = AF_INET6;
    supportedAddressType2 = AF_INET6;
    hints.ai_family = AF_INET6;
#else
#error PAL_NET_DNS_IP_SUPPORT is not defined to a valid value.
#endif

    res = getaddrinfo(hostname, NULL, &hints, &pAddrInf);
    if(res < 0)
    {
        // getaddrinfo returns EAI-error. In case of EAI_SYSTEM, the error
        // is 'Other system error, check errno for details'
        // (http://man7.org/linux/man-pages/man3/getaddrinfo.3.html#RETURN_VALUE)
        if (res == EAI_SYSTEM)
        {
            result = translateErrorToPALError(errno);
        }
        else
        {
            // errno values are positive, getaddrinfo errors are negative so they can be mapped
            // in the same place.
            result = translateErrorToPALError(res);
        }
    }
    else
    {
        if ((pAddrInf != NULL) && (pAddrInf->ai_family == supportedAddressType1 || pAddrInf->ai_family == supportedAddressType2))
        {
            result = pal_plat_socketAddressToPalSockAddr((struct sockaddr*)pAddrInf->ai_addr, address, length);
        }
        else
        {
            result = PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
        }

        freeaddrinfo(pAddrInf);
    }

    return result;
}

#if (PAL_DNS_API_VERSION == 3)

PAL_PRIVATE palStatus_t getAddressInfo(const char *hostname, struct addrinfo **addrInfo)
{
    palStatus_t result = PAL_SUCCESS;
    struct addrinfo hints = {0};
    int err;
    int supportedAddressType1;
    int supportedAddressType2;

#if PAL_NET_TCP_AND_TLS_SUPPORT == true
    hints.ai_socktype = SOCK_STREAM;
#else
    hints.ai_socktype = SOCK_DGRAM;
#endif
#if PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_ANY
    supportedAddressType1 = AF_INET;
    supportedAddressType2 = AF_INET6;
    hints.ai_family = AF_UNSPEC;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV4_ONLY
    supportedAddressType1 = AF_INET;
    supportedAddressType2 = AF_INET;
    hints.ai_family = AF_INET;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV6_ONLY
    supportedAddressType1 = AF_INET6;
    supportedAddressType2 = AF_INET6;
    hints.ai_family = AF_INET6;
#else
#error PAL_NET_DNS_IP_SUPPORT is not defined to a valid value.
#endif

    err = getaddrinfo(hostname, NULL, &hints, addrInfo);
    if (err < 0)
    {
        // getaddrinfo returns EAI-error. In case of EAI_SYSTEM, the error
        // is 'Other system error, check errno for details'
        // (http://man7.org/linux/man-pages/man3/getaddrinfo.3.html#RETURN_VALUE)
        if (err == EAI_SYSTEM)
        {
            result = translateErrorToPALError(errno);
        }
        else
        {
            // errno values are positive, getaddrinfo errors are negative so they can be mapped
            // in the same place.
            result = translateErrorToPALError(err);
        }
    }
    else
    {
        // remove addresses that don't match what hints tried to tell
        struct addrinfo *prev = *addrInfo, *curr = *addrInfo;
        while (curr) {
            if ((curr->ai_family != supportedAddressType1 && curr->ai_family != supportedAddressType2) ||
                  curr->ai_socktype != hints.ai_socktype)
            {
                // remove from the list
                if (prev == curr)
                {
                    // remove first item
                    *addrInfo = curr->ai_next;
                    prev = curr->ai_next;
                }
                else
                {
                    // remove from the middle or end
                    prev->ai_next = curr->ai_next;
                    prev = curr;
                }
                free(curr);
                curr = prev->ai_next;
            }
            else
            {
                prev = curr;
                curr = curr->ai_next;
            }
        }
    }

    return result;
}

// Thread function.
PAL_PRIVATE void asyncDNSQueryFunc(void const *arg)
{
    pal_asyncAddressInfo_t *info  = (pal_asyncAddressInfo_t *)(arg);
    struct addrinfo *addr;
    palStatus_t result = getAddressInfo(info->hostname, &addr);
    if (result == PAL_SUCCESS)
    {
        info->addrInfo = (palAddressInfo_t *)addr;
    }
    else
    {
        info->addrInfo = NULL;
    }

    info->callback(info->hostname, info->addrInfo, result, info->callbackArgument); // invoke callback
    free(info);
}

int pal_plat_getDNSCount(palAddressInfo_t *addrInfo)
{
    int count = 0;
    struct addrinfo *curr = (struct addrinfo *)addrInfo;
    while (curr)
    {
        count++;
        curr = curr->ai_next;
    }
    return count;
}

palStatus_t pal_plat_getDNSAddress(palAddressInfo_t *addressInfo, uint16_t index, palSocketAddress_t *addr)
{
    struct addrinfo *info = (struct addrinfo *)addressInfo;
    uint16_t count = 0;
    palStatus_t result = PAL_ERR_INVALID_ARGUMENT;

    while (info)
    {
        if (count == index)
        {
            palSocketLength_t length;
            result = pal_plat_socketAddressToPalSockAddr(info->ai_addr, addr, &length);
            break;
        }
        count++;
        info = info->ai_next;
    }
    return result;
}

void pal_plat_freeAddrInfo(palAddressInfo_t *addressInfo)
{
    freeaddrinfo((struct addrinfo *)addressInfo);
}

palStatus_t pal_plat_free_addressinfoAsync(palDNSQuery_t queryHandle)
{
    return pal_plat_cancelAddressInfoAsync(queryHandle);
}

palStatus_t pal_plat_getAddressInfoAsync(pal_asyncAddressInfo_t *info)
{
    return pal_osThreadCreateWithAlloc(asyncDNSQueryFunc, (void *)info, PAL_osPriorityReservedDNS, PAL_ASYNC_DNS_THREAD_STACK_SIZE, NULL, info->queryHandle);
}

palStatus_t pal_plat_cancelAddressInfoAsync(palDNSQuery_t queryHandle)
{
    // just try to delete thread
    palStatus_t result = PAL_SUCCESS;
    if (queryHandle != NULLPTR)
    {
        palStatus_t result = pal_osThreadTerminate(&queryHandle);
        if (PAL_SUCCESS != result)
        {
            PAL_LOG_ERR("error terminating dns async thread: %d", result);
        }
        queryHandle = NULLPTR;
    }
    return result;
}

#endif // (PAL_DNS_API_VERSION == 3)
#endif // PAL_NET_DNS_SUPPORT

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t interfaceIndex, connectionStatusCallback callback, void *arg)
{
    (void)interfaceIndex;
    (void)callback;
    (void)arg;

    return PAL_ERR_NOT_SUPPORTED;
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

