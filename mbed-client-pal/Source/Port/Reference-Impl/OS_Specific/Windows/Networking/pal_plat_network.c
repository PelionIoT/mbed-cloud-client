/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <process.h>
#include <stdlib.h>
#include <string.h>
#include "pal_plat_network.h"

typedef struct win_socket {
    SOCKET socket;
    WSAEVENT events;
    HANDLE stop;
    HANDLE thread;
    unsigned thread_id;
    volatile LONG references;
    volatile LONG closing;
    volatile LONG connect_error;
    bool nonblocking;
    palAsyncSocketCallback_t callback;
    void *argument;
} win_socket;

static SRWLOCK network_lock = SRWLOCK_INIT;
static LONG initializations;
static volatile LONG socket_count;
static bool registered;

static palStatus_t socket_error(int error)
{
    switch (error) {
        case 0: return PAL_SUCCESS;
        case WSAEWOULDBLOCK: return PAL_ERR_SOCKET_WOULD_BLOCK;
        case WSAEINPROGRESS: case WSAEALREADY: return PAL_ERR_SOCKET_IN_PROGRES;
        case WSAEISCONN: return PAL_ERR_SOCKET_ALREADY_CONNECTED;
        case WSAEADDRINUSE: return PAL_ERR_SOCKET_ADDRESS_IN_USE;
        case WSAEADDRNOTAVAIL: return PAL_ERR_SOCKET_INVALID_ADDRESS;
        case WSAEAFNOSUPPORT: return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
        case WSAENETUNREACH: case WSAEHOSTUNREACH: return PAL_ERR_SOCKET_HOST_UNREACHABLE;
        case WSAECONNABORTED: return PAL_ERR_SOCKET_CONNECTION_ABORTED;
        case WSAECONNRESET: return PAL_ERR_SOCKET_CONNECTION_RESET;
        case WSAECONNREFUSED: return PAL_ERR_SOCKET_CONNECTION_ABORTED;
        case WSAENOTCONN: return PAL_ERR_SOCKET_NOT_CONNECTED;
        case WSAETIMEDOUT: return PAL_ERR_SOCKET_WOULD_BLOCK;
        case WSAENOBUFS: return PAL_ERR_SOCKET_NO_BUFFERS;
        case WSAEACCES: return PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED;
        case WSAEMSGSIZE: return PAL_ERR_SOCKET_SEND_BUFFER_TOO_BIG;
        case WSAEINVAL: case WSAENOTSOCK: return PAL_ERR_SOCKET_INVALID_VALUE;
        case WSAEINTR: return PAL_ERR_SOCKET_INTERRUPTED;
        case WSAENOPROTOOPT: return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
        default: return PAL_ERR_SOCKET_GENERIC;
    }
}

/* PAL uses Linux family numbers (IPv6 == 10); Winsock uses IPv6 == 23.
 * The remaining sockaddr_in/in6 layout matches PAL. Copy rather than cast:
 * palSocketAddress_t has only two-byte alignment. */
static palStatus_t native_address(const palSocketAddress_t *pal, palSocketLength_t length,
    struct sockaddr_storage *native, int *native_length)
{
    int family;
    if (!pal) return PAL_ERR_SOCKET_INVALID_ADDRESS;
    if (pal->addressType == PAL_AF_INET) { family = AF_INET; *native_length = sizeof(struct sockaddr_in); }
    else if (pal->addressType == PAL_AF_INET6) { family = AF_INET6; *native_length = sizeof(struct sockaddr_in6); }
    else return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    if (length < (palSocketLength_t)*native_length) return PAL_ERR_SOCKET_INVALID_VALUE;
    memset(native, 0, sizeof(*native));
    memcpy(native, pal, (size_t)*native_length);
    native->ss_family = (ADDRESS_FAMILY)family;
    return PAL_SUCCESS;
}

static palStatus_t pal_address(const struct sockaddr *native, int length,
    palSocketAddress_t *pal, palSocketLength_t *pal_length)
{
    unsigned short family;
    size_t size;
    if (!native || !pal || !pal_length) return PAL_ERR_SOCKET_INVALID_VALUE;
    if (native->sa_family == AF_INET) { family = PAL_AF_INET; size = sizeof(struct sockaddr_in); }
    else if (native->sa_family == AF_INET6) { family = PAL_AF_INET6; size = sizeof(struct sockaddr_in6); }
    else return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    if (length < (int)size || size > sizeof(*pal)) return PAL_ERR_SOCKET_INVALID_VALUE;
    memset(pal, 0, sizeof(*pal));
    memcpy(pal, native, size);
    pal->addressType = family;
    *pal_length = (palSocketLength_t)size;
    return PAL_SUCCESS;
}

static void socket_release(win_socket *socket)
{
    if (InterlockedDecrement(&socket->references) == 0) {
        closesocket(socket->socket);
        if (socket->events != WSA_INVALID_EVENT) WSACloseEvent(socket->events);
        if (socket->stop) CloseHandle(socket->stop);
        if (socket->thread) CloseHandle(socket->thread);
        InterlockedDecrement(&socket_count);
        free(socket);
    }
}

static unsigned __stdcall socket_events(void *argument)
{
    win_socket *socket = argument;
    HANDLE objects[2] = {socket->stop, socket->events};
    while (WaitForMultipleObjects(2, objects, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
        WSANETWORKEVENTS events;
        if (InterlockedCompareExchange(&socket->closing, 0, 0)) break;
        if (WSAEnumNetworkEvents(socket->socket, socket->events, &events) == SOCKET_ERROR) break;
        if (events.lNetworkEvents & FD_CONNECT) InterlockedExchange(&socket->connect_error, events.iErrorCode[FD_CONNECT_BIT]);
        /* Close from this callback is permitted. Its worker reference remains
         * alive until this loop exits; close from another thread waits for it. */
        if (events.lNetworkEvents && !InterlockedCompareExchange(&socket->closing, 0, 0)) socket->callback(socket->argument);
    }
    socket_release(socket);
    return 0;
}

static palStatus_t wrap_socket(SOCKET native, bool nonblocking, palAsyncSocketCallback_t callback,
    void *argument, palSocket_t *out)
{
    win_socket *socket = calloc(1, sizeof(*socket));
    u_long mode = nonblocking ? 1 : 0;
    palStatus_t status = PAL_ERR_SOCKET_ALLOCATION_FAILED;
    if (!socket) { closesocket(native); return PAL_ERR_NO_MEMORY; }
    socket->socket = native;
    socket->events = WSA_INVALID_EVENT;
    socket->nonblocking = nonblocking;
    socket->callback = callback;
    socket->argument = argument;
    socket->references = 1;
    InterlockedIncrement(&socket_count);
    /* Synchronous sockets are usable without a callback. Event-selected
     * Winsock sockets are necessarily nonblocking. */
    if (callback && !nonblocking) { status = PAL_ERR_NOT_SUPPORTED; goto failed; }
    if (ioctlsocket(native, FIONBIO, &mode) == SOCKET_ERROR) {
        status = socket_error(WSAGetLastError()); goto failed;
    }
    if (callback) {
        socket->events = WSACreateEvent();
        socket->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (socket->events == WSA_INVALID_EVENT || !socket->stop) goto failed;
        if (WSAEventSelect(native, socket->events, FD_READ | FD_WRITE | FD_CONNECT | FD_ACCEPT | FD_CLOSE) == SOCKET_ERROR) {
            status = socket_error(WSAGetLastError()); goto failed;
        }
        socket->thread = (HANDLE)_beginthreadex(NULL, 0, socket_events, socket, CREATE_SUSPENDED, &socket->thread_id);
        if (!socket->thread) goto failed;
        InterlockedIncrement(&socket->references);
    }
    *out = socket;
    if (socket->thread) ResumeThread(socket->thread);
    return PAL_SUCCESS;
failed:
    socket_release(socket);
    return status;
}

palStatus_t pal_plat_socketsInit(void *context)
{
    WSADATA data;
    int error = 0;
    (void)context;
    AcquireSRWLockExclusive(&network_lock);
    if (!initializations) error = WSAStartup(MAKEWORD(2, 2), &data);
    if (!error) ++initializations;
    ReleaseSRWLockExclusive(&network_lock);
    return socket_error(error);
}

palStatus_t pal_plat_socketsTerminate(void *context)
{
    palStatus_t status = PAL_SUCCESS;
    (void)context;
    AcquireSRWLockExclusive(&network_lock);
    if (initializations == 1 && InterlockedCompareExchange(&socket_count, 0, 0)) status = PAL_ERR_SOCKET_OPERATION_NOT_PERMITTED;
    else if (initializations && --initializations == 0) { WSACleanup(); registered = false; }
    ReleaseSRWLockExclusive(&network_lock);
    return status;
}

palStatus_t pal_plat_registerNetworkInterface(void *context, uint32_t *index)
{
    if (!index) return PAL_ERR_INVALID_ARGUMENT;
    /* Initial direct-connect profile delegates adapter selection to Windows. */
    if (context && *(const char *)context && strcmp(context, "default")) return PAL_ERR_NOT_SUPPORTED;
    AcquireSRWLockExclusive(&network_lock);
    registered = true;
    *index = 0;
    ReleaseSRWLockExclusive(&network_lock);
    return PAL_SUCCESS;
}
palStatus_t pal_plat_unregisterNetworkInterface(uint32_t index)
{
    if (index != 0) return PAL_ERR_INVALID_ARGUMENT;
    AcquireSRWLockExclusive(&network_lock);
    registered = false;
    ReleaseSRWLockExclusive(&network_lock);
    return PAL_SUCCESS;
}
palStatus_t pal_plat_getNumberOfNetInterfaces(uint32_t *count)
{
    if (!count) return PAL_ERR_INVALID_ARGUMENT;
    AcquireSRWLockShared(&network_lock);
    *count = registered ? 1 : 0;
    ReleaseSRWLockShared(&network_lock);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t index, palNetInterfaceInfo_t *info)
{
    IP_ADAPTER_ADDRESSES *adapters = NULL, *adapter;
    ULONG size = 0, result;
    palStatus_t status = PAL_ERR_SOCKET_INVALID_ADDRESS;
    uint32_t count;
    if (!info || index != 0) return PAL_ERR_INVALID_ARGUMENT;
    pal_plat_getNumberOfNetInterfaces(&count);
    if (!count) return PAL_ERR_SOCKET_INVALID_VALUE;
    memset(info, 0, sizeof(*info));
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, NULL, &size);
    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        free(adapters);
        adapters = malloc(size);
        if (!adapters) return PAL_ERR_NO_MEMORY;
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, adapters, &size);
    }
    if (result == NO_ERROR) {
        for (adapter = adapters; adapter && status != PAL_SUCCESS; adapter = adapter->Next) {
            IP_ADAPTER_UNICAST_ADDRESS *address;
            if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            for (address = adapter->FirstUnicastAddress; address; address = address->Next) {
                status = pal_address(address->Address.lpSockaddr, address->Address.iSockaddrLength, &info->address, &info->addressSize);
                if (status == PAL_SUCCESS) { strcpy_s(info->interfaceName, sizeof(info->interfaceName), "default"); break; }
            }
        }
    }
    free(adapters);
    return status;
}

palStatus_t pal_plat_asynchronousSocket(palSocketDomain_t domain, palSocketType_t type, bool nonblocking,
    uint32_t interface_index, palAsyncSocketCallback_t callback, void *argument, palSocket_t *out)
{
    SOCKET native;
    int family, socket_type;
    palStatus_t status;
    if (!out) return PAL_ERR_INVALID_ARGUMENT;
    *out = NULL;
    if (interface_index != 0 && interface_index != PAL_NET_DEFAULT_INTERFACE) return PAL_ERR_SOCKET_INVALID_VALUE;
    if (domain == PAL_AF_INET) family = AF_INET;
    else if (domain == PAL_AF_INET6) family = AF_INET6;
    else return PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY;
    if (type == PAL_SOCK_DGRAM) socket_type = SOCK_DGRAM;
    else if (type == PAL_SOCK_STREAM || type == PAL_SOCK_STREAM_SERVER) socket_type = SOCK_STREAM;
    else return PAL_ERR_SOCKET_INVALID_VALUE;
    AcquireSRWLockShared(&network_lock);
    if (!initializations) { ReleaseSRWLockShared(&network_lock); return PAL_ERR_NOT_INITIALIZED; }
    native = socket(family, socket_type, 0);
    status = native == INVALID_SOCKET ? socket_error(WSAGetLastError()) : wrap_socket(native, nonblocking, callback, argument, out);
    ReleaseSRWLockShared(&network_lock);
    return status;
}

palStatus_t pal_plat_isNonBlocking(palSocket_t handle, bool *nonblocking)
{
    if (!handle || !nonblocking) return PAL_ERR_INVALID_ARGUMENT;
    *nonblocking = ((win_socket *)handle)->nonblocking;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_bind(palSocket_t handle, palSocketAddress_t *address, palSocketLength_t length)
{
    struct sockaddr_storage native;
    int size;
    palStatus_t status;
    if (!handle) return PAL_ERR_SOCKET_INVALID_VALUE;
    status = native_address(address, length, &native, &size);
    if (status != PAL_SUCCESS) return status;
    return bind(((win_socket *)handle)->socket, (struct sockaddr *)&native, size) == SOCKET_ERROR ? socket_error(WSAGetLastError()) : PAL_SUCCESS;
}

palStatus_t pal_plat_sendTo(palSocket_t handle, const void *buffer, size_t length,
    const palSocketAddress_t *to, palSocketLength_t to_length, size_t *sent)
{
    struct sockaddr_storage native;
    int size, result;
    palStatus_t status;
    if (!sent) return PAL_ERR_INVALID_ARGUMENT;
    *sent = 0;
    if (!handle || (!buffer && length)) return PAL_ERR_INVALID_ARGUMENT;
    if (length > INT_MAX) return PAL_ERR_SOCKET_SEND_BUFFER_TOO_BIG;
    status = native_address(to, to_length, &native, &size);
    if (status != PAL_SUCCESS) return status;
    result = sendto(((win_socket *)handle)->socket, buffer, (int)length, 0, (struct sockaddr *)&native, size);
    if (result == SOCKET_ERROR) return socket_error(WSAGetLastError());
    *sent = (size_t)result;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_receiveFrom(palSocket_t handle, void *buffer, size_t length,
    palSocketAddress_t *from, palSocketLength_t *from_length, size_t *received)
{
    struct sockaddr_storage native;
    int size = sizeof(native), result;
    if (!received) return PAL_ERR_INVALID_ARGUMENT;
    *received = 0;
    if (!handle || (!buffer && length) || (from && !from_length)) return PAL_ERR_INVALID_ARGUMENT;
    if (length > INT_MAX) length = INT_MAX;
    result = recvfrom(((win_socket *)handle)->socket, buffer, (int)length, 0, (struct sockaddr *)&native, &size);
    if (result == SOCKET_ERROR) return socket_error(WSAGetLastError());
    *received = (size_t)result;
    return from ? pal_address((struct sockaddr *)&native, size, from, from_length) : PAL_SUCCESS;
}

palStatus_t pal_plat_connect(palSocket_t handle, const palSocketAddress_t *address, palSocketLength_t length)
{
    win_socket *socket = handle;
    struct sockaddr_storage native;
    int size, error;
    palStatus_t status;
    if (!socket) return PAL_ERR_INVALID_ARGUMENT;
    error = (int)InterlockedCompareExchange(&socket->connect_error, 0, 0);
    if (error) return socket_error(error);
    status = native_address(address, length, &native, &size);
    if (status != PAL_SUCCESS) return status;
    if (connect(socket->socket, (struct sockaddr *)&native, size) == 0) return PAL_SUCCESS;
    error = WSAGetLastError();
    return error == WSAEWOULDBLOCK ? PAL_ERR_SOCKET_IN_PROGRES : socket_error(error);
}

palStatus_t pal_plat_recv(palSocket_t handle, void *buffer, size_t length, size_t *received)
{
    int result;
    if (!received) return PAL_ERR_INVALID_ARGUMENT;
    *received = 0;
    if (!handle || (!buffer && length)) return PAL_ERR_INVALID_ARGUMENT;
    if (!length) return PAL_SUCCESS;
    if (length > INT_MAX) length = INT_MAX;
    result = recv(((win_socket *)handle)->socket, buffer, (int)length, 0);
    if (result == SOCKET_ERROR) return socket_error(WSAGetLastError());
    if (!result) return PAL_ERR_SOCKET_CONNECTION_CLOSED;
    *received = (size_t)result;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_send(palSocket_t handle, const void *buffer, size_t length, size_t *sent)
{
    int result, error;
    if (!sent) return PAL_ERR_INVALID_ARGUMENT;
    *sent = 0;
    if (!handle || (!buffer && length)) return PAL_ERR_INVALID_ARGUMENT;
    error = (int)InterlockedCompareExchange(&((win_socket *)handle)->connect_error, 0, 0);
    if (error) return socket_error(error);
    if (length > INT_MAX) length = INT_MAX;
    result = send(((win_socket *)handle)->socket, buffer, (int)length, 0);
    if (result == SOCKET_ERROR) return socket_error(WSAGetLastError());
    *sent = (size_t)result;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_listen(palSocket_t handle, int backlog)
{
    if (!handle) return PAL_ERR_INVALID_ARGUMENT;
    return listen(((win_socket *)handle)->socket, backlog) == SOCKET_ERROR ? socket_error(WSAGetLastError()) : PAL_SUCCESS;
}

palStatus_t pal_plat_accept(palSocket_t handle, palSocketAddress_t *address, palSocketLength_t *length,
    palSocket_t *accepted, palAsyncSocketCallback_t callback, void *argument)
{
    struct sockaddr_storage native;
    int size = sizeof(native);
    SOCKET result;
    palStatus_t status;
    if (!accepted) return PAL_ERR_INVALID_ARGUMENT;
    *accepted = NULL;
    if (!handle || (address && !length)) return PAL_ERR_INVALID_ARGUMENT;
    result = accept(((win_socket *)handle)->socket, (struct sockaddr *)&native, &size);
    if (result == INVALID_SOCKET) return socket_error(WSAGetLastError());
    if (address) {
        status = pal_address((struct sockaddr *)&native, size, address, length);
        if (status != PAL_SUCCESS) { closesocket(result); return status; }
    }
    /* Accepted sockets inherit the listener's event selection: clear it before
     * configuring their own callback and blocking mode. */
    WSAEventSelect(result, NULL, 0);
    return wrap_socket(result, ((win_socket *)handle)->nonblocking, callback, argument, accepted);
}

palStatus_t pal_plat_close(palSocket_t *handle)
{
    win_socket *socket;
    if (!handle || !*handle) return PAL_ERR_INVALID_ARGUMENT;
    socket = *handle;
    *handle = NULL;
    InterlockedExchange(&socket->closing, 1);
    if (socket->stop) SetEvent(socket->stop);
    shutdown(socket->socket, SD_BOTH);
    if (socket->thread && GetCurrentThreadId() != socket->thread_id) WaitForSingleObject(socket->thread, INFINITE);
    socket_release(socket);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_setSocketOptionsWithLevel(palSocket_t handle, palSocketOptionLevelName_t level,
    int option, const void *value, palSocketLength_t length)
{
    int native_level = SOL_SOCKET, native_option;
    if (!handle || !value || length != sizeof(int)) return PAL_ERR_SOCKET_INVALID_VALUE;
    if (level == PAL_SOL_IPPROTO_IPV6) {
        native_level = IPPROTO_IPV6;
        if (option == PAL_SO_IPV6_MULTICAST_HOPS) native_option = IPV6_MULTICAST_HOPS;
        else return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    } else if (level == PAL_SOL_SOCKET) {
        switch (option) {
            case PAL_SO_REUSEADDR: native_option = SO_REUSEADDR; break;
            case PAL_SO_KEEPALIVE: native_option = SO_KEEPALIVE; break;
            case PAL_SO_SNDTIMEO: native_option = SO_SNDTIMEO; break;
            case PAL_SO_RCVTIMEO: native_option = SO_RCVTIMEO; break;
            case PAL_SO_KEEPIDLE: native_level = IPPROTO_TCP; native_option = TCP_KEEPIDLE; break;
            case PAL_SO_KEEPINTVL: native_level = IPPROTO_TCP; native_option = TCP_KEEPINTVL; break;
            default: return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
        }
    } else return PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED;
    return setsockopt(((win_socket *)handle)->socket, native_level, native_option, value, (int)length) == SOCKET_ERROR
        ? socket_error(WSAGetLastError()) : PAL_SUCCESS;
}
palStatus_t pal_plat_setSocketOptions(palSocket_t handle, int option, const void *value, palSocketLength_t length)
{
    return pal_plat_setSocketOptionsWithLevel(handle, PAL_SOL_SOCKET, option, value, length);
}

#if PAL_NET_DNS_SUPPORT && (PAL_DNS_API_VERSION == 0 || PAL_DNS_API_VERSION == 1)
palStatus_t pal_plat_getAddressInfo(const char *hostname, palSocketAddress_t *address, palSocketLength_t *length)
{
    struct addrinfo hints = {0}, *addresses = NULL, *entry;
    palStatus_t status = PAL_ERR_SOCKET_DNS_ERROR;
    if (!hostname || !address || !length) return PAL_ERR_INVALID_ARGUMENT;
    *length = 0;
    hints.ai_socktype = SOCK_STREAM;
#if PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV4_ONLY
    hints.ai_family = AF_INET;
#elif PAL_NET_DNS_IP_SUPPORT == PAL_NET_DNS_IPV6_ONLY
    hints.ai_family = AF_INET6;
#else
    hints.ai_family = AF_UNSPEC;
#endif
    if (getaddrinfo(hostname, NULL, &hints, &addresses) != 0) return status;
    for (entry = addresses; entry; entry = entry->ai_next) {
        status = pal_address(entry->ai_addr, (int)entry->ai_addrlen, address, length);
        if (status == PAL_SUCCESS) break;
    }
    freeaddrinfo(addresses);
    return status;
}
#elif PAL_NET_DNS_SUPPORT
#error "Windows PAL currently uses DNS API 0 or PAL's generic asynchronous DNS API 1."
#endif

palStatus_t pal_plat_setConnectionStatusCallback(uint32_t index, connectionStatusCallback callback, void *argument)
{
    (void)index; (void)callback; (void)argument;
    return PAL_ERR_NOT_SUPPORTED; /* Same contract as the existing Linux PAL. */
}
uint8_t pal_plat_getRttEstimate(void) { return PAL_DEFAULT_RTT_ESTIMATE; }
uint16_t pal_plat_getStaggerEstimate(uint16_t amount) { (void)amount; return PAL_DEFAULT_STAGGER_ESTIMATE; }
