/* SPDX-License-Identifier: Apache-2.0
 * Included by the shared POSIX socket implementation for Darwin only.
 */
#include <stddef.h>
#include <sys/event.h>
#include <SystemConfiguration/SystemConfiguration.h>

typedef struct darwin_pal_ipv6 {
    uint16_t family;
    uint16_t port;
    uint32_t flow;
    palIpV6Addr_t address;
    uint32_t scope;
} darwin_pal_ipv6;

typedef struct darwin_socket_watch {
    int fd;
    uintptr_t generation;
    unsigned in_callback;
    bool armed;
    palAsyncSocketCallback_t callback;
    void *argument;
} darwin_socket_watch;

static pthread_mutex_t darwin_network_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t darwin_callbacks_done = PTHREAD_COND_INITIALIZER;
static darwin_socket_watch darwin_watches[PAL_NET_TEST_MAX_ASYNC_SOCKETS];
static pthread_t darwin_poll_thread;
static int darwin_queue = -1;
static bool darwin_closing;
static uintptr_t darwin_next_generation;

static int darwin_configure_socket(int fd, bool nonblocking)
{
    int flags = fcntl(fd, F_GETFL);
    int descriptor_flags = fcntl(fd, F_GETFD);
    int enabled = 1;
    if (flags < 0 || descriptor_flags < 0) return -1;
    if (fcntl(fd, F_SETFL, nonblocking ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) return -1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
}

static bool darwin_valid_interface(uint32_t index)
{
    if (index == PAL_NET_DEFAULT_INTERFACE) return true;
    pthread_mutex_lock(&darwin_network_lock);
    bool valid = index < PAL_MAX_SUPORTED_NET_INTERFACES && s_palNetworkInterfacesSupported[index].interfaceName != NULL;
    pthread_mutex_unlock(&darwin_network_lock);
    return valid;
}

static darwin_socket_watch *darwin_find_watch(int fd)
{
    for (size_t i = 0; i < PAL_NET_TEST_MAX_ASYNC_SOCKETS; ++i) {
        if (darwin_watches[i].fd == fd) return &darwin_watches[i];
    }
    return NULL;
}

static void *darwin_socket_events(void *unused)
{
    (void)unused;
    struct kevent events[PAL_NET_TEST_MAX_ASYNC_SOCKETS * 2 + 1];
    for (;;) {
        int count = kevent(darwin_queue, NULL, 0, events, sizeof(events) / sizeof(events[0]), NULL);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) break;
        pthread_mutex_lock(&darwin_network_lock);
        bool closing = darwin_closing;
        pthread_mutex_unlock(&darwin_network_lock);
        if (closing) break;
        for (int i = 0; i < count; ++i) {
            if (events[i].filter == EVFILT_USER) continue;
            bool duplicate = false;
            for (int j = 0; j < i; ++j) {
                if (events[j].ident == events[i].ident && events[j].udata == events[i].udata) duplicate = true;
            }
            if (duplicate) continue;
            pthread_mutex_lock(&darwin_network_lock);
            darwin_socket_watch *watch = darwin_find_watch((int)events[i].ident);
            if (!watch || watch->generation != (uintptr_t)events[i].udata || darwin_closing) {
                pthread_mutex_unlock(&darwin_network_lock);
                continue;
            }
            ++watch->in_callback;
            palAsyncSocketCallback_t callback = watch->callback;
            void *argument = watch->argument;
            pthread_mutex_unlock(&darwin_network_lock);
            /* Callbacks may close their own socket. Never hold the registry
             * lock while application code runs. Generation IDs reject events
             * queued for a descriptor that has since been closed and reused. */
            callback(argument);
            pthread_mutex_lock(&darwin_network_lock);
            --watch->in_callback;
            pthread_cond_broadcast(&darwin_callbacks_done);
            pthread_mutex_unlock(&darwin_network_lock);
        }
    }
    return NULL;
}

palStatus_t pal_plat_socketsInit(void *context)
{
    (void)context;
    pthread_mutex_lock(&darwin_network_lock);
    if (s_pal_network_initialized) { pthread_mutex_unlock(&darwin_network_lock); return PAL_SUCCESS; }
    darwin_queue = kqueue();
    if (darwin_queue < 0) { pthread_mutex_unlock(&darwin_network_lock); return PAL_ERR_SOCKET_GENERIC; }
    struct kevent wake;
    EV_SET(&wake, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (fcntl(darwin_queue, F_SETFD, FD_CLOEXEC) != 0 || kevent(darwin_queue, &wake, 1, NULL, 0, NULL) != 0) {
        close(darwin_queue);
        darwin_queue = -1;
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_SOCKET_GENERIC;
    }
    for (size_t i = 0; i < PAL_NET_TEST_MAX_ASYNC_SOCKETS; ++i) {
        memset(&darwin_watches[i], 0, sizeof(darwin_watches[i]));
        darwin_watches[i].fd = -1;
    }
    darwin_closing = false;
    if (pthread_create(&darwin_poll_thread, NULL, darwin_socket_events, NULL) != 0) {
        close(darwin_queue);
        darwin_queue = -1;
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_SOCKET_GENERIC;
    }
    s_pal_network_initialized = 1;
    pthread_mutex_unlock(&darwin_network_lock);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_socketsTerminate(void *context)
{
    (void)context;
    pthread_mutex_lock(&darwin_network_lock);
    if (!s_pal_network_initialized) { pthread_mutex_unlock(&darwin_network_lock); return PAL_SUCCESS; }
    if (pthread_equal(pthread_self(), darwin_poll_thread) || darwin_closing) {
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_RTOS_RESOURCE;
    }
    darwin_closing = true;
    struct kevent wake;
    EV_SET(&wake, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(darwin_queue, &wake, 1, NULL, 0, NULL);
    pthread_mutex_unlock(&darwin_network_lock);
    pthread_join(darwin_poll_thread, NULL);
    pthread_mutex_lock(&darwin_network_lock);
    for (size_t i = 0; i < PAL_NET_TEST_MAX_ASYNC_SOCKETS; ++i) {
        if (darwin_watches[i].fd >= 0) close(darwin_watches[i].fd);
        darwin_watches[i].fd = -1;
    }
    close(darwin_queue);
    darwin_queue = -1;
    for (size_t i = 0; i < PAL_MAX_SUPORTED_NET_INTERFACES; ++i) {
        free(s_palNetworkInterfacesSupported[i].interfaceName);
        s_palNetworkInterfacesSupported[i].interfaceName = NULL;
    }
    s_palNumOfInterfaces = 0;
    s_pal_network_initialized = 0;
    pthread_mutex_unlock(&darwin_network_lock);
    return PAL_SUCCESS;
}

PAL_PRIVATE palStatus_t registerAsyncSocketParams(palSocket_t socket, palAsyncSocketCallback_t callback, void *argument)
{
    if (!callback) return PAL_ERR_INVALID_ARGUMENT;
    pthread_mutex_lock(&darwin_network_lock);
    darwin_socket_watch *watch = NULL;
    for (size_t i = 0; i < PAL_NET_TEST_MAX_ASYNC_SOCKETS; ++i) {
        if (darwin_watches[i].fd < 0 && !darwin_watches[i].in_callback) { watch = &darwin_watches[i]; break; }
    }
    if (!watch || !s_pal_network_initialized || darwin_closing || darwin_next_generation == UINTPTR_MAX) {
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_SOCKET_GENERIC;
    }
    watch->fd = (int)(intptr_t)socket;
    watch->generation = ++darwin_next_generation;
    watch->callback = callback;
    watch->argument = argument;
    int type = 0;
    socklen_t type_size = sizeof(type);
    struct sockaddr_storage peer;
    socklen_t peer_size = sizeof(peer);
    watch->armed = getsockopt(watch->fd, SOL_SOCKET, SO_TYPE, &type, &type_size) == 0 &&
        (type != SOCK_STREAM || getpeername(watch->fd, (struct sockaddr *)&peer, &peer_size) == 0);
    struct kevent changes[2];
    unsigned short flags = EV_ADD | EV_CLEAR | (watch->armed ? EV_ENABLE : EV_DISABLE);
    EV_SET(&changes[0], watch->fd, EVFILT_READ, flags, 0, 0, (void *)watch->generation);
    EV_SET(&changes[1], watch->fd, EVFILT_WRITE, flags, 0, 0, (void *)watch->generation);
    int error = kevent(darwin_queue, changes, 2, NULL, 0, NULL);
    if (error) {
        changes[0].flags = changes[1].flags = EV_DELETE;
        kevent(darwin_queue, changes, 2, NULL, 0, NULL);
        watch->fd = -1;
    }
    pthread_mutex_unlock(&darwin_network_lock);
    return error ? PAL_ERR_SOCKET_GENERIC : PAL_SUCCESS;
}

static void darwin_arm_socket(int fd, bool writable)
{
    pthread_mutex_lock(&darwin_network_lock);
    darwin_socket_watch *watch = darwin_find_watch(fd);
    if (watch && !darwin_closing) {
        watch->armed = true;
        struct kevent changes[2];
        EV_SET(&changes[0], fd, EVFILT_READ, EV_ENABLE, 0, 0, (void *)watch->generation);
        EV_SET(&changes[1], fd, EVFILT_WRITE, writable ? EV_ENABLE : EV_DISABLE, 0, 0, (void *)watch->generation);
        kevent(darwin_queue, changes, 2, NULL, 0, NULL);
    }
    pthread_mutex_unlock(&darwin_network_lock);
}

PAL_PRIVATE void clearSocketFilter(int fd)
{
    pthread_mutex_lock(&darwin_network_lock);
    darwin_socket_watch *watch = darwin_find_watch(fd);
    if (watch && watch->armed && !darwin_closing) {
        /* Reading part of a buffer must leave its remaining bytes observable.
         * Writes use kqueue's normal transition to writable after backpressure. */
        struct kevent change;
        EV_SET(&change, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)watch->generation);
        kevent(darwin_queue, &change, 1, NULL, 0, NULL);
    }
    pthread_mutex_unlock(&darwin_network_lock);
}

palStatus_t pal_plat_close(palSocket_t *socket)
{
    if (!socket) return PAL_ERR_INVALID_ARGUMENT;
    int fd = (int)(intptr_t)*socket;
    if (fd == PAL_LINUX_INVALID_SOCKET) return PAL_SUCCESS;
    pthread_mutex_lock(&darwin_network_lock);
    darwin_socket_watch *watch = darwin_find_watch(fd);
    uintptr_t generation = watch ? watch->generation : 0;
    if (watch) {
        watch->fd = -1;
        struct kevent changes[2];
        EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        kevent(darwin_queue, changes, 2, NULL, 0, NULL);
    }
    if (watch && !pthread_equal(pthread_self(), darwin_poll_thread)) {
        while (watch->generation == generation && watch->in_callback) pthread_cond_wait(&darwin_callbacks_done, &darwin_network_lock);
    }
    /* Keep the native descriptor reserved until an in-flight callback returns.
     * Otherwise its I/O could hit a different socket that reused this number. */
    int error = close(fd);
    int saved = errno;
    if (!error) *socket = (palSocket_t)(intptr_t)PAL_LINUX_INVALID_SOCKET;
    pthread_mutex_unlock(&darwin_network_lock);
    return error ? translateErrorToPALError(saved) : PAL_SUCCESS;
}

palStatus_t pal_plat_registerNetworkInterface(void *context, uint32_t *index)
{
    if (!context || !index || strlen(context) >= IF_NAMESIZE) return PAL_ERR_INVALID_ARGUMENT;
    pthread_mutex_lock(&darwin_network_lock);
    uint32_t free_index = PAL_MAX_SUPORTED_NET_INTERFACES;
    for (uint32_t i = 0; i < PAL_MAX_SUPORTED_NET_INTERFACES; ++i) {
        const char *name = s_palNetworkInterfacesSupported[i].interfaceName;
        if (name && !strcmp(name, context)) { *index = i; pthread_mutex_unlock(&darwin_network_lock); return PAL_SUCCESS; }
        if (!name && free_index == PAL_MAX_SUPORTED_NET_INTERFACES) free_index = i;
    }
    if (free_index == PAL_MAX_SUPORTED_NET_INTERFACES) {
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_SOCKET_MAX_NUMBER_OF_INTERFACES_REACHED;
    }
    char *copy = strdup(context);
    if (!copy) { pthread_mutex_unlock(&darwin_network_lock); return PAL_ERR_NO_MEMORY; }
    s_palNetworkInterfacesSupported[free_index].interfaceName = copy;
    ++s_palNumOfInterfaces;
    *index = free_index;
    pthread_mutex_unlock(&darwin_network_lock);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_unregisterNetworkInterface(uint32_t index)
{
    pthread_mutex_lock(&darwin_network_lock);
    if (index >= PAL_MAX_SUPORTED_NET_INTERFACES || !s_palNetworkInterfacesSupported[index].interfaceName) {
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_INVALID_ARGUMENT;
    }
    free(s_palNetworkInterfacesSupported[index].interfaceName);
    s_palNetworkInterfacesSupported[index].interfaceName = NULL;
    --s_palNumOfInterfaces;
    pthread_mutex_unlock(&darwin_network_lock);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_getNumberOfNetInterfaces(uint32_t *count)
{
    if (!count) return PAL_ERR_INVALID_ARGUMENT;
    pthread_mutex_lock(&darwin_network_lock);
    *count = s_palNumOfInterfaces;
    pthread_mutex_unlock(&darwin_network_lock);
    return PAL_SUCCESS;
}

static bool darwin_primary_interface(char name[IF_NAMESIZE])
{
    const CFStringRef keys[] = {CFSTR("State:/Network/Global/IPv4"), CFSTR("State:/Network/Global/IPv6")};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        CFPropertyListRef value = SCDynamicStoreCopyValue(NULL, keys[i]);
        bool found = false;
        if (value && CFGetTypeID(value) == CFDictionaryGetTypeID()) {
            CFStringRef primary = CFDictionaryGetValue((CFDictionaryRef)value, CFSTR("PrimaryInterface"));
            found = primary && CFGetTypeID(primary) == CFStringGetTypeID() &&
                CFStringGetCString(primary, name, IF_NAMESIZE, kCFStringEncodingUTF8);
        }
        if (value) CFRelease(value);
        if (found) return true;
    }
    return false;
}

palStatus_t pal_plat_getNetInterfaceInfo(uint32_t index, palNetInterfaceInfo_t *info)
{
    if (!info) return PAL_ERR_INVALID_ARGUMENT;
    char name[IF_NAMESIZE];
    pthread_mutex_lock(&darwin_network_lock);
    if (index >= PAL_MAX_SUPORTED_NET_INTERFACES || !s_palNetworkInterfacesSupported[index].interfaceName) {
        pthread_mutex_unlock(&darwin_network_lock);
        return PAL_ERR_INVALID_ARGUMENT;
    }
    strlcpy(name, s_palNetworkInterfacesSupported[index].interfaceName, sizeof(name));
    pthread_mutex_unlock(&darwin_network_lock);
    if (!strcmp(name, "default") && !darwin_primary_interface(name)) return PAL_ERR_GENERIC_FAILURE;
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) return translateErrorToPALError(errno);
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    memset(info, 0, sizeof(*info));
    for (struct ifaddrs *entry = interfaces; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || !(entry->ifa_flags & IFF_UP) || strcmp(name, entry->ifa_name)) continue;
        if (entry->ifa_addr->sa_family != AF_INET && entry->ifa_addr->sa_family != AF_INET6) continue;
        status = pal_plat_socketAddressToPalSockAddr(entry->ifa_addr, &info->address, &info->addressSize);
        strlcpy(info->interfaceName, name, sizeof(info->interfaceName));
        if (status == PAL_SUCCESS) break;
    }
    freeifaddrs(interfaces);
    return status;
}
