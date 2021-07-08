/* Copyright (c) 2021 Pelion
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
 */

#ifndef CUSTOM_K_WORK_POLL_H
#define CUSTOM_K_WORK_POLL_H

#include "pal.h"

#include <fcntl.h>
#include <net/socket.h>
#include <kernel.h>

#if defined(PAL_SOCKET_USE_K_WORK_POLL) && (PAL_SOCKET_USE_K_WORK_POLL == 1)
#elif defined(PAL_SOCKET_USE_LONG_POLLING) && (PAL_SOCKET_USE_LONG_POLLING == 1)
#elif defined(PAL_SOCKET_USE_LONG_POLLING_THREAD) && (PAL_SOCKET_USE_LONG_POLLING_THREAD == 1)
#else
#error PAL_SOCKET_USE_K_WORK_POLL, PAL_SOCKET_USE_LONG_POLLING, or PAL_SOCKET_USE_LONG_POLLING_THREAD \
       must be defined and set to 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure for passing arguments across multiple work queue executions.
 */
typedef struct fd_work_poll_s {
#if (defined(PAL_SOCKET_USE_LONG_POLLING) && (PAL_SOCKET_USE_LONG_POLLING == 1)) || \
    (defined(PAL_SOCKET_USE_LONG_POLLING_THREAD) && (PAL_SOCKET_USE_LONG_POLLING_THREAD == 1))
    struct k_work_delayable work;
    int nfds;
    k_ticks_t timeout;
    k_ticks_t remaining;
#else
    struct k_work_poll work;
    int nfds;
    struct k_poll_event poll_events[CONFIG_NET_SOCKETS_POLL_MAX];
    int num_events;
    k_timeout_t timeout;
    uint64_t end;
#endif
    struct zsock_pollfd *fds;
    void (*handler)(struct fd_work_poll_s*);
} fd_work_poll_t;

typedef void (*fd_work_handler_t)(fd_work_poll_t *work);

/**
 * @brief      Custom version of k_work_poll_init for polling file descriptor signals
 *             instead of kernel signals.
 *
 *             Use fd_work_poll_t instead of k_work_poll_t, otherwise usage and API
 *             is the same as k_work_poll_submit.
 *
 * @param      work     Pointer to fd_work_poll_t struct. Stuct must stay in scope
 *                      until handler has been invoked.
 * @param[in]  handler  Handler to be invoked when signal is raised or timeout reached.
 */
void fd_work_poll_init(fd_work_poll_t *work, fd_work_handler_t handler);

/**
 * @brief      Custom version of k_work_poll_submit that takes file descriptor signals
 *             instead of kernel signals.
 *
 *             Use fd_work_poll_t instead of k_work_poll_t, otherwise usage and API
 *             is the same as k_work_poll_submit.
 *
 * @param      work     Pointer to fd_work_poll_t struct. Stuct must stay in scope
 *                      until handler has been invoked.
 * @param      fds      Array of file descriptors to be monitored.
 * @param[in]  nfds     Size of file descriptor array.
 * @param[in]  timeout  k_timeout_t for when handler should be invoked even if signal
 *                      hasn't been raised.
 *
 * @return               0: Work item started watching for events.
 *                 -EINVAL: Work item is being processed or has completed its work.
 *             -EADDRINUSE: Work item is pending on a different workqueue.
 */
int fd_work_poll_submit(fd_work_poll_t *work, struct zsock_pollfd *fds, int nfds, k_timeout_t timeout);

/**
 * @brief      Custom version of k_work_poll_cancel.
 *
 *             Use fd_work_poll_cancel to cancel work pending execution.
 *
 * @param      work  Pointer to fd_work_poll_t struct.
 *
 * @return           0: Work item canceled.
 *             -EINVAL: Work item is being processed or has completed its work.
 */
int fd_work_poll_cancel(fd_work_poll_t *work);

#ifdef __cplusplus
}
#endif

#endif
