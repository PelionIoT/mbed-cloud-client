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

#include "fd_work_poll.h"

#if (defined(PAL_SOCKET_USE_LONG_POLLING) && (PAL_SOCKET_USE_LONG_POLLING == 1)) || \
    (defined(PAL_SOCKET_USE_LONG_POLLING_THREAD) && (PAL_SOCKET_USE_LONG_POLLING_THREAD == 1))

#ifndef CONFIG_NET_SOCKETS_POSIX_NAMES
#include <poll.h>
#endif

#if 0
#include <stdio.h>
#define FD_POLL_DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define FD_POLL_DEBUG_PRINT(...)
#endif

#include <logging/log.h>
LOG_MODULE_REGISTER(fd_net_sock, CONFIG_NET_SOCKETS_LOG_LEVEL);


#if defined(PAL_SOCKET_USE_LONG_POLLING_THREAD) && (PAL_SOCKET_USE_LONG_POLLING_THREAD == 1)
/**
 * Use dedicated work queue running in its own thread.
 * Poll is called blocking with an exponentially increasing
 * timeout until a maximum is reached.
 */

/* Min and max polling interval:
 * Min should be larger than the round-trip-time.
 * Max should be less than the CoAP retransmission time (default 2 seconds).
 */
#define FD_POLLING_MS_MIN 10
#define FD_POLLING_MS_MAX (60*1000)

#define FD_WORK_STACK_SIZE 1024
#define FD_WORK_PRIORITY 5

#define WORK_QUEUE_NAME fd_work_q

static K_THREAD_STACK_DEFINE(fd_work_stack_area, FD_WORK_STACK_SIZE);
static struct k_work_q fd_work_q;

#else
/**
 * Default to using the built-in system work queue.
 * Poll is called non-blocking with an exponentially growing
 * interval until a maximum has ben reached.
 */

/* Min and max polling interval:
 * Min should be larger than the round-trip-time.
 * Max should be less than the CoAP retransmission time (default 2 seconds).
 */
#define FD_POLLING_MS_MIN 10
#define FD_POLLING_MS_MAX (1000)

#define WORK_QUEUE_NAME k_sys_work_q
#endif

static K_MUTEX_DEFINE(fd_work_mutex);

static void fd_work_delayed_handler(struct k_work* work);

void fd_work_poll_init(fd_work_poll_t *work, fd_work_handler_t handler)
{

#if defined(PAL_SOCKET_USE_LONG_POLLING_THREAD) && (PAL_SOCKET_USE_LONG_POLLING_THREAD == 1)
    static bool need_init = true;

    if (need_init) {
        need_init = false;

        k_work_q_start(&fd_work_q, fd_work_stack_area,
               K_THREAD_STACK_SIZEOF(fd_work_stack_area), FD_WORK_PRIORITY);
    }
#endif

    k_work_init_delayable(&work->work, fd_work_delayed_handler);

    work->handler = handler;
}

int fd_work_poll_submit(fd_work_poll_t *work, struct zsock_pollfd *fds, int nfds, k_timeout_t timeout)
{
    FD_POLL_DEBUG_PRINT("fd_work_poll_submit\r\n");

    if (work && fds) {

        /* Work is submitted from another thread. Ensure all values are set atomically. */
        k_mutex_lock(&fd_work_mutex, K_FOREVER);

        work->fds = fds;
        work->nfds = nfds;
        work->timeout = k_ms_to_ticks_floor32(FD_POLLING_MS_MIN);
        work->remaining = timeout.ticks;

        k_mutex_unlock(&fd_work_mutex);

        /* wait at least one polling interval before actually polling. */
        k_work_reschedule_for_queue(&WORK_QUEUE_NAME,
                                    &work->work,
                                    Z_TIMEOUT_TICKS(work->timeout));
    }

    return 0;
}

static void fd_work_delayed_handler(struct k_work* input)
{
    FD_POLL_DEBUG_PRINT("fd_work_delayed_handler\r\n");

    /**
     * Get the encapsulating container which contains variables carried across
     * work queue invocations.
     */
    struct k_work_delayable* delayed = CONTAINER_OF(input, struct k_work_delayable, work);

    fd_work_poll_t* work = CONTAINER_OF(delayed, fd_work_poll_t, work);

    /* Work is submitted from another thread. Ensure all values are read atomically. */
    k_mutex_lock(&fd_work_mutex, K_FOREVER);

    struct zsock_pollfd *fds = work->fds;
    int nfds = work->nfds;
    k_ticks_t timeout = work->timeout;
    k_ticks_t remaining = work->remaining;
    fd_work_handler_t handler = work->handler;

    /* set remaining time if timeout is not set to be forever. */
    if (remaining != K_TICKS_FOREVER) {

        /* don't let time underflow */
        remaining = (remaining > timeout) ? remaining - timeout : 0;

        /* store remaining time in work struct */
        work->remaining = remaining;
    }

    /* set next exponential backoff timer if still beneath max threshold. */
    if (timeout < k_ms_to_ticks_floor32(FD_POLLING_MS_MAX)) {

        timeout *= 2;

        /* store timeout in work struct */
        work->timeout = timeout;
    }

    k_mutex_unlock(&fd_work_mutex);

    /* If the work has been cancelled, the number of file descriptors will be zero. */
    if (nfds) {

#if defined(PAL_SOCKET_USE_LONG_POLLING_THREAD) && (PAL_SOCKET_USE_LONG_POLLING_THREAD == 1)
        k_ticks_t poll_timeout = timeout;
        k_ticks_t work_delay = 0;
#else
        k_ticks_t poll_timeout = 0;
        k_ticks_t work_delay = timeout;
#endif

        /* do a non-blocking poll to minimize execution time in the shared work queue. */
        int status = poll(fds, nfds, k_ticks_to_ms_floor32(poll_timeout));

        FD_POLL_DEBUG_PRINT("timeout: %d\r\n", k_ticks_to_ms_floor32(timeout));
        FD_POLL_DEBUG_PRINT("remaining: %d\r\n", k_ticks_to_ms_floor32(remaining));

        /* stop polling and invoke callback if events are ready or timeout is reached. */
        if (status ||
           ((remaining != K_TICKS_FOREVER) && (remaining <= timeout))) {

            /* invoke callback. */
            if (handler) {
                handler(work);
            }
        } else {

            /* reschedule work. */
            k_work_reschedule_for_queue(&WORK_QUEUE_NAME,
                                        delayed,
                                        Z_TIMEOUT_TICKS(work_delay));
        }
    }
}

int fd_work_poll_cancel(fd_work_poll_t *work)
{
    FD_POLL_DEBUG_PRINT("fd_work_poll_cancel\r\n");

    int status = -EINVAL;

    if (work) {

        /* remove work from queue. */
        status = k_work_cancel_delayable(&work->work);

        /* Work is submitted from another thread. Ensure all values are set atomically. */
        k_mutex_lock(&fd_work_mutex, K_FOREVER);
        work->nfds = 0;
        k_mutex_unlock(&fd_work_mutex);
    }

    return status;
}

#endif
