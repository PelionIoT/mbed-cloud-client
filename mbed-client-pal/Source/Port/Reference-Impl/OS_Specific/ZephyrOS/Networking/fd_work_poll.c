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

#if defined(PAL_SOCKET_USE_K_WORK_POLL) && (PAL_SOCKET_USE_K_WORK_POLL == 1)

#include <logging/log.h>
LOG_MODULE_REGISTER(fd_net_sock, CONFIG_NET_SOCKETS_LOG_LEVEL);

#include "sockets_internal.h"

static void fd_zsock_poll_work(struct k_work *work);
static inline void *get_sock_vtable(
            int sock, const struct socket_op_vtable **vtable);

void fd_work_poll_init(fd_work_poll_t *work, fd_work_handler_t handler)
{
    k_work_poll_init(&work->work, fd_zsock_poll_work);

    work->handler = handler;
}

int fd_work_poll_cancel(fd_work_poll_t *work)
{
    return k_work_poll_cancel(&work->work);
}

int fd_work_poll_submit(fd_work_poll_t *work, struct zsock_pollfd *fds, int nfds, k_timeout_t timeout)
{
    int i;
    struct zsock_pollfd *pfd;
    struct k_poll_event *pev;
    const struct fd_op_vtable *vtable;
    uint64_t end;
    bool offload = false;
    const struct fd_op_vtable *offl_vtable = NULL;
    void *offl_ctx = NULL;


    /* use memory allocation from fd_work_poll_t.
     */
    struct k_poll_event *poll_events = work->poll_events;
    struct k_poll_event *pev_end = poll_events + ARRAY_SIZE(work->poll_events);

    /* original zsock_poll uses milliseconds, convert k_timeout_t to int.
     */
    int poll_timeout;

    if (timeout.ticks == K_TICKS_FOREVER) {
        poll_timeout = SYS_FOREVER_MS;
    } else {
#ifdef CONFIG_TIMEOUT_64BIT
        poll_timeout = k_ticks_to_ms_near64(timeout.ticks);
#else
        poll_timeout = k_ticks_to_ms_near32(timeout.ticks);
#endif
    }

    /*************************************************************************/
    /* Begin - code copied from:                                             */
    /* net/sockets.c:1278-1344 rev: d29fcb8187ebc8f06a542d2ffcf7126914e5ff50 */
    /*************************************************************************/

    end = z_timeout_end_calc(timeout);

    pev = poll_events;
    for (pfd = fds, i = nfds; i--; pfd++) {
        void *ctx;
        int result;

        /* Per POSIX, negative fd's are just ignored */
        if (pfd->fd < 0) {
            continue;
        }

        ctx = get_sock_vtable(pfd->fd,
                (const struct socket_op_vtable **)&vtable);
        if (ctx == NULL) {
            /* Will set POLLNVAL in return loop */
            continue;
        }

        result = z_fdtable_call_ioctl(vtable, ctx,
                          ZFD_IOCTL_POLL_PREPARE,
                          pfd, &pev, pev_end);
        if (result == -EALREADY) {
            /* If POLL_PREPARE returned with EALREADY, it means
             * it already detected that some socket is ready. In
             * this case, we still perform a k_poll to pick up
             * as many events as possible, but without any wait.
             */
            timeout = K_NO_WAIT;
            continue;
        } else if (result == -EXDEV) {
            /* If POLL_PREPARE returned EXDEV, it means
             * it detected an offloaded socket.
             * If offloaded socket is used with native TLS, the TLS
             * wrapper for the offloaded poll will be used.
             * In case the fds array contains a mixup of offloaded
             * and non-offloaded sockets, the offloaded poll handler
             * shall return an error.
             */
            offload = true;
            if (offl_vtable == NULL || net_socket_is_tls(ctx)) {
                offl_vtable = vtable;
                offl_ctx = ctx;
            }
            continue;
        } else if (result != 0) {
            errno = -result;
            return -1;
        }
    }

    if (offload) {
        return z_fdtable_call_ioctl(offl_vtable, offl_ctx,
                        ZFD_IOCTL_POLL_OFFLOAD,
                        fds, nfds, poll_timeout);
    }

    if (!K_TIMEOUT_EQ(timeout, K_NO_WAIT) &&
        !K_TIMEOUT_EQ(timeout, K_FOREVER)) {
        int64_t remaining = end - z_tick_get();

        if (remaining <= 0) {
            timeout = K_NO_WAIT;
        } else {
            timeout = Z_TIMEOUT_TICKS(remaining);
        }
    }

    /*************************************************************************/
    /* End                                                                   */
    /* net/sockets.c:1271-1344 rev: d29fcb8187ebc8f06a542d2ffcf7126914e5ff50 */
    /*************************************************************************/

    work->fds = fds;
    work->nfds = nfds;
    work->num_events = pev - poll_events;
    work->timeout = timeout;
    work->end = end;

    /* if there are no events to wait for, invoke callback immediately through work queue */
    if (work->num_events) {

        k_work_poll_submit(&work->work, work->poll_events, work->num_events, work->timeout);
    } else {

        k_work_submit(&work->work.work);
    }

    return 0;
}

static void fd_zsock_poll_work(struct k_work *input)
{
    int i;
    bool retry;
    int ret = 0;
    struct zsock_pollfd *pfd;
    struct k_poll_event *pev;
    const struct fd_op_vtable *vtable;

    bool repost = false;

    /**
     * Get the encapsulating container which contains variables carried across
     * consecutive work queue invocations.
     */
    fd_work_poll_t* work = CONTAINER_OF(input, fd_work_poll_t, work);

    struct k_poll_event *poll_events = work->poll_events;
    struct zsock_pollfd *fds = work->fds;
    int nfds = work->nfds;
    k_timeout_t timeout = work->timeout;
    uint64_t end = work->end;

    do {
    /*************************************************************************/
    /* Begin - code copied from:                                             */
    /* net/sockets.c:1354-1409 rev: d29fcb8187ebc8f06a542d2ffcf7126914e5ff50 */
    /*************************************************************************/

        retry = false;
        ret = 0;

        pev = poll_events;
        for (pfd = fds, i = nfds; i--; pfd++) {
            void *ctx;
            int result;

            pfd->revents = 0;

            if (pfd->fd < 0) {
                continue;
            }

            ctx = get_sock_vtable(pfd->fd,
                (const struct socket_op_vtable **)&vtable);
            if (ctx == NULL) {
                pfd->revents = ZSOCK_POLLNVAL;
                ret++;
                continue;
            }

            result = z_fdtable_call_ioctl(vtable, ctx,
                              ZFD_IOCTL_POLL_UPDATE,
                              pfd, &pev);
            if (result == -EAGAIN) {
                retry = true;
                continue;
            } else if (result != 0) {
                errno = -result;
    /*************************************************************************/
                /* retry and repost are both false by default, this will break
                 * us out of both the for-loop and do-while-loop and invoke
                 * the handler function, which at least will give the callee
                 * a chance to recover.
                 */
                // return -1;
                break;
    /*************************************************************************/
            }

            if (pfd->revents != 0) {
                ret++;
            }
        }

        if (retry) {
            if (ret > 0) {
                break;
            }

            if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
                break;
            }

            if (!K_TIMEOUT_EQ(timeout, K_FOREVER)) {
                int64_t remaining = end - z_tick_get();

                if (remaining <= 0) {
                    break;
                } else {
                    timeout = Z_TIMEOUT_TICKS(remaining);
                }
            }

    /*************************************************************************/
    /* End                                                                   */
    /* net/sockets.c:1354-1409 rev: d29fcb8187ebc8f06a542d2ffcf7126914e5ff50 */
    /*************************************************************************/

            /* If this point is reached, the normal do-while-loop would have
             * made another pass. Instead, repost the work item to queue.
             */
            repost = true;
        }

        /* Only make one pass, either repost or invoke handler function instead. */
        break;

    /* Keep original code in loop to preserve break-commands. */
    } while (retry);


    if (repost) {

        /* Carry over local variables. */
        work->num_events = pev - poll_events;
        work->timeout = timeout;

        k_work_poll_submit(&work->work, work->poll_events, work->num_events, work->timeout);
    } else {
        fd_work_handler_t handler = work->handler;

        if (handler) {
            handler(work);
        }
    }
}


    /*************************************************************************/
    /* Begin - code copied from:                                             */
    /* net/sockets.c:45-79     rev: d29fcb8187ebc8f06a542d2ffcf7126914e5ff50 */
    /*************************************************************************/

static inline void *get_sock_vtable(
            int sock, const struct socket_op_vtable **vtable)
{
    void *ctx;

    ctx = z_get_fd_obj_and_vtable(sock,
                      (const struct fd_op_vtable **)vtable);

#ifdef CONFIG_USERSPACE
    if (ctx != NULL && z_is_in_user_syscall()) {
        struct z_object *zo;
        int ret;

        zo = z_object_find(ctx);
        ret = z_object_validate(zo, K_OBJ_NET_SOCKET, _OBJ_INIT_TRUE);

        if (ret != 0) {
            z_dump_object_error(ret, ctx, zo, K_OBJ_NET_SOCKET);
            /* Invalidate the context, the caller doesn't have
             * sufficient permission or there was some other
             * problem with the net socket object
             */
            ctx = NULL;
        }
    }
#endif /* CONFIG_USERSPACE */

    if (ctx == NULL) {
        NET_ERR("invalid access on sock %d by thread %p", sock,
            _current);
    }

    return ctx;
}
    /*************************************************************************/
    /* End                                                                   */
    /* net/sockets.c:45-79     rev: d29fcb8187ebc8f06a542d2ffcf7126914e5ff50 */
    /*************************************************************************/

#endif
