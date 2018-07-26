// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "arm_uc_http_socket_private.h"

#include "arm_uc_socket_help.h"

#include <pal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#if !defined(ARM_UC_SOCKET_TIMEOUT_MS)
#define ARM_UC_SOCKET_TIMEOUT_MS 10000 /* 10 seconds */
#endif

/* Pointer to struct containing all global variables.
   Can be dynamically allocated and deallocated.
*/
static arm_uc_http_socket_context_t* context = NULL;

/******************************************************************************
 * Internal helpers for DNS resolution
 * These functions are used to implement DNS resolution in two variants:
 * asynchronous (MBED_CONF_MBED_CLIENT_DNS_USE_THREAD == 1) or
 * synchronous (otherwise). */

#if MBED_CONF_MBED_CLIENT_DNS_USE_THREAD /* use asychronous DNS calls */

#define arm_uc_get_address_info pal_getAddressInfoAsync

static arm_uc_error_t arm_uc_start_dns_timer()
{
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    if (context)
    {
        palStatus_t pal_inner = pal_osTimerStart(context->timeout_timer_id,
                                                ARM_UC_SOCKET_TIMEOUT_MS);
        if (pal_inner != PAL_SUCCESS)
        {
            UC_SRCE_ERR_MSG("Start socket timeout timer failed pal status: 0x%" PRIu32,
                            (uint32_t)pal_inner);
            arm_uc_socket_close();
        }
        else
        {
            result.code = SRCE_ERR_NONE;
        }
    }
    return result;
}

static arm_uc_error_t arm_uc_stop_dns_timer()
{
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    if (context)
    {
        palStatus_t pal_inner = pal_osTimerStop(context->timeout_timer_id);
        if (pal_inner != PAL_SUCCESS)
        {
            UC_SRCE_ERR_MSG("pal_osTimerStop returned 0x%" PRIX32,
                            (uint32_t) pal_inner);
        }
        else
        {
            result.code = SRCE_ERR_NONE;
        }
    }
    return result;
}

#else /* use synchronous DNS calls */

static palStatus_t arm_uc_get_address_info(const char* url, palSocketAddress_t* address,
                                           palSocketLength_t* address_length,
                                           palGetAddressInfoAsyncCallback_t callback,
                                           void* argument)
{
    /* Run the synchronous DNS request and call the callback
       immediately after the request is done */
    palStatus_t pal_inner = pal_getAddressInfo(url, address, address_length);
    /* Call the callback with the result of pal_getAddressInfo.
       The callback will examine the value of pal_inner and act
       accordingly (see arm_uc_dns_callback below). */
    callback(url, address, address_length, pal_inner, argument);
    /* Always return PAL_SUCCESS so that the caller can continue
       execution. The actual check for success/failure happens
       in the callback (see the comment above). */
    return PAL_SUCCESS;
}

/* Timers are not used for synchronous DNS calls,
   since the synchronous call can't be interrupted */
static arm_uc_error_t arm_uc_start_dns_timer()
{
    return (arm_uc_error_t){ SRCE_ERR_NONE };
}

static arm_uc_error_t arm_uc_stop_dns_timer()
{
    return (arm_uc_error_t){ SRCE_ERR_NONE };
}

#endif // MBED_CONF_MBED_CLIENT_DNS_USE_THREAD

/*****************************************************************************/

/**
 * @brief Initialize Http module.
 * @details A memory struct is passed as well as a function pointer for event
 *          handling.
 *
 * @param context Struct holding all global variables.
 * @param handler Event handler for signaling when each operation is complete.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_initialize(arm_uc_http_socket_context_t* _context,
                                        void (*handler)(uint32_t))
{
    UC_SRCE_TRACE("arm_uc_socket_initialize");

    /* default return value */
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    /* save global context */
    context = _context;

    if (context)
    {
        /* initialize global variables */
        context->callback_handler = handler;

        context->request_uri = NULL;
        context->request_buffer = NULL;
        context->request_offset = 0;
        context->request_type = RQST_TYPE_NONE;

        context->socket_state = STATE_DISCONNECTED;
        context->expected_event = SOCKET_EVENT_UNDEFINED;
        context->expected_remaining = 0;

        context->socket = NULL;

        context->isr_callback_counter = 0;

        context->timeout_timer_id = 0;

        context->cache_address.addressType = 0;
        memset(context->cache_address.addressData, 0, PAL_NET_MAX_ADDR_SIZE);
        context->cache_address_length = 0;

        /* set return value to success */
        result = (arm_uc_error_t){ SRCE_ERR_NONE };
    }

    return result;
}

/**
 * @brief Resets HTTP socket to uninitialized state and clears memory struct.
 * @details HTTP sockets must be initialized again before use.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_terminate()
{
    /* default return value */
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    if (context)
    {
        /* close socket */
        arm_uc_socket_close();

        /* reset all global variables */
        context->request_uri = NULL;
        context->request_buffer = NULL;
        context->request_offset = 0;
        context->request_type = RQST_TYPE_NONE;

        context->socket_state = STATE_DISCONNECTED;
        context->expected_event = SOCKET_EVENT_UNDEFINED;
        context->expected_remaining = 0;

        context->socket = NULL;

        context = NULL;

        result = (arm_uc_error_t){ SRCE_ERR_NONE };
    }

    return result;
}

/**
 * @brief Get resource at URI.
 * @details Download resource at URI from given offset and store in buffer.
 *          Events are generated when download finish or on error
 *
 * @param uri Pointer to structure with resource location.
 * @param buffer Pointer to structure with buffer location, maxSize, and size.
 * @param offset Offset in resource to begin download from.
 * @param type Indicate what type of request that was initiated.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_get(arm_uc_uri_t* uri,
                                 arm_uc_buffer_t* buffer,
                                 uint32_t offset,
                                 arm_uc_rqst_t type)
{
    UC_SRCE_TRACE("arm_uc_socket_get");

    /* default return value */
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    /* check for NULL pointers */
    if (uri &&
        uri->scheme &&
        uri->host &&
        uri->path &&
        buffer &&
        buffer->ptr &&
        context)
    {
        /* parameters are valid */
        result.code = SRCE_ERR_NONE;

        /* store request */
        context->request_uri = uri;
        context->request_buffer = buffer;
        context->request_offset = offset;
        context->request_type = type;

        /* clear buffer */
        context->request_buffer->size = 0;

        UC_SRCE_TRACE("Socket State: %d", context->socket_state);

        /* connect socket if not already connected */
        result = arm_uc_socket_connect();
    }

    return result;
}

/**
 * @brief Connect to server set in the global URI struct.
 * @details Connecting generates a socket event, which automatically processes
 *          the request passed in arm_uc_socket_get. If a DNS request must
 *          be made, this call initiates an asynchronous DNS request. After
 *          the request is done, the connection process will be resumed in
 *          arm_uc_socket_finish_connect().
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_connect()
{
    /* default return value */
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    /* NULL pointer check */
    if (context && context->request_uri)
    {
        if (context->socket_state == STATE_DISCONNECTED)
        {
            result = (arm_uc_error_t){ SRCE_ERR_NONE };

            /* create socket timeout timer */
            palStatus_t pal_inner = pal_osTimerCreate(arm_uc_timeout_timer_callback,
                                                      NULL,
                                                      palOsTimerOnce,
                                                      &context->timeout_timer_id);

            if (pal_inner != PAL_SUCCESS)
            {
                UC_SRCE_ERR_MSG("socket timeout timer creation failed pal status: 0x%" PRIu32,
                                (uint32_t)pal_inner);
                arm_uc_socket_close();
                result = (arm_uc_error_t){ SRCE_ERR_FAILED };
            }
            else
            {
                /* start socket timeout timer */
                result = arm_uc_start_dns_timer();
            }
            if (result.code == SRCE_ERR_NONE)
            {
                /* initiate DNS lookup */
                pal_inner = arm_uc_get_address_info(context->request_uri->host,
                                                    &context->cache_address,
                                                    &context->cache_address_length,
                                                    arm_uc_dns_callback,
                                                    NULL);

                if (pal_inner != PAL_SUCCESS)
                {
                    UC_SRCE_ERR_MSG("pal_getAddressInfoAsync (DNS) failed pal status: 0x%" PRIu32,
                                    (uint32_t)pal_inner);
                    arm_uc_socket_close();
                    result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };
                }
                else
                {
                    UC_SRCE_TRACE("Initiated DNS lookup");
                }
            }
        }
        else if (context->socket_state == STATE_CONNECTED_IDLE) /* already connected */
        {
            /* Socket already connected, progress state machine */
            palStatus_t pal_inner = pal_osTimerStart(context->timeout_timer_id,
                                         ARM_UC_SOCKET_TIMEOUT_MS);

            if (pal_inner != PAL_SUCCESS)
            {
                UC_SRCE_ERR_MSG("Start socket timeout timer failed pal status: 0x%" PRIu32,
                                (uint32_t)pal_inner);
                arm_uc_socket_close();
                return (arm_uc_error_t){ SRCE_ERR_FAILED };
            }

            UC_SRCE_TRACE("Socket already connected, progress state machine");
            context->expected_event = SOCKET_EVENT_CONNECT_DONE;
            result = (arm_uc_error_t){ SRCE_ERR_NONE };
            arm_uc_socket_isr(NULL);
        }
        else /* socket busy */
        {
            UC_SRCE_TRACE("Socket Busy");
            result = (arm_uc_error_t){ SRCE_ERR_BUSY };
        }
    }

    UC_SRCE_TRACE("arm_uc_socket_connect returning %s", ARM_UC_err2Str(result));

    return result;
}

/**
 * @brief Finishes connecting to the server requested in a previous call to
 *        arm_uc_socket_connect().
 * @details This function is called after the DNS resolution for the host
 *          requested in arm_uc_socket_get() above is done. It finishes the
 *          connection process by creating a socket and connecting it.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_finish_connect()
{
    /* default return value */
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    /* NULL pointer check */
    if (context && context->request_uri)
    {
        result = (arm_uc_error_t){ SRCE_ERR_NONE };

        UC_SRCE_TRACE("socket: address type is: %u", context->cache_address.addressType);
        /* create new async PAL socket */
        palStatus_t pal_inner = pal_asynchronousSocket((palSocketDomain_t)context->cache_address.addressType,
                                                       PAL_SOCK_STREAM,
                                                       true,
                                                       0,
                                                       arm_uc_socket_isr,
                                                       &context->socket);

        if (pal_inner != PAL_SUCCESS)
        {
            UC_SRCE_ERR_MSG("socket creation failed with pal status: 0x%" PRIX32,
                            (uint32_t) pal_inner);
            arm_uc_socket_close();
            result = (arm_uc_error_t){ SRCE_ERR_FAILED };
        }
        else
        {
            UC_SRCE_TRACE("socket: create success");
        }

        /* start socket timeout timer */
        if (result.code == SRCE_ERR_NONE)
        {
            pal_inner = pal_osTimerStart(context->timeout_timer_id,
                                            ARM_UC_SOCKET_TIMEOUT_MS);

            if (pal_inner != PAL_SUCCESS)
            {
                UC_SRCE_ERR_MSG("Start socket timeout timer failed");
                arm_uc_socket_close();
                result = (arm_uc_error_t){ SRCE_ERR_FAILED };
            }
        }

        /* convert URI to PAL address if cache is not empty */
        if ((result.code == SRCE_ERR_NONE) &&
            (context->cache_address_length != 0))
        {
            /* set PAL port */
            pal_inner = pal_setSockAddrPort(&context->cache_address,
                                            context->request_uri->port);

            if (pal_inner != PAL_SUCCESS)
            {
                UC_SRCE_ERR_MSG("pal_setSockAddrPort returned: 0x%" PRIX32,
                                (uint32_t) pal_inner);
                arm_uc_socket_close();
                result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };
            }
        }

        /* connect to server */
        if (result.code == SRCE_ERR_NONE)
        {
            pal_inner = pal_connect(context->socket,
                                    &context->cache_address,
                                    context->cache_address_length);
            UC_SRCE_TRACE("pal_connect returned: 0x%" PRIX32,
                            (uint32_t) pal_inner);

            if (pal_inner == PAL_SUCCESS) /* synchronous finish */
            {
                context->socket_state = STATE_CONNECTED_IDLE;
                context->expected_event = SOCKET_EVENT_CONNECT_DONE;
                result = (arm_uc_error_t){ SRCE_ERR_NONE };
                arm_uc_socket_isr(NULL);
            }
            else if (pal_inner == PAL_ERR_SOCKET_IN_PROGRES) /* asynchronous finish */
            {
                context->expected_event = SOCKET_EVENT_CONNECT_DONE;
                result = (arm_uc_error_t){ SRCE_ERR_NONE };
            }
            else
            {
                UC_SRCE_ERR_MSG("Error: socket connection failed");
                result = (arm_uc_error_t){ SRCE_ERR_FAILED };
                arm_uc_socket_close();
            }
        }
    }

    UC_SRCE_TRACE("arm_uc_socket_finish_connect returning %s", ARM_UC_err2Str(result));

    return result;
}


/**
 * @brief Send request passed in arm_uc_socket_get.
 * @details This call assumes the HTTP socket is already connected to server.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_send_request()
{
    /* default return value */
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_FAILED };

    /* NULL pointer check */
    if (context)
    {
        /* get local references */
        arm_uc_buffer_t* request_buffer = context->request_buffer;
        arm_uc_uri_t*    request_uri    = context->request_uri;
        arm_uc_rqst_t    request_type   = context->request_type;

        /* template for generating HTTP requests */
        static const char HTTP_HEADER_TEMPLATE[] =
            "%s %s HTTP/1.1\r\n" // status line
            "Host: %s\r\n"; // mandated for http 1.1

        if (request_type == RQST_TYPE_HASH_ETAG ||
            request_type == RQST_TYPE_HASH_DATE)
        {
            /* construct ETag and Date request header */
            request_buffer->size = snprintf((char *) request_buffer->ptr,
                                            request_buffer->size_max,
                                            HTTP_HEADER_TEMPLATE,
                                            "HEAD",
                                            request_uri->path,
                                            request_uri->host);
        }
        else
        {
            /* construct download header */
            request_buffer->size = snprintf((char *) request_buffer->ptr,
                                            request_buffer->size_max,
                                            HTTP_HEADER_TEMPLATE,
                                            "GET",
                                            request_uri->path,
                                            request_uri->host);
        }

        if (request_type == RQST_TYPE_GET_FRAG)
        {
            /* construct the Range field that makes this a partial content request */
            request_buffer->size += snprintf((char *) request_buffer->ptr + request_buffer->size,
                                             request_buffer->size_max - request_buffer->size,
                                             "Range: bytes=%" PRIu32 "-%" PRIu32 "\r\n",
                                             context->request_offset,
                                             context->request_offset + request_buffer->size_max - 1);
        }

        /* terminate request with a carriage return and newline */
        request_buffer->size += snprintf((char *) request_buffer->ptr + request_buffer->size,
                                         request_buffer->size_max - request_buffer->size,
                                         "\r\n");

        /* terminate string */
        request_buffer->ptr[request_buffer->size] = '\0';
        UC_SRCE_TRACE("%s", request_buffer->ptr);

        /*************************************************************************/

        size_t bytes_sent = 0;

        /* send HTTP request */
        palStatus_t pal_result = pal_send(context->socket,
                                          request_buffer->ptr,
                                          request_buffer->size,
                                          &bytes_sent);

        if (pal_result == PAL_SUCCESS) /* asynchronous finish */
        {
            UC_SRCE_TRACE("send success");

            /* reset buffer and prepare to receive header */
            request_buffer->size = 0;
            context->socket_state = STATE_PROCESS_HEADER;
            context->expected_event = SOCKET_EVENT_SEND_DONE;

            result = (arm_uc_error_t){ SRCE_ERR_NONE };
        }
        else if(pal_result == PAL_ERR_SOCKET_WOULD_BLOCK)
        {
            UC_SRCE_TRACE("send would block, will retry");

            /* keep current state and force callback to retry sending */
            request_buffer->size = 0;
            arm_uc_socket_isr(NULL);

            result = (arm_uc_error_t){ SRCE_ERR_NONE };
        }
        else
        {
            UC_SRCE_TRACE("send error 0x%" PRIX32, (uint32_t) pal_result);

            /* clean up */
            arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
        }
    }

    return result;
}

/**
 * @brief Receive data from HTTP socket.
 * @details Data is stored in global buffer. The call will automatically retry
 *          if the socket is busy.
 */
void arm_uc_socket_receive()
{
    /* NULL pointer check */
    if (context)
    {
        /* get local references */
        arm_uc_buffer_t* request_buffer = context->request_buffer;

        size_t received_bytes = 0;
        palStatus_t pal_result = PAL_SUCCESS;

        while ( (context->socket_state != STATE_DISCONNECTED) &&
                (pal_result == PAL_SUCCESS) &&
                context->request_buffer )
        {
            if (request_buffer->size >= request_buffer->size_max)
            {
                UC_SRCE_ERR_MSG("There is no space in the buffer left");
                arm_uc_socket_error(UCS_HTTP_EVENT_ERROR_BUFFER_SIZE);
                break;
            }

            /* append data from socket receive buffer to request buffer. */
            pal_result = pal_recv(context->socket,
                                  &(request_buffer->ptr[request_buffer->size]),
                                  request_buffer->size_max - request_buffer->size,
                                  &received_bytes);

            if (pal_result == PAL_SUCCESS && received_bytes > 0)
            {
                /* Note: the proper formatter %zu is not supported on mbed's libc,
                 * hence the casts to difference type.
                 */
                UC_SRCE_TRACE("recv success: %lu bytes received",
                              (unsigned long)received_bytes);

                if (request_buffer->size + received_bytes > request_buffer->size_max)
                {
                    UC_SRCE_ERR_MSG("Got more data than available space in the buffer");
                    arm_uc_socket_error(UCS_HTTP_EVENT_ERROR_BUFFER_SIZE);
                    break;
                }

                /* update buffer size with received bytes */
                request_buffer->size += received_bytes;

                /* update expected event to signal receive done */
                context->expected_event = SOCKET_EVENT_RECEIVE_CONTINUE;

                /* received data */
                if (context->socket_state == STATE_PROCESS_HEADER)
                {
                    /* expecting HTTP header */
                    arm_uc_socket_process_header();
                }
                else if (context->socket_state == STATE_PROCESS_BODY)
                {
                    /* expecting body */
                    arm_uc_socket_process_body();
                }
                else
                {
                    /* unexpected data, generate error and clean up */
                    arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
                }
            }
            else if (pal_result == PAL_ERR_SOCKET_WOULD_BLOCK)
            {
                /* Note: at least on mbed os the pal_recv() returns garbage on recievedDataSize
                 * if the socket call returns anything but PAL_SUCCESS, so this needs to
                 * recalculate the remaining bytes count.
                 */
                UC_SRCE_TRACE("recv: pending: %" PRIu32,
                              (request_buffer->size_max - request_buffer->size));

                /* update expected event to retry receiving */
                context->expected_event = SOCKET_EVENT_RECEIVE_CONTINUE;
            }
            else
            {
                UC_SRCE_ERR_MSG("Error: socket receive failed");

                /* clean up */
                arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
            }
        }
    }
}

/**
 * @brief Function is called when some data has been received but an HTTP
 *        header has yet to be processed.
 * @details Function is called repeatedly until a header is found or the buffer
 *          is full. Once a header is found, the ETag, date, or content length
 *          is parsed. For file and fragment downloads the receive process is
 *          restarted and the header is erased.
 */
void arm_uc_socket_process_header()
{
    /* NULL pointer check */
    if (context)
    {
        /* get local references */
        arm_uc_buffer_t* request_buffer = context->request_buffer;
        arm_uc_uri_t*    request_uri    = context->request_uri;
        arm_uc_rqst_t    request_type   = context->request_type;
        uint32_t         request_offset = context->request_offset;

        /* setup default return to be failure */
        bool request_successfully_processed = false;

        uint32_t index = arm_uc_strnstrn(request_buffer->ptr,
                                         request_buffer->size,
                                         (const uint8_t*) "\r\n\r\n",
                                         4);

        /* Continue receiving if full header is not found. */
        if (index > request_buffer->size)
        {
            request_successfully_processed = true;
            arm_uc_socket_receive();
        }
        else
        {
            /* process header */
            UC_SRCE_TRACE("HTTP header found");

            const char header_tag[] = "HTTP/1.1 ";

            uint32_t header_start = arm_uc_strnstrn(request_buffer->ptr,
                                                    request_buffer->size,
                                                    (const uint8_t*) header_tag,
                                                    sizeof(header_tag) - 1);

            /* found beginning of header */
            if (header_start < request_buffer->size)
            {
                /* status code is after the header tag */
                header_start = header_start + sizeof(header_tag) - 1;
            }

            /* buffer size check */
            if (header_start < request_buffer->size)
            {
                /* parse status code */
                bool header_parsed = false;
                uint32_t status_code = arm_uc_str2uint32(
                                            &(request_buffer->ptr[header_start]),
                                            request_buffer->size - header_start,
                                            &header_parsed);

                if (header_parsed == true)
                {
                    UC_SRCE_TRACE("HTTP status code %" PRIu32, status_code);

                    /* Redirect status codes:
                       301: Moved Permanently
                       302: Found [Elsewhere]
                       303: See Other
                       307: Temporary Redirect
                    */
                    if ((status_code >= 301 && status_code <= 303) ||
                        (status_code == 307))
                    {
                        /* move location to front of buffer */
                        const char tag[] = "Location";
                        bool found = arm_uc_socket_trim_value(request_buffer,
                                                              tag,
                                                              sizeof(tag) - 1);

                        if (found)
                        {
                            /* NULL terminate string */
                            request_buffer->ptr[request_buffer->size] = '\0';

                            /* parse location and store in URI */
                            arm_uc_error_t err = arm_uc_str2uri(request_buffer->ptr,
                                                                request_buffer->size,
                                                                request_uri);

                            if ((err.error == ERR_NONE) &&
                                (request_uri->scheme == URI_SCHEME_HTTP))
                            {
                                UC_SRCE_TRACE("HTTP redirecting to http://%s:%" PRIu16 "/%s",
                                              request_uri->host,
                                              request_uri->port,
                                              request_uri->path);

                                /* close current socket */
                                arm_uc_socket_close();

                                /* run "get" again with the new location (above) */
                                err = arm_uc_socket_get(request_uri, request_buffer,
                                                        request_offset, request_type);
                                if (err.error == ERR_NONE)
                                {
                                    request_successfully_processed = true;
                                }
                                else
                                {
                                    UC_SRCE_ERR_MSG("Error: HTTP redirect failed");
                                }
                            }
                            else
                            {
                                UC_SRCE_ERR_MSG("Error: unable to parse URI string");
                            }
                        }
                        else
                        {
                            UC_SRCE_ERR_MSG("Error: unable to find redirect location");
                        }
                    }
                    /* All remaining codes outside 200-226 are treated as errors */
                    else if (status_code < 200 || status_code > 226)
                    {
                        UC_SRCE_ERR_MSG("Error: server returned HTTP status code %" PRIu32,
                                        status_code);
                    }
                    /* All codes between 200 to 226 */
                    else
                    {
                        /* NOTE: HTTP 1.1 Code 206 with Header "Connection:close" is not
                           handled here, instead the execution falls trough to error-
                           handling in http_socket (ARM_UCS_HTTPEVent with UCS_HTTP_EVENT_ERROR)
                           where the retry-mechanism will resume firmware download if
                           the server closed the connection.
                        */
                        if (request_type == RQST_TYPE_HASH_ETAG)
                        {
                            /* look for ETag and move to front of buffer */
                            const char tag[] = "ETag";
                            bool found = arm_uc_socket_trim_value(request_buffer,
                                                                  tag,
                                                                  sizeof(tag) - 1);

                            if (found)
                            {
                                /* ETag successfully read - post callback */
                                if (context->callback_handler)
                                {
                                    palStatus_t status = pal_osTimerStop(context->timeout_timer_id);
                                    if (status != PAL_SUCCESS)
                                    {
                                        UC_SRCE_ERR_MSG("pal_osTimerStop returned 0x%" PRIX32,
                                                        (uint32_t) status);
                                        arm_uc_socket_close();
                                    }

                                    ARM_UC_PostCallback(&context->event_callback_struct,
                                                        context->callback_handler,
                                                        UCS_HTTP_EVENT_HASH);
                                }

                                /* request complete - close socket */
                                arm_uc_socket_close();

                                /* success - no clean up needed */
                                request_successfully_processed = true;
                            }
                            else
                            {
                                UC_SRCE_ERR_MSG("Error: unable to find ETag");
                            }
                        }
                        else if (request_type == RQST_TYPE_HASH_DATE)
                        {
                            /* look for date and move to front of buffer */
                            const char tag[] = "Last-Modified";
                            bool found = arm_uc_socket_trim_value(request_buffer,
                                                                  tag,
                                                                  sizeof(tag) - 1);

                            if (found)
                            {
                                /* date successfully read - post callback */
                                if (context->callback_handler)
                                {
                                    palStatus_t status = pal_osTimerStop(context->timeout_timer_id);
                                    if (status != PAL_SUCCESS)
                                    {
                                        UC_SRCE_ERR_MSG("pal_osTimerStop returned 0x%" PRIX32,
                                                        (uint32_t) status);
                                        arm_uc_socket_close();
                                    }

                                    ARM_UC_PostCallback(&context->event_callback_struct,
                                                        context->callback_handler,
                                                        UCS_HTTP_EVENT_DATE);
                                }

                                /* request complete - close socket */
                                arm_uc_socket_close();

                                /* signal clean up is not needed */
                                request_successfully_processed = true;
                            }
                            else
                            {
                                UC_SRCE_ERR_MSG("Error: unable to find last modified date");
                            }
                        }
                        /* request is GetFile or GetFragment */
                        else
                        {
                            /* save current buffer size so we can recover body after
                               the content length has been read. */
                            uint32_t current_size = request_buffer->size;

                            /* find content length and move value to front of buffer */
                            const char tag[] = "Content-Length";
                            bool found = arm_uc_socket_trim_value(request_buffer,
                                                                  tag,
                                                                  sizeof(tag) - 1);

                            if (found)
                            {
                                /* NULL terminate string */
                                request_buffer->ptr[request_buffer->size] = '\0';

                                /* parse full length of content */
                                char *ptr;
                                context->expected_remaining = strtoul(request_buffer->ptr, &ptr, 10);

                                /* only continue if exactly one argument was parsed */
                                if (ptr != request_buffer->ptr)
                                {
                                    UC_SRCE_TRACE("content: %" PRIu32,
                                                  context->expected_remaining);

                                    /* replace HTTP header with body */
                                    memmove(request_buffer->ptr,
                                            &(request_buffer->ptr[index + 4]),
                                            current_size - (index + 4));

                                    /* set size of partial body */
                                    request_buffer->size = current_size - (index + 4);

                                    /*  */
                                    if (request_buffer->size >= context->expected_remaining)
                                    {
                                        /* all data received - process data */
                                        arm_uc_socket_process_body();
                                    }
                                    else
                                    {
                                        /* expecting more data - continue receiving */
                                        UC_SRCE_TRACE("expecting more data %" PRIu32 "/%" PRIu32 "\r\n",
                                            request_buffer->size,
                                            context->expected_remaining);
                                    }

                                    /* signal clean up is not needed */
                                    request_successfully_processed = true;

                                    /* continue processing body */
                                    context->socket_state = STATE_PROCESS_BODY;
                                }
                                else
                                {
                                    UC_SRCE_ERR_MSG("Error: unable to parse content length");
                                }
                            }
                            else
                            {
                                UC_SRCE_ERR_MSG("Error: unable find content length");
                            }
                        }
                    }
                }
                else
                {
                    UC_SRCE_ERR_MSG("Error: unable to read status code");
                }
            }
            else
            {
                UC_SRCE_ERR_MSG("Error: HTTP header not found");
            }
        }

        /* clean up */
        if (request_successfully_processed == false)
        {
            arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
        }
    }
}

/**
 * @brief Function is called when file or fragment is being downloaded.
 * @details Function drives the download and continues until the buffer is full
 *          or the expected amount of data has been downloaded.
 */
void arm_uc_socket_process_body()
{
    /* NULL pointer check */
    if (context)
    {
        /* check if all expected bytes have been received */
        if (context->request_buffer->size >= context->expected_remaining)
        {
            UC_SRCE_TRACE("process body done");

            /* fragment or file successfully received - post callback */
            if (context->callback_handler)
            {
                palStatus_t status = pal_osTimerStop(context->timeout_timer_id);
                if (status != PAL_SUCCESS)
                {
                    UC_SRCE_ERR_MSG("pal_osTimerStop returned 0x%" PRIX32,
                                    (uint32_t) status);
                    arm_uc_socket_close();
                }

                ARM_UC_PostCallback(&context->event_callback_struct,
                                    context->callback_handler,
                                    UCS_HTTP_EVENT_DOWNLOAD);
            }

            /* reset buffers and state */
            context->socket_state = STATE_CONNECTED_IDLE;
            context->request_buffer = NULL;
            context->expected_event = SOCKET_EVENT_UNDEFINED;
        }
    }
}

/**
 * @brief Close socket and set internal state to disconnected.
 */
void arm_uc_socket_close()
{
    /* NULL pointer check */
    if (context)
    {
        /* close socket if not NULL */
        if (context->socket)
        {
            pal_close(&context->socket);
        }

        /* delete socket timeout timer */
        if (context->timeout_timer_id != (palTimerID_t) NULL)
        {
            pal_osTimerDelete(&context->timeout_timer_id);
        }

        /* reset buffers and state */
        context->request_buffer = NULL;
        context->expected_event = SOCKET_EVENT_UNDEFINED;
        context->socket_state = STATE_DISCONNECTED;
        context->timeout_timer_id = 0;
    }
}

/**
 * @brief Close socket, set internal state to disconnected and generate error
 *        event.
 */
void arm_uc_socket_error(arm_ucs_http_event_t error)
{
    /* NULL pointer check */
    if (context)
    {
        if (context->socket_state != STATE_DISCONNECTED)
        {
            /* close socket */
            arm_uc_socket_close();
        }

        /* clear DNS cache */
        context->cache_address.addressType = 0;
        memset(context->cache_address.addressData, 0, PAL_NET_MAX_ADDR_SIZE);
        context->cache_address_length = 0;

        /* if callback handler is set, generate error event */
        if (context->callback_handler)
        {
            UC_SRCE_ERR_MSG("posting to callback with event %d", error);
            ARM_UC_PostCallback(&context->event_callback_struct,
                                context->callback_handler,
                                error);
        }
    }
}

/**
 * @brief PAL socket event handler.
 * @param unused PAL API doesn't support parameters.
 */
void arm_uc_socket_callback(uint32_t unused)
{
    (void) unused;

    UC_SRCE_TRACE("arm_uc_socket_callback");

    /* NULL pointer check */
    if (context)
    {
        /* unlock posting callbacks to the queue */
        pal_osAtomicIncrement(&context->isr_callback_counter, -1);

        switch (context->expected_event)
        {
            case SOCKET_EVENT_DNS_DONE:
                UC_SRCE_TRACE("DNS done");

                {
                    /* stop DNS timeout timer */
                    arm_uc_error_t result = arm_uc_stop_dns_timer();
                    if (result.code != SRCE_ERR_NONE)
                    {
                        arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
                    }
                    else
                    {
                        if (context->cache_address.addressType == 0 &&
                            context->cache_address_length == 0)
                        {
                            UC_SRCE_ERR_MSG("DNS resolution failed for host %s",
                                            context->request_uri->host);
                            arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
                        }
                        else
                        {
                            result = arm_uc_socket_finish_connect();
                            if (result.code != SRCE_ERR_NONE)
                            {
                                UC_SRCE_ERR_MSG("arm_uc_socket_finish_connect failed: %s",
                                                ARM_UC_err2Str(result));
                                arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
                            }
                        }
                    }
                }
                break;

            case SOCKET_EVENT_CONNECT_DONE:
                UC_SRCE_TRACE("Connect done");

                context->socket_state = STATE_CONNECTED_IDLE;
                {
                    arm_uc_error_t result = arm_uc_socket_send_request();
                    if (result.code != SRCE_ERR_NONE)
                    {
                        UC_SRCE_ERR_MSG("arm_uc_socket_send_request failed: %s",
                                        ARM_UC_err2Str(result));
                        arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
                    }
                }
                break;

            case SOCKET_EVENT_SEND_DONE:
                UC_SRCE_TRACE("send done");

                /* request send, receive response */
                context->expected_event = SOCKET_EVENT_RECEIVE_CONTINUE;
                arm_uc_socket_receive();
                break;

            case SOCKET_EVENT_RECEIVE_CONTINUE:
                UC_SRCE_TRACE("recv continue");

                /* outstanding data, continue receiving */
                arm_uc_socket_receive();
                break;

            case SOCKET_EVENT_TIMER_FIRED:
                UC_SRCE_TRACE("socket timeout timer fired");

                /* delete socket timeout timer */
                if (context->timeout_timer_id != (palTimerID_t) NULL)
                {
                    pal_osTimerDelete(&context->timeout_timer_id);
                    context->timeout_timer_id = 0;
                }
                arm_uc_socket_error(UCS_HTTP_EVENT_ERROR);
                break;

            case SOCKET_EVENT_UNDEFINED:
            default:
                UC_SRCE_TRACE("event: undefined");
                break;
        }
    }
}

/**
 * @brief Callback handler for PAL socket events. Callbacks go through the task
 *        queue because we don't know what context we are running from.
 */
void arm_uc_socket_isr(void* unused)
{
    /* NULL pointer check */
    if (context)
    {
        /* ensure we only have one callback in flight */
        int32_t count = pal_osAtomicIncrement(&context->isr_callback_counter, 0);

        if (count == 0)
        {
            pal_osAtomicIncrement(&context->isr_callback_counter, 1);

            /* post callback to de-escalate event */
            ARM_UC_PostCallback(&context->isr_callback_struct,
                                arm_uc_socket_callback,
                                0);
        }
    }
}

/**
 * @brief Callback handler for the socket timeout timer callback.
 *        Callbacks go through the task queue because we don't know
 *        what context we are running from.
 */
void arm_uc_timeout_timer_callback(void const *unused)
{
    (void) unused;

    if (context != NULL)
    {
        context->expected_event = SOCKET_EVENT_TIMER_FIRED;
        /* push event to the socket event queue */
        arm_uc_socket_isr(NULL);
    }
}

/**
 * @brief Callback handler for the asynchronous DNS resolver.
 *        Callbacks go through the task queue because we don't know
 *        what context we are running from.
 */
void arm_uc_dns_callback(const char* url, palSocketAddress_t* address,
                         palSocketLength_t* address_length, palStatus_t status,
                         void *argument)
{
    (void)url;
    (void)address;
    (void)address_length;
    (void)argument;

    if (context != NULL)
    {
        /* check if DNS call succeeded */
        if (status != PAL_SUCCESS)
        {
            /* clear the address-related fields to signal an error */
            context->cache_address.addressType = 0;
            context->cache_address_length = 0;
        }
        context->expected_event = SOCKET_EVENT_DNS_DONE;
        /* push event to the socket event queue */
        arm_uc_socket_isr(NULL);
    }
}
