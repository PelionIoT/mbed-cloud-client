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

#ifndef __ARM_UC_HTTP_SOCKET_PRIVATE_H__
#define __ARM_UC_HTTP_SOCKET_PRIVATE_H__

#include "update-client-source-http-socket/arm_uc_http_socket.h"
#include "update-client-common/arm_uc_common.h"
#include <pal.h>

/**
 * @brief Initialize Http module.
 * @details A memory struct is passed as well as a function pointer for event
 *          handling.
 *
 * @param context Struct holding all global variables.
 * @param handler Event handler for signaling when each operation is complete.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_initialize(arm_uc_http_socket_context_t* context,
                                        ARM_UCS_HttpEvent_t handler);

/**
 * @brief Resets HTTP socket to uninitialized state and clears memory struct.
 * @details HTTP sockets must be initialized again before use.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_terminate(void);

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
                                 arm_uc_rqst_t type);

/**
 * @brief Connect to server set in the global URI struct.
 * @details Connecting generates a socket event, which automatically processes
 *          the request passed in arm_uc_socket_get. If a DNS request must
 *          be made, this call initiates an asynchronous DNS request. After
 *          the request is done, the connection process will be resumed in
 *          arm_uc_socket_finish_connect().
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_connect(void);

/**
 * @brief Finishes connecting to the server requested in a previous call to
 *        arm_uc_socket_connect().
 * @details This function is called after the DNS resolution for the host
 *          requested in arm_uc_socket_get() above is done. It finishes the
 *          connection process by creating a socket and connecting it.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_finish_connect(void);

/**
 * @brief Send request passed in arm_uc_socket_get.
 * @details This call assumes the HTTP socket is already connected to server.
 * @return Error code.
 */
arm_uc_error_t arm_uc_socket_send_request(void);

/**
 * @brief Receive data from HTTP socket.
 * @details Data is stored in global buffer. The call will automatically retry
 *          if the socket is busy.
 */
void arm_uc_socket_receive(void);

/**
 * @brief Function is called when some data has been received but an HTTP
 *        header has yet to be processed.
 * @details Function is called repeatedly until a header is found or the buffer
 *          is full. Once a header is found, the ETag, date, or content length
 *          is parsed. For file and fragment downloads the receive process is
 *          restarted and the header is erased.
 */
void arm_uc_socket_process_header(void);

/**
 * @brief Function is called when file or fragment is being downloaded.
 * @details Function drives the download and continues until the buffer is full
 *          or the expected amount of data has been downloaded.
 */
void arm_uc_socket_process_body(void);

/**
 * @brief Close socket and set internal state to disconnected.
 */
void arm_uc_socket_close(void);

/**
 * @brief Close socket, set internal state to disconnected and generate error
 *        event.
 * @param error The code of the error event.
 */
void arm_uc_socket_error(arm_ucs_http_event_t error);

/**
 * @brief Callback function for handling events in application context.
 * @param unused Unused.
 */
void arm_uc_socket_callback(uint32_t unused);

/**
 * @brief Callback function for handling events in interrupt context.
 * @details All events are de-escalated through the callback queue.
 */
void arm_uc_socket_isr(void*);

/**
 * @brief Callback handler for the socket timeout timer callback.
 *        Callbacks go through the task queue because we don't know
 *        what context we are running from.
 */
void arm_uc_timeout_timer_callback(void const *);

/**
 * @brief Callback handler for the asynchronous DNS resolver.
 *        Callbacks go through the task queue because we don't know
 *        what context we are running from.
 */
void arm_uc_dns_callback(const char* url,
                         palSocketAddress_t* address,
                         palSocketLength_t* address_length,
                         palStatus_t status,
                         void* argument);

#endif // __ARM_UC_HTTP_SOCKET_PRIVATE_H__
