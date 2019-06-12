// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize Http module.
 * @details A memory struct is passed as well as a function pointer for event
 *          handling.
 *
 * @param context Struct holding all global variables.
 * @param handler Event handler for signaling when each operation is complete.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_initialize(arm_uc_http_socket_context_t *context,
                                             ARM_UCS_HttpEvent_t handler);

/**
 * @brief Resets HTTP socket to uninitialized state and clears memory struct.
 * @details HTTP sockets must be initialized again before use.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_terminate(void);

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
arm_uc_error_t arm_uc_http_socket_get(arm_uc_uri_t *uri,
                                      arm_uc_buffer_t *buffer,
                                      uint32_t offset,
                                      arm_uc_http_rqst_t type);

/**
 * @brief Connect to server set in the global URI struct.
 * @details Connecting generates a socket event, which automatically processes
 *          the request passed in arm_uc_http_socket_get.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_connect(void);

/**
 * @brief Send request passed in arm_uc_http_socket_get.
 * @details This call assumes the HTTP socket is already connected to server.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_send_request(void);

/**
 * @brief Receive data from HTTP socket.
 * @details Data is stored in global buffer. The call will automatically retry
 *          if the socket is busy.
 */
arm_uc_error_t arm_uc_http_socket_receive(void);

/**
 * @brief Function is called when some data has been received but an HTTP
 *        header has yet to be processed.
 * @details Function is called repeatedly until a header is found or the buffer
 *          is full. Once a header is found, the ETag, date, or content length
 *          is parsed. For file and fragment downloads the receive process is
 *          restarted and the header is erased.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_process_header(void);

/**
 * @brief Function is called when file or fragment is being downloaded.
 * @details Function drives the download and continues until the buffer is full
 *          or the expected amount of data has been downloaded.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_process_frag(void);

/**
 * @brief Close socket and set internal state to disconnected.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_close(void);

/**
 * @brief Close socket, set internal state to disconnected and generate error
 *        event.
 * @param error The code of the error event.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_fatal_error(arm_ucs_http_event_t error);

/**
 * @brief Callback function for handling events in application context.
 * @param unused Unused.
 */
void arm_uc_http_socket_callback(uintptr_t unused);

/**
 * @brief Helper function to cancel resume engine externally
 * @param unused Unused.
 */
void arm_uc_http_socket_end_resume(void);

#ifdef __cplusplus
}
#endif

#endif // __ARM_UC_HTTP_SOCKET_PRIVATE_H__
