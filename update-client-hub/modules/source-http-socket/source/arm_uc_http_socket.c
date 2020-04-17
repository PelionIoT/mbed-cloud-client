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

#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_FEATURE_FW_SOURCE_HTTP) && (ARM_UC_FEATURE_FW_SOURCE_HTTP == 1)

#include "arm_uc_http_socket_private.h"

#include "update-client-source-http-socket/arm_uc_http_socket.h"
#include "update-client-common/arm_uc_common.h"


/*****************************************************************************/
/* Public Function                                                           */
/*****************************************************************************/

/**
 * @brief Initialize Http module.
 * @details Function pointer to event handler is passed as argument.
 *
 * @param context Struct holding all global variables.
 * @param handler Event handler for signaling when each operation is complete.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_HttpSocket_Initialize(arm_uc_http_socket_context_t *context,
                                             ARM_UCS_HttpEvent_t handler)
{
    return arm_uc_http_socket_initialize(context, handler);
}

/**
 * @brief Resets HTTP socket to uninitialized state and clears memory struct.
 * @details HTTP sockets must be initialized again before use.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_HttpSocket_Terminate(void)
{
    return arm_uc_http_socket_terminate();
}

/**
 * @brief Get hash for resource at URI.
 * @details Store hash in provided buffer. Enclosing "" and '\0' are removed.
 *
 *          Event generated: EVENT_HASH
 *
 * @param uri Pointer to struct with resource location.
 * @param buffer Pointer to structure with buffer location, maxSize, and size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_HttpSocket_GetHash(arm_uc_uri_t *uri,
                                          arm_uc_buffer_t *buffer)
{
    return arm_uc_http_socket_get(uri, buffer, UINT32_MAX, RQST_TYPE_HASH_ETAG);
}

/**
 * @brief Get date for resource at URI.
 * @details Store Last-Modified data in provided buffer. Enclosing "" and '\0' are removed.
 *
 *          Event generated: EVENT_DATE
 *
 * @param uri Pointer to struct with resource location.
 * @param buffer Pointer to structure with buffer location, maxSize, and size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_HttpSocket_GetDate(arm_uc_uri_t *uri,
                                          arm_uc_buffer_t *buffer)
{
    return arm_uc_http_socket_get(uri, buffer, UINT32_MAX, RQST_TYPE_HASH_DATE);
}

/**
 * @brief Get full resource at URI.
 * @details Download resource at URI and store in provided buffer.
 *          If the provided buffer is not big enough to contain the whole resource
 *          what can fit in the buffer will be downloaded.
 *          The user can then use GetFragment to download the rest.

 *          Events generated: EVENT_DOWNLOAD_PENDING if there is still data to
 *          download and EVENT_DOWNLOAD_DONE if the file is completely downloaded.
 *
 * @param uri Pointer to structure with resource location.
 * @param buffer Pointer to structure with buffer location, maxSize, and size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_HttpSocket_GetFile(arm_uc_uri_t *uri,
                                          arm_uc_buffer_t *buffer)
{
    return arm_uc_http_socket_get(uri, buffer, UINT32_MAX, RQST_TYPE_GET_FILE);
}

/**
 * @brief Get partial resource at URI.
 * @details Download resource at URI from given offset and store in buffer.
 *
 *          The buffer maxSize determines how big a fragment to download. If the
 *          buffer is larger than the requested fragment (offset to end-of-file)
 *          the buffer size is set to indicate the number of available bytes.
 *
 *          Events generated: EVENT_DOWNLOAD_PENDING if there is still data to
 *          download and EVENT_DOWNLOAD_DONE if the file is completely downloaded.
 *
 * @param uri Pointer to structure with resource location.
 * @param buffer Pointer to structure with buffer location, maxSize, and size.
 * @param offset Offset in resource to begin download from.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_HttpSocket_GetFragment(arm_uc_uri_t *uri,
                                              arm_uc_buffer_t *buffer,
                                              uint32_t offset)
{
    return arm_uc_http_socket_get(uri, buffer, offset, RQST_TYPE_GET_FRAG);
}

/**
 * @brief Cancel resume engine externally
 * @param unused Unused.
 */
void ARM_UC_HttpSocket_EndResume(void)
{
    arm_uc_http_socket_end_resume();
}

#endif // ARM_UC_FEATURE_FW_SOURCE_HTTP

