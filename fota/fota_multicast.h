// ----------------------------------------------------------------------------
// Copyright 2020 Pelion Ltd.
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

#ifndef __FOTA_MULTICAST_H_
#define __FOTA_MULTICAST_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)

// Post action callback - supplying success/error code
typedef void (*fota_multicast_node_post_action_callback_t)(int);

/**
 * Got a new manifest via Multicast.
 *
 * \param[in] data              manifest data.
 * \param[in] size              manifest size.
 * \param[in] on_manifest_cb    callback whether OK to continue or error.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_multicast_node_on_manifest(uint8_t *data, size_t size,
                                    fota_multicast_node_post_action_callback_t on_manifest_cb);

/**
 * Got an image ready indication from Multicast.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_multicast_node_on_image_ready(void);

/**
 * Got an activate update command from Multicast.
 *
 * \param[in] activate_in_sec   Seconds to wait before activation.
 * \param[in] finish_cb         Callback triggered when finished.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_multicast_node_on_activate(size_t activate_in_sec,
                                    fota_multicast_node_post_action_callback_t activate_finish_cb);

/**
 * Got an abort update command from Multicast.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_multicast_node_on_abort(void);

/**
 *  Got a request from Multicast to get ready to store a new image.
 *
 * \param[in] image_size   Image size
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_multicast_node_get_ready_for_image(size_t image_size);

/**
 * Write a fragment to the image at a certain offset.
 * Note: writes can’t be done twice to the same offset.
 *
 * \param[in] buffer Buffer to write.
 * \param[in] offset Offset of buffer in image.
 * \param[in] size   Buffer size
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_multicast_node_write_image_fragment(const void *buffer, size_t offset, size_t size);

/**
 * Read a fragment from the image at a certain offset.
 *
 * \param[in] buffer Buffer to read.
 * \param[in] offset Offset of buffer in image.
 * \param[in] size   Buffer size
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_multicast_node_read_image_fragment(void *buffer, size_t offset, size_t size);

/**
 * Set multicast network fragment size.
 *
 * \param[in] frag_size Fragment size.
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_multicast_node_set_fragment_size(size_t frag_size);

#elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)

typedef struct {
    char    uri[FOTA_MANIFEST_URI_SIZE];                  // URI for downloading the image
    size_t  payload_size;                                 // Image size to be downloaded
    uint8_t payload_digest[FOTA_CRYPTO_HASH_SIZE];        // Image SHA256 digest
} fota_multicast_br_image_params;

// Post action callback - supplying success/error code
typedef void (*fota_multicast_br_post_action_callback_t)(int);

/**
 * Called when a new image is available from service to the BR
 *
 * \param[in] image_params   Downloaded image parameters.
 * \param[in] image_ready_cb Callback called when image download ends successfully or fails.
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_multicast_br_on_image_request(const fota_multicast_br_image_params *image_params,
                                       fota_multicast_br_post_action_callback_t image_ready_cb);

/**
 * Read a fragment from downloaded image at a certain offset.
 *
 * \param[in] buffer Buffer to read.
 * \param[in] offset Offset of buffer in image.
 * \param[in] size   Buffer size
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_multicast_br_read_from_image(void *buffer, size_t offset, size_t size);

#endif // FOTA_MULTICAST_BR_MODE

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_MULTICAST_H_
