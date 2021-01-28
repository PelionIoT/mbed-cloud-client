// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#ifndef __FOTA_FW_DOWNLAD_H_
#define __FOTA_FW_DOWNLAD_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * FOTA download init.
 *
 * \param[out] download_handle for the context.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_download_init(void **download_handle);

/**
 * FOTA download start.
 *
 * \param[in] download_handle for the context.
 * \param[in] payload_url download file url.
 * \param[in] payload_offset download file offset for the start.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_download_start(void *download_handle, const char *payload_url, size_t payload_offset);

/**
 * FOTA download request fragment.
 *
 * \param[in] download_handle for the context.
 * \param[in] payload_url download file url.
 * \param[in] payload_offset download file offset for the next fragment.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_download_request_next_fragment(void *download_handle, const char *payload_url, size_t payload_offset);

/**
 * FOTA download deinit for cleanup.
 *
 * \param[in,out] download_handle for the context.
 */
void fota_download_deinit(void **download_handle);


#ifdef __cplusplus
}
#endif

#endif  // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_FW_DOWNLAD_H_
