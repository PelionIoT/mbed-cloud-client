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

#ifndef __FOTA_EXT_DOWNLOADER_H_
#define __FOTA_EXT_DOWNLOADER_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

#if MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER

/**
 * Tell FOTA that image downloaded externally is ready.
 *
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_ext_downloader_on_image_ready(void);

/**
 * Write a fragment to the image at a certain offset.
 * Notes:
 *  - Writes can’t be done twice to the same offset.
 *  - Writes can only start after download has been authorized by app
 *  - Write offset should be a multiple of the candidate storage program size
 *  - Write size should be a multiple of the candidate storage program size (except for the last write)
 *
 * \param[in] buffer Buffer to write.
 * \param[in] offset Offset of buffer in image.
 * \param[in] size   Buffer size
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_ext_downloader_write_image_fragment(const void *buffer, size_t offset, size_t size);

#endif // MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_MULTICAST_H_
