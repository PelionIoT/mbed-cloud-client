// ----------------------------------------------------------------------------
// Copyright 2018-2021 ARM Ltd.
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

#ifndef __FOTA_CURR_FW_H_
#define __FOTA_CURR_FW_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota_header_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file fota_curr_fw.h
 *  \brief FOTA requires access to the currently installed firmware (FW) and the FW metadata header.
 * By default, on non-Mbed-OS targets, the FOTA library assumes a custom FW layout structure and expects that the application will implement the current FW interfaces described in this file.
 * If the FW image and the FW header reside in a memory mapped flash, you can define the ::FOTA_CUSTOM_CURR_FW_STRUCTURE=0 macro, in which case, the application only has to implement these functions:
 *     uint8_t *fota_curr_fw_get_app_start_addr(void)
 *     uint8_t *fota_curr_fw_get_app_header_addr(void)
 */

/**
 * Returns a pointer to the application start.
 *
 * \return Pointer to the application start.
 */
uint8_t *fota_curr_fw_get_app_start_addr(void);

/**
 * Returns a pointer to the header start.
 *
 * \return Pointers to the header start.
 */
uint8_t *fota_curr_fw_get_app_header_addr(void);

#if FOTA_CUSTOM_CURR_FW_STRUCTURE || defined(TARGET_LIKE_LINUX)
/**
 * Reads the header of the current firmware.
 *
 * \param[in] header_info Header info structure.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read_header(fota_header_info_t *header_info);
#else

// Default read header implementation.
static inline int fota_curr_fw_read_header(fota_header_info_t *header_info)
{
    uint8_t *header_in_curr_fw = (uint8_t *)fota_curr_fw_get_app_header_addr();
    return fota_deserialize_header(header_in_curr_fw, fota_get_header_size(), header_info);
}
#endif  // FOTA_CUSTOM_CURR_FW_STRUCTURE

/**
 * Read from the current firmware.
 *
 * \param[out] buf       Buffer to read into.
 * \param[in]  offset    Offset in the firmware.
 * \param[in]  size      Size to read in bytes.
 * \param[out] num_read  Number of read bytes.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read(uint8_t *buf, size_t offset, size_t size, size_t *num_read);

/**
 * Read the digest from the current firmware.
 *
 * \param[out]  buf     Buffer to read into.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_get_digest(uint8_t *buf);

#ifdef __cplusplus
}
#endif
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_CURR_FW_H_
