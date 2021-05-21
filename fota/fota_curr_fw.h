// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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
 * Support code for each platform should implement the current FW interfaces described in this file.
 */

/**
 * Reads the header of the current firmware.
 *
 * \param[in] header_info Header info structure.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read_header(fota_header_info_t *header_info);

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
