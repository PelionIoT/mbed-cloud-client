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

#ifndef __FOTA_CURR_FW_LINUX_H_
#define __FOTA_CURR_FW_LINUX_H_

#include "fota/fota_base.h"

#if MBED_CLOUD_CLIENT_FOTA_ENABLE

#include "fota_header_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read header from given file.
 *
 * \param[out] header_info Header info structure.
 * \param[in] file_name   File name.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read_header_from_file(fota_header_info_t *header_info, const char *file_name);

/**
 * Write header to given file.
 *
 * \param[in] header_info Header info structure.
 * \param[in] file_name   File name.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_write_header_to_file(fota_header_info_t *header_info, const char *file_name);

#ifdef __cplusplus
}
#endif
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE

#endif // __FOTA_CURR_FW_LINUX_H_
