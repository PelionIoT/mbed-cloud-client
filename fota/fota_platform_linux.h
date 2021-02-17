// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef __FOTA_PLATFORM_LINUX_H_
#define __FOTA_PLATFORM_LINUX_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

#include "fota_candidate.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
// This could also have been implemented with the functions below, however it's implemented with defines due to a surreal bug
// in unitests, clobbering the pointer to the internal string when called from a different module.
#define fota_linux_get_header_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME
#define fota_linux_get_temp_header_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME
#define fota_linux_get_update_storage_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME
#define fota_linux_get_candidate_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME
#else
const char *fota_linux_get_header_file_name(void);
const char *fota_linux_get_temp_header_file_name(void);
const char *fota_linux_get_update_storage_file_name(void);
const char *fota_linux_get_candidate_file_name(void);
#endif

int fota_linux_candidate_iterate(fota_candidate_iterate_callback_info *info);
int fota_linux_init();
void fota_linux_deinit();

#ifdef __cplusplus
}
#endif
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_PLATFORM_LINUX_H_
