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

#ifndef __FOTA_PLATFORM_LINUX_H_
#define __FOTA_PLATFORM_LINUX_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

#include "fota_candidate.h"
#include "fota_header_info.h"
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#include "fota_combined_package.h"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#define MBED_CLOUD_CLIENT_FOTA_LINUX_PACKAGE_DESCRIPTOR_FILE_NAME  MBED_CLOUD_CLIENT_FOTA_LINUX_PACKAGE_DIRECTORY_NAME  "/" FOTA_COMBINED_IMAGE_DESCRIPTOR_FILENAME
#endif

#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
// This could also have been implemented with the functions below, however it's implemented with defines due to a surreal bug
// in unitests, clobbering the pointer to the internal string when called from a different module.
#define fota_linux_get_header_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME
#define fota_linux_get_temp_header_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME
#define fota_linux_get_update_storage_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME
#define fota_linux_get_candidate_file_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#define fota_linux_get_package_dir_name() MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/" MBED_CLOUD_CLIENT_FOTA_LINUX_PACKAGE_DIRECTORY_NAME
#define fota_linux_get_package_descriptor_file_name() fota_linux_get_package_dir_name() "/" FOTA_COMBINED_IMAGE_DESCRIPTOR_FILENAME
#endif
#else
const char *fota_linux_get_header_file_name(void);
const char *fota_linux_get_temp_header_file_name(void);
const char *fota_linux_get_update_storage_file_name(void);
const char *fota_linux_get_candidate_file_name(void);
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
const char *fota_linux_get_package_dir_name(void);
const char *fota_linux_get_package_descriptor_file_name(void);
#endif
#endif

int fota_linux_candidate_iterate(const char* comp_name, const char *sub_comp_name, fota_comp_candidate_iterate_callback_info *info, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx);
int fota_linux_update_curr_fw_header(fota_header_info_t *header_info);
int fota_linux_get_curr_fw_size(size_t *size);
int fota_linux_get_curr_fw_digest(size_t fw_size, uint8_t *digest);
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
int fota_linux_extract_and_get_package_descriptor_data(uint8_t **package_descriptor_data, size_t *package_descriptor_data_size);
int fota_linux_read_file(const char *file_name, uint8_t **p_buffer, size_t *p_buffer_size);
int fota_linux_remove_directory(const char *path_name);
int fota_linux_create_directory(const char* file_name);
int fota_linux_untar_file(const char* file_name, const char* dir_name);
#endif
int fota_linux_init();
void fota_linux_deinit();

#ifdef __cplusplus
}
#endif
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_PLATFORM_LINUX_H_
