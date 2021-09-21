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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE
#if defined(TARGET_LIKE_LINUX)

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "fota_platform_linux.h"
#include "fota_crypto.h"
#include "fota_curr_fw.h"
#include "fota_curr_fw_linux.h"
#include "fota_component_internal.h"

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
#if MBED_CLOUD_CLIENT_FOTA_SUPPORT_PAL
#include "pal.h"
#endif
#endif

#define TRACE_GROUP "FOTA"

#ifdef MBED_CLOUD_CLIENT_FOTA_INIT_MAIN_VERSION
#define __STRINGIFY(macro) #macro
#define STRINGIFY(macro) __STRINGIFY(macro)
#define INIT_MAIN_VERSION STRINGIFY(MBED_CLOUD_CLIENT_FOTA_INIT_MAIN_VERSION)
#else
#define INIT_MAIN_VERSION "0.0.0"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#define MAX_SYS_CALL_COMMAND_SIZE 512
char command_buffer[MAX_SYS_CALL_COMMAND_SIZE] = { 0 };
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
static char *header_file_name = NULL;
static char *temp_header_file_name = NULL;
static char *update_storage_file_name = NULL;
static char *candidate_file_name = NULL;
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
static char *package_dir_name = NULL;
static char *package_descriptor_file_name = NULL;
#endif
// Use config directory for all FOTA files
static void set_full_file_name(char **var, const char *base)
{
    char *curr_dir = ".";
    char *dirname;
#if MBED_CLOUD_CLIENT_FOTA_SUPPORT_PAL
    // In yocto, header file and temp header file reside in primary pal partition (mnt/config),and defined in fota_config.h as a simple file name.
    // The candidate and raw candidate files reside in /mnt/cache directory and defined as a full path.

    // If fota file starts with '/' - its already have a full path, we don't need to build full file name
    if (base[0] != '/') {
        char primary[PAL_MAX_FILE_AND_FOLDER_LENGTH];
        pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, primary);
        dirname = primary;
    }
#else
#if defined(SIMULATED_KVSTORE_FILE_NAME)
    char kvfile[] = SIMULATED_KVSTORE_FILE_NAME;
#else
    char kvfile[] = "";
#endif
    char *p = strrchr(kvfile, '/');
    if (p) {
        *p = 0;
    } else {
        kvfile[0] = 0;
    }
    dirname = kvfile;
#endif
    if (!strlen(dirname)) {
        dirname = curr_dir;
    }
    free(*var);
    if (base[0] == '/') {
        // If current file name is a full path, allocate memory only for the path, no need additional space
        *var = (char *) malloc(strlen(base) + 1);
        FOTA_ASSERT(*var);
        sprintf(*var, "%s", base);
    } else {
        *var = (char *) malloc(strlen(dirname) + strlen(base) + 2);
        FOTA_ASSERT(*var);
        sprintf(*var, "%s/%s", dirname, base);
    }
}


const char *fota_linux_get_header_file_name(void)
{
    return header_file_name;
}

const char *fota_linux_get_temp_header_file_name(void)
{
    return temp_header_file_name;
}

const char *fota_linux_get_update_storage_file_name(void)
{
    return update_storage_file_name;
}

const char *fota_linux_get_candidate_file_name(void)
{
    return candidate_file_name;
}
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
const char *fota_linux_get_package_dir_name(void)
{
    return package_dir_name;
}

const char *fota_linux_get_package_descriptor_file_name(void)
{
    return package_descriptor_file_name;
}
#endif


#endif // !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)

static const int fw_buf_size = 2048;

int fota_linux_candidate_iterate(const char* comp_name, const char *sub_comp_name, fota_comp_candidate_iterate_callback_info *info, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx)
{
    switch (info->status) {
        case FOTA_CANDIDATE_ITERATE_START: {
            // open candidate file to write
            info->user_ctx = (void *)fopen(fota_linux_get_candidate_file_name(), "wb");
            if (info->user_ctx == NULL) {
                FOTA_TRACE_ERROR("Failed opening file %s: %d", fota_linux_get_candidate_file_name(), errno);
                return FOTA_STATUS_STORAGE_WRITE_FAILED;
            }

            return FOTA_STATUS_SUCCESS;
        }

        case FOTA_CANDIDATE_ITERATE_FRAGMENT:
            if (fseek((FILE *)info->user_ctx, info->frag_pos, SEEK_SET)) {
                (void)fclose((FILE *)info->user_ctx);
                return FOTA_STATUS_STORAGE_WRITE_FAILED;
            }
            if (fwrite(info->frag_buf, info->frag_size, 1, (FILE *)info->user_ctx) != 1) {
                (void)fclose((FILE *)info->user_ctx);
                return FOTA_STATUS_STORAGE_WRITE_FAILED;
            }

            return FOTA_STATUS_SUCCESS;

        case FOTA_CANDIDATE_ITERATE_FINISH: {
            (void)fclose((FILE *)info->user_ctx);
            return FOTA_STATUS_SUCCESS;
        }

        default:
            return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_INTERNAL_ERROR;
}

int fota_linux_update_curr_fw_header(fota_header_info_t *header_info)
{
    int status;

    status = fota_curr_fw_write_header_to_file(header_info, fota_linux_get_temp_header_file_name());
    if (status) {
        return status;
    }
    if (rename(fota_linux_get_temp_header_file_name(), fota_linux_get_header_file_name())) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_linux_get_curr_fw_size(size_t *size)
{
    struct stat statbuf;
    if (stat(MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME, &statbuf) != 0) {
        FOTA_TRACE_ERROR("Failed to read current FW size");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    *size = (size_t) statbuf.st_size;
    return FOTA_STATUS_SUCCESS;
}
#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
int fota_linux_get_curr_fw_digest(size_t fw_size, uint8_t *digest)
{
    uint8_t fw_buf[fw_buf_size];
    size_t actual_size;

    fota_hash_context_t *hash_ctx = NULL;
    if (fota_hash_start(&hash_ctx) != FOTA_STATUS_SUCCESS) {
        FOTA_TRACE_ERROR("Hash start failed");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    for (size_t i = 0; i < fw_size; i += fw_buf_size) {
        if (fota_curr_fw_read(fw_buf, i, fw_buf_size, &actual_size) == FOTA_STATUS_SUCCESS) {
            if (fota_hash_update(hash_ctx, fw_buf, actual_size)) {
                FOTA_TRACE_ERROR("Hash update failed");
                return FOTA_STATUS_INTERNAL_ERROR;
            }
        } else {
            FOTA_TRACE_ERROR("Unable to read current firmware");
            return FOTA_STATUS_INTERNAL_ERROR;
        }
    }

    if (fota_hash_result(hash_ctx, digest)) {
        FOTA_TRACE_ERROR("Hash finish failed");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    fota_hash_finish(&hash_ctx);

    return FOTA_STATUS_SUCCESS;
}
#endif

int fota_linux_init()
{
    int status = FOTA_STATUS_INTERNAL_ERROR;
    fota_header_info_t header_info;

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
    set_full_file_name(&header_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME);
    set_full_file_name(&temp_header_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME);
    set_full_file_name(&update_storage_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
    set_full_file_name(&candidate_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME);
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    set_full_file_name(&package_dir_name, MBED_CLOUD_CLIENT_FOTA_LINUX_PACKAGE_DIRECTORY_NAME);
    set_full_file_name(&package_descriptor_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_PACKAGE_DESCRIPTOR_FILE_NAME);
#endif
#endif

    // Check if a valid temporary file exists. If so, use it as our file (as it can only exist
    // if update was interrupted before rename operation was interrupted).
    status = fota_curr_fw_read_header_from_file(&header_info, fota_linux_get_temp_header_file_name());
    if (!status) {
        status = rename(fota_linux_get_temp_header_file_name(), fota_linux_get_header_file_name());
        FOTA_ASSERT(!status);
        FOTA_TRACE_DEBUG("Using temporary header file");
    }

    // Check whether header file exists and valid
    status = fota_curr_fw_read_header_from_file(&header_info, fota_linux_get_header_file_name());
    if (status) {
        // Header completely invalid - regenerate it from scratch
        memset(&header_info, 0, sizeof(header_info));

        if (fota_component_version_semver_to_int(INIT_MAIN_VERSION, &header_info.version)) {
            FOTA_TRACE_ERROR("Invalid initial version " INIT_MAIN_VERSION);
            FOTA_ASSERT(!status);
        }
    }

#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
    // Header may be valid, but in case of a single main file, may still not match it
    // (for instance if exe file replaced during development process, without replacing header file)
    size_t curr_fw_size;
    status = fota_linux_get_curr_fw_size(&curr_fw_size);
    FOTA_ASSERT(!status);

    uint8_t calc_digest[FOTA_CRYPTO_HASH_SIZE];
    status = fota_linux_get_curr_fw_digest(curr_fw_size, calc_digest);
    FOTA_ASSERT(!status);

    if ((header_info.fw_size == curr_fw_size) &&
            !memcmp(header_info.digest, calc_digest, FOTA_CRYPTO_HASH_SIZE)) {
        // All good, nothing more to do here
        return FOTA_STATUS_SUCCESS;
    }

    // Update digest and firmware size, falling through to header regeneration
    header_info.fw_size = curr_fw_size;
    memcpy(header_info.digest, calc_digest, FOTA_CRYPTO_HASH_SIZE);

#else // !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
    // Multifile - only regenerate header if it was invalid
    if (!status) {
        return FOTA_STATUS_SUCCESS;
    }
#endif

    // Regenerate header
    FOTA_TRACE_DEBUG("Header file regenerated");
    status = fota_linux_update_curr_fw_header(&header_info);
    FOTA_ASSERT(!status);

    return FOTA_STATUS_SUCCESS;
}
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
#if  MBED_CLOUD_CLIENT_FOTA_SUPPORT_PAL == 1
int fota_linux_remove_directory(const char *path_name)
{
    // delete the files in package directory
    palStatus_t  pal_status = pal_fsRmFiles(path_name);
    // the use case is that package directory may not exist
    if ((pal_status != PAL_SUCCESS) && (pal_status != PAL_ERR_FS_NO_FILE) && (pal_status != PAL_ERR_FS_NO_PATH)) {
        FOTA_TRACE_ERROR("Failed to remove package directory files %s with pal_status  0x%x", path_name, (unsigned int)pal_status);
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    // delete the package directory directory
    pal_status = pal_fsRmDir(fota_linux_get_package_dir_name());
    if (pal_status != PAL_SUCCESS) {
        // Any error apart from dir not exist returns error.
        if ((pal_status != PAL_ERR_FS_NO_FILE) && (pal_status != PAL_ERR_FS_NO_PATH)) {
            FOTA_TRACE_ERROR("Failed to remove package directory %s with pal_status  0x%x", path_name, (unsigned int)pal_status);
            return FOTA_STATUS_INTERNAL_ERROR;
        }
    }
    return FOTA_STATUS_SUCCESS;
}
#endif
#else
//TODO: Implement this with c function (without system call)
int fota_linux_remove_directory(const char *path_name)
{
    int res = 0;
    // Initialize command buffer.
    memset(command_buffer, 0, sizeof(command_buffer));
    // Build rm directory command string.
    res = snprintf(command_buffer, sizeof(command_buffer), "rm -rf %s ", path_name);
    if (res == 0) {
        FOTA_TRACE_ERROR("Failed to build rm -rf command");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Use system call to delete directory.
    res = system(command_buffer);
    if (res) {
        FOTA_TRACE_ERROR("System call remove directory failed");
        return FOTA_STATUS_INTERNAL_ERROR;
    }
	
    return FOTA_STATUS_SUCCESS;
}
#endif

// Read file data : get the size of the file -> allocate memory -> read the file
int fota_linux_read_file(const char *file_name, uint8_t **p_buffer, size_t *p_buffer_size)
{
    int res = 0;
    size_t bytes_read = 0;
    uint8_t *p_temp = NULL;

    // Open file.
    FILE *desc_handle = fopen(file_name, "r");
    if (!desc_handle) {
        if (errno == ENOENT) {
            res = FOTA_STATUS_COMB_PACKAGE_DIR_NOT_FOUND;
        } else {
            FOTA_TRACE_ERROR("Failed to open file : %s", strerror(errno));
            res = FOTA_STATUS_INTERNAL_ERROR;
        }
        goto cleanup;
    }
    if (fseek(desc_handle, 0L, SEEK_END)) {
        FOTA_TRACE_ERROR("Failed SEEK_END descriptor file");
        res = FOTA_STATUS_INTERNAL_ERROR;
        goto cleanup;
    }
    // Get size of the descriptor file.
    *p_buffer_size = ftell(desc_handle);

    // Allocate buffer for descriptor file data.
    p_temp = malloc(*p_buffer_size);
    if (!p_temp) {
        FOTA_TRACE_ERROR("Failed to allocate memory");
        res = FOTA_STATUS_OUT_OF_MEMORY;
        goto cleanup;
    }

    // Seek to the beginning of the file.
    fseek(desc_handle, 0, SEEK_SET);

    // Read the file to the allocated buffer
    bytes_read = fread(p_temp, 1, *p_buffer_size, desc_handle);
    if (bytes_read != *p_buffer_size) {
        FOTA_TRACE_ERROR("Failed to read descripor file");
        res = FOTA_STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    *p_buffer = p_temp;

cleanup:
    // Close file handle
    if (desc_handle) {
        fclose(desc_handle);
    }
    // In case of failure release package descriptor data memory.
    if (res != 0 && p_temp != NULL) {
        free(p_temp);
    }
    return res;
}
int fota_linux_create_directory(const char* file_name)
{
    // Remove package directory
    int res = fota_linux_remove_directory(file_name);
    if (res) {
        FOTA_TRACE_ERROR("Failed to remove directory %s ", file_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Create package directory
    res = mkdir(file_name, 0700);
    if (res) {
        FOTA_TRACE_ERROR("Failed to create directory %s",file_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return res;
}

int fota_linux_untar_file(const char* file_name, const char* dir_name)
{
    // Initialize command buffer.
    memset(command_buffer, 0, sizeof(command_buffer));
    // Build tar command string.
    int res = snprintf(command_buffer, sizeof(command_buffer), "tar -xf %s -C %s", file_name,dir_name);
    if (res == 0) {
        FOTA_TRACE_ERROR("Failed to build tar command");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Use system call to untar the combined package.
    res = system(command_buffer);
    if (res) {
        FOTA_TRACE_ERROR("System call tar failed");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return res;
}

int fota_linux_extract_and_get_package_descriptor_data(uint8_t **package_descriptor_data, size_t *package_descriptor_data_size)
{
    int res = 0;
    char command_buffer[MAX_SYS_CALL_COMMAND_SIZE] = { 0 };

    // Create package directory
    res = fota_linux_create_directory(fota_linux_get_package_dir_name());
    if (res) {
        FOTA_TRACE_ERROR("Failed to create package directory %s ", fota_linux_get_package_dir_name());
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Untar package directory
    res = fota_linux_untar_file(fota_linux_get_candidate_file_name(),fota_linux_get_package_dir_name());
    if (res) {
        FOTA_TRACE_ERROR("Failed to untar package file %s ", fota_linux_get_candidate_file_name());
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // Read descriptor file
    res = fota_linux_read_file(fota_linux_get_package_descriptor_file_name(),package_descriptor_data,package_descriptor_data_size);
    if (res) {
        FOTA_TRACE_ERROR("Failed to read descriptor file");
        res = FOTA_STATUS_INTERNAL_ERROR;
    }
    return res;
}
#endif

void fota_linux_deinit()
{
#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
    free(header_file_name);
    header_file_name = NULL;
    free(temp_header_file_name);
    temp_header_file_name = NULL;
    free(update_storage_file_name);
    update_storage_file_name = NULL;
    free(candidate_file_name);
    candidate_file_name = NULL;
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    free(package_dir_name);
    package_dir_name = NULL;
    free(package_descriptor_file_name);
    package_descriptor_file_name = NULL;
#endif
#endif
}

#endif  // defined(TARGET_LIKE_LINUX)
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
