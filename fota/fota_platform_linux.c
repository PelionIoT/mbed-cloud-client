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

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
static char *header_file_name = NULL;
static char *temp_header_file_name = NULL;
static char *update_storage_file_name = NULL;
static char *candidate_file_name = NULL;

// Use config directory for all FOTA files
static void set_full_file_name(char **var, const char *base)
{
    char *curr_dir = ".";
    char *dirname;
#if MBED_CLOUD_CLIENT_FOTA_SUPPORT_PAL
    char primary[PAL_MAX_FILE_AND_FOLDER_LENGTH];
    pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, primary);
    dirname = primary;
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
    *var = (char *) malloc(strlen(dirname) + strlen(base) + 2);
    FOTA_ASSERT(*var);
    sprintf(*var, "%s/%s", dirname, base);
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
#endif // !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)

static const int fw_buf_size = 2048;

int fota_linux_candidate_iterate(fota_candidate_iterate_callback_info *info)
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

            // write current header
            size_t size;
            uint8_t header_buf[fw_buf_size];

            if (fota_serialize_header(info->header_info, header_buf, fw_buf_size, &size) != FOTA_STATUS_SUCCESS) {
                FOTA_TRACE_ERROR("Failed to serialize header");
                return FOTA_STATUS_INTERNAL_ERROR;
            }

            // Use temporary file to ensure resilience of header file modification
            FILE *fd = fopen(fota_linux_get_temp_header_file_name(), "wb");
            if (!fd) {
                FOTA_TRACE_ERROR("Failed to open header file for update");
                return FOTA_STATUS_INTERNAL_ERROR;
            }

            if (fwrite(header_buf, size, 1, fd) != 1) {
                FOTA_TRACE_ERROR("Failed to write header");
                (void)fclose(fd);
                return FOTA_STATUS_INTERNAL_ERROR;
            }

            (void)fclose(fd);

            if (rename(fota_linux_get_temp_header_file_name(),
                       fota_linux_get_header_file_name())) {
                return FOTA_STATUS_INTERNAL_ERROR;
            }

            return FOTA_STATUS_SUCCESS;
        }

        default:
            return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_INTERNAL_ERROR;
}

int fota_linux_init()
{
    int status = FOTA_STATUS_INTERNAL_ERROR;
    fota_header_info_t header_info;

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR)
    set_full_file_name(&header_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME);
    set_full_file_name(&temp_header_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME);
    set_full_file_name(&update_storage_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
    set_full_file_name(&candidate_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME);
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

        status = fota_component_version_semver_to_int(INIT_MAIN_VERSION, &header_info.version);
        if (status) {
            FOTA_TRACE_ERROR("Invalid initial version " INIT_MAIN_VERSION);
            FOTA_ASSERT(!status);
        }
    }

#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
    // Header may be valid, but in case of a single main file, may still not match it
    // (for instance if exe file replaced during development process, without replacing header file)
    struct stat statbuf;
    if (stat(MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME, &statbuf) != 0) {
        FOTA_ASSERT(!"Failed to read program file params");
    }

    uint8_t fw_buf[fw_buf_size];
    uint8_t calc_digest[FOTA_CRYPTO_HASH_SIZE];
    size_t actual_size;

    fota_hash_context_t *hash_ctx = NULL;
    if (fota_hash_start(&hash_ctx) != FOTA_STATUS_SUCCESS) {
        FOTA_ASSERT(!"Hash start failed");
    }

    for (size_t i = 0; i < statbuf.st_size; i += fw_buf_size) {
        if (fota_curr_fw_read(fw_buf, i, fw_buf_size, &actual_size) == FOTA_STATUS_SUCCESS) {
            if (fota_hash_update(hash_ctx, fw_buf, actual_size)) {
                FOTA_ASSERT(!"Hash update failed");
            }
        } else {
            FOTA_ASSERT(!"Unable to read current firmware");
        }
    }

    if (fota_hash_result(hash_ctx, calc_digest)) {
        FOTA_ASSERT(!"Hash finish failed");
    }

    fota_hash_finish(&hash_ctx);

    if ((header_info.fw_size == statbuf.st_size) &&
            !memcmp(header_info.digest, calc_digest, FOTA_CRYPTO_HASH_SIZE)) {
        // All good, nothing more to do here
        return FOTA_STATUS_SUCCESS;
    }

    // Update digest and firmware size, falling through to header regeneration
    header_info.fw_size = statbuf.st_size;
    memcpy(header_info.digest, calc_digest, FOTA_CRYPTO_HASH_SIZE);

#else // !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
    // Multifile - only regenerate header if it was invalid
    if (!status) {
        return FOTA_STATUS_SUCCESS;
    }
#endif

    // Regenerate header
    FOTA_TRACE_DEBUG("Header file regenerated");
    status = fota_curr_fw_write_header_to_file(&header_info, fota_linux_get_temp_header_file_name());
    FOTA_ASSERT(!status);
    status = rename(fota_linux_get_temp_header_file_name(), fota_linux_get_header_file_name());
    FOTA_ASSERT(!status);

    return FOTA_STATUS_SUCCESS;
}

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
#endif
}

#endif  // defined(TARGET_LIKE_LINUX)
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
