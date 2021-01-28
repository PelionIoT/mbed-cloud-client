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

#define TRACE_GROUP "FOTA"

#ifdef MBED_CLOUD_CLIENT_FOTA_INIT_MAIN_VERSION
#define __STRINGIFY(macro) #macro
#define STRINGIFY(macro) __STRINGIFY(macro)
#define INIT_MAIN_VERSION STRINGIFY(MBED_CLOUD_CLIENT_FOTA_INIT_MAIN_VERSION)
#else
#define INIT_MAIN_VERSION "0.0.0"
#endif


extern char *program_invocation_name;
static const int fw_buf_size = 2048;

int fota_linux_candidate_iterate(fota_candidate_iterate_callback_info *info)
{
    switch (info->status) {
        case FOTA_CANDIDATE_ITERATE_START: {
            // open candidate file to write
            info->user_ctx = (void *)fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME, "wb");
            if (info->user_ctx == NULL) {
                FOTA_TRACE_ERROR("Failed opening file %s: %d", MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME, errno);
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
            FILE *fd = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME, "wb");
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

            if (rename(MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME,
                       MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME)) {
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
    FILE *fs;

    // Check if temporary file exists. If so, use it as our file (as it can only exist
    // if update was interrupted before rename operation was interrupted).
    fs = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME, "r");
    if (fs) {
        fclose(fs);
        fota_header_info_t header_info;

        FOTA_TRACE_DEBUG("Found temporary header file");
        status = fota_curr_fw_read_header_from_file(&header_info,
                                                    MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME);
        if (status) {
            // invalid temp header file, can't do anything with it
            remove(MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME);
            FOTA_TRACE_DEBUG("Illegal temporary header file. Removed.");
        } else {
            int ret = rename(MBED_CLOUD_CLIENT_FOTA_LINUX_TEMP_HEADER_FILENAME,
                             MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME);
            FOTA_ASSERT(!ret);
            FOTA_TRACE_DEBUG("Using temporary header file");
        }
    }

    // Check first whether file exists, if exists skip header creation part
    fs = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME, "r");
    if (!fs) {
        fota_header_info_t header_info = {0};

        status = fota_component_version_semver_to_int(INIT_MAIN_VERSION, &header_info.version);
        if (status) {
            FOTA_TRACE_ERROR("Invalid initial version " INIT_MAIN_VERSION);
            FOTA_ASSERT(!status);
        }

        status = FOTA_STATUS_INTERNAL_ERROR;

        // Write valid header information into file
        fs = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME, "w");
        if (!fs) {
            FOTA_TRACE_ERROR("Failed to create file for header information");
            return status;
        }

        struct stat statbuf;
        if (stat(program_invocation_name, &statbuf) != 0) {
            FOTA_TRACE_ERROR("Failed to read program file params");
            goto cleanup;
        }

        header_info.fw_size = statbuf.st_size;
        fota_set_header_info_magic(&header_info);
        uint8_t fw_buf[fw_buf_size];
        size_t actual_size;

        fota_hash_context_t *hash_ctx = NULL;
        if (fota_hash_start(&hash_ctx) != FOTA_STATUS_SUCCESS) {
            goto cleanup;
        }

        for (size_t i = 0; i < statbuf.st_size; i += fw_buf_size) {
            if (fota_curr_fw_read(fw_buf, i, fw_buf_size, &actual_size) == FOTA_STATUS_SUCCESS) {
                if (fota_hash_update(hash_ctx, fw_buf, actual_size)) {
                    goto cleanup;
                }
            } else {
                goto cleanup;
            }
        }

        if (fota_hash_result(hash_ctx, header_info.digest)) {
            goto cleanup;
        }

        fota_hash_finish(&hash_ctx);

        if (fota_serialize_header(&header_info, fw_buf, fw_buf_size, &actual_size)) {
            goto cleanup;
        }

        if (fwrite(fw_buf, 1, actual_size, fs) != actual_size) {
            goto cleanup;
        }
    } // !fs

    status = FOTA_STATUS_SUCCESS;

cleanup:
    fclose(fs);
    return status;
}

#endif  // defined(TARGET_LIKE_LINUX)
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
