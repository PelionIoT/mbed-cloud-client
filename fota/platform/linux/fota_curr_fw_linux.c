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
#define TRACE_GROUP "FOTA"

#include <stdlib.h>
#include "fota/fota_curr_fw.h"
#include "fota/fota_status.h"
#include "fota_platform_linux.h"

// These two functions are only required in delta update case, which is on relevant for single main file
#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
int fota_curr_fw_read(uint8_t *buf, size_t offset, size_t size, size_t *num_read)
{
    int status = FOTA_STATUS_INTERNAL_ERROR;
    size_t read_bytes;
    FILE *fs = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME, "r");
    if (!fs) {
        FOTA_TRACE_ERROR("Failed to open program file");
        return status;
    }

    if (fseek(fs, offset, SEEK_SET) == -1) {
        goto cleanup;
    }

    read_bytes = fread(buf, 1, size, fs);
    if (read_bytes < 1) {
        goto cleanup;
    }

    *num_read = read_bytes;
    status = FOTA_STATUS_SUCCESS;

cleanup:
    (void)fclose(fs);
    return status;
}

int fota_curr_fw_get_digest(uint8_t *buf)
{
    fota_header_info_t curr_fw_info;
    int ret = fota_curr_fw_read_header(&curr_fw_info);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to read current header");
        return ret;
    }
    memcpy(buf, curr_fw_info.digest, FOTA_CRYPTO_HASH_SIZE);
    return FOTA_STATUS_SUCCESS;
}
#endif // MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE

int fota_curr_fw_read_header_from_file(fota_header_info_t *header_info, const char *file_name)
{
    int status = FOTA_STATUS_INTERNAL_ERROR;
    size_t bytes_read = 0;

    FILE *fs = fopen(file_name, "r");
    if (!fs) {
        return status;
    }

    const size_t header_size = fota_get_header_size();
    uint8_t *buf = (uint8_t *)malloc(header_size);
    if (!buf) {
        FOTA_TRACE_ERROR("Failed to allocate buffer for header reading");
        goto cleanup;
    }

    bytes_read = fread(buf, 1, header_size, fs);
    if (bytes_read != header_size) {
        FOTA_TRACE_ERROR("Failed to read header file");
        goto cleanup;
    }

    status = fota_deserialize_header(buf, header_size, header_info);
    if (status) {
        goto cleanup;
    }

    if (header_info->footer != FOTA_FW_HEADER_MAGIC) {
        FOTA_TRACE_ERROR("Invalid header in current installed firmware");
        goto cleanup;
    }

    status = FOTA_STATUS_SUCCESS;

cleanup:
    (void)fclose(fs);
    free(buf);
    return status;
}

int fota_curr_fw_read_header(fota_header_info_t *header_info)
{
    return fota_curr_fw_read_header_from_file(header_info, fota_linux_get_header_file_name());
}

int fota_curr_fw_write_header_to_file(fota_header_info_t *header_info, const char *file_name)
{
    int status = FOTA_STATUS_INTERNAL_ERROR;
    size_t actual_size;

    FILE *fs = fopen(file_name, "w");
    if (!fs) {
        FOTA_TRACE_ERROR("Failed to open current header file");
        return status;
    }

    const size_t header_size = fota_get_header_size();
    uint8_t *buf = (uint8_t *)malloc(header_size);
    if (!buf) {
        FOTA_TRACE_ERROR("Failed to allocate buffer for header writing");
        goto cleanup;
    }

    fota_set_header_info_magic(header_info);
    if (fota_serialize_header(header_info, buf, header_size, &actual_size)) {
        goto cleanup;
    }

    if (fwrite(buf, 1, actual_size, fs) != actual_size) {
        FOTA_TRACE_ERROR("Failed to write header file");
        goto cleanup;
    }

    status = FOTA_STATUS_SUCCESS;

cleanup:
    (void)fclose(fs);
    free(buf);
    return status;
}

#endif  // defined(TARGET_LIKE_LINUX)
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
