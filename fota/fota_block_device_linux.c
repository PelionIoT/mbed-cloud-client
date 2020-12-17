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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE
#if defined(TARGET_LIKE_LINUX)
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_EXTERNAL_BD)

#define TRACE_GROUP "FOTA"

#include <errno.h>
#include "fota/fota_block_device.h"
#include "fota/fota_status.h"

#include <stdio.h>
#include <assert.h>
#include <sys/stat.h>

#define BD_ERASE_VALUE 0x0
#define BD_ERASE_SIZE 0x1
#define BD_READ_SIZE 0x1
#define BD_PROGRAM_SIZE 0x1
#define BD_ERASE_BUFFER_SIZE 0x1000

static FILE *bd_backend = NULL;

static size_t get_bd_backend_file_size()
{
    struct stat st;

    if (stat(MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME, &st) == 0) {
        return (st.st_size);
    } else {
        FOTA_TRACE_ERROR("stat failed: %s", strerror(errno));
        assert(0);
        return 0;
    }
}

int fota_bd_size(size_t *size)
{
    assert(bd_backend);
    *size = MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE;
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_init(void)
{
    if (!bd_backend) {
        bd_backend = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME, "rb+");
        if (NULL == bd_backend) {
            bd_backend = fopen(MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME, "wb+");
            if (NULL == bd_backend) {
                FOTA_TRACE_ERROR("fopen failed: %s", strerror(errno));
                FOTA_TRACE_ERROR("Failed to initialize BlockDevice - failed to create file %s", MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
                return FOTA_STATUS_STORAGE_WRITE_FAILED;
            }
        }
    }

    FOTA_TRACE_DEBUG("FOTA BlockDevice init file is %s", MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_deinit(void)
{
    if (bd_backend) {
        if (fclose(bd_backend)) {
            FOTA_TRACE_ERROR("fclose failed: %s", strerror(errno));
            FOTA_TRACE_ERROR("Failed to deinit BlockDevice - failed to close %s", MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
        } else {
            FOTA_TRACE_DEBUG("Closed FOTA BlockDevice file %s", MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
        }
        bd_backend = NULL;
    }

    FOTA_TRACE_DEBUG("FOTA BlockDevice deinit file is %s", MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_read(void *buffer, size_t addr, size_t size)
{
    assert(bd_backend);

    size_t file_size = get_bd_backend_file_size();
    size_t read_addr = MIN(file_size, addr);

    if (fseek(bd_backend, read_addr, SEEK_SET)) {
        FOTA_TRACE_ERROR("fseek failed: %s", strerror(errno));
        return FOTA_STATUS_STORAGE_READ_FAILED;
    }

    size_t bytes_read = fread(buffer, 1, size, bd_backend);
    memset(buffer + bytes_read, BD_ERASE_VALUE, size - bytes_read);
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_program(const void *buffer, size_t addr, size_t size)
{
    assert(bd_backend);

    if (fseek(bd_backend, addr, SEEK_SET)) {
        FOTA_TRACE_ERROR("fseek failed: %s", strerror(errno));
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    size_t bytes_written = fwrite(buffer, 1, size, bd_backend);
    if (bytes_written != size) {
        FOTA_TRACE_ERROR("fwrite failed: %s", strerror(errno));
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_bd_erase(size_t addr, size_t size)
{
    assert(bd_backend);

    size_t file_size = get_bd_backend_file_size();

    if (addr >= file_size) {
        return FOTA_STATUS_SUCCESS;
    }

    if (fseek(bd_backend, addr, SEEK_SET)) {
        FOTA_TRACE_ERROR("fseek failed: %s", strerror(errno));
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    size_t erase_size = size;
    if ((addr + size) > file_size) {
        erase_size = file_size - addr;
    }

    uint8_t erase_buff[BD_ERASE_BUFFER_SIZE];
    memset(erase_buff, BD_ERASE_VALUE, sizeof(erase_buff));
    size_t bytes_written = 0;
    size_t size_to_write;
    while (erase_size) {
        size_to_write = MIN(sizeof(erase_buff), erase_size);
        bytes_written = fwrite(erase_buff, 1, size_to_write, bd_backend);
        if (bytes_written != size_to_write) {
            FOTA_TRACE_ERROR("fwrite failed: %s", strerror(errno));
            FOTA_TRACE_ERROR("Write failed BlockDevice - file %s", MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME);
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
        erase_size -= size_to_write;
    }

    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_read_size(size_t *read_size)
{
    *read_size = BD_READ_SIZE;
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_program_size(size_t *prog_size)
{
    *prog_size = BD_PROGRAM_SIZE;
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_erase_size(size_t addr, size_t *erase_size)
{
    *erase_size = BD_ERASE_SIZE;
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_get_erase_value(int *erase_value)
{
    *erase_value = BD_ERASE_VALUE;
    return FOTA_STATUS_SUCCESS;
}

#endif // (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE != FOTA_EXTERNAL_BD)
#endif // defined(TARGET_LIKE_LINUX)
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
