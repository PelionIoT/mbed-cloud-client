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
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_EXTERNAL_BD)

#define TRACE_GROUP "FOTA"

#include <errno.h>
#include "fota/fota_block_device.h"
#include "fota/fota_status.h"
#include "fota_platform_linux.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>

#define BD_ERASE_VALUE 0xff
#define BD_ERASE_SIZE 0x1
#define BD_READ_SIZE 0x1
#define BD_PROGRAM_SIZE 0x1
#define BD_ERASE_BUFFER_SIZE 0x1000

static size_t get_bd_backend_file_size()
{
    struct stat st;

    if (stat(fota_linux_get_update_storage_file_name(), &st) == 0) {
        return (st.st_size);
    } else {
        FOTA_TRACE_ERROR("stat failed: %s", strerror(errno));
        FOTA_ASSERT(0);
        return 0;
    }
}

static FILE *get_bd_backend(void)
{
    FILE *bd_backend = fopen(fota_linux_get_update_storage_file_name(), "rb+");
    FOTA_ASSERT(bd_backend);
    return bd_backend;
}

int fota_bd_size(size_t *size)
{
    *size = MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE;
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_init(void)
{
    FILE *bd_backend = fopen(fota_linux_get_update_storage_file_name(), "rb+");
    if (NULL == bd_backend) {
        bd_backend = fopen(fota_linux_get_update_storage_file_name(), "wb+");
        if (NULL == bd_backend) {
            FOTA_TRACE_ERROR("fopen failed: %s", strerror(errno));
            FOTA_TRACE_ERROR("Failed to initialize BlockDevice - failed to create file %s", fota_linux_get_update_storage_file_name());
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
    }
    fclose(bd_backend);

    return FOTA_STATUS_SUCCESS;
}

int fota_bd_deinit(void)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_bd_read(void *buffer, size_t addr, size_t size)
{
    size_t bytes_read;
    size_t file_size = get_bd_backend_file_size();
    int ret;

    if (addr + size > file_size) {
        FOTA_TRACE_ERROR("Read failed: addr %ld, size %ld file size %ld", addr, size, file_size);
        return FOTA_STATUS_STORAGE_READ_FAILED;
    }

    FILE *bd_backend = get_bd_backend();

    if (fseek(bd_backend, addr, SEEK_SET)) {
        FOTA_TRACE_ERROR("fseek failed: %s", strerror(errno));
        ret = FOTA_STATUS_STORAGE_READ_FAILED;
        goto end;
    }

    bytes_read = fread(buffer, 1, size, bd_backend);
    memset(buffer + bytes_read, BD_ERASE_VALUE, size - bytes_read);
    ret = FOTA_STATUS_SUCCESS;

end:
    fclose(bd_backend);
    return ret;
}

int fota_bd_program(const void *buffer, size_t addr, size_t size)
{
    size_t bytes_written;
    size_t file_size = get_bd_backend_file_size();
    int ret;

    if (addr + size > file_size) {
        size_t delta = addr + size - file_size;
        if (truncate(fota_linux_get_update_storage_file_name(), addr + size)) {
           FOTA_TRACE_ERROR("truncate to new size failed : addr %ld, size %ld file size %ld", addr, size, file_size);
           return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
        ret = fota_bd_erase(file_size, delta);
        if (ret) {
            FOTA_TRACE_ERROR("Erase storage failed %d", ret);
            return FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
    }

    FILE *bd_backend = get_bd_backend();

    if (fseek(bd_backend, addr, SEEK_SET)) {
        FOTA_TRACE_ERROR("fseek failed: %s", strerror(errno));
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        goto end;
    }

    bytes_written = fwrite(buffer, 1, size, bd_backend);
    if (bytes_written != size) {
        FOTA_TRACE_ERROR("fwrite failed: %s", strerror(errno));
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        goto end;
    }

    ret = FOTA_STATUS_SUCCESS;

end:
    fclose(bd_backend);
    return ret;
}

int fota_bd_erase(size_t addr, size_t size)
{
    int ret;
    size_t erase_size;
    uint8_t erase_buff[BD_ERASE_BUFFER_SIZE];

    if (addr + size > MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE) {
        FOTA_TRACE_ERROR("Erase failed: addr %ld, size %ld storage size %ld", addr, size, MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE);
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    size_t file_size = get_bd_backend_file_size();

    if (addr >= file_size) {
        size += addr - file_size;
        addr = file_size;
    }

    FILE *bd_backend = get_bd_backend();

    if (fseek(bd_backend, addr, SEEK_SET)) {
        FOTA_TRACE_ERROR("fseek failed: %s", strerror(errno));
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        goto end;
    }

    memset(erase_buff, BD_ERASE_VALUE, sizeof(erase_buff));
    erase_size = size;
    while (erase_size) {
        size_t size_to_write = MIN(sizeof(erase_buff), erase_size);
        size_t bytes_written = fwrite(erase_buff, 1, size_to_write, bd_backend);
        if (bytes_written != size_to_write) {
            FOTA_TRACE_ERROR("fwrite failed: %s", strerror(errno));
            FOTA_TRACE_ERROR("Write failed BlockDevice - file %s", fota_linux_get_update_storage_file_name());
            ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
            goto end;
        }
        erase_size -= size_to_write;
    }

    ret = FOTA_STATUS_SUCCESS;

end:
    fclose(bd_backend);
    return ret;
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

size_t fota_bd_physical_addr_to_logical_addr(size_t phys_addr)
{
    return phys_addr;
}

#endif // (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE != FOTA_EXTERNAL_BD)
#endif // defined(TARGET_LIKE_LINUX)
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
