/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



// ----------------------------------------------------------- Includes -----------------------------------------------------------

#include "sotp.h"

#if (SYS_CONF_SOTP==SYS_CONF_SOTP_LIMITED)

#include "esfs.h"
#include "pal.h"
#include <string.h>
#include <stdio.h>
#include "sotp_int.h"

#define FILE_NAME_BASE "sotp_type_"
#define FILE_NAME_SIZE (sizeof(FILE_NAME_BASE)+4)

STATIC bool init_done = false;

static const sotp_type_e otp_types[] = {SOTP_TYPE_TRUSTED_TIME_SRV_ID};

// --------------------------------------------------------- Definitions ----------------------------------------------------------


// -------------------------------------------------- Local Functions Declaration ----------------------------------------------------

// -------------------------------------------------- Functions Implementation ----------------------------------------------------

// Start of API functions

bool sotp_is_otp_type(uint32_t type)
{
    unsigned int i;
    for (i = 0; i < sizeof(otp_types) / sizeof(sotp_type_e); i++) {
        if (otp_types[i] == type) {
            return true;
        }
    }
    return false;
}

sotp_result_e sotp_get(uint32_t type, uint16_t buf_len_bytes, uint32_t *buf, uint16_t *actual_len_bytes)
{
    esfs_file_t handle;
    uint16_t mode;
    char file_name[FILE_NAME_SIZE];
    esfs_result_e esfs_ret;
    size_t act_size;
    sotp_result_e ret;

    if (!init_done) {
        ret = sotp_init();
        if (ret != SOTP_SUCCESS)
            return ret;
    }

    if (type > SOTP_MAX_TYPES) {
        return SOTP_BAD_VALUE;
    }

    memset(&handle, 0, sizeof(handle));
    sprintf(file_name, "%s%ld", FILE_NAME_BASE, type);

    esfs_ret = esfs_open((uint8_t *)file_name, strlen(file_name), &mode, &handle);
    if (esfs_ret == ESFS_NOT_EXISTS) {
        return SOTP_NOT_FOUND;
    }
    else if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    if (!buf) {
        buf_len_bytes = 0;
    }

    esfs_ret = esfs_file_size(&handle, &act_size);
    *actual_len_bytes = (uint16_t) act_size;
    if (esfs_ret != ESFS_SUCCESS) {
        esfs_close(&handle);
        return SOTP_READ_ERROR;
    }

    if (*actual_len_bytes > buf_len_bytes) {
        esfs_close(&handle);
        return SOTP_BUFF_TOO_SMALL;
    }

    if (*actual_len_bytes) {
        esfs_ret = esfs_read(&handle, buf, buf_len_bytes, &act_size);
        if (esfs_ret != ESFS_SUCCESS) {
            esfs_close(&handle);
            return SOTP_READ_ERROR;
        }
    }

    esfs_ret = esfs_close(&handle);
    if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    return SOTP_SUCCESS;
}

sotp_result_e sotp_get_item_size(uint32_t type, uint16_t *actual_len_bytes)
{
    esfs_file_t handle;
    uint16_t mode;
    char file_name[FILE_NAME_SIZE];
    esfs_result_e esfs_ret;
    size_t size_bytes;
    sotp_result_e ret;

    if (!init_done) {
        ret = sotp_init();
        if (ret != SOTP_SUCCESS)
            return ret;
    }

    if (type > SOTP_MAX_TYPES) {
        return SOTP_BAD_VALUE;
    }

    memset(&handle, 0, sizeof(handle));
    sprintf(file_name, "%s%ld", FILE_NAME_BASE, type);

    esfs_ret = esfs_open((uint8_t *)file_name, strlen(file_name), &mode, &handle);
    if (esfs_ret == ESFS_NOT_EXISTS) {
        return SOTP_NOT_FOUND;
    }
    if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    esfs_ret = esfs_file_size(&handle, &size_bytes);
    if (esfs_ret != ESFS_SUCCESS) {
        esfs_close(&handle);
        return SOTP_READ_ERROR;
    }

    esfs_ret = esfs_close(&handle);
    if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    *actual_len_bytes = (uint16_t) size_bytes;
    return SOTP_SUCCESS;
}

sotp_result_e sotp_set(uint32_t type, uint16_t buf_len_bytes, const uint32_t *buf)
{
    esfs_file_t handle;
    uint16_t mode;
    char file_name[FILE_NAME_SIZE];
    esfs_result_e esfs_ret;
    sotp_result_e ret;

    if (!init_done) {
        ret = sotp_init();
        if (ret != SOTP_SUCCESS)
            return ret;
    }

    if (type > SOTP_MAX_TYPES) {
        return SOTP_BAD_VALUE;
    }

    // Only perform actual setting of values on OTP types. Return success for the rest without
    // doing anything.
    if (!sotp_is_otp_type(type)) {
        return SOTP_SUCCESS;
    }

    memset(&handle, 0, sizeof(handle));
    sprintf(file_name, "%s%ld", FILE_NAME_BASE, type);

    esfs_ret = esfs_open((uint8_t *)file_name, strlen(file_name), &mode, &handle);
    if (esfs_ret == ESFS_SUCCESS) {
        esfs_close(&handle);
        return SOTP_ALREADY_EXISTS;
    }
    if (esfs_ret != ESFS_NOT_EXISTS) {
        return SOTP_OS_ERROR;
    }

    esfs_ret = esfs_create((uint8_t *)file_name, strlen(file_name), NULL, 0, ESFS_FACTORY_VAL, &handle);
    if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    if (buf && buf_len_bytes) {
        esfs_ret = esfs_write(&handle, buf, buf_len_bytes);
        if (esfs_ret != ESFS_SUCCESS) {
            esfs_close(&handle);
            return SOTP_WRITE_ERROR;
        }
    }

    esfs_ret = esfs_close(&handle);
    if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    return SOTP_SUCCESS;
}

#ifdef RBP_TESTING

sotp_result_e sotp_set_for_testing(uint32_t type, uint16_t buf_len_bytes, const uint32_t *buf)
{
    char file_name[FILE_NAME_SIZE];
    esfs_result_e esfs_ret;
    sotp_result_e ret;

    if (!init_done) {
        ret = sotp_init();
        if (ret != SOTP_SUCCESS)
            return ret;
    }

    sprintf(file_name, "%s%ld", FILE_NAME_BASE, type);
    esfs_ret = esfs_delete((uint8_t *)file_name, strlen(file_name));
    if ((esfs_ret != ESFS_NOT_EXISTS) && (esfs_ret != ESFS_SUCCESS)) {
        return SOTP_OS_ERROR;
    }
    return sotp_set(type, buf_len_bytes, buf);
}

sotp_result_e sotp_delete(uint32_t type)
{
    char file_name[FILE_NAME_SIZE];
    esfs_result_e esfs_ret;
    sotp_result_e ret;

    if (!init_done) {
        ret = sotp_init();
        if (ret != SOTP_SUCCESS)
            return ret;
    }

    sprintf(file_name, "%s%ld", FILE_NAME_BASE, type);
    esfs_ret = esfs_delete((uint8_t *)file_name, strlen(file_name));
    if (esfs_ret == ESFS_SUCCESS)
        return SOTP_SUCCESS;

    if (esfs_ret == ESFS_NOT_EXISTS)
        return SOTP_NOT_FOUND;

    return SOTP_OS_ERROR;
}

#endif

sotp_result_e sotp_init(void)
{
    esfs_result_e esfs_ret;

    if (init_done)
        return SOTP_SUCCESS;

    esfs_ret = esfs_init();
    if (esfs_ret != ESFS_SUCCESS) {
        return SOTP_OS_ERROR;
    }

    return SOTP_SUCCESS;
}

sotp_result_e sotp_deinit(void)
{
    return SOTP_SUCCESS;
}

sotp_result_e sotp_reset(void)
{
    char file_name[FILE_NAME_SIZE];
    esfs_result_e esfs_ret;
    uint32_t type;
    sotp_result_e ret;

    if (!init_done) {
        ret = sotp_init();
        if (ret != SOTP_SUCCESS)
            return ret;
    }

    for (type = 0; type < SOTP_MAX_TYPES; type++) {
        sprintf(file_name, "%s%ld", FILE_NAME_BASE, type);

        esfs_ret = esfs_delete((uint8_t *)file_name, strlen(file_name));
        if ((esfs_ret != ESFS_NOT_EXISTS) && (esfs_ret != ESFS_SUCCESS)) {
            return SOTP_OS_ERROR;
        }
    }

    return SOTP_SUCCESS;
}

#ifdef RBP_TESTING

sotp_result_e sotp_force_garbage_collection(void)
{
    return SOTP_SUCCESS;
}

#endif

#endif
