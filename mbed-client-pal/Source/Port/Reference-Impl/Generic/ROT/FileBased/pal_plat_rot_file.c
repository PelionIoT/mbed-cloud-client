/*******************************************************************************
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
#include "pal.h"

#if (PAL_USE_ROT_FROM_FILE == 1)
#include <stdio.h>
#include "pal_plat_rot.h"
#include "storage_kcm.h"
#ifdef _WIN32
#include "pal_plat_fileSystem.h"
#endif

#define TRACE_GROUP "ROTF"

#define MAX_ROT_FILE_PATH_LEN 4096

palStatus_t pal_plat_osGetRoT(uint8_t *key, size_t keyLenBytes)
{
    size_t file_path_len = 0;
    char file_path[MAX_ROT_FILE_PATH_LEN];
    palStatus_t  pal_status = PAL_SUCCESS;

#ifdef _WIN32
    palFileDescriptor_t fp = 0;
#else
    FILE *fp;
#endif
    size_t bytes_read;

    // Read RoTFilePath from the STORAGE_RBP_ROT_FILE_PATH_NAME
    pal_status = storage_rbp_read(STORAGE_RBP_ROT_FILE_PATH_NAME, (uint8_t *)file_path, MAX_ROT_FILE_PATH_LEN, &file_path_len);
    if (pal_status != PAL_SUCCESS)
    {
        PAL_PRINTF("pal_plat_osGetRoT() - storage_rbp_read() failed to get item %s, pal_status = 0x%x", STORAGE_RBP_ROT_FILE_PATH_NAME, (unsigned int)pal_status);
        return pal_status;
    }

#ifdef _WIN32
    if (file_path_len >= sizeof(file_path)) {
        return PAL_ERR_BUFFER_TOO_SMALL;
    }
#endif
    // Ensure null termination
    file_path[file_path_len] = '\0';

    // Validate key buffer and length
    if (key == NULL || keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES) {
        PAL_PRINTF("pal_plat_osGetRoT() - key == NULL || keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES");
        return PAL_ERR_INVALID_ARGUMENT;
    }

    // Open the RoT file
#ifdef _WIN32
    /* Reuse Windows PAL's UTF-8 path conversion and binary I/O. */
    pal_status = pal_plat_fsFopen(file_path, PAL_FS_FLAG_READONLY, &fp);
    if (pal_status != PAL_SUCCESS) return pal_status;
    pal_status = pal_plat_fsFread(&fp, key, keyLenBytes, &bytes_read);
    {
        palStatus_t close_status = pal_plat_fsFclose(&fp);
        if (pal_status != PAL_SUCCESS) return pal_status;
        if (close_status != PAL_SUCCESS) return close_status;
    }
#else
    fp = fopen(file_path, "rb");
    if (fp == NULL) {
        PAL_PRINTF("pal_plat_osGetRoT() - fopen() failed");
        return PAL_ERR_GENERIC_FAILURE;
    }

    // Read the RoT key
    bytes_read = fread(key, 1, keyLenBytes, fp);
    fclose(fp);
#endif

    if (bytes_read != keyLenBytes) {
        PAL_PRINTF("pal_plat_osGetRoT() - bytes_read != keyLenBytes");
        return PAL_ERR_GENERIC_FAILURE;
    }

    return PAL_SUCCESS;
}


palStatus_t pal_plat_osSetRoT(uint8_t * key, size_t keyLenBytes)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

#endif // PAL_USE_ROT_FROM_FILE
