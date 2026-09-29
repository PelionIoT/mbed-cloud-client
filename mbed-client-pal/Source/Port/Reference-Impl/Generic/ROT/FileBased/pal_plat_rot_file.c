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
#if (PAL_USE_ROT_FROM_FILE == 1)
#include <stdio.h>
#include "pal.h"
#include "pal_plat_rot.h"
#include "storage_kcm.h"

#define TRACE_GROUP "ROTF"

#define MAX_ROT_FILE_PATH_LEN 4096

palStatus_t pal_plat_osGetRoT(uint8_t *key, size_t keyLenBytes)
{
    size_t file_path_len = 0;
    char file_path[MAX_ROT_FILE_PATH_LEN];
    palStatus_t  pal_status = PAL_SUCCESS;

    FILE *fp;
    size_t bytes_read;

    // Read RoTFilePath from the STORAGE_RBP_ROT_FILE_PATH_NAME
    pal_status = storage_rbp_read(STORAGE_RBP_ROT_FILE_PATH_NAME, (uint8_t *)file_path, MAX_ROT_FILE_PATH_LEN, &file_path_len);
    if (pal_status != PAL_SUCCESS)
    {
        PAL_PRINTF("pal_plat_osGetRoT() - storage_rbp_read() failed to get item %s, pal_status = 0x%x", STORAGE_RBP_ROT_FILE_PATH_NAME, (unsigned int)pal_status);
        return pal_status;
    }

    // Ensure null termination
    file_path[file_path_len] = '\0';

    // Validate key buffer and length
    if (key == NULL || keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES) {
        PAL_PRINTF("pal_plat_osGetRoT() - key == NULL || keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES");
        return PAL_ERR_INVALID_ARGUMENT;
    }

    // Open the RoT file
    fp = fopen(file_path, "rb");
    if (fp == NULL) {
        PAL_PRINTF("pal_plat_osGetRoT() - fopen() failed");
        return PAL_ERR_GENERIC_FAILURE;
    }

    // Read the RoT key
    bytes_read = fread(key, 1, keyLenBytes, fp);
    fclose(fp);

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
