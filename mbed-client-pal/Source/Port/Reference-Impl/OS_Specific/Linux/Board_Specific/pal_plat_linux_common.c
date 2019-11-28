/*******************************************************************************
 * Copyright 2016-2019 ARM Ltd.
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

#include "pal_plat_rtos.h"
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#define TRACE_GROUP "PAL"

PAL_PRIVATE bool getFileNameFromSystemEnv(char *fileNameOut, size_t fileNameMaxLength)
{
    const char *file_name_from_env = getenv("ENTROPYSOURCE");

    if ((file_name_from_env != NULL) && (strnlen(file_name_from_env, fileNameMaxLength) > 0)) {

        // Note: although we succeeded reading from system environment (ENTROPYSOURCE=<some file name>) that doesn't mean
        // we able to read from the target file, in some cases it may be corrupted or not exist on the target machine,
        // if this is the case use the default `entropyFileName` instead as supplied by the calling function
        if (access(file_name_from_env, F_OK) == 0) {
            PAL_LOG_INFO("Fetching entropy source file from System Environment since ENTROPYSOURCE is set");
            strncpy(fileNameOut, file_name_from_env, fileNameMaxLength);
            return true; // success
        }
    }

    return false; // failed to read from system environment
}

palStatus_t pal_plat_osEntropyRead(const char *entropyFileName, uint8_t *randomBufOut, size_t bufSizeBytes, size_t *actualRandomSizeBytesOut)
{
    palStatus_t status = PAL_SUCCESS;
    FILE *fp;
    size_t actualRead = 0;
    const char *entropySourceFileName = entropyFileName; // set as default
    char fileNameSysEnv[256]; // file name should not exceed 255 chars
    bool success = getFileNameFromSystemEnv(fileNameSysEnv, sizeof(fileNameSysEnv));
    if (success) {
        entropySourceFileName = fileNameSysEnv;
    }

    // Random generation can be really slow, entropy collection on a freshly booted device
    // can take up to 10-20 minutes! Installing RNG-tools can speed things up.

    printf("Generating random from %s, this can take a long time!\n", entropySourceFileName);

    fp = fopen(entropySourceFileName, "r");
    if (NULL != fp) {
        actualRead = fread(randomBufOut, 1, bufSizeBytes, fp);
        if (0 == actualRead) {
            status = PAL_ERR_RTOS_TRNG_FAILED;
        } else if (actualRead != bufSizeBytes) {
            status = PAL_ERR_RTOS_TRNG_PARTIAL_DATA;
        }
        fclose(fp);
    } else {
        status = PAL_ERR_FS_NO_FILE;
    }

    if (NULL != actualRandomSizeBytesOut) {
        *actualRandomSizeBytesOut = actualRead;
    }
    return status;
}
