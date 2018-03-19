/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
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
#include <stdio.h> // needed to FILE operations
#include <stdlib.h>
#include <string.h>


#define TRACE_GROUP "PAL"

palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes)
{
	palStatus_t status = PAL_SUCCESS;
	FILE *fp;
	size_t actualRead = 0;

	fp = fopen("/dev/hwrng", "r");
	if (NULL != fp)
	{
		actualRead = fread(randomBuf, 1, bufSizeBytes, fp);
		if (0 == actualRead)
		{
			status = PAL_ERR_RTOS_TRNG_FAILED;
		}
		else if (actualRead != bufSizeBytes)
		{
			status = PAL_ERR_RTOS_TRNG_PARTIAL_DATA;
		}
		fclose(fp);
	}
	else
	{
		status = PAL_ERR_FS_NO_FILE;
	}

    if (NULL != actualRandomSizeBytes)
    {
        *actualRandomSizeBytes = actualRead;
    }
	return status;
}

