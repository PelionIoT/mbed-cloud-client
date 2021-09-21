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
#include "pal.h"
#include "pal_plat_internalFlash.h"

#if (PAL_USE_INTERNAL_FLASH)

#if PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM

#include <stdio.h> // for snprintf
#include <stdlib.h>
#include <string.h>

#define TRACE_GROUP "PAL"

#define BITS_ALIGNED_TO_32  0x3

#ifndef PAL_SIMULATOR_FLASH_FACTORY_MODE
#warning PAL_SIMULATOR_FLASH_FACTORY_MODE is not defined. \
         Set PAL_SIMULATOR_FLASH_FACTORY_MODE = 1 during factory provisioning, allowing file creation. \
         Set PAL_SIMULATOR_FLASH_FACTORY_MODE = 0 when deployed to prevent data corruption. \
         Current default is 1 for backwards compatibility but will change to 0 in the future.

#define PAL_SIMULATOR_FLASH_FACTORY_MODE 1
#endif

PAL_PRIVATE palFileDescriptor_t g_fd = 0;

//////////////////////////END GLOBALS SECTION ////////////////////////////


//////////////////////////START PRIVATE SECTION////////////////////////////
// Verify that the alignment  to sector size
// Parameters :
// @param[in] address     - Address to verify.
// @param[in] size        - Size to write
// Return     : None.
PAL_PRIVATE bool pal_isAlignedToSector(uint32_t address, size_t size)
{
    uint32_t currentSectorSize = pal_internalFlashGetSectorSize(address);
    if ((size % currentSectorSize) || (address % currentSectorSize))
    {
        return false;
    }
    else
    {
        return true;
    }
}


// Get path of the simulated flash file
// Parameters :
// @param[out] path        - output buffer
// Return     : PAL_SUCCESS if the combined mount point and flash directory are under the maximum path limit
PAL_PRIVATE palStatus_t pal_getFlashSimulationFilePath(char* path)
{
    char root[PAL_MAX_FILE_AND_FOLDER_LENGTH];

    palStatus_t status = PAL_SUCCESS;

    status = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, root);
    if (PAL_SUCCESS == status)
    {
        size_t written;
        if (SIMULATE_FLASH_DIR[0] != 0)
        {
            written = snprintf(path, PAL_MAX_FILE_AND_FOLDER_LENGTH, "%s/%s", root, SIMULATE_FLASH_DIR);
        }
        else {
            written = snprintf(path, PAL_MAX_FILE_AND_FOLDER_LENGTH, "%s", root);
        }

        // verify, if the mount point and SIMULATE_FLASH_DIR fit to the hard coded maximum.
        if (written >= PAL_MAX_FILE_AND_FOLDER_LENGTH)
        {
            status = PAL_ERR_INVALID_ARGUMENT;
        }
    }

    return status;
}

// Get path and filename of the simulated flash file
// Parameters :
// @param[out] path        - output buffer
// Return     : PAL_SUCCESS if the combined filenames are under the maximum path limit
PAL_PRIVATE palStatus_t pal_getFlashSimulationFilePathAndName(char* path)
{
    char root[PAL_MAX_FILE_AND_FOLDER_LENGTH];

    palStatus_t status = PAL_ERR_FS_INVALID_FILE_NAME;

    if (SIMULATE_FLASH_FILE_NAME[0] == '/')
    {
        status = pal_fsGetMountPoint(PAL_FS_PARTITION_SECONDARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, root);
        if (PAL_SUCCESS == status)
        {
            // the SIMULATE_FLASH_FILE_NAME is specified to contain also the SIMULATE_FLASH_DIR -directory
            // and it will begin with a '/' char, so this needs separate implementation from pal_getFlashSimulationFileDir()
            int written = snprintf(path, PAL_MAX_FILE_AND_FOLDER_LENGTH, "%s%s", root, SIMULATE_FLASH_FILE_NAME);
            if (written >= PAL_MAX_FILE_AND_FOLDER_LENGTH)
            {
                status = PAL_ERR_INVALID_ARGUMENT;
            }
        }
    }

    return status;
}

// Check whether area file exists. Create it if not.
// Parameters :
// @param[in]
// Return     : None.
// Note - If file does not exist create and fill with 0xFF this simulate erased flash
PAL_PRIVATE palStatus_t pal_verifyAndCreateFlashFile(void)
{
    uint32_t index;
    uint8_t writeBuffer[SIMULATE_FLASH_PAGE_SIZE] = {0};
    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palStatus_t ret = PAL_SUCCESS;
    size_t numOfBytes = 0;
    palSotpAreaData_t areaData_1, areaData_2;

    pal_internalFlashGetAreaInfo(0, &areaData_1);
    pal_internalFlashGetAreaInfo(1, &areaData_2);

    ret = pal_getFlashSimulationFilePathAndName(buffer);
    if (PAL_SUCCESS == ret)
    {
        ret = pal_fsFopen(buffer, PAL_FS_FLAG_READWRITEEXCLUSIVE, &g_fd);
        if (PAL_ERR_FS_NAME_ALREADY_EXIST == ret)
        {
            return PAL_SUCCESS; //file exist nothing else to do
        }
        else if (PAL_SUCCESS == ret)
        {
            memset(writeBuffer, PAL_INT_FLASH_BLANK_VAL, SIMULATE_FLASH_PAGE_SIZE);
            for (index = 0; index < (areaData_1.size + areaData_2.size) / SIMULATE_FLASH_PAGE_SIZE; index++)
            {
                ret = pal_fsFwrite(&g_fd, (void *)writeBuffer, SIMULATE_FLASH_PAGE_SIZE, &numOfBytes);
                if (PAL_SUCCESS != ret)
                {
                    break;
                }
            }
            pal_fsFclose(&g_fd);
        }
    }
    return ret;
}


//////////////////////////END PRIVATE SECTION////////////////////////////


size_t pal_plat_internalFlashGetPageSize(void)
{
    size_t ret = SIMULATE_FLASH_PAGE_SIZE;
    return ret;
}

size_t pal_plat_internalFlashGetSectorSize(uint32_t address)
{

    size_t ret = SIMULATE_FLASH_SECTOR_SIZE;
    return ret;
}

palStatus_t pal_plat_internalFlashInit(void)
{
    palStatus_t ret = PAL_SUCCESS;

    char buffer[PAL_MAX_FILE_AND_FOLDER_LENGTH];

#if (PAL_SIMULATOR_FLASH_FACTORY_MODE == 0)
    // Factory mode disabled, only check if file exists.
    ret = pal_getFlashSimulationFilePathAndName(buffer);

    if (PAL_SUCCESS == ret)
    {
        ret = pal_fsFopen(buffer, PAL_FS_FLAG_READONLY, &g_fd);
        if (PAL_SUCCESS == ret)
        {
            pal_fsFclose(&g_fd);
        }
    }

#elif (PAL_SIMULATOR_FLASH_FACTORY_MODE == 1)
    // Factory mode enabled, create file if missing.
    ret = pal_getFlashSimulationFilePath(buffer);

    if (PAL_SUCCESS == ret)
    {
        ret = pal_fsMkDir(buffer); //Create Directory
        if ((PAL_ERR_FS_NAME_ALREADY_EXIST == ret))
        {
            ret = PAL_SUCCESS;
        }

        if (PAL_SUCCESS == ret)
        {
            // Create file too, which verifies that the access rights on
            // the filesystem are correct and it has enough space for simulation
            // file.
            ret = pal_verifyAndCreateFlashFile();
        }
    }
#else
#error PAL_SIMULATOR_FLASH_FACTORY_MODE not defined
#endif

    return ret;
}


palStatus_t pal_plat_internalFlashDeInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    return ret;
}

palStatus_t pal_plat_internalFlashRead(const size_t size, const uint32_t address, uint32_t * buffer)
{
    palStatus_t ret = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR ((buffer == NULL), PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED)
    PAL_VALIDATE_CONDITION_WITH_ERROR ((size == 0),PAL_ERR_INTERNAL_FLASH_WRONG_SIZE)

    size_t numberOfBytesRead = 0;
    char fileBuffer[PAL_MAX_FILE_AND_FOLDER_LENGTH];

    ret = pal_getFlashSimulationFilePathAndName(fileBuffer);
    if (PAL_SUCCESS == ret)
    {
        // XXX: why not keep the file open all the time? There is init() & deinit()
        // to allow that. The code even uses a global file handle for the temporary
        // operations.
        ret = pal_fsFopen(fileBuffer, PAL_FS_FLAG_READONLY, &g_fd);
        if (PAL_SUCCESS == ret)
        {
            ret = pal_fsFseek(&g_fd, address, PAL_FS_OFFSET_SEEKSET);
            if (PAL_SUCCESS == ret)
            {
                ret = pal_fsFread(&g_fd, buffer, size, &numberOfBytesRead);
            }
            pal_fsFclose(&g_fd);
        }
    }

    return ret;
}


palStatus_t pal_plat_internalFlashErase(uint32_t address, size_t size)
{
    palStatus_t ret = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR ((size == 0),PAL_ERR_INTERNAL_FLASH_WRONG_SIZE)
    PAL_VALIDATE_ARG_RLZ ((address & BITS_ALIGNED_TO_32),PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED)//Address not aligned to 32 bit
    PAL_VALIDATE_ARG_RLZ ((!pal_isAlignedToSector(address,size)),PAL_ERR_INTERNAL_FLASH_SECTOR_NOT_ALIGNED)//not aligned to sector

    char fileBuffer[PAL_MAX_FILE_AND_FOLDER_LENGTH];
    size_t numOfBytes = 0, index = 0;
    uint8_t writeBuffer[SIMULATE_FLASH_PAGE_SIZE] = {0};

    ret = pal_getFlashSimulationFilePathAndName(fileBuffer);
    if (PAL_SUCCESS == ret)
    {
        ret = pal_fsFopen(fileBuffer, PAL_FS_FLAG_READWRITE, &g_fd);
        if (PAL_SUCCESS == ret)
        {
            ret = pal_fsFseek(&g_fd, address, PAL_FS_OFFSET_SEEKSET);
            if (PAL_SUCCESS == ret)
            {
                memset(writeBuffer, PAL_INT_FLASH_BLANK_VAL, SIMULATE_FLASH_PAGE_SIZE);
                for (index = 0; index < size / SIMULATE_FLASH_PAGE_SIZE; index++)
                {
                    ret = pal_fsFwrite(&g_fd, (void *)writeBuffer, SIMULATE_FLASH_PAGE_SIZE, &numOfBytes);
                    if (PAL_SUCCESS != ret)
                    {
                        break;
                    }
                }
            }
            pal_fsFclose(&g_fd);
        }
    }

    return ret;
}


palStatus_t pal_plat_internalFlashWrite(const size_t size, const uint32_t address, const uint32_t * buffer)
{
    palStatus_t ret = PAL_SUCCESS;
    uint32_t pageSize = 0;

    PAL_VALIDATE_CONDITION_WITH_ERROR ((buffer == NULL), PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED)
    PAL_VALIDATE_ARG_RLZ ((address & BITS_ALIGNED_TO_32),PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED)//Address not aligned to 32 bit
    PAL_VALIDATE_ARG_RLZ ((size == 0),PAL_ERR_INTERNAL_FLASH_WRONG_SIZE)

    pageSize = pal_plat_internalFlashGetPageSize();

    char fileBuffer[PAL_MAX_FILE_AND_FOLDER_LENGTH];
    uint32_t alignmentLeft = 0;
    size_t numOfBytes = 0;

    ret = pal_getFlashSimulationFilePathAndName(fileBuffer);
    if (PAL_SUCCESS == ret)
    {
        ret = pal_fsFopen(fileBuffer, PAL_FS_FLAG_READWRITE, &g_fd);
        if (PAL_SUCCESS == ret)
        {
            alignmentLeft = size % pageSize; //Keep the leftover to be copied separately
            if (size >= pageSize)
            {
                ret = pal_fsFseek(&g_fd, address, PAL_FS_OFFSET_SEEKSET);
                if (PAL_SUCCESS == ret)
                {
                    ret = pal_fsFwrite(&g_fd, (void *)buffer, size - alignmentLeft, &numOfBytes);
                }
            }

            if ((ret == PAL_SUCCESS) && (alignmentLeft != 0))
            {
                uint32_t * pageBuffer = (uint32_t *)malloc(pageSize);
                if (pageBuffer == NULL)
                {
                    ret = PAL_ERR_NO_MEMORY;
                }
                else
                {
                    memset(pageBuffer, 0xFF, pageSize);
                    memcpy(pageBuffer, (uint8_t*)buffer + (size - alignmentLeft), alignmentLeft);
                    ret = pal_fsFseek(&g_fd, address + (size - alignmentLeft), PAL_FS_OFFSET_SEEKSET);
                    if (PAL_SUCCESS == ret)
                    {
                        ret = pal_fsFwrite(&g_fd, (void *)pageBuffer, pageSize, &numOfBytes);
                    }
                    free(pageBuffer);
                }
            }
            pal_fsFclose(&g_fd);
        }
    }

    return ret;
}


#endif // PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM

#endif //(PAL_USE_INTERNAL_FLASH)
