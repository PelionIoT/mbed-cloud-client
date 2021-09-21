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
#include <stdlib.h>
#include <string.h>

#define TRACE_GROUP "PAL"

#if (PAL_USE_INTERNAL_FLASH)

#define BITS_ALIGNED_TO_32  0x3

//////////////////////////GLOBALS SECTION ////////////////////////////
#if PAL_THREAD_SAFETY
// Use semaphore and not mutex, as mutexes don't behave well when trying to delete them while taken (which may happen in our tests).
static palSemaphoreID_t flashSem = 0;
#endif

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


// Program to Flash with alignments to page size
// Parameters :
// @param[in]   buffer - pointer to the buffer to be written
// @param[in]   size - the size of the buffer in bytes.
// @param[in]   address - the address of the internal flash, must be aligned to minimum writing unit (page size).
// Return     : None.
PAL_PRIVATE palStatus_t pal_programToFlashAligned(const size_t size, const uint32_t address, const uint32_t * buffer)
{
    palStatus_t ret = PAL_SUCCESS;
    uint32_t pageSize = 0, alignmentLeft = 0;

    pageSize = pal_internalFlashGetPageSize();
    alignmentLeft = size % pageSize; //Keep the leftover to be copied separately

    if (size >= pageSize)
    {
        ret = pal_plat_internalFlashWrite(size - alignmentLeft, address, buffer);
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
            ret = pal_plat_internalFlashWrite(pageSize, address + (size - alignmentLeft), pageBuffer);
            free(pageBuffer);
        }
    }
    return ret;
}


//////////////////////////END PRIVATE SECTION////////////////////////////


size_t pal_internalFlashGetPageSize(void)
{

    size_t ret = pal_plat_internalFlashGetPageSize();


    return ret;
}

size_t pal_internalFlashGetSectorSize(uint32_t address)
{
    size_t ret = pal_plat_internalFlashGetSectorSize(address);
    return ret;
}

palStatus_t pal_internalFlashInit(void)
{
    palStatus_t ret = PAL_SUCCESS;

#if PAL_THREAD_SAFETY
    ret = pal_osSemaphoreCreate(1, &flashSem);
    if (PAL_SUCCESS != ret)
    {
        PAL_LOG_ERR("Semaphore Create Error %" PRId32 ".", ret);
    }
    else
#endif
    {

#if PAL_THREAD_SAFETY
        ret = pal_osSemaphoreWait(flashSem, PAL_RTOS_WAIT_FOREVER, NULL);
        if (PAL_SUCCESS == ret)
#endif
        {
            ret = pal_plat_internalFlashInit();

#if PAL_THREAD_SAFETY
            palStatus_t error = pal_osSemaphoreRelease(flashSem);
            if (PAL_SUCCESS != error)
            {
                PAL_LOG_ERR("SemaphoreRelease Error %" PRId32 ".", error);
            }
#endif
        }

        if (PAL_SUCCESS != ret)
        {//Clean resources, including the flash semaphore
            pal_internalFlashDeInit();
        }
    }

    return ret;
}


palStatus_t pal_internalFlashDeInit(void)
{
    palStatus_t ret = PAL_SUCCESS;

#if PAL_THREAD_SAFETY
    ret = pal_osSemaphoreWait(flashSem, PAL_RTOS_WAIT_FOREVER, NULL);
    if (PAL_SUCCESS != ret)
    {
        return ret;
    }
#endif
    if (PAL_SUCCESS == ret)
    {
        ret = pal_plat_internalFlashDeInit();
        if (PAL_SUCCESS != ret) {
            PAL_LOG_ERR("pal_plat_internalFlashDeInit Error %" PRId32 ".", ret);
        }

#if PAL_THREAD_SAFETY
        ret = pal_osSemaphoreRelease(flashSem);
        if (PAL_SUCCESS != ret) {
            PAL_LOG_ERR("SemaphoreRelease Error %" PRId32 ".", ret);
        }
        ret = pal_osSemaphoreDelete(&flashSem);
        if (PAL_SUCCESS != ret) {
            PAL_LOG_ERR("pal_osSemaphoreDelete Error %" PRId32 ".", ret);
        }
#endif
    }
    return ret;
}

palStatus_t pal_internalFlashRead(const size_t size, const uint32_t address, uint32_t * buffer)
{
    palStatus_t ret = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR ((buffer == NULL), PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED)
    PAL_VALIDATE_CONDITION_WITH_ERROR ((size == 0),PAL_ERR_INTERNAL_FLASH_WRONG_SIZE)

#if PAL_THREAD_SAFETY
    ret = pal_osSemaphoreWait(flashSem, PAL_RTOS_WAIT_FOREVER, NULL);
    if (PAL_SUCCESS != ret)
    {
        return ret;
    }
#endif

    ret = pal_plat_internalFlashRead(size, address, buffer);

#if PAL_THREAD_SAFETY
    palStatus_t error = pal_osSemaphoreRelease(flashSem);
    if (PAL_SUCCESS != error)
    {
        PAL_LOG_ERR("SemaphoreRelease Error %" PRId32 ".", error);
    }
#endif

    return ret;
}


palStatus_t pal_internalFlashErase(uint32_t address, size_t size)
{
    palStatus_t ret = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR ((size == 0),PAL_ERR_INTERNAL_FLASH_WRONG_SIZE)
    PAL_VALIDATE_ARG_RLZ ((address & BITS_ALIGNED_TO_32),PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED)//Address not aligned to 32 bit
    PAL_VALIDATE_ARG_RLZ ((!pal_isAlignedToSector(address,size)),PAL_ERR_INTERNAL_FLASH_SECTOR_NOT_ALIGNED)//not aligned to sector

#if PAL_THREAD_SAFETY
    ret = pal_osSemaphoreWait(flashSem, PAL_RTOS_WAIT_FOREVER, NULL);
    if (PAL_SUCCESS != ret)
    {
        return ret;
    }
#endif

    size_t sectorSize = 0;
    sectorSize = pal_internalFlashGetSectorSize(address);
    while (size)
    {
        ret = pal_plat_internalFlashErase(address, sectorSize);
        size -= sectorSize;
        address += pal_internalFlashGetSectorSize(address + sectorSize);
        sectorSize = pal_internalFlashGetSectorSize(address);
    }

#if PAL_THREAD_SAFETY
    palStatus_t error = pal_osSemaphoreRelease(flashSem);
    if (PAL_SUCCESS != error)
    {
        PAL_LOG_ERR("SemaphoreRelease Error %" PRId32 ".", error);
    }
#endif
    return ret;
}


palStatus_t pal_internalFlashWrite(const size_t size, const uint32_t address, const uint32_t * buffer)
{
    palStatus_t ret = PAL_SUCCESS;
    uint32_t pageSize = 0;

    PAL_VALIDATE_CONDITION_WITH_ERROR ((buffer == NULL), PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED)
    PAL_VALIDATE_ARG_RLZ ((address & BITS_ALIGNED_TO_32),PAL_ERR_INTERNAL_FLASH_BUFFER_ADDRESS_NOT_ALIGNED)//Address not aligned to 32 bit
    PAL_VALIDATE_ARG_RLZ ((size == 0),PAL_ERR_INTERNAL_FLASH_WRONG_SIZE)

    pageSize = pal_internalFlashGetPageSize();
    if (address % pageSize)
    {
        ret =  PAL_ERR_INTERNAL_FLASH_ADDRESS_NOT_ALIGNED;
    }
    else
    {
#if PAL_THREAD_SAFETY
        ret = pal_osSemaphoreWait(flashSem, PAL_RTOS_WAIT_FOREVER, NULL);
        if (PAL_SUCCESS != ret)
        {
            return ret;
        }
#endif
        size_t sizeLeft = size;
        uint32_t tempAddress = address;
        uint32_t sectorSize = pal_internalFlashGetSectorSize(address);

        //This section handles writing on cross sectors
        while (((tempAddress % sectorSize) + sizeLeft) > sectorSize)
        {
            size_t tmpSize = sectorSize - (tempAddress % sectorSize);
            ret = pal_programToFlashAligned(tmpSize, tempAddress, buffer); //Fill the sector to the end
            if (PAL_SUCCESS != ret)
            {
                break;
            }
            sizeLeft -= tmpSize;
            tempAddress += tmpSize;
            buffer += tmpSize / sizeof(uint32_t);
            //Read sector size again because Sector size can change when crossing sectors.
            sectorSize = pal_internalFlashGetSectorSize(address);
        }

        //Write part of a sector (remainder of the buffer)
        if ((PAL_SUCCESS == ret) && (sizeLeft > 0))
        {
            ret = pal_programToFlashAligned(sizeLeft, tempAddress, buffer);
        }
#if PAL_THREAD_SAFETY
        palStatus_t error = pal_osSemaphoreRelease(flashSem);
        if (PAL_SUCCESS != error)
        {
            PAL_LOG_ERR("SemaphoreRelease Error %" PRId32 ".", error);
        }
#endif

    }
    return ret;
}


palStatus_t pal_internalFlashGetAreaInfo(uint8_t section, palSotpAreaData_t *data)
{
    palStatus_t ret = PAL_SUCCESS;
    const palSotpAreaData_t internalFlashArea[] =
    {
        {PAL_INTERNAL_FLASH_SECTION_1_ADDRESS, PAL_INTERNAL_FLASH_SECTION_1_SIZE},
        {PAL_INTERNAL_FLASH_SECTION_2_ADDRESS, PAL_INTERNAL_FLASH_SECTION_2_SIZE}
    };

    PAL_VALIDATE_CONDITION_WITH_ERROR ((data == NULL), PAL_ERR_INTERNAL_FLASH_NULL_PTR_RECEIVED)

    data->address = internalFlashArea[section].address;
    data->size = internalFlashArea[section].size;
    return ret;
}

#endif //(PAL_USE_INTERNAL_FLASH)
