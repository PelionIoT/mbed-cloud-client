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
#include "fsl_flash.h"

////////////////////////////PRIVATE///////////////////////////////////
PAL_PRIVATE flash_config_t g_flashDescriptor = {0};
////////////////////////////END PRIVATE////////////////////////////////

palStatus_t pal_plat_internalFlashInit(void)
{
    status_t status;
    palStatus_t ret = PAL_SUCCESS;
    status = FLASH_Init(&g_flashDescriptor);
    if(kStatus_FLASH_Success != status)
    {
        ret = PAL_ERR_INTERNAL_FLASH_INIT_ERROR;
    }
	return ret;
}


palStatus_t pal_plat_internalFlashDeInit(void)
{
    memset(&g_flashDescriptor, 0, sizeof(g_flashDescriptor));
	return PAL_SUCCESS;
}


palStatus_t pal_plat_internalFlashWrite(const size_t size, const uint32_t address, const uint32_t * buffer)
{
    palStatus_t ret = PAL_SUCCESS;
    status_t status = kStatus_Success;

	/* We need to prevent flash accesses during program operation */
	__disable_irq();
	status = FLASH_Program(&g_flashDescriptor, address, (uint32_t *)buffer, size);
	if (kStatus_Success == status)
	{
		// Must use kFlashMargin_User, or kFlashMargin_Factory for verify program
		status = FLASH_VerifyProgram(&g_flashDescriptor, address, size, (uint32_t *)buffer, kFLASH_marginValueUser, NULL, NULL);
		if(kStatus_Success != status)
		{
			ret = PAL_ERR_INTERNAL_FLASH_WRITE_ERROR;
		}
	}
	__enable_irq();

    return ret;
}

palStatus_t pal_plat_internalFlashRead(const size_t size, const uint32_t address, uint32_t * buffer)
{
    memcpy(buffer, (const void *)address, size);
    return PAL_SUCCESS;
}


palStatus_t pal_plat_internalFlashErase(uint32_t address, size_t size)
{
    palStatus_t ret = PAL_SUCCESS;
    int16_t  status = kStatus_Success;

    __disable_irq();
    status = FLASH_Erase(&g_flashDescriptor, address, pal_plat_internalFlashGetSectorSize(address), kFLASH_apiEraseKey);
    if (kStatus_Success == status)
    {
        status = FLASH_VerifyErase(&g_flashDescriptor, address, pal_plat_internalFlashGetSectorSize(address), kFLASH_marginValueNormal);
    }

    if (kStatus_Success != status)
    {
        ret = PAL_ERR_INTERNAL_FLASH_ERASE_ERROR;
    }
    __enable_irq();
    return ret;
}


size_t pal_plat_internalFlashGetPageSize(void)
{
	return FSL_FEATURE_FLASH_PFLASH_BLOCK_WRITE_UNIT_SIZE;
}


size_t pal_plat_internalFlashGetSectorSize(uint32_t address)
{
    size_t devicesize = 0;
    FLASH_GetProperty(&g_flashDescriptor, kFLASH_propertyPflashSectorSize, (uint32_t*)&devicesize);
    return devicesize;
}

