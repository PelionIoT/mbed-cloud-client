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

#include "mbed.h"
#include "flash_api.h"
#include "pal.h"
#include "pal_plat_internalFlash.h"


////////////////////////////PRIVATE///////////////////////////////////
PAL_PRIVATE FlashIAP flash;
PAL_PRIVATE palStatus_t pal_platFlashErrorTranslation(int32_t status);
////////////////////////////END PRIVATE////////////////////////////////

palStatus_t pal_plat_internalFlashInit(void)
{
	uint32_t status = 0;
	palStatus_t ret = PAL_SUCCESS;
	status = flash.init();
	if (status != 0)
	{
		ret = pal_platFlashErrorTranslation(status);
	}
	return ret;
}


palStatus_t pal_plat_internalFlashDeInit(void)
{
	uint32_t status = 0;
	palStatus_t ret = PAL_SUCCESS;
	status = flash.deinit();
	if (status != 0)
	{
		ret = pal_platFlashErrorTranslation(status);
	}
	return ret;
}


palStatus_t pal_plat_internalFlashWrite(const size_t size, const uint32_t address, const uint32_t * buffer)
{
	uint32_t status = 0;
	palStatus_t ret = PAL_SUCCESS;

	status = flash.program(buffer, address, size);
	if (status != 0)
	{
		ret = pal_platFlashErrorTranslation(status);
	}
	return ret;
}


palStatus_t pal_plat_internalFlashRead(const size_t size, const uint32_t address, uint32_t * buffer)
{
	uint32_t status = 0;
	palStatus_t ret = PAL_SUCCESS;
	status = flash.read(buffer, address, size);
	if (status != 0)
	{
		ret = pal_platFlashErrorTranslation(status);
	}
	return ret;
}


palStatus_t pal_plat_internalFlashErase(uint32_t address, size_t size)
{
	uint32_t status = 0;
	palStatus_t ret = PAL_SUCCESS;

	status = flash.erase(address, size);
	if (status != 0)
	{
		ret = pal_platFlashErrorTranslation(status);
	}
	return ret;
}


size_t pal_plat_internalFlashGetPageSize(void)
{
	size_t ret = flash.get_page_size();
	return ret;
}


size_t pal_plat_internalFlashGetSectorSize(uint32_t address)
{
	size_t ret = flash.get_sector_size(address);
	return ret;
}


PAL_PRIVATE palStatus_t pal_platFlashErrorTranslation(int32_t status)
{
	return PAL_ERR_INTERNAL_FLASH_GENERIC_FAILURE;//ALL mbedOS error are -1
}

