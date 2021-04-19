/* Copyright (c) 2021 Pelion IoT
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
 */

#include "FlashIAP.h"

#include "FlashMap.h"

/*******************************************************************************
 * Implementation
 ******************************************************************************/

namespace mbed {

#if FLASH_AREA_LABEL_EXISTS(pelion_storage)
static pelion::FlashMap flash(FLASH_AREA_ID(pelion_storage));
#elif FLASH_AREA_LABEL_EXISTS(storage) && !defined(CONFIG_SETTINGS)
/* Only use default storage area if not already in use. */
static pelion::FlashMap flash(FLASH_AREA_ID(storage));
#else
#error "Missing pelion_storage partition for storing credentials and settings"
#endif

int FlashIAP::init()
{
    return flash.init();
}

int FlashIAP::deinit()
{
    return flash.deinit();
}

int FlashIAP::read(void *buffer, uint32_t address, uint32_t size)
{
    return flash.read(buffer, address, size);
}

int FlashIAP::program(const void *buffer, uint32_t address, uint32_t size)
{
    return flash.program(buffer, address, size);
}

int FlashIAP::erase(uint32_t address, uint32_t size)
{
    return flash.erase(address, size);
}

uint32_t FlashIAP::get_page_size() const
{
    return flash.get_page_size();
}

uint32_t FlashIAP::get_sector_size(uint32_t address) const
{
    return flash.get_sector_size(address);
}

uint32_t FlashIAP::get_flash_start() const
{
    return flash.get_flash_start();
}

uint32_t FlashIAP::get_flash_size() const
{
    return flash.get_flash_size();
}

uint8_t FlashIAP::get_erase_value() const
{
    return flash.get_erase_value();
}

}
