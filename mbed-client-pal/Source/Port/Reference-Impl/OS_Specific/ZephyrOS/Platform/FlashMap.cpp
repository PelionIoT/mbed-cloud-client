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

#include "FlashMap.h"

#include <drivers/flash.h>

#define __STDC_LIMIT_MACROS 1
#include <stdint.h>

#if 0
#include <logging/log.h>
LOG_MODULE_REGISTER(pelion);
#define DEBUG_PRINT(...) LOG_INF(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

/*******************************************************************************
 * Implementation
 ******************************************************************************/

namespace pelion {

FlashMap::FlashMap(int id)
    : _area(NULL), _flash_size(0), _page_size(0), _erase_value(0xF0)
{
    int status = flash_area_open(id, &_area);

    if ((status == 0) && _area) {

        /* Store flash dimensions in object variables for easy retrieval. */
        _flash_size = _area->fa_size;

        /* get underlying flash device */
        const struct device *flash_dev = flash_area_get_device(_area);

        if (flash_dev) {

            /* get flash parameters */
            const struct flash_parameters *params = flash_get_parameters(flash_dev);

            _page_size = params->write_block_size;
            _erase_value = params->erase_value;
        }
    }
}

FlashMap::~FlashMap()
{
    flash_area_close(_area);
}

int FlashMap::init()
{
    return (_area) ? 0 : -ENODEV;
}

int FlashMap::deinit()
{
    return 0;
}

int FlashMap::read(void *buffer, uint32_t address, uint32_t size)
{
    DEBUG_PRINT("FlashMap::read: %" PRIX32 " %" PRIX32 "\r\n", address, size);

    int result = -ENODEV;

    if (_area) {
        result = flash_area_read(_area, (off_t) address, buffer, size);
    }

    return result;
}

int FlashMap::program(const void *buffer, uint32_t address, uint32_t size)
{
    DEBUG_PRINT("FlashMap::program: %" PRIX32 " %" PRIX32 "\r\n", address, size);

    int result = -ENODEV;

    if (_area) {
        result = flash_area_write(_area, (off_t) address, buffer, size);
    }

    return result;
}

int FlashMap::erase(uint32_t address, uint32_t size)
{
    DEBUG_PRINT("FlashMap::erase: %" PRIX32 " %" PRIX32 "\r\n", address, size);

    int result = -ENODEV;

    if (_area) {
        result = flash_area_erase(_area, (off_t) address, size);
    }

    return result;
}

uint32_t FlashMap::get_sector_size(uint32_t address) const
{
    uint32_t sector_size = UINT32_MAX;

    if (_area) {

        /* Get underlying flash device for flash area */
        const struct device *flash_dev = flash_area_get_device(_area);

        if (flash_dev) {

            /* Get page information at specified address.
             * Note that Zephyr uses "page" to mean both "erase page size" and "write page size"
             * while Pelion uses "erase sector size" and "write page size".
             */
            struct flash_pages_info info = { 0 };

            int status = flash_get_page_info_by_offs(flash_dev, (off_t) address, &info);

            if (status == 0) {

                DEBUG_PRINT("sector: %ld %u %u\r\n", info.start_offset, info.size, info.index);

                sector_size = info.size;
            }
        }
    }

    return sector_size;
}

uint32_t FlashMap::get_flash_start() const
{
    /* Each flash area is treated as it's own device with start address 0. */
    return 0;
}

uint32_t FlashMap::get_flash_size() const
{
    return _flash_size;
}

uint32_t FlashMap::get_page_size() const
{
    return _page_size;
}

uint8_t FlashMap::get_erase_value() const
{
    return _erase_value;
}

}
