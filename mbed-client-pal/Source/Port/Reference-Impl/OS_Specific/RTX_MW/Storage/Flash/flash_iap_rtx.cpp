/* mbed Microcontroller Library
 * Copyright (c) 2020 ARM Limited
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "FlashIAP.h"
#include "Driver_Flash.h"

/* Flash driver instance */
extern ARM_DRIVER_FLASH Driver_FLASH0;
static ARM_DRIVER_FLASH *flashDev = &Driver_FLASH0;

namespace mbed {

int FlashIAP::init()
{        
    flashDev->Initialize(NULL);
    flashDev->PowerControl(ARM_POWER_FULL);

    return 0;
}

int FlashIAP::deinit()
{
    return flashDev->Uninitialize();
}

int FlashIAP::read(void *buffer, uint32_t addr, uint32_t size)
{
    return flashDev->ReadData(addr, buffer, size);
}

int FlashIAP::program(const void *buffer, uint32_t addr, uint32_t size)
{    
    return flashDev->ProgramData(addr, buffer, size);
}

bool FlashIAP::is_aligned_to_sector(uint32_t addr, uint32_t size)
{
    return true;
}

int FlashIAP::erase(uint32_t addr, uint32_t size)
{    
    return flashDev->EraseSector(addr);    
}

uint32_t FlashIAP::get_page_size() const
{
    ARM_FLASH_INFO* info = flashDev->GetInfo(); 
    return info->page_size;
}

uint32_t FlashIAP::get_sector_size(uint32_t addr) const
{    
    ARM_FLASH_INFO* info = flashDev->GetInfo();
    return info->sector_size;
}

uint32_t FlashIAP::get_flash_start() const
{    
    ARM_FLASH_INFO* info = flashDev->GetInfo();    
    return info->sector_info->start;
}

uint32_t FlashIAP::get_flash_size() const
{       
    ARM_FLASH_INFO* info = flashDev->GetInfo(); 
    return info->sector_count * info->sector_size;    
}

uint8_t FlashIAP::get_erase_value() const
{
    ARM_FLASH_INFO* info = flashDev->GetInfo(); 
    return info->erased_value;
}

}
