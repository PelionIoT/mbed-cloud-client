// ----------------------------------------------------------------------------
// Copyright 2016-2020 ARM Ltd.
// Copyright 2022 Izuma Networks
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "update-client-common/arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT) && (ARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT == 1)

#include "update-client-pal-flashiap-mcuboot/arm_uc_pal_flashiap_mcuboot_platform.h"

#if defined(__ZEPHYR__)

#include "FlashMap.h"

// use Zephyr's partitions to configure where the active and candidate firmware are
static izuma::FlashMap flash_active(FLASH_AREA_ID(image_0));
static izuma::FlashMap flash_candidate(FLASH_AREA_ID(image_1));

#define FLASH_ACTIVE_OBJ flash_active
#define FLASH_CANDIDATE_OBJ flash_candidate

#else

#include "FlashIAP.h"

// default to using same FlashIAP object and device for both active and candidate firmware
static mbed::FlashIAP flash_both;

#define FLASH_ACTIVE_OBJ flash_both
#define FLASH_CANDIDATE_OBJ flash_both

#endif

/*****************************************************************************/
/* Flash functions for active  firmware partition.                           */
/*****************************************************************************/

/** Initialize a flash IAP device
 *
 *  Should be called once per lifetime of the object.
 *  @return 0 on success or a negative error code on failure
 */
int32_t arm_uc_flashiap_active_init(void)
{
    return FLASH_ACTIVE_OBJ.init();
}

/** Read data from a flash device.
 *
 *  This method invokes memcpy - reads number of bytes from the address
 *
 *  @param buffer   Buffer to write to
 *  @param address  Flash address to begin reading from
 *  @param size     Size to read in bytes
 *  @return         0 on success, negative error code on failure
 */
int32_t arm_uc_flashiap_active_read(uint8_t *buffer,
                                    uint32_t address,
                                    uint32_t size)
{
    return FLASH_ACTIVE_OBJ.read(buffer, address, size);
}


/*****************************************************************************/
/* Flash functions for active firmware partition, used for delta updates.    */
/*****************************************************************************/

/** Initialize a flash IAP device
 *
 *  Should be called once per lifetime of the object.
 *  @return 0 on success or a negative error code on failure
 */
int32_t arm_uc_flashiap_init(void)
{
    return arm_uc_flashiap_active_init();
}

/** Read data from a flash device.
 *
 *  This method invokes memcpy - reads number of bytes from the address
 *
 *  @param buffer   Buffer to write to
 *  @param address  Flash address to begin reading from
 *  @param size     Size to read in bytes
 *  @return         0 on success, negative error code on failure
 */
int32_t arm_uc_flashiap_read(uint8_t *buffer,
                             uint32_t address,
                             uint32_t size)
{
    return arm_uc_flashiap_active_read(buffer, address, size);
}

/*****************************************************************************/
/* Flash functions for candidate firmware partition.                         */
/*****************************************************************************/

int32_t arm_uc_flashiap_candidate_init(void)
{
    return FLASH_CANDIDATE_OBJ.init();
}

int32_t arm_uc_flashiap_candidate_erase(uint32_t address, uint32_t size)
{
    return FLASH_CANDIDATE_OBJ.erase(address, size);
}

int32_t arm_uc_flashiap_candidate_program(const uint8_t *buffer, uint32_t address, uint32_t size)
{
    uint32_t page_size = FLASH_CANDIDATE_OBJ.get_page_size();
    int status = ARM_UC_FLASHIAP_FAIL;

    for (uint32_t i = 0; i < size; i += page_size) {
        status = FLASH_CANDIDATE_OBJ.program(buffer + i, address + i, page_size);
        if (status != ARM_UC_FLASHIAP_SUCCESS) {
            break;
        }
    }

    return status;
}

int32_t arm_uc_flashiap_candidate_read(uint8_t *buffer, uint32_t address, uint32_t size)
{
    return FLASH_CANDIDATE_OBJ.read(buffer, address, size);
}

uint32_t arm_uc_flashiap_candidate_get_page_size(void)
{
    return FLASH_CANDIDATE_OBJ.get_page_size();
}

uint32_t arm_uc_flashiap_candidate_get_sector_size(uint32_t address)
{
    uint32_t sector_size = FLASH_CANDIDATE_OBJ.get_sector_size(address);
    if (sector_size == ARM_UC_FLASH_INVALID_SIZE || sector_size == 0) {
        return ARM_UC_FLASH_INVALID_SIZE;
    } else {
        return sector_size;
    }
}

uint32_t arm_uc_flashiap_candidate_get_flash_size(void)
{
    return FLASH_CANDIDATE_OBJ.get_flash_size();
}

uint32_t arm_uc_flashiap_candidate_get_flash_start(void)
{
    return FLASH_CANDIDATE_OBJ.get_flash_start();
}

#endif /* ARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT */
