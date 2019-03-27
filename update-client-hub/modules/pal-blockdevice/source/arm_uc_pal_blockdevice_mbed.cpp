// ----------------------------------------------------------------------------
// Copyright 2017-2018 ARM Ltd.
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

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) && (ARM_UC_FEATURE_PAL_BLOCKDEVICE == 1)
#if defined(TARGET_LIKE_MBED)

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_platform.h"
#include "mbed.h"

#if defined(TARGET_CY8CKIT_062_WIFI_BT_PSA)

#include "arm_uc_trace.h"

#define SD_BLOCK_DEVICE_ERROR_CRC                -5009  /*!< CRC error */

#endif //TARGET_CY8CKIT_062_WIFI_BT_PSA


BlockDevice* arm_uc_blockdevice_ext = BlockDevice::get_default_instance();

int32_t arm_uc_blockdevice_init(void)
{
    return arm_uc_blockdevice_ext->init();
}

uint32_t arm_uc_blockdevice_get_program_size(void)
{
    return arm_uc_blockdevice_ext->get_program_size();
}

uint32_t arm_uc_blockdevice_get_erase_size(void)
{
    return arm_uc_blockdevice_ext->get_erase_size();
}

int32_t arm_uc_blockdevice_erase(uint64_t address, uint64_t size)
{
    return arm_uc_blockdevice_ext->erase(address, size);
}

int32_t arm_uc_blockdevice_program(const uint8_t *buffer,
                                   uint64_t address,
                                   uint32_t size)
{
    return arm_uc_blockdevice_ext->program(buffer, address, size);
}

int32_t arm_uc_blockdevice_read(uint8_t *buffer,
                                uint64_t address,
                                uint32_t size)
{

#if defined(TARGET_CY8CKIT_062_WIFI_BT_PSA)
    /**
     * Workaround for Cypress CY8CKIT_062 issue which might cause some bytes not to be read and return zero data.
     * https://jira.arm.com/browse/IOTSTOR-815
     * We read each block of data twice and compare their sha-256.
     * If they are equal than we assume that data is correct, otherwise we read twice again
    **/

    int status, i;
    int num_of_retries = 10;
    uint8_t sha_calc[2][32];

    while(num_of_retries--) {

        for (i = 0; i < 2; i++) {
            
            // read data from external blockdevice
            status = arm_uc_blockdevice_ext->read(buffer, address, size);
            
            //calculate sha256
            if (!status) {
                mbedtls_sha256((const unsigned char*) buffer, size, sha_calc[i], 0);
            }
            else {
                //read failed, return error
                return status;
            }
        }

        //compare sha256 for two reads, if they are same, we assume that the data in buffer is valid
        if (memcmp(sha_calc[0], sha_calc[1], 32) == 0) {
            break;
        }
    }

    if (num_of_retries == 0) {
        UC_PAAL_ERR_MSG("failed to read consistent data from block device");
        status =  SD_BLOCK_DEVICE_ERROR_CRC;
    }

    return status;
    
#else  //TARGET_CY8CKIT_062_WIFI_BT_PSA
    return arm_uc_blockdevice_ext->read(buffer, address, size);
#endif

}

#endif /* #if defined(TARGET_LIKE_MBED) */
#endif /* defined(ARM_UC_FEATURE_PAL_BLOCKDEVICE) */
