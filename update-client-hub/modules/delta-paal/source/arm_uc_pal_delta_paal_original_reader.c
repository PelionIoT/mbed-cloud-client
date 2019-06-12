// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include "arm_uc_config.h"

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
#include "update-client-common/arm_uc_common.h"
#include <inttypes.h>
#if defined(TARGET_LIKE_MBED)
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"
// TODO: do we need something different for old style definition of mbed app start?
#define MBED_CONF_APP_APPLICATION_START_ADDRESS APPLICATION_ADDR
#endif

#if defined(ARM_UC_FEATURE_PAL_LINUX) && (ARM_UC_FEATURE_PAL_LINUX == 1)
#if defined(TARGET_IS_PC_LINUX)
#include "update-client-pal-linux/arm_uc_pal_linux_implementation_internal.h"
#endif
#endif

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE==1)
#define ORIG_FILENAME_MAX_PATH 78
#define ORIG_FIRMWARE_DIR "pal/firmware"
#else
#define ORIG_FILENAME_MAX_PATH PAL_MAX_FILE_AND_FOLDER_LENGTH
#endif // ARM_UC_PROFILE_MBED_CLIENT_LITE

#include "update-client-paal/arm_uc_paal_update_api.h"
#define TRACE_GROUP  "UCPI"

#include "update-client-paal/arm_uc_paal_update_api.h"
#define TRACE_GROUP  "UCPI"

static int flash_init_done = 0;

/**
 * @brief arm_uc_deltapaal_original_reader - helper function to read bytes from original reader.
 * @param stream
 * @param buffer
 * @param length
 * @return
 */
int arm_uc_deltapaal_original_reader(void* buffer, uint64_t length, uint32_t offset)
{
    //arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    //UC_PAAL_TRACE("arm_uc_deltapaal_original_reader: offset %d  size %" PRIu64,
    //              offset, length);

#if defined(TARGET_LIKE_MBED)
    uint32_t appStart = MBED_CONF_APP_APPLICATION_START_ADDRESS;

    int32_t status = ARM_UC_FLASHIAP_SUCCESS;

    if (!flash_init_done) {
        status = arm_uc_flashiap_init();
        if (status == ARM_UC_FLASHIAP_SUCCESS)
            flash_init_done = 1;
    }

    if (status == ARM_UC_FLASHIAP_SUCCESS) {
        status = arm_uc_flashiap_read(buffer,
                                      appStart + offset,
                                      (uint32_t)length);
    }

    if (status == ARM_UC_FLASHIAP_SUCCESS) {
        return ERR_NONE;
    } else {
        UC_PAAL_ERR_MSG("ARM_UC_PAL_FlashIAP_BlockDevice_Original_Read: arm_uc_flashiap_read failed");
        return ERR_INVALID_PARAMETER;
    }

#else

    // LINUX Reading

    arm_uc_error_t result;
    char file_path[ORIG_FILENAME_MAX_PATH] = { 0 };
    arm_uc_buffer_t uc_buffer = {
        .size_max = length,
        .size     = length,
        .ptr      = buffer
    };

    /* construct firmware file path */
    result = arm_uc_pal_linux_internal_file_path(file_path,
                                                 ORIG_FILENAME_MAX_PATH,
#if defined(ARM_UC_FEATURE_PAL_LINUX) && (ARM_UC_FEATURE_PAL_LINUX == 1)
#if defined(TARGET_X86_X64)
#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE==0)


                                                 pal_imageGetFolder(),
#else
                                                 ORIG_FIRMWARE_DIR,
#endif
#else                                                 // For Yocto Linux devices, expect original firmware
                                                 //  .tar-package (with same name original_image.bin
                                                 // is done in Prepare-script into /mnt/root/original_image.bin
                                                 "/mnt/root",
#endif // TARGET_X86_X64
#else
                                                 pal_imageGetFolder(),
#endif // ARM_UC_FEATURE_PAL_LINUX
                                                 "original_image",
                                                 NULL);

    if (result.error != ERR_NONE) {
        UC_PAAL_ERR_MSG("arm_uc_pal_linux_internal_file_path failed with %d\n", result.error);
        return ERR_UNSPECIFIED;
    }
    result = arm_uc_pal_linux_internal_read((const char *)file_path, offset, &uc_buffer);

    if (result.error != ERR_NONE) {
        UC_PAAL_ERR_MSG("arm_uc_pal_linux_internal_read failed with %d %s\n", result.error, file_path);
        return ERR_UNSPECIFIED;
    }
#endif
    return (ERR_NONE);
}

#endif
