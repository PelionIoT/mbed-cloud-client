// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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
#if defined(ARM_UC_CUSTOM_FW_DETAILS) && defined(TARGET_CYTFM_064B0S2_4343W)
#if defined(ARM_UC_FEATURE_PAL_FLASHIAP) && (ARM_UC_FEATURE_PAL_FLASHIAP == 1)

#define __STDC_FORMAT_MACROS

#include "update-client-pal-flashiap/arm_uc_pal_flashiap.h"

#include <inttypes.h>
#include <stddef.h>

#define TRACE_GROUP  "UCPI"

/*****************************************************************************/

#define ARM_UC_CYPRESS_HEADER_MAGIC       0x96f3b83dUL

#pragma packed(1)

typedef struct _arm_uc_cypress_image_version {
    uint8_t iv_major;
    uint8_t iv_minor;
    uint16_t iv_revision;
    uint32_t iv_build_num;
} arm_uc_cypress_image_version_t;

typedef struct _arm_uc_cypress_bootloader_header {
    uint32_t ih_magic;
    uint32_t ih_load_addr;
    uint16_t ih_hdr_size;
    uint8_t  id;           /* Image ID */
    uint8_t  monotonic;    /* Monotonic rollback counter */
    uint32_t ih_img_size;
    uint32_t ih_flags;
    arm_uc_cypress_image_version_t ih_ver;
    uint32_t _pad2;
} arm_uc_cypress_bootloader_header_t;

#pragma pop()

arm_uc_error_t ARM_UC_PAL_FlashIAP_GetCustomDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    uint64_t major_version = 0;
    uint64_t minor_version = 0;
    arm_uc_cypress_bootloader_header_t header_buff[sizeof(arm_uc_cypress_bootloader_header_t)];

    memset(details, 0x0, sizeof(arm_uc_firmware_details_t));

    memcpy(&header_buff, (const void *) MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS, sizeof(arm_uc_cypress_bootloader_header_t));

    if (header_buff->ih_magic != ARM_UC_CYPRESS_HEADER_MAGIC) {
         result.code = ERR_NOT_READY;
        goto exit;
    }

    //read the version for image header
    major_version = header_buff->ih_ver.iv_major;
    minor_version = header_buff->ih_ver.iv_minor;

    details->version = ((major_version << 32) | (minor_version << 0)) ;
    
    printf("Current FW image version: %"PRIu64".%"PRIu64"\n", major_version, minor_version);

    //read the size from image header
    details->size = header_buff->ih_img_size;

    result.error = ERR_NONE;
    result.code = ERR_NONE;

exit:
     return result;
}

#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
#endif /* defined(ARM_UC_CUSTOM_FW_DETAILS) && defined(TARGET_CYTFM_064B0S2_4343W) */
