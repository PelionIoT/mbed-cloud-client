// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
#if defined(ARM_UC_FEATURE_PAL_FILESYSTEM) && (ARM_UC_FEATURE_PAL_FILESYSTEM == 1)
#if defined(TARGET_LIKE_MBED)

#include "update-client-pal-filesystem/arm_uc_pal_extensions.h"

#include "update-client-pal-flashiap/arm_uc_pal_flashiap_implementation.h"

static void (*arm_ucex_mbed_callback)(uintptr_t) = 0;

arm_uc_error_t pal_ext_imageInitAPI(void (*callback)(uintptr_t))
{
    arm_ucex_mbed_callback = callback;

    return ARM_UC_PAL_FlashIAP_Initialize(callback);
}

arm_uc_error_t pal_ext_imageGetActiveDetails(arm_uc_firmware_details_t *details)
{
    return ARM_UC_PAL_FlashIAP_GetActiveDetails(details);
}

arm_uc_error_t pal_ext_installerGetDetails(arm_uc_installer_details_t *details)
{
    return ARM_UC_PAL_FlashIAP_GetInstallerDetails(details);
}

arm_uc_error_t pal_ext_imageActivate(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    /* pal_imageActivate not implemented */
    arm_ucex_mbed_callback(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);

    return result;
}

#endif /* TARGET_LIKE_MBED */
#endif /* ARM_UC_FEATURE_PAL_FILESYSTEM */
