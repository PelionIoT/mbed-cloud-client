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
#if defined(ARM_UC_FEATURE_PAL_LINUX) && (ARM_UC_FEATURE_PAL_LINUX == 1)
#if defined(TARGET_IS_PC_LINUX)

#include "update-client-paal/arm_uc_paal_update_api.h"
#include "update-client-pal-linux/arm_uc_pal_linux_implementation.h"
#include "update-client-pal-linux/arm_uc_pal_linux_implementation_internal.h"
#include <unistd.h>

/**
 * @brief Get a bitmap indicating supported features.
 * @details The bitmap is used in conjunction with the firmware and
 *          installer details struct to indicate what fields are supported
 *          and which values are valid.
 *
 * @return Capability bitmap.
 */
ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UC_PAL_Linux_GetCapabilities_OpenWRT(void)
{
    const ARM_UC_PAAL_UPDATE_CAPABILITIES result = {
        .installer_arm_hash = 0,
        .installer_oem_hash = 0,
        .installer_layout   = 0,
        .firmware_hash      = 1,
        .firmware_hmac      = 0,
        .firmware_campaign  = 0,
        .firmware_version   = 1,
        .firmware_size      = 1
    };

    return result;
}

arm_ucp_worker_t arm_uc_worker_parameters_active_details = {
    .command = "/usr/sbin/arm_update_active_details.sh",
    .header   = 1,
    .firmware = 0,
    .location = 0,
    .offset   = 0,
    .size     = 0,
    .success_event = ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE,
    .failure_event = ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR,
    .post_runner = NULL
};

arm_ucp_worker_t arm_uc_worker_parameters_activate = {
    .command = "/usr/sbin/arm_update_activate.sh",
    .header   = 1,
    .firmware = 1,
    .location = 0,
    .offset   = 0,
    .size     = 0,
    .success_event = ARM_UC_PAAL_EVENT_ACTIVATE_DONE,
    .failure_event = ARM_UC_PAAL_EVENT_ACTIVATE_ERROR,
    .post_runner = NULL
};

arm_uc_error_t ARM_UC_PAL_Linux_Initialize_OpenWRT(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    extern arm_ucp_worker_config_t arm_uc_worker_parameters;

    arm_uc_worker_parameters.activate       = &arm_uc_worker_parameters_activate;
    arm_uc_worker_parameters.active_details = &arm_uc_worker_parameters_active_details;
    arm_uc_worker_parameters.details        = NULL;
    arm_uc_worker_parameters.finalize       = NULL;
    arm_uc_worker_parameters.initialize     = NULL;
    arm_uc_worker_parameters.installer      = NULL;
    arm_uc_worker_parameters.prepare        = NULL;
    arm_uc_worker_parameters.read           = NULL;
    arm_uc_worker_parameters.write          = NULL;

    return ARM_UC_PAL_Linux_Initialize(callback);
}

const ARM_UC_PAAL_UPDATE ARM_UCP_LINUX_OPENWRT = {
    .Initialize                 = ARM_UC_PAL_Linux_Initialize_OpenWRT,
    .GetCapabilities            = ARM_UC_PAL_Linux_GetCapabilities_OpenWRT,
    .GetMaxID                   = ARM_UC_PAL_Linux_GetMaxID,
    .Prepare                    = ARM_UC_PAL_Linux_Prepare,
    .Write                      = ARM_UC_PAL_Linux_Write,
    .Finalize                   = ARM_UC_PAL_Linux_Finalize,
    .Read                       = ARM_UC_PAL_Linux_Read,
    .Activate                   = ARM_UC_PAL_Linux_Activate,
    .GetActiveFirmwareDetails   = ARM_UC_PAL_Linux_GetActiveFirmwareDetails,
    .GetFirmwareDetails         = ARM_UC_PAL_Linux_GetFirmwareDetails,
    .GetInstallerDetails        = ARM_UC_PAL_Linux_GetInstallerDetails
};

#endif /* TARGET_IS_PC_LINUX */
#endif /* ARM_UC_FEATURE_PAL_LINUX */
