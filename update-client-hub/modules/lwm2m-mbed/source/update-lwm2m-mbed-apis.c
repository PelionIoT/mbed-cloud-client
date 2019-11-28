// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#if defined (ARM_UC_ENABLE) && (ARM_UC_ENABLE == 1)

#include "update-lwm2m-mbed-apis.h"

const ARM_UPDATE_MONITOR ARM_UCS_LWM2M_MONITOR = {
    .GetVersion           = ARM_UCS_LWM2M_MONITOR_GetVersion,
    .GetCapabilities      = ARM_UCS_LWM2M_MONITOR_GetCapabilities,
    .Initialize           = ARM_UCS_LWM2M_MONITOR_Initialize,
    .Uninitialize         = ARM_UCS_LWM2M_MONITOR_Uninitialize,

    .SendState            = ARM_UCS_LWM2M_MONITOR_SendState,
    .SendUpdateResult     = ARM_UCS_LWM2M_MONITOR_SendUpdateResult,
    .SendName             = ARM_UCS_LWM2M_MONITOR_SendName,
    .SendVersion          = ARM_UCS_LWM2M_MONITOR_SendVersion,

    .SetBootloaderHash    = ARM_UCS_LWM2M_MONITOR_SetBootloaderHash,
    .SetOEMBootloaderHash = ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash
};

const ARM_UPDATE_SOURCE ARM_UCS_LWM2M_SOURCE = {
    .GetVersion             = ARM_UCS_LWM2M_SOURCE_GetVersion,
    .GetCapabilities        = ARM_UCS_LWM2M_SOURCE_GetCapabilities,
    .Initialize             = ARM_UCS_LWM2M_SOURCE_Initialize,
    .Uninitialize           = ARM_UCS_LWM2M_SOURCE_Uninitialize,
    .GetManifestDefaultCost = ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost,
    .GetManifestURLCost     = ARM_UCS_LWM2M_SOURCE_GetManifestURLCost,
    .GetFirmwareURLCost     = ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost,
    .GetKeytableURLCost     = ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost,
    .GetManifestDefault     = ARM_UCS_LWM2M_SOURCE_GetManifestDefault,
    .GetManifestURL         = ARM_UCS_LWM2M_SOURCE_GetManifestURL,
    .GetFirmwareFragment    = ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment,
    .GetKeytableURL         = ARM_UCS_LWM2M_SOURCE_GetKeytableURL
};
#endif
