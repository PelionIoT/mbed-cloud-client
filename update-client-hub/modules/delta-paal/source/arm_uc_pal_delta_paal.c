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

#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)

#include "update-client-paal/arm_uc_paal_update_api.h"

#include "update-client-delta-paal/arm_uc_pal_delta_paal_implementation.h"




const ARM_UC_PAAL_UPDATE ARM_UCP_DELTA_PAAL = {
    .Initialize                 = ARM_UC_PAL_DeltaPaal_Initialize,
    .GetCapabilities            = ARM_UC_PAL_DeltaPaal_GetCapabilities,
    .GetMaxID                   = ARM_UC_PAL_DeltaPaal_GetMaxID,
    .Prepare                    = ARM_UC_PAL_DeltaPaal_Prepare,
    .Write                      = ARM_UC_PAL_DeltaPaal_Write,
    .Finalize                   = ARM_UC_PAL_DeltaPaal_Finalize,
    .Read                       = ARM_UC_PAL_DeltaPaal_Read,
    .Activate                   = ARM_UC_PAL_DeltaPaal_Activate,
    .GetActiveFirmwareDetails   = ARM_UC_PAL_DeltaPaal_GetActiveDetails,
    .GetFirmwareDetails         = ARM_UC_PAL_DeltaPaal_GetFirmwareDetails,
    .GetInstallerDetails        = ARM_UC_PAL_DeltaPaal_GetInstallerDetails
};

#endif // #if defined(ARM_UC_FEATURE_DELTA_PAAL)
