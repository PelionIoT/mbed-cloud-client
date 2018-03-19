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

#ifndef ARM_UC_PAL_EXTENSIONS
#define ARM_UC_PAL_EXTENSIONS

#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-paal/arm_uc_paal_update_api.h"

#ifdef __cplusplus
extern "C" {
#endif

arm_uc_error_t pal_ext_imageInitAPI(ARM_UC_PAAL_UPDATE_SignalEvent_t callback);

arm_uc_error_t pal_ext_imageGetActiveDetails(arm_uc_firmware_details_t* details);

arm_uc_error_t pal_ext_installerGetDetails(arm_uc_installer_details_t* details);

arm_uc_error_t pal_ext_imageActivate(uint32_t location);

#ifdef __cplusplus
}
#endif

#endif // ARM_UC_PAL_EXTENSIONS
