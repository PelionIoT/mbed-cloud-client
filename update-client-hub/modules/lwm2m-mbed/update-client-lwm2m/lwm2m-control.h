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

#ifndef ARM_UC_LWM2M_CONTROL_H
#define ARM_UC_LWM2M_CONTROL_H

#include "update-client-common/arm_uc_common.h"
#include "update-client-common/arm_uc_config.h"
#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
#include "mbed-client/m2minterface.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set callback function for externally triggering an update.
 * @details The callback function is called when an external trigger
 *          is fired. The callback function should force an update.
 *
 * @param callback Function pointer.
 */
arm_uc_error_t ARM_UC_CONTROL_SetOverrideCallback(void (*callback)(void));

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
arm_uc_error_t ARM_UC_CONTROL_SetM2MInterface(M2MInterface *interface);
#endif

#ifdef __cplusplus
}
#endif

#endif // ARM_UCS_LWM2M_CONTROL_H
