// ----------------------------------------------------------------------------
// Copyright 2016-2018 ARM Ltd.
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

/** @file update-lwm2m-mbed-apis.h
 * @brief This file contains forward declarations for all functions used as
 * APIS for the update client
 *
 * @detail Because C++ does not support designated initialisers, this file is
 * used to provide linkage from C++ to C structure initialisers. This pattern is
 * necessary to ensure that the APIs are not brittle and prone to breakage if
 * APIs are added or the API structure is changed.
 */

#include "update-client-common/arm_uc_error.h"
#include "update-client-monitor/arm_uc_monitor.h"
#include "update-client-source/arm_uc_source.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t ARM_UCS_LWM2M_MONITOR_GetVersion(void);
ARM_MONITOR_CAPABILITIES ARM_UCS_LWM2M_MONITOR_GetCapabilities(void);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_Initialize(void (*notification_handler)(void));
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_Uninitialize(void);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendState(arm_uc_monitor_state_t state);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendUpdateResult(arm_uc_monitor_result_t updateResult);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendName(arm_uc_buffer_t *name);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendVersion(uint64_t version);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetBootloaderHash(arm_uc_buffer_t *hash);
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash(arm_uc_buffer_t *hash);

uint32_t ARM_UCS_LWM2M_SOURCE_GetVersion(void);
ARM_SOURCE_CAPABILITIES ARM_UCS_LWM2M_SOURCE_GetCapabilities(void);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_Initialize(ARM_SOURCE_SignalEvent_t cb_event);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_Uninitialize(void);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost(uint32_t *cost);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestDefault(arm_uc_buffer_t *buffer,
                                                       uint32_t offset);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURL(arm_uc_uri_t *uri,
                                                   arm_uc_buffer_t *buffer,
                                                   uint32_t offset);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment(arm_uc_uri_t *uri,
                                                        arm_uc_buffer_t *buffer,
                                                        uint32_t offset);
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURL(arm_uc_uri_t *uri,
                                                   arm_uc_buffer_t *buffer);


#ifdef __cplusplus
}
#endif
