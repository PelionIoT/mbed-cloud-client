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

#ifndef __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__
#define __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__

#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobject.h"
#include "update-client-common/arm_uc_config.h"
#include "update-client-monitor/arm_uc_monitor.h"

namespace FirmwareUpdateResource {

// New enums based on http://www.openmobilealliance.org/tech/profiles/lwm2m/10252.xml
typedef arm_uc_update_state_t arm_ucs_lwm2m_state_t;
typedef arm_uc_update_result_t arm_ucs_lwm2m_result_t;

void Initialize(void);
void Uninitialize(void);

M2MObject *getObject(void);

/* Add callback for resource /10252/0/1, Package */
int32_t addPackageCallback(void (*cb)(const uint8_t *buffer, uint16_t length));

#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
/* Add callback for resource /5/0/2, Update */
int32_t addUpdateCallback(void (*cb)(void));
#endif

/* Add callback for when send{State, UpdateResult} is done */
int32_t addNotificationCallback(void (*notification_handler)(void));

/* Send state for resource /10252/0/2, State */
int32_t sendState(arm_ucs_lwm2m_state_t state);

/* Send result for resource /10252/0/3, Update Result */
int32_t sendUpdateResult(arm_ucs_lwm2m_result_t result);

/* Send name for resource /10252/0/5, PkgName */
int32_t sendPkgName(const uint8_t *name, uint16_t length);

/* Send version for resource /10252/0/6, PkgVersion */
int32_t sendPkgVersion(uint64_t version);

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
int32_t setM2MInterface(M2MInterface *interface);

M2MInterface *getM2MInterface(void);
#endif //ARM_UC_FEATURE_FW_SOURCE_COAP
}

#endif // __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__
