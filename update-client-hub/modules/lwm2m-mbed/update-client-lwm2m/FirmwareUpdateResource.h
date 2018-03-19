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
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobject.h"

namespace FirmwareUpdateResource {

    typedef enum {
        ARM_UCS_LWM2M_STATE_FIRST       = 0,
        ARM_UCS_LWM2M_STATE_IDLE        = ARM_UCS_LWM2M_STATE_FIRST,
        ARM_UCS_LWM2M_STATE_DOWNLOADING = 1,
        ARM_UCS_LWM2M_STATE_DOWNLOADED  = 2,
        ARM_UCS_LWM2M_STATE_UPDATING    = 3,
        ARM_UCS_LWM2M_STATE_LAST        = ARM_UCS_LWM2M_STATE_UPDATING
    } arm_ucs_lwm2m_state_t;

    typedef enum {
        ARM_UCS_LWM2M_RESULT_FIRST            = 0,
        ARM_UCS_LWM2M_RESULT_INITIAL          = ARM_UCS_LWM2M_RESULT_FIRST,
        ARM_UCS_LWM2M_RESULT_SUCCESS          = 1,
        ARM_UCS_LWM2M_RESULT_ERROR_STORAGE    = 2,
        ARM_UCS_LWM2M_RESULT_ERROR_MEMORY     = 3,
        ARM_UCS_LWM2M_RESULT_ERROR_CONNECTION = 4,
        ARM_UCS_LWM2M_RESULT_ERROR_CRC        = 5,
        ARM_UCS_LWM2M_RESULT_ERROR_TYPE       = 6,
        ARM_UCS_LWM2M_RESULT_ERROR_URI        = 7,
        ARM_UCS_LWM2M_RESULT_ERROR_UPDATE     = 8,
        ARM_UCS_LWM2M_RESULT_ERROR_HASH       = 9,
        ARM_UCS_LWM2M_RESULT_LAST             = ARM_UCS_LWM2M_RESULT_ERROR_HASH
    } arm_ucs_lwm2m_result_t;

    void Initialize(void);
    void Uninitialize(void);

    M2MObject* getObject(void);

    /* Add callback for resource /5/0/0, Package */
    int32_t addPackageCallback(void (*cb)(const uint8_t* buffer, uint16_t length));

    /* Add callback for resource /5/0/1, Package URI */
    int32_t addPackageURICallback(void (*cb)(const uint8_t* buffer, uint16_t length));

    /* Add callback for resource /5/0/2, Update */
    int32_t addUpdateCallback(void (*cb)(void));

    /* Add callback for when send{State, UpdateResult} is done */
    int32_t addNotificationCallback(void (*notification_handler)(void));

    /* Send state for resource /5/0/3, State */
    int32_t sendState(arm_ucs_lwm2m_state_t state);

    /* Send result for resource /5/0/5, Update Result */
    int32_t sendUpdateResult(arm_ucs_lwm2m_result_t result);

    /* Send name for resource /5/0/6, PkgName */
    int32_t sendPkgName(const uint8_t* name, uint16_t length);

    /* Send version for resource /5/0/7, PkgVersion */
    int32_t sendPkgVersion(uint64_t version);
}

#endif // __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__
