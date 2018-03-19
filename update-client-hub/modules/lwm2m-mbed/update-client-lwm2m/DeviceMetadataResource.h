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

#ifndef __ARM_UCS_DEVICE_METADATA_RESOURCE_H__
#define __ARM_UCS_DEVICE_METADATA_RESOURCE_H__

#include "update-client-common/arm_uc_common.h"

#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobject.h"

namespace DeviceMetadataResource {

    void Initialize(void);
    void Uninitialize(void);

    M2MObject* getObject(void);

    /* set bootloader hash resource /10255/0/1 */
    int32_t setBootloaderHash(arm_uc_buffer_t* hash);

    /* set OEM bootloader hash resource /10255/0/2 */
    int32_t setOEMBootloaderHash(arm_uc_buffer_t* hash);
}

#endif // __ARM_UCS_DEVICE_METADATA_RESOURCE_H__
