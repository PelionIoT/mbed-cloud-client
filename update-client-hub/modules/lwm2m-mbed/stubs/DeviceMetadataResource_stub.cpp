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

#include "update-client-lwm2m/DeviceMetadataResource.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-common/arm_uc_common.h"
#include "pal4life-device-identity/pal_device_identity.h"

#include <stdio.h>

#define ARM_UCS_LWM2M_INTERNAL_ERROR (-1)
#define ARM_UCS_LWM2M_INTERNAL_SUCCESS (0)

namespace DeviceMetadataResource {
bool initialized = false;
}


/**
 * @brief Initialize LWM2M Device Metadata Object
 * @details Sets up LWM2M object with accompanying resources.
 */
void DeviceMetadataResource::Initialize(void)
{
    printf("STUBBED DeviceMetadataResource::Initialize\n");
    initialized = true;
}

int32_t DeviceMetadataResource::setBootloaderHash(arm_uc_buffer_t *hash)
{
    printf("STUBBED DeviceMetadataResource::setBootloaderHash ptr %p size %u\n", hash, hash->size);

    int32_t result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;

    return result;
}

int32_t DeviceMetadataResource::setOEMBootloaderHash(arm_uc_buffer_t *hash)
{
    printf("STUBBED DeviceMetadataResource::setOEMBootloaderHash ptr %p size %u\n", hash, hash->size);

    int32_t result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;

    return result;
}

void DeviceMetadataResource::Uninitialize()
{
    printf("STUBBED DeviceMetadataResource::Uninitialize\n");
    initialized = false;

}
