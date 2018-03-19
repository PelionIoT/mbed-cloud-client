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

#include "update-client-lwm2m/lwm2m-control.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"

/**
 * @brief Set callback function for externally triggering an update.
 * @details The callback function is called when an external trigger
 *          is fired. The callback function should force an update.
 *
 * @param callback Function pointer.
 */
arm_uc_error_t ARM_UC_CONTROL_SetOverrideCallback(void (*callback)(void))
{
    arm_uc_error_t retval = { .code = ERR_INVALID_PARAMETER };

    int32_t result = FirmwareUpdateResource::addUpdateCallback(callback);

    if (result == 0)
    {
        retval.code = ERR_NONE;
    }

    return retval;
}
