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
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-common/arm_uc_config.h"

/**
 * @brief Set callback function for externally triggering an update.
 * @details The callback function is called when an external trigger
 *          is fired. The callback function should force an update.
 *
 * @param callback Function pointer.
 */
arm_uc_error_t ARM_UC_CONTROL_SetOverrideCallback(void (*callback)(void))
{
#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
    return FirmwareUpdateResource::addUpdateCallback(callback);
#else
    ARM_UC_INIT_ERROR(retval, ERR_INVALID_PARAMETER);
    return retval;
#endif
}

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
/**
 * @brief Setter for having reference to M2MInterface in Update client.
 * @details M2MInterface::get_data_request is used in LWM2M source for
 *          requesting FW data over COAP *
 * @param interface pointer to the M2MInterface instance.
 */
arm_uc_error_t ARM_UC_CONTROL_SetM2MInterface(M2MInterface *interface)
{
    return ARM_UCS_LWM2M_SOURCE_SetM2MInterface(interface);
}
#endif //ARM_UC_FEATURE_FW_SOURCE_COAP
