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

#ifndef __ARM_UCS_LWM2M_SOURCE_H__
#define __ARM_UCS_LWM2M_SOURCE_H__

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1) && !defined(MBED_CONF_MBED_CLIENT_ENABLE_CPP_API)
#define LWM2M_SOURCE_USE_C_API
#endif

#include "update-client-source/arm_uc_source.h"
#include "update-client-common/arm_uc_config.h"
#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1) && defined(__cplusplus)
#include "mbed-client/m2minterface.h"

/**
 * @brief      Function for providing access to the M2M interface.
 * @param      interface  Pointer to M2M interface.
 * @return     Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_SetM2MInterface(M2MInterface *interface);
#endif

#ifdef LWM2M_SOURCE_USE_C_API
#include "lwm2m_endpoint.h"

#ifdef __cplusplus
extern "C" {
#endif


void ARM_UCS_LWM2M_SOURCE_endpoint_set(endpoint_t *ep);
registry_t *ARM_UCS_LWM2M_SOURCE_registry_get(void);
const ARM_UPDATE_SOURCE *ARM_UCS_LWM2M_SOURCE_source_get(void);
bool ARM_UCS_LWM2M_SOURCE_manifast_received(const uint8_t *buffer, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif

extern const ARM_UPDATE_SOURCE ARM_UCS_LWM2M_SOURCE;

#endif // __ARM_UCS_LWM2M_SOURCE_H__
