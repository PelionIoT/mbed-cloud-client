// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#include "lwm2m-source.h"

#ifdef LWM2M_SOURCE_USE_C_API

#ifndef __DEVICE_METADATA_RESOURCE_H__
#define __DEVICE_METADATA_RESOURCE_H__

#include "update-client-common/arm_uc_types.h"

#include "lwm2m_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

bool device_metadata_create(registry_t *registry);

void device_metadata_destroy(registry_t *registry);

/* set bootloader hash resource /10255/0/1 */
bool device_metadata_set_bootloader_hash(registry_t *registry, arm_uc_buffer_t *hash);

/* set OEM bootloader hash resource /10255/0/2 */
bool device_metadata_set_oem_bootloader_hash(registry_t *registry, arm_uc_buffer_t *hash);

#ifdef __cplusplus
}
#endif

#endif // __DEVICE_METADATA_RESOURCE_H__

#endif //LWM2M_SOURCE_USE_C_API
