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

#ifndef __FIRMWARE_UPDATE_RESOURCE_H__
#define __FIRMWARE_UPDATE_RESOURCE_H__

#include "update-client-common/arm_uc_types.h"

#include "lwm2m_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

bool firmware_update_initialize(registry_t *registry);

void firmware_update_add_notification_callback(void (*cb)(void));

bool firmware_update_send_state(registry_t *registry, int64_t state);

bool firmware_update_send_update_result(registry_t *registry, int64_t updateResult);

bool firmware_update_send_pkg_name(registry_t *registry, const uint8_t *name, uint16_t length);

bool firmware_update_send_pkg_version(registry_t *registry, uint64_t version);

void firmware_update_destroy(registry_t *registry);

#ifdef __cplusplus
}
#endif

#endif // __FIRMWARE_UPDATE_RESOURCE_H__

#endif //LWM2M_SOURCE_USE_C_API
