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

#ifndef ARM_UC_HUB_EVENT_HANDLERS_H
#define ARM_UC_HUB_EVENT_HANDLERS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Event handler for the Firmware Manager.
 *
 * @param event Event ID.
 */
void ARM_UC_HUB_FirmwareManagerEventHandler(uintptr_t event);

/**
 * @brief Event handler for the Manifest Manager.
 *
 * @param event Event ID.
 */
void ARM_UC_HUB_ManifestManagerEventHandler(uintptr_t event);

/**
 * @brief Event handler for the Source Manager.
 *
 * @param event Event ID.
 */
void ARM_UC_HUB_SourceManagerEventHandler(uintptr_t event);

/**
 * @brief Event handler for the Control Center.
 *
 * @param event Event ID.
 */
void ARM_UC_HUB_ControlCenterEventHandler(uintptr_t event);

#ifdef __cplusplus
}
#endif
#endif // ARM_UC_HUB_EVENT_HANDLERS_H
