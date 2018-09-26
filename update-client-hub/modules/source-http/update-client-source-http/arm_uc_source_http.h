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

#ifndef __UPDATE_CLIENT_SOURCE_HTTP_H__
#define __UPDATE_CLIENT_SOURCE_HTTP_H__

#include "update-client-source/arm_uc_source.h"

/**
 * @brief Get driver version.
 * @return Driver version.
 */
uint32_t ARM_UCS_Http_GetVersion(void);

/**
 * @brief Get Source capabilities.
 * @return Struct containing capabilites. See definition above.
 */
ARM_SOURCE_CAPABILITIES ARM_UCS_Http_GetCapabilities(void);

/**
 * @brief Initialize Source.
 * @details Function pointer to event handler is passed as argument.
 *
 * @param cb_event Function pointer to event handler. See events above.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_Initialize(ARM_SOURCE_SignalEvent_t cb_event);

/**
 * @brief Uninitialized Source.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_Uninitialize(void);

/**
 * @brief Cost estimation for retrieving manifest from the default location.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The manifest is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
 *
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetManifestDefaultCost(uint32_t *cost);

/**
 * @brief Cost estimation for retrieving manifest from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The manifest is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
 *
 * @param uri URI struct with manifest location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetManifestURLCost(arm_uc_uri_t *uri, uint32_t *cost);

/**
 * @brief Cost estimation for retrieving firmware from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The firmware is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve firmware from this Source.
 *
 * @param uri URI struct with firmware location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetFirmwareURLCost(arm_uc_uri_t *uri, uint32_t *cost);

/**
 * @brief Cost estimation for retrieving key table from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The firmware is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve firmware from this Source.
 *
 * @param uri URI struct with keytable location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetKeytableURLCost(arm_uc_uri_t *uri, uint32_t *cost);

/**
 * @brief Retrieve manifest from the default location.
 * @details Manifest is stored in supplied buffer.
 *          Event is generated once manifest is in buffer.
 *
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @param offset Manifest offset in bytes where the requested fragment begins.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetManifestDefault(arm_uc_buffer_t *buffer, uint32_t offset);

/**
 * @brief Retrieve manifest from URL.
 * @details Manifest is stored in supplied buffer.
 *          Event is generated once manifest is in buffer.
 *
 * @param uri URI struct with manifest location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @param offset Manifest offset in bytes where the requested fragment begins.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetManifestURL(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer, uint32_t offset);

/**
 * @brief Retrieve firmware fragment.
 * @details Firmware fragment is stored in supplied buffer.
 *          Event is generated once fragment is in buffer.
 *
 * @param uri URI struct with firmware location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @param offset Firmware offset to retrieve fragment from.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetFirmwareFragment(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer, uint32_t offset);

/**
 * @brief Retrieve a key table from a URL.
 * @details Key table is stored in supplied buffer.
 *          Event is generated once fragment is in buffer.
 *
 * @param uri URI struct with keytable location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Http_GetKeytableURL(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer);

extern ARM_UPDATE_SOURCE ARM_UCS_HTTPSource;

arm_uc_error_t ARM_UCS_Http_GetError(void);
arm_uc_error_t ARM_UCS_Http_SetError(arm_uc_error_t an_error);

#endif // __UPDATE_CLIENT_SOURCE_HTTP_H__
