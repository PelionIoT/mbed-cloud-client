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

#ifndef __ARM_UPDATE_SOURCE_H__
#define __ARM_UPDATE_SOURCE_H__

#include "update-client-common/arm_uc_common.h"

#include <stdint.h>

/**
 * @brief Struct containing the Source's capabilities.
 * @details notify: Source can notify about new manifests.
 *          manifest_default: Source can download manifest from default location.
 *          manifest_url: Source can download manifest from URL.
 *          firmware: Source can download firmware from URL.
 */
typedef struct _ARM_SOURCE_CAPABILITIES {
    uint32_t notify: 1;
    uint32_t manifest_default: 1;
    uint32_t manifest_url: 1;
    uint32_t firmware: 1;
    uint32_t keytable: 1;
    uint32_t reserved: 27;
} ARM_SOURCE_CAPABILITIES;

/**
 * @brief Events passed to event handler.
 * @details EVENT_NOTIFICATION: New manifest is available.
 *          EVENT_MANIFEST: Manifest retrieved.
 *          EVENT_FIRMWARE: Firmware fragment retrieved.
 */
typedef enum _ARM_SOURCE_EVENT {
    EVENT_NOTIFICATION,
    EVENT_MANIFEST,
    EVENT_FIRMWARE,
    EVENT_KEYTABLE,
    EVENT_ERROR,
    EVENT_ERROR_SOURCE,
    EVENT_ERROR_BUFFER_SIZE
} ARM_SOURCE_EVENT;

/**
 * @brief Prototype for event handler.
 */
typedef void (*ARM_SOURCE_SignalEvent_t)(uint32_t event);

/**
 * @brief Structure definition holding API function pointers.
 */
typedef struct _ARM_UPDATE_SOURCE {

    /**
     * @brief Get driver version.
     * @return Driver version.
     */
    uint32_t (*GetVersion)(void);

    /**
     * @brief Get Source capabilities.
     * @return Struct containing capabilites. See definition above.
     */
    ARM_SOURCE_CAPABILITIES(*GetCapabilities)(void);

    /**
     * @brief Initialize Source.
     * @details Function pointer to event handler is passed as argument.
     *
     * @param cb_event Function pointer to event handler. See events above.
     * @return Error code.
     */
    arm_uc_error_t (*Initialize)(ARM_SOURCE_SignalEvent_t cb_event);

    /**
     * @brief Uninitialized Source.
     * @return Error code.
     */
    arm_uc_error_t (*Uninitialize)(void);

    /**
     * @brief Cost estimation for retrieving manifest from the default location.
     * @details The estimation can vary over time and should not be cached too long.
     *          0x00000000 - The manifest is already downloaded.
     *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
     *
     * @param cost Pointer to variable for the return value.
     * @return Error code.
     */
    arm_uc_error_t (*GetManifestDefaultCost)(uint32_t *cost);

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
    arm_uc_error_t (*GetManifestURLCost)(arm_uc_uri_t *uri, uint32_t *cost);

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
    arm_uc_error_t (*GetFirmwareURLCost)(arm_uc_uri_t *uri, uint32_t *cost);

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
    arm_uc_error_t (*GetKeytableURLCost)(arm_uc_uri_t *uri, uint32_t *cost);

    /**
     * @brief Retrieve manifest from the default location.
     * @details Manifest is stored in supplied buffer.
     *          Event is generated once manifest is in buffer.
     *
     * @param buffer Struct containing byte array, maximum size, and actual size.
     * @param offset Manifest offset in bytes where the requested fragment begins.
     * @return Error code.
     */
    arm_uc_error_t (*GetManifestDefault)(arm_uc_buffer_t *buffer, uint32_t offset);

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
    arm_uc_error_t (*GetManifestURL)(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer, uint32_t offset);

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
    arm_uc_error_t (*GetFirmwareFragment)(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer, uint32_t offset);

    /**
     * @brief Retrieve a key table from a URL.
     * @details Key table is stored in supplied buffer.
     *          Event is generated once fragment is in buffer.
     *
     * @param uri URI struct with keytable location.
     * @param buffer Struct containing byte array, maximum size, and actual size.
     * @return Error code.
     */
    arm_uc_error_t (*GetKeytableURL)(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer);

} ARM_UPDATE_SOURCE;

#endif /* __ARM_UPDATE_SOURCE_H__ */
