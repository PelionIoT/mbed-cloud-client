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

#ifndef __ARM_UPDATE_MONITOR_H__
#define __ARM_UPDATE_MONITOR_H__

#include "update-client-common/arm_uc_common.h"

#include <stdint.h>

/**
 * @brief Struct containing the Monitor's capabilities.
 * @details state: Monitor can report the device's state.
 *          result: Monitor can report the update result.
 *          version: Monitor can report the current version.
 */
typedef struct _ARM_MONITOR_CAPABILITIES {
    uint32_t state: 1;
    uint32_t result: 1;
    uint32_t version: 1;
    uint32_t reserved: 30;
} ARM_MONITOR_CAPABILITIES;

/**
 *
 */
typedef enum {
    ARM_UC_MONITOR_STATE_FIRST       = 0,
    ARM_UC_MONITOR_STATE_IDLE        = ARM_UC_MONITOR_STATE_FIRST,
    ARM_UC_MONITOR_STATE_DOWNLOADING = 1,
    ARM_UC_MONITOR_STATE_DOWNLOADED  = 2,
    ARM_UC_MONITOR_STATE_UPDATING    = 3,
    ARM_UC_MONITOR_STATE_LAST        = ARM_UC_MONITOR_STATE_UPDATING
} arm_uc_monitor_state_t;

typedef enum {
    ARM_UC_MONITOR_RESULT_FIRST            = 0,
    ARM_UC_MONITOR_RESULT_INITIAL          = ARM_UC_MONITOR_RESULT_FIRST,
    ARM_UC_MONITOR_RESULT_SUCCESS          = 1,
    ARM_UC_MONITOR_RESULT_ERROR_STORAGE    = 2,
    ARM_UC_MONITOR_RESULT_ERROR_MEMORY     = 3,
    ARM_UC_MONITOR_RESULT_ERROR_CONNECTION = 4,
    ARM_UC_MONITOR_RESULT_ERROR_CRC        = 5,
    ARM_UC_MONITOR_RESULT_ERROR_TYPE       = 6,
    ARM_UC_MONITOR_RESULT_ERROR_URI        = 7,
    ARM_UC_MONITOR_RESULT_ERROR_UPDATE     = 8,
    ARM_UC_MONITOR_RESULT_ERROR_HASH       = 9,
    ARM_UC_MONITOR_RESULT_LAST             = ARM_UC_MONITOR_RESULT_ERROR_HASH
} arm_uc_monitor_result_t;

/**
 * @brief Structure definition holding API function pointers.
 */
typedef struct _ARM_UPDATE_MONITOR {

    /**
     * @brief Get driver version.
     * @return Driver version.
     */
    uint32_t (*GetVersion)(void);

    /**
     * @brief Get Source capabilities.
     * @return Struct containing capabilites. See definition above.
     */
    ARM_MONITOR_CAPABILITIES (*GetCapabilities)(void);

    /**
     * @brief Initialize Monitor.
     * @return Error code.
     */
    arm_uc_error_t (*Initialize)(void (*notification_handler)(void));

    /**
     * @brief Uninitialized Monitor.
     * @return Error code.
     */
    arm_uc_error_t (*Uninitialize)(void);

    /**
     * @brief Send Update Client state.
     * @details From the OMA LWM2M Technical Specification:
     *
     *          Indicates current state with respect to this firmware update.
     *          This value is set by the LWM2M Client.
     *          0: Idle (before downloading or after successful updating)
     *          1: Downloading (The data sequence is on the way)
     *          2: Downloaded
     *          3: Updating
     *
     *          If writing the firmware package to Package Resource is done,
     *          or, if the device has downloaded the firmware package from the
     *          Package URI the state changes to Downloaded.
     *
     *          If writing an empty string to Package Resource is done or
     *          writing an empty string to Package URI is done, the state
     *          changes to Idle.
     *
     *          When in Downloaded state, and the executable Resource Update is
     *          triggered, the state changes to Updating.
     *          If the Update Resource failed, the state returns at Downloaded.
     *          If performing the Update Resource was successful, the state
     *          changes from Updating to Idle.
     *
     * @param state Valid states: ARM_UC_MONITOR_STATE_IDLE
     *                            ARM_UC_MONITOR_STATE_DOWNLOADING
     *                            ARM_UC_MONITOR_STATE_DOWNLOADED
     *                            ARM_UC_MONITOR_STATE_UPDATING
     *
     * @return Error code.
     */
    arm_uc_error_t (*SendState)(arm_uc_monitor_state_t state);

    /**
     * @brief Send update result.
     * @details From the OMA LWM2M Technical Specification:
     *
     *          Contains the result of downloading or updating the firmware
     *          0: Initial value. Once the updating process is initiated
     *             (Download /Update), this Resource MUST be reset to Initial
     *             value.
     *          1: Firmware updated successfully,
     *          2: Not enough storage for the new firmware package.
     *          3. Out of memory during downloading process.
     *          4: Connection lost during downloading process.
     *          5: CRC check failure for new downloaded package.
     *          6: Unsupported package type.
     *          7: Invalid URI
     *          8: Firmware update failed
     *
     *          This Resource MAY be reported by sending Observe operation.
     *
     * @param result Valid results: ARM_UC_MONITOR_RESULT_INITIAL
     *                              ARM_UC_MONITOR_RESULT_SUCCESS
     *                              ARM_UC_MONITOR_RESULT_ERROR_STORAGE
     *                              ARM_UC_MONITOR_RESULT_ERROR_MEMORY
     *                              ARM_UC_MONITOR_RESULT_ERROR_CONNECTION
     *                              ARM_UC_MONITOR_RESULT_ERROR_CRC
     *                              ARM_UC_MONITOR_RESULT_ERROR_TYPE
     *                              ARM_UC_MONITOR_RESULT_ERROR_URI
     *                              ARM_UC_MONITOR_RESULT_ERROR_UPDATE
     *                              ARM_UC_MONITOR_RESULT_ERROR_HASH
     *
     * @return Error code.
     */
    arm_uc_error_t (*SendUpdateResult)(arm_uc_monitor_result_t updateResult);

    /**
     * @brief Send current firmware name.
     * @details The firmware name is the SHA256 hash.
     *
     * @param name Pointer to buffer struct. Hash is stored as byte array.
     * @return Error code.
     */
    arm_uc_error_t (*SendName)(arm_uc_buffer_t* name);

    /**
     * @brief Send current firmware version.
     * @details The firmware version is the timestamp from the manifest that
     *          authorized the firmware.
     *
     * @param version Timestamp, 64 bit unsigned integer.
     * @return Error code.
     */
    arm_uc_error_t (*SendVersion)(uint64_t version);

    /**
     * @brief Set the bootloader hash.
     * @details The bootloader hash is a hash of the bootloader. This is
     *          used for tracking the version of the bootloader used.
     *
     * @param name Pointer to buffer struct. Hash is stored as byte array.
     * @return Error code.
     */
    arm_uc_error_t (*SetBootloaderHash)(arm_uc_buffer_t* hash);

    /**
     * @brief Set the OEM bootloader hash.
     * @details If the end-user has modified the bootloader the hash of the
     *          modified bootloader can be set here.
     *
     * @param name Pointer to buffer struct. Hash is stored as byte array.
     * @return Error code.
     */
    arm_uc_error_t (*SetOEMBootloaderHash)(arm_uc_buffer_t* hash);
} ARM_UPDATE_MONITOR;

#endif /* __ARM_UPDATE_MONITOR_H__ */
