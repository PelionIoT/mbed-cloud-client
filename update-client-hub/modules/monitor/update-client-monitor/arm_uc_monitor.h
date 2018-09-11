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
 * New State & Result -enums based on http://www.openmobilealliance.org/tech/profiles/lwm2m/10252.xml
 */
typedef enum {
    ARM_UC_MONITOR_STATE_FIRST                      = 0,
    ARM_UC_MONITOR_STATE_UNINITIALISED              = ARM_UC_MONITOR_STATE_FIRST,
    ARM_UC_MONITOR_STATE_IDLE                       = 1,
    ARM_UC_MONITOR_STATE_PROCESSING_MANIFEST        = 2,
    ARM_UC_MONITOR_STATE_AWAITING_DOWNLOAD_APPROVAL = 3,
    ARM_UC_MONITOR_STATE_DOWNLOADING                = 4,
    ARM_UC_MONITOR_STATE_DOWNLOADED                 = 5,
    ARM_UC_MONITOR_STATE_AWAITING_APP_APPROVAL      = 6,
    ARM_UC_MONITOR_STATE_UPDATING                   = 7,
    ARM_UC_MONITOR_STATE_REBOOTING                  = 8,
    ARM_UC_MONITOR_STATE_LAST                       = ARM_UC_MONITOR_STATE_REBOOTING
} arm_uc_monitor_state_t;

typedef enum {
    ARM_UC_MONITOR_RESULT_FIRST                        = 0,
    ARM_UC_MONITOR_RESULT_INITIAL                      = ARM_UC_MONITOR_RESULT_FIRST,
    ARM_UC_MONITOR_RESULT_SUCCESS                      = 1,
    ARM_UC_MONITOR_RESULT_MANIFEST_TIMEOUT             = 2,
    ARM_UC_MONITOR_RESULT_MANIFEST_NOT_FOUND           = 3,
    ARM_UC_MONITOR_RESULT_MANIFEST_FAILED_INTEGRITY    = 4,
    ARM_UC_MONITOR_RESULT_MANIFEST_REJECTED            = 5,
    ARM_UC_MONITOR_RESULT_MANIFEST_CERT_NOT_FOUND      = 6,
    ARM_UC_MONITOR_RESULT_MANIFEST_SIGNATURE_FAILED    = 7,
    ARM_UC_MONITOR_RESULT_DEPENDENT_MANIFEST_NOT_FOUND = 8,
    ARM_UC_MONITOR_RESULT_ERROR_STORAGE                = 9,
    ARM_UC_MONITOR_RESULT_ERROR_MEMORY                 = 10,
    ARM_UC_MONITOR_RESULT_ERROR_CONNECTION             = 11,
    ARM_UC_MONITOR_RESULT_ERROR_CRC                    = 12,
    ARM_UC_MONITOR_RESULT_ERROR_TYPE                   = 13,
    ARM_UC_MONITOR_RESULT_ERROR_URI                    = 14,
    ARM_UC_MONITOR_RESULT_ERROR_UPDATE                 = 15,
    ARM_UC_MONITOR_RESULT_UNSUPPORTED_DELTA_FORMAT     = 16,
    ARM_UC_MONITOR_RESULT_ERROR_HASH                   = 17,
    ARM_UC_MONITOR_RESULT_ASSET_UPDATE_COMPLETED       = 18,
    ARM_UC_MONITOR_RESULT_ASSET_UPDATED_AFTER_RECOVERY = 19,
    ARM_UC_MONITOR_RESULT_LAST                         = ARM_UC_MONITOR_RESULT_ASSET_UPDATED_AFTER_RECOVERY
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
    ARM_MONITOR_CAPABILITIES(*GetCapabilities)(void);

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
     *          Indicates current state of manifest processing.
     *          This value is set by the LWM2M Client.
     *          0: Uninitialised
     *          1: Idle (before downloading or after successful updating)
     *          2: Processing manifest
     *          3: Awaiting download approval
     *          4: Downloading (The data sequence is on the way)
     *          5: Downloaded
     *          6: Awaiting application approval
     *          7: Updating
     *          8: Rebooting
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
     * @param state Valid states: ARM_UC_MONITOR_STATE_UNINITIALISED
     *                            ARM_UC_MONITOR_STATE_IDLE
     *                            ARM_UC_MONITOR_STATE_PROCESSING_MANIFEST
     *                            ARM_UC_MONITOR_STATE_AWAITING_DOWNLOAD_APPROVAL
     *                            ARM_UC_MONITOR_STATE_DOWNLOADING
     *                            ARM_UC_MONITOR_STATE_DOWNLOADED
     *                            ARM_UC_MONITOR_STATE_AWAITING_APP_APPROVAL
     *                            ARM_UC_MONITOR_STATE_UPDATING
     *                            ARM_UC_MONITOR_STATE_REBOOTING
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
     *          1: Success
     *          2: Manifest timeout. The Manifest URI has timed-out.
     *          3: Manifest not found. The Manifest URI not found.
     *          4: Unsupported package type.
     *          5: Manifest rejected. The Manifest attributes do not apply to this device.
     *          6: Manifest certificate not found
     *          7: Manifest signature failed. The Manifest signature is not recognised by this device.
     *          8: Dependent manifest not found
     *          9: Not enough storage for the new firmware package.
     *          10. Out of memory during downloading process.
     *          11: Connection lost during downloading process.
     *          12: CRC check failure for new downloaded package.
     *          13: Unsupported asset type
     *          14: Invalid URI
     *          15: Timed out downloading asset
     *          16: Unsupported delta format
     *          17: Unsupported encryption format
     *          18: Asset update successfully completed
     *          19: Asset updated successfully after recovery
     *
     *          This Resource MAY be reported by sending Observe operation.
     *
     * @param result Valid results: ARM_UC_MONITOR_RESULT_INITIAL
     *                              ARM_UC_MONITOR_RESULT_SUCCESS
     *                              ARM_UC_MONITOR_RESULT_MANIFEST_TIMEOUT
     *                              ARM_UC_MONITOR_RESULT_MANIFEST_NOT_FOUND
     *                              ARM_UC_MONITOR_RESULT_MANIFEST_FAILED_INTEGRITY
     *                              ARM_UC_MONITOR_RESULT_MANIFEST_REJECTED
     *                              ARM_UC_MONITOR_RESULT_MANIFEST_CERT_NOT_FOUND
     *                              ARM_UC_MONITOR_RESULT_MANIFEST_SIGNATURE_FAILED
     *                              ARM_UC_MONITOR_RESULT_DEPENDENT_MANIFEST_NOT_FOUND
     *                              ARM_UC_MONITOR_RESULT_ERROR_STORAGE
     *                              ARM_UC_MONITOR_RESULT_ERROR_MEMORY
     *                              ARM_UC_MONITOR_RESULT_ERROR_CONNECTION
     *                              ARM_UC_MONITOR_RESULT_ERROR_CRC
     *                              ARM_UC_MONITOR_RESULT_ERROR_TYPE
     *                              ARM_UC_MONITOR_RESULT_ERROR_URI
     *                              ARM_UC_MONITOR_RESULT_ERROR_UPDATE
     *                              ARM_UC_MONITOR_RESULT_UNSUPPORTED_DELTA_FORMAT
     *                              ARM_UC_MONITOR_RESULT_ERROR_HASH
     *                              ARM_UC_MONITOR_RESULT_ASSET_UPDATE_COMPLETED
     *                              ARM_UC_MONITOR_RESULT_ASSET_UPDATED_AFTER_RECOVERY
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
    arm_uc_error_t (*SendName)(arm_uc_buffer_t *name);

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
    arm_uc_error_t (*SetBootloaderHash)(arm_uc_buffer_t *hash);

    /**
     * @brief Set the OEM bootloader hash.
     * @details If the end-user has modified the bootloader the hash of the
     *          modified bootloader can be set here.
     *
     * @param name Pointer to buffer struct. Hash is stored as byte array.
     * @return Error code.
     */
    arm_uc_error_t (*SetOEMBootloaderHash)(arm_uc_buffer_t *hash);
} ARM_UPDATE_MONITOR;

#endif /* __ARM_UPDATE_MONITOR_H__ */
