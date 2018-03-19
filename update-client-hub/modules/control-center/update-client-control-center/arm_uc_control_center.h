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

#ifndef ARM_UPDATE_CONTROL_CENTER_H
#define ARM_UPDATE_CONTROL_CENTER_H

#include "update-client-monitor/arm_uc_monitor.h"
#include "update-client-common/arm_uc_common.h"

#include <stdint.h>

typedef enum {
    ARM_UCCC_EVENT_AUTHORIZE_DOWNLOAD,
    ARM_UCCC_EVENT_AUTHORIZE_INSTALL,
    ARM_UCCC_EVENT_MONITOR_SEND_DONE,
} arm_uc_contro_center_event_t;

/**
 * @brief Initialize Control Center.
 *
 * @param callback Event handler to signal authorizations.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_Initialize(void (*callback)(uint32_t));

/**
 * @brief Add monitor struct for sending status and results remotely.
 * @details Update Client call for adding remote monitor.
 *
 * @param monitor Pointer to an ARM_UPDATE_MONITOR struct.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_AddMonitor(const ARM_UPDATE_MONITOR* monitor);

/**
 * @brief Set callback for receiving download progress.
 * @details User application call for setting callback handler.
 *          The callback function takes the progreess in percent as argument.
 *
 * @param callback Function pointer to the progress function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_SetProgressHandler(void (*callback)(uint32_t progress, uint32_t total));

/**
 * @brief Set callback function for authorizing requests.
 * @details User application call for setting callback handler.
 *          The callback function takes an enum request and an authorization
 *          function pointer. To authorize the given request, the caller
 *          invokes the authorization function.
 *
 * @param callback Function pointer to the authorization function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_SetAuthorityHandler(void (*callback)(int32_t));

/**
 * @brief Request authorization from Control Center.
 * @details Update Client call for asking user application for permission.
 *
 * @param type Request type.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_GetAuthorization(arm_uc_request_t request);

/**
 * @brief Authorize request.
 * @details User application call for authorizing request.
 *
 * @param request Request type. Must match the type in callback function.
 */
arm_uc_error_t ARM_UC_ControlCenter_Authorize(arm_uc_request_t request);

/**
 * @brief Override update authorization handler.
 * @details Force download and update to progress regardless of authorization
 *          handler. This function is used for unblocking an update in a buggy
 *          application.
 */
void ARM_UC_ControlCenter_OverrideAuthorization(void);

/**
 * @brief Report download progress.
 * @details Update Client call for informing the Control Center about the
 *          current download progress. The Control Center will send this to the
 *          appication handler and the monitor if either/both are attached.
 *
 * @param progress Bytes already downloaded.
 * @param total Total bytes in download.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportProgress(uint32_t progress, uint32_t total);

/**
 * @brief Send Update Client state.
 * @details Update Client call for informing the Control Center about the
 *          current state. The Control Center will send this to the monitor.
 *
 *          From the OMA LWM2M Technical Specification:
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
arm_uc_error_t ARM_UC_ControlCenter_ReportState(arm_uc_monitor_state_t state);

/**
 * @brief Set update result.
 * @details Update Client call for informing the Control Center about the
 *          latest update result. The Control Center will send this to the monitor.
 *
 *          From the OMA LWM2M Technical Specification:
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
arm_uc_error_t ARM_UC_ControlCenter_ReportUpdateResult(arm_uc_monitor_result_t updateResult);

/**
 * @brief Set current firmware name.
 * @details Update Client call for informing the Control Center about the
 *          current firmware name. The Control Center will send this to the
 *          monitor. The firmware name is the SHA256 hash.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportName(arm_uc_buffer_t* name);

/**
 * @brief Set current firmware version.
 * @details Update Client call for informing the Control Center about the
 *          current firmware version. The Control Center will send this to the
 *          monitor. The firmware version is the manifest timestamp that
 *          authorized the installation.
 *
 * @param version Timestamp, 64 bit unsigned integer.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportVersion(uint64_t version);

/**
 * @brief Send bootloader hash to monitor.
 * @details The bootloader hash is a hash of the bootloader. This is
 *          used for tracking the version of the bootloader used.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportBootloaderHash(arm_uc_buffer_t* hash);

/**
 * @brief Send the OEM bootloader hash to monitor.
 * @details If the end-user has modified the bootloader the hash of the
 *          modified bootloader can be set here.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportOEMBootloaderHash(arm_uc_buffer_t* hash);

#endif // __ARM_UPDATE_CONTROL_CENTER_H__


