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
#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_public.h"
#include "update-client-common/arm_uc_scheduler.h"

#include <stdint.h>

typedef enum {
    ARM_UCCC_EVENT_AUTHORIZE_DOWNLOAD,
    ARM_UCCC_EVENT_REJECT_DOWNLOAD,
    ARM_UCCC_EVENT_UNAVAILABLE_DOWNLOAD,
    ARM_UCCC_EVENT_AUTHORIZE_INSTALL,
    ARM_UCCC_EVENT_REJECT_INSTALL,
    ARM_UCCC_EVENT_UNAVAILABLE_INSTALL,
    ARM_UCCC_EVENT_MONITOR_SEND_DONE,
} arm_uc_control_center_event_t;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Initialize Control Center.
 *
 * @param callback Event handler to signal authorizations.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_Initialize(void (*callback)(uintptr_t));

/**
 * @brief Add monitor struct for sending status and results remotely.
 * @details Update Client call for adding remote monitor.
 *
 * @param monitor Pointer to an ARM_UPDATE_MONITOR struct.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_AddMonitor(const ARM_UPDATE_MONITOR *monitor);

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
 * @brief Set callback function for authorizing requests without specific priority.
 * @details User application call for setting callback handler.
 *          The callback function takes an enum request and an authorization
 *          function pointer. To authorize the given request, the caller
 *          invokes the authorization function.
 *
 * @param callback Function pointer to the authorization function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_SetAuthorityHandler(void (*callback)(int32_t)) __attribute__((deprecated("Use ARM_UC_ControlCenter_SetPriorityAuthorityHandler instead")));

/**
 * @brief Set callback function for authorizing requests with specific priority.
 * @details User application call for setting callback handler.
 *          The callback function takes an enum request, an authorization
 *          function pointer and a priority value. To authorize the given
 *          request, the caller invokes the authorization function.
 *
 * @param callback Function pointer to the authorization function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_SetPriorityAuthorityHandler(void (*callback)(int32_t request, uint64_t priority));

/**
 * @brief Request authorization from Control Center.
 * @details Update Client call for asking user application for permission.
 *
 * @param request Request type.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_GetAuthorization(arm_uc_request_t request, uint64_t priority);

/**
 * @brief Authorize request.
 * @details User application call for authorizing request.
 *
 * @param request Request type. Must match the type in callback function.
 */
arm_uc_error_t ARM_UC_ControlCenter_Authorize(arm_uc_request_t request);

/**
 * @brief Reject request.
 * @details User application call for rejecting request.
 *
 * @param request Request type. Must match the type in callback function.
 * @param reason Reason for rejecting the request.
 */
arm_uc_error_t ARM_UC_ControlCenter_Reject(arm_uc_request_t request, arm_uc_reject_reason_t reason);

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
 * @param state Valid states: Any of type arm_uc_monitor_state_t.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportState(arm_uc_monitor_state_t state);

/**
 * return 1 if current state is state
 */
uint8_t ARM_UC_ControlCenter_CheckState(arm_uc_monitor_state_t state);

/**
 * @brief Set update result.
 * @details Update Client call for informing the Control Center about the
 *          latest update result. The Control Center will send this to the monitor.
 *
 * @param result Valid results: Any of type arm_uc_monitor_result_t
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
arm_uc_error_t ARM_UC_ControlCenter_ReportName(arm_uc_buffer_t *name);

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
arm_uc_error_t ARM_UC_ControlCenter_ReportBootloaderHash(arm_uc_buffer_t *hash);

/**
 * @brief Send the OEM bootloader hash to monitor.
 * @details If the end-user has modified the bootloader the hash of the
 *          modified bootloader can be set here.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportOEMBootloaderHash(arm_uc_buffer_t *hash);

#ifdef __cplusplus
}
#endif

#endif // __ARM_UPDATE_CONTROL_CENTER_H__
