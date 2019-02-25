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

#include "update-client-control-center/arm_uc_control_center.h"
#include "update-client-common/arm_uc_trace.h"

#include <stdbool.h>

/* event handler */
static void (*arm_uccc_event_handler)(uintptr_t) = NULL;
static arm_uc_callback_t arm_uccc_authorize_callback = { 0 };
static arm_uc_callback_t arm_uccc_monitor_callback = { 0 };

/* authorization callback */
static void (*arm_uc_authority_callback)(int32_t) = NULL;
static bool arm_uc_download_token_armed = false;
static bool arm_uc_install_token_armed = false;

/* force authorization */
static arm_uc_callback_t arm_uccc_override_callback = { 0 };

static void arm_uccc_override_task(uintptr_t unused);

/* progress callback */
static void (*arm_uc_progress_callback)(uint32_t, uint32_t) = NULL;

/* function pointer structs */
static const ARM_UPDATE_MONITOR *arm_uc_monitor_struct = NULL;

static void ARM_UC_ControlCenter_Notification_Handler(void)
{
    if (arm_uccc_event_handler) {
        ARM_UC_PostCallback(&arm_uccc_monitor_callback,
                            arm_uccc_event_handler,
                            ARM_UCCC_EVENT_MONITOR_SEND_DONE);
    }
}

/**
 * @brief Initialize Control Center.
 *
 * @param callback Event handler to signal authorizations.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_Initialize(void (*callback)(uintptr_t))
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_Initialize: %p", callback);

    arm_uccc_event_handler = callback;

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Add monitor struct for sending status and results remotely.
 *
 * @param monitor Pointer to an ARM_UPDATE_MONITOR struct.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_AddMonitor(const ARM_UPDATE_MONITOR *monitor)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_AddMonitor: %p", monitor);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    arm_uc_monitor_struct = monitor;

    if (arm_uc_monitor_struct) {
        result = arm_uc_monitor_struct->Initialize(ARM_UC_ControlCenter_Notification_Handler);
    }

    return result;
}

/**
 * @brief Set callback for receiving download progress.
 * @details User application call for setting callback handler.
 *          The callback function takes the progreess in percent as argument.
 *
 * @param callback Function pointer to the progress function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_SetProgressHandler(void (*callback)(uint32_t progress, uint32_t total))
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_SetProgressHandler: %p", callback);

    arm_uc_progress_callback = callback;

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Set callback function for authorizing requests.
 * @details The callback function takes an enum request and an authorization
 *          function pointer. To authorize the given request, the caller
 *          invokes the authorization function.
 *
 * @param callback Function pointer to the authorization function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_SetAuthorityHandler(void (*callback)(int32_t))
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_SetAuthorityHandler: %p", callback);

    arm_uc_authority_callback = callback;

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Request authorization from Control Center.
 *
 * @param type Request type.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_GetAuthorization(arm_uc_request_t request)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_GetAuthorization: %d", (int) request);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    switch (request) {
        case ARM_UCCC_REQUEST_DOWNLOAD:
            /* Arm callback token */
            arm_uc_download_token_armed = true;

            if (arm_uc_authority_callback) {
                arm_uc_authority_callback(ARM_UCCC_REQUEST_DOWNLOAD);
            } else {
                ARM_UC_ControlCenter_Authorize(ARM_UCCC_REQUEST_DOWNLOAD);
            }
            result.code = ERR_NONE;
            break;

        case ARM_UCCC_REQUEST_INSTALL:
            /* Arm callback token */
            arm_uc_install_token_armed = true;

            if (arm_uc_authority_callback) {
                arm_uc_authority_callback(ARM_UCCC_REQUEST_INSTALL);
            } else {
                ARM_UC_ControlCenter_Authorize(ARM_UCCC_REQUEST_INSTALL);
            }
            result.code = ERR_NONE;
            break;
        default:
            break;
    }

    return result;
}

/**
 * @brief Authorize request.
 *
 * @param request Request type. Must match the type in callback function.
 */
arm_uc_error_t ARM_UC_ControlCenter_Authorize(arm_uc_request_t request)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_Authorize: %d", (int) request);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    switch (request) {
        case ARM_UCCC_REQUEST_DOWNLOAD:
            if (arm_uccc_event_handler && arm_uc_download_token_armed) {
                arm_uc_download_token_armed = false;

                ARM_UC_PostCallback(&arm_uccc_authorize_callback,
                                    arm_uccc_event_handler,
                                    ARM_UCCC_EVENT_AUTHORIZE_DOWNLOAD);

                result.code = ERR_NONE;
            }
            break;

        case ARM_UCCC_REQUEST_INSTALL:
            if (arm_uccc_event_handler && arm_uc_install_token_armed) {
                arm_uc_install_token_armed = false;

                ARM_UC_PostCallback(&arm_uccc_authorize_callback,
                                    arm_uccc_event_handler,
                                    ARM_UCCC_EVENT_AUTHORIZE_INSTALL);

                result.code = ERR_NONE;
            }
            break;

        default:
            break;
    }

    return result;
}

/**
 * @brief Override update authorization handler.
 * @details Force download and update to progress regardless of authorization
 *          handler. This function is used for unblocking an update in a buggy
 *          application.
 */
void ARM_UC_ControlCenter_OverrideAuthorization(void)
{
    ARM_UC_PostCallback(&arm_uccc_override_callback,
                        arm_uccc_override_task,
                        0);
}

static void arm_uccc_override_task(uintptr_t unused)
{
    (void) unused;

    UC_CONT_TRACE("arm_uccc_override_task");

    if (arm_uc_download_token_armed) {
        arm_uc_download_token_armed = false;

        /* force authorization */
        if (arm_uccc_event_handler) {
            arm_uccc_event_handler(ARM_UCCC_EVENT_AUTHORIZE_DOWNLOAD);
        }
    } else if (arm_uc_install_token_armed) {
        arm_uc_install_token_armed = false;

        /* force authorization */
        if (arm_uccc_event_handler) {
            arm_uccc_event_handler(ARM_UCCC_EVENT_AUTHORIZE_INSTALL);
        }
    }

    /* disable authorization function */
    arm_uc_authority_callback = NULL;
}

/**
 * @brief Report download progress.
 * @details Update Client call for informing the Control Center about the
 *          current download progress. The Control Center will send this to the
 *          appication handler and the monitor if either/both are attached.
 *
 * @param progrss Bytes already downloaded.
 * @param total Total amount of bytes in download.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportProgress(uint32_t progress, uint32_t total)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportProgress: %" PRIu32 " / %" PRIu32, progress, total);

    /* only forward request if callback is set. */
    if (arm_uc_progress_callback) {
        arm_uc_progress_callback(progress, total);
    }

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Send Update Client state.
 * @param state Update Client state.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportState(arm_uc_monitor_state_t state)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportState: %d", (int) state);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (arm_uc_monitor_struct) {
        arm_uc_monitor_struct->SendState(state);
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Set update result.
 * @param result Update result.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportUpdateResult(arm_uc_monitor_result_t updateResult)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportUpdateResult: %d", (int) updateResult);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (arm_uc_monitor_struct) {
        arm_uc_monitor_struct->SendUpdateResult(updateResult);
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Set current firmware name.
 * @details Update Client call for informing the Control Center about the
 *          current firmware name. The Control Center will send this to the
 *          monitor. The firmware name is the SHA256 hash.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportName(arm_uc_buffer_t *name)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportName: %p", name);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (arm_uc_monitor_struct) {
        arm_uc_monitor_struct->SendName(name);
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Set current firmware version.
 * @details The firmware version is the SHA256 hash.
 *
 * @param version Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportVersion(uint64_t version)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportVersion: %" PRIu64, version);

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (arm_uc_monitor_struct) {
        arm_uc_monitor_struct->SendVersion(version);
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Send bootloader hash to monitor.
 * @details The bootloader hash is a hash of the bootloader. This is
 *          used for tracking the version of the bootloader used.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportBootloaderHash(arm_uc_buffer_t *hash)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportBootloaderHash");

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (arm_uc_monitor_struct && arm_uc_monitor_struct->SetBootloaderHash) {
        result = arm_uc_monitor_struct->SetBootloaderHash(hash);
    }

    return result;
}

/**
 * @brief Send the OEM bootloader hash to monitor.
 * @details If the end-user has modified the bootloader the hash of the
 *          modified bootloader can be set here.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_ControlCenter_ReportOEMBootloaderHash(arm_uc_buffer_t *hash)
{
    UC_CONT_TRACE("ARM_UC_ControlCenter_ReportOEMBootloaderHash");

    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (arm_uc_monitor_struct && arm_uc_monitor_struct->SetOEMBootloaderHash) {
        result = arm_uc_monitor_struct->SetOEMBootloaderHash(hash);
    }

    return result;
}
