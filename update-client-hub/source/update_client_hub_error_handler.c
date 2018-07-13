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

#include "update_client_hub_error_handler.h"

#include "update-client-control-center/arm_uc_control_center.h"
#include "update-client-common/arm_uc_common.h"

static void (*arm_uc_error_callback_handler)(int32_t error) = NULL;

void ARM_UC_HUB_AddErrorCallbackInternal(void (*callback)(int32_t error))
{
    arm_uc_error_callback_handler = callback;
}

/**
 * @brief Error handler.
 * @details Generates error code for the user application and any registered
 *          monitors. Also responsible for setting the Hub back to a consistent
 *          state.
 *
 *          Supported error codes:
 *
 *          ARM_UC_MONITOR_RESULT_INITIAL
 *          ARM_UC_MONITOR_RESULT_SUCCESS
 *          ARM_UC_MONITOR_RESULT_ERROR_STORAGE
 *          ARM_UC_MONITOR_RESULT_ERROR_MEMORY
 *          ARM_UC_MONITOR_RESULT_ERROR_CONNECTION
 *          ARM_UC_MONITOR_RESULT_ERROR_CRC
 *          ARM_UC_MONITOR_RESULT_ERROR_TYPE
 *          ARM_UC_MONITOR_RESULT_ERROR_URI
 *          ARM_UC_MONITOR_RESULT_ERROR_UPDATE
 *          ARM_UC_MONITOR_RESULT_ERROR_HASH
 *
 * @param error arm_uc_error_t code.
 * @param state Internal Hub state.
 */
void ARM_UC_HUB_ErrorHandler(int32_t error, arm_uc_hub_state_t state)
{
    UC_HUB_TRACE("error: %" PRIX32 " %d", (uint32_t) error, state);

    int32_t error_external = ARM_UC_WARNING_UNKNOWN;
    arm_uc_monitor_result_t error_monitor = ARM_UC_MONITOR_RESULT_INITIAL;
    arm_uc_hub_state_t next_state = ARM_UC_HUB_STATE_WAIT_FOR_ERROR_ACK;

    switch (error)
    {
        /* Certificate Manager */
        case ARM_UC_CM_ERR_NOT_FOUND:
            UC_HUB_ERR_MSG("ARM_UC_CM_ERR_NOT_FOUND: %" PRIX32,
                           (uint32_t) ARM_UC_CM_ERR_NOT_FOUND);
            error_external = ARM_UC_WARNING_CERTIFICATE_NOT_FOUND;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        /* Firmware Manager */
        case FIRM_ERR_WRITE:
            UC_HUB_ERR_MSG("FIRM_ERR_WRITE: %" PRIX32,
                           (uint32_t) FIRM_ERR_WRITE);
            error_external = ARM_UC_ERROR_WRITE_TO_STORAGE;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_STORAGE;
            break;

        case FIRM_ERR_INVALID_PARAMETER:
            UC_HUB_ERR_MSG("FIRM_ERR_INVALID_PARAMETER: %" PRIX32,
                           (uint32_t) FIRM_ERR_INVALID_PARAMETER);
            error_external = ARM_UC_ERROR_WRITE_TO_STORAGE;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_STORAGE;
            break;

        case FIRM_ERR_INVALID_HASH:
            UC_HUB_ERR_MSG("FIRM_ERR_INVALID_HASH: %" PRIX32,
                           (uint32_t) FIRM_ERR_INVALID_HASH);
            error_external = ARM_UC_ERROR_INVALID_HASH;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_HASH;
            break;

        /* Manifest Manager */
        case MFST_ERR_NULL_PTR:
            UC_HUB_ERR_MSG("MFST_ERR_NULL_PTR: %" PRIX32,
                           (uint32_t) MFST_ERR_NULL_PTR);
            error_external = ARM_UC_WARNING_IDENTITY_NOT_FOUND;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        case MFST_ERR_GUID_VENDOR:
            UC_HUB_ERR_MSG("MFST_ERR_GUID_VENDOR: %" PRIX32,
                           (uint32_t) MFST_ERR_GUID_VENDOR);
            error_external = ARM_UC_WARNING_VENDOR_MISMATCH;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        case MFST_ERR_GUID_DEVCLASS:
            UC_HUB_ERR_MSG("MFST_ERR_GUID_DEVCLASS: %" PRIX32,
                           (uint32_t) MFST_ERR_GUID_DEVCLASS);
            error_external = ARM_UC_WARNING_CLASS_MISMATCH;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        case MFST_ERR_GUID_DEVICE:
            UC_HUB_ERR_MSG("MFST_ERR_GUID_DEVICE: %" PRIX32,
                           (uint32_t) MFST_ERR_GUID_DEVICE);
            error_external = ARM_UC_WARNING_DEVICE_MISMATCH;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        case MFST_ERR_CERT_INVALID:
            UC_HUB_ERR_MSG("MFST_ERR_CERT_INVALID: %" PRIX32,
                           (uint32_t) MFST_ERR_CERT_INVALID);
            error_external = ARM_UC_WARNING_CERTIFICATE_INVALID;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        case MFST_ERR_INVALID_SIGNATURE:
            UC_HUB_ERR_MSG("MFST_ERR_INVALID_SIGNATURE: %" PRIX32,
                           (uint32_t) MFST_ERR_INVALID_SIGNATURE);
            error_external = ARM_UC_WARNING_SIGNATURE_INVALID;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;

        /* Source Manager */
        case SOMA_ERR_INVALID_PARAMETER:
            UC_HUB_ERR_MSG("SOMA_ERR_INVALID_PARAMETER: %" PRIX32,
                           (uint32_t) SOMA_ERR_INVALID_PARAMETER);
            error_external = ARM_UC_WARNING_URI_NOT_FOUND;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_URI;
            break;

        /* Hub */
        case HUB_ERR_INTERNAL_ERROR:
            UC_HUB_ERR_MSG("HUB_ERR_INTERNAL_ERROR: %" PRIX32,
                           (uint32_t) HUB_ERR_INTERNAL_ERROR);
            error_external = ARM_UC_FATAL;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_UPDATE;
            break;

        case HUB_ERR_ROLLBACK_PROTECTION:
            UC_HUB_ERR_MSG("HUB_ERR_ROLLBACK_PROTECTION: %" PRIX32,
                           (uint32_t) HUB_ERR_ROLLBACK_PROTECTION);
            error_external = ARM_UC_WARNING_ROLLBACK_PROTECTION;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_UPDATE;
            break;

        /* LWM2M source */
        case HUB_ERR_CONNECTION:
            UC_HUB_ERR_MSG("HUB_ERR_CONNECTION: %" PRIX32,
                           (uint32_t) HUB_ERR_CONNECTION);
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_CONNECTION;
            /* Prevent a possible infinite loop: when HUB_ERR_CONNECTION is received,
               the next state was always set to ARM_UC_HUB_STATE_UNKNOWN. However,
               this function also sends a report which might fail, which will trigger
               the HUB_ERR_CONNECTION event and will repeat the whole process again,
               potentially in an inifinite loop in case of network issues. So switch
               the state to "idle" directly to prevent this.*/
            next_state = ARM_UC_HUB_STATE_IDLE;
            break;

        default:
            UC_HUB_ERR_MSG("Unknown error");
            error_external = ARM_UC_WARNING_UNKNOWN;
            error_monitor = ARM_UC_MONITOR_RESULT_ERROR_TYPE;
            break;
    }

    /* send error code to monitor */
    ARM_UC_ControlCenter_ReportUpdateResult(error_monitor);

    /* progress state in hub */
    ARM_UC_HUB_setState(next_state);

    /* Send the external code to the user application. */
    if (arm_uc_error_callback_handler) {
        arm_uc_error_callback_handler(error_external);
    }

}

