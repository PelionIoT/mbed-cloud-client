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

#include "update-lwm2m-mbed-apis.h"
#include "update-client-lwm2m/lwm2m-monitor.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-lwm2m/DeviceMetadataResource.h"

/**
 * @brief Get driver version.
 * @return Driver version.
 */
uint32_t ARM_UCS_LWM2M_MONITOR_GetVersion(void)
{
    return 0;
}

/**
 * @brief Get Source capabilities.
 * @return Struct containing capabilites. See definition above.
 */
ARM_MONITOR_CAPABILITIES ARM_UCS_LWM2M_MONITOR_GetCapabilities(void)
{
    ARM_MONITOR_CAPABILITIES result;
    result.state   = 1;
    result.result  = 1;
    result.version = 1;

    return result;
}

/**
 * @brief Initialize Monitor.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_Initialize(void (*notification_handler)(void))
{
    ARM_UC_INIT_ERROR(retval, ERR_NONE);

    FirmwareUpdateResource::Initialize();
    FirmwareUpdateResource::addNotificationCallback(notification_handler);

    DeviceMetadataResource::Initialize();

    return retval;
}

/**
 * @brief Uninitialized Monitor.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_Uninitialize(void)
{
    ARM_UC_INIT_ERROR(retval, ERR_NONE);
    return retval;
}

/**
 * @brief Send Update Client state.
 * @details From the OMA LWM2M Technical Specification:
 *
 *          Indicates current state with respect to this firmware update.
 *          This value is set by the LWM2M Client in accordance with state
 *          and arm_uc_monitor_state_t type.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendState(arm_uc_monitor_state_t an_update_state)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    // If out of range of a legitimate update-state, return an "invalid-parameter" error to the caller,
    //   otherwise try send the new state to the monitor.
    if (!ARM_UC_IsValidState(an_update_state)) {
        ARM_UC_SET_ERROR(result, ERR_INVALID_PARAMETER);
    } else {
        FirmwareUpdateResource::arm_ucs_lwm2m_state_t state =
            (FirmwareUpdateResource::arm_ucs_lwm2m_state_t)an_update_state;
        if (FirmwareUpdateResource::sendState(state) != 0) {
            ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
        }
    }
    return result;
}

/**
 * @brief Send update result.
 * @details From the OMA LWM2M Technical Specification:
 *          Contains the result of downloading or updating the firmware
 *          This Resource MAY be reported by sending Observe operation.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendUpdateResult(arm_uc_monitor_result_t an_update_result)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    // If out of range of a legitimate update-result, send an "unspecified-error" result.
    if (!ARM_UC_IsValidResult(an_update_result)) {
        ARM_UC_SET_ERROR(result, ERR_INVALID_PARAMETER);
    } else {
        // Cast the arm_uc_monitor_result_t to a arm_ucs_lwm2m_result_t, and send it.
        FirmwareUpdateResource::arm_ucs_lwm2m_result_t code =
            (FirmwareUpdateResource::arm_ucs_lwm2m_result_t)an_update_result;
        if (FirmwareUpdateResource::sendUpdateResult(code) != 0) {
            ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
        }
    }
    return result;
}

/**
 * @brief Send current firmware name.
 * @details The firmware name is the SHA256 hash.
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendName(arm_uc_buffer_t *name)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);
    if (!name || !name->ptr) {
        ARM_UC_SET_ERROR(result, ERR_INVALID_PARAMETER);
    } else if (FirmwareUpdateResource::sendPkgName(name->ptr, name->size) != 0) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }
    return result;
}

/**
 * @brief Send current firmware version.
 * @details The firmware version is the timestamp from the manifest that
 *          authorized the firmware.
 * @param version Timestamp, 64 bit unsigned integer.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendVersion(uint64_t version)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);
    if (FirmwareUpdateResource::sendPkgVersion(version) != 0) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }
    return result;
}

/**
 * @brief Set the bootloader hash.
 * @details The bootloader hash is a hash of the bootloader. This is
 *          used for tracking the version of the bootloader used.
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetBootloaderHash(arm_uc_buffer_t *hash)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);
    if (DeviceMetadataResource::setBootloaderHash(hash) != 0) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }
    return result;
}

/**
 * @brief Set the OEM bootloader hash.
 * @details If the end-user has modified the bootloader the hash of the
 *          modified bootloader can be set here.
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash(arm_uc_buffer_t *hash)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);
    if (DeviceMetadataResource::setOEMBootloaderHash(hash) != 0) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }
    return result;
}

