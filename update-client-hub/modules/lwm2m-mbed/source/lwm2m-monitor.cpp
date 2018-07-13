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
    ARM_UC_INIT_ERROR(retval, SRCE_ERR_NONE);

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
    ARM_UC_INIT_ERROR(retval, SRCE_ERR_NONE);

    return retval;
}

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
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendState(arm_uc_monitor_state_t state)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = -1;

    switch (state)
    {
        case ARM_UC_MONITOR_STATE_IDLE:
            retval = FirmwareUpdateResource::sendState(
                FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_IDLE);
            break;
        case ARM_UC_MONITOR_STATE_DOWNLOADING:
            retval = FirmwareUpdateResource::sendState(
                FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_DOWNLOADING);
            break;
        case ARM_UC_MONITOR_STATE_DOWNLOADED:
            retval = FirmwareUpdateResource::sendState(
                FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_DOWNLOADED);
            break;
        case ARM_UC_MONITOR_STATE_UPDATING:
            retval = FirmwareUpdateResource::sendState(
                FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_UPDATING);
            break;
        default:
            break;
    }

    if (retval == 0)
    {
        result.code = ERR_NONE;
    }

    return result;
}

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
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendUpdateResult(arm_uc_monitor_result_t updateResult)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = -1;

    switch (updateResult)
    {
        case ARM_UC_MONITOR_RESULT_INITIAL:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_INITIAL);
            break;
        case ARM_UC_MONITOR_RESULT_SUCCESS:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_SUCCESS);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_STORAGE:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_STORAGE);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_MEMORY:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_MEMORY);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_CONNECTION:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_CONNECTION);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_CRC:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_CRC);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_TYPE:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_TYPE);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_URI:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_URI);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_UPDATE:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_UPDATE);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_HASH:
            retval = FirmwareUpdateResource::sendUpdateResult(
                FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_HASH);
            break;
        default:
            break;
    }

    if (retval == 0)
    {
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Send current firmware name.
 * @details The firmware name is the SHA256 hash.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendName(arm_uc_buffer_t* name)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = -1;

    if (name && name->ptr)
    {
        retval = FirmwareUpdateResource::sendPkgName(name->ptr, name->size);
    }

    if (retval == 0)
    {
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Send current firmware version.
 * @details The firmware version is the timestamp from the manifest that
 *          authorized the firmware.
 *
 * @param version Timestamp, 64 bit unsigned integer.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendVersion(uint64_t version)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = FirmwareUpdateResource::sendPkgVersion(version);

    if (retval == 0)
    {
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Set the bootloader hash.
 * @details The bootloader hash is a hash of the bootloader. This is
 *          used for tracking the version of the bootloader used.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetBootloaderHash(arm_uc_buffer_t* hash)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = DeviceMetadataResource::setBootloaderHash(hash);

    if (retval == 0)
    {
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Set the OEM bootloader hash.
 * @details If the end-user has modified the bootloader the hash of the
 *          modified bootloader can be set here.
 *
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash(arm_uc_buffer_t* hash)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = DeviceMetadataResource::setOEMBootloaderHash(hash);

    if (retval == 0)
    {
        result.code = ERR_NONE;
    }

    return result;
}

