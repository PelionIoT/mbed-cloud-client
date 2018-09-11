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

    switch (state) {
        case ARM_UC_MONITOR_STATE_IDLE:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_IDLE);
            break;
        case ARM_UC_MONITOR_STATE_PROCESSING_MANIFEST:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_PROCESSING_MANIFEST);
            break;
        case ARM_UC_MONITOR_STATE_AWAITING_DOWNLOAD_APPROVAL:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_AWAITING_DOWNLOAD_APPROVAL);
            break;
        case ARM_UC_MONITOR_STATE_DOWNLOADING:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_DOWNLOADING);
            break;
        case ARM_UC_MONITOR_STATE_DOWNLOADED:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_DOWNLOADED);
            break;
        case ARM_UC_MONITOR_STATE_AWAITING_APP_APPROVAL:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_AWAITING_APP_APPROVAL);
            break;
        case ARM_UC_MONITOR_STATE_UPDATING:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_UPDATING);
            break;
        case ARM_UC_MONITOR_STATE_REBOOTING:
            retval = FirmwareUpdateResource::sendState(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_STATE_REBOOTING);
            break;
        default:
            break;
    }

    if (retval == 0) {
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
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendUpdateResult(arm_uc_monitor_result_t updateResult)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = -1;

    switch (updateResult) {
        case ARM_UC_MONITOR_RESULT_INITIAL:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_INITIAL);
            break;
        case ARM_UC_MONITOR_RESULT_SUCCESS:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_SUCCESS);
            break;
        case ARM_UC_MONITOR_RESULT_MANIFEST_TIMEOUT:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_MANIFEST_TIMEOUT);
            break;
        case ARM_UC_MONITOR_RESULT_MANIFEST_NOT_FOUND:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_MANIFEST_NOT_FOUND);
            break;
        case ARM_UC_MONITOR_RESULT_MANIFEST_FAILED_INTEGRITY:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_MANIFEST_FAILED_INTEGRITY);
            break;
        case ARM_UC_MONITOR_RESULT_MANIFEST_REJECTED:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_MANIFEST_REJECTED);
            break;
        case ARM_UC_MONITOR_RESULT_MANIFEST_CERT_NOT_FOUND:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_MANIFEST_CERT_NOT_FOUND);
            break;
        case ARM_UC_MONITOR_RESULT_MANIFEST_SIGNATURE_FAILED:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_MANIFEST_SIGNATURE_FAILED);
            break;
        case ARM_UC_MONITOR_RESULT_DEPENDENT_MANIFEST_NOT_FOUND:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_DEPENDENT_MANIFEST_NOT_FOUND);
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
        case ARM_UC_MONITOR_RESULT_UNSUPPORTED_DELTA_FORMAT:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_UNSUPPORTED_DELTA_FORMAT);
            break;
        case ARM_UC_MONITOR_RESULT_ERROR_HASH:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ERROR_HASH);
            break;
        case ARM_UC_MONITOR_RESULT_ASSET_UPDATE_COMPLETED:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ASSET_UPDATE_COMPLETED);
            break;
        case ARM_UC_MONITOR_RESULT_ASSET_UPDATED_AFTER_RECOVERY:
            retval = FirmwareUpdateResource::sendUpdateResult(
                         FirmwareUpdateResource::ARM_UCS_LWM2M_RESULT_ASSET_UPDATED_AFTER_RECOVERY);
            break;
        default:
            break;
    }

    if (retval == 0) {
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
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SendName(arm_uc_buffer_t *name)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = -1;

    if (name && name->ptr) {
        retval = FirmwareUpdateResource::sendPkgName(name->ptr, name->size);
    }

    if (retval == 0) {
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

    if (retval == 0) {
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
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetBootloaderHash(arm_uc_buffer_t *hash)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = DeviceMetadataResource::setBootloaderHash(hash);

    if (retval == 0) {
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
arm_uc_error_t ARM_UCS_LWM2M_MONITOR_SetOEMBootloaderHash(arm_uc_buffer_t *hash)
{
    ARM_UC_INIT_ERROR(result, ERR_INVALID_PARAMETER);

    int32_t retval = DeviceMetadataResource::setOEMBootloaderHash(hash);

    if (retval == 0) {
        result.code = ERR_NONE;
    }

    return result;
}

