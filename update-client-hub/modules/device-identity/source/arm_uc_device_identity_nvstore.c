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

#include "pal4life-device-identity/pal_device_identity.h"
#include "update-client-common/arm_uc_config.h"
#include <stdint.h>

#if defined(ARM_UC_FEATURE_IDENTITY_NVSTORE) && (ARM_UC_FEATURE_IDENTITY_NVSTORE == 1)

#include "CloudClientStorage.h"

#define SIZE_OF_GUID (sizeof(arm_uc_guid_t))
// Hex encoded GUIDs with up to 4 hyphens.
#define SIZE_OF_TEXT_GUID ((SIZE_OF_GUID) * 2 + 4)

/**
 * @brief Helper Function for setting a specific GUID Into NVStore.
 * @details .
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param key The NVSTORE Key where to store the GUID
 * @return Error code.
 */
static arm_uc_error_t pal_nvstore_internal_set_guid(const arm_uc_guid_t *guid,
                                                    cloud_client_param key)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (guid && key) {
        ccs_status_e ccs_status = set_config_parameter(key,
                                                       (const uint8_t *) guid,
                                                       SIZE_OF_GUID);

        if (ccs_status == CCS_STATUS_SUCCESS) {
            result.code = ERR_NONE;
        }
    }

    return result;
}

/**
 * @brief Helper Function for getting a specific GUID From NVStore.
 * @details .
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param key The NVSTORE Key where to get the GUID
 * @return Error code.
 */
static arm_uc_error_t pal_nvstore_internal_get_guid(arm_uc_guid_t *guid,
                                                    cloud_client_param key)
{
    arm_uc_error_t result = { .error = ERR_INVALID_PARAMETER };

    if (guid && key) {
        uint8_t buffer[SIZE_OF_GUID] = { 0 };
        size_t value_length = 0;
        memset(guid, 0, SIZE_OF_GUID);

        ccs_status_e ccs_status = get_config_parameter(key,
                                                       buffer,
                                                       SIZE_OF_GUID,
                                                       &value_length);
        if (ccs_status == CCS_STATUS_KEY_DOESNT_EXIST) {
            result.code = ARM_UC_DI_ERR_NOT_FOUND;
        }

        if (ccs_status == CCS_STATUS_SUCCESS) {
            result.code = ERR_NONE;
            memcpy(guid, buffer, SIZE_OF_GUID);
        }
    }

    return result;
}

/**
 * @brief Helper Function for comparing the GUID from NVStore to
 *        given buffer.
 * @details .
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param buffer buffer which to compare GUID value to
 * @return Error code.
 */
static bool pal_nvstore_internal_compare(const arm_uc_guid_t *guid,
                                         const arm_uc_buffer_t *buffer)
{
    // count how many bytes match
    size_t index = 0;

    if (guid && buffer) {
        for (; (index < sizeof(arm_uc_guid_t)) && (index < buffer->size); index++) {
            if (((uint8_t *) guid)[index] != buffer->ptr[index]) {
                break;
            }
        }
    }
    return (index == sizeof(arm_uc_guid_t));
}

/**
 * @brief Function for setting the vendor GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param copy Boolean value indicating whether the value should be copied or
 *             referenced.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_setVendorGuid(const arm_uc_guid_t *guid)
{
    return pal_nvstore_internal_set_guid(guid,
                                         KEY_VENDOR_ID);
}

/**
 * @brief Function for getting a pointer to the vendor GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_getVendorGuid(arm_uc_guid_t *guid)
{
    return pal_nvstore_internal_get_guid(guid,
                                         KEY_VENDOR_ID);
}

/**
 * @brief Function for setting the device class GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param copy Boolean value indicating whether the value should be copied or
 *             referenced.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_setClassGuid(const arm_uc_guid_t *guid)
{
    return pal_nvstore_internal_set_guid(guid,
                                         KEY_CLASS_ID);
}

/**
 * @brief Function for getting a pointer to the device class GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_getClassGuid(arm_uc_guid_t *guid)
{
    return pal_nvstore_internal_get_guid(guid,
                                         KEY_CLASS_ID);

}

/**
 * @brief Function for setting the device GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param copy Boolean value indicating whether the value should be copied or
 *             referenced.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_setDeviceGuid(const arm_uc_guid_t *guid)
{
    return pal_nvstore_internal_set_guid(guid,
                                         ENDPOINT_NAME);
}

/**
 * @brief Function for getting a pointer to the device GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_getDeviceGuid(arm_uc_guid_t *guid)
{
    return pal_nvstore_internal_get_guid(guid,
                                         ENDPOINT_NAME);
}


/**
 * @brief Check whether the three GUIDs provided are valid on the device.
 * @details
 * @param vendor_buffer Buffer pointer to the Vendor GUID.
 * @param class_buffer  Buffer pointer to the device class GUID.
 * @param device_buffer Buffer pointer to the device GUID.
 * @param isValid     Pointer to the boolean return value.
 * @return Error code.
 */
arm_uc_error_t pal_nvstore_deviceIdentityCheck(const arm_uc_buffer_t *vendor_buffer,
                                               const arm_uc_buffer_t *class_buffer,
                                               const arm_uc_buffer_t *device_buffer)
{
    arm_uc_error_t result = { .code = MFST_ERR_NULL_PTR };

    uint8_t parameters_set = 0;
    uint8_t parameters_ok = 0;

    /* check device - device is optional */
    if (device_buffer &&
            device_buffer->ptr &&
            (device_buffer->size > 0)) {
        parameters_set++;

        arm_uc_guid_t guid = { 0 };

        arm_uc_error_t retval = pal_nvstore_getDeviceGuid(&guid);

        if (retval.code == ERR_NONE) {
            bool is_same = pal_nvstore_internal_compare(&guid, device_buffer);

            if (is_same) {
                parameters_ok++;
            } else {
                result.code = MFST_ERR_GUID_DEVICE;
            }
        }
    }

    /* check class - class is optional */
    if (class_buffer &&
            class_buffer->ptr &&
            (class_buffer->size > 0)) {
        parameters_set++;

        arm_uc_guid_t guid = { 0 };

        arm_uc_error_t retval = pal_nvstore_getClassGuid(&guid);

        if (retval.code == ERR_NONE) {
            bool is_same = pal_nvstore_internal_compare(&guid, class_buffer);

            if (is_same) {
                parameters_ok++;
            } else {
                result.code = MFST_ERR_GUID_DEVCLASS;
            }
        }
    }

    /* check vendor - vendor is mandatory and has mask 0x10. */
    if (vendor_buffer &&
            vendor_buffer->ptr &&
            (vendor_buffer->size > 0)) {
        parameters_set += 0x10;

        arm_uc_guid_t guid = { 0 };

        arm_uc_error_t retval = pal_nvstore_getVendorGuid(&guid);

        if (retval.code == ERR_NONE) {
            bool is_same = pal_nvstore_internal_compare(&guid, vendor_buffer);

            if (is_same) {
                parameters_ok += 0x10;
            } else {
                result.code = MFST_ERR_GUID_VENDOR;
            }
        }
    }

    /* Device ID checks out when:
        - vendor match and neither class nor device is passed
        - vendor and class match and no device is passed
        - vendor and device match and no class is passed
        - vendor and class and device match
    */
    if ((parameters_set >= 0x10) && (parameters_set == parameters_ok)) {
        result.code = MFST_ERR_NONE;
    }

    return result;
}

const ARM_PAL_DEVICE_IDENTITY arm_uc_device_identity_nvstore = {
    .SetVendorGuid          = pal_nvstore_setVendorGuid,
    .GetVendorGuid          = pal_nvstore_getVendorGuid,
    .SetClassGuid           = pal_nvstore_setClassGuid,
    .GetClassGuid           = pal_nvstore_getClassGuid,
    .SetDeviceGuid          = pal_nvstore_setDeviceGuid,
    .GetDeviceGuid          = pal_nvstore_getDeviceGuid,
    .DeviceIdentityCheck    = pal_nvstore_deviceIdentityCheck
};

#endif // ARM_UC_FEATURE_IDENTITY_NVSTORE
