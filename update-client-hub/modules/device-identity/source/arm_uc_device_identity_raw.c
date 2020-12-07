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

#if defined(ARM_UC_FEATURE_IDENTITY_RAW_CONFIG) && (ARM_UC_FEATURE_IDENTITY_RAW_CONFIG == 1)

#define SIZE_OF_GUID (sizeof(arm_uc_guid_t))
// Hex encoded GUIDs with up to 4 hyphens.
#define SIZE_OF_TEXT_GUID ((SIZE_OF_GUID) * 2 + 4)

static arm_uc_guid_t arm_uc_class_id_raw = {0};
static arm_uc_guid_t arm_uc_vendor_id_raw = {0};
static arm_uc_guid_t arm_uc_device_id_raw = {0};

/**
 * @brief Function for setting the vendor GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_raw_setVendorGuid(const arm_uc_guid_t *guid)
{
    arm_uc_error_t err = {ERR_NONE};
    if (guid == NULL) {
        err.code = ARM_UC_DI_ERR_INVALID_PARAMETER;
    } else {
        memcpy(arm_uc_vendor_id_raw, guid, sizeof(arm_uc_guid_t));
    }
    return err;
}

/**
 * @brief Function for getting a pointer to the vendor GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_raw_getVendorGuid(arm_uc_guid_t *guid)
{
    arm_uc_error_t err = {ERR_NONE};
    if (guid == NULL) {
        err.code = ARM_UC_DI_ERR_INVALID_PARAMETER;
    } else {
        memcpy(guid, arm_uc_vendor_id_raw, sizeof(arm_uc_guid_t));
    }
    return err;
}

/**
 * @brief Function for setting the device class GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param copy Boolean value indicating whether the value should be copied or
 *             referenced.
 * @return Error code.
 */
arm_uc_error_t pal_raw_setClassGuid(const arm_uc_guid_t *guid)
{
    arm_uc_error_t err = {ERR_NONE};
    if (guid == NULL) {
        err.code = ARM_UC_DI_ERR_INVALID_PARAMETER;
    } else {
        memcpy(arm_uc_class_id_raw, guid, sizeof(arm_uc_guid_t));
    }
    return err;
}

/**
 * @brief Function for getting a pointer to the device class GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_raw_getClassGuid(arm_uc_guid_t *guid)
{
    arm_uc_error_t err = {ERR_NONE};
    if (guid == NULL) {
        err.code = ARM_UC_DI_ERR_INVALID_PARAMETER;
    } else {
        memcpy(guid, arm_uc_class_id_raw, sizeof(arm_uc_guid_t));
    }
    return err;
}


/**
 * @brief Check whether the three GUIDs provided are valid on the device.
 * @details
 * @param vendor_buffer Buffer pointer to the Vendor GUID.
 * @param class_buffer  Buffer pointer to the device class GUID.
 * @return Error code.
 */
arm_uc_error_t pal_raw_deviceIdentityCheck(const arm_uc_buffer_t *vendor_buffer,
                                           const arm_uc_buffer_t *class_buffer)
{
    // TODO is it correct to use Manifest Manager error codes
    arm_uc_error_t result = { .code = MFST_ERR_NULL_PTR };

    uint8_t parameters_set = 0;
    uint8_t parameters_ok = 0;
    arm_uc_guid_t guid = { 0 };
    arm_uc_buffer_t guid_buffer = {
        .size_max = sizeof(arm_uc_guid_t),
        .size = sizeof(arm_uc_guid_t),
        .ptr = (uint8_t *) &guid
    };

    /* check class - class is optional */
    if (class_buffer &&
            class_buffer->ptr &&
            (class_buffer->size > 0)) {
        parameters_set++;

        arm_uc_error_t retval = pal_raw_getClassGuid(&guid);

        if (retval.code == ERR_NONE) {
            uint32_t rc = ARM_UC_BinCompareCT(&guid_buffer, class_buffer);
            bool is_same = !rc;

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

        arm_uc_error_t retval = pal_raw_getVendorGuid(&guid);

        if (retval.code == ERR_NONE) {
            uint32_t rc = ARM_UC_BinCompareCT(&guid_buffer, vendor_buffer);
            bool is_same = !rc;

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
        result.code = ERR_NONE;
    }

    return result;
}

const ARM_PAL_DEVICE_IDENTITY arm_uc_device_identity_raw = {
    .SetVendorGuid          = pal_raw_setVendorGuid,
    .GetVendorGuid          = pal_raw_getVendorGuid,
    .SetClassGuid           = pal_raw_setClassGuid,
    .GetClassGuid           = pal_raw_getClassGuid,
    .DeviceIdentityCheck    = pal_raw_deviceIdentityCheck
};

#endif // ARM_UC_FEATURE_IDENTITY_RAW_CONFIG
