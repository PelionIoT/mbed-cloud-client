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

#ifndef ARM_UC_USE_KCM
#define ARM_UC_USE_KCM 0
#endif

#if ARM_UC_USE_KCM

#include "key-config-manager/key_config_manager.h"

#define SIZE_OF_GUID (sizeof(arm_uc_guid_t))
// Hex encoded GUIDs with up to 4 hyphens.
#define SIZE_OF_TEXT_GUID ((SIZE_OF_GUID) * 2 + 4)

/* these defines are copied from:
   mbed-cloud-client/source/include/CloudClientStorage.h
*/
#define KEY_DEVICE_MANUFACTURER_DEPRECATED      "mbed.Manufacturer"
#define KEY_DEVICE_MODELNUMBER_DEPRECATED       "mbed.ModelNumber"
#define KEY_ENDPOINT_NAME                       "mbed.EndpointName"
#define KEY_VENDOR_ID                           "mbed.VendorId"
#define KEY_CLASS_ID                            "mbed.ClassId"

static arm_uc_error_t pal_kcm_internal_set_guid(const arm_uc_guid_t* guid,
                                                const char* key,
                                                size_t key_length)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (guid && key)
    {
        kcm_status_e kcm_status = kcm_item_store((const uint8_t*) key,
                                                 key_length,
                                                 KCM_CONFIG_ITEM,
                                                 true,
                                                 (const uint8_t*) guid,
                                                 SIZE_OF_GUID,
                                                 NULL);

        if (kcm_status == KCM_STATUS_SUCCESS)
        {
            result.code = ERR_NONE;
        }
    }

    return result;
}

static arm_uc_error_t pal_kcm_internal_get_guid(arm_uc_guid_t* guid,
                                                const char* key,
                                                size_t key_length)
{
    arm_uc_error_t result = { .module = TWO_CC('D', 'I'), .error = ERR_INVALID_PARAMETER };

    if (guid && key)
    {
        uint8_t buffer[SIZE_OF_GUID] = { 0 };
        size_t value_length = 0;
        memset(guid, 0, SIZE_OF_GUID);

        kcm_status_e kcm_status = kcm_item_get_data((const uint8_t*) key,
                                        key_length,
                                        KCM_CONFIG_ITEM,
                                        buffer,
                                        SIZE_OF_GUID,
                                        &value_length);
        if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND)
        {
            result.code = ARM_UC_DI_ERR_NOT_FOUND;
        }

        if (kcm_status == KCM_STATUS_SUCCESS)
        {
            result.code = ERR_NONE;
            memcpy(guid, buffer, SIZE_OF_GUID);
        }
    }

    return result;
}

static bool pal_kcm_internal_compare(const arm_uc_guid_t* guid,
                                     const arm_uc_buffer_t* buffer)
{
    // count how many bytes match
    uint8_t index = 0;

    if (guid && buffer)
    {
        for ( ; (index < sizeof(arm_uc_guid_t)) && (index < buffer->size); index++)
        {
            // printf("%02X %02X\r\n", ((uint8_t*) guid)[index], buffer->ptr[index]);

            if (((uint8_t*) guid)[index] != buffer->ptr[index])
            {
                break;
            }
        }
    }

    // return true if all bytes matched
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
arm_uc_error_t pal_kcm_setVendorGuid(const arm_uc_guid_t* guid)
{
    return pal_kcm_internal_set_guid(guid,
                                     KEY_VENDOR_ID,
                                     sizeof(KEY_VENDOR_ID) - 1);
}

/**
 * @brief Function for getting a pointer to the vendor GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_kcm_getVendorGuid(arm_uc_guid_t* guid)
{
    arm_uc_error_t err = pal_kcm_internal_get_guid(guid,
                                    KEY_VENDOR_ID,
                                    sizeof(KEY_VENDOR_ID) - 1);
    if (err.code == ARM_UC_DI_ERR_NOT_FOUND)
    {
        err = pal_kcm_internal_get_guid(guid,
                                    KEY_DEVICE_MANUFACTURER_DEPRECATED,
                                    sizeof(KEY_DEVICE_MANUFACTURER_DEPRECATED) - 1);
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
arm_uc_error_t pal_kcm_setClassGuid(const arm_uc_guid_t* guid)
{
    return pal_kcm_internal_set_guid(guid,
                                     KEY_CLASS_ID,
                                     sizeof(KEY_CLASS_ID) - 1);
}

/**
 * @brief Function for getting a pointer to the device class GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_kcm_getClassGuid(arm_uc_guid_t* guid)
{
    arm_uc_error_t err = pal_kcm_internal_get_guid(guid,
                                    KEY_CLASS_ID,
                                    sizeof(KEY_CLASS_ID) - 1);
    if (err.code == ARM_UC_DI_ERR_NOT_FOUND)
    {
        err = pal_kcm_internal_get_guid(guid,
                                    KEY_DEVICE_MODELNUMBER_DEPRECATED,
                                    sizeof(KEY_DEVICE_MODELNUMBER_DEPRECATED) - 1);
    }
    return err;
}

/**
 * @brief Function for setting the device GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @param copy Boolean value indicating whether the value should be copied or
 *             referenced.
 * @return Error code.
 */
arm_uc_error_t pal_kcm_setDeviceGuid(const arm_uc_guid_t* guid)
{
    return pal_kcm_internal_set_guid(guid,
                                     KEY_ENDPOINT_NAME,
                                     sizeof(KEY_ENDPOINT_NAME) - 1);
}

/**
 * @brief Function for getting a pointer to the device GUID.
 * @param guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_kcm_getDeviceGuid(arm_uc_guid_t* guid)
{
    return pal_kcm_internal_get_guid(guid,
                                     KEY_ENDPOINT_NAME,
                                     sizeof(KEY_ENDPOINT_NAME) - 1);
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
arm_uc_error_t pal_kcm_deviceIdentityCheck(const arm_uc_buffer_t* vendor_buffer,
                                           const arm_uc_buffer_t* class_buffer,
                                           const arm_uc_buffer_t* device_buffer)
{
    arm_uc_error_t result = { .code = MFST_ERR_NULL_PTR };

    uint8_t parameters_set = 0;
    uint8_t parameters_ok = 0;

    /* check device - device is optional */
    if (device_buffer &&
        device_buffer->ptr &&
        (device_buffer->size > 0))
    {
        parameters_set++;

        arm_uc_guid_t guid = { 0 };

        arm_uc_error_t retval = pal_kcm_getDeviceGuid(&guid);

        if (retval.code == ERR_NONE)
        {
            bool is_same = pal_kcm_internal_compare(&guid, device_buffer);

            if (is_same)
            {
                parameters_ok++;
            }
            else
            {
                result.code = MFST_ERR_GUID_DEVICE;
            }
        }
    }

    /* check class - class is optional */
    if (class_buffer &&
        class_buffer->ptr &&
        (class_buffer->size > 0))
    {
        parameters_set++;

        arm_uc_guid_t guid = { 0 };

        arm_uc_error_t retval = pal_kcm_getClassGuid(&guid);

        if (retval.code == ERR_NONE)
        {
            bool is_same = pal_kcm_internal_compare(&guid, class_buffer);

            if (is_same)
            {
                parameters_ok++;
            }
            else
            {
                result.code = MFST_ERR_GUID_DEVCLASS;
            }
        }
    }

    /* check vendor - vendor is mandatory and has mask 0x10. */
    if (vendor_buffer &&
        vendor_buffer->ptr &&
        (vendor_buffer->size > 0))
    {
        parameters_set += 0x10;

        arm_uc_guid_t guid = { 0 };

        arm_uc_error_t retval = pal_kcm_getVendorGuid(&guid);

        if (retval.code == ERR_NONE)
        {
            bool is_same = pal_kcm_internal_compare(&guid, vendor_buffer);

            if (is_same)
            {
                parameters_ok += 0x10;
            }
            else
            {
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
    if ((parameters_set >= 0x10) && (parameters_set == parameters_ok))
    {
        result.code = MFST_ERR_NONE;
    }

    return result;
}

const ARM_PAL_DEVICE_IDENTITY arm_uc_device_identity_kcm = {
    .SetVendorGuid          = pal_kcm_setVendorGuid,
    .GetVendorGuid          = pal_kcm_getVendorGuid,
    .SetClassGuid           = pal_kcm_setClassGuid,
    .GetClassGuid           = pal_kcm_getClassGuid,
    .SetDeviceGuid          = pal_kcm_setDeviceGuid,
    .GetDeviceGuid          = pal_kcm_getDeviceGuid,
    .DeviceIdentityCheck    = pal_kcm_deviceIdentityCheck
};

#endif // ARM_UC_USE_KCM
