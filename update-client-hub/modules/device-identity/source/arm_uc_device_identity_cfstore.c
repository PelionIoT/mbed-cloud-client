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

#ifndef ARM_UC_USE_CFSTORE
#define ARM_UC_USE_CFSTORE 0
#endif

#if ARM_UC_USE_CFSTORE

#include <string.h>

static arm_uc_guid_t arm_uc_vendor_guid = {0};
static int arm_uc_vendor_guid_set = 0;
static arm_uc_guid_t arm_uc_class_guid = {0};
static int arm_uc_class_guid_set = 0;
static arm_uc_guid_t arm_uc_device_guid = {0};
static int arm_uc_device_guid_set = 0;

/**
 * @brief Function for setting the vendor GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_cfstore_setVendorGuid(const arm_uc_guid_t* vendor_guid)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    if (vendor_guid)
    {
        memcpy(&arm_uc_vendor_guid, vendor_guid, sizeof(arm_uc_guid_t));
        arm_uc_vendor_guid_set = 1;
    }
    else
    {
        memset(&arm_uc_vendor_guid, 0, sizeof(arm_uc_guid_t));
        arm_uc_vendor_guid_set = 0;
    }
    return result;
}

/**
 * @brief Function for getting a pointer to the vendor GUID.
 * @param guid Pointer to a arm_uc_guid_t.
 * @return Error code.
 */
arm_uc_error_t pal_cfstore_getVendorGuid(arm_uc_guid_t* vendor_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (vendor_guid && arm_uc_vendor_guid_set)
    {
        result.code = ERR_NONE;
        memcpy(vendor_guid, &arm_uc_vendor_guid, sizeof(arm_uc_guid_t));
    }

    return result;
}

/**
 * @brief Function for setting the device class GUID.
 * @details The GUID is copied/
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_cfstore_setClassGuid(const arm_uc_guid_t* class_guid)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    if (class_guid)
    {
        memcpy(&arm_uc_class_guid, class_guid, sizeof(arm_uc_guid_t));
        arm_uc_class_guid_set = 1;
    }
    else
    {
        memset(&arm_uc_class_guid, 0, sizeof(arm_uc_guid_t));
        arm_uc_class_guid_set = 0;
    }
    return result;
}

/**
 * @brief Function for getting a pointer to the device class GUID.
 * @param guid Pointer to a arm_uc_guid_t.
 * @return Error code.
 */
arm_uc_error_t pal_cfstore_getClassGuid(arm_uc_guid_t* class_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (class_guid && arm_uc_class_guid_set)
    {
        result.code = ERR_NONE;
        memcpy(class_guid, &arm_uc_class_guid, sizeof(arm_uc_guid_t));
    }

    return result;
}

/**
 * @brief Function for setting the device GUID.
 * @details The GUID is copied.
 * @param guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_cfstore_setDeviceGuid(const arm_uc_guid_t* device_guid)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    if (device_guid)
    {
        memcpy(&arm_uc_device_guid, device_guid, sizeof(arm_uc_guid_t));
        arm_uc_device_guid_set = 1;
    }
    else
    {
        memset(&arm_uc_device_guid, 0, sizeof(arm_uc_guid_t));
        arm_uc_device_guid_set = 0;
    }
    return result;
}

/**
 * @brief Function for getting a pointer to the device GUID.
 * @param guid Pointer to a arm_uc_guid_t.
 * @return Error code.
 */
arm_uc_error_t pal_cfstore_getDeviceGuid(arm_uc_guid_t* device_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (device_guid && arm_uc_device_guid_set)
    {
        result.code = ERR_NONE;
        memcpy(device_guid, &arm_uc_device_guid, sizeof(arm_uc_guid_t));
    }

    return result;
}

static bool pal_cfstore_internal_compare(const arm_uc_guid_t* guid,
                                         const arm_uc_buffer_t* buffer)
{
    // count how many bytes match
    uint8_t index = 0;

    if (guid && buffer)
    {
        for ( ; (index < sizeof(arm_uc_guid_t)) && (index < buffer->size); index++)
        {
            if (((const uint8_t*) guid)[index] != buffer->ptr[index])
            {
                break;
            }
        }
    }

    // return true if all bytes matched
    return (index == sizeof(arm_uc_guid_t));
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
arm_uc_error_t pal_cfstore_deviceIdentityCheck(const arm_uc_buffer_t* vendor_buffer,
                                               const arm_uc_buffer_t* class_buffer,
                                               const arm_uc_buffer_t* device_buffer)
{
    arm_uc_error_t result = { .code = MFST_ERR_NULL_PTR };

    uint8_t parameters_set = 0;
    uint8_t parameters_ok = 0;

    /* check device - device is optional */
    if (arm_uc_device_guid_set)
    {
        if (device_buffer && device_buffer->ptr)
        {
            bool is_same = pal_cfstore_internal_compare(&arm_uc_device_guid,
                                                        device_buffer);

            if (is_same)
            {
                parameters_ok++;
            }
            else
            {
                result.code = MFST_ERR_GUID_DEVICE;
            }

            parameters_set++;
        }
    }

    /* check class - class is optional */
    if (arm_uc_class_guid_set)
    {
        if (class_buffer && class_buffer->ptr)
        {
            bool is_same = pal_cfstore_internal_compare(&arm_uc_class_guid,
                                                        class_buffer);

            if (is_same)
            {
                parameters_ok++;
            }
            else
            {
                result.code = MFST_ERR_GUID_DEVCLASS;
            }

            parameters_set++;
        }
    }

    /* check vendor - vendor is mandatory and has mask 0x10. */
    if (arm_uc_vendor_guid_set)
    {
        if (vendor_buffer && vendor_buffer->ptr)
        {
            bool is_same = pal_cfstore_internal_compare(&arm_uc_vendor_guid,
                                                        vendor_buffer);

            if (is_same)
            {
                parameters_ok += 0x10;
            }
            else
            {
                result.code = MFST_ERR_GUID_VENDOR;
            }

            parameters_set += 0x10;
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

const ARM_PAL_DEVICE_IDENTITY arm_uc_device_identity_cfstore = {
    .SetVendorGuid          = pal_cfstore_setVendorGuid,
    .GetVendorGuid          = pal_cfstore_getVendorGuid,
    .SetClassGuid           = pal_cfstore_setClassGuid,
    .GetClassGuid           = pal_cfstore_getClassGuid,
    .SetDeviceGuid          = pal_cfstore_setDeviceGuid,
    .GetDeviceGuid          = pal_cfstore_getDeviceGuid,
    .DeviceIdentityCheck    = pal_cfstore_deviceIdentityCheck
};

#endif // ARM_UC_USE_CFSTORE
