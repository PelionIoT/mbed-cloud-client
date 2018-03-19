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

#if ARM_UC_USE_KCM
extern const ARM_PAL_DEVICE_IDENTITY arm_uc_device_identity_kcm;
static const ARM_PAL_DEVICE_IDENTITY* arm_uc_device_identity =
    &arm_uc_device_identity_kcm;
#elif ARM_UC_USE_CFSTORE
extern const ARM_PAL_DEVICE_IDENTITY arm_uc_device_identity_cfstore;
static const ARM_PAL_DEVICE_IDENTITY* arm_uc_device_identity =
    &arm_uc_device_identity_cfstore;
#else
#error No configuration store set
#endif

/**
 * @brief Function for setting the vendor GUID.
 * @details The GUID is copied.
 * @param vendor_guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_setVendorGuid(const arm_uc_guid_t* vendor_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->SetVendorGuid(vendor_guid);
    }

    return result;
}

/**
 * @brief Function for getting a pointer to the vendor GUID.
 * @param vendor_guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_getVendorGuid(arm_uc_guid_t* vendor_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->GetVendorGuid(vendor_guid);
    }

    return result;
}

/**
 * @brief Function for setting the device class GUID.
 * @details The GUID is copied.
 * @param class_guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_setClassGuid(const arm_uc_guid_t* class_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->SetClassGuid(class_guid);
    }

    return result;
}

/**
 * @brief Function for getting a pointer to the device class GUID.
 * @param class_guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_getClassGuid(arm_uc_guid_t* class_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->GetClassGuid(class_guid);
    }

    return result;
}

/**
 * @brief Function for setting the device GUID.
 * @details The GUID is copied.
 * @param device_guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_setDeviceGuid(const arm_uc_guid_t* device_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->SetDeviceGuid(device_guid);
    }

    return result;
}

/**
 * @brief Function for getting a pointer to the device GUID.
 * @param device_guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_getDeviceGuid(arm_uc_guid_t* device_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->GetDeviceGuid(device_guid);
    }

    return result;
}

/**
 * @brief Check whether the three GUIDs provided are valid on the device.
 * @details
 * @param vendor_guid Buffer pointer to the Vendor GUID.
 * @param class_guid  Buffer pointer to the device class GUID.
 * @param device_guid Buffer pointer to the device GUID.
 * @return Error code.
 */
arm_uc_error_t pal_deviceIdentityCheck(const arm_uc_buffer_t* vendor_guid,
                                       const arm_uc_buffer_t* class_guid,
                                       const arm_uc_buffer_t* device_guid)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (arm_uc_device_identity)
    {
        result = arm_uc_device_identity->DeviceIdentityCheck(vendor_guid,
                                                       class_guid,
                                                       device_guid);
    }

    return result;
}
