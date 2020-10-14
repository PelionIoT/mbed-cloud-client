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

#ifndef PAL4LIFE_DEVICE_IDENTITY_H
#define PAL4LIFE_DEVICE_IDENTITY_H

#include "update-client-common/arm_uc_common.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function for setting the vendor GUID.
 * @details The GUID is copied.
 * @param vendor_guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_setVendorGuid(const arm_uc_guid_t *vendor_guid);

/**
 * @brief Function for getting a pointer to the vendor GUID.
 * @param vendor_guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_getVendorGuid(arm_uc_guid_t *vendor_guid);

/**
 * @brief Function for setting the device class GUID.
 * @details The GUID is copied.
 * @param class_guid Pointer to a arm_uc_guid_t GUID.
 * @return Error code.
 */
arm_uc_error_t pal_setClassGuid(const arm_uc_guid_t *class_guid);

/**
 * @brief Function for getting a pointer to the device class GUID.
 * @param class_guid Pointer to a arm_uc_guid_t pointer.
 * @return Error code.
 */
arm_uc_error_t pal_getClassGuid(arm_uc_guid_t *class_guid);

/**
 * @brief Check whether the three GUIDs provided are valid on the device.
 * @details
 * @param vendor_guid Buffer pointer to the Vendor GUID.
 * @param class_guid  Buffer pointer to the device class GUID.
 * @return Error code.
 */
arm_uc_error_t pal_deviceIdentityCheck(const arm_uc_buffer_t *vendor_guid,
                                       const arm_uc_buffer_t *class_guid);

/**
 * @brief Structure definition holding API function pointers.
 */
typedef struct _ARM_PAL_DEVICE_IDENTITY {
    /**
     * @brief Function for setting the vendor GUID.
     * @details The GUID is copied.
     * @param vendor_guid Pointer to a arm_uc_guid_t GUID.
     * @return Error code.
     */
    arm_uc_error_t (*SetVendorGuid)(const arm_uc_guid_t *vendor_guid);

    /**
     * @brief Function for getting a pointer to the vendor GUID.
     * @param vendor_guid Pointer to a arm_uc_guid_t pointer.
     * @return Error code.
     */
    arm_uc_error_t (*GetVendorGuid)(arm_uc_guid_t *vendor_guid);

    /**
     * @brief Function for setting the device class GUID.
     * @details The GUID is copied.
     * @param class_guid Pointer to a arm_uc_guid_t GUID.
     * @return Error code.
     */
    arm_uc_error_t (*SetClassGuid)(const arm_uc_guid_t *class_guid);

    /**
     * @brief Function for getting a pointer to the device class GUID.
     * @param class_guid Pointer to a arm_uc_guid_t pointer.
     * @return Error code.
     */
    arm_uc_error_t (*GetClassGuid)(arm_uc_guid_t *class_guid);

    /**
     * @brief Check whether the three GUIDs provided are valid on the device.
     * @details
     * @param vendor_guid Buffer pointer to the Vendor GUID.
     * @param class_guid  Buffer pointer to the device class GUID.
     * @return Error code.
     */
    arm_uc_error_t (*DeviceIdentityCheck)(const arm_uc_buffer_t *vendor_guid,
                                          const arm_uc_buffer_t *class_guid);
} ARM_PAL_DEVICE_IDENTITY;

#ifdef __cplusplus
}
#endif

#endif // PAL4LIFE_DEVICE_IDENTITY_H
