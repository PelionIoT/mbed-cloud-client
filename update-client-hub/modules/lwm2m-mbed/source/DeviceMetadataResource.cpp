// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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
#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_ENABLE) && (ARM_UC_ENABLE == 1)

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "update-client-lwm2m/DeviceMetadataResource.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-common/arm_uc_types.h"
#include "pal4life-device-identity/pal_device_identity.h"

#include <inttypes.h>
#include <stdio.h>

#define ARM_UCS_LWM2M_INTERNAL_ERROR (-1)
#define ARM_UCS_LWM2M_INTERNAL_SUCCESS (0)

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
#define RESOURCE_VALUE(arg) arg
#define PROTOCOL_VERSION 2
#else
#define RESOURCE_VALUE(arg) #arg
#define PROTOCOL_VERSION 3
#endif

namespace DeviceMetadataResource {
/* LWM2M Firmware Update Object */
static M2MObject *deviceMetadataObject;

/* LWM2M Firmware Update Object resources */
static M2MResource *protocolSupportedResource = NULL; // /10255/0/0
static M2MResource *bootloaderHashResource    = NULL; // /10255/0/1
static M2MResource *OEMBootloaderHashResource = NULL; // /10255/0/2
static M2MResource *vendorIdResource          = NULL; // /10255/0/3
static M2MResource *classIdResource           = NULL; // /10255/0/4
static M2MResource *deviceIdResource          = NULL; // /10255/0/5

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
/* M2MInterface */
static M2MInterface *_m2m_interface = NULL;
#endif
}


/**
 * @brief Initialize LWM2M Device Metadata Object
 * @details Sets up LWM2M object with accompanying resources.
 */
void DeviceMetadataResource::Initialize(void)
{
    static bool initialized = false;

    if (!initialized) {

        /* The LWM2M Firmware Update Object is at /10255 */
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
        deviceMetadataObject = M2MInterfaceFactory::create_object(10255, _m2m_interface);
#else
        deviceMetadataObject = M2MInterfaceFactory::create_object("10255");
#endif

        if (deviceMetadataObject) {
            initialized = true;

#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)
            deviceMetadataObject->set_register_uri(false);
#endif
            /* Set object operating mode to GET_ALLOWED */
            deviceMetadataObject->set_operation(M2MBase::GET_ALLOWED);
            /* Create first (and only) instance /10255/0 */
            M2MObjectInstance *deviceMetadataInstance = deviceMetadataObject->create_object_instance();

            if (deviceMetadataInstance) {
#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)
                deviceMetadataInstance->set_register_uri(false);
#endif

                /* Default values are non-standard, but the standard has no
                   values for indicating that the device is initializing.
                */
                const int64_t version   = PROTOCOL_VERSION;
                const uint8_t invalid_value[]    = "INVALID";
                const uint8_t invalid_value_size = sizeof(invalid_value) - 1;

                ARM_UC_INIT_ERROR(err, ERR_INVALID_PARAMETER);
                arm_uc_guid_t guid    = { 0 };
                uint8_t *value        = NULL;
                uint32_t value_length = 0;

                /* Set instance operating mode to GET_ALLOWED */
                deviceMetadataInstance->set_operation(M2MBase::GET_ALLOWED);

                /* Create Update resource /10255/0/0 */
                protocolSupportedResource = deviceMetadataInstance->create_dynamic_resource(
                                                RESOURCE_VALUE(0),
                                                "ProtocolSupported",
                                                M2MResourceInstance::INTEGER,
                                                true);
                if (protocolSupportedResource) {
                    protocolSupportedResource->set_operation(M2MBase::GET_ALLOWED);
                    protocolSupportedResource->set_value(version);
                    protocolSupportedResource->publish_value_in_registration_msg(true);
                    protocolSupportedResource->set_auto_observable(true);
                }

                /* Create Update resource /10255/0/1 */
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                bootloaderHashResource = deviceMetadataInstance->create_dynamic_resource(
                                             RESOURCE_VALUE(1),
                                             "BootloaderHash",
                                             M2MResourceInstance::OPAQUE,
                                             true);
#else
                bootloaderHashResource = deviceMetadataInstance->create_static_resource(
                                             RESOURCE_VALUE(1),
                                             "BootloaderHash",
                                             M2MResourceInstance::OPAQUE,
                                             (uint8_t *) invalid_value,
                                             invalid_value_size);
#endif
                if (bootloaderHashResource) {
                    bootloaderHashResource->set_operation(M2MBase::GET_ALLOWED);
                    bootloaderHashResource->publish_value_in_registration_msg(true);
                    bootloaderHashResource->set_auto_observable(true);
                }

                /* Create Update resource /10255/0/2 */
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                OEMBootloaderHashResource = deviceMetadataInstance->create_dynamic_resource(
                                                RESOURCE_VALUE(2),
                                                "OEMBootloaderHash",
                                                M2MResourceInstance::OPAQUE,
                                                true);
#else
                OEMBootloaderHashResource = deviceMetadataInstance->create_static_resource(
                                                RESOURCE_VALUE(2),
                                                "OEMBootloaderHash",
                                                M2MResourceInstance::OPAQUE,
                                                (uint8_t *) invalid_value,
                                                invalid_value_size);
#endif
                if (OEMBootloaderHashResource) {
                    OEMBootloaderHashResource->set_operation(M2MBase::GET_ALLOWED);
                    OEMBootloaderHashResource->publish_value_in_registration_msg(true);
                    OEMBootloaderHashResource->set_auto_observable(true);
                }

                /* get vendor ID */
                err = pal_getVendorGuid(&guid);
                if (err.error == ERR_NONE) {
                    value = (uint8_t *) &guid;
                    value_length = sizeof(arm_uc_guid_t);
                } else {
                    value = (uint8_t *) invalid_value;
                    value_length = invalid_value_size;
                }

                /* Create Update resource /10255/0/3 */
                vendorIdResource = deviceMetadataInstance->create_dynamic_resource(
                                       RESOURCE_VALUE(3),
                                       "Vendor",
                                       M2MResourceInstance::OPAQUE,
                                       true);

                if (vendorIdResource) {
                    vendorIdResource->set_operation(M2MBase::GET_ALLOWED);
                    vendorIdResource->set_value(value, value_length);
                    vendorIdResource->publish_value_in_registration_msg(true);
                    vendorIdResource->set_auto_observable(true);
                }

                /* get class ID */
                err = pal_getClassGuid(&guid);
                if (err.error == ERR_NONE) {
                    value = (uint8_t *) &guid;
                    value_length = sizeof(arm_uc_guid_t);
                } else {
                    value = (uint8_t *) invalid_value;
                    value_length = invalid_value_size;
                }

                /* Create Update resource /10255/0/4 */
                classIdResource = deviceMetadataInstance->create_dynamic_resource(
                                      RESOURCE_VALUE(4),
                                      "Class",
                                      M2MResourceInstance::OPAQUE,
                                      true);

                if (classIdResource) {
                    classIdResource->set_operation(M2MBase::GET_ALLOWED);
                    classIdResource->set_value(value, value_length);
                    classIdResource->publish_value_in_registration_msg(true);
                    classIdResource->set_auto_observable(true);
                }

                /* get device ID */
                err = pal_getDeviceGuid(&guid);
                if (err.error == ERR_NONE) {
                    value = (uint8_t *) &guid;
                    value_length = sizeof(arm_uc_guid_t);
                } else {
                    value = (uint8_t *) invalid_value;
                    value_length = invalid_value_size;
                }

                /* Create Update resource /10255/0/5 */
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                deviceIdResource = deviceMetadataInstance->create_dynamic_resource(
                                       RESOURCE_VALUE(5),
                                       "DeviceId",
                                       M2MResourceInstance::OPAQUE,
                                       true);
#else
                deviceIdResource = deviceMetadataInstance->create_static_resource(
                                       RESOURCE_VALUE(5),
                                       "DeviceId",
                                       M2MResourceInstance::OPAQUE,
                                       value,
                                       value_length);
#endif
                if (deviceIdResource) {
                    deviceIdResource->set_operation(M2MBase::GET_ALLOWED);
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                    deviceIdResource->set_value(value, value_length);
#endif
                    deviceIdResource->publish_value_in_registration_msg(true);
                    deviceIdResource->set_auto_observable(true);
                }
            }
        }
    }
}

int32_t DeviceMetadataResource::setBootloaderHash(arm_uc_buffer_t *hash)
{
    UC_SRCE_TRACE("DeviceMetadataResource::setBootloaderHash ptr %p size %" PRIu32, hash, hash->size);

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (bootloaderHashResource && hash && hash->size > 0) {
        bool rt = bootloaderHashResource->set_value(hash->ptr, hash->size);
        if (rt == true) {
            result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
        }
    }

    return result;
}

int32_t DeviceMetadataResource::setOEMBootloaderHash(arm_uc_buffer_t *hash)
{
    UC_SRCE_TRACE("DeviceMetadataResource::setOEMBootloaderHash ptr %p size %" PRIu32, hash, hash->size);

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (OEMBootloaderHashResource && hash && hash->size > 0) {
        bool rt = OEMBootloaderHashResource->set_value(hash->ptr, hash->size);
        if (rt == true) {
            result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
        }
    }

    return result;
}

M2MObject *DeviceMetadataResource::getObject()
{
    Initialize();

    return deviceMetadataObject;
}

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
int32_t DeviceMetadataResource::setM2MInterface(M2MInterface *interface)
{
    UC_SRCE_TRACE("DeviceMetadataResource::setM2MInterface");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (interface != NULL) {
        _m2m_interface = interface;
        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }
    return result;
}
#endif

void DeviceMetadataResource::Uninitialize()
{
    UC_SRCE_TRACE("DeviceMetadataResource::Uninitialize");
    delete deviceMetadataObject;
    deviceMetadataObject = NULL;
}

#endif // ARM_UC_ENABLE
