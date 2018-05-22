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

#include "update-client-lwm2m/FirmwareUpdateResource.h"

#include "update-client-common/arm_uc_common.h"

#include <stdio.h>

#define ARM_UCS_LWM2M_INTERNAL_ERROR (-1)
#define ARM_UCS_LWM2M_INTERNAL_SUCCESS (0)

namespace FirmwareUpdateResource {

    /* send delayed response */
    enum {
        ResourcePackage,
        ResourcePackageURI,
        ResourceUpdate
    };

    static void packageCallback(void* _parameters);
    static void packageURICallback(void* _parameters);
    static void updateCallback(void*);
    static void notificationCallback(void);
    static void sendDelayedResponseTask(uint32_t parameter);

    /* LWM2M Firmware Update Object */
    static M2MObject* updateObject;

    /* LWM2M Firmware Update Object resources */
    static M2MResource* resourcePackage = NULL;
    static M2MResource* resourcePackageURI = NULL;
    static M2MResource* resourceUpdate = NULL;
    static M2MResource* resourceState = NULL;
    static M2MResource* resourceResult = NULL;
    static M2MResource* resourceName = NULL;
    static M2MResource* resourceVersion = NULL;

    /* function pointers to callback functions */
    static void (*externalPackageCallback)(const uint8_t* buffer, uint16_t length) = NULL;
    static void (*externalPackageURICallback)(const uint8_t* buffer, uint16_t length) = NULL;
    static void (*externalUpdateCallback)(void) = NULL;
    static void (*externalNotificationCallback)(void) = NULL;

    /* Callback structs for delayed response.
     *
     * There needs to be one per callback type to avoid collisions between different operations.
     */
    static arm_uc_callback_t callbackNodePackage = { NULL, 0, NULL, 0 };
    static arm_uc_callback_t callbackNodePackageURI = { NULL, 0, NULL, 0 };
    static arm_uc_callback_t callbackNodeResourceUpdate = { NULL, 0, NULL, 0 };
}

/**
 * @brief Initialize LWM2M Firmware Update Object
 * @details Sets up LWM2M object with accompanying resources.
 */
void FirmwareUpdateResource::Initialize(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        initialized = true;

        /* The LWM2M Firmware Update Object is at /5 */
        updateObject = M2MInterfaceFactory::create_object("5");

        if (updateObject)
        {
            /* Create first (and only) instance /5/0 */
            M2MObjectInstance* updateInstance = updateObject->create_object_instance();

            if (updateInstance)
            {
                /* Set observable so the Portal can read it */
                updateInstance->set_observable(true);

                /* Default values are non-standard, but the standard has no
                   values for indicating that the device is initializing.
                   To address this, Service ignores -1 and/or 255 values coming through,
                   so for our purposes this is the correct form of initialization.
                */
                uint8_t defaultValue[] = {"-1"};
                uint8_t defaultVersion[] = {"-1"};

                /* Create Package resource /5/0/0 */
                resourcePackage = updateInstance->create_dynamic_resource(
                                    "0", "Package", M2MResourceInstance::OPAQUE, false);
                if (resourcePackage)
                {
                    /* This should be PUT according to the standard but
                       Connector client doesn't support callbacks for PUT.
                    */
                    resourcePackage->set_operation(M2MBase::POST_ALLOWED);
                    resourcePackage->set_execute_function(packageCallback);

                    /* The delayed response if for processing heavier loads */
                    resourcePackage->set_delayed_response(true);
                }

                /* Create Package URI resource /5/0/1 */
                resourcePackageURI = updateInstance->create_dynamic_resource(
                                    "1", "PackageURI", M2MResourceInstance::STRING, false);
                if (resourcePackageURI)
                {
                    resourcePackageURI->set_operation(M2MBase::POST_ALLOWED);
                    resourcePackageURI->set_execute_function(packageURICallback);
                    resourcePackageURI->set_delayed_response(true);
                }

                /* Create Update resource /5/0/2 */
                resourceUpdate = updateInstance->create_dynamic_resource(
                                    "2", "Update", M2MResourceInstance::BOOLEAN, false);
                if (resourceUpdate)
                {
                    resourceUpdate->set_operation(M2MBase::POST_ALLOWED);
                    resourceUpdate->set_execute_function(updateCallback);
                    resourceUpdate->set_delayed_response(true);
                }

                /* Create State resource /5/0/3 */
                resourceState = updateInstance->create_dynamic_resource(
                                    "3", "State", M2MResourceInstance::INTEGER, true);
                if (resourceState)
                {
                    resourceState->set_operation(M2MBase::GET_ALLOWED);
                    resourceState->set_notification_sent_callback(notificationCallback);
                    resourceState->set_value(defaultValue, sizeof(defaultValue) - 1);
                }

                /* Create Update Result resource /5/0/5 */
                resourceResult = updateInstance->create_dynamic_resource(
                                    "5", "UpdateResult", M2MResourceInstance::INTEGER, true);
                if (resourceResult)
                {
                    resourceResult->set_operation(M2MBase::GET_ALLOWED);
                    resourceResult->set_notification_sent_callback(notificationCallback);
                    resourceResult->set_value(defaultValue, sizeof(defaultValue) - 1);
                }

                /* Create PkgName resource /5/0/6 */
                resourceName = updateInstance->create_dynamic_resource(
                                    "6", "PkgName", M2MResourceInstance::STRING, true);
                if (resourceName)
                {
                    resourceName->set_operation(M2MBase::GET_ALLOWED);
                    resourceName->set_value(defaultVersion, sizeof(defaultVersion) - 1);
                }

                /* Create PkgVersion resource /5/0/7 */
                resourceVersion = updateInstance->create_dynamic_resource(
                                    "7", "PkgVersion", M2MResourceInstance::STRING, true);
                if (resourceVersion)
                {
                    resourceVersion->set_operation(M2MBase::GET_ALLOWED);
                    resourceVersion->set_value(defaultVersion, sizeof(defaultVersion) - 1);
                }
            }
        }
    }
}

M2MObject* FirmwareUpdateResource::getObject()
{
    Initialize();

    return updateObject;
}

void FirmwareUpdateResource::packageCallback(void* _parameters)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::packageCallback");

    if (_parameters && externalPackageCallback)
    {
        /* recast parameter */
        M2MResource::M2MExecuteParameter* parameters =
            static_cast<M2MResource::M2MExecuteParameter*>(_parameters);

        /* read payload */
        const uint8_t* buffer = parameters->get_argument_value();
        uint16_t length = parameters->get_argument_value_length();

        /* invoke external callback function */
        externalPackageCallback(buffer, length);

        /* schedule delayed response */
        ARM_UC_PostCallback(&callbackNodePackage,
                            FirmwareUpdateResource::sendDelayedResponseTask,
                            FirmwareUpdateResource::ResourcePackage);
    }
}

void FirmwareUpdateResource::packageURICallback(void* _parameters)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::packageURICallback");

    if (_parameters && externalPackageURICallback)
    {
        /* recast parameter */
        M2MResource::M2MExecuteParameter* parameters =
            static_cast<M2MResource::M2MExecuteParameter*>(_parameters);

        /* read payload */
        const uint8_t* buffer = parameters->get_argument_value();
        uint16_t length = parameters->get_argument_value_length();

        /* invoke external callback function */
        externalPackageURICallback(buffer, length);

        /* schedule delayed response */
        ARM_UC_PostCallback(&callbackNodePackageURI,
                            FirmwareUpdateResource::sendDelayedResponseTask,
                            FirmwareUpdateResource::ResourcePackageURI);
    }
}

void FirmwareUpdateResource::updateCallback(void* _parameters)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::updateCallback");

    (void) _parameters;

    if (externalUpdateCallback)
    {
        /* invoke external callback function */
        externalUpdateCallback();

        /* schedule delayed response */
        ARM_UC_PostCallback(&callbackNodeResourceUpdate,
                            FirmwareUpdateResource::sendDelayedResponseTask,
                            FirmwareUpdateResource::ResourceUpdate);
    }
}

void FirmwareUpdateResource::notificationCallback(void)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::notificationCallback");

    if (externalNotificationCallback)
    {
        externalNotificationCallback();
    }
}

void FirmwareUpdateResource::sendDelayedResponseTask(uint32_t parameter)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendDelayedResponseTask");

    switch (parameter)
    {
        case FirmwareUpdateResource::ResourcePackage:
            UC_SRCE_TRACE("resourcePackage->send_delayed_post_response");
            resourcePackage->send_delayed_post_response();
            break;
        case FirmwareUpdateResource::ResourcePackageURI:
            UC_SRCE_TRACE("resourcePackageURI->send_delayed_post_response");
            resourcePackageURI->send_delayed_post_response();
            break;
        case FirmwareUpdateResource::ResourceUpdate:
            UC_SRCE_TRACE("resourceUpdate->send_delayed_post_response");
            resourceUpdate->send_delayed_post_response();
            break;
        default:
            UC_SRCE_ERR_MSG("unsupported resource");
            break;
    }
}

/*****************************************************************************/
/* Update Client Source                                                      */
/*****************************************************************************/

/* Add callback for resource /5/0/0, Package */
int32_t FirmwareUpdateResource::addPackageCallback(void (*cb)(const uint8_t* buffer, uint16_t length))
{
    UC_SRCE_TRACE("FirmwareUpdateResource::addPackageCallback: %p", cb);

    externalPackageCallback = cb;

    return ARM_UCS_LWM2M_INTERNAL_SUCCESS;
}

/* Add callback for resource /5/0/1, Package URI */
int32_t FirmwareUpdateResource::addPackageURICallback(void (*cb)(const uint8_t* buffer, uint16_t length))
{
    UC_SRCE_TRACE("FirmwareUpdateResource::addPackageURICallback: %p", cb);

    externalPackageURICallback = cb;

    return ARM_UCS_LWM2M_INTERNAL_SUCCESS;
}

/* Add callback for resource /5/0/2, Update */
int32_t FirmwareUpdateResource::addUpdateCallback(void (*cb)(void))
{
    UC_SRCE_TRACE("FirmwareUpdateResource::addUpdateCallback: %p", cb);

    externalUpdateCallback = cb;

    return ARM_UCS_LWM2M_INTERNAL_SUCCESS;
}

/* Add callback for when send{State, UpdateResult} is done */
int32_t FirmwareUpdateResource::addNotificationCallback(void (*cb)(void))
{
    UC_SRCE_TRACE("FirmwareUpdateResource::addNotificationCallback: %p", cb);

    externalNotificationCallback = cb;

    return ARM_UCS_LWM2M_INTERNAL_SUCCESS;
}

/*****************************************************************************/
/* Update Client Status                                                      */
/*****************************************************************************/

/* Send state for resource /5/0/3, State */
int32_t FirmwareUpdateResource::sendState(arm_ucs_lwm2m_state_t state)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendState");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (state <= ARM_UCS_LWM2M_STATE_LAST)
    {
        /* valid states: 0-3 */
        uint8_t value[2];
        snprintf((char*)value, 2, "%d", state);
        resourceState->set_value(value, 1);

        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }

    return result;
}

/* Send result for resource /5/0/5, Update Result */
int32_t FirmwareUpdateResource::sendUpdateResult(arm_ucs_lwm2m_result_t updateResult)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendUpdateResult");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (updateResult <= ARM_UCS_LWM2M_RESULT_LAST)
    {
        /* valid results: 0-8 */
        uint8_t value[2];
        snprintf((char*)value, 2, "%d", updateResult);
        resourceResult->set_value(value, 1);

        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }

    return result;
}

/* Send name for resource /5/0/6 PkgName */
int32_t FirmwareUpdateResource::sendPkgName(const uint8_t* name, uint16_t length)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendPkgName");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    /* the maximum length is defined in the OMA LWM2M standard. */
    if ((name != NULL) && (length <= 255))
    {
        uint8_t value[64] = { 0 };
        uint8_t index = 0;

        /* convert to printable characters using lookup table */
        for ( ; (index < 32) && (index < length); index++)
        {
            value[2 * index    ] = arm_uc_hex_table[name[index] >> 4];
            value[2 * index + 1] = arm_uc_hex_table[name[index] & 0x0F];
        }

        resourceName->set_value(value, 2 * index);

        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }

    return result;
}

/* Send version for resource /5/0/7, PkgVersion */
int32_t FirmwareUpdateResource::sendPkgVersion(uint64_t version)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendPkgVersion");

    uint8_t value[21] = { 0 };
    uint8_t length = snprintf((char*) value, 21, "%llu" , version);
    resourceVersion->set_value(value, length);

    return ARM_UCS_LWM2M_INTERNAL_SUCCESS;
}

void FirmwareUpdateResource::Uninitialize(void)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::Uninitialize"); 
    delete updateObject;
    updateObject = NULL;
}