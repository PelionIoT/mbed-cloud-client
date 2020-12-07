// ----------------------------------------------------------------------------
// Copyright 2016-2020 ARM Ltd.
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

#include "update-client-lwm2m/FirmwareUpdateResource.h"

#include "update-client-common/arm_uc_common.h"
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
#include "mbed-client/source/include/m2mcallbackstorage.h"
#include "mbed-client/m2mexecuteparams.h"
#include "mbed-client/m2mbase.h"
#endif
#include "source/update_client_hub_state_machine.h"
#include "source/update_client_hub_error_handler.h"

// Need to use .h includes instead of <c...> because of SXOS support
#include <stdio.h>
#include <inttypes.h>

#define ARM_UCS_LWM2M_INTERNAL_ERROR (-1)
#define ARM_UCS_LWM2M_INTERNAL_SUCCESS (0)

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
#define RESOURCE_VALUE(arg) arg
#else
#define RESOURCE_VALUE(arg) #arg
#endif

namespace FirmwareUpdateResource {

/* send delayed response */
enum {
    ResourcePackage,
    ResourcePackageURI,
    ResourceUpdate
};

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
static void packageCallback(void *_parameters, const M2MExecuteParameter &params);
static void packageURICallback(void *_parameters, const M2MExecuteParameter &params);
static void updateCallback(void *, const M2MExecuteParameter &params);
static void notificationCallback(void *client_args, const M2MBase &object, NotificationDeliveryStatus delivery_status);
/* Default values are non-standard, but the standard has no
   values for indicating that the device is initializing.
   To address this, Service ignores -1 and/or 255 values coming through,
   so for our purposes this is the correct form of initialization.
*/
const uint8_t defaultValue = -1;
#else
static void packageCallback(void *_parameters);
static void updateCallback(void *);
static void notificationCallback(const M2MBase& base, const M2MBase::MessageDeliveryStatus status, const M2MBase::MessageType type, void *client_args);
uint8_t defaultValue[] = {"-1"};
#endif
static void sendDelayedResponseTask(uintptr_t parameter);

/* LWM2M Firmware Update Object */
static M2MObject *updateObject;

/* LWM2M Firmware Update Object resources */
static M2MResource *resourcePackage = NULL;
static M2MResource *resourcePackageURI = NULL;
static M2MResource *resourceUpdate = NULL;
static M2MResource *resourceState = NULL;
static M2MResource *resourceResult = NULL;
static M2MResource *resourceName = NULL;
static M2MResource *resourceVersion = NULL;

/* function pointers to callback functions */
static void (*externalPackageCallback)(const uint8_t *buffer, uint16_t length) = NULL;
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
static void (*externalPackageURICallback)(const uint8_t *buffer, uint16_t length) = NULL;
#endif
static void (*externalUpdateCallback)(void) = NULL;
static void (*externalNotificationCallback)(void) = NULL;

/* Callback structs for delayed response.
 *
 * There needs to be one per callback type to avoid collisions between different operations.
 */
static arm_uc_callback_t callbackNodePackage = { NULL, 0, NULL, 0 };
static arm_uc_callback_t callbackNodePackageURI = { NULL, 0, NULL, 0 };
static arm_uc_callback_t callbackNodeResourceUpdate = { NULL, 0, NULL, 0 };

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
/* M2MInterface */
static M2MInterface *_m2m_interface;
#endif
}

/**
 * @brief Initialize LWM2M Firmware Update Object
 * @details Sets up LWM2M object with accompanying resources.
 */
void FirmwareUpdateResource::Initialize(void)
{
    static bool initialized = false;

    if (!initialized) {
        /* The LWM2M Firmware Update Object for LITE client is at /10252 (Manifest) */
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
        updateObject = M2MInterfaceFactory::create_object(10252, _m2m_interface);
#else
        updateObject = M2MInterfaceFactory::create_object("10252");
#endif

        if (updateObject) {
            initialized = true;

#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)
            updateObject->set_register_uri(true);

#endif

            /* Create first (and only) instance /10252/0 */
            M2MObjectInstance *updateInstance = updateObject->create_object_instance();

            if (updateInstance) {

#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)
                /* Set observable so the Portal can read it */
                updateInstance->set_register_uri(false);
#endif
                uint8_t defaultVersion[] = {"-1"};

                /* Create Package resource /10252/0/1 */
                resourcePackage = updateInstance->create_dynamic_resource(
                                      RESOURCE_VALUE(1), "Package", M2MResourceInstance::OPAQUE, false);
                if (resourcePackage) {
                    /* This should be PUT according to the standard but
                       Connector client doesn't support callbacks for PUT.
                    */
                    resourcePackage->set_operation(M2MBase::POST_ALLOWED);
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                    resourcePackage->set_execute_function((M2MResourceBase::execute_callback)packageCallback, NULL);
#else
                    resourcePackage->set_execute_function(packageCallback);

                    /* The delayed response if for processing heavier loads */
                    resourcePackage->set_delayed_response(true);
                    resourcePackage->set_register_uri(false);
#endif

                }

                /* Create State resource /10252/0/2 */
                resourceState = updateInstance->create_dynamic_resource(
                                    RESOURCE_VALUE(2), "State", M2MResourceInstance::INTEGER, true);
                if (resourceState) {
                    resourceState->set_operation(M2MBase::GET_ALLOWED);
                    resourceState->set_message_delivery_status_cb(notificationCallback, NULL);
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                    resourceState->set_value(defaultValue);
#else
                    resourceState->set_value(defaultValue, sizeof(defaultValue) - 1);
#endif
                    resourceState->publish_value_in_registration_msg(true);
                    resourceState->set_auto_observable(true);
                }

                /* Create Update Result resource /10252/0/3 */
                resourceResult = updateInstance->create_dynamic_resource(
                                     RESOURCE_VALUE(3), "UpdateResult", M2MResourceInstance::INTEGER, true);
                if (resourceResult) {
                    resourceResult->set_operation(M2MBase::GET_ALLOWED);
                    resourceResult->set_message_delivery_status_cb(notificationCallback, NULL);
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                    resourceResult->set_value(defaultValue);
#else
                    resourceResult->set_value(defaultValue, sizeof(defaultValue) - 1);
#endif
                    resourceResult->publish_value_in_registration_msg(true);
                    resourceResult->set_auto_observable(true);
                }

                /* Create PkgName resource /10252/0/5 */
                resourceName = updateInstance->create_dynamic_resource(
                                   RESOURCE_VALUE(5), "PkgName", M2MResourceInstance::STRING, true);
                if (resourceName) {
                    resourceName->set_operation(M2MBase::GET_ALLOWED);
                    resourceName->set_value(defaultVersion, sizeof(defaultVersion) - 1);
                    resourceName->publish_value_in_registration_msg(true);
                    resourceName->set_auto_observable(true);
                }

                /* Create PkgVersion resource /10252/0/6 */
                resourceVersion = updateInstance->create_dynamic_resource(
                                      RESOURCE_VALUE(6), "PkgVersion", M2MResourceInstance::STRING, true);
                if (resourceVersion) {
                    resourceVersion->set_operation(M2MBase::GET_ALLOWED);
                    resourceVersion->set_value(defaultVersion, sizeof(defaultVersion) - 1);
                    resourceVersion->publish_value_in_registration_msg(true);
                    resourceVersion->set_auto_observable(true);
                }

#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
                /* Create Update resource /10252/0/9 */
                resourceUpdate = updateInstance->create_dynamic_resource(
                                     "9", "Update", M2MResourceInstance::STRING, false);
                if (resourceUpdate) {
                    resourceUpdate->set_operation(M2MBase::POST_ALLOWED);
                    resourceUpdate->set_execute_function(updateCallback);
                    resourceUpdate->set_delayed_response(true);
                    resourceUpdate->set_register_uri(false);
                }
#endif
            }
        }
    }
}

M2MObject *FirmwareUpdateResource::getObject()
{
    Initialize();

    return updateObject;
}

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
void FirmwareUpdateResource::packageCallback(void *_parameters, const M2MExecuteParameter &params)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::packageCallback");

    // Reset the resource values for every new Campaign
    // to make sure values of new Campaign get sent to service
    resourceState->set_value(defaultValue);
    resourceResult->set_value(defaultValue);

    if (externalPackageCallback) {
        /* read payload */
        const uint8_t *buffer = params.get_argument_value();
        uint16_t length = params.get_argument_value_length();

        /* invoke external callback function */
        externalPackageCallback(buffer, length);

        params.get_resource().send_post_response(params.get_token(), params.get_token_length());

        // TODO: Do we need to pass the token param to delayed callback
        // Or is above send_post_response enough?
        // Below callback is needed because otherwise UC Hub is not notified
#else
void FirmwareUpdateResource::packageCallback(void *_parameters)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::packageCallback");

    // Reset the resource values for every new Campaign
    // to make sure values of new Campaign get sent to service
    resourceState->set_value(defaultValue, sizeof(defaultValue) - 1);
    resourceResult->set_value(defaultValue, sizeof(defaultValue) - 1);

    if (_parameters && externalPackageCallback) {
        /* recast parameter */
        M2MResource::M2MExecuteParameter *parameters =
            static_cast<M2MResource::M2MExecuteParameter *>(_parameters);

        /* read payload */
        const uint8_t *buffer = parameters->get_argument_value();
        uint16_t length = parameters->get_argument_value_length();

        /* invoke external callback function */
        externalPackageCallback(buffer, length);
#endif
        /* schedule delayed response */
        ARM_UC_PostCallback(&callbackNodePackage,
                            FirmwareUpdateResource::sendDelayedResponseTask,
                            FirmwareUpdateResource::ResourcePackage);
    }
}

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
void FirmwareUpdateResource::packageURICallback(void *_parameters, const M2MExecuteParameter &params)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::packageURICallback");

    if (_parameters && externalPackageURICallback) {
        /* read payload */
        const uint8_t *buffer = params.get_argument_value();
        uint16_t length = params.get_argument_value_length();

        /* invoke external callback function */
        externalPackageURICallback(buffer, length);

        params.get_resource().send_post_response(params.get_token(), params.get_token_length());

        // TODO: Do we need to pass the token param to delayed callback
        // Or is above send_post_response enough?
        // Below callback is needed because otherwise UC Hub is not notified
        /* schedule delayed response */
        ARM_UC_PostCallback(&callbackNodePackageURI,
                            FirmwareUpdateResource::sendDelayedResponseTask,
                            FirmwareUpdateResource::ResourcePackageURI);
    }
}
#endif

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
void FirmwareUpdateResource::updateCallback(void *_parameters, const M2MExecuteParameter &params)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::updateCallback");

    (void) _parameters;

    if (externalUpdateCallback) {
        /* invoke external callback function */
        externalUpdateCallback();

        params.get_resource().send_post_response(params.get_token(), params.get_token_length());

        // TODO: Do we need to pass the token param to delayed callback
        // Or is above send_post_response enough?
#else
void FirmwareUpdateResource::updateCallback(void *_parameters)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::updateCallback");

    (void) _parameters;

    if (externalUpdateCallback) {
        /* invoke external callback function */
        externalUpdateCallback();

#endif
        // Below callback is needed because otherwise UC Hub is not notified
        /* schedule delayed response */
        ARM_UC_PostCallback(&callbackNodeResourceUpdate,
                            FirmwareUpdateResource::sendDelayedResponseTask,
                            FirmwareUpdateResource::ResourceUpdate);
    }
}

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
void FirmwareUpdateResource::notificationCallback(void *client_args,
                                                  const M2MBase &object,
                                                  const NotificationDeliveryStatus delivery_status)
#else
void FirmwareUpdateResource::notificationCallback(const M2MBase& base,
                                                  const M2MBase::MessageDeliveryStatus delivery_status,
                                                  const M2MBase::MessageType type,
                                                  void *client_args)
#endif
{
    UC_SRCE_TRACE("FirmwareUpdateResource::notificationCallback status: %d", delivery_status);
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
    path_buffer buffer;
    object.uri_path(buffer);
    UC_SRCE_TRACE("Callback for resource: %s", buffer.c_str());
#endif
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
    if (delivery_status == NOTIFICATION_STATUS_DELIVERED) {
#else
    if (delivery_status == M2MBase::MESSAGE_STATUS_DELIVERED) {
#endif
        // Notification has been ACKed by server, complete to callback
        UC_SRCE_TRACE("FirmwareUpdateResource::notificationCallback DELIVERED");

        if (externalNotificationCallback) {
            externalNotificationCallback();
        }
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)

    } else if (delivery_status == NOTIFICATION_STATUS_BUILD_ERROR ||
               delivery_status == NOTIFICATION_STATUS_RESEND_QUEUE_FULL ||
               delivery_status == NOTIFICATION_STATUS_SEND_FAILED ||
               delivery_status == NOTIFICATION_STATUS_UNSUBSCRIBED) {
#else
    } else if (delivery_status == M2MBase::MESSAGE_STATUS_BUILD_ERROR ||
               delivery_status == M2MBase::MESSAGE_STATUS_RESEND_QUEUE_FULL ||
               delivery_status == M2MBase::MESSAGE_STATUS_SEND_FAILED ||
               delivery_status == M2MBase::MESSAGE_STATUS_UNSUBSCRIBED) {
#endif
        // Error case, notification not reaching service
        // We are sending out error because we cannot rely connection is
        // anymore up and the service and client are not in sync anymore.
        // Also sending new notifications after this might lock event
        // machine because comms cannot service us anymore.
        UC_SRCE_ERR_MSG("Received Notification delivery status: %d - ERROR!", delivery_status);
        ARM_UC_HUB_ErrorHandler(HUB_ERR_CONNECTION, ARM_UC_HUB_getState());
    } else {
        // NOTIFICATION_STATUS_INIT
        // NOTIFICATION_STATUS_SENT
        // NOTIFICATION_STATUS_SUBSCRIBED
        UC_SRCE_TRACE("FirmwareUpdateResource::notificationCallback Status ignored, waiting delivery...");
    }
}

void FirmwareUpdateResource::sendDelayedResponseTask(uintptr_t parameter)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendDelayedResponseTask");

    switch (parameter) {
        case FirmwareUpdateResource::ResourcePackage:
            UC_SRCE_TRACE("resourcePackage->send_delayed_post_response");
#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
            resourcePackage->send_delayed_post_response();
#else
            //called already in callback: resourcePackage->send_delayed_post_response();
#endif
            break;
        case FirmwareUpdateResource::ResourcePackageURI:
            UC_SRCE_TRACE("resourcePackageURI->send_delayed_post_response");
#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
            resourcePackageURI->send_delayed_post_response();
#else
            //called already in callback: resourcePackageURI->send_delayed_post_response();
#endif
            break;
        case FirmwareUpdateResource::ResourceUpdate:
            UC_SRCE_TRACE("resourceUpdate->send_delayed_post_response");
#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
            resourceUpdate->send_delayed_post_response();
#else
            //called already in callback: resourceUpdate->send_delayed_post_response();
#endif
            break;
        default:
            UC_SRCE_ERR_MSG("unsupported resource");
            break;
    }
}

/*****************************************************************************/
/* Update Client Source                                                      */
/*****************************************************************************/

/* Add callback for resource /10252/0/1, Package */
int32_t FirmwareUpdateResource::addPackageCallback(void (*cb)(const uint8_t *buffer, uint16_t length))
{
    UC_SRCE_TRACE("FirmwareUpdateResource::addPackageCallback: %p", cb);

    externalPackageCallback = cb;

    return ARM_UCS_LWM2M_INTERNAL_SUCCESS;
}

#if !defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) || (ARM_UC_PROFILE_MBED_CLIENT_LITE == 0)
/* Add callback for resource /10252/0/9, Update */
arm_uc_error_t FirmwareUpdateResource::addUpdateCallback(void (*cb)(void))
{
    UC_SRCE_TRACE("FirmwareUpdateResource::addUpdateCallback: %p", cb);

    ARM_UC_INIT_ERROR(retval, ERR_NONE);

    externalUpdateCallback = cb;

    return retval;
}
#endif

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

/* Send state for resource /10252/0/2, State */
int32_t FirmwareUpdateResource::sendState(arm_ucs_lwm2m_state_t state)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendState");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if ((resourceState != NULL)
            && ARM_UC_IsValidState(state)
            && resourceState->set_value((int64_t)state)) {
        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }
    return result;
}

/* Send result for resource /10252/0/3, Update Result */
int32_t FirmwareUpdateResource::sendUpdateResult(arm_ucs_lwm2m_result_t updateResult)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendUpdateResult");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if ((resourceResult != NULL)
            && ARM_UC_IsValidResult(updateResult)
            && resourceResult->set_value((int64_t)updateResult)) {
        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }
    return result;
}

/* Send name for resource /10252/0/5 PkgName */
#define MAX_PACKAGE_NAME_CHARS 32
int32_t FirmwareUpdateResource::sendPkgName(const uint8_t *name, uint16_t length)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendPkgName");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if ((resourceName == NULL)
            || (name == NULL)
            || (length > MAX_PACKAGE_NAME_CHARS)) {
        UC_SRCE_ERR_MSG("bad arguments - resourceName, package name or length.");
    } else {
        /* the maximum length is defined in the OMA LWM2M standard. */
        uint8_t value[MAX_PACKAGE_NAME_CHARS * 2] = { 0 };
        uint8_t index = 0;

        /* convert to printable characters using lookup table */
        for (; (index < 32) && (index < length); index++) {
            value[2 * index    ] = arm_uc_hex_table[name[index] >> 4];
            value[2 * index + 1] = arm_uc_hex_table[name[index] & 0x0F];
        }
        if (resourceName->set_value(value, 2 * index)) {
            result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
        }
    }
    return result;
}

/* Send version for resource /10252/0/6, PkgVersion */
#define MAX_PACKAGE_VERSION_CHARS 21
int32_t FirmwareUpdateResource::sendPkgVersion(uint64_t version)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::sendPkgVersion");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;
    if (resourceVersion != NULL) {
        char buffer[20+1];
        uint32_t len = m2m::itoa_c(version, buffer);
        if (resourceVersion->set_value((uint8_t*)buffer, len)) {
            result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
        }
    }
    return result;
}

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
int32_t FirmwareUpdateResource::setM2MInterface(M2MInterface *interface)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::setM2MInterface");

    int32_t result = ARM_UCS_LWM2M_INTERNAL_ERROR;

    if (interface != NULL) {
        _m2m_interface = interface;
        result = ARM_UCS_LWM2M_INTERNAL_SUCCESS;
    }
    return result;
}
#endif

void FirmwareUpdateResource::Uninitialize(void)
{
    UC_SRCE_TRACE("FirmwareUpdateResource::Uninitialize");
    delete updateObject;
    updateObject = NULL;
    resourcePackage = NULL;
    resourcePackageURI = NULL;
    resourceUpdate = NULL;
    resourceState = NULL;
    resourceResult = NULL;
    resourceName = NULL;
    resourceVersion = NULL;

}

#endif // ARM_UC_ENABLE
