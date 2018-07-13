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
#include "update-client-common/arm_uc_common.h"
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-lwm2m/DeviceMetadataResource.h"


/* forward declaration */
static void ARM_UCS_PackageCallback(const uint8_t* buffer, uint16_t length);

/* local copy of the received manifest */
static uint8_t* arm_ucs_manifest_buffer = NULL;
static uint16_t arm_ucs_manifest_length = 0;

/* callback function pointer and struct */
static void (*ARM_UCS_EventHandler)(uint32_t event) = 0;
static arm_uc_callback_t callbackNodeManifest = { NULL, 0, NULL, 0 };
static arm_uc_callback_t callbackNodeNotification = { NULL, 0, NULL, 0 };

/**
 * @brief Get driver version.
 * @return Driver version.
 */
uint32_t ARM_UCS_LWM2M_SOURCE_GetVersion(void)
{
    return 0;
}

/**
 * @brief Get Source capabilities.
 * @return Struct containing capabilites. See definition above.
 */
ARM_SOURCE_CAPABILITIES ARM_UCS_LWM2M_SOURCE_GetCapabilities(void)
{
    ARM_SOURCE_CAPABILITIES result;
    result.notify = 0;
    result.manifest_default = 0;
    result.manifest_url = 0;
    result.firmware = 0;
    result.keytable = 0;

    /* the event handler must be set before module can be used */
    if (ARM_UCS_EventHandler != 0)
    {
        result.notify = 1;
        result.manifest_default = 1;
    }

    return result;
}

/**
 * @brief Initialize Source.
 * @details Function pointer to event handler is passed as argument.
 *
 * @param cb_event Function pointer to event handler. See events above.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_Initialize(ARM_SOURCE_SignalEvent_t cb_event)
{
    UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_Initialize: %p", cb_event);
    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    if (cb_event != 0)
    {
        /* store callback handler */
        ARM_UCS_EventHandler = cb_event;

        /* Initialize LWM2M Firmware Update Object */
        FirmwareUpdateResource::Initialize();

        /* Register callback handler */
        FirmwareUpdateResource::addPackageCallback(ARM_UCS_PackageCallback);

        DeviceMetadataResource::Initialize();

        ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);
    }

    return result;
}

/**
 * @brief Uninitialized Source.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_Uninitialize(void)
{
    ARM_UC_INIT_ERROR(retval, SRCE_ERR_NONE);
    DeviceMetadataResource::Uninitialize();
    FirmwareUpdateResource::Uninitialize();

    return retval;
}

/**
 * @brief Cost estimation for retrieving manifest from the default location.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The manifest is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
 *
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost(uint32_t* cost)
{
    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    if (cost != 0)
    {
        /* set cost to 0 when manifest is cached */
        if (arm_ucs_manifest_buffer && arm_ucs_manifest_length)
        {
            *cost = 0;
        }
        /* set cost to 0xFFFFFFFF when manifest has been read */
        else
        {
            *cost = 0xFFFFFFFF;
        }

        ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);
    }

    return result;
}

/**
 * @brief Retrieve manifest from the default location.
 * @details Manifest is stored in supplied buffer.
 *          Event is generated once manifest is in buffer.
 *
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestDefault(arm_uc_buffer_t* buffer,
                                                       uint32_t offset)
{
    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* copy manifest from cache into buffer */
    if ((buffer != NULL) &&
        (buffer->ptr != NULL) &&
        (arm_ucs_manifest_buffer != NULL) &&
        (arm_ucs_manifest_length != 0) &&
        (offset < arm_ucs_manifest_length))
    {
        /* remaining length based on offset request */
        uint16_t length = arm_ucs_manifest_length - offset;

        /* set actual length based on buffer size */
        if (length > buffer->size_max)
        {
            length = buffer->size_max;
        }

        /* size check */
        if (length > 0)
        {
            /* copy manifest from local buffer to external buffer */
            memcpy(buffer->ptr, &arm_ucs_manifest_buffer[offset], length);
            buffer->size = length;

            /* delete local buffer once the entire manifest has been read */
            if (offset + length >= arm_ucs_manifest_length)
            {
                delete[] arm_ucs_manifest_buffer;
                arm_ucs_manifest_buffer = NULL;
                arm_ucs_manifest_length = 0;
            }

            ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);

            /* signal event handler that manifest has been copied to buffer */
            if (ARM_UCS_EventHandler)
            {
                ARM_UC_PostCallback(&callbackNodeManifest,
                                    ARM_UCS_EventHandler,
                                    EVENT_MANIFEST);
            }
        }
    }

    return result;
}

static void ARM_UCS_PackageCallback(const uint8_t* buffer, uint16_t length)
{
    uint32_t event_code = EVENT_ERROR;

    if (arm_ucs_manifest_buffer)
    {
        UC_SRCE_ERR_MSG("received new manifest before reading the old one");

        /* delete old buffer to make space for the new one */
        delete[] arm_ucs_manifest_buffer;
        arm_ucs_manifest_length = 0;
    }

    /* allocate a local buffer of the same size as the manifest */
    arm_ucs_manifest_buffer = new uint8_t[length];

    if (arm_ucs_manifest_buffer)
    {
        /* copy manifest from payload to local buffer */
        memcpy(arm_ucs_manifest_buffer, buffer, length);
        arm_ucs_manifest_length = length;

        event_code = EVENT_NOTIFICATION;
    }

    /* signal event handler with result */
    if (ARM_UCS_EventHandler)
    {
        ARM_UC_PostCallback(&callbackNodeNotification,
                            ARM_UCS_EventHandler,
                            event_code);
    }
}

/*****************************************************************************/
/* Capabilities not supported by this source                                 */
/*****************************************************************************/

/**
 * @brief Cost estimation for retrieving manifest from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The manifest is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
 *
 * @param uri URI struct with manifest location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURLCost(arm_uc_uri_t* uri,
                                                       uint32_t* cost)
{
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if (cost)
    {
        *cost = 0xFFFFFFFF;
        ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);
    }

    return result;
}

/**
 * @brief Cost estimation for retrieving firmware from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The firmware is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve firmware from this Source.
 *
 * @param uri URI struct with firmware location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost(arm_uc_uri_t* uri,
                                                       uint32_t* cost)
{
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if (cost != 0)
    {
        *cost = 0xFFFFFFFF;
        ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);
    }

    return result;
}

/**
 * @brief Cost estimation for retrieving key table from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The firmware is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve firmware from this Source.
 *
 * @param uri URI struct with keytable location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost(arm_uc_uri_t* uri,
                                                       uint32_t* cost)
{
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0))
    {
        *cost = 0xFFFFFFFF;
        ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);
    }

    return result;
}

/**
 * @brief Retrieve manifest from URL.
 * @details Manifest is stored in supplied buffer.
 *          Event is generated once manifest is in buffer.
 *
 * @param uri URI struct with manifest location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURL(arm_uc_uri_t* uri,
                                                   arm_uc_buffer_t* buffer,
                                                   uint32_t offset)
{
    (void) uri;
    (void) buffer;
    (void) offset;

    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

    return retval;
}

/**
 * @brief Retrieve firmware fragment.
 * @details Firmware fragment is stored in supplied buffer.
 *          Event is generated once fragment is in buffer.
 *
 * @param uri URI struct with firmware location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @param offset Firmware offset to retrieve fragment from.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment(arm_uc_uri_t* uri,
                                                        arm_uc_buffer_t* buffer,
                                                        uint32_t offset)
{
    (void) uri;
    (void) buffer;
    (void) offset;

    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

    return retval;
}

/**
 * @brief Retrieve a key table from a URL.
 * @details Key table is stored in supplied buffer.
 *          Event is generated once fragment is in buffer.
 *
 * @param uri URI struct with keytable location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURL(arm_uc_uri_t* uri,
                                                   arm_uc_buffer_t* buffer)
{
    (void) uri;
    (void) buffer;

    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

    return retval;
}

