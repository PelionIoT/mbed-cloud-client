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

#include <inttypes.h>

#include "update-client-common/arm_uc_trace.h"
#include "update-lwm2m-mbed-apis.h"
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-client-common/arm_uc_scheduler.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-lwm2m/DeviceMetadataResource.h"
#ifdef LWM2M_SOURCE_USE_C_API
#include "firmware_update.h"
#include "device_metadata.h"
#include "lwm2m_get_req_handler.h"
#endif

#include <stdio.h>

#ifndef LWM2M_SOURCE_USE_C_API
/* forward declaration */
static void ARM_UCS_PackageCallback(const uint8_t *buffer, uint16_t length);
#endif

/* local copy of the received manifest */
static uint8_t *arm_ucs_manifest_buffer = NULL;
static uint16_t arm_ucs_manifest_length = 0;

/* callback function pointer and struct */
static void (*ARM_UCS_EventHandler)(uintptr_t event) = 0;
static arm_uc_callback_t callbackNodeData = { NULL, 0, NULL, 0 };
static arm_uc_callback_t callbackNodeNotification = { NULL, 0, NULL, 0 };

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
static void arm_uc_get_data_req_callback(const uint8_t *buffer, size_t buffer_size, size_t total_size, bool last_block,
                                         void *context);
static void arm_uc_get_data_req_error_callback(get_data_req_error_t error_code, void *context);

#define ARM_UCS_DEFAULT_COST (900)

// The hub uses a double buffer system to speed up firmware download and storage
#define BUFFER_SIZE_MAX (ARM_UC_BUFFER_SIZE / 2) //  define size of the double buffers

#if BUFFER_SIZE_MAX < SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
#error MBED_CLOUD_CLIENT_UPDATE_BUFFER must be at least double the size of SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE 1
#endif

/* consistency check */
#if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE == 0)
#error Update client storage page cannot be zero.
#endif

/* Check that SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE is aligned with the storage page size */
#if ((SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE % MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) != 0)
#error SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE must be divisible by the block page size
#endif

#ifndef LWM2M_SOURCE_USE_C_API
/* M2MInterface */
static M2MInterface *arm_ucs_m2m_interface = NULL;
#endif

#endif // ARM_UC_FEATURE_FW_SOURCE_COAP

#ifdef LWM2M_SOURCE_USE_C_API

static endpoint_t *endpoint;

void ARM_UCS_LWM2M_SOURCE_endpoint_set(endpoint_t *ep)
{
    endpoint = ep;
}

registry_t *ARM_UCS_LWM2M_SOURCE_registry_get(void)
{
    return &endpoint->registry;
}

const ARM_UPDATE_SOURCE *ARM_UCS_LWM2M_SOURCE_source_get(void)
{
   return &ARM_UCS_LWM2M_SOURCE;
}

#endif

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
    UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetCapabilities:");

    result.notify = 0;
    result.manifest_default = 0;
    result.manifest_url = 0;
    result.firmware = 0;
    result.keytable = 0;

    /* the event handler must be set before module can be used */
    if (ARM_UCS_EventHandler != 0) {
        result.notify = 1;
        result.manifest_default = 1;
        result.manifest_url = 1;
#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
        result.firmware = 1;
#endif
        result.keytable = 1;
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

    if (cb_event != 0) {
        /* store callback handler */
        ARM_UCS_EventHandler = cb_event;

#ifndef LWM2M_SOURCE_USE_C_API

        /* Initialize LWM2M Firmware Update Object */
        FirmwareUpdateResource::Initialize();

        /* Register callback handler */
        FirmwareUpdateResource::addPackageCallback(ARM_UCS_PackageCallback);

        DeviceMetadataResource::Initialize();

        ARM_UC_SET_ERROR(result, ERR_NONE);

#else
        /* Initialize LWM2M Firmware Update Object */
        if (firmware_update_initialize(&endpoint->registry) && device_metadata_create(&endpoint->registry)) {
            ARM_UC_SET_ERROR(result, ERR_NONE);
        } else {
            firmware_update_destroy(&endpoint->registry);
        }
#endif


    }

    return result;
}

/**
 * @brief Uninitialized Source.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_Uninitialize(void)
{
    ARM_UC_INIT_ERROR(retval, ERR_NONE);
#ifndef LWM2M_SOURCE_USE_C_API
    DeviceMetadataResource::Uninitialize();
    FirmwareUpdateResource::Uninitialize();
#else
    device_metadata_destroy(&endpoint->registry);
    firmware_update_destroy(&endpoint->registry);
#endif

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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestDefaultCost(uint32_t *cost)
{
    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    if (cost != 0) {
        /* set cost to 0 when manifest is cached */
        if (arm_ucs_manifest_buffer && arm_ucs_manifest_length) {
            *cost = 0;
        }
        /* set cost to 0xFFFFFFFF when manifest has been read */
        else {
            *cost = 0xFFFFFFFF;
        }

        ARM_UC_SET_ERROR(result, ERR_NONE);
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestDefault(arm_uc_buffer_t *buffer,
                                                       uint32_t offset)
{
    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* copy manifest from cache into buffer */
    if ((buffer != NULL) &&
            (buffer->ptr != NULL) &&
            (arm_ucs_manifest_buffer != NULL) &&
            (arm_ucs_manifest_length != 0) &&
            (offset < arm_ucs_manifest_length)) {
        /* remaining length based on offset request */
        uint16_t length = arm_ucs_manifest_length - offset;

        /* set actual length based on buffer size */
        if (length > buffer->size_max) {
            length = buffer->size_max;
        }

        /* size check */
        if (length > 0) {
            /* copy manifest from local buffer to external buffer */
            memcpy(buffer->ptr, &arm_ucs_manifest_buffer[offset], length);
            buffer->size = length;

            /* delete local buffer once the entire manifest has been read */
            if (offset + length >= arm_ucs_manifest_length) {
                delete[] arm_ucs_manifest_buffer;
                arm_ucs_manifest_buffer = NULL;
                arm_ucs_manifest_length = 0;
            }

            ARM_UC_SET_ERROR(result, ERR_NONE);

            /* signal event handler that manifest has been copied to buffer */
            if (ARM_UCS_EventHandler) {
                ARM_UC_PostCallback(&callbackNodeData,
                                    ARM_UCS_EventHandler,
                                    EVENT_MANIFEST);
            }
        }
    }

    return result;
}

bool ARM_UCS_LWM2M_SOURCE_manifast_received(const uint8_t *buffer, uint16_t length)
{
    uint32_t event_code = EVENT_ERROR;

    if (arm_ucs_manifest_buffer) {
        UC_SRCE_ERR_MSG("received new manifest before reading the old one");

        /* delete old buffer to make space for the new one */
        delete[] arm_ucs_manifest_buffer;
        arm_ucs_manifest_length = 0;
    }

    /* allocate a local buffer of the same size as the manifest */
    arm_ucs_manifest_buffer = new uint8_t[length];

    if (arm_ucs_manifest_buffer) {
        /* copy manifest from payload to local buffer */
        memcpy(arm_ucs_manifest_buffer, buffer, length);
        arm_ucs_manifest_length = length;

        event_code = EVENT_NOTIFICATION;
    }

    /* signal event handler with result */
    if (ARM_UCS_EventHandler) {
        ARM_UC_PostCallback(&callbackNodeNotification,
                            ARM_UCS_EventHandler,
                            event_code);
    }

    return (event_code != EVENT_ERROR);

}

#ifndef LWM2M_SOURCE_USE_C_API
static void ARM_UCS_PackageCallback(const uint8_t *buffer, uint16_t length)
{
    (void)ARM_UCS_LWM2M_SOURCE_manifast_received(buffer, length);
}
#endif


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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost)
{
    UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost");

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
    /* not supported - return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0)) {
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost uri and cost");
        *cost = ARM_UCS_DEFAULT_COST;
        result.code = ERR_NONE ;
    }
#else
    /* not supported */
    if (cost != 0) {
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost cost 0xFFFFFFFF");
        *cost = 0xFFFFFFFF;
        result.code = ERR_NONE ;
    }
#endif

    return result;
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment(arm_uc_uri_t *uri,
                                                        arm_uc_buffer_t *buffer,
                                                        uint32_t offset)
{
    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
    if (uri &&
        uri->ptr &&
        buffer &&
        buffer->ptr &&
#ifndef LWM2M_SOURCE_USE_C_API
        arm_ucs_m2m_interface) {
#else
        endpoint) {
#endif

        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: %s%s, buffer size: %" PRIu32 ", buffer max: %" PRIu32
                      " offset: %" PRIu32, (const char *) uri->host, uri->path, buffer->size, buffer->size_max, offset);

        /* Convert URI struct back to URI string. */
        buffer->size = 0;
        if (uri->scheme == URI_SCHEME_COAPS) {
            buffer->size = snprintf((char*) buffer->ptr, buffer->size_max, "coaps://%s%s", uri->host, uri->path);
        } else if (uri->scheme == URI_SCHEME_HTTP) {
            buffer->size = snprintf((char*) buffer->ptr, buffer->size_max, "http://%s%s", uri->host, uri->path);
        }
        buffer->ptr[buffer->size] = '\0';

        if (buffer->size) {
            /* Request data fragment through M2M interface from offset. Requested length defaults
               to the CoAP packet size when the asynchronous flag is set to true.
            */
#ifndef LWM2M_SOURCE_USE_C_API
            arm_ucs_m2m_interface->get_data_request(FIRMWARE_DOWNLOAD,
                                                    (const char*) buffer->ptr,
                                                    offset,
                                                    true,
                                                    arm_uc_get_data_req_callback,
                                                    arm_uc_get_data_req_error_callback,
                                                    buffer);
#else
            get_handler_send_get_data_request(endpoint,
                                              FIRMWARE_DOWNLOAD,
                                              (const char*) buffer->ptr,
                                              offset,
                                              true,
                                              arm_uc_get_data_req_callback,
                                              arm_uc_get_data_req_error_callback,
                                              buffer);
#endif

            retval.code = ERR_NONE;
        }
    }

    return retval;

#else
    (void) uri;
    (void) buffer;
    (void) offset;

    return retval;
#endif //ARM_UC_FEATURE_FW_SOURCE_COAP
}

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
/**
 * @brief      Internal function for handling data reception.
 *
 * @param[in]  buffer       Pointer to buffer with received data.
 * @param[in]  buffer_size  Buffer size.
 * @param[in]  total_size   Total size of requested resource.
 * @param[in]  last_block   Boolean to indicate if this is the last block of the resource.
 * @param      context      Pointer to context passed in the originating call.
 */
void arm_uc_get_data_req_callback(const uint8_t *buffer,
                                  size_t buffer_size,
                                  size_t total_size,
                                  bool last_block,
                                  void *context)
{
    (void) last_block;
    (void) total_size;

    UC_SRCE_TRACE("get_data_req_callback: %" PRIu32 ", %" PRIu32,
                  (uint32_t) buffer_size, (uint32_t) total_size);

    /* Cast context back to buffer pointer. */
    arm_uc_buffer_t *output_buffer = (arm_uc_buffer_t *) context;

    /* Ensure buffer is valid. */
    if (output_buffer &&
        output_buffer->ptr &&
        (output_buffer->size_max >= buffer_size)) {

        /* Copy data to internal buffer and set size. */
        memcpy(output_buffer->ptr, buffer, buffer_size);
        output_buffer->size = buffer_size;

        /* Signal hub data is ready. */
        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeData,
                                ARM_UCS_EventHandler,
                                EVENT_FIRMWARE);
        }
    } else {
        /* Signal hub an error occurred. */
        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeData,
                                ARM_UCS_EventHandler,
                                EVENT_ERROR);
        }
    }

#ifdef ARM_UC_COAP_DATA_PRINTOUT
    if (buffer) {
        uint32_t i = 0;
        int row_len = 40;
        uint32_t max_length = 2048;

        while (i < buffer_size && i < max_length) {
            if (i + row_len > buffer_size) {
                row_len = buffer_size - i;
            }
            UC_SRCE_TRACE("Payload:\t\t%s", tr_array(buffer + i, row_len)); // in HEX

            i += row_len;
        }
    }
#endif
}

/**
 * @brief      Internal function for handling request errors.
 *
 * @param[in]  error_code  Error code.
 * @param      context     Pointer to context passed in the originating call.
 */
void arm_uc_get_data_req_error_callback(get_data_req_error_t error_code, void *context)
{
    UC_SRCE_TRACE("get_data_req_error_callback: ERROR: %u\n", error_code);

    /* Propagate error to hub. */
    if (ARM_UCS_EventHandler) {
        ARM_UC_PostCallback(&callbackNodeData,
                            ARM_UCS_EventHandler,
                            EVENT_ERROR);
    }
}

/**
 * @brief      Function for providing access to the M2M interface.
 * @param      interface  Pointer to M2M interface.
 * @return     Error code.
 */
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_SetM2MInterface(M2MInterface *interface)
{
    UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_SetM2MInterface");

    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

    if (interface) {
#ifndef LWM2M_SOURCE_USE_C_API
        arm_ucs_m2m_interface = interface;
#endif
        retval.code = ERR_NONE;

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
        DeviceMetadataResource::setM2MInterface(interface);
        FirmwareUpdateResource::setM2MInterface(interface);
#endif
    }

    return retval;
}
#endif //ARM_UC_FEATURE_FW_SOURCE_COAP

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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost)
{
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if (cost) {
        *cost = 0xFFFFFFFF;
        ARM_UC_SET_ERROR(result, ERR_NONE);
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost)
{
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0)) {
        *cost = 0xFFFFFFFF;
        ARM_UC_SET_ERROR(result, ERR_NONE);
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURL(arm_uc_uri_t *uri,
                                                   arm_uc_buffer_t *buffer,
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURL(arm_uc_uri_t *uri,
                                                   arm_uc_buffer_t *buffer)
{
    (void) uri;
    (void) buffer;

    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

    return retval;
}
#endif // ARM_UC_ENABLE 1
