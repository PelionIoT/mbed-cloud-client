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
// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>

#include "update-lwm2m-mbed-apis.h"
#include "update-client-common/arm_uc_common.h"
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-lwm2m/DeviceMetadataResource.h"
#include "update-client-common/arm_uc_config.h"

/* forward declaration */
static void ARM_UCS_PackageCallback(const uint8_t *buffer, uint16_t length);

/* local copy of the received manifest */
static uint8_t *arm_ucs_manifest_buffer = NULL;
static uint16_t arm_ucs_manifest_length = 0;

/* callback function pointer and struct */
static void (*ARM_UCS_EventHandler)(uint32_t event) = 0;
static arm_uc_callback_t callbackNodeManifest = { NULL, 0, NULL, 0 };
static arm_uc_callback_t callbackNodeNotification = { NULL, 0, NULL, 0 };

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
static bool arm_uc_get_data_request_transaction_ongoing = false;
static size_t arm_uc_received_file_size = 0;
static size_t arm_uc_total_file_size = 0;
static void arm_uc_get_data_req_callback(const uint8_t *buffer, size_t buffer_size, size_t total_size, bool last_block,
                                         void *context);
static void arm_uc_get_data_req_error_callback(get_data_req_error_t error_code, void *context);

#define ARM_UCS_DEFAULT_COST (900)
#define ARM_UCS_HASH_LENGTH  (40)

// The hub uses a double buffer system to speed up firmware download and storage
#define BUFFER_SIZE_MAX (ARM_UC_BUFFER_SIZE / 2) //  define size of the double buffers

// Set proper Storage buffer size with requirements:
// 1. Storage buffer size >= Block size (SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE)
// 1. & 2 AND is >= page size (BUFFER_SIZE_MAX)
// 2. & 3. AND is multiple of Block size (X * SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE)
#define STORAGE_BUFFER_SIZE max_storage(SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE, BUFFER_SIZE_MAX)
//                                  1.               2.                 3.
#define max_storage(X,Y)    ((X) > (Y) ? (X) : ( (Y%X==0) ? (Y) :(BLOCK_MULTIPLIER(X,Y)*X)))

#define BLOCK_MULTIPLIER(X,Y)   ((Y/X)+1)

static uint8_t storage_message[STORAGE_BUFFER_SIZE];
static arm_uc_buffer_t storage_buffer = {
    .size_max = STORAGE_BUFFER_SIZE,
    .size = 0,
    .ptr = storage_message
};

static arm_uc_buffer_t *output_buffer_ptr = NULL;
static char *copy_full_url = NULL;
static DownloadType download_type = FIRMWARE_DOWNLOAD; //default FIRMWARE = COAP download using filepath of server;

#endif // ARM_UC_FEATURE_FW_SOURCE_COAP

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

#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
    arm_uc_get_data_request_transaction_ongoing = false;
    arm_uc_received_file_size = 0;
    arm_uc_total_file_size = 0;
#endif

    if (cb_event != 0) {
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

            ARM_UC_SET_ERROR(result, SRCE_ERR_NONE);

            /* signal event handler that manifest has been copied to buffer */
            if (ARM_UCS_EventHandler) {
                ARM_UC_PostCallback(&callbackNodeManifest,
                                    ARM_UCS_EventHandler,
                                    EVENT_MANIFEST);
            }
        }
    }

    return result;
}

static void ARM_UCS_PackageCallback(const uint8_t *buffer, uint16_t length)
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
        result.code = SRCE_ERR_NONE ;
    }
#else
    /* not supported */
    if (cost != 0) {
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareURLCost cost 0xFFFFFFFF");
        *cost = 0xFFFFFFFF;
        result.code = SRCE_ERR_NONE ;
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

    arm_uc_error_t retval = { .code = SRCE_ERR_INVALID_PARAMETER };
#if defined(ARM_UC_FEATURE_FW_SOURCE_COAP) && (ARM_UC_FEATURE_FW_SOURCE_COAP == 1)
    if (uri == NULL || buffer == NULL || FirmwareUpdateResource::getM2MInterface() == NULL) {
        return retval;
    }

    UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: %s %s, buffer size: %" PRIu32 ", buffer max: %" PRIu32
                  " offset: %" PRIu32, (const char *)uri->ptr, uri->path, buffer->size, buffer->size_max, offset);
    UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: total file size %" PRIu32 ", received file size %" PRIu32,
                  (uint32_t)arm_uc_total_file_size, (uint32_t)arm_uc_received_file_size);

    /*
     * NOTE: we are using M2MInterface API "get_data_request()" asynchronously, so first call to GetFirmwareFragment()
     * will not return anything in the buffer. Instead we will get COAP blocks into callback arm_uc_get_data_req_callback()
     * where we will copy those to our internal storage_buffer. When storage_buffer has enough data
     * (more or eq than buffer->size_max == Storage Page size) we will copy data from it to output buffer
     * and indicate to Hub state machine using event EVENT_FIRMWARE
     */
    if (offset == 0) {
        // First fragment
        storage_buffer.size = 0;
        arm_uc_received_file_size = 0;
        arm_uc_total_file_size = 0;
    } else if (arm_uc_received_file_size == 0) {
        // The received file size was reset to zero indicating that we have received the full payload
        // as indicated by the server but we are asked to carry on downloading from the given offset.
        // This indicates a mismatch between the actual payload size in the server and that given in the manifest.
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: payload size indicated in manifest is bigger than that reported by server!");
        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeManifest,
                                ARM_UCS_EventHandler,
                                EVENT_ERROR);
        }
        return retval;
    }

    output_buffer_ptr = buffer;
    free(copy_full_url);
    copy_full_url = (char *)malloc(arm_uc_calculate_full_uri_length(uri));
    if (copy_full_url == NULL) {
        //TODO to return SRCE_ERR_OUT_OF_MEMORY
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: ERROR OUT OF MEMORY for uri copy!");
        return retval;
    }
    if (uri->scheme == URI_SCHEME_COAPS) {
        strcpy(copy_full_url, UC_COAPS_STRING);
    } else if (uri->scheme == URI_SCHEME_HTTP) {
        strcpy(copy_full_url, UC_HTTP_STRING);
    } else {
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: Not Supported SCHEME!");
        return retval;
    }
    strcat(copy_full_url, (const char *)uri->ptr);
    strcat(copy_full_url, uri->path);


    if ((arm_uc_received_file_size == arm_uc_total_file_size &&
            arm_uc_received_file_size != 0)) {

        // If last block - write to buffer and complete
        if (storage_buffer.ptr &&
                (arm_uc_received_file_size == arm_uc_total_file_size)) {
            memcpy(buffer->ptr, storage_buffer.ptr, storage_buffer.size);
            buffer->size = storage_buffer.size;
            memmove(storage_buffer.ptr, storage_buffer.ptr + storage_buffer.size, (storage_buffer.size_max - storage_buffer.size));
            storage_buffer.size -= buffer->size;
        }

        // We were waiting for one more state machine cycle for previous write to complete
        // Now we can return with EVENT_FIRMWARE so that main state machine changes properly
        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeManifest,
                                ARM_UCS_EventHandler,
                                EVENT_FIRMWARE);
        }
        retval.code = SRCE_ERR_NONE;
        arm_uc_received_file_size = 0;
        arm_uc_total_file_size = 0;
    } else if (!arm_uc_get_data_request_transaction_ongoing) {
        // We need to get request for next block of data
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: Issue new get request for uri: %s, offset: %" PRIu32,
                      copy_full_url, (uint32_t)arm_uc_received_file_size);
        if (FirmwareUpdateResource::getM2MInterface()) {

            FirmwareUpdateResource::getM2MInterface()->get_data_request(download_type,
                                                                        copy_full_url,
                                                                        arm_uc_received_file_size,
                                                                        true,
                                                                        arm_uc_get_data_req_callback,
                                                                        arm_uc_get_data_req_error_callback,
                                                                        FirmwareUpdateResource::getM2MInterface());

            arm_uc_get_data_request_transaction_ongoing = true;

            retval.code = SRCE_ERR_NONE;
        }
    } else {
        // There is not enough data in Storage buffer yet
        // AND We have Async get_data_request already ongoing
        // -> Do nothing we should not get here?
        UC_SRCE_TRACE("ARM_UCS_LWM2M_SOURCE_GetFirmwareFragment: ERROR should not get here!");
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
void arm_uc_get_data_req_callback(const uint8_t *buffer, size_t buffer_size, size_t total_size, bool last_block,
                                  void *context) {
    (void)last_block;

    UC_SRCE_TRACE("get_data_req_callback: %" PRIu32 ", %" PRIu32, (uint32_t)buffer_size, (uint32_t)total_size);
    M2MInterface *interface = (M2MInterface *)context;

    if (arm_uc_received_file_size == 0) {
        arm_uc_total_file_size = total_size;
    }

    arm_uc_received_file_size += buffer_size;
    UC_SRCE_TRACE("get_data_req_callback:  received %" PRIu32 "/%" PRIu32, (uint32_t)arm_uc_received_file_size,
                  (uint32_t)arm_uc_total_file_size);

    if (arm_uc_received_file_size == arm_uc_total_file_size) {
        UC_SRCE_TRACE("get_data_req_callback:  transfer completed\n");
    }

    /*
     * FLOW:
     * 1. If there is space in Storage buffer for the incoming buffer -> copy buffer to storage buffer
     * 2. Else signal error event EVENT_ERROR_BUFFER_SIZE
     */
    // Check there is space available in the storage buffer
    if (storage_buffer.size_max - storage_buffer.size >= buffer_size) {
        memcpy(storage_buffer.ptr + storage_buffer.size, buffer, buffer_size);
        storage_buffer.size += buffer_size;
    } else {
        // Error - no space available, signal it to source manager
        UC_SRCE_TRACE("arm_uc_get_data_req_callback:  Storage Buffer OVERFLOW ERROR!! \n");
        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeManifest,
                                ARM_UCS_EventHandler,
                                EVENT_ERROR_BUFFER_SIZE);
        }
        return;
    }

    /*
     * FLOW:
     * 1. If there is enough data in storage-buffer now to complete to output buffer, copy now and indicate with EVENT_FIRMWARE
     *    to continue to write -cycle
     * 2. Else if this is the last block of data, copy the remaining (<size_max) to output buffer and indicate with
     *    EVENT_FIRMWARE to continue to write-cycle
     * 3. Else Request new block of data using API get_data_request
     */
    if (storage_buffer.size >= output_buffer_ptr->size_max) {
        // 1. We have received into Storage buffer at least one page size of data
        // -> Let's return it to UC Hub so that it can be written
        UC_SRCE_TRACE("arm_uc_get_data_req_callback: return with Storage buffer size: %" PRIu32 ", buffer size: %" PRIu32,
                      storage_buffer.size, output_buffer_ptr->size_max);
        if (storage_buffer.ptr) {
            memcpy(output_buffer_ptr->ptr, storage_buffer.ptr, output_buffer_ptr->size_max);
            //storage_buffer.ptr += buffer->size_max;
            memmove(storage_buffer.ptr, storage_buffer.ptr + output_buffer_ptr->size_max,
                    (storage_buffer.size_max - output_buffer_ptr->size_max));
            storage_buffer.size -= output_buffer_ptr->size_max;
            output_buffer_ptr->size = output_buffer_ptr->size_max;
        }

        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeManifest,
                                ARM_UCS_EventHandler,
                                EVENT_FIRMWARE);
        }
        arm_uc_get_data_request_transaction_ongoing = false;
    } else if (arm_uc_received_file_size == arm_uc_total_file_size &&
               arm_uc_received_file_size != 0) {

        // 2. this is the last block of data - copy to output buffer and complete with EVENT_FIRMWARE
        if (storage_buffer.ptr &&
                (arm_uc_received_file_size == arm_uc_total_file_size)) {
            memcpy(output_buffer_ptr->ptr, storage_buffer.ptr, storage_buffer.size);
            output_buffer_ptr->size = storage_buffer.size;

            memmove(storage_buffer.ptr, storage_buffer.ptr + storage_buffer.size, (storage_buffer.size_max - storage_buffer.size));
            storage_buffer.size = 0;
        }

        // We were waiting for one more state machine cycle for previous write to complete
        // Now we can return with EVENT_FIRMWARE so that main state machine changes properly
        if (ARM_UCS_EventHandler) {
            ARM_UC_PostCallback(&callbackNodeManifest,
                                ARM_UCS_EventHandler,
                                EVENT_FIRMWARE);
        }
        arm_uc_get_data_request_transaction_ongoing = false;
        free(copy_full_url);
        copy_full_url = NULL;
        arm_uc_received_file_size = 0;
        arm_uc_total_file_size = 0;
    } else  {
        // 3. We want to issue new get data
        UC_SRCE_TRACE("arm_uc_get_data_req_callback: Issue new get request for uri: %s, offset: %" PRIu32, copy_full_url,
                      (uint32_t)arm_uc_received_file_size);
        interface->get_data_request(download_type,
                                        copy_full_url,
                                        arm_uc_received_file_size,
                                        true,
                                        arm_uc_get_data_req_callback,
                                        arm_uc_get_data_req_error_callback,
                                        interface);
        arm_uc_get_data_request_transaction_ongoing = true;
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

void arm_uc_get_data_req_error_callback(get_data_req_error_t error_code, void *context) {
    UC_SRCE_TRACE("get_data_req_error_callback:  ERROR: %u\n", error_code);
    arm_uc_received_file_size = 0;
    arm_uc_total_file_size = 0;
    arm_uc_get_data_request_transaction_ongoing = false;
    free(copy_full_url);
    copy_full_url = NULL;
    download_type = FIRMWARE_DOWNLOAD;
    if (ARM_UCS_EventHandler) {
        ARM_UC_PostCallback(&callbackNodeManifest,
                            ARM_UCS_EventHandler,
                            EVENT_ERROR);
    }
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
                                                       uint32_t *cost) {
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if (cost) {
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetKeytableURLCost(arm_uc_uri_t *uri,
                                                       uint32_t *cost) {
    (void) uri;
    (void) cost;

    ARM_UC_INIT_ERROR(result, SRCE_ERR_INVALID_PARAMETER);

    /* not supported - return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0)) {
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
arm_uc_error_t ARM_UCS_LWM2M_SOURCE_GetManifestURL(arm_uc_uri_t *uri,
                                                   arm_uc_buffer_t *buffer,
                                                   uint32_t offset) {
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
                                                   arm_uc_buffer_t *buffer) {
    (void) uri;
    (void) buffer;

    ARM_UC_INIT_ERROR(retval, SRCE_ERR_INVALID_PARAMETER);

    return retval;
}

