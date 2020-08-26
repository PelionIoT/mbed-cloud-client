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

#include "update-client-common/arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_FILESYSTEM) && (ARM_UC_FEATURE_PAL_FILESYSTEM == 1)

#include "update-client-paal/arm_uc_paal_update_api.h"

#include "update-client-pal-filesystem/arm_uc_pal_extensions.h"
#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"
#include "arm_uc_pal_filesystem_utils.h"

#include "pal.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "UCPI"

#include <stdio.h>

#define ARM_UC_FIRMWARE_FOLDER_NAME "firmware"

/* pointer to external callback handler */
static ARM_UC_PAAL_UPDATE_SignalEvent_t arm_uc_pal_external_callback = NULL;

static void arm_uc_pal_classic_signal_callback(uintptr_t event)
{
    if (arm_uc_pal_external_callback) {
        arm_uc_pal_external_callback(event);
    }
}

static void arm_uc_pal_classic_callback(palImageEvents_t event)
{
    /*
        ARM_UC_PAAL_EVENT_INITIALIZE_DONE,
        ARM_UC_PAAL_EVENT_PREPARE_DONE,
        ARM_UC_PAAL_EVENT_WRITE_DONE,
        ARM_UC_PAAL_EVENT_FINALIZE_DONE,
        ARM_UC_PAAL_EVENT_READ_DONE,
        ARM_UC_PAAL_EVENT_ACTIVATE_DONE,
        ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE,
        ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE,
        ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE,
        ARM_UC_PAAL_EVENT_INITIALIZE_ERROR,
        ARM_UC_PAAL_EVENT_PREPARE_ERROR,
        ARM_UC_PAAL_EVENT_WRITE_ERROR,
        ARM_UC_PAAL_EVENT_FINALIZE_ERROR,
        ARM_UC_PAAL_EVENT_READ_ERROR,
        ARM_UC_PAAL_EVENT_ACTIVATE_ERROR,
        ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR,
        ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_ERROR,
        ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_ERROR,
    */
    tr_debug("arm_uc_pal_classic_callback");

    switch (event) {
        case PAL_IMAGE_EVENT_INIT:
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);
            break;
        case PAL_IMAGE_EVENT_PREPARE:
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_PREPARE_DONE);
            break;
        case PAL_IMAGE_EVENT_WRITE:
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_WRITE_DONE);
            break;
        case PAL_IMAGE_EVENT_FINALIZE:
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_FINALIZE_DONE);
            break;
        case PAL_IMAGE_EVENT_READTOBUFFER:
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_READ_DONE);
            break;
        case PAL_IMAGE_EVENT_ACTIVATE:
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);
            break;
        default:
            break;
    }
}

/**
 * @brief Initialize the underlying storage and set the callback handler.
 *
 * @param callback Function pointer to event handler.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (callback) {
        palStatus_t status1 = pal_imageInitAPI(arm_uc_pal_classic_callback);
        arm_uc_error_t status2 = pal_ext_imageInitAPI(arm_uc_pal_classic_signal_callback);

        if ((status1 == PAL_SUCCESS) && (status2.error == ERR_NONE)) {
            arm_uc_pal_external_callback = callback;
            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);

            result.code = ERR_NONE;
        } else {
            result.code = ERR_NOT_READY;
        }
    }

    return result;
}

/**
 * @brief Get a bitmap indicating supported features.
 * @details The bitmap is used in conjunction with the firmware and
 *          installer details struct to indicate what fields are supported
 *          and which values are valid.
 *
 * @return Capability bitmap.
 */
ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UC_Classic_PAL_GetCapabilities(void)
{
    ARM_UC_PAAL_UPDATE_CAPABILITIES result = {
        .installer_arm_hash = 0,
        .installer_oem_hash = 0,
        .installer_layout   = 0,
        .firmware_hash      = 1,
        .firmware_hmac      = 0,
        .firmware_campaign  = 0,
        .firmware_version   = 1,
        .firmware_size      = 1
    };

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_Classic_PAL_GetMaxID(void)
{
    return 1;
}

/**
 * @brief Prepare the storage layer for a new firmware image.
 * @details The storage location is set up to receive an image with
 *          the details passed in the details struct.
 *
 * @param location Storage location ID.
 * @param details Pointer to a struct with firmware details.
 * @param buffer Temporary buffer for formatting and storing metadata.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_Prepare(uint32_t location,
                                          const arm_uc_firmware_details_t *details,
                                          arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer) {
        /* encode firmware details in buffer */
        arm_uc_error_t header_status = { .code = ERR_UNSPECIFIED };
        #if ARM_UC_USE_EXTERNAL_HEADER
                header_status = arm_uc_create_external_header_v2(details, buffer);
        #else
                header_status = arm_uc_create_internal_header_v2(details, buffer);
        #endif

        if (header_status.error == ERR_NONE) {
            /* format file name and path */
            char file_path[PAL_MAX_FILE_AND_FOLDER_LENGTH] = { 0 };

            arm_uc_error_t rv = arm_uc_pal_filesystem_get_path(location,
                                                    FIRMWARE_IMAGE_ITEM_HEADER,
                                                    file_path,
                                                    PAL_MAX_FILE_AND_FOLDER_LENGTH);

            if (rv.code == ERR_NONE) {
                tr_debug("file_path: %s", file_path);

                palFileDescriptor_t file = 0;

                /* open file and get file handler */
                palStatus_t status = pal_fsFopen(file_path,
                                                 PAL_FS_FLAG_READWRITETRUNC,
                                                 &file);

                if (status == PAL_SUCCESS) {
                    size_t xfer_size = 0;

                    /* write buffer to file */
                    status = pal_fsFwrite(&file,
                                          buffer->ptr,
                                          buffer->size,
                                          &xfer_size);

                    tr_debug("written: %lu", (unsigned long)xfer_size);

                    /* call event hadnler and set return code if write was successful */
                    if ((status == PAL_SUCCESS) &&
                            (xfer_size == buffer->size)) {
                        result.code = ERR_NONE;

                        arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_PREPARE_DONE);
                    }

                    /* close file after write */
                    status = pal_fsFclose(&file);

                    if (status != PAL_SUCCESS) {
                        tr_error("pal_fsFclose failed: %" PRId32, status);
                    }
                } else {
                    tr_error("pal_fsFopen failed: %" PRId32, status);
                }
            } else {
                tr_error("file name and path too long");
            }
        } else {
            tr_error("header too large for buffer");
        }
    }

    return result;
}

/**
 * @brief Write a fragment to the indicated storage location.
 * @details The storage location must have been allocated using the Prepare
 *          call. The call is expected to write the entire fragment before
 *          signaling completion.
 *
 * @param location Storage location ID.
 * @param offset Offset in bytes to where the fragment should be written.
 * @param buffer Pointer to buffer struct with fragment.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_Write(uint32_t location,
                                        uint32_t offset,
                                        const arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer) {
        palStatus_t status = pal_imageWrite(location,
                                            offset,
                                            (palConstBuffer_t *) buffer);

        if (status == PAL_SUCCESS) {
            result.code = ERR_NONE;
        } else {
            result.code = ERR_NOT_READY;
        }
    }

    return result;
}

/**
 * @brief Close storage location for writing and flush pending data.
 *
 * @param location Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_Finalize(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NOT_READY };

    palStatus_t status = pal_imageFinalize(location);

    if (status == PAL_SUCCESS) {
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Read a fragment from the indicated storage location.
 * @details The function will read until the buffer is full or the end of
 *          the storage location has been reached. The actual amount of
 *          bytes read is set in the buffer struct.
 *
 * @param location Storage location ID.
 * @param offset Offset in bytes to read from.
 * @param buffer Pointer to buffer struct to store fragment. buffer->size
 *        contains the intended read size.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 *         buffer->size contains actual bytes read on return.
 */
arm_uc_error_t ARM_UC_Classic_PAL_Read(uint32_t location,
                                       uint32_t offset,
                                       arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer) {
        palStatus_t status = pal_imageReadToBuffer(location,
                                                   offset,
                                                   (palBuffer_t *) buffer);

        if (status == PAL_SUCCESS) {
            tr_debug("pal_imageReadToBuffer succeeded: %" PRIX32, buffer->size);
            result.code = ERR_NONE;
        } else {
            tr_error("pal_imageReadToBuffer failed");
            result.code = ERR_NOT_READY;
        }
    }

    return result;
}

/**
 * @brief Set the firmware image in the slot to be the new active image.
 * @details This call is responsible for initiating the process for
 *          applying a new/different image. Depending on the platform this
 *          could be:
 *           * An empty call, if the installer can deduce which slot to
 *             choose from based on the firmware details.
 *           * Setting a flag to indicate which slot to use next.
 *           * Decompressing/decrypting/installing the firmware image on
 *             top of another.
 *
 * @param location Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_Activate(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    result = pal_ext_imageActivate(location);

    return result;
}

/**
 * @brief Get firmware details for the actively running firmware.
 * @details This call populates the passed details struct with information
 *          about the currently active firmware image. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        result = pal_ext_imageGetActiveDetails(details);
    }

    return result;
}

/**
 * @brief Get firmware details for the firmware image in the slot passed.
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_GetFirmwareDetails(uint32_t location,
                                                     arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        char file_path[PAL_MAX_FILE_AND_FOLDER_LENGTH + 1] = { 0 };

        arm_uc_error_t rv = arm_uc_pal_filesystem_get_path(location,
                                                    FIRMWARE_IMAGE_ITEM_HEADER,
                                                    file_path,
                                                    PAL_MAX_FILE_AND_FOLDER_LENGTH);

        if (rv.code == ERR_NONE) {
            palFileDescriptor_t file = 0;

            /* open metadata header file if it exists */
            palStatus_t pal_rc = pal_fsFopen(file_path,
                                             PAL_FS_FLAG_READONLY,
                                             &file);

            if (pal_rc == PAL_SUCCESS) {
                size_t xfer_size = 0;

                /* read metadata header */
                uint8_t read_buffer[ARM_UC_EXTERNAL_HEADER_SIZE_V2] = { 0 };

                pal_rc = pal_fsFread(&file,
                                     read_buffer,
                                     ARM_UC_EXTERNAL_HEADER_SIZE_V2,
                                     &xfer_size);

                /* check return code */
                if ((pal_rc == PAL_SUCCESS) &&
                        (xfer_size == ARM_UC_EXTERNAL_HEADER_SIZE_V2)) {
                    tr_debug("read bytes: %lu", (unsigned long)xfer_size);

                    /* read out header magic */
                    uint32_t headerMagic = arm_uc_parse_uint32(&read_buffer[0]);

                    /* read out header magic */
                    uint32_t headerVersion = arm_uc_parse_uint32(&read_buffer[4]);

                    /* choose version to decode */
                    if ((headerMagic == ARM_UC_EXTERNAL_HEADER_MAGIC_V2) &&
                            (headerVersion == ARM_UC_EXTERNAL_HEADER_VERSION_V2)) {
                        result = arm_uc_parse_external_header_v2(read_buffer, details);

                        tr_debug("version: %" PRIu64, details->version);
                        tr_debug("size: %"PRIu64, details->size);

                        if (result.error == ERR_NONE) {
                            arm_uc_pal_classic_signal_callback(ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE);
                        }
                    } else {
                        /* invalid header format */
                        tr_error("invalid header in slot %" PRIu32, location);
                    }
                } else if (xfer_size != ARM_UC_EXTERNAL_HEADER_SIZE_V2) {
                    /* invalid header format */
                    tr_error("invalid header in slot %" PRIu32, location);
                } else {
                    /* unsuccessful read */
                    tr_error("pal_fsFread returned 0x%" PRIX32, (uint32_t) pal_rc);
                }

                /* close file after use */
                pal_rc = pal_fsFclose(&file);

                if (pal_rc != PAL_SUCCESS) {
                    tr_error("pal_fsFclose failed: %" PRId32, pal_rc);
                }
            } else {
                /* header file not present, slot is either invalid or unused. */
                result.code = ERR_NOT_READY;
            }
        }
    }

    return result;
}

/**
 * @brief Get details for the component responsible for installation.
 * @details This call populates the passed details struct with information
 *          about the local installer. Only the fields marked as supported
 *          in the capabilities bitmap will have valid values. The
 *          installer could be the bootloader, a recovery image, or some
 *          other component responsible for applying the new firmware
 *          image.
 *
 * @param details Pointer to installer details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_Classic_PAL_GetInstallerDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        result = pal_ext_installerGetDetails(details);
    }

    return result;
}

const ARM_UC_PAAL_UPDATE ARM_UCP_FILESYSTEM = {
    .Initialize                 = ARM_UC_Classic_PAL_Initialize,
    .GetCapabilities            = ARM_UC_Classic_PAL_GetCapabilities,
    .GetMaxID                   = ARM_UC_Classic_PAL_GetMaxID,
    .Prepare                    = ARM_UC_Classic_PAL_Prepare,
    .Write                      = ARM_UC_Classic_PAL_Write,
    .Finalize                   = ARM_UC_Classic_PAL_Finalize,
    .Read                       = ARM_UC_Classic_PAL_Read,
    .Activate                   = ARM_UC_Classic_PAL_Activate,
    .GetActiveFirmwareDetails   = ARM_UC_Classic_PAL_GetActiveFirmwareDetails,
    .GetFirmwareDetails         = ARM_UC_Classic_PAL_GetFirmwareDetails,
    .GetInstallerDetails        = ARM_UC_Classic_PAL_GetInstallerDetails
};

#endif /* ARM_UC_FEATURE_PAL_FILESYSTEM */
