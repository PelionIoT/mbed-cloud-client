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

#if defined(TARGET_LIKE_MBED)

#define __STDC_FORMAT_MACROS

#include "update-client-pal-flashiap/arm_uc_pal_flashiap.h"

#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"

#include "update-client-common/arm_uc_metadata_header_v2.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_utilities.h"

#define TRACE_GROUP "UCPI"
#include "update-client-common/arm_uc_trace.h"
#include <inttypes.h>
#include <stddef.h>

#ifndef MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS
#define MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS
#define MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE 1
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS 1
#endif

/* consistency check */
#if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE == 0)
#error Update client storage page cannot be zero.
#endif

#if (MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS == 0)
#error Update client storage locations must be at least 1.
#endif

/* Check that the statically allocated buffers are aligned with the block size */
#define ARM_UC_PAL_ONE_BUFFER (ARM_UC_BUFFER_SIZE / 2)
#define ARM_UC_PAL_PAGES (ARM_UC_PAL_ONE_BUFFER / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)

#if !((ARM_UC_PAL_PAGES * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) == ARM_UC_PAL_ONE_BUFFER)
#error Update client buffer must be divisible by the block page size
#endif

/* Calculate aligned external header size */
#define ARM_UC_PAL_HEADER_SIZE (((ARM_UC_INTERNAL_HEADER_SIZE_V2 + MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)   \
                                / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)

static void (*arm_uc_pal_flashiap_callback)(uint32_t) = NULL;

static void arm_uc_pal_flashiap_signal_internal(uint32_t event)
{
    if (arm_uc_pal_flashiap_callback)
    {
        arm_uc_pal_flashiap_callback(event);
    }
}

arm_uc_error_t ARM_UC_PAL_FlashIAP_Initialize(void (*callback)(uint32_t))
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    int32_t status = arm_uc_flashiap_init();

    if (status == ARM_UC_FLASHIAP_SUCCESS)
    {
        arm_uc_pal_flashiap_callback = callback;
        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);

        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_FlashIAP_GetMaxID(void)
{
    return MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
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
arm_uc_error_t ARM_UC_PAL_FlashIAP_Prepare(uint32_t location,
                                           const arm_uc_firmware_details_t* details,
                                           arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer && buffer->ptr)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Prepare: %" PRIX32 " %" PRIX32,
                 location, details->size);

        /* encode firmware details in buffer */
        result  = arm_uc_create_internal_header_v2(details, buffer);

        /* make space for new firmware */
        if (result.error == ERR_NONE)
        {
            /* find location start address */
            uint32_t slot_size = MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                 MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
            uint32_t start_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                     location * slot_size;

            /* find end address */
            uint32_t end_address = start_address +
                                   ARM_UC_PAL_HEADER_SIZE +
                                   details->size;

            uint32_t erase_address = start_address;

            /* find exact erase size */
            while (erase_address < end_address)
            {
                uint32_t sector_size = arm_uc_flashiap_get_sector_size(erase_address);
                erase_address += sector_size;
            }

            if (erase_address > (start_address + slot_size))
            {
                result.code = ERR_INVALID_PARAMETER;
                UC_PAAL_ERR_MSG("Firmware too large");
            }
            else
            {
                /* erase */
                erase_address = start_address;
                while (erase_address < end_address)
                {
                    uint32_t sector_size = arm_uc_flashiap_get_sector_size(erase_address);

                    int32_t status = arm_uc_flashiap_erase(erase_address, sector_size);

                    UC_PAAL_TRACE("erase: %" PRIX32 " %" PRIX32 " %" PRId32,
                             erase_address,
                             sector_size,
                             status);

                    if (status == ARM_UC_FLASHIAP_SUCCESS)
                    {
                        erase_address += sector_size;
                    }
                    else
                    {
                        result.code = ERR_INVALID_PARAMETER;
                        break;
                    }
                }
            }

            if (result.error == ERR_NONE)
            {
                UC_PAAL_TRACE("program: %" PRIX32 " %" PRIX32,
                         start_address,
                         ARM_UC_PAL_HEADER_SIZE);

                uint32_t page_size = arm_uc_flashiap_get_page_size();

                /* set default return code */
                result.code = ERR_NONE;

                for (uint32_t index = 0;
                     index < ARM_UC_PAL_HEADER_SIZE;
                     index += page_size)
                {
                    /* write header */
                    int32_t status = arm_uc_flashiap_program(&buffer->ptr[index],
                                                             start_address + index,
                                                             page_size);

                    if (status != ARM_UC_FLASHIAP_SUCCESS)
                    {
                        /* set return code */
                        result.code = ERR_INVALID_PARAMETER;
                        break;
                    }
                }

                if (result.error == ERR_NONE)
                {
                    /* signal done */
                    arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);
                }
                else
                {
                    UC_PAAL_ERR_MSG("arm_uc_flashiap_program failed");
                }
            }
            else
            {
                UC_PAAL_ERR_MSG("arm_uc_flashiap_erase failed");
            }
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_create_internal_header_v2 failed");
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
arm_uc_error_t ARM_UC_PAL_FlashIAP_Write(uint32_t location,
                                         uint32_t offset,
                                         const arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr)
    {
        /* find location address */
        uint32_t physical_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                    (location * MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) +
                                    ARM_UC_PAL_HEADER_SIZE +
                                    offset;

        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Write: %p %" PRIX32 " %" PRIX32 " %" PRIX32,
                 buffer->ptr,
                 buffer->size,
                 physical_address,
                 offset);

        /* set default return code */
        result.code = ERR_NONE;

        uint32_t page_size = arm_uc_flashiap_get_page_size();

        for (uint32_t index = 0; index < buffer->size; index += page_size)
        {
            int status = arm_uc_flashiap_program(&buffer->ptr[index],
                                                 physical_address + index,
                                                 page_size);

            if (status != ARM_UC_FLASHIAP_SUCCESS)
            {
                /* set return code */
                result.code = ERR_INVALID_PARAMETER;
                break;
            }
        }

        if (result.error == ERR_NONE)
        {
            /* signal done */
            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_flashiap_program failed");
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
arm_uc_error_t ARM_UC_PAL_FlashIAP_Finalize(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Finalize");

    arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

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
arm_uc_error_t ARM_UC_PAL_FlashIAP_Read(uint32_t location,
                                        uint32_t offset,
                                        arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Read: %" PRIX32 " %" PRIX32 " %" PRIX32,
                 location, offset, buffer->size);

        /* find location address */
        uint32_t physical_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                    (location * MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) +
                                    ARM_UC_PAL_HEADER_SIZE +
                                    offset;

        uint32_t read_size = buffer->size;

        int status = arm_uc_flashiap_read(buffer->ptr,
                                          physical_address,
                                          read_size);

        if (status == ARM_UC_FLASHIAP_SUCCESS)
        {
            /* set return code */
            result.code = ERR_NONE;

            /* signal done */
            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_READ_DONE);
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_flashiap_read failed");
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
arm_uc_error_t ARM_UC_PAL_FlashIAP_Activate(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Activate");

    arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);

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
arm_uc_error_t ARM_UC_PAL_FlashIAP_GetFirmwareDetails(
                                        uint32_t location,
                                        arm_uc_firmware_details_t* details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_GetFirmwareDetails");

        /* find location address */
        uint32_t physical_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                    (location * MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS);

        uint8_t buffer[ARM_UC_PAL_HEADER_SIZE] = { 0 };

        int status = arm_uc_flashiap_read(buffer,
                                          physical_address,
                                          ARM_UC_PAL_HEADER_SIZE);

        if (status == ARM_UC_FLASHIAP_SUCCESS)
        {
            result = arm_uc_parse_internal_header_v2(buffer, details);

            if (result.error == ERR_NONE)
            {
                /* signal done */
                arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE);
            }
            else
            {
                UC_PAAL_ERR_MSG("arm_uc_parse_internal_header_v2 failed");
            }
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_flashiap_read failed");
        }
    }

    return result;
}

/*****************************************************************************/

arm_uc_error_t ARM_UC_PAL_FlashIAP_GetActiveDetails(arm_uc_firmware_details_t* details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details)
    {
        /* read details from memory if offset is set */
        if (MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS)
        {
            /* set default error code */
            result.code = ERR_NOT_READY;

            /* Use flash driver eventhough we are reading from internal flash.
               This will make it easier to use with uVisor.
             */
            uint8_t version_buffer[8] = { 0 };

            /* read metadata magic and version from flash */
            int rc = arm_uc_flashiap_read(version_buffer,
                                          MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                          8);

            if (rc == ARM_UC_FLASHIAP_SUCCESS)
            {
                /* read out header magic */
                uint32_t headerMagic = arm_uc_parse_uint32(&version_buffer[0]);

                /* read out header magic */
                uint32_t headerVersion = arm_uc_parse_uint32(&version_buffer[4]);

                /* choose version to decode */
                switch(headerVersion)
                {
                    case ARM_UC_INTERNAL_HEADER_VERSION_V2:
                    {
                        result.code = ERR_NONE;
                        /* Check the header magic */
                        if (headerMagic != ARM_UC_INTERNAL_HEADER_MAGIC_V2)
                        {
                            UC_PAAL_ERR_MSG("firmware header is v2, but does not contain v2 magic");
                            result.code = ERR_NOT_READY;
                        }

                        uint8_t read_buffer[ARM_UC_INTERNAL_HEADER_SIZE_V2] = { 0 };
                        /* Read the rest of the header */
                        if (result.error == ERR_NONE)
                        {
                            rc = arm_uc_flashiap_read(read_buffer,
                                                      MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                                      ARM_UC_INTERNAL_HEADER_SIZE_V2);
                            if (rc != 0)
                            {
                                result.code = ERR_NOT_READY;
                                UC_PAAL_ERR_MSG("failed to read v2 header");
                            }
                        }
                        /* Parse the header */
                        if (result.error == ERR_NONE)
                        {
                            result = arm_uc_parse_internal_header_v2(read_buffer, details);
                            if (result.error != ERR_NONE)
                            {
                                UC_PAAL_ERR_MSG("failed to parse v2 header");
                            }
                        }
                        break;
                    }
                    /*
                     * Other firmware header versions can be supported here.
                     */
                    default:
                    {
                        UC_PAAL_ERR_MSG("unrecognized firmware header version");
                        result.code = ERR_NOT_READY;
                    }
                }
            }
            else
            {
                UC_PAAL_ERR_MSG("flash read failed");
            }
        }
        else
        {
            /* offset not set - zero out struct */
            memset(details, 0, sizeof(arm_uc_firmware_details_t));

            result.code = ERR_NONE;
        }

        /* signal event if operation was successful */
        if (result.error == ERR_NONE)
        {
            UC_PAAL_TRACE("callback");

            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);
        }
    }

    return result;
}

arm_uc_error_t ARM_UC_PAL_FlashIAP_GetInstallerDetails(arm_uc_installer_details_t* details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details)
    {
        /* only read from memory if offset is set */
        if (MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS)
        {
            uint8_t* arm = (uint8_t*) (MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS +
                offsetof(arm_uc_installer_details_t, arm_hash));

            uint8_t* oem = (uint8_t*) (MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS +
                offsetof(arm_uc_installer_details_t, oem_hash));

            uint8_t* layout = (uint8_t*) (MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS +
                offsetof(arm_uc_installer_details_t, layout));

            /* populate installer details struct */
            memcpy(&details->arm_hash, arm, ARM_UC_SHA256_SIZE);
            memcpy(&details->oem_hash, oem, ARM_UC_SHA256_SIZE);
            details->layout = arm_uc_parse_uint32(layout);
        }
        else
        {
            /* offset not set, zero details struct */
            memset(details, 0, sizeof(arm_uc_installer_details_t));
        }

        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);

        result.code = ERR_NONE;
    }

    return result;
}

#endif
