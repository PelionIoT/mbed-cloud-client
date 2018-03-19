//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2017 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#if defined(ARM_UC_USE_PAL_BLOCKDEVICE)

#define __STDC_FORMAT_MACROS

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice.h"

#include "update-client-pal-blockdevice/arm_uc_pal_blockdevice_platform.h"

#include "update-client-common/arm_uc_config.h"
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_metadata_header_v2.h"

#define TRACE_GROUP "UCPI"
#include "update-client-common/arm_uc_trace.h"
#include <inttypes.h>

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE 0
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
#define ARM_UC_PAL_HEADER_SIZE (((ARM_UC_EXTERNAL_HEADER_SIZE_V2 + MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)   \
                                / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)

static ARM_UC_PAAL_UPDATE_SignalEvent_t arm_uc_block_event_handler = NULL;

static void arm_uc_pal_blockdevice_signal_internal(uint32_t event)
{
    if (arm_uc_block_event_handler)
    {
        arm_uc_block_event_handler(event);
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (callback)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Initialize");

        int status = arm_uc_blockdevice_init();

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS)
        {
            arm_uc_block_event_handler = callback;
            arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);
            result.code = ERR_NONE;
        }
    }

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_BlockDevice_GetMaxID(void)
{
    return 0;
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Prepare(uint32_t location,
                                              const arm_uc_firmware_details_t* details,
                                              arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer && buffer->ptr)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Prepare: %" PRIX32 " %" PRIX32,
                 location, details->size);

        /* encode firmware details in buffer */
        arm_uc_error_t header_status = arm_uc_create_external_header_v2(details,
                                                                        buffer);
        if (header_status.error == ERR_NONE)
        {
            /* round up header to page size */
            uint32_t page_size = arm_uc_blockdevice_get_program_size();
            uint32_t header_size = ((buffer->size + page_size - 1) /
                                    page_size) * page_size;

            /* round up to sector size */
            uint32_t sector_size = arm_uc_blockdevice_get_erase_size();
            uint32_t erase_size = ((header_size + details->size + sector_size - 1) /
                                   sector_size) * sector_size;

            /* find location address */
            uint64_t physical_address =
                MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                    ((uint64_t) location * MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                    MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS);

            UC_PAAL_TRACE("erase: %" PRIX32 " %" PRIX32, physical_address, erase_size);

            /* erase */
            int status = arm_uc_blockdevice_erase(physical_address, erase_size);

            if (status == ARM_UC_BLOCKDEVICE_SUCCESS)
            {
                /* write header */
                status = arm_uc_blockdevice_program(buffer->ptr,
                                                    physical_address,
                                                    header_size);

                if (status == ARM_UC_BLOCKDEVICE_SUCCESS)
                {
                    /* set return code */
                    result.code = ERR_NONE;

                    /* signal done */
                    arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);
                }
                else
                {
                    UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");
                }
            }
            else
            {
                UC_PAAL_ERR_MSG("arm_uc_blockdevice_erase failed");
            }
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_create_external_header_v2 failed");
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Write(uint32_t location,
                                            uint32_t offset,
                                            const arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Write: %" PRIX32 " %" PRIX32 " %" PRIX32,
                 location, offset, buffer->size);

        /* find location address */
        uint64_t physical_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                    ((uint64_t) location *
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) +
                                    ARM_UC_PAL_HEADER_SIZE +
                                    offset;

        int status = ARM_UC_BLOCKDEVICE_SUCCESS;

        /* aligned write */
        uint32_t page_size = arm_uc_blockdevice_get_program_size();
        uint32_t aligned_size = (buffer->size / page_size) * page_size;

        if (aligned_size > 0)
        {
            status = arm_uc_blockdevice_program(buffer->ptr,
                                                physical_address,
                                                aligned_size);
        }

        /* write remainder */
        uint32_t remainder_size = buffer->size - aligned_size;

        if ((status == ARM_UC_BLOCKDEVICE_SUCCESS) && (remainder_size > 0))
        {
            /* check if it is safe to use buffer, i.e. buffer is larger than a page */
            if (buffer->size_max >= page_size)
            {
                memmove(buffer->ptr, &(buffer->ptr[aligned_size]), remainder_size);
                status = arm_uc_blockdevice_program(buffer->ptr,
                                                    physical_address + aligned_size,
                                                    page_size);
            }
            else
            {
                UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");

                status = ARM_UC_BLOCKDEVICE_FAIL;
            }
        }

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS)
        {
            /* set return code */
            result.code = ERR_NONE;

            /* signal done */
            arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_blockdevice_program failed");
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Finalize(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Finalize");

    arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Read(uint32_t location,
                                           uint32_t offset,
                                           arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Read: %" PRIX32 " %" PRIX32 " %" PRIX32,
                 location, offset, buffer->size);

        /* find location address */
        uint64_t physical_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                    ((uint64_t) location *
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) +
                                    ARM_UC_PAL_HEADER_SIZE +
                                    offset;
        uint32_t page_size = arm_uc_blockdevice_get_program_size();
        uint32_t read_size = ((buffer->size - 1) / page_size + 1) * page_size;
        uint32_t status = ARM_UC_BLOCKDEVICE_FAIL;

        if (read_size <= buffer->size_max)
        {
            status = arm_uc_blockdevice_read(buffer->ptr,
                                             physical_address,
                                             read_size);
        }

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS)
        {
            /* set return code */
            result.code = ERR_NONE;

            /* signal done */
            arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_READ_DONE);
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_blockdevice_read failed");
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
arm_uc_error_t ARM_UC_PAL_BlockDevice_Activate(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_Activate");

    arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);

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
arm_uc_error_t ARM_UC_PAL_BlockDevice_GetFirmwareDetails(
                                        uint32_t location,
                                        arm_uc_firmware_details_t* details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details)
    {
        UC_PAAL_TRACE("ARM_UC_PAL_BlockDevice_GetFirmwareDetails");

        /* find location address */
        uint64_t physical_address = MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS +
                                    ((uint64_t) location *
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE /
                                     MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS);

        uint8_t buffer[ARM_UC_PAL_HEADER_SIZE] = { 0 };

        int status = arm_uc_blockdevice_read(buffer,
                                             physical_address,
                                             ARM_UC_PAL_HEADER_SIZE);

        if (status == ARM_UC_BLOCKDEVICE_SUCCESS)
        {
            result = arm_uc_parse_external_header_v2(buffer, details);

            if (result.error == ERR_NONE)
            {
                /* signal done */
                arm_uc_pal_blockdevice_signal_internal(ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE);
            }
            else
            {
                UC_PAAL_ERR_MSG("arm_uc_parse_external_header_v2 failed");
            }
        }
        else
        {
            UC_PAAL_ERR_MSG("arm_uc_blockdevice_read failed");
        }
    }

    return result;
}

#endif // #if defined(ARM_UC_USE_PAL_BLOCKDEVICE)
