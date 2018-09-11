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

#include "arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_RTL8195AM) && (ARM_UC_FEATURE_PAL_RTL8195AM == 1)
#if defined(TARGET_REALTEK_RTL8195AM)

#include "update-client-paal/arm_uc_paal_update_api.h"
#include "update-client-pal-flashiap/arm_uc_pal_flashiap_platform.h"

#include "update-client-common/arm_uc_metadata_header_v2.h"
#include "update-client-common/arm_uc_common.h"

#include "ota_api.h"
#include "flash_ext.h"

#define HEADER_SIZE     (OTA_CRC32_OFS + 4)

typedef enum {
    BASE_ADDRESS_RUNNING,
    BASE_ADDRESS_SPARE
} base_address_t;

typedef enum {
    BASE_SLOT_0 = 0,
    BASE_SLOT_1 = 1,
    BASE_SLOT_INVALID
} base_slot_t;

/**
 * Base slot, for caching between operations.
 */
static base_slot_t arm_uc_base_slot = BASE_SLOT_INVALID;

static const uint32_t arm_uc_address_header[2] = { OTA_REGION1_HEADER, OTA_REGION2_HEADER };
static const uint32_t arm_uc_address_firmware[2] = { OTA_REGION1_BASE, OTA_REGION2_BASE };

/**
 * Callback handler.
 */
static void (*arm_uc_pal_rtl8195am_callback)(uint32_t) = NULL;

/**
 * @brief      Signal external event handler with NULL pointer check.
 *
 * @param[in]  event  The event
 */
static void arm_uc_pal_rtl8195am_signal_internal(uint32_t event)
{
    if (arm_uc_pal_rtl8195am_callback) {
        arm_uc_pal_rtl8195am_callback(event);
    }
}

/**
 * @brief      Create header compatible with the RTL8195AM bootloader
 *
 * @param[in]  details  Update client firmware details struct.
 * @param      buffer   Scratch buffer for creating the header.
 *
 * @return     ERR_NONE on success. ERR_INVALID_PARAMETER on failure.
 */
static arm_uc_error_t arm_uc_pal_create_realtek_header(const arm_uc_firmware_details_t *details,
                                                       arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer && buffer->ptr && (buffer->size_max >= HEADER_SIZE)) {
        /* set tag */
        buffer->ptr[OTA_TAG_OFS    ] =  OTA_TAG_ID        & 0xFF;
        buffer->ptr[OTA_TAG_OFS + 1] = (OTA_TAG_ID >>  8) & 0xFF;
        buffer->ptr[OTA_TAG_OFS + 2] = (OTA_TAG_ID >> 16) & 0xFF;
        buffer->ptr[OTA_TAG_OFS + 3] = (OTA_TAG_ID >> 24) & 0xFF;

        /* set version tag */
        buffer->ptr[OTA_VER_OFS    ] =  OTA_VER_ID        & 0xFF;
        buffer->ptr[OTA_VER_OFS + 1] = (OTA_VER_ID >>  8) & 0xFF;
        buffer->ptr[OTA_VER_OFS + 2] = (OTA_VER_ID >> 16) & 0xFF;
        buffer->ptr[OTA_VER_OFS + 3] = (OTA_VER_ID >> 24) & 0xFF;

        /* set timestamp */
        buffer->ptr[OTA_EPOCH_OFS    ] =  details->version        & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 1] = (details->version >>  8) & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 2] = (details->version >> 16) & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 3] = (details->version >> 24) & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 4] = (details->version >> 32) & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 5] = (details->version >> 40) & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 6] = (details->version >> 48) & 0xFF;
        buffer->ptr[OTA_EPOCH_OFS + 7] = (details->version >> 56) & 0xFF;

        /* set size */
        uint32_t size_with_header = details->size + HEADER_SIZE;

        buffer->ptr[OTA_SIZE_OFS    ] =  size_with_header        & 0xFF;
        buffer->ptr[OTA_SIZE_OFS + 1] = (size_with_header >>  8) & 0xFF;
        buffer->ptr[OTA_SIZE_OFS + 2] = (size_with_header >> 16) & 0xFF;
        buffer->ptr[OTA_SIZE_OFS + 3] = (size_with_header >> 24) & 0xFF;

        /* copy hash */
        for (size_t index = 0; index < ARM_UC_SHA256_SIZE; index++) {
            buffer->ptr[OTA_HASH_OFS + index] = details->hash[index];
        }

        /* copy campaign */
        for (size_t index = 0; index < ARM_UC_GUID_SIZE; index++) {
            buffer->ptr[OTA_CAMPAIGN_OFS + index] = details->campaign[index];
        }

        /* set buffer size minus CRC */
        buffer->size = HEADER_SIZE - 4;

        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief      Read header for the image located at the base address.
 *
 * @param[in]  base_slot     Header slot.
 * @param      details       Update client details struct.
 *
 * @return     ERR_NONE on success, ERR_INVALID_PARAMETER on failure.
 */
static arm_uc_error_t arm_uc_pal_get_realtek_header(base_slot_t base_slot,
                                                    arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if ((base_slot != BASE_SLOT_INVALID) && details) {
        uint8_t buffer[HEADER_SIZE] = { 0 };

        int rc = arm_uc_flashiap_read(buffer, arm_uc_address_header[base_slot], sizeof(buffer));

        if (rc == 0) {
#if 0
            printf("debug: \r\n");
            for (size_t index = 0; index < sizeof(buffer); index++) {
                printf("%02X", buffer[index]);
            }
            printf("\r\n");
#endif

            /* parse tag */
            uint32_t tag = buffer[OTA_TAG_OFS + 3];
            tag = (tag << 8) | buffer[OTA_TAG_OFS + 2];
            tag = (tag << 8) | buffer[OTA_TAG_OFS + 1];
            tag = (tag << 8) | buffer[OTA_TAG_OFS + 0];

            /* parse version tag */
            uint32_t version_tag = buffer[OTA_VER_OFS + 3];
            version_tag = (version_tag << 8) | buffer[OTA_VER_OFS + 2];
            version_tag = (version_tag << 8) | buffer[OTA_VER_OFS + 1];
            version_tag = (version_tag << 8) | buffer[OTA_VER_OFS + 0];

            UC_PAAL_TRACE("tag: %" PRIX32, tag);
            UC_PAAL_TRACE("version_tag: %" PRIX32, version_tag);

            /* check tags */
            if ((tag == OTA_TAG_ID) && (version_tag == OTA_VER_ID)) {
                /* parse CRC */
                uint32_t crc_header = buffer[OTA_CRC32_OFS + 3];
                crc_header = (crc_header << 8) | buffer[OTA_CRC32_OFS + 2];
                crc_header = (crc_header << 8) | buffer[OTA_CRC32_OFS + 1];
                crc_header = (crc_header << 8) | buffer[OTA_CRC32_OFS + 0];

                /* calculate crc */
                uint32_t crc_calculated = arm_uc_crc32(buffer, OTA_CRC32_OFS);

                UC_PAAL_TRACE("CRC header:     %" PRIX32, crc_header);
                UC_PAAL_TRACE("CRC calculated: %" PRIX32, crc_calculated);

                /* check crc before proceeding */
                if (crc_header == crc_calculated) {
                    /* parse size */
                    uint32_t size = buffer[OTA_SIZE_OFS + 3];
                    size = (size << 8) | buffer[OTA_SIZE_OFS + 2];
                    size = (size << 8) | buffer[OTA_SIZE_OFS + 1];
                    size = (size << 8) | buffer[OTA_SIZE_OFS + 0];

                    /* parse version */
                    uint64_t version = buffer[OTA_EPOCH_OFS + 7];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 6];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 5];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 4];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 3];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 2];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 1];
                    version = (version << 8) | buffer[OTA_EPOCH_OFS + 0];

                    /* copy hash */
                    for (size_t index = 0; index < ARM_UC_SHA256_SIZE; index++) {
                        details->hash[index] = buffer[OTA_HASH_OFS + index];
                    }

                    details->size = size - HEADER_SIZE;
                    details->version = version;

                    UC_PAAL_TRACE("size: %" PRIu64, details->size);
                    UC_PAAL_TRACE("version: %" PRIu64, details->version);

#if 0
                    printf("hash: ");
                    for (size_t index = 0; index < ARM_UC_SHA256_SIZE; index++) {
                        printf("%02X", details->hash[index]);
                    }
                    printf("\r\n");
#endif

                    result.code = ERR_NONE;
                } else {
                    UC_PAAL_ERR_MSG("header crc check failed");
                }
            } else {
                UC_PAAL_ERR_MSG("invalid header");
            }
        } else {
            UC_PAAL_ERR_MSG("error reading from flash");
        }
    }

    return result;
}

/**
 * @brief      Find base address of either running or spare firmare slot.
 *
 * @param[in]  find  Enum specifying what to find (running or spare slot).
 *
 * @return     Base slot.
 */
static base_slot_t arm_uc_pal_find_base_slot(base_address_t find)
{
    base_slot_t base_slot = BASE_SLOT_0;

    arm_uc_firmware_details_t slot_0 = { 0 };
    arm_uc_firmware_details_t slot_1 = { 0 };

    /* read header from both slots */
    arm_uc_error_t result_0 = arm_uc_pal_get_realtek_header(BASE_SLOT_0, &slot_0);
    arm_uc_error_t result_1 = arm_uc_pal_get_realtek_header(BASE_SLOT_1, &slot_1);

    /* both headers are valid */
    if ((result_0.error == ERR_NONE) && (result_1.error == ERR_NONE)) {
        /* running firmware has the highest version number */
        if (find == BASE_ADDRESS_RUNNING) {
            base_slot = (slot_0.version >= slot_1.version) ? BASE_SLOT_0 : BASE_SLOT_1;
        }
        /* spare firmware has the lowest version number */
        else {
            /* same test, swap result */
            base_slot = (slot_0.version >= slot_1.version) ? BASE_SLOT_1 : BASE_SLOT_0;
        }
    }
    /* only slot0 has a valid header */
    else if (result_0.error == ERR_NONE) {
        if (find == BASE_ADDRESS_RUNNING) {
            /* only valid header must be the running one */
            base_slot = BASE_SLOT_0;
        } else {
            /* slot with invalid header can be used as spare */
            base_slot = BASE_SLOT_1;
        }
    }
    /* only slot1 has a valid header */
    else if (result_1.error == ERR_NONE) {
        if (find == BASE_ADDRESS_RUNNING) {
            /* only valid header must be the running one */
            base_slot = BASE_SLOT_1;
        } else {
            /* slot with invalid header can be used as spare */
            base_slot = BASE_SLOT_0;
        }
    }

    /* if both headers are invalid return 0 */

    return base_slot;
}

/*****************************************************************************/

arm_uc_error_t ARM_UC_PAL_RTL8195AM_Initialize(void (*callback)(uint32_t))
{
    arm_uc_error_t result = { .code = ERR_NONE };

    arm_uc_flashiap_init();
    arm_uc_pal_rtl8195am_callback = callback;

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_RTL8195AM_GetMaxID(void)
{
    return 2;
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
arm_uc_error_t ARM_UC_PAL_RTL8195AM_Prepare(uint32_t location,
                                            const arm_uc_firmware_details_t *details,
                                            arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer && buffer->ptr) {
        UC_PAAL_TRACE("Prepare: %" PRIX32 " %" PRIX64 " %" PRIu64,
                      location,
                      details->size,
                      details->version);

        /* find location for the spare slot */
        arm_uc_base_slot = arm_uc_pal_find_base_slot(BASE_ADDRESS_SPARE);

        UC_PAAL_TRACE("spare base slot: %d", arm_uc_base_slot);

        /* check that the firmware can fit the spare slot */
        if (((arm_uc_base_slot == BASE_SLOT_0) &&
                (details->size < (OTA_REGION1_SIZE - FLASH_SECTOR_SIZE))) ||
                ((arm_uc_base_slot == BASE_SLOT_1) &&
                 (details->size < (OTA_REGION2_SIZE - FLASH_SECTOR_SIZE)))) {
            /* encode firmware details in buffer */
            result  = arm_uc_pal_create_realtek_header(details, buffer);

            /* make space for new firmware */
            if (result.error == ERR_NONE) {
                /* erase header */
                uint32_t erase_address = arm_uc_address_header[arm_uc_base_slot];
                uint32_t end_address = erase_address + HEADER_SIZE;

                /* erase */
                while (erase_address < end_address) {
                    uint32_t sector_size = arm_uc_flashiap_get_sector_size(erase_address);
                    int status = arm_uc_flashiap_erase(erase_address, sector_size);

                    UC_PAAL_TRACE("erase: %" PRIX32 " %" PRIX32 " %d",
                                  erase_address,
                                  sector_size,
                                  status);

                    if (status == 0) {
                        erase_address += sector_size;
                    } else {
                        result.code = ERR_INVALID_PARAMETER;
                        break;
                    }
                }

                /* erase firmware */
                if (result.error == ERR_NONE) {
                    /* find end address */
                    erase_address = arm_uc_address_firmware[arm_uc_base_slot];
                    end_address = erase_address + details->size;

                    /* erase */
                    while (erase_address < end_address) {
                        uint32_t sector_size = arm_uc_flashiap_get_sector_size(erase_address);
                        int status = arm_uc_flashiap_erase(erase_address, sector_size);

                        UC_PAAL_TRACE("erase: %" PRIX32 " %" PRIX32 " %d",
                                      erase_address,
                                      sector_size,
                                      status);

                        if (status == 0) {
                            erase_address += sector_size;
                        } else {
                            result.code = ERR_INVALID_PARAMETER;
                            break;
                        }
                    }

                    /* write header */
                    if (result.error == ERR_NONE) {
                        UC_PAAL_TRACE("program: %u %" PRIu32,
                                      arm_uc_address_header[arm_uc_base_slot],
                                      buffer->size);

                        /* set default return code */
                        result.code = ERR_NONE;

                        /* write header without CRC */
                        int status = arm_uc_flashiap_program(buffer->ptr,
                                                             arm_uc_address_header[arm_uc_base_slot],
                                                             buffer->size);

                        if (status != 0) {
                            /* set return code */
                            result.code = ERR_INVALID_PARAMETER;
                        }

                        if (result.error == ERR_NONE) {
                            /* signal done */
                            arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);
                        } else {
                            UC_PAAL_ERR_MSG("flash program failed");
                        }
                    } else {
                        UC_PAAL_ERR_MSG("flash erase failed");
                    }
                } else {
                    UC_PAAL_ERR_MSG("erase header failed");
                }
            } else {
                UC_PAAL_ERR_MSG("create header failed");
            }
        } else {
            UC_PAAL_ERR_MSG("firmware larger than slot");
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
arm_uc_error_t ARM_UC_PAL_RTL8195AM_Write(uint32_t location,
                                          uint32_t offset,
                                          const arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr && (arm_uc_base_slot != BASE_SLOT_INVALID)) {
        /* find location address */
        uint32_t physical_address = arm_uc_address_firmware[arm_uc_base_slot] + offset;

        UC_PAAL_TRACE("Write: %p %" PRIX32 " %" PRIX32 " %" PRIX32,
                      buffer->ptr,
                      buffer->size,
                      offset,
                      physical_address);

        /* set default return code */
        result.code = ERR_NONE;

        for (size_t index = 0; index < buffer->size;) {
            /* write aligned */
            size_t modulo = (physical_address + index) % FLASH_PAGE_SIZE;
            size_t remaining = buffer->size - index;
            size_t write_size = 0;

            /* fill remaining flash page */
            if (modulo > 0) {
                write_size = modulo;
            }
            /* write last page */
            else if (remaining < FLASH_PAGE_SIZE) {
                write_size = remaining;
            }
            /* write full page */
            else {
                write_size = FLASH_PAGE_SIZE;
            }

            int status = arm_uc_flashiap_program(&buffer->ptr[index],
                                                 physical_address + index,
                                                 write_size);

            if (status != 0) {
                /* set return code */
                result.code = ERR_INVALID_PARAMETER;
                break;
            }

            index += write_size;
        }

        if (result.error == ERR_NONE) {
            /* signal done */
            arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);
        } else {
            UC_PAAL_ERR_MSG("flash program failed");
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
arm_uc_error_t ARM_UC_PAL_RTL8195AM_Finalize(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    UC_PAAL_TRACE("Finalize");

    arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

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
arm_uc_error_t ARM_UC_PAL_RTL8195AM_Read(uint32_t location,
                                         uint32_t offset,
                                         arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && buffer->ptr) {
        /* find the base address for the spare slot if not already set */
        if (arm_uc_base_slot == BASE_SLOT_INVALID) {
            arm_uc_base_slot = arm_uc_pal_find_base_slot(BASE_ADDRESS_SPARE);
        }

        /* calculate actual physical address */
        uint32_t physical_address = arm_uc_address_firmware[arm_uc_base_slot] + offset;

        UC_PAAL_TRACE("Read: %" PRIX32 " %" PRIX32 " %" PRIX32,
                      physical_address,
                      offset,
                      buffer->size);

        uint32_t read_size = buffer->size;

        int status = arm_uc_flashiap_read(buffer->ptr, physical_address, read_size);

        if (status == 0) {
            /* set buffer size */
            buffer->size = read_size;

            /* set return code */
            result.code = ERR_NONE;

            /* signal done */
            arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_READ_DONE);
        } else {
            UC_PAAL_ERR_MSG("flash read failed");
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
arm_uc_error_t ARM_UC_PAL_RTL8195AM_Activate(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    UC_PAAL_TRACE("Activate");

    if (arm_uc_base_slot != BASE_SLOT_INVALID) {
        uint8_t buffer[HEADER_SIZE] = { 0 };

        int status = arm_uc_flashiap_read(buffer, arm_uc_address_header[arm_uc_base_slot], sizeof(buffer));

        if (status == 0) {
            /* calculate CRC */
            uint32_t crc = arm_uc_crc32(buffer, OTA_CRC32_OFS);

            buffer[0] =  crc        & 0xFF;
            buffer[1] = (crc >>  8) & 0xFF;
            buffer[2] = (crc >> 16) & 0xFF;
            buffer[3] = (crc >> 24) & 0xFF;

            /* set crc in header to signal the bootloader that the image is ready */
            status = arm_uc_flashiap_program(buffer, arm_uc_address_header[arm_uc_base_slot] + OTA_CRC32_OFS, 4);

            if (status == 0) {
                /* set return code */
                result.code = ERR_NONE;

                /* signal done */
                arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);
            }
        }
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
arm_uc_error_t ARM_UC_PAL_RTL8195AM_GetFirmwareDetails(
    uint32_t location,
    arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* this function is only used by the mbed Bootloader */

    return result;
}

/*****************************************************************************/

arm_uc_error_t ARM_UC_PAL_RTL8195AM_GetActiveDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        UC_PAAL_TRACE("GetActiveDetails");

        /* find running slot */
        base_slot_t base_slot = arm_uc_pal_find_base_slot(BASE_ADDRESS_RUNNING);

        UC_PAAL_TRACE("active base: %d", base_slot);

        result = arm_uc_pal_get_realtek_header(base_slot, details);

        /* signal event if operation was successful */
        if (result.error == ERR_NONE) {
            arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);
        }
    }

    return result;
}

arm_uc_error_t ARM_UC_PAL_RTL8195AM_GetInstallerDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* reset installer details struct */
        memset(&details->arm_hash, 0, ARM_UC_SHA256_SIZE);
        memset(&details->oem_hash, 0, ARM_UC_SHA256_SIZE);
        details->layout = 0;

        /* the magic tag identifies the bootloader it is compatible with */
        details->oem_hash[0] = (OTA_TAG_ID >> 24) & 0xFF;
        details->oem_hash[1] = (OTA_TAG_ID >> 16) & 0xFF;
        details->oem_hash[2] = (OTA_TAG_ID >>  8) & 0xFF;
        details->oem_hash[3] =  OTA_TAG_ID        & 0xFF;

        details->oem_hash[4] = (OTA_VER_ID >> 24) & 0xFF;
        details->oem_hash[5] = (OTA_VER_ID >> 16) & 0xFF;
        details->oem_hash[6] = (OTA_VER_ID >>  8) & 0xFF;
        details->oem_hash[7] =  OTA_VER_ID        & 0xFF;

        result.code = ERR_NONE;

        arm_uc_pal_rtl8195am_signal_internal(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);
    }

    return result;
}

ARM_UC_PAAL_UPDATE_CAPABILITIES ARM_UC_PAL_RTL8195AM_GetCapabilities(void)
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

const ARM_UC_PAAL_UPDATE ARM_UCP_REALTEK_RTL8195AM = {
    .Initialize                 = ARM_UC_PAL_RTL8195AM_Initialize,
    .GetCapabilities            = ARM_UC_PAL_RTL8195AM_GetCapabilities,
    .GetMaxID                   = ARM_UC_PAL_RTL8195AM_GetMaxID,
    .Prepare                    = ARM_UC_PAL_RTL8195AM_Prepare,
    .Write                      = ARM_UC_PAL_RTL8195AM_Write,
    .Finalize                   = ARM_UC_PAL_RTL8195AM_Finalize,
    .Read                       = ARM_UC_PAL_RTL8195AM_Read,
    .Activate                   = ARM_UC_PAL_RTL8195AM_Activate,
    .GetActiveFirmwareDetails   = ARM_UC_PAL_RTL8195AM_GetActiveDetails,
    .GetFirmwareDetails         = ARM_UC_PAL_RTL8195AM_GetFirmwareDetails,
    .GetInstallerDetails        = ARM_UC_PAL_RTL8195AM_GetInstallerDetails
};

#endif
#endif /* ARM_UC_FEATURE_PAL_RTL8195AM */
