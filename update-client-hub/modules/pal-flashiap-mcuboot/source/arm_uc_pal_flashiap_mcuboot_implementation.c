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
#if defined(ARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT) && (ARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT == 1)

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>

#include "update-client-pal-flashiap-mcuboot/arm_uc_pal_flashiap_mcuboot.h"
#include "update-client-pal-flashiap-mcuboot/arm_uc_pal_flashiap_mcuboot_platform.h"
#include "update-client-pal-flashiap-mcuboot/arm_uc_pal_flashiap_mcuboot_helper.h"

#include <inttypes.h>
#include <stddef.h>

#define TRACE_GROUP  "UCPI"

/* Address for MCUBOOT header in the active slot */
#ifndef MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS
#define MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS 0
#endif

/* Address for MCUBOOT header in the candidate slot */
#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS 0
#endif

/* Slot size */
#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE 0
#endif

/* Flash page write size */
#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE 1
#endif

/* Number of candidate slots, only 1 is supported */
#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS
#define MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS 1
#endif

/* MCUBOOT trailer size, depends on slot size, page size, and optional encryption. */
#ifndef MBED_CONF_UPDATE_CLIENT_MCUBOOT_TRAILER_SIZE
#define MBED_CONF_UPDATE_CLIENT_MCUBOOT_TRAILER_SIZE 0
#endif

/* consistency check */
#if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE == 0)
#error Update client storage page cannot be zero.
#endif

#if !(MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS == 1)
#error Update client storage locations must be 1.
#endif

/* Check that the statically allocated buffers are aligned with the block size */
#define ARM_UC_PAL_ONE_BUFFER (ARM_UC_BUFFER_SIZE / 2)
#define ARM_UC_PAL_PAGES (ARM_UC_PAL_ONE_BUFFER / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)

#if !((ARM_UC_PAL_PAGES * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE) == ARM_UC_PAL_ONE_BUFFER)
#error Update client buffer must be divisible by the block page size
#endif

/* Check if trailer size has been set */
#if MBED_CONF_UPDATE_CLIENT_MCUBOOT_TRAILER_SIZE
#error Custom trailers currently not supported. \
       Configure MCUBOOT to work without trailers or \
       use imgtool.py to create signed images with padded trailers.
#endif

/**
 * Calculate buffer size for storing activation header.
 */
#if IMAGE_HEADER_SIZE < MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
/* use page size as buffer size directly */
#define MCUBOOT_HEADER_BUFFER_SIZE MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#else
/* round up buffer size and aling to page size */
#define PAGE_MINUS_ONE (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)
#define HEADER_PLUS_PAGE_MINUS_ONE (IMAGE_HEADER_SIZE + PAGE_MINUS_ONE)
#define PAGES_PER_HEADER (HEADER_PLUS_PAGE_MINUS_ONE / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)
#define MCUBOOT_HEADER_BUFFER_SIZE (PAGES_PER_HEADER * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)
#endif

static uint8_t arm_uc_pal_flashiap_mcuboot_header[MCUBOOT_HEADER_BUFFER_SIZE] = { 0 };

/**
 * Transfer firmare details across function calls.
 * Details are provided in Prepare and used in Activate
 */
static arm_uc_firmware_details_t arm_uc_pal_flashiap_details = { 0 };

/**
 * Callback functions
 */
static void (*arm_uc_pal_flashiap_callback)(uint32_t) = NULL;

static void arm_uc_pal_flashiap_signal_internal(uint32_t event)
{
    if (arm_uc_pal_flashiap_callback) {
        arm_uc_pal_flashiap_callback(event);
    }
}

/**
 * @brief Align address up/down to sector boundary
 *
 * @param addr The address that need to be rounded up
 * @param round_down if the value is 1, will align down to sector
                     boundary otherwise align up.
 * @return Returns the address aligned to sector boundary
 */
static uint32_t arm_uc_pal_flashiap_align_to_sector(uint32_t addr, int8_t round_down)
{
    uint32_t sector_start_addr = arm_uc_flashiap_get_flash_start();

    /* check the address is pointing to internal flash */
    if ((addr > sector_start_addr + arm_uc_flashiap_get_flash_size()) ||
            (addr < sector_start_addr)) {
        return ARM_UC_FLASH_INVALID_SIZE;
    }

    /* add sectors from start of flash until exeeced the required address
       we cannot assume uniform sector size as in some mcu sectors have
       drastically different sizes */
    uint32_t sector_size = ARM_UC_FLASH_INVALID_SIZE;
    while (sector_start_addr < addr) {
        sector_size = arm_uc_flashiap_get_sector_size(sector_start_addr);
        if (sector_size != ARM_UC_FLASH_INVALID_SIZE) {
            sector_start_addr += sector_size;
        } else {
            return ARM_UC_FLASH_INVALID_SIZE;
        }
    }

    /* if round down to nearest section, remove the last sector from addr */
    if (round_down != 0 && sector_start_addr > addr) {
        sector_start_addr -= sector_size;
    }

    return sector_start_addr;
}

/**
 * @brief Round size up to nearest page
 *
 * @param size The size that need to be rounded up
 * @return Returns the size rounded up to the nearest page
 */
static uint32_t arm_uc_pal_flashiap_round_up_to_page_size(uint32_t size)
{
    uint32_t page_size = arm_uc_flashiap_get_page_size();

    if (size != 0) {
        size = ((size - 1) / page_size + 1) * page_size;
    }

    return size;
}

/**
 * @brief Get the physicl slot address and size given slot_id
 *
 * @param slot_id Storage location ID.
 * @param slot_addr the slot address is returned in this pointer
 * @param slot_size the slot size is returned in this pointer
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
static arm_uc_error_t arm_uc_pal_flashiap_get_slot_addr_size(uint32_t slot_id,
                                                             uint32_t* slot_addr,
                                                             uint32_t* slot_size)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };
    /* find the start address of the whole storage area. It needs to be aligned to
       sector boundary and we cannot go outside user defined storage area, hence
       rounding up to sector boundary */
    uint32_t storage_start_addr = arm_uc_pal_flashiap_align_to_sector(
                                      MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS, 0);
    /* find the end address of the whole storage area. It needs to be aligned to
       sector boundary and we cannot go outside user defined storage area, hence
       rounding down to sector boundary */
    uint32_t storage_end_addr = arm_uc_pal_flashiap_align_to_sector(
                                    MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS + \
                                    MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE, 1);
    /* find the maximum size each slot can have given the start and end, without
       considering the alignment of individual slots */
    uint32_t max_slot_size = (storage_end_addr - storage_start_addr) / \
                             MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
    /* find the start address of slot. It needs to align to sector boundary. We
       choose here to round down at each slot boundary */
    uint32_t slot_start_addr = arm_uc_pal_flashiap_align_to_sector(
                                   storage_start_addr + \
                                   slot_id * max_slot_size, 1);
    /* find the end address of the slot, rounding down to sector boundary same as
       the slot start address so that we make sure two slot don't overlap */
    uint32_t slot_end_addr = arm_uc_pal_flashiap_align_to_sector(
                                 slot_start_addr + \
                                 max_slot_size, 1);

    /* Any calculation above might result in an invalid address. */
    if ((storage_start_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (storage_end_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (slot_start_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (slot_end_addr == ARM_UC_FLASH_INVALID_SIZE) ||
            (slot_id >= MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS)) {
        UC_PAAL_ERR_MSG("Aligning fw storage slot to erase sector failed"
                        " storage_start_addr %" PRIX32 " slot_start_addr %" PRIX32
                        " max_slot_size %" PRIX32, storage_start_addr, slot_start_addr,
                        max_slot_size);
        *slot_addr = ARM_UC_FLASH_INVALID_SIZE;
        *slot_size = ARM_UC_FLASH_INVALID_SIZE;
    } else {
        *slot_addr = slot_start_addr;
        *slot_size = slot_end_addr - slot_start_addr;
        result.code = ERR_NONE;
    }

    return result;
}

/**
 * @brief Initialise the flash IAP API
 *
 * @param callback function pointer to the PAAL event handler
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_Initialize(void (*callback)(uint32_t))
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    int32_t status = arm_uc_flashiap_init();

    if (status == ARM_UC_FLASHIAP_SUCCESS) {
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
uint32_t ARM_UC_PAL_FlashIAP_Mcuboot_GetMaxID(void)
{
    return MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
}

/**
 * @brief Prepare the storage layer for a new firmware image.
 * @details The storage location is set up to receive an image with
 *          the details passed in the details struct.
 *
 * @param slot_id Storage location ID.
 * @param details Pointer to a struct with firmware details.
 * @param buffer Temporary buffer for formatting and storing metadata.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_Prepare(uint32_t slot_id,
                                                   const arm_uc_firmware_details_t* details,
                                                   arm_uc_buffer_t* buffer)
{
    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_Prepare slot_id %" PRIu32 " details %p buffer %p",
                  slot_id, details, buffer);

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* validate input */
    if (details &&
        buffer && buffer->ptr &&
        (slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS)) {
        UC_PAAL_TRACE("FW size %" PRIu64, details->size);

        uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
        uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
        uint32_t trailer_size = MBED_CONF_UPDATE_CLIENT_MCUBOOT_TRAILER_SIZE;

        /* find slot start address */
        result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id, &slot_addr, &slot_size);

        /* calculate space for new firmware */
        if ((result.error == ERR_NONE) && (details->size <= (slot_size - trailer_size))) {

            /* erase all sectors in slot */
            uint32_t erase_addr = slot_addr;

            while (erase_addr < slot_addr + slot_size) {

                /* account for changing sector sizes */
                uint32_t sector_size = arm_uc_flashiap_get_sector_size(erase_addr);
                UC_PAAL_TRACE("erase: addr %" PRIX32 " size %" PRIX32,
                              erase_addr, sector_size);

                /* erase single sector */
                if (sector_size != ARM_UC_FLASH_INVALID_SIZE) {
                    int32_t status = arm_uc_flashiap_erase(erase_addr, sector_size);
                    if (status == ARM_UC_FLASHIAP_SUCCESS) {
                        erase_addr += sector_size;
                    } else {
                        UC_PAAL_ERR_MSG("Flash erase failed with status %" PRIi32, status);
                        result.code = ERR_INVALID_PARAMETER;
                        break;
                    }
                } else {
                    UC_PAAL_ERR_MSG("Get sector size for addr %" PRIX32 " failed", erase_addr);
                    result.code = ERR_INVALID_PARAMETER;
                    break;
                }
            }

        } else {
            result.code = PAAL_ERR_FIRMWARE_TOO_LARGE;
            UC_PAAL_ERR_MSG("Firmware too large! required %" PRIX64 " available: %" PRIX32,
                            details->size, slot_size - trailer_size);
        }

        if (result.error == ERR_NONE) {

            /* store firmware deatils in global */
            memcpy(&arm_uc_pal_flashiap_details, details, sizeof(arm_uc_firmware_details_t));

            /* signal done */
            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);
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
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to where the fragment should be written.
 * @param buffer Pointer to buffer struct with fragment.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_Write(uint32_t slot_id,
                                                 uint32_t offset,
                                                 const arm_uc_buffer_t* buffer)
{
    /* find slot address and size */
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    arm_uc_error_t result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id,
                                                                   &slot_addr,
                                                                   &slot_size);

    if (buffer && buffer->ptr && result.error == ERR_NONE) {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_Write: %p %" PRIX32 " %" PRIX32 " %" PRIX32,
                      buffer->ptr, buffer->size, slot_addr, offset);

        /* set default error */
        result.code = ERR_INVALID_PARAMETER;

        /**
         * Catch MCUBOOT header at offset 0 and store it in buffer for later activation.
         */
        const uint8_t* write_buffer = buffer->ptr;
        uint32_t write_size = buffer->size;
        uint32_t write_offset = offset;

        if (write_offset == 0) {
            UC_PAAL_TRACE("cache MCUBOOT header for later activation");

            /* copy header to buffer */
            memcpy(arm_uc_pal_flashiap_mcuboot_header, write_buffer, MCUBOOT_HEADER_BUFFER_SIZE);

            /* reconfigure parameters to write after header */
            write_buffer += MCUBOOT_HEADER_BUFFER_SIZE;
            write_size -= MCUBOOT_HEADER_BUFFER_SIZE;
            write_offset += MCUBOOT_HEADER_BUFFER_SIZE;
        }

        /* find physical address of the write */
        uint32_t page_size = arm_uc_flashiap_get_page_size();
        uint32_t physical_address = slot_addr + write_offset;

        /* if last chunk, pad out to page_size aligned size */
        if ((write_size % page_size != 0) &&
            ((write_offset + write_size) >= arm_uc_pal_flashiap_details.size)) {
            write_size = arm_uc_pal_flashiap_round_up_to_page_size(write_size);
        }

        /* check page alignment of the program address and size */
        if ((write_size % page_size == 0) && (physical_address % page_size == 0)) {
            UC_PAAL_TRACE("programming addr %" PRIX32 " size %" PRIX32,
                          physical_address, write_size);

            /* write pages */
            int status = arm_uc_flashiap_program(write_buffer,
                                                 physical_address,
                                                 write_size);

            if (status != ARM_UC_FLASHIAP_SUCCESS) {
                UC_PAAL_ERR_MSG("arm_uc_flashiap_program failed");
            } else {
                result.code = ERR_NONE;
                arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);
            }
        } else {
            UC_PAAL_ERR_MSG("program size %" PRIX32 " or address %" PRIX32
                            " not aligned to page size %" PRIX32, write_size,
                            physical_address, page_size);
        }
    } else {
        result.code = ERR_INVALID_PARAMETER;
    }

    return result;
}

/**
 * @brief Close storage location for writing and flush pending data.
 *
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_Finalize(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    (void) slot_id;

    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_Finalize");

    arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

    return result;
}

/**
 * @brief Read a fragment from the indicated storage location.
 * @details The function will read until the buffer is full or the end of
 *          the storage location has been reached. The actual amount of
 *          bytes read is set in the buffer struct.
 *
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to read from.
 * @param buffer Pointer to buffer struct to store fragment. buffer->size
 *        contains the intended read size.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 *         buffer->size contains actual bytes read on return.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_Read(uint32_t slot_id,
                                                uint32_t offset,
                                                arm_uc_buffer_t* buffer)
{
    /* find slot address and size */
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    arm_uc_error_t result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id,
                                                                   &slot_addr,
                                                                   &slot_size);

    if (buffer && buffer->ptr && result.error == ERR_NONE) {
        UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_Read: %" PRIX32 " %" PRIX32 " %" PRIX32,
                      slot_id, offset, buffer->size);

        /* find physical address of the read */
        uint32_t read_size = buffer->size;
        uint32_t physical_address = slot_addr + offset;

        UC_PAAL_TRACE("reading addr %" PRIX32 " size %" PRIX32,
                      physical_address, read_size);

        int status = arm_uc_flashiap_read(buffer->ptr,
                                          physical_address,
                                          read_size);

        if (status == ARM_UC_FLASHIAP_SUCCESS) {
            result.code = ERR_NONE;

            /**
             * Provide MCUBOOT header from buffer when reading at offset 0
             * so that hash checking newly downloaded firmware succeeds.
             */
            if ((offset == 0) && (buffer->size_max >= MCUBOOT_HEADER_BUFFER_SIZE)) {

                UC_PAAL_TRACE("replace MCUBOOT header with cached version");

                /* copy header to buffer */
                memcpy(buffer->ptr, arm_uc_pal_flashiap_mcuboot_header, MCUBOOT_HEADER_BUFFER_SIZE);
            }

            arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_READ_DONE);
        } else {
            result.code = ERR_INVALID_PARAMETER;
            UC_PAAL_ERR_MSG("arm_uc_flashiap_read failed");
        }
    } else {
        result.code = ERR_INVALID_PARAMETER;
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
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_Activate(uint32_t slot_id)
{
    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_Activate");

    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;

    arm_uc_error_t result = arm_uc_pal_flashiap_get_slot_addr_size(slot_id, &slot_addr, &slot_size);

    /**
     * Get active images's MCUBOOT header hash.
     */
    arm_uc_hash_t header_hash_active = { 0 };

    if (result.error == ERR_NONE) {
        result = arm_uc_pal_flashiap_mcuboot_get_hash_from_header(
                        MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                        &header_hash_active);
    }

    /**
     * Get candidate image's MCUBOOT header hash.
     */
    arm_uc_hash_t header_hash_candidate = { 0 };

    /* find TLV address from header cache */
    image_header_t* header_cache = (image_header_t*) arm_uc_pal_flashiap_mcuboot_header;

    if ((result.error == ERR_NONE) && (header_cache->ih_magic == IMAGE_MAGIC)) {

        UC_PAAL_TRACE("magic: %" PRIX32, header_cache->ih_magic);
        UC_PAAL_TRACE("load: %" PRIX32, header_cache->ih_load_addr);
        UC_PAAL_TRACE("hdr: %" PRIX16, header_cache->ih_hdr_size);
        UC_PAAL_TRACE("img: %" PRIX32, header_cache->ih_img_size);
        UC_PAAL_TRACE("prot: %" PRIX16, header_cache->ih_protect_tlv_size);

        uint32_t tlv_address = slot_addr +
                               header_cache->ih_hdr_size +
                               header_cache->ih_img_size;

        /* search TLV for hash */
        result = arm_uc_pal_flashiap_mcuboot_get_hash_from_tlv(tlv_address,
                                                               &header_hash_candidate);

        /**
         * If hash wasn't found, assume we just searched the optional protected TLV.
         * Proceed to the main TLV and search for hash.
         */
        if ((result.error != ERR_NONE) && header_cache->ih_protect_tlv_size) {

            tlv_address += header_cache->ih_protect_tlv_size;
            result = arm_uc_pal_flashiap_mcuboot_get_hash_from_tlv(tlv_address,
                                                                   &header_hash_candidate);
        }

        if (result.error ==  ERR_NONE) {
            /**
             * Write details to KCM.
             * The active header hash is used to identify which key-value pair to replace.
             */
            arm_uc_pal_flashiap_mcuboot_set_kcm_details(&header_hash_active,
                                                        &header_hash_candidate,
                                                        &arm_uc_pal_flashiap_details);
        } else {
            UC_PAAL_ERR_MSG("No hash found in candidate image");
        }
    }

    /**
     * Final step in activation, write MCUBOOT header.
     */
    UC_PAAL_TRACE("write activation header");

    /* MCUBOOT header buffer is checked for alignment at compile time */
    int status = arm_uc_flashiap_program(arm_uc_pal_flashiap_mcuboot_header,
                                         slot_addr,
                                         MCUBOOT_HEADER_BUFFER_SIZE);

    if (status == ARM_UC_FLASHIAP_SUCCESS) {
        result.code = ERR_NONE;

        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);
    } else {
        UC_PAAL_ERR_MSG("arm_uc_flashiap_program failed");
        result.code = FIRM_ERR_ACTIVATE;
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
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_GetFirmwareDetails(
    uint32_t slot_id,
    arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_GetFirmwareDetails");

    (void) slot_id;
    (void) details;

    /**
     * This function is not used for MCUBOOT.
     */

    arm_uc_error_t result = { .code = ERR_NOT_READY };

    return result;
}

/*****************************************************************************/

arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_GetActiveDetails(arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("ARM_UC_PAL_FlashIAP_Mcuboot_GetActiveDetails");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {

        /* parse MCUBOOT header and get hash from TLV struct */
        arm_uc_hash_t header_hash = { 0 };

        arm_uc_pal_flashiap_mcuboot_get_hash_from_header(MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                                         &header_hash);

        /* use MCUBOOT hash to lookup firmware details in KCM */
        result = arm_uc_pal_flashiap_mcuboot_get_kcm_details(&header_hash, details);

        /* if no details were found in KCM, use hash from MCUBOOT header */
        if (result.error != ERR_NONE) {

            memcpy(details->hash, &header_hash, sizeof(arm_uc_hash_t));
            result.code = ERR_NONE;
        }

#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
        printf("[TRACE][SRCE] manifest hash: ");
        for (size_t index = 0; index < sizeof(arm_uc_hash_t); index++) {
            printf("%02X", details->hash[index]);
        }
        printf("\r\n");
#endif

        /* signal event if operation was successful */
        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);
    }

    return result;
}

/**
 * @brief Get details for the firmware installer.
 * @details This call populates the passed details struct with information
 *          about the firmware installer.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_FlashIAP_Mcuboot_GetInstallerDetails(arm_uc_installer_details_t* details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {

        result.code = ERR_NONE;

        /* installer details not supported with MCUBOOT, zero details struct */
        memset(details, 0, sizeof(arm_uc_installer_details_t));

        arm_uc_pal_flashiap_signal_internal(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);
    }

    return result;
}

#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
