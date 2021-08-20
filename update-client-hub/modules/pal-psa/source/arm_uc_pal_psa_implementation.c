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
#if defined(ARM_UC_FEATURE_PAL_PSA) && (ARM_UC_FEATURE_PAL_PSA == 1)

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>

#include "update-client-pal-psa/arm_uc_pal_psa.h"
#include "update-client-pal-psa/arm_uc_pal_psa_helper.h"

#include <inttypes.h>
#include <stddef.h>

#include "mbedtls/md.h"

/* PSA Firmware Update API */
#include "psa/update.h"

#define TRACE_GROUP  "UCPI"

/* consistency check */
#if !(MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS == 1)
#error Update client storage locations must be 1.
#endif

#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE < IMAGE_HEADER_SIZE
#error SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE must be larger than \
       or equal to MCUBOOTs header size, IMAGE_HEADER_SIZE.
#endif

/**
 * Callback functions
 */
static void (*arm_uc_pal_psa_callback)(uint32_t) = NULL;

static void arm_uc_pal_psa_signal_internal(uint32_t event)
{
    if (arm_uc_pal_psa_callback) {
        arm_uc_pal_psa_callback(event);
    }
}

/* TODO: Support secure and combined secure/non-secure firmware update */

/* PSA image ID: active/stage + non-secure */
#define IMAGE_ID_ACTIVE_NONSECURE                                       \
    ((psa_image_id_t) FWU_CALCULATE_IMAGE_ID(FWU_IMAGE_ID_SLOT_ACTIVE,  \
                                             FWU_IMAGE_TYPE_NONSECURE,  \
                                             0))
#define IMAGE_ID_STAGE_NONSECURE                                        \
    ((psa_image_id_t) FWU_CALCULATE_IMAGE_ID(FWU_IMAGE_ID_SLOT_STAGE,   \
                                             FWU_IMAGE_TYPE_NONSECURE,  \
                                             0))
                                                    
/* firmware update context struct */
typedef struct firmware_update_ctx_s {
    struct psa_fwu_active_s {
        psa_image_info_t        info;
        image_version_t         version;
    } psa_fwu_active;

    struct psa_fwu_stage_s {
        psa_image_info_t        info;
        psa_image_id_t          dependency_uuid;
        psa_image_version_t     dependency_version;
        image_header_t          image_header;       // Cached image header on the fly
                                                    // During FWU process, image version is not available
                                                    // through psa_fwu_query(). Acquire from above cached instead.
        arm_uc_firmware_details_t   details;        // Cached firmware details
    } psa_fwu_stage;
} firmware_update_ctx_t;

/* non-secure firmware update context */
static firmware_update_ctx_t firmware_update_ctx_nonsecure;
                                            
/**
 * @brief Initialise the flash IAP API
 *
 * @param callback function pointer to the PAAL event handler
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_Initialize(void (*callback)(uint32_t))
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    arm_uc_pal_psa_callback = callback;

    /* get active image's version. */
    psa_status_t status = psa_fwu_query(IMAGE_ID_ACTIVE_NONSECURE,
                                        &firmware_update_ctx_nonsecure.psa_fwu_active.info);
    if (status != PSA_SUCCESS) {
        UC_PAAL_ERR_MSG("psa_fwu_query() failed: %d\r\n", status);
        result.code = ERR_UNSPECIFIED;
        return result;
    }
    /* psa_image_version_t and image_version_t are the same struct format, so straight memcpy(). */
    memcpy(&firmware_update_ctx_nonsecure.psa_fwu_active.version,
           &firmware_update_ctx_nonsecure.psa_fwu_active.info.version,
           sizeof(firmware_update_ctx_nonsecure.psa_fwu_active.version));

    /* signal done */
    arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_INITIALIZE_DONE);

    result.code = ERR_NONE;

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_PSA_Mcuboot_GetMaxID(void)
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
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_Prepare(uint32_t slot_id,
                                              const arm_uc_firmware_details_t* details,
                                              arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* validate input */
    if (details &&
        buffer && buffer->ptr &&
        (slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS)) {
        UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_Prepare slot_id %" PRIu32 " details %p buffer %p",
                      slot_id, details, buffer);
        UC_PAAL_TRACE("FW size %" PRIu64, details->size);

        /* clear for clean */
        memset(&firmware_update_ctx_nonsecure.psa_fwu_stage, 0x00, sizeof(firmware_update_ctx_nonsecure.psa_fwu_stage));

        /* store firmware details */
        memcpy(&firmware_update_ctx_nonsecure.psa_fwu_stage.details, details, sizeof(arm_uc_firmware_details_t));

        /* support rewrite sequence aborting previous one */
        psa_fwu_abort(IMAGE_ID_STAGE_NONSECURE);

        /* signal done */
        arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_PREPARE_DONE);

        result.code = ERR_NONE;
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
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_Write(uint32_t slot_id,
                                                 uint32_t offset,
                                                 const arm_uc_buffer_t* buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if ((slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) &&
        buffer && buffer->ptr) {
        UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_Write: buffer=%p buffer size=%" PRIX32 " offset=%" PRIX32,
                      buffer->ptr, buffer->size, offset);

        /* catch MCUBOOT header at offset 0 and store it in buffer for later activation. */
        if (offset == 0) {
            UC_PAAL_TRACE("cache MCUBOOT header for later activation");

            if (buffer->size < sizeof(image_header_t)) {
                UC_PAAL_ERR_MSG("failed to cache MCUBOOT header for later activation at first write: write size=%d",
                                buffer->size);
                result.code = ERR_UNSPECIFIED;
                return result;
            }

            memcpy(&firmware_update_ctx_nonsecure.psa_fwu_stage.image_header, buffer->ptr, sizeof(image_header_t));

            if (firmware_update_ctx_nonsecure.psa_fwu_stage.image_header.ih_magic != IMAGE_MAGIC) {
                UC_PAAL_ERR_MSG("Invalid MCUBOOT header magic");
                result.code = ERR_UNSPECIFIED;
                return result;
            }

            UC_PAAL_TRACE("Image header: padded header size=%d, image size=%d, protected TLV size=%d",
                          firmware_update_ctx_nonsecure.psa_fwu_stage.image_header.ih_hdr_size,
                          firmware_update_ctx_nonsecure.psa_fwu_stage.image_header.ih_img_size,
                          firmware_update_ctx_nonsecure.psa_fwu_stage.image_header.ih_protect_tlv_size);
        }

        /* write through psa_fwu_write(), with max block size PSA_FWU_MAX_BLOCK_SIZE */
        const uint8_t *fwu_src_pos = buffer->ptr;
        const uint8_t *fwu_src_end = buffer->ptr + buffer->size;
        size_t fwu_dst_pos = offset;
        size_t fwu_todo;
        psa_status_t status;

        while (fwu_src_pos < fwu_src_end) {
            fwu_todo = fwu_src_end - fwu_src_pos;
            if (fwu_todo > PSA_FWU_MAX_BLOCK_SIZE) {
                fwu_todo = PSA_FWU_MAX_BLOCK_SIZE;
            }

            status = psa_fwu_write(IMAGE_ID_STAGE_NONSECURE,
                                   fwu_dst_pos,
                                   fwu_src_pos,
                                   fwu_todo);
            if (status != PSA_SUCCESS) {
                UC_PAAL_ERR_MSG("psa_fwu_write(offset=%d, size=%d) failed: %d\r\n",
                                fwu_dst_pos, fwu_todo, status);
                result.code = FIRM_ERR_WRITE;
                return result;
            }

            /* Next block */
            fwu_dst_pos += fwu_todo;
            fwu_src_pos += fwu_todo;
        }

        /* signal done */
        arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_WRITE_DONE);

        result.code = ERR_NONE;
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
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_Finalize(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* validate input */
    if ((slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS)) {
        UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_Finalize");

        /* signal done */
        arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_FINALIZE_DONE);

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
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to read from.
 * @param buffer Pointer to buffer struct to store fragment. buffer->size
 *        contains the intended read size.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 *         buffer->size contains actual bytes read on return.
 */
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_Read(uint32_t slot_id,
                                                uint32_t offset,
                                                arm_uc_buffer_t* buffer)
{
    UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_Read");

    (void) slot_id;
    (void) offset;
    (void) buffer;

    arm_uc_error_t result = { .code = ERR_NOT_READY };

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
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_Activate(uint32_t slot_id)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* validate input */
    if ((slot_id < MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS)) {
        UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_Activate");

        image_header_t* header_candidate = &firmware_update_ctx_nonsecure.psa_fwu_stage.image_header;
        arm_uc_firmware_details_t *details_candidate = &firmware_update_ctx_nonsecure.psa_fwu_stage.details;

        UC_PAAL_TRACE("magic: %" PRIX32, header_candidate->ih_magic);
        UC_PAAL_TRACE("load: %" PRIX32, header_candidate->ih_load_addr);
        UC_PAAL_TRACE("hdr: %" PRIX16, header_candidate->ih_hdr_size);
        UC_PAAL_TRACE("img: %" PRIX32, header_candidate->ih_img_size);
        UC_PAAL_TRACE("prot: %" PRIX16, header_candidate->ih_protect_tlv_size);

        /* Write details to KCM. The active image version is used to identify
         * which key-value pair to replace. */
        result = arm_uc_pal_psa_set_kcm_details(&firmware_update_ctx_nonsecure.psa_fwu_active.version,
                                                &firmware_update_ctx_nonsecure.psa_fwu_stage.image_header.ih_ver,
                                                details_candidate);
        if (result.error != ERR_NONE) {
            return result;
        }

        psa_status_t status = psa_fwu_install(IMAGE_ID_STAGE_NONSECURE,
                                              &firmware_update_ctx_nonsecure.psa_fwu_stage.dependency_uuid,
                                              &firmware_update_ctx_nonsecure.psa_fwu_stage.dependency_version);
        if (status != PSA_SUCCESS && status != PSA_SUCCESS_REBOOT) {
            UC_PAAL_ERR_MSG("psa_fwu_install() failed: %d\r\n", status);
            result.code = FIRM_ERR_ACTIVATE;
            return result;
        }

        /* signal done */
        arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_ACTIVATE_DONE);
    
        result.code = ERR_NONE;
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
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_GetFirmwareDetails(
    uint32_t slot_id,
    arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_GetFirmwareDetails");

    (void) slot_id;
    (void) details;

    /* This function is not used for MCUBOOT. */

    arm_uc_error_t result = { .code = ERR_NOT_READY };

    return result;
}

/*****************************************************************************/

arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_GetActiveDetails(arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("ARM_UC_PAL_PSA_Mcuboot_GetActiveDetails");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {

        /* Clear for clean */
        memset(details, 0x00, sizeof(arm_uc_firmware_details_t));

        /* use MCUBOOT image version to lookup firmware details in KCM */
        result = arm_uc_pal_psa_get_kcm_details(&firmware_update_ctx_nonsecure.psa_fwu_active.version,
                                                details);

        /* if no details were found in KCM */
        if (result.error != ERR_NONE) {
            UC_PAAL_ERR_MSG("No active details found. Possibly firmware update the first time\r\n");
            return result;
        }

        /* signal event if operation was successful */
        arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);

        result.code = ERR_NONE;
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
arm_uc_error_t ARM_UC_PAL_PSA_Mcuboot_GetInstallerDetails(arm_uc_installer_details_t* details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {

        /* installer details not supported with MCUBOOT, zero details struct */
        memset(details, 0, sizeof(arm_uc_installer_details_t));

        /* signal done */
        arm_uc_pal_psa_signal_internal(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);

        result.code = ERR_NONE;
    }

    return result;
}

#endif /* ARM_UC_FEATURE_PAL_FLASHIAP */
