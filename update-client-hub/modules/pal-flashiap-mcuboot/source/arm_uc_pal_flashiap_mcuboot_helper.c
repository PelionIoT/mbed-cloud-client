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

#include "update-client-pal-flashiap-mcuboot/arm_uc_pal_flashiap_mcuboot_helper.h"

#include "update-client-pal-flashiap-mcuboot/arm_uc_pal_flashiap_mcuboot_platform.h"
#include "update-client-paal/arm_uc_paal_update_api.h"

#include "key_config_manager.h"

#include "mbedtls/md.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define TRACE_GROUP  "UCPI"

/**
 * Default size is a trade-off between estimated available stack size
 * and reducing the number of reads from flash.
 */
#ifdef MBED_CONF_UPDATE_CLIENT_MCUBOOT_BUFFER_SIZE
#define MCUBOOT_BUFFER_SIZE MBED_CONF_UPDATE_CLIENT_MCUBOOT_BUFFER_SIZE
#else
#define MCUBOOT_BUFFER_SIZE 256
#endif

/*****************************************************************************/
/* MCUBOOT header and TLV functions                                          */
/*****************************************************************************/

/**
 * @brief      Get total image size.
 *
 * @param[in]  flash_reader Function pointer to internal or external flash reader.
 * @param      address      Address in flash where TLV struct begins.
 * @param      tlv_size     Pointer to size_t for storing total image size.
 *
 * @return     ERR_NONE     Success, the hash-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find hash at address.
 */
static arm_uc_error_t arm_uc_pal_flashiap_mcuboot_get_tlv_size(arm_uc_reader_p flash_reader,
                                                               uint32_t address,
                                                               uint32_t* tlv_size)
{
    UC_PAAL_TRACE("arm_uc_pal_flashiap_mcuboot_get_tlv_size");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (tlv_size) {

        /* get main TLV struct */
        image_tlv_info_t tlv_info = { 0 };

        int status = flash_reader((uint8_t*) &tlv_info, address, sizeof(image_tlv_info_t));

        /* check for header magic */
        if ((status == ARM_UC_FLASHIAP_SUCCESS) &&
            ((tlv_info.it_magic == IMAGE_TLV_INFO_MAGIC) ||
             (tlv_info.it_magic == IMAGE_TLV_PROT_INFO_MAGIC))) {

            UC_PAAL_TRACE("magic: %" PRIX16, tlv_info.it_magic);
            UC_PAAL_TRACE("size: %" PRIX16, tlv_info.it_tlv_tot);

            /* return total TLV size */
            *tlv_size = tlv_info.it_tlv_tot;
            UC_PAAL_TRACE("tlv_size: %" PRIX32, *tlv_size);

            result.code = ERR_NONE;
        }
    }

    return result;
}

/**
 * @brief      Get hash from MCUBOOT TLV struct.
 *
 *             This function reads the hash directly from the TLV struct.
 *
 * @param[in]  flash_reader Function pointer to internal or external flash reader.
 * @param      address      Address in flash where TLV struct begins.
 * @param      header_hash  Pointer to hash-struct to be filed.
 *
 * @return     ERR_NONE     Success, the hash-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find hash at address.
 */
arm_uc_error_t arm_uc_pal_flashiap_mcuboot_get_hash_from_tlv(arm_uc_reader_p flash_reader,
                                                             uint32_t address,
                                                             arm_uc_hash_t* header_hash)
{
    UC_PAAL_TRACE("arm_uc_pal_flashiap_mcuboot_get_hash_from_tlv");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (header_hash) {

        /* get main TLV struct */
        image_tlv_info_t tlv_info = { 0 };

        int status = flash_reader((uint8_t*) &tlv_info, address, sizeof(image_tlv_info_t));

        /* check for header magic */
        if ((status == ARM_UC_FLASHIAP_SUCCESS) &&
            ((tlv_info.it_magic == IMAGE_TLV_INFO_MAGIC) ||
             (tlv_info.it_magic == IMAGE_TLV_PROT_INFO_MAGIC))) {

            UC_PAAL_TRACE("magic: %" PRIX16, tlv_info.it_magic);
            UC_PAAL_TRACE("size: %" PRIX16, tlv_info.it_tlv_tot);

            /* step through TLV records, adjust address and size for main TLV above */
            address += sizeof(image_tlv_info_t);
            uint32_t address_end = address + tlv_info.it_tlv_tot - sizeof(image_tlv_info_t);

            while ((address < address_end) && (status == ARM_UC_FLASHIAP_SUCCESS)) {

                /* read TLV record */
                image_tlv_t record;

                status = flash_reader((uint8_t*) &record,
                                      address,
                                      sizeof(image_tlv_t));

                if (status == ARM_UC_FLASHIAP_SUCCESS) {

                    UC_PAAL_TRACE("type: %" PRIX16, record.it_type);

                    /* search for the mandatory SHA256 record */
                    if (record.it_type == IMAGE_TLV_SHA256) {

                        /* read hash into struct */
                        status = flash_reader((uint8_t*) header_hash,
                                              address + sizeof(image_tlv_t),
                                              sizeof(arm_uc_hash_t));

                        if (status == ARM_UC_FLASHIAP_SUCCESS) {

#if ARM_UC_PAAL_TRACE_ENABLE
                            printf("[TRACE][SRCE] MCUBOOT hash: ");
                            for (size_t index = 0; index < sizeof(arm_uc_hash_t); index++) {
                                printf("%02X", (*header_hash)[index]);
                            }
                            printf("\r\n");
#endif

                            result.code = ERR_NONE;
                        }

                        /* breakout whether read was succesful or not */
                        break;
                    }

                    /* skip to next record */
                    address += sizeof(image_tlv_t) + record.it_len;
                }
            }
        }
    }

    if (result.error != ERR_NONE) {
        UC_PAAL_TRACE("hash not found in TLV area");
    }

    return result;
}

/**
 * @brief      Get hash from MCUBOOT TLV struct.
 *
 *             This function uses the MCUBOOT header to find the address
 *             for the TLV struct where the hash is stored.
 *
 * @param[in]  address      Address in flash where MCUBOOT header begins.
 * @param      header_hash  Pointer to hash-struct to be filled.
 * @param      total_size   Pointer to size_t for storing total, signed image size.
 *
 * @return     ERR_NONE     Success, the hash-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find hash at address.
 */
arm_uc_error_t arm_uc_pal_flashiap_mcuboot_get_hash_from_header(arm_uc_reader_p flash_reader,
                                                                uint32_t address,
                                                                arm_uc_hash_t* header_hash,
                                                                uint32_t* total_size)
{
    UC_PAAL_TRACE("arm_uc_pal_flashiap_mcuboot_get_hash_from_header");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (header_hash && total_size) {

        /* get MCUBOOT header */
        image_header_t header = { 0 };

        int status = flash_reader((uint8_t*) &header, address, sizeof(image_header_t));

        /* check for header magic */
        if ((status == ARM_UC_FLASHIAP_SUCCESS) && (header.ih_magic == IMAGE_MAGIC)) {

            UC_PAAL_TRACE("magic: %" PRIX32, header.ih_magic);
            UC_PAAL_TRACE("load: %" PRIX32, header.ih_load_addr);
            UC_PAAL_TRACE("hdr: %" PRIX16, header.ih_hdr_size);
            UC_PAAL_TRACE("img: %" PRIX32, header.ih_img_size);
            UC_PAAL_TRACE("prot: %" PRIX16, header.ih_protect_tlv_size);

            /* find address for TLV */
            uint32_t offset = header.ih_hdr_size + header.ih_img_size;

            /* search protected TLV first */
            result = arm_uc_pal_flashiap_mcuboot_get_hash_from_tlv(flash_reader,
                                                                   address + offset,
                                                                   header_hash);

            /**
             * If hash wasn't found, assume we just searched the optional protected TLV.
             * Proceed to the main TLV and search for hash.
             */
            if ((result.error != ERR_NONE) && header.ih_protect_tlv_size) {

                offset += header.ih_protect_tlv_size;
                result = arm_uc_pal_flashiap_mcuboot_get_hash_from_tlv(flash_reader,
                                                                       address + offset,
                                                                       header_hash);
            }

            /**
             * Find remaining TLV and return full, signed image size.
             */
            if (result.error == ERR_NONE) {

                uint32_t tlv_size = 0;
                result = arm_uc_pal_flashiap_mcuboot_get_tlv_size(flash_reader,
                                                                  address + offset,
                                                                  &tlv_size);

                /* total size is offset + latest TLV size */
                if (result.error == ERR_NONE) {
                    *total_size = offset + tlv_size;
                }
            }
        } else {
            UC_PAAL_TRACE("no header at address: %" PRIX32, address);
        }
    }

    return result;
}

/**
 * @brief      Calculate hash directly from stored image.
 *
 * @param[in]  flash_reader Function pointer to internal or external flash reader.
 * @param      address      Address in flash where MCUBOOT header begins.
 * @param      total_size   uint32_t with total, signed image size.
 * @param      header_hash  Pointer to hash-struct to be filled.
 *
 * @return     ERR_NONE     Success, the hash-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find hash at address.
 */
arm_uc_error_t arm_uc_pal_flashiap_mcuboot_calculate_hash(arm_uc_reader_p flash_reader,
                                                          uint32_t address,
                                                          uint32_t total_size,
                                                          arm_uc_hash_t* header_hash)
{
    UC_PAAL_TRACE("arm_uc_pal_flashiap_mcuboot_calculate_hash");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (header_hash) {

        /* use Mbed TLS to calculate firmware's SHA256 hash */
        mbedtls_md_context_t context = { 0 };
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

        mbedtls_md_init(&context);
        mbedtls_md_setup(&context, md_info, 0);
        mbedtls_md_starts(&context);

        /* use flash read to calculate hash one fragment at a time
         * to support off-chip storage.
         */
        uint8_t buffer[MCUBOOT_BUFFER_SIZE] = { 0 };
        uint32_t offset = 0;
        int status = ARM_UC_FLASHIAP_SUCCESS;

        while ((offset < total_size) && (status == ARM_UC_FLASHIAP_SUCCESS)) {

            uint32_t actual_size = MCUBOOT_BUFFER_SIZE;
            uint32_t remaining = total_size - offset;

            /* limit the last fragment's read size */
            if (MCUBOOT_BUFFER_SIZE > remaining) {
                actual_size = remaining;
            }

            /* read fragment into buffer */
            status = flash_reader((uint8_t*) buffer,
                                  address + offset,
                                  actual_size);

            /* update hash calculation with fragment */
            if (status == ARM_UC_FLASHIAP_SUCCESS) {
                mbedtls_md_update(&context, buffer, actual_size);
            }

            /* move to next fragment */
            offset += actual_size;
        }

        mbedtls_md_finish(&context, (uint8_t*) header_hash);

        if (status == ARM_UC_FLASHIAP_SUCCESS) {
            result.code = ERR_NONE;
        }
    }

    return result;
}

/*****************************************************************************/
/* KCM getting and setting firmware details                                  */
/*****************************************************************************/

/**
 * @brief      Helper function for reading firmware details from KCM
 *             when given slot name and hash.
 *
 * @param[in]  slot_name    String with name to match.
 * @param[in]  slot_size    Size of name, doesn't have to include '\0'.
 * @param      header_hash  Pointer to hash-struct to match.
 * @param      details      Pointer to details-struct to be filled.
 *
 * @return     TRUE/FALSE   On success/failure.
 */
static bool internal_get_details_from_slot(const uint8_t* slot_name,
                                           size_t slot_size,
                                           arm_uc_hash_t* header_hash,
                                           arm_uc_firmware_details_t* details)
{
    bool result = false;

    /**
     * Read entry into temporary buffer.
     * Hash and details are stored one after another in memory.
     */
    uint8_t buffer[sizeof(arm_uc_hash_t) + sizeof(arm_uc_firmware_details_t)];
    size_t buffer_size = sizeof(arm_uc_hash_t) + sizeof(arm_uc_firmware_details_t);
    size_t item_size;

    kcm_status_e status = kcm_item_get_data(slot_name, slot_size,
                                            KCM_CONFIG_ITEM,
                                            buffer, buffer_size,
                                            &item_size);

    if ((status == KCM_STATUS_SUCCESS) && (item_size == buffer_size)) {

        /* compare provided hash with the one stored in KCM entry */
        int diff = memcmp(header_hash, buffer, sizeof(arm_uc_hash_t));

        if (diff == 0) {

            /* copy firmware details if hash matches */
            memcpy(details, buffer + sizeof(arm_uc_hash_t), sizeof(arm_uc_firmware_details_t));
            result = true;
        }
    }

    return result;
}

/**
 * @brief      Helper function for erasing slot in KCM.
 *
 * @param[in]  slot_name  String with slot name to erase.
 * @param[in]  slot_size  Size of name, doesn't have to include '\0'.
 *
 * @return     TRUE/FALSE   On success/failure.
 */
static bool internal_erase_slot(const uint8_t* slot_name,
                                size_t slot_size)
{
    kcm_status_e status = kcm_item_delete(slot_name, slot_size, KCM_CONFIG_ITEM);

    return (status == KCM_STATUS_SUCCESS);
}

/**
 * @brief      Get firmware details stored in KCM.
 *
 *             The function uses a SHA256 hash to search two preassigned
 *             locations in the KCM for the firmware details associated
 *             with the hash.
 *
 * @param      header_hash  Hash from MCUBOOT header.
 * @param      details      Pointer to firmware details struct to be filled.
 *
 * @return     ERR_NONE     Success, the details-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find entry with hash.
 */
arm_uc_error_t arm_uc_pal_flashiap_mcuboot_get_kcm_details(arm_uc_hash_t* header_hash,
                                                           arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("arm_uc_pal_flashiap_mcuboot_get_kcm_details");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (header_hash && details) {

        /* search for active firmware details in slot A */
        bool status = internal_get_details_from_slot(SLOT_A_NAME, SLOT_A_SIZE, header_hash, details);

        if (status) {

            UC_PAAL_TRACE("found active details in slot A; search slot B next");

            arm_uc_firmware_details_t slot_b_details = { 0 };

            status = internal_get_details_from_slot(SLOT_B_NAME, SLOT_B_SIZE,
                                                    header_hash,
                                                    &slot_b_details);

            if (status) {

                UC_PAAL_TRACE("found active details in slot B; compare version next");

                if (slot_b_details.version > details->version) {

                    UC_PAAL_TRACE("slot B details are newer; clean up slot A");

                    /* copy details to return struct */
                    memcpy(details, &slot_b_details, sizeof(arm_uc_firmware_details_t));

                    /* clean up slot A */
                    internal_erase_slot(SLOT_A_NAME, SLOT_A_SIZE);

                } else {

                    UC_PAAL_TRACE("slot A details are newer; clean up slot B");

                    /* clean up slot B */
                    internal_erase_slot(SLOT_B_NAME, SLOT_B_SIZE);
                }

            } else {

                UC_PAAL_TRACE("no active details in slot B; clean up slot B");

                /* clean up slot B */
                internal_erase_slot(SLOT_B_NAME, SLOT_B_SIZE);
            }

            /* set return value */
            result.code = ERR_NONE;

        } else {

            /* active firmware details were not found in slot A, search slot B */
            status = internal_get_details_from_slot(SLOT_B_NAME, SLOT_B_SIZE, header_hash, details);

            if (status) {

                UC_PAAL_TRACE("found active details in slot B; clean up slot A");

                /* active firmware details found in slot B, clean up slot A*/
                internal_erase_slot(SLOT_A_NAME, SLOT_A_SIZE);

                /* set return value */
                result.code = ERR_NONE;
            } else {

                UC_PAAL_TRACE("no details in KCM");
            }
        }
    }

    return result;
}

/**
 * @brief      Helper function for writing firmware details to KCM
 *             under given slot name and hash.
 *
 * @param[in]  slot_name    String with name for slot.
 * @param[in]  slot_size    Size of name, doesn't have to include '\0'.
 * @param      header_hash  Pointer to hash-struct to store.
 * @param      details      Pointer to details-struct to store.
 *
 * @return     TRUE/FALSE   On success/failure.
 */
static bool internal_set_details_in_slot(const uint8_t* slot_name,
                                         size_t slot_size,
                                         arm_uc_hash_t* header_hash,
                                         arm_uc_firmware_details_t* details)
{
    /* copy hash and details to same buffer */
    uint8_t buffer[sizeof(arm_uc_hash_t) + sizeof(arm_uc_firmware_details_t)];
    size_t buffer_size = sizeof(arm_uc_hash_t) + sizeof(arm_uc_firmware_details_t);

    memcpy(buffer, header_hash, sizeof(arm_uc_hash_t));
    memcpy(buffer + sizeof(arm_uc_hash_t), details, sizeof(arm_uc_firmware_details_t));

    /* store buffer in KCM*/
    kcm_status_e status = kcm_item_store(slot_name, slot_size,
                                         KCM_CONFIG_ITEM, false,
                                         buffer, buffer_size,
                                         NULL);

    UC_PAAL_TRACE("storing: %.*s", slot_size, slot_name);
#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
    for (size_t index = 0; index < buffer_size; index++) {
        printf("%02X", buffer[index]);
    }
    printf("\r\n");
#endif
    UC_PAAL_TRACE("result: %d", status);

    return (status == KCM_STATUS_SUCCESS);
}

/**
 * @brief      Set firmware details in KCM.
 *
 *             The function stores firmware details in the KCM using a
 *             SHA256 hash as the key for two preallocated entries.
 *             The hash for the active firmware is passed as argument
 *             as well to resolve any ambiguity on which entry should
 *             be used.
 *
 * @param      header_hash_active     Hash for active firmware.
 * @param      header_hash_candidate  Hash for candidate firmware.
 * @param      details                Pointer to the candidate firmware's details.
 *
 * @return     ERR_NONE     Success, firmware details has been stored in KCM.
 *             ERR_INVALID_PARAMETER Failure, unable to store details.
 */
arm_uc_error_t arm_uc_pal_flashiap_mcuboot_set_kcm_details(arm_uc_hash_t* header_hash_active,
                                                           arm_uc_hash_t* header_hash_candidate,
                                                           arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("arm_uc_pal_flashiap_mcuboot_set_kcm_details");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (header_hash_active && header_hash_candidate && details) {

        /**
         * Find the KCM slot that holds the active firmware's details,
         * then use the other slot to store the candidate details.
         */
        arm_uc_firmware_details_t throw_away;

        /* search slot A for active firmware details */
        bool status = internal_get_details_from_slot(SLOT_A_NAME, SLOT_A_SIZE,
                                                     header_hash_active,
                                                     &throw_away);

        if (status) {

            UC_PAAL_TRACE("found active details in slot A; erase and store candidate details in slot B");

            internal_erase_slot(SLOT_B_NAME, SLOT_B_SIZE);
            status = internal_set_details_in_slot(SLOT_B_NAME, SLOT_B_SIZE,
                                                  header_hash_candidate,
                                                  details);
        } else {

            UC_PAAL_TRACE("active details not in slot A; erase and store candidate details in slot A");

            internal_erase_slot(SLOT_A_NAME, SLOT_A_SIZE);
            status = internal_set_details_in_slot(SLOT_A_NAME, SLOT_A_SIZE,
                                                  header_hash_candidate,
                                                  details);
        }

        /* set return value based on storage status */
        if (status) {
            result.code = ERR_NONE;
        }
    }

    return result;
}

#endif // ARM_UC_FEATURE_PAL_FLASHIAP_MCUBOOT
