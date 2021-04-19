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

#ifndef ARM_UC_PAL_FLASHIAP_MCUBOOT_HELPER_H
#define ARM_UC_PAL_FLASHIAP_MCUBOOT_HELPER_H

#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"

/*****************************************************************************/
/* MCUBOOT                                                                   */
/*****************************************************************************/

#define IMAGE_MAGIC                 0x96f3b83d
#define IMAGE_HEADER_SIZE           32

/**
 * MCUBOOT Image version.
 */
typedef struct image_version {
    uint8_t iv_major;
    uint8_t iv_minor;
    uint16_t iv_revision;
    uint32_t iv_build_num;
} image_version_t;

/**
 * MCUBOOT Image header. All fields are in little endian byte order.
 */
typedef struct image_header {
    uint32_t ih_magic;
    uint32_t ih_load_addr;
    uint16_t ih_hdr_size;           /* Size of image header (bytes). */
    uint16_t ih_protect_tlv_size;   /* Size of protected TLV area (bytes). */
    uint32_t ih_img_size;           /* Does not include header. */
    uint32_t ih_flags;              /* IMAGE_F_[...]. */
    image_version_t ih_ver;
    uint32_t _pad1;
} image_header_t;

/**
 * MCUBOOT Image TLV header.  All fields in little endian.
 */
typedef struct image_tlv_info {
    uint16_t it_magic;
    uint16_t it_tlv_tot;  /* size of TLV area (including tlv_info header) */
} image_tlv_info_t;

/**
 * MCUBOOT Image trailer TLV format. All fields in little endian.
 */
typedef struct image_tlv {
    uint8_t it_type;   /* IMAGE_TLV_[...]. */
    uint8_t _pad;
    uint16_t it_len;    /* Data length (not including TLV header). */
} image_tlv_t;

#define IMAGE_TLV_INFO_MAGIC        0x6907
#define IMAGE_TLV_PROT_INFO_MAGIC   0x6908
#define IMAGE_TLV_SHA256            0x10   /* SHA256 of image hdr and body */

/*****************************************************************************/
/* KCM                                                                       */
/*****************************************************************************/

/* Shorthand for key-names used for KCM access. */
#define SLOT_A_NAME ((const uint8_t*) "UC_A")
#define SLOT_A_SIZE (4)
#define SLOT_B_NAME ((const uint8_t*) "UC_B")
#define SLOT_B_SIZE (4)

typedef int32_t (*arm_uc_reader_p)(uint8_t *, uint32_t, uint32_t);

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
                                                             arm_uc_hash_t* header_hash);

/**
 * @brief      Get hash from MCUBOOT TLV struct.
 *
 *             This function uses the MCUBOOT header to find the address
 *             for the TLV struct where the hash is stored.
 *
 * @param[in]  flash_reader Function pointer to internal or external flash reader.
 * @param      address      Address in flash where MCUBOOT header begins.
 * @param      header_hash  Pointer to hash-struct to be filled.
 * @param      total_size   Pointer to uint32_t for storing total, signed image size.
 *
 * @return     ERR_NONE     Success, the hash-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find hash at address.
 */
arm_uc_error_t arm_uc_pal_flashiap_mcuboot_get_hash_from_header(arm_uc_reader_p flash_reader,
                                                                uint32_t address,
                                                                arm_uc_hash_t* header_hash,
                                                                uint32_t* total_size);

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
                                                          arm_uc_hash_t* header_hash);

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
                                                           arm_uc_firmware_details_t* details);

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
                                                           arm_uc_firmware_details_t* details);

#endif /* ARM_UC_PAL_FLASHIAP_MCUBOOT_HELPER_H */
