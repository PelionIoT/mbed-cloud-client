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

#include "update-client-pal-psa/arm_uc_pal_psa_helper.h"
#include "update-client-paal/arm_uc_paal_update_api.h"

#include "key_config_manager.h"

#include "mbedtls/md.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define TRACE_GROUP  "UCPI"

/*****************************************************************************/
/* KCM getting and setting firmware details                                  */
/*****************************************************************************/

/**
 * @brief      Helper function for reading firmware details from KCM
 *             when given slot name and hash.
 *
 * @param[in]  slot_name    String with name to match.
 * @param[in]  slot_size    Size of name, doesn't have to include '\0'.
 * @param      version      Pointer to version-struct to match.
 * @param      details      Pointer to details-struct to be filled.
 *
 * @return     TRUE/FALSE   On success/failure.
 */
static bool internal_get_details_from_slot(const uint8_t* slot_name,
                                           size_t slot_size,
                                           image_version_t* version,
                                           arm_uc_firmware_details_t* details)
{
    bool result = false;

    /**
     * Read entry into temporary buffer.
     * Hash and details are stored one after another in memory.
     */
    uint8_t buffer[sizeof(image_version_t) + sizeof(arm_uc_firmware_details_t)];
    size_t buffer_size = sizeof(image_version_t) + sizeof(arm_uc_firmware_details_t);
    size_t item_size;

    kcm_status_e status = kcm_item_get_data(slot_name, slot_size,
                                            KCM_CONFIG_ITEM,
                                            buffer, buffer_size,
                                            &item_size);

    if ((status == KCM_STATUS_SUCCESS) && (item_size == buffer_size)) {

        /* compare provided version with the one stored in KCM entry */
        int diff = memcmp(version, buffer, sizeof(image_version_t));

        if (diff == 0) {

            /* copy firmware details if hash matches */
            memcpy(details, buffer + sizeof(image_version_t), sizeof(arm_uc_firmware_details_t));
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
 *             The function uses a image version to search two preassigned
 *             locations in the KCM for the firmware details associated
 *             with the MCUBOOT image version.
 *
 * @param      version      image version.
 * @param      details      Pointer to firmware details struct to be filled.
 *
 * @return     ERR_NONE     Success, the details-struct has been populated.
 *             ERR_INVALID_PARAMETER Failure, unable to find entry with image version.
 */
arm_uc_error_t arm_uc_pal_psa_get_kcm_details(image_version_t *version,
                                                           arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("arm_uc_pal_psa_get_kcm_details");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (version && details) {

        /* search for active firmware details in slot A */
        bool status = internal_get_details_from_slot(SLOT_A_NAME, SLOT_A_SIZE, version, details);

        if (status) {

            UC_PAAL_TRACE("found active details in slot A; search slot B next");

            arm_uc_firmware_details_t slot_b_details = { 0 };

            status = internal_get_details_from_slot(SLOT_B_NAME, SLOT_B_SIZE,
                                                    version,
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
            status = internal_get_details_from_slot(SLOT_B_NAME, SLOT_B_SIZE, version, details);

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
 * @param      version      Pointer to version-struct to store.
 * @param      details      Pointer to details-struct to store.
 *
 * @return     TRUE/FALSE   On success/failure.
 */
static bool internal_set_details_in_slot(const uint8_t* slot_name,
                                         size_t slot_size,
                                         image_version_t* version,
                                         arm_uc_firmware_details_t* details)
{
    /* copy version and details to same buffer */
    uint8_t buffer[sizeof(image_version_t) + sizeof(arm_uc_firmware_details_t)];
    size_t buffer_size = sizeof(image_version_t) + sizeof(arm_uc_firmware_details_t);

    memcpy(buffer, version, sizeof(image_version_t));
    memcpy(buffer + sizeof(image_version_t), details, sizeof(arm_uc_firmware_details_t));

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
 *             image version as the key for two preallocated entries.
 *             The image version for the active firmware is passed as argument
 *             as well to resolve any ambiguity on which entry should
 *             be used.
 *
 * @param      version_active         image version for active firmware
 * @param      version_candidate      image version for candidate firmware.
 * @param      details                Pointer to the candidate firmware's details.
 *
 * @return     ERR_NONE     Success, firmware details has been stored in KCM.
 *             ERR_INVALID_PARAMETER Failure, unable to store details.
 */
arm_uc_error_t arm_uc_pal_psa_set_kcm_details(image_version_t *version_active,
                                              image_version_t* version_candidate,
                                              arm_uc_firmware_details_t* details)
{
    UC_PAAL_TRACE("arm_uc_pal_psa_set_kcm_details");

    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (version_active && version_candidate && details) {

        /**
         * Find the KCM slot that holds the active firmware's details,
         * then use the other slot to store the candidate details.
         */
        arm_uc_firmware_details_t throw_away;

        /* search slot A for active firmware details */
        bool status = internal_get_details_from_slot(SLOT_A_NAME, SLOT_A_SIZE,
                                                     version_active,
                                                     &throw_away);

        if (status) {

            UC_PAAL_TRACE("found active details in slot A; erase and store candidate details in slot B");

            internal_erase_slot(SLOT_B_NAME, SLOT_B_SIZE);
            status = internal_set_details_in_slot(SLOT_B_NAME, SLOT_B_SIZE,
                                                  version_candidate,
                                                  details);
        } else {

            UC_PAAL_TRACE("active details not in slot A; erase and store candidate details in slot A");

            internal_erase_slot(SLOT_A_NAME, SLOT_A_SIZE);
            status = internal_set_details_in_slot(SLOT_A_NAME, SLOT_A_SIZE,
                                                  version_candidate,
                                                  details);
        }

        /* set return value based on storage status */
        if (status) {
            result.code = ERR_NONE;
        }
    }

    return result;
}

#endif // ARM_UC_FEATURE_PAL_PSA
