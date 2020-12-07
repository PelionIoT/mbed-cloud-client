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

#ifndef ARM_UC_FIRMWARE_MANAGER_H
#define ARM_UC_FIRMWARE_MANAGER_H

#include "update-client-paal/arm_uc_paal_update_api.h"
#include "update-client-common/arm_uc_common.h"

typedef void (*ARM_UCFM_SignalEvent_t)(uintptr_t event);

#define UCFM_MAX_BLOCK_SIZE 16

typedef enum {
    UCFM_EVENT_INITIALIZE_DONE                   = ARM_UC_PAAL_EVENT_INITIALIZE_DONE,
    UCFM_EVENT_PREPARE_DONE                      = ARM_UC_PAAL_EVENT_PREPARE_DONE,
    UCFM_EVENT_WRITE_DONE                        = ARM_UC_PAAL_EVENT_WRITE_DONE,
    UCFM_EVENT_FINALIZE_DONE                     = ARM_UC_PAAL_EVENT_FINALIZE_DONE,
    UCFM_EVENT_READ_DONE                         = ARM_UC_PAAL_EVENT_READ_DONE,
    UCFM_EVENT_ACTIVATE_DONE                     = ARM_UC_PAAL_EVENT_ACTIVATE_DONE,
    UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE  = ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE,
    UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE         = ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE,
    UCFM_EVENT_GET_INSTALLER_DETAILS_DONE        = ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE,
    UCFM_EVENT_INITIALIZE_ERROR                  = ARM_UC_PAAL_EVENT_INITIALIZE_ERROR,
    UCFM_EVENT_PREPARE_ERROR                     = ARM_UC_PAAL_EVENT_PREPARE_ERROR,
    UCFM_EVENT_FIRMWARE_TOO_LARGE_ERROR          = ARM_UC_PAAL_EVENT_FIRMWARE_TOO_LARGE_ERROR,
    UCFM_EVENT_WRITE_ERROR                       = ARM_UC_PAAL_EVENT_WRITE_ERROR,
    UCFM_EVENT_FINALIZE_ERROR                    = ARM_UC_PAAL_EVENT_FINALIZE_ERROR,
    UCFM_EVENT_ACTIVATE_ERROR                    = ARM_UC_PAAL_EVENT_ACTIVATE_ERROR,
    UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR = ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR,
    UCFM_EVENT_GET_FIRMWARE_DETAILS_ERROR        = ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_ERROR,
    UCFM_EVENT_GET_INSTALLER_DETAILS_ERROR       = ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_ERROR,
    UCFM_EVENT_PROCESSOR_PARSE_ERROR             = ARM_UC_PAAL_EVENT_PROCESSOR_PARSE_ERROR,
    UCFM_EVENT_PROCESSOR_INSUFFICIENT_MEMORY_SPACE  = ARM_UC_PAAL_EVENT_PROCESSOR_INSUFFICIENT_MEMORY_SPACE,
    UCFM_EVENT_FINALIZE_INVALID_HASH_ERROR
} ARM_UCFM_Event_t;

typedef enum {
    UCFM_MODE_UNINIT,
    UCFM_MODE_NONE_SHA_256,
    UCFM_MODE_AES_CTR_128_SHA_256,
    UCFM_MODE_AES_CTR_256_SHA_256
} ARM_UCFM_mode_t;

typedef struct _ARM_UCFM_Setup {
    ARM_UCFM_mode_t mode;
    arm_uc_buffer_t *key;
    arm_uc_buffer_t *iv;
    arm_uc_buffer_t *hash;
    uint32_t package_id;
    uint32_t package_size;
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
    uint8_t is_delta;
#endif
} ARM_UCFM_Setup_t;

typedef struct _ARM_UC_FIRMWARE_MANAGER {
    /**
     * @brief Initialization function.
     * @param handler Function pointer to the event handler.
     * @return Error code.
     */
    arm_uc_error_t (*Initialize)(ARM_UCFM_SignalEvent_t handler);

    /**
     * @brief Setup new package to be processed.
     * @details Generates UCFM_EVENT_PREPARE_DONE event if call is accepted.
     * @param configuration Struct containing configuration data.
     * @param buffer Scratch pad for temporary storage.
     * @return Error code.
     */
    arm_uc_error_t (*Prepare)(ARM_UCFM_Setup_t *configuration,
                              const arm_uc_firmware_details_t *details,
                              arm_uc_buffer_t *buffer);

    /**
     * @brief Function for adding a package fragment.
     * @details Generates either UCFM_EVENT_WRITE_DONE or UCFM_EVENT_WRITE_ERROR.
     * @details Fragments are processed based on the mode set in the configure
     *          struct. This can include decryption, validation, and storage.
     * @param input Buffer struct.
     * @return Error code.
     */
    arm_uc_error_t (*Write)(const arm_uc_buffer_t *input);

    /**
     * @brief Function for adding a package fragment with offset.
     * @details Generates either UCFM_EVENT_WRITE_DONE or UCFM_EVENT_WRITE_ERROR.
     * @details Fragments are processed based on the mode set in the configure
     *          struct. This can include decryption, validation, and storage.
     * @param input Buffer struct.
     * @param offset Offset where to write.
     * @return Error code.
     */
    arm_uc_error_t (*WriteWithOffset)(const arm_uc_buffer_t *input, const uint32_t offset);

    /**
     * @brief Function for reading a package fragment from the storage.
     */
    arm_uc_error_t (*Read)(const arm_uc_buffer_t* output, uint32_t offset);

    arm_uc_error_t (*ReadFromSlot)(const arm_uc_buffer_t* output, uint32_t location, uint32_t offset);

    /**
     * @brief Function for finalizing the current package.
     * @details Flushes all write buffers and initiates the hash validation.
     *          Generates UCFM_EVENT_FINALIZE_DONE, UCFM_EVENT_FINALIZE_ERROR
     *          or UCFM_EVENT_FINALIZE_INVALID_HASH_ERROR.
     *          To speed up hash computation, this function accepts two buffer
     *          arguments ('front' and 'back):
     *          - if both 'front' and 'back' are NULL, a small internal buffer is
     *            used. Note that this can have an adverse impact on performance.
     *          - if only 'front' isn't NULL, 'front' will be used instead of the
     *            internal buffer. If 'front' is a large buffer, a performance
     *            improvement is likely to be observed.
     *          - if both 'front' and 'back' are not NULL, the code will initiate
     *            a read in the back buffer, hash the data in the front buffer,
     *            then swap the buffers. This configuration should provide the
     *            best performance (but also uses the most memory).
     *          It is an error to call this function with 'front' equal to NULL
     *          and a non-null value for 'back'.
     *          NOTE: the buffer size must be a multiple of ARM_UC_SHA256_SIZE.
     * @return Error code.
     */
    arm_uc_error_t (*Finalize)(arm_uc_buffer_t *front, arm_uc_buffer_t *back);

    /**
     * @brief Function for activating or installing the current package.
     * @details Activates or installs the current package.
     *          In the future this function might take the image ID as
     *          paramter.
     * @param location ID of slot to be activated.
     * @return Error code.
     */
    arm_uc_error_t (*Activate)(uint32_t location);

    /**
     * @brief Get the firmware details for the currently active image.
     *
     * @param details Pointer to firmware details struct.
     * @return Error code.
     */
    arm_uc_error_t (*GetActiveFirmwareDetails)(arm_uc_firmware_details_t *details);

    /**
     * @brief Get the firmware details for the specified location.
     *
     * @param location Location ID to get details for.
     * @param details Pointer to firmware details struct.
     * @return Error code.
     */
    arm_uc_error_t (*GetFirmwareDetails)(uint32_t location,
                                         arm_uc_firmware_details_t *details);

    /**
     * @brief Get the installer details.
     * @details Installer is responsible for applying the firmware image.
     *
     * @param details Pointer to installer details struct.
     * @return Error code.
     */
    arm_uc_error_t (*GetInstallerDetails)(arm_uc_installer_details_t *details);

} ARM_UC_FIRMWARE_MANAGER_t;

extern ARM_UC_FIRMWARE_MANAGER_t ARM_UC_FirmwareManager;

#endif // ARM_UC_FIRMWARE_MANAGER_H
