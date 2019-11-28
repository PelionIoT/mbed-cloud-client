// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#if defined(ARM_UC_ENABLE) && (ARM_UC_ENABLE == 1)


#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-common/arm_uc_common.h"

#include "update-client-paal/arm_uc_paal_update.h"

#include <stdio.h>
#include <stdbool.h>

static ARM_UCFM_SignalEvent_t ucfm_handler = NULL;

static ARM_UCFM_Setup_t *package_configuration = NULL;
static arm_uc_hash_t package_hash;
static uint32_t package_offset = 0;
static bool ready_to_receive = false;

static arm_uc_callback_t arm_uc_event_handler_callback = { 0 };

static arm_uc_mdHandle_t mdHandle = { 0 };
static arm_uc_cipherHandle_t cipherHandle = { 0 };
static arm_uc_buffer_t *front_buffer = NULL;
static arm_uc_buffer_t *back_buffer = NULL;

#define UCFM_DEBUG_OUTPUT 0


static void arm_uc_signal_ucfm_handler(uintptr_t event);

/******************************************************************************/
/* Debug output functions for writing formatted output                        */
/******************************************************************************/

#if UCFM_DEBUG_OUTPUT

static void debug_output_decryption(const uint8_t *encrypted,
                                    arm_uc_buffer_t *decrypted)
{
    for (size_t index = 0; index < UCFM_MAX_BLOCK_SIZE; index++) {
        if (index < decrypted->size) {
            uint8_t symbol = encrypted[index];

            printf("%02X", symbol);
        } else {
            printf("  ");
        }
    }

    printf("\t:\t");

    for (size_t index = 0; index < UCFM_MAX_BLOCK_SIZE; index++) {
        if (index < decrypted->size) {
            uint8_t symbol = encrypted[index];

            if ((symbol > 32) && (symbol < 127)) {
                printf("%c", symbol);
            } else {
                printf(" ");
            }
        } else {
            printf(" ");
        }
    }

    printf("\t:\t");

    for (size_t index = 0; index < decrypted->size_max; index++) {
        if (index < decrypted->size) {
            uint8_t symbol = decrypted->ptr[index];

            if ((symbol > 32) && (symbol < 127)) {
                printf("%c", symbol);
            } else {
                printf(" ");
            }
        } else {
            printf(" ");
        }
    }

    printf("\r\n");
}

static void debug_print_hash(const char* message, const uint8_t* ptr, const uint32_t size)
{
    printf("\r\n");
    printf("%s ", message);
    for (size_t index = 0; index < size; index++) {
        printf("%02X", ptr[index]);
    }
}

static void debug_output_validation(arm_uc_hash_t *hash,
                                    arm_uc_buffer_t *output_buffer)
{
    debug_print_hash("expected hash  :", (uint8_t*)hash, ARM_UC_SHA256_SIZE);
    debug_print_hash("calculated hash:", output_buffer->ptr, output_buffer->size);
    printf("\r\n");
    printf("\r\n");
}

#endif

/******************************************************************************/

/* Hash calculation is performed using the output buffer. This function fills
   the output buffer with data from the PAL.
*/
static void arm_uc_internal_process_hash(void)
{
    bool double_buffering = (front_buffer != back_buffer);
    bool needs_more_data = (package_offset < package_configuration->package_size);
    arm_uc_error_t status = { .code = ERR_NONE };
    uint32_t error_event = UCFM_EVENT_FINALIZE_ERROR;

    if (double_buffering && needs_more_data) {
#if UCFM_DEBUG_OUTPUT
        printf("double buffering: %p %" PRIX32 "\r\n", back_buffer, back_buffer->size_max);
#endif

        /* if using double buffering, initiate a new data read as soon as possible */
        /* Indicate read size */
        uint32_t bytes_remaining = package_configuration->package_size - package_offset;
        back_buffer->size = (bytes_remaining > back_buffer->size_max) ?
                            back_buffer->size_max : bytes_remaining;

        /* initiate read from PAL */
        status = ARM_UCP_Read(package_configuration->package_id,
                              package_offset,
                              back_buffer);
    }

    if (status.error == ERR_NONE) {
        /* process data in front buffer */
        ARM_UC_cryptoHashUpdate(&mdHandle, front_buffer);

        if (needs_more_data) {
            /* if we're actually using two buffers, the read operation was initiated earlier,
             * otherwise it needs to be initiated now, after we're done hashing the only
             * buffer that we're using
             */
            if (!double_buffering) {
#if UCFM_DEBUG_OUTPUT
                printf("single buffering: %p\r\n", front_buffer);
#endif
                /* Indicate read size */
                uint32_t bytes_remaining = package_configuration->package_size - package_offset;
                back_buffer->size = (bytes_remaining > back_buffer->size_max) ?
                                    back_buffer->size_max : bytes_remaining;

                /* initiate read from PAL */
                status = ARM_UCP_Read(package_configuration->package_id,
                                      package_offset,
                                      back_buffer);
            }
        } else {
            /* invert status code so that it has to be set explicitly for success */
            status.code = FIRM_ERR_INVALID_PARAMETER;

            /* finalize hash calculation */
            uint8_t hash_output_ptr[2 * UCFM_MAX_BLOCK_SIZE];
            arm_uc_buffer_t hash_buffer = {
                .size_max = sizeof(hash_output_ptr),
                .size = 0,
                .ptr = hash_output_ptr
            };

            ARM_UC_cryptoHashFinish(&mdHandle, &hash_buffer);

            /* size check before memcmp call */
            if (hash_buffer.size == ARM_UC_SHA256_SIZE) {
                int diff = memcmp(hash_buffer.ptr,
                                  package_hash,
                                  ARM_UC_SHA256_SIZE);

#if UCFM_DEBUG_OUTPUT
                debug_output_validation(package_hash,
                                        &hash_buffer);
#endif

                /* hash matches */
                if (diff == 0) {
                    UC_FIRM_TRACE("UCFM_EVENT_FINALIZE_DONE");

                    arm_uc_signal_ucfm_handler(UCFM_EVENT_FINALIZE_DONE);
                    status.code = ERR_NONE;
                } else {
                    /* use specific event for "invalid hash" */
                    UC_FIRM_ERR_MSG("Invalid image hash");

                    error_event = UCFM_EVENT_FINALIZE_INVALID_HASH_ERROR;
                }
                // clear local hash
                memset(package_hash, 0, ARM_UC_SHA256_SIZE);
            }
        }

        /* Front buffer is processed, back buffer might be reading more data.
           Swap buffer so that data will be ready in front buffer
        */
        arm_uc_buffer_t *temp = front_buffer;
        front_buffer = back_buffer;
        back_buffer = temp;
    }

    /* signal error if status is not clean */
    if (status.error != ERR_NONE) {
        UC_FIRM_TRACE("UCFM_EVENT_FINALIZE_ERROR");
        arm_uc_signal_ucfm_handler(error_event);
    }
}

/******************************************************************************/

/* Function for decoupling PAL callbacks using the internal task queue. */
/* Write commit done */
static void event_handler_finalize(void)
{
    UC_FIRM_TRACE("event_handler_finalize");

    /* setup mandatory hash */
    arm_uc_mdType_t mdtype = ARM_UC_CU_SHA256;
    arm_uc_error_t result = ARM_UC_cryptoHashSetup(&mdHandle, mdtype);

    if (result.error == ERR_NONE) {
        /* initiate hash calculation */
        package_offset = 0;

        /* indicate number of bytes needed */
        front_buffer->size = (package_configuration->package_size < front_buffer->size_max) ?
                             package_configuration->package_size : front_buffer->size_max;

        /* initiate read from PAL */
        result = ARM_UCP_Read(package_configuration->package_id,
                              package_offset,
                              front_buffer);
    }

    if (result.error != ERR_NONE) {
        UC_FIRM_ERR_MSG("ARM_UC_cryptoHashSetup failed");
        arm_uc_signal_ucfm_handler(UCFM_EVENT_FINALIZE_ERROR);
    }
}

/* Function for decoupling PAL callbacks using the internal task queue. */
static void event_handler_read(void)
{
#if UCFM_DEBUG_OUTPUT
    printf("event_handler_read: %" PRIX32 "\r\n", front_buffer->size);
#endif

    /* check that read succeeded in reading data into buffer */
    if (front_buffer->size > 0) {
        /* check if read over shot */
        if ((package_offset + front_buffer->size) >
                package_configuration->package_size) {
            /* trim buffer */
            front_buffer->size = package_configuration->package_size - package_offset;
        }

        /* update offset and continue reading data from PAL */
        package_offset += front_buffer->size;
        arm_uc_internal_process_hash();
    } else {
        /* error - no data processed */
        UC_FIRM_TRACE("UCFM_EVENT_FINALIZE_ERROR");
        arm_uc_signal_ucfm_handler(UCFM_EVENT_FINALIZE_ERROR);
    }
}

static void arm_uc_signal_ucfm_handler(uintptr_t event)
{
    if (ucfm_handler) {
        ucfm_handler(event);
    }
}

static void arm_uc_internal_event_handler(uintptr_t event)
{
    switch (event) {
        case ARM_UC_PAAL_EVENT_FINALIZE_DONE:
            event_handler_finalize();
            break;
        case ARM_UC_PAAL_EVENT_READ_DONE:
            event_handler_read();
            break;
        default:
            /* pass all other events directly */
            arm_uc_signal_ucfm_handler(event);
            break;
    }
}

static void ARM_UCFM_PALEventHandler(uintptr_t event)
{
    /* decouple event handler from callback */
    ARM_UC_PostCallback(&arm_uc_event_handler_callback,
                        arm_uc_internal_event_handler, event);
}

/******************************************************************************/
static arm_uc_error_t ARM_UCFM_Initialize(ARM_UCFM_SignalEvent_t handler)
{
    UC_FIRM_TRACE("ARM_UCFM_Initialize");

    arm_uc_error_t result = (arm_uc_error_t) { FIRM_ERR_INVALID_PARAMETER };

    if (handler) {
        result = ARM_UCP_Initialize(ARM_UCFM_PALEventHandler);

        if (result.error == ERR_NONE) {
            ucfm_handler = handler;
        }
    }

    return result;
}

static arm_uc_error_t ARM_UCFM_Prepare(ARM_UCFM_Setup_t *configuration,
                                       const arm_uc_firmware_details_t *details,
                                       arm_uc_buffer_t *buffer)
{
    UC_FIRM_TRACE("ARM_UCFM_Setup");

    arm_uc_error_t result = (arm_uc_error_t) { ERR_NONE };

    /* sanity checks */
    if (!ucfm_handler) {
        UC_FIRM_ERR_MSG("Event handler not set. Should call Initialise before calling Setup");
        result = (arm_uc_error_t) { FIRM_ERR_UNINITIALIZED };
    }
    /* check configuration is defined and contains key and iv. */
    else if ((!(configuration &&
                ((configuration->mode == UCFM_MODE_NONE_SHA_256) ||
                 (configuration->key && configuration->iv)))) ||
             !buffer ||
             !buffer->ptr) {
        result = (arm_uc_error_t) { FIRM_ERR_INVALID_PARAMETER };
    }

    /* allocate space using PAL */
    if (result.error == ERR_NONE) {
        result = ARM_UCP_Prepare(configuration->package_id,
                                 details,
                                 buffer);

        if (result.error != ERR_NONE) {
            UC_FIRM_ERR_MSG("ARM_UCP_Prepare failed");
        }
    }

    /* setup encryption if requested by mode */
    if ((result.error == ERR_NONE) &&
            (configuration->mode != UCFM_MODE_NONE_SHA_256)) {
        /* A previously aborted firmware write will have left the cipherHandler
           in an inconsistent state. If the IV is not NULL, clear the context
           using the call to finish and set the struct to zero.
        */
        if (cipherHandle.aes_iv != NULL) {
            ARM_UC_cryptoDecryptFinish(&cipherHandle, buffer);
            memset(&cipherHandle, 0, sizeof(arm_uc_cipherHandle_t));
        }

        /* setup cipherHanlde with decryption keys */
        uint32_t bits = (configuration->mode == UCFM_MODE_AES_CTR_128_SHA_256) ? 128 : 256;
        result = ARM_UC_cryptoDecryptSetup(&cipherHandle,
                                           configuration->key,
                                           configuration->iv,
                                           bits);

        if (result.error != ERR_NONE) {
            UC_FIRM_ERR_MSG("ARM_UC_cryptoDecryptSetup failed in %" PRIu32 " bit mode", bits);
        }
    }

    /* Initialise the internal state */
    if (result.error == ERR_NONE) {
        package_configuration = configuration;
        // Make copy of hash because the fwInfo in hub shares memory
        // with backbuffer and is overwritten in Finalize-phase
        memcpy(package_hash, configuration->hash->ptr, ARM_UC_SHA256_SIZE);
        package_offset = 0;
        ready_to_receive = true;
    } else {
        if (result.code == PAAL_ERR_FIRMWARE_TOO_LARGE) {
            arm_uc_signal_ucfm_handler(UCFM_EVENT_FIRMWARE_TOO_LARGE_ERROR);
        } else {
            arm_uc_signal_ucfm_handler(UCFM_EVENT_PREPARE_ERROR);
        }
    }
#if UCFM_DEBUG_OUTPUT
    /* Initialize hash to calculate downloaded fragments hash */
    if (result.error == ERR_NONE) {
        arm_uc_mdType_t mdtype = ARM_UC_CU_SHA256;
        result = ARM_UC_cryptoHashSetup(&mdHandle, mdtype);
    }
#endif

    return result;
}

static arm_uc_error_t ARM_UCFM_Write(const arm_uc_buffer_t *fragment)
{
    UC_FIRM_TRACE("ARM_UCFM_Write");

    arm_uc_error_t result = (arm_uc_error_t) { ERR_NONE };

    if (!fragment || fragment->size_max == 0 || fragment->size > fragment->size_max || !fragment->ptr) {
        result = (arm_uc_error_t) { FIRM_ERR_INVALID_PARAMETER };
    } else if (!ready_to_receive) {
        result = (arm_uc_error_t) { FIRM_ERR_UNINITIALIZED };
    } else {
        /* decrypt fragment before writing to PAL */
        if (package_configuration->mode != UCFM_MODE_NONE_SHA_256) {
            /* temporary buffer for decrypting in place */
            uint8_t decrypt_output_ptr[2 * UCFM_MAX_BLOCK_SIZE];
            arm_uc_buffer_t decrypt_buffer = {
                .size_max = sizeof(decrypt_output_ptr),
                .size = 0,
                .ptr = decrypt_output_ptr
            };

            uint32_t fragment_offset = 0;
            while (fragment_offset < fragment->size) {
                /* default to max length */
                uint32_t length_update = decrypt_buffer.size_max;

                /* adjust size to not overshoot */
                if (fragment_offset + length_update > fragment->size) {
                    length_update = fragment->size - fragment_offset;
                }

                /* decrypt part of the fragment using the offset */
                ARM_UC_cryptoDecryptUpdate(&cipherHandle,
                                           &fragment->ptr[fragment_offset],
                                           length_update,
                                           &decrypt_buffer);

#if UCFM_DEBUG_OUTPUT
                debug_output_decryption(&fragment->ptr[fragment_offset],
                                        &decrypt_buffer);
#endif

                /* overwrite the encrypted data with the decrypted data */
                memcpy(&fragment->ptr[fragment_offset],
                       decrypt_buffer.ptr,
                       length_update);

                /* update offset */
                fragment_offset += length_update;
            }
        }
#if UCFM_DEBUG_OUTPUT
        /* calculate hash on the fly for debugging purpose */
        ARM_UC_cryptoHashUpdate(&mdHandle, fragment);
#endif
        /* store fragment using PAL */
        result = ARM_UCP_Write(package_configuration->package_id,
                               package_offset,
                               fragment);

        if (result.error == ERR_NONE) {
            package_offset += fragment->size;
        }
    }

    return result;
}

static arm_uc_error_t ARM_UCFM_Finalize(arm_uc_buffer_t *front, arm_uc_buffer_t *back)
{
    UC_FIRM_TRACE("ARM_UCFM_Finish");

    arm_uc_error_t result = (arm_uc_error_t) { ERR_NONE };

    if (!ready_to_receive) {
        result = (arm_uc_error_t) { FIRM_ERR_UNINITIALIZED };
    } else if ((front == NULL) ||
               (front != NULL && ((front->size_max % ARM_UC_SHA256_SIZE) != 0)) ||
               (back != NULL && ((back->size_max % ARM_UC_SHA256_SIZE) != 0))) {
        result = (arm_uc_error_t) { FIRM_ERR_INVALID_PARAMETER };
    } else {

        if (package_configuration->mode != UCFM_MODE_NONE_SHA_256) {
            /* flush decryption buffer, discard data */
            ARM_UC_cryptoDecryptFinish(&cipherHandle, front);
            memset(&cipherHandle, 0, sizeof(arm_uc_cipherHandle_t));
        }

        /* save buffers, checking if the buffers actually exist */
        front_buffer = front;
        back_buffer = (back == NULL) ? front_buffer : back;

        /* flush to PAL */
        result = ARM_UCP_Finalize(package_configuration->package_id);

        /* disable module until next setup call is received */
        ready_to_receive = false;

#if UCFM_DEBUG_OUTPUT
        /* finalize hash calculation */
        uint8_t hash_output_ptr[2 * UCFM_MAX_BLOCK_SIZE];
        arm_uc_buffer_t hash_buffer = {
            .size_max = sizeof(hash_output_ptr),
            .size = 0,
            .ptr = hash_output_ptr
        };

        ARM_UC_cryptoHashFinish(&mdHandle, &hash_buffer);

        debug_print_hash("downloaded hash:", hash_buffer.ptr, hash_buffer.size);
#endif
    }

    return result;
}

static arm_uc_error_t ARM_UCFM_Activate(uint32_t location)
{
    UC_FIRM_TRACE("ARM_UCFM_Activate");

    arm_uc_error_t result = { .code = FIRM_ERR_ACTIVATE };

    if (ucfm_handler) {
        result = ARM_UCP_Activate(location);
    }

    return result;
}

static arm_uc_error_t ARM_UCFM_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details)
{
    UC_FIRM_TRACE("ARM_UCFM_GetActiveFirmwareDetails");

    arm_uc_error_t result = { .code = FIRM_ERR_INVALID_PARAMETER };

    if (ucfm_handler && details) {
        result = ARM_UCP_GetActiveFirmwareDetails(details);
    }

    return result;
}

static arm_uc_error_t ARM_UCFM_GetFirmwareDetails(uint32_t location,
                                                  arm_uc_firmware_details_t *details)
{
    UC_FIRM_TRACE("ARM_UCFM_GetFirmwareDetails");

    arm_uc_error_t result = { .code = FIRM_ERR_INVALID_PARAMETER };

    if (ucfm_handler && details) {
        result = ARM_UCP_GetFirmwareDetails(location, details);
    }

    return result;
}

static arm_uc_error_t ARM_UCFM_GetInstallerDetails(arm_uc_installer_details_t *details)
{
    UC_FIRM_TRACE("ARM_UCFM_GetInstallerDetails");

    arm_uc_error_t result = { .code = FIRM_ERR_INVALID_PARAMETER };

    if (ucfm_handler && details) {
        result = ARM_UCP_GetInstallerDetails(details);
    }

    return result;
}

ARM_UC_FIRMWARE_MANAGER_t ARM_UC_FirmwareManager = {
    .Initialize               = ARM_UCFM_Initialize,
    .Prepare                  = ARM_UCFM_Prepare,
    .Write                    = ARM_UCFM_Write,
    .Finalize                 = ARM_UCFM_Finalize,
    .Activate                 = ARM_UCFM_Activate,
    .GetActiveFirmwareDetails = ARM_UCFM_GetActiveFirmwareDetails,
    .GetFirmwareDetails       = ARM_UCFM_GetFirmwareDetails,
    .GetInstallerDetails      = ARM_UCFM_GetInstallerDetails
};

#endif
