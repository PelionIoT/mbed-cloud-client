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
#if defined(ARM_UC_FEATURE_PAL_LINUX) && (ARM_UC_FEATURE_PAL_LINUX == 1)
#if defined(TARGET_IS_PC_LINUX)
#define _FILE_OFFSET_BITS  64

#include "update-client-pal-linux/arm_uc_pal_linux_implementation_internal.h"
#include "update-client-pal-linux/arm_uc_pal_linux_implementation.h"
#include "update-client-paal/arm_uc_paal_update_api.h"
#include "update-client-pal-linux/arm_uc_pal_linux_ext.h"

#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern linux_worker_thread_info_t linux_worker_thread;

/* worker struct, must be accessible externally */
arm_ucp_worker_config_t arm_uc_worker_parameters = { 0 };

static FILE *arm_uc_firmware_descriptor = NULL;

static arm_uc_error_t spawn_thread(void *(*start_routine)(void *), void *arg)
{
    arm_uc_error_t result = {ERR_NONE};

    /* Get the thread mutex. This prevents another thread from being spawned until this one completes.
       There should only ever be one thread at a time, since they are spawned via a single-threaded
       state machine, but this guarantees that there will only be one. */
    int status = pthread_mutex_trylock(&linux_worker_thread.mutex);
    if (status == EBUSY) {
        ARM_UC_SET_ERROR(result, ERR_NOT_READY);
    } else if (status != 0) {
        uint32_t code = (TWO_CC('P', 'T') << 16) | (status & 0xFFFF);
        ARM_UC_SET_ERROR(result, code);
    }
    /* Create "detached thread" attribute only once */
    if (result.error == ERR_NONE && linux_worker_thread.attr_initialized == 0) {
        if ((status = pthread_attr_init(&linux_worker_thread.attr)) != 0) {
            result.error = ERR_INVALID_PARAMETER;
            pthread_mutex_unlock(&linux_worker_thread.mutex);
        } else {
            if ((status = pthread_attr_setdetachstate(&linux_worker_thread.attr, PTHREAD_CREATE_DETACHED)) != 0) {
                result.error = ERR_INVALID_PARAMETER;
                pthread_mutex_unlock(&linux_worker_thread.mutex);
            } else {
                linux_worker_thread.attr_initialized = 1;
            }
        }
    }
    if (result.error == ERR_NONE) {
        /* create a detached thread to execute the supplied routine */
        int status = pthread_create(&linux_worker_thread.thread,
                                    &linux_worker_thread.attr,
                                    start_routine,
                                    arg);

        /* check if thread was created successfully */
        if (status != 0) {
            result.code = ERR_INVALID_PARAMETER;
            pthread_mutex_unlock(&linux_worker_thread.mutex);
        }
    }
    return result;
}

/**
 * @brief Initialize the underlying storage and set the callback handler.
 *
 * @param callback Function pointer to event handler.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_Linux_Initialize(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (callback) {
        arm_uc_pal_linux_internal_set_callback(callback);

        /* create folder for headers if it does not already exist */
        errno = 0;
        int status = mkdir(ARM_UC_HEADER_FOLDER_PATH, 0700);

        if ((status == 0) || (errno == EEXIST)) {
            /* create folder for firmwares if it does not already exist */
            errno = 0;
            status = mkdir(ARM_UC_FIRMWARE_FOLDER_PATH, 0700);

            if ((status == 0) || (errno == EEXIST)) {
                /* set return code on success */
                result.code = ERR_NONE;
            }
        }

        /* signal completion or perform extended preparation */
        if (result.error == ERR_NONE) {
            /* set explicit ERR_NONE upon success */
            result.code = ERR_NONE;

            if (arm_uc_worker_parameters.initialize) {
                /* use extended prepare, invoke script from worker thread */

                /* create a second thread which executes worker_parameters_prepare */
                result = spawn_thread(arm_uc_pal_linux_extended_post_worker,
                                      arm_uc_worker_parameters.initialize);
            } else {
                /* call event handler */
                arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_INITIALIZE_DONE, false);
            }
        }

    }

    return result;
}

/**
 * @brief Get maximum number of supported storage locations.
 *
 * @return Number of storage locations.
 */
uint32_t ARM_UC_PAL_Linux_GetMaxID(void)
{
    return 1;
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
arm_uc_error_t ARM_UC_PAL_Linux_Prepare(uint32_t location,
                                        const arm_uc_firmware_details_t *details,
                                        arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details && buffer) {
        UC_PAAL_TRACE("details size: %" PRIu64, details->size);

        /* write header */
        result = arm_uc_pal_linux_internal_write_header(&location, details);

        /* allocate space for firmware */
        if (result.error == ERR_NONE) {
            char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

            /* construct header file path */
            result = arm_uc_pal_linux_internal_file_path(file_path,
                                                         ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                                         ARM_UC_FIRMWARE_FOLDER_PATH,
                                                         "firmware",
                                                         &location);

            UC_PAAL_TRACE("file path: %s", file_path);

            if (result.error == ERR_NONE) {
                /* open file */
                errno = 0;
                FILE *descriptor = fopen(file_path, "wb");

                if (descriptor != NULL) {
                    /* allocate space by writing empty file */
                    memset(buffer->ptr, 0, buffer->size_max);
                    buffer->size = buffer->size_max;

                    uint64_t index = 0;
/*
 * writing of full file is not enabled by default now. Few drawbacks of writing before download:
 * -kernel watchdog issue due some file IO problem with a huge write (around 4GB)
 * -wear of the MCC device for unnecessary physical writes (there is max number of writes that can be done before physical cells of memory break)
 * -increased time of update process. specially with huge files this will be many minutes of extra time spend to MCC write.
*/
#ifdef WRITE_FULL_PHYSICAL_FILE
                    uint64_t writeSize = details->size;
#else
                    uint64_t writeSize = 1;
#endif
                    while (index < writeSize) {
                        // calculate write size to handle overspill
                        size_t actual_size = details->size - index;

                        if (actual_size > buffer->size) {
                            actual_size = buffer->size;
                        }

                        /* write buffer */
                        size_t xfer_size = fwrite(buffer->ptr,
                                                  sizeof(uint8_t),
                                                  actual_size,
                                                  descriptor);

                        /* break out if write failed */
                        if (xfer_size == actual_size) {
                            index += actual_size;
                        } else {
                            result.code = PAAL_ERR_FIRMWARE_TOO_LARGE;
                            break;
                        }
                    }

                    /* close file after write */
                    int status = fclose(descriptor);

                    if (status == EOF) {
                        UC_PAAL_ERR_MSG("failed to allocate space for firmware");
                        result.code = ERR_INVALID_PARAMETER;
                    }
                } else {
                    UC_PAAL_ERR_MSG("failed to open file: %s", strerror(errno));
                }
            } else {
                UC_PAAL_ERR_MSG("file name and path too long");
            }
        } else {
            UC_PAAL_ERR_MSG("could not write header");
        }

        /* signal completion or perform extended preparation */
        if (result.error == ERR_NONE) {
            /* set explicit ERR_NONE upon success */
            result.code = ERR_NONE;

            if (arm_uc_worker_parameters.prepare) {
                /* use extended prepare, invoke script from worker thread */
                /* export location */
                arm_uc_pal_linux_internal_set_location(&location);

                /* create a second thread which executes worker_parameters_prepare */
                result = spawn_thread(arm_uc_pal_linux_extended_post_worker,
                                      arm_uc_worker_parameters.prepare);
            } else {
                /* call event handler */
                arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_PREPARE_DONE, false);
            }
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
arm_uc_error_t ARM_UC_PAL_Linux_Write(uint32_t location,
                                      uint32_t offset,
                                      const arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer) {
        /* reverse default error code */
        result.code = ERR_NONE;

        /* open file if descriptor is not set */
        if (arm_uc_firmware_descriptor == NULL) {
            char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

            /* construct firmware file path */
            result = arm_uc_pal_linux_internal_file_path(file_path,
                                                         ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                                         ARM_UC_FIRMWARE_FOLDER_PATH,
                                                         "firmware",
                                                         &location);

            if (result.error == ERR_NONE) {
                /* open file */
                if (arm_uc_worker_parameters.write) {
                    /* in extended write, each fragment is stored in its own file */
                    arm_uc_firmware_descriptor = fopen(file_path, "w+b");

                    /* export offset before resetting it */
                    arm_uc_pal_linux_internal_set_offset(offset);
                    offset = 0;
                } else {
                    /* in normal write, each fragment is added to an existing file */
                    arm_uc_firmware_descriptor = fopen(file_path, "r+b");
                }
            } else {
                UC_PAAL_ERR_MSG("firmware file name and path too long");
            }
        }

        /* continue if file is open */
        if (arm_uc_firmware_descriptor != NULL) {
            /* set write position */
            int status = fseeko(arm_uc_firmware_descriptor,
                                offset,
                                SEEK_SET);

            /* continue if position is set */
            if (status == 0) {
                /* write buffer */
                size_t xfer_size = fwrite(buffer->ptr,
                                          sizeof(uint8_t),
                                          buffer->size,
                                          arm_uc_firmware_descriptor);

                /* set error code if write failed */
                if (xfer_size != buffer->size) {
                    UC_PAAL_ERR_MSG("failed to write firmware");
                    result.code = ERR_INVALID_PARAMETER;
                }

                /* if using extended write */
                if (arm_uc_worker_parameters.write) {
                    /* close file after write */
                    int status = fclose(arm_uc_firmware_descriptor);
                    arm_uc_firmware_descriptor = NULL;

                    if (status == EOF) {
                        UC_PAAL_ERR_MSG("failed to close firmware file");
                        result.code = ERR_INVALID_PARAMETER;
                    }
                }
            } else {
                UC_PAAL_ERR_MSG("failed to seek in firmware");
                result.code = ERR_INVALID_PARAMETER;
            }
        }

        /* signal completion or perform extended write */
        if (result.error == ERR_NONE) {
            /* set explicit ERR_NONE */
            result.code = ERR_NONE;

            if (arm_uc_worker_parameters.write) {
                /* use extended write, invoke script from worker thread */
                /* export location */
                arm_uc_pal_linux_internal_set_location(&location);

                /* create a second thread which executes worker_parameters_write */
                result = spawn_thread(arm_uc_pal_linux_extended_post_worker,
                                      arm_uc_worker_parameters.write);
            } else {
                /* call event handler */
                arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_WRITE_DONE, false);
            }
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
arm_uc_error_t ARM_UC_PAL_Linux_Finalize(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_NONE };

    /* only close firmware file if descriptor is not NULL */
    if (arm_uc_firmware_descriptor != NULL) {
        /* close file */
        int status = fclose(arm_uc_firmware_descriptor);
        arm_uc_firmware_descriptor = NULL;

        if (status == EOF) {
            UC_PAAL_ERR_MSG("failed to close firmware file");
            result.code = ERR_INVALID_PARAMETER;
        }
    }

    /* signal completion or perform extended finalization */
    if (result.error == ERR_NONE) {
        /* explicitly set code to ERR_NONE */
        result.code = ERR_NONE;

        /* use extended finalize, invoke script from worker thread */
        if (arm_uc_worker_parameters.finalize) {
            /* export location */
            arm_uc_pal_linux_internal_set_location(&location);

            /* create a second thread which executes worker_parameters_finalize */
            result = spawn_thread(arm_uc_pal_linux_extended_post_worker,
                                  arm_uc_worker_parameters.finalize);
        } else {
            /* call event handler */
            arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_FINALIZE_DONE, false);
        }
    }

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
arm_uc_error_t ARM_UC_PAL_Linux_Read(uint32_t location,
                                     uint32_t offset,
                                     arm_uc_buffer_t *buffer)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer) {
        /* use extended finalize, invoke script from worker thread */
        if (arm_uc_worker_parameters.read) {
            /* export location, offset and buffer */
            arm_uc_pal_linux_internal_set_location(&location);
            arm_uc_pal_linux_internal_set_offset(offset);
            arm_uc_pal_linux_internal_set_buffer(buffer);

            /* create a second thread which executes worker_parameters_read */
            result = spawn_thread(arm_uc_pal_linux_extended_pre_worker,
                                  arm_uc_worker_parameters.read);
        } else {
            /* normal read */
            char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

            /* construct firmware file path */
            result = arm_uc_pal_linux_internal_file_path(file_path,
                                                         ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                                         ARM_UC_FIRMWARE_FOLDER_PATH,
                                                         "firmware",
                                                         &location);

            /* file path is valid */
            if (result.error == ERR_NONE) {
                result = arm_uc_pal_linux_internal_read(file_path, offset, buffer);

                /* signal completion */
                if (result.error == ERR_NONE) {
                    /* call event handler */
                    arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_READ_DONE, false);
                }
            }
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
arm_uc_error_t ARM_UC_PAL_Linux_Activate(uint32_t location)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* read firmware details from location */
    arm_uc_firmware_details_t details = { 0 };
    result = arm_uc_pal_linux_internal_read_header(&location, &details);

    if (result.error == ERR_NONE) {
        UC_PAAL_TRACE("version: %" PRIu64, details.version);
        UC_PAAL_TRACE("size: %"PRIu64, details.size);

        /* write details to active location */
        result = arm_uc_pal_linux_internal_write_header(NULL, &details);

        if (result.error == ERR_NONE) {
            /* explicitly set code to ERR_NONE */
            result.code = ERR_NONE;

            /* use extended activate, invoke script from worker thread */
            if (arm_uc_worker_parameters.activate) {
                /* export location */
                arm_uc_pal_linux_internal_set_location(&location);

                /* create a second thread which executes worker_parameters_read */
                result = spawn_thread(arm_uc_pal_linux_extended_post_worker,
                                      arm_uc_worker_parameters.activate);
            } else {
                arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_ACTIVATE_DONE, false);
            }
        }
    }

    return result;
}

/**
 * @brief Get firmware details for the actively running firmware.
 * @details This call populates the passed details struct with information
 *          about the currently active firmware image. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_Linux_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* use extended get firmware details, invoke script from worker thread */
        if (arm_uc_worker_parameters.active_details) {
            /* export details */
            arm_uc_pal_linux_internal_set_details(details);

            /* create a second thread which executes worker_parameters_read */
            result = spawn_thread(arm_uc_pal_linux_extended_pre_worker,
                                  arm_uc_worker_parameters.active_details);

        } else {
            /* normal read */
            result = arm_uc_pal_linux_internal_read_header(NULL, details);

            if (result.error == ERR_NONE) {
                UC_PAAL_TRACE("version: %" PRIu64, details->version);
                UC_PAAL_TRACE("size: %"PRIu64, details->size);

                if (result.error == ERR_NONE) {
                    arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE, false);
                }
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
arm_uc_error_t ARM_UC_PAL_Linux_GetFirmwareDetails(uint32_t location,
                                                   arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* use extended get firmware details, invoke script from worker thread */
        if (arm_uc_worker_parameters.details) {
            /* export location and details */
            arm_uc_pal_linux_internal_set_location(&location);
            arm_uc_pal_linux_internal_set_details(details);

            /* create a second thread which executes worker_parameters_read */
            result = spawn_thread(arm_uc_pal_linux_extended_pre_worker,
                                  arm_uc_worker_parameters.details);
        } else {
            /* normal read */
            result = arm_uc_pal_linux_internal_read_header(&location, details);

            if (result.error == ERR_NONE) {
                UC_PAAL_TRACE("version: %" PRIu64, details->version);
                UC_PAAL_TRACE("size: %"PRIu64, details->size);

                arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_GET_FIRMWARE_DETAILS_DONE, false);
            }
        }
    }

    return result;
}

/**
 * @brief Get details for the component responsible for installation.
 * @details This call populates the passed details struct with information
 *          about the local installer. Only the fields marked as supported
 *          in the capabilities bitmap will have valid values. The
 *          installer could be the bootloader, a recovery image, or some
 *          other component responsible for applying the new firmware
 *          image.
 *
 * @param details Pointer to installer details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
arm_uc_error_t ARM_UC_PAL_Linux_GetInstallerDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* use extended installer details, invoke script from worker thread */
        if (arm_uc_worker_parameters.installer) {
            /* export installer details */
            arm_uc_pal_linux_internal_set_installer(details);

            /* create a second thread which executes worker_parameters_read */
            result = spawn_thread(arm_uc_pal_linux_extended_pre_worker,
                                  arm_uc_worker_parameters.installer);
        } else {
            /* normal read */
            result = arm_uc_pal_linux_internal_read_installer(details);

            if (result.error == ERR_NONE) {
                arm_uc_pal_linux_signal_callback(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE, false);
            }
        }
    }

    return result;
}

/**
 * @brief Write a manifest to a file.
 * @param location Storage location ID.
 * @param buffer Buffer that contains the manifest.
 * @return Returns ERR_NONE if the manifest was written.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
arm_uc_error_t ARM_UC_PAL_Linux_WriteManifest(uint32_t location, const arm_uc_buffer_t *buffer)
{
    return arm_uc_pal_linux_internal_write_manifest(&location, buffer);
}

#endif /* TARGET_IS_PC_LINUX */
#endif /* ARM_UC_FEATURE_PAL_LINUX */
