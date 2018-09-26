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

#include "update-client-pal-linux/arm_uc_pal_linux_implementation_internal.h"

#include "update-client-common/arm_uc_trace.h"
#include "update-client-common/arm_uc_utilities.h"
#include "update-client-common/arm_uc_metadata_header_v2.h"
#include "update-client-common/arm_uc_scheduler.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* pointer to external callback handler */
static ARM_UC_PAAL_UPDATE_SignalEvent_t arm_uc_pal_external_callback = NULL;

linux_worker_thread_info_t linux_worker_thread = { .attr_initialized = 0, .mutex = PTHREAD_MUTEX_INITIALIZER };

// storage set aside for adding event_cb to the event queue
static arm_uc_callback_t event_cb_storage = { 0 };

void arm_uc_pal_linux_signal_callback(uint32_t event, bool from_thread)
{
    if (arm_uc_pal_external_callback) {
        if (from_thread) {
            /* Run given callback in the update client's thread */
            ARM_UC_PostCallback(&event_cb_storage, arm_uc_pal_external_callback, event);
        } else {
            arm_uc_pal_external_callback(event);
        }
    }
    if (from_thread) {
        /* The last thing that the thread does is call arm_uc_pal_linux_signal_callback(),
         * so unlock the thread mutex so that another thread can be created if needed */
        pthread_mutex_unlock(&linux_worker_thread.mutex);
    }
}

void arm_uc_pal_linux_internal_set_callback(ARM_UC_PAAL_UPDATE_SignalEvent_t callback)
{
    arm_uc_pal_external_callback = callback;
}

static uint32_t arm_uc_offset = 0;
static arm_uc_buffer_t *arm_uc_buffer = NULL;
static arm_uc_firmware_details_t *arm_uc_details = NULL;
static arm_uc_installer_details_t *arm_uc_installer = NULL;
static uint32_t *arm_uc_location = NULL;
static uint32_t arm_uc_location_buffer = 0;

void arm_uc_pal_linux_internal_set_offset(uint32_t offset)
{
    arm_uc_offset = offset;
}

void arm_uc_pal_linux_internal_set_buffer(arm_uc_buffer_t *buffer)
{
    arm_uc_buffer = buffer;
}

void arm_uc_pal_linux_internal_set_details(arm_uc_firmware_details_t *details)
{
    arm_uc_details = details;
}

void arm_uc_pal_linux_internal_set_installer(arm_uc_installer_details_t *details)
{
    arm_uc_installer = details;
}

void arm_uc_pal_linux_internal_set_location(uint32_t *location)
{
    if (location) {
        arm_uc_location_buffer = *location;
        arm_uc_location = &arm_uc_location_buffer;
    } else {
        arm_uc_location = NULL;
    }
}

arm_uc_error_t arm_uc_pal_linux_internal_file_path(char *buffer,
                                                   size_t buffer_length,
                                                   const char *folder,
                                                   const char *type,
                                                   uint32_t *location)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (buffer && folder && type) {
        int actual_length = 0;

        if (location) {
            /* construct file path using location */
            actual_length = snprintf(buffer, buffer_length,
                                     "%s/%s_%" PRIu32 ".bin", folder, type, *location);
        } else {
            /* construct file path without location */
            actual_length = snprintf(buffer, buffer_length,
                                     "%s/%s.bin", folder, type);
        }

        /* check that the buffer is large enough */
        if (actual_length < buffer_length) {
            result.code = ERR_NONE;
        }
    }

    return result;
}

static bool arm_uc_pal_linux_internal_command(arm_ucp_worker_t *parameters,
                                              char *command,
                                              size_t command_length)
{
    /* default to failed */
    bool valid = false;

    if (parameters && command) {
        /* invert status */
        valid = true;

        int length = snprintf(command,
                              command_length,
                              "%s ",
                              parameters->command);

        /* initialize remaining */
        int remaining = command_length - length;

        /* add header parameter if requested */
        if ((remaining > 0) && (parameters->header)) {
            char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

            /* construct header file path */
            arm_uc_error_t result =
                arm_uc_pal_linux_internal_file_path(file_path,
                                                    sizeof(file_path),
                                                    ARM_UC_HEADER_FOLDER_PATH,
                                                    "header",
                                                    arm_uc_location);

            /* generated valid file path */
            if (result.error == ERR_NONE) {
                /* add parameter to command line */
                length += snprintf(&command[length],
                                   remaining,
                                   "-h %s ",
                                   file_path);
            }

            /* update remaining */
            remaining = ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH - length;

            /* check validity */
            valid = ((result.error == ERR_NONE) && (remaining > 0));
        }

        /* add firmware parameter if requested */
        if ((valid) && (parameters->firmware)) {
            char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

            /* construct firmware file path */
            arm_uc_error_t result =
                arm_uc_pal_linux_internal_file_path(file_path,
                                                    sizeof(file_path),
                                                    ARM_UC_FIRMWARE_FOLDER_PATH,
                                                    "firmware",
                                                    arm_uc_location);

            /* generated valid file path */
            if (result.error == ERR_NONE) {
                /* add parameter to command line */
                length += snprintf(&command[length],
                                   remaining,
                                   "-f %s ",
                                   file_path);
            }

            /* update remaining */
            remaining = ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH - length;

            /* check validity */
            valid = ((result.error == ERR_NONE) && (remaining > 0));
        }

        /* add location parameter if requested */
        if ((valid) && (parameters->location)) {
            /* add parameter to command line */
            length += snprintf(&command[length],
                               remaining,
                               "-l %" PRIu32 " ",
                               *arm_uc_location);

            /* update remaining */
            remaining = ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH - length;

            /* check validity */
            valid = (remaining > 0);
        }

        /* add offset parameter if requested */
        if ((valid) && (parameters->offset)) {
            /* add parameter to command line */
            length += snprintf(&command[length],
                               remaining,
                               "-o %" PRIu32 " ",
                               arm_uc_offset);

            /* update remaining */
            remaining = ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH - length;

            /* check validity */
            valid = (remaining > 0);
        }

        /* add size parameter if requested */
        if ((valid) && (parameters->size)) {
            if (arm_uc_buffer) {
                /* add parameter to command line */
                length += snprintf(&command[length],
                                   remaining,
                                   "-s %" PRIu32 " ",
                                   arm_uc_buffer->size_max);

                /* update remaining */
                remaining = ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH - length;

                /* check validity */
                valid = (remaining > 0);
            } else {
                valid = false;
            }
        }
    }

    return valid;
}

arm_uc_error_t arm_uc_pal_linux_internal_read(const char *file_path,
                                              uint32_t offset,
                                              arm_uc_buffer_t *buffer)
{
    /* default to failure result */
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (file_path && buffer) {
        /* open file */
        errno = 0;
        FILE *descriptor = fopen(file_path, "rb");

        /* continue if file is open */
        if (descriptor != NULL) {
            /* set read position */
            int status = fseek(descriptor, offset, SEEK_SET);

            /* continue if position is set */
            if (status == 0) {
                /* read buffer */
                errno = 0;
                size_t xfer_size = fread(buffer->ptr,
                                         sizeof(uint8_t),
                                         buffer->size,
                                         descriptor);

                /* set buffer size if read succeeded */
                status = ferror(descriptor);

                if (status == 0) {
                    buffer->size = xfer_size;

                    /* set successful result */
                    result.code = ERR_NONE;
                } else {
                    /* set error code if read failed */
                    UC_PAAL_ERR_MSG("failed to read %s: %s", file_path, strerror(errno));
                    buffer->size = 0;
                }

                /* close file after read */
                fclose(descriptor);
            } else {
                UC_PAAL_ERR_MSG("failed to seek in: %s", file_path);
            }
        } else {
            UC_PAAL_ERR_MSG("failed to open %s: %s", file_path, strerror(errno));
        }
    }

    return result;
}

arm_uc_error_t arm_uc_pal_linux_internal_read_header(uint32_t *location,
                                                     arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* construct header file path */
        char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

        result = arm_uc_pal_linux_internal_file_path(file_path,
                                                     ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                                     ARM_UC_HEADER_FOLDER_PATH,
                                                     "header",
                                                     location);

        /* file path is valid */
        if (result.error == ERR_NONE) {
            /* allocate external header sized read buffer since it will be
               large enough to hold either an internal or external header.
             */
            uint8_t read_buffer[ARM_UC_EXTERNAL_HEADER_SIZE_V2] = { 0 };

            arm_uc_buffer_t buffer = {
                .size_max = sizeof(read_buffer),
                .size     = sizeof(read_buffer),
                .ptr      = read_buffer
            };

            /* read metadata header */
            result = arm_uc_pal_linux_internal_read(file_path, 0, &buffer);

            /* check return code */
            if (result.error == ERR_NONE) {
                UC_PAAL_TRACE("header bytes: %u", buffer.size);

                /* read out header magic */
                uint32_t headerMagic = arm_uc_parse_uint32(&read_buffer[0]);

                /* read out header magic */
                uint32_t headerVersion = arm_uc_parse_uint32(&read_buffer[4]);

                /* choose version to decode */
                if ((headerMagic == ARM_UC_INTERNAL_HEADER_MAGIC_V2) &&
                        (headerVersion == ARM_UC_INTERNAL_HEADER_VERSION_V2) &&
                        (buffer.size == ARM_UC_INTERNAL_HEADER_SIZE_V2)) {
                    result = arm_uc_parse_internal_header_v2(read_buffer, details);
                } else if ((headerMagic == ARM_UC_EXTERNAL_HEADER_MAGIC_V2) &&
                           (headerVersion == ARM_UC_EXTERNAL_HEADER_VERSION_V2) &&
                           (buffer.size == ARM_UC_EXTERNAL_HEADER_SIZE_V2)) {
                    result = arm_uc_parse_external_header_v2(read_buffer, details);
                } else {
                    if (location) {
                        UC_PAAL_ERR_MSG("invalid header in slot %" PRIu32, *location);
                    } else {
                        UC_PAAL_ERR_MSG("invalid header location");
                    }

                    /* invalid header format */
                    result.code = ERR_INVALID_PARAMETER;
                }
            } else {
                /* unsuccessful read */
                if (location) {
                    UC_PAAL_ERR_MSG("unable to read header in slot %" PRIX32, *location);
                } else {
                    UC_PAAL_ERR_MSG("unable to read from unspecified header location");
                }
            }
        } else {
            UC_PAAL_ERR_MSG("header file name and path too long");
        }
    }

    return result;
}

arm_uc_error_t arm_uc_pal_linux_internal_read_installer(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* construct file path */
        char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

        result = arm_uc_pal_linux_internal_file_path(file_path,
                                                     ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                                     ARM_UC_INSTALLER_FOLDER_PATH,
                                                     "installer",
                                                     NULL);

        /* file path is valid */
        if (result.error == ERR_NONE) {
            uint8_t read_buffer[2 * sizeof(arm_uc_hash_t) + sizeof(uint32_t)] = { 0 };

            arm_uc_buffer_t buffer = {
                .size_max = sizeof(read_buffer),
                .size     = 0,
                .ptr      = read_buffer
            };

            /* read installer details */
            result = arm_uc_pal_linux_internal_read(file_path, 0, &buffer);

            UC_PAAL_TRACE("installer bytes: %u", buffer.size);

            /* check return code */
            if ((result.error == ERR_NONE) &&
                    (buffer.size == sizeof(read_buffer))) {
                memcpy(details->arm_hash,
                       buffer.ptr,
                       sizeof(arm_uc_hash_t));

                memcpy(details->oem_hash,
                       &buffer.ptr[sizeof(arm_uc_hash_t)],
                       sizeof(arm_uc_hash_t));

                details->layout = arm_uc_parse_uint32(&buffer.ptr[2 * sizeof(arm_uc_hash_t)]);
            } else {
                /* unsuccessful read */
                UC_PAAL_ERR_MSG("unable to read installer details");
            }
        } else {
            UC_PAAL_ERR_MSG("installer file name and path too long");
        }
    }

    return result;
}

arm_uc_error_t arm_uc_pal_linux_internal_write_header(uint32_t *location,
                                                      const arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* allocate external header sized buffer since it will be
           large enough to hold either an internal or external header.
         */
        uint8_t temp_buffer[ARM_UC_EXTERNAL_HEADER_SIZE_V2] = { 0 };

        arm_uc_buffer_t buffer = {
            .size_max = sizeof(temp_buffer),
            .size     = 0,
            .ptr      = temp_buffer
        };

        /* encode firmware details in buffer */
#if ARM_UC_USE_EXTERNAL_HEADER
        result = arm_uc_create_external_header_v2(details, &buffer);
#else
        result = arm_uc_create_internal_header_v2(details, &buffer);
#endif

        /* write header file */
        if (result.error == ERR_NONE) {
            char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

            /* construct header file path */
            result = arm_uc_pal_linux_internal_file_path(file_path,
                                                         ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                                         ARM_UC_HEADER_FOLDER_PATH,
                                                         "header",
                                                         location);

            if (result.error == ERR_NONE) {
                /* inverse result */
                result.code = ERR_INVALID_PARAMETER;

                /* open file and get file handler */
                errno = 0;
                FILE *file = fopen(file_path, "wb");

                if (file != NULL) {
                    /* write buffer to file */
                    size_t xfer_size = fwrite(buffer.ptr,
                                              sizeof(uint8_t),
                                              buffer.size,
                                              file);

                    UC_PAAL_TRACE("written: %" PRIu64, xfer_size);

                    /* close file after write */
                    int status = fclose(file);

                    if ((xfer_size == buffer.size) &&
                            (status != EOF)) {
                        /* set return code if write was successful */
                        result.code = ERR_NONE;
                    } else {
                        UC_PAAL_ERR_MSG("failed to write header");
                    }
                } else {
                    UC_PAAL_ERR_MSG("file open failed: %s", strerror(errno));
                }
            } else {
                UC_PAAL_ERR_MSG("header file name and path too long");
            }
        } else {
            UC_PAAL_ERR_MSG("header too large for buffer");
        }

    }

    return result;
}

/**
 * @brief Function to run script in a worker thread before file operations.
 *
 * @param params Pointer to arm_ucp_worker_t struct.
 */
void *arm_uc_pal_linux_extended_pre_worker(void *params)
{
    /* default to failure */
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    /* get parameters */
    arm_ucp_worker_t *parameters = (arm_ucp_worker_t *) params;

    /* file path to script result */
    char file_path[ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH] = { 0 };

    /* construct script command */
    char command[ARM_UC_MAXIMUM_COMMAND_LENGTH] = { 0 };

    int valid = arm_uc_pal_linux_internal_command(parameters,
                                                  command,
                                                  ARM_UC_MAXIMUM_COMMAND_LENGTH);

    /* command is valid */
    if (valid) {
        UC_PAAL_TRACE("Extended pre-script command: %s", command);

        /* execute script */
        errno = 0;
        FILE *pipe = popen(command, "r");

        if (pipe) {
            /* read pipe */
            size_t xfer_size = fread(file_path,
                                     sizeof(uint8_t),
                                     ARM_UC_MAXIMUM_FILE_AND_PATH_LENGTH,
                                     pipe);

            /* trim non-printable characters */
            for (size_t index = 0; index < xfer_size; index++) {
                /* space is the first printable character */
                if (file_path[index] < ' ') {
                    /* truncate string */
                    file_path[index] = '\0';
                    break;
                }
            }

            int status = 0;

            /* check fread error status */
            status = ferror(pipe);
            if (status == 0) {
                /* Wait for child thread termination and check exit status */
                status = pclose(pipe);

                /* make sure child thread terminated correctly and scirpt exit status is 0 */
                if (status != -1 && WIFEXITED(status)) {
                    if (WEXITSTATUS(status) == 0) {
                        /* switch from boolean result to arm_uc_error_t */
                        result.code = ERR_NONE;
                    } else {
                        UC_PAAL_ERR_MSG("Script exited with non-zero status %" PRId32, status);
                    }
                } else {
                    UC_PAAL_ERR_MSG("pipe terminated incorrectly %" PRId32, status);
                }
            } else {
                UC_PAAL_ERR_MSG("failed to read pipe: %" PRId32, status);
            }
        } else {
            UC_PAAL_ERR_MSG("failed to execute script: %" PRId32, errno);
        }
    }

    /* file path is valid */
    if (result.error == ERR_NONE) {
        /* invert status */
        result.code = ERR_INVALID_PARAMETER;

        extern arm_ucp_worker_config_t arm_uc_worker_parameters;

        /* perform read operation */
        if ((parameters == arm_uc_worker_parameters.read) &&
                (arm_uc_buffer != NULL)) {
            result = arm_uc_pal_linux_internal_read(file_path, 0, arm_uc_buffer);

            /* reset global buffer */
            arm_uc_buffer = NULL;
        }

        /* read details */
        if ((parameters == arm_uc_worker_parameters.details) &&
                (arm_uc_details != NULL)) {
            result = arm_uc_pal_linux_internal_read_header(arm_uc_location,
                                                           arm_uc_details);

            /* reset global details pointer */
            arm_uc_details = NULL;
        }

        /* read active details */
        if ((parameters == arm_uc_worker_parameters.active_details) &&
                (arm_uc_details != NULL)) {
            result = arm_uc_pal_linux_internal_read_header(NULL,
                                                           arm_uc_details);

            /* reset global details pointer */
            arm_uc_details = NULL;
        }

        /* read installer details */
        if ((parameters == arm_uc_worker_parameters.installer) &&
                (arm_uc_installer != NULL)) {
            result = arm_uc_pal_linux_internal_read_installer(arm_uc_installer);

            /* reset global installer pointer */
            arm_uc_installer = NULL;
        }
    }

    if (result.error == ERR_NONE) {
        UC_PAAL_TRACE("pre-script complete");

        arm_uc_pal_linux_signal_callback(parameters->success_event, true);
    } else {
        UC_PAAL_ERR_MSG("pre-script failed");

        arm_uc_pal_linux_signal_callback(parameters->failure_event, true);
    }
    return NULL;
}

/**
 * @brief Function to run script in a worker thread before file operations.
 *
 * @param params Pointer to arm_ucp_worker_t struct.
 */
void *arm_uc_pal_linux_extended_post_worker(void *params)
{
    /* get parameters */
    arm_ucp_worker_t *parameters = (arm_ucp_worker_t *) params;

    /* construct script command */
    char command[ARM_UC_MAXIMUM_COMMAND_LENGTH] = { 0 };

    int error = 0;
    int32_t event = 0;
    int valid = arm_uc_pal_linux_internal_command(parameters,
                                                  command,
                                                  ARM_UC_MAXIMUM_COMMAND_LENGTH);

    if (valid) {
        UC_PAAL_TRACE("Extended post-script command: %s", command);

        /* execute script command */
        error = system(command);
        error = WEXITSTATUS(error);

        /* update valid flag */
        valid = (error == 0);
    }

    if (valid) {
        UC_PAAL_TRACE("post-script completed");

        event = parameters->success_event;

        /* execute the post runner if it exists and the script succeeded */
        if (parameters->post_runner) {
            event = parameters->post_runner();
            UC_PAAL_TRACE("post runner returned event %" PRId32, event);
        }
    } else {
        UC_PAAL_ERR_MSG("post-script failed: %" PRId32, error);

        event = parameters->failure_event;
    }

    arm_uc_pal_linux_signal_callback(event, true);

    return NULL;
}

#endif /* TARGET_IS_PC_LINUX */
#endif /* ARM_UC_FEATURE_PAL_LINUX */
