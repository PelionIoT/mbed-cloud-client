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

#include "update-client-common/arm_uc_config.h"
#if defined(ARM_UC_FEATURE_PAL_FILESYSTEM) && (ARM_UC_FEATURE_PAL_FILESYSTEM == 1)
#if defined(TARGET_IS_PC_LINUX)

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
#include "arm_uc_crypto.h"
#include "update-client-delta-paal/arm_uc_pal_delta_paal_original_reader.h"
#endif

#include "update-client-pal-filesystem/arm_uc_pal_extensions.h"

#include "update-client-metadata-header/arm_uc_metadata_header_v2.h"
#include "arm_uc_pal_filesystem_utils.h"

#include "pal.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "update-client-extensions"

#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
#include <sys/stat.h>
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS
#define MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS 0
#endif

#ifndef MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS
#define MBED_CONF_UPDATE_CLIENT_BOOTLOADER_DETAILS 0
#endif

static void (*arm_ucex_linux_callback)(uintptr_t) = NULL;
static palImageId_t arm_ucex_activate_image_id;

#ifndef PAL_UPDATE_ACTIVATE_SCRIPT
#define PAL_UPDATE_ACTIVATE_SCRIPT "./activate_script"
#endif

#define ORIG_FILENAME_MAX_PATH PAL_MAX_FILE_AND_FOLDER_LENGTH

// IMAGE_HEADER_FILENAME_UPDATE points to filename/path where the
// active firmware metadata header is to be found.
// At the end of update the above activate-script should copy the
// new metadata header to this path so that new version
// gets reported to the cloud in next bootup
#define IMAGE_HEADER_FILENAME_UPDATE    "header.bin"

/**
 * Return file size of original firmware.
 * @return ERR_NONE if success, otherwise error
 */
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
static int original_file_stat(uint64_t* file_size)
{
    arm_uc_error_t result;
    char file_path[ORIG_FILENAME_MAX_PATH] = { 0 };

    result = arm_uc_delta_paal_construct_original_image_file_path(file_path, ORIG_FILENAME_MAX_PATH);

    if (result.error != ERR_NONE) {
        UC_PAAL_ERR_MSG("arm_uc_pal_linux_internal_file_path failed with %d\n", result.error);
        return ERR_UNSPECIFIED;
    }
    struct stat buf;

    int stat_res = stat(file_path, &buf);

    if (stat_res == 0) {
        *file_size = buf.st_size;
        return ERR_NONE;
    }
    return ERR_UNSPECIFIED;
}
#endif // #if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)

arm_uc_error_t pal_ext_imageInitAPI(void (*callback)(uintptr_t))
{
    arm_uc_error_t result = { .code = ERR_NONE };

    arm_ucex_linux_callback = callback;

    return result;
}

arm_uc_error_t pal_ext_imageGetActiveDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        palFileDescriptor_t fd;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_MULTICAST_UPDATE
        char primary[PAL_MAX_FILE_AND_FOLDER_LENGTH];
        char path[PAL_MAX_FILE_AND_FOLDER_LENGTH];
        palStatus_t status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, primary);
#else
        palStatus_t status = pal_fsFopen(IMAGE_HEADER_FILENAME_UPDATE, PAL_FS_FLAG_READONLY, &fd);
#endif
        if (PAL_SUCCESS == status) {
#ifdef MBED_CLOUD_CLIENT_SUPPORT_MULTICAST_UPDATE
            snprintf(path, PAL_MAX_FILE_AND_FOLDER_LENGTH, "%s/%s", primary, IMAGE_HEADER_FILENAME_UPDATE);
            status = pal_fsFopen(path, PAL_FS_FLAG_READONLY, &fd);
            if (PAL_SUCCESS == status) {
#endif
                uint8_t read_buffer[ARM_UC_EXTERNAL_HEADER_SIZE_V2];
                size_t bytes_read;
                status = pal_fsFread(&fd, &read_buffer, sizeof(read_buffer), &bytes_read);
                if (PAL_SUCCESS == status) {
                    /* read out header magic */
                    uint32_t headerMagic = arm_uc_parse_uint32(&read_buffer[0]);

                    /* read out header magic */
                    uint32_t headerVersion = arm_uc_parse_uint32(&read_buffer[4]);

                    /* choose version to decode */
                    if (headerMagic == ARM_UC_INTERNAL_HEADER_MAGIC_V2 &&
                            headerVersion == ARM_UC_INTERNAL_HEADER_VERSION_V2 &&
                            bytes_read == ARM_UC_INTERNAL_HEADER_SIZE_V2) {
                        result = arm_uc_parse_internal_header_v2(read_buffer, details);
                    } else if (headerMagic == ARM_UC_EXTERNAL_HEADER_MAGIC_V2 &&
                               headerVersion == ARM_UC_EXTERNAL_HEADER_VERSION_V2 &&
                               bytes_read == ARM_UC_EXTERNAL_HEADER_SIZE_V2) {
                        result = arm_uc_parse_external_header_v2(read_buffer, details);
                    } else {
                        /* invalid header format */
                        tr_err("Unrecognized firmware header: magic = 0x%" PRIx32 ", version = 0x%" PRIx32 ", size = %" PRIu32 ,
                               headerMagic, headerVersion, bytes_read);
                    }
                }
                pal_fsFclose(&fd);
            } else {
                // XXX TODO: Need to implement version query before any update has been processed.
                //           In this version info is fetched only from header file which is created
                //           during update process.
                tr_info("pal_fsOpen returned status = %" PRIu32, status);
            }

            if (PAL_SUCCESS != status || ERR_NONE != result.code) {
                // Zero the details
                memset(details, 0, sizeof(arm_uc_firmware_details_t));

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
                // Attempt to calculate hash for currently running executable to satisfy
                // delta payload precursor check.
                int64_t f_size;
                int stat_res = original_file_stat(&f_size);
                if (stat_res == ERR_NONE) {
                    arm_uc_mdHandle_t mdHandle = { 0 };
                    arm_uc_error_t res = ARM_UC_cryptoHashSetup(&mdHandle, ARM_UC_CU_SHA256);
                    if (res.error == ERR_NONE) {
                        // buffer
                        uint8_t data_buf[ARM_UC_SHA256_SIZE];

                        // arm buffer
                        arm_uc_buffer_t buffer;
                        buffer.size = 0;
                        buffer.size_max = ARM_UC_SHA256_SIZE;
                        buffer.ptr = data_buf;

                        // reading offset
                        size_t offset = 0;

                        // reading length
                        uint64_t len;

                        // trim to max of file size
                        if (f_size < ARM_UC_SHA256_SIZE) {
                            len = f_size;
                        } else {
                            len = ARM_UC_SHA256_SIZE;
                        }

                        // read original file
                        while(len > 0 && arm_uc_deltapaal_original_reader(buffer.ptr, len, offset) == ERR_NONE) {
                            // update hash
                            buffer.size = len;
                            ARM_UC_cryptoHashUpdate(&mdHandle, &buffer);

                            // update offset
                            offset += len;

                            // trim next read to file size if necessary
                            if (f_size - offset < ARM_UC_SHA256_SIZE) {
                                len = f_size - offset;
                            } else {
                                len = ARM_UC_SHA256_SIZE;
                            }
                        }

                        // get hash to buffer
                        ARM_UC_cryptoHashFinish(&mdHandle, &buffer);

                        if (offset == 0) {
                            tr_warn("Original reader failed with first read => keep zero hash");
                        }
                        else {
                            // copy hash to otherwise zeroed details
                            memcpy(details->hash, buffer.ptr, ARM_UC_SHA256_SIZE);
                        }
                    } else {
                        tr_warn("ARM_UC_cryptoHashSetup failed with %" PRIu32, res.error);
                    }
                }
                else {
                    tr_warn("arm_uc_deltapaal_original_stat failed with %d", stat_res);
                }
#endif // #if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
            }
#ifdef MBED_CLOUD_CLIENT_SUPPORT_MULTICAST_UPDATE
        } else {
            tr_err("pal_fsGetMountPoint returned status = %" PRIu32, status);
        }
#endif
        if (arm_ucex_linux_callback) {
            arm_ucex_linux_callback(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);
        }
    }

    return result;
}

arm_uc_error_t pal_ext_installerGetDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        /* dummy implementation, return 0 */
        memset(details, 0, sizeof(arm_uc_installer_details_t));

        result.code = ERR_NONE;

        if (arm_ucex_linux_callback) {
            arm_ucex_linux_callback(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);
        }
    }

    return result;
}

static void pal_ext_imageActivationWorker(const void *location)
{
    char cmd_buf[sizeof(PAL_UPDATE_ACTIVATE_SCRIPT) + 1 + PAL_MAX_FILE_AND_FOLDER_LENGTH + 1];
    char path_buf[PAL_MAX_FILE_AND_FOLDER_LENGTH];
#ifdef MBED_CLOUD_CLIENT_SUPPORT_MULTICAST_UPDATE
    arm_uc_error_t result = arm_uc_pal_filesystem_get_path(*(palImageId_t *)location, FIRMWARE_IMAGE_ITEM_HEADER,
                                                           path_buf, PAL_MAX_FILE_AND_FOLDER_LENGTH);
#else
    arm_uc_error_t result = arm_uc_pal_filesystem_get_path(*(palImageId_t *)location, FIRMWARE_IMAGE_ITEM_DATA,
                                                               path_buf, PAL_MAX_FILE_AND_FOLDER_LENGTH);
#endif
    palStatus_t rc = PAL_ERR_GENERIC_FAILURE;

    if (result.code == ERR_NONE) {
        int err = snprintf(cmd_buf, sizeof(cmd_buf), "%s %s",
                           PAL_UPDATE_ACTIVATE_SCRIPT, path_buf);
        if (err > 0) {
            rc = PAL_SUCCESS;
        } else {
            tr_err("snprintf failed with err %i", err);
            rc = PAL_ERR_GENERIC_FAILURE;
        }
    }


    if (rc == PAL_SUCCESS) {
        tr_debug("Activate by executing %s", cmd_buf);
        int err = system(cmd_buf);
        err = WEXITSTATUS(err);

        if (err != -1) {
            tr_debug("Activate completed with %" PRId32, err);
            rc = PAL_SUCCESS;
        } else {
            tr_err("system call failed with err %" PRId32, err);
            rc = PAL_ERR_GENERIC_FAILURE;
        }
    }
    fflush(stdout);
    sleep(1);

    if (arm_ucex_linux_callback) {
        uint32_t event = (rc == PAL_SUCCESS ? ARM_UC_PAAL_EVENT_ACTIVATE_DONE : ARM_UC_PAAL_EVENT_ACTIVATE_ERROR);
        arm_ucex_linux_callback(event);
    }
}

arm_uc_error_t pal_ext_imageActivate(uint32_t location)
{
    arm_uc_error_t err = { .code = ERR_INVALID_PARAMETER };

    memcpy(&arm_ucex_activate_image_id, &location, sizeof(palImageId_t));

    palThreadID_t thread_id = 0;
    palStatus_t rc = pal_osThreadCreateWithAlloc(pal_ext_imageActivationWorker, &arm_ucex_activate_image_id,
                                                 PAL_osPriorityBelowNormal, PTHREAD_STACK_MIN, NULL, &thread_id);
    if (rc != PAL_SUCCESS) {
        tr_err("Thread creation failed with %x", rc);
        err.code = ERR_INVALID_PARAMETER;
    } else {
        tr_debug("Activation thread created, thread ID: %" PRIuPTR, thread_id);
        err.code = ERR_NONE;
    }

    return err;
}

#endif /* TARGET_IS_PC_LINUX */
#endif /* ARM_UC_FEATURE_PAL_FILESYSTEM */
