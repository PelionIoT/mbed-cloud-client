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
#if defined(__SXOS__)

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

#include <fota.h>
#include <vfs.h>
#include <tgt_m.h>


static void (*arm_ucex_sxos_callback)(uint32_t) = NULL;

// Header filename of active image
#define IMAGE_HEADER_FILENAME_ACTIVE    "header_active.bin"

// Header filename for new image (during update process)
#define IMAGE_HEADER_FILENAME_UPDATE    "header_update.bin"

#define OEM_HASH_VALUE_MAX_ITEM_LEN     (ARM_UC_SHA256_SIZE / 2)

static FOTA_ENV_T fenv = {
    .packFname = FOTA_PACK_DEFAULT_FILENAME,
    .idxFname = FOTA_INDEX_DEFAULT_FILENAME,
};
static FOTA_CONTEXT_T *fota_ctx = NULL;


arm_uc_error_t pal_ext_imageInitAPI(void (*callback)(uint32_t))
{
    arm_uc_error_t result = { .code = ERR_NONE };

    arm_ucex_sxos_callback = callback;

    tr_debug("Initializing FOTA...");
    fota_ctx = (FOTA_CONTEXT_T *)malloc(fotaContextSize());
    if (fota_ctx) {
        if (fotaInit(fota_ctx, &fenv)) {
            if (FOTA_AREA_UPGRADED == fotaGetStatus(fota_ctx)) {
                // FOTA upgrade successful -> Rename header file as active
                tr_debug("FOTA succeeded. Updating new image header");
                if (vfs_rename(IMAGE_HEADER_FILENAME_UPDATE, IMAGE_HEADER_FILENAME_ACTIVE) != 0) {
                    tr_error("Unable to rename update header as active!");
                }
            }
            // Mark fota image as handled
            fotaInvalidate(fota_ctx);

            // Remove fota image from file system
            pal_fsUnlink(FOTA_PACK_DEFAULT_FILENAME);
        } else {
            tr_error("FOTA init failure!");
            free(fota_ctx);
            fota_ctx = NULL;
            result.code = ERR_NOT_READY;
        }
    } else {
        tr_error("Unable to allocate FOTA CTX!");
        result.code = ERR_NOT_READY;
    }

    tr_debug("Initializing FOTA... Result = %d", result.code);
    return result;
}

arm_uc_error_t pal_ext_imageGetActiveDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        palFileDescriptor_t fd;
        palStatus_t status = pal_fsFopen(IMAGE_HEADER_FILENAME_ACTIVE, PAL_FS_FLAG_READONLY, &fd);
        if (PAL_SUCCESS == status) {
            uint8_t read_buffer[ARM_UC_EXTERNAL_HEADER_SIZE_V2];
            size_t bytes_read;
            status = pal_fsFread(&fd, &read_buffer, sizeof(read_buffer), &bytes_read);
            if (PAL_SUCCESS == status) {
                /* read out header magic */
                uint32_t headerMagic = arm_uc_parse_uint32(&read_buffer[0]);

                /* read out header magic */
                uint32_t headerVersion = arm_uc_parse_uint32(&read_buffer[4]);

                /* choose version to decode */
                if ((headerMagic == ARM_UC_INTERNAL_HEADER_MAGIC_V2) &&
                    (headerVersion == ARM_UC_INTERNAL_HEADER_VERSION_V2) &&
                    (bytes_read == ARM_UC_INTERNAL_HEADER_SIZE_V2)) {
                    result = arm_uc_parse_internal_header_v2(read_buffer, details);
                } else if ((headerMagic == ARM_UC_EXTERNAL_HEADER_MAGIC_V2) &&
                           (headerVersion == ARM_UC_EXTERNAL_HEADER_VERSION_V2) &&
                           (bytes_read == ARM_UC_EXTERNAL_HEADER_SIZE_V2)) {
                    result = arm_uc_parse_external_header_v2(read_buffer, details);
                } else {
                    /* invalid header format */
                    tr_error("Unrecognized firmware header: magic = 0x%" PRIx32 ", version = 0x%" PRIx32 ", size = %" PRIu32 ,
                        headerMagic, headerVersion, bytes_read);
                    result.code = ERR_INVALID_PARAMETER;
                }
            }
            pal_fsFclose(&fd);
        } else {
            // XXX TODO: Need to implement version query before any update has been processed.
            //           In this version info is fetched only from header file which is created
            //           during update process.
            tr_warn("No image header");
        }

        if (PAL_SUCCESS != status || ERR_NONE != result.code) {
            memset(details, 0, sizeof(arm_uc_firmware_details_t));
        }

        if (arm_ucex_sxos_callback) {
            arm_ucex_sxos_callback(ARM_UC_PAAL_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE);
        }
    }

    return result;
}

arm_uc_error_t pal_ext_installerGetDetails(arm_uc_installer_details_t *details)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (details) {
        const char *build_release;
        const char *build_version;

        memset(details, 0, sizeof(arm_uc_installer_details_t));

        /* Get values from SXOS */
        build_release = tgt_GetBuildRelease();
        build_version = tgt_GetBuildVerNo();

        if (build_release) {
            memcpy(details->oem_hash, build_release, (strlen(build_release) > OEM_HASH_VALUE_MAX_ITEM_LEN) ? OEM_HASH_VALUE_MAX_ITEM_LEN : strlen(build_release));
        }

        if (build_version) {
            memcpy(details->oem_hash + OEM_HASH_VALUE_MAX_ITEM_LEN, build_version, (strlen(build_version) > OEM_HASH_VALUE_MAX_ITEM_LEN) ? OEM_HASH_VALUE_MAX_ITEM_LEN : strlen(build_version));
        }

        tr_info("OEM hash value: %s", trace_array(details->oem_hash, ARM_UC_SHA256_SIZE));

        result.code = ERR_NONE;

        if (arm_ucex_sxos_callback) {
            arm_ucex_sxos_callback(ARM_UC_PAAL_EVENT_GET_INSTALLER_DETAILS_DONE);
        }
    }

    return result;
}

arm_uc_error_t pal_ext_imageActivate(uint32_t location)
{
    arm_uc_error_t err = { .code = ERR_INVALID_PARAMETER };
    palStatus_t rc = PAL_ERR_GENERIC_FAILURE;

    char image_path_buf[PAL_MAX_FILE_AND_FOLDER_LENGTH];
    char header_path_buf[PAL_MAX_FILE_AND_FOLDER_LENGTH];

    tr_info("Activating FOTA image...");

    err = arm_uc_pal_filesystem_get_path((palImageId_t)location, FIRMWARE_IMAGE_ITEM_DATA,
                                         image_path_buf, PAL_MAX_FILE_AND_FOLDER_LENGTH);
    if (err.code == ERR_NONE) {
        err = arm_uc_pal_filesystem_get_path((palImageId_t)location, FIRMWARE_IMAGE_ITEM_HEADER,
                                             header_path_buf, PAL_MAX_FILE_AND_FOLDER_LENGTH);
        if (err.code == ERR_NONE) {
            // Mark old file as invalid
            fotaInvalidate(fota_ctx);

            // SX OS expects FOTA image to be names as FOTA_PACK_DEFAULT_FILENAME
            if (vfs_rename(image_path_buf, FOTA_PACK_DEFAULT_FILENAME) == 0) {
                if (fotaDownloadFinished(fota_ctx)) {
                    // Copy header as candidate for new image
                    if (vfs_rename(header_path_buf, IMAGE_HEADER_FILENAME_UPDATE) == 0) {
                        rc = PAL_SUCCESS;
                    } else {
                        tr_error("Unable to rename FOTA header!");
                    }
                } else {
                    tr_error("FOTA image validation failed!");
                    fotaInvalidate(fota_ctx);
                }
            } else {
                tr_error("Unable to rename FOTA image!");
            }
        } else {
            tr_error("Unable to find image header!");
        }
    } else {
        tr_error("Unable to find image!");
    }

    if (arm_ucex_sxos_callback) {
        uint32_t event = (rc == PAL_SUCCESS && err.code == ERR_NONE ? ARM_UC_PAAL_EVENT_ACTIVATE_DONE : ARM_UC_PAAL_EVENT_ACTIVATE_ERROR);
        arm_ucex_sxos_callback(event);
    }

    if (rc != PAL_SUCCESS) {
        err.code = ERR_INVALID_PARAMETER;
    } else {
        err.code = ERR_NONE;
    }

    tr_info("Activating FOTA image... Done. rc = %d, err = %d", rc, err.code);
    return err;
}

#endif /* __SXOS__ */
#endif /* ARM_UC_FEATURE_PAL_FILESYSTEM */
