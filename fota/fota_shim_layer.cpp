// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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

#include "fota/fota_shim_layer.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE) && defined(FOTA_SHIM_LAYER)

#define TRACE_GROUP "FOTA"

#include "fota/fota_app_ifs.h"

#include <inttypes.h>

auth_handler_t auth_handler = NULL;
priority_auth_handler_t priority_auth_handler = NULL;
progress_handler_t progress_handler = NULL;

void fota_shim_set_auth_handler(auth_handler_t handler)
{
    auth_handler = handler;
}

void fota_shim_set_auth_handler(priority_auth_handler_t handler)
{
    priority_auth_handler = handler;
}

void fota_shim_set_progress_handler(progress_handler_t handler)
{
    progress_handler = handler;
}

void fota_app_on_download_progress(size_t downloaded_size, size_t current_chunk_size, size_t total_size)
{
    FOTA_ASSERT(total_size);
    if (progress_handler) {
        progress_handler(downloaded_size, total_size);
        return;
    }

    static const uint32_t  print_range_percent = 5;

    total_size /= 100;
    // In case total size is less then 100B return without printing progress
    if (total_size == 0) {
        return;
    }

    uint32_t progress = (downloaded_size + current_chunk_size) / total_size;
    uint32_t prev_progress = downloaded_size / total_size;

    if (downloaded_size == 0 || ((progress / print_range_percent) > (prev_progress / print_range_percent))) {
        FOTA_APP_PRINT("Downloading firmware. %" PRIu32 "%c", progress, '%');
    }
}

/* Pelion FOTA done or terminated.
 * Application can restore performance sensitive tasks and
 * dismiss any update running dialogs.
 *
*/
int fota_app_on_complete(int32_t status)
{
    return FOTA_STATUS_SUCCESS;
}

/* Pelion FOTA Client wishes to reboot and apply the new firmware.

    The user application is supposed to save all current work
    before rebooting.

    Note: the authorization call can be postponed and called later.
    This doesn't affect the performance of the Cloud Client.
*/
int fota_app_on_install_authorization()
{
    if (priority_auth_handler) {
        priority_auth_handler(ARM_UCCC_REQUEST_INSTALL, 0);
    } else if (auth_handler) {
        auth_handler(ARM_UCCC_REQUEST_INSTALL);
    } else {
        fota_app_authorize();
        FOTA_APP_PRINT("Install authorization granted");
    }
    return FOTA_STATUS_SUCCESS;
}

/* Pelion FOTA Client wishes to download new firmware.
    This can have a negative impact on the performance of the
    rest of the system.

    The user application is supposed to pause performance
    sensitive tasks before authorizing the download.

    Note: the authorization call can be postponed and called later.
    This doesn't affect the performance of the Cloud Client.
*/
int fota_app_on_download_authorization(
    const manifest_firmware_info_t *candidate_info,
    fota_component_version_t curr_fw_version
)
{
    if (priority_auth_handler) {
        priority_auth_handler(ARM_UCCC_REQUEST_DOWNLOAD, candidate_info->priority);
    } else if (auth_handler) {
        auth_handler(ARM_UCCC_REQUEST_DOWNLOAD);
    } else {
        char curr_semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = { 0 };
        char new_semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = { 0 };
        fota_component_version_int_to_semver(curr_fw_version, curr_semver);
        fota_component_version_int_to_semver(candidate_info->version, new_semver);
        FOTA_APP_PRINT("---------------------------------------------------");
        FOTA_APP_PRINT(
            "Updating component %s from version %s to %s",
            candidate_info->component_name,
            curr_semver, new_semver
        );
        FOTA_APP_PRINT("Update priority %" PRIu32, candidate_info->priority);

        if (candidate_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
            FOTA_APP_PRINT(
                "Delta update. Patch size %zuB full image size %zuåB",
                candidate_info->payload_size,
                candidate_info->installed_size
            );
        } else if (candidate_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW) {
            FOTA_APP_PRINT("Update size %zuB (Encrypted image size %zuB)",
                candidate_info->installed_size,
                candidate_info->payload_size
            );
        } else {
            FOTA_APP_PRINT("Update size %zuB", candidate_info->payload_size);
        }
        FOTA_APP_PRINT("---------------------------------------------------");
        FOTA_APP_PRINT("Download authorization granted");
        fota_app_authorize();
        /* Application can reject an update in the following way
            fota_app_reject(127);
            Reason error code will be logged.
        Alternatively application can defer the update by calling
            fota_app_defer();
        Deferred update will be restarted on next boot or by calling fota_app_resume() API.

        */
    }
    return FOTA_STATUS_SUCCESS;
}

#endif  // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE) && defined(FOTA_SHIM_LAYER)
