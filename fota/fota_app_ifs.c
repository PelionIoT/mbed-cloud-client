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
#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota.h"
#include "fota/fota_source.h"
#include "fota/fota_internal.h"
#include "fota/fota_event_handler.h"
#include "fota/fota_component_defs.h"
#include "fota/fota_component.h"

#include <inttypes.h>

#if defined(TARGET_LIKE_LINUX)
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#endif // defined(TARGET_LIKE_LINUX)

void fota_app_authorize()
{
    fota_event_handler_defer_with_result(fota_on_authorize, FOTA_INSTALL_STATE_AUTHORIZE /*This parameter is relevant only to the FOTA install stage.*/);
}

void fota_app_reject(int32_t reason)
{
    fota_event_handler_defer_with_result(fota_on_reject, reason);
}

void fota_app_defer()
{
    fota_event_handler_defer_with_result(fota_on_defer, FOTA_INSTALL_STATE_DEFER /*This parameter is relevant only to the FOTA install stage.*/);
}

void fota_app_postpone_reboot()
{
     fota_event_handler_defer_with_result(fota_on_defer, FOTA_INSTALL_STATE_POSTPONE_REBOOT /*This parameter is relevant only to the FOTA install stage.*/);  
}

void fota_app_resume(void)
{
    fota_event_handler_defer_with_result_ignore_busy(fota_on_resume, FOTA_RESUME_REASON_USER_APP);
}

#if defined (FOTA_DEFAULT_APP_IFS) && FOTA_DEFAULT_APP_IFS==1
void fota_app_on_download_progress(size_t downloaded_size, size_t current_chunk_size, size_t total_size)
{
    FOTA_ASSERT(total_size);
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

    Note: The authorization call can be deferred and called later.
    This doesn't affect the performance of the Cloud Client.
*/
int fota_app_on_install_authorization(void)
{
    fota_app_authorize();
    FOTA_APP_PRINT("Install authorization granted");
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
            "Delta update. Patch size %zuB full image size %zuB",
            candidate_info->payload_size,
            candidate_info->installed_size
        );
    } else if (candidate_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || candidate_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
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
    return FOTA_STATUS_SUCCESS;
}
#endif // #if defined (FOTA_DEFAULT_APP_IFS) && FOTA_DEFAULT_APP_IFS==1

#if defined(TARGET_LIKE_LINUX)
#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)

int fota_app_install_main_app(const char *candidate_file_name)
{
    unsigned int file_mode = ALLPERMS;
    struct stat statbuf;

    FOTA_TRACE_INFO("Installing MAIN application");

    // get current file permissions
    if (stat(MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME, &statbuf) == 0) {
        file_mode = statbuf.st_mode & 0x1FF;
    }

    // unlink current file
    if (unlink(MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME) != 0) {
        FOTA_TRACE_ERROR("Failed to unlink file %s: %s", MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME, strerror(errno));
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // change file permission to same as previously
    chmod(candidate_file_name, file_mode);

    if (rename(candidate_file_name, MBED_CLOUD_CLIENT_FOTA_LINUX_CURR_FW_FILENAME) != 0) {
        FOTA_TRACE_ERROR("Failed to rename file %s: %s", candidate_file_name, strerror(errno));
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

#endif  // defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
#endif  // defined(TARGET_LIKE_LINUX)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
