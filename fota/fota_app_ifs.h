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

#ifndef __FOTA_APP_IFS_H_
#define __FOTA_APP_IFS_H_

#include "fota/fota_config.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_status.h"
#include "fota/fota_header_info.h"
#include "fota/fota_manifest.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file fota_app_ifs.h
 *  \brief Callbacks the device application can use to manage the firmware update flow.
 *         If your application does not require an implementation of any special logic, FOTA provides a default implementation for the update callbacks.
 *         To enable the default implementation, inject the ::FOTA_DEFAULT_APP_IFS define into the application build.
 */

/**
 * FOTA download authorization callback to be implemented by the device application.
 *
 * The application must implement this callback if you want the application to authorize the FOTA client to start downloading the candidate image.
 * The client invokes this callback for the first time when the device receives the update manifest from Device Management.
 *
 * FOTA expects the callback implementation to call one of these APIs:
 *   - ::fota_app_authorize() - Authorize request to download image. The download phase will proceed.
 *   - ::fota_app_reject() - Reject request to download image and discard the manifest. The client will not re-prompt the update.
 *   - ::fota_app_defer() - Defer image download to a later phase. This aborts the current image download attempt, while preserving the update manifest.
 *                          Image download continues on the next boot after device registration or when the device application calls the :fota_app_resume() API.
 *                          The client invokes ::fota_app_on_download_authorization when the update flow continues.
 *                          Both ::fota_app_defer() and ::fota_app_resume() APIs are implemented only if the ::MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT build flag is not equal to ::FOTA_RESUME_UNSUPPORTED.
 *
 * \note Only required if the ::MBED_CLOUD_CLIENT_FOTA_ENABLE build flag is specified.
 * \note Only required if the ::FOTA_DEFAULT_APP_IFS build flag is disabled.
 * \note The firmware versions in this callback are in internal library format and should be converted to strings using ::fota_component_version_int_to_semver() before use.
 *
 * \param[in] candidate_info Candidate image descriptor.
 * \param[in] curr_fw_version Firmware version of the component currently on the device.
 *
 * \return ::FOTA_STATUS_SUCCESS to acknowledge that the application received the authorization callback properly.
 */
int fota_app_on_download_authorization(
    const manifest_firmware_info_t *candidate_info,
    fota_component_version_t curr_fw_version
);


/**
 * Pelion FOTA install authorization callback to be implemented by the device application.
 *
 * Should be implemented by the application if it wants to authorize FOTA to install the update.
 * The client invokes this callback for the first time when the device fully downloads the update candidate image.
 *
 * FOTA client expects the callback implementation to call one of these APIs:
 *   - ::fota_app_authorize() - Authorize FOTA to install the candidate image. Reboot or connectivity loss may occur during installation.
 *                              This phase is critical because power loss can brick the device.
 *   - ::fota_app_reject() - Reject request to install, and discard the update.  The update will not be re-prompted.
 *   - ::fota_app_defer() - Defer the installation to a later phase. This marks the candidate image as valid, but the device will not reboot.
 *                          For the main component, the installation proceeds automatically after the device reboots.
 *                          For user components, the update flow proceeds on the next boot after device registration or when the device application calls the ::fota_app_resume() API.
 *                          The application invokes the ::fota_app_on_download_authorization and ::fota_app_on_install_authorization() callbacks when the update flow proceeds.
 *                          The client implements the ::fota_app_defer() and ::fota_app_resume() APIs only if the ::MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT build flag is not equal to ::FOTA_RESUME_UNSUPPORTED.
 *
 * \note Only required if the ::MBED_CLOUD_CLIENT_FOTA_ENABLE build flag is specified.
 * \note Only required if the ::FOTA_DEFAULT_APP_IFS build flag is disabled.
 *
 * \return ::FOTA_STATUS_SUCCESS to acknowledge that the application received the authorization callback properly.
 */
int fota_app_on_install_authorization(void);

/**
 * Pelion FOTA complete callback to be implemented by the device application.
 *
 * Should be implemented by the application if it wants to receive a notification that the update process is done/terminated.
 * The update result can be determined based on the status argument.
 *
 * \note Only required if the ::MBED_CLOUD_CLIENT_FOTA_ENABLE build flag is specified.
 * \note Only required if the ::FOTA_DEFAULT_APP_IFS build flag is disabled.
 * \note This callback will not be called if the device reboots as part of update installation.
 *
 * \param[in] status Pelion FOTA status code. ::FOTA_STATUS_SUCCESS if the update is deployed successfully.
 *
 * \return ::FOTA_STATUS_SUCCESS to acknowledge that the application received authorization callback properly.
 */
int fota_app_on_complete(int32_t status);

/**
 * Resume Pelion FOTA update.
 *
 * If the update process is interrupted, the application can call this function to resume the process.
 * This API invokes ::fota_app_on_download_authorization() CB.
 *
 * \note The function is implemented only if ::MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT build flag is not equal to ::FOTA_RESUME_UNSUPPORTED.
 * \note If ::MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT build flag is equal to ::FOTA_RESUME_SUPPORT_RESTART, the update flow will restart from the beginning.
 * \note If ::MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT build flag is equal to ::FOTA_RESUME_SUPPORT_RESUME, the update flow will resume from the point that it was interrupted.
 *
 */
void fota_app_resume(void);

/**
 * Authorize Pelion FOTA client to proceed with an update.
 *
 * FOTA client expects the ::fota_app_on_download_authorization() and ::fota_app_on_install_authorization() application callbacks to call this API.
 *
 */
void fota_app_authorize(void);

/**
 * Reject Pelion FOTA update.
 *
 * ::fota_app_on_download_authorization() and ::fota_app_on_install_authorization() application callbacks may call this API.
 *
 * \param[in] reason Reject reason code.
 */
void fota_app_reject(int32_t reason);

/**
 * Defer Pelion FOTA update.
 *
 * The FOTA client releases resources and reattempts the update on the next boot after device registration or when the device application calls
 * the ::fota_app_resume() API.
 * ::fota_app_on_download_authorization() and ::fota_app_on_install_authorization() application callbacks may call this API.
 *
 * \note The function is implemented only if ::MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT build flag is not equal to ::FOTA_RESUME_UNSUPPORTED.
 */
void fota_app_defer(void);


/**
 * Progress bar support for Pelion FOTA update.
 *
 * The application should implement this API.(Optional)
 * FOTA client calls this API when the download progresses by 5% percent (approximately).
 *
 * \param[in] downloaded_size Number of bytes already downloaded to the device.
 * \param[in] current_chunk_size Size, in bytes, of the currently downloaded chunk.
 * \param[in] total_size Total image size in bytes.
 */
void fota_app_on_download_progress(size_t downloaded_size, size_t current_chunk_size, size_t total_size);

/**
 * FOTA callback for verifying installation of the main application, to be implemented by the application.
 *
 * Should be implemented by the application if it has custom logic to verify installation of the main application.
 * If custom logic is not required, FOTA uses the default implementation.
 *
 * The ::expected_header_info field includes the whole candidate header, including the vendor_data field, which can
 * store vendor-specific data to help verify installation of the main app (for example, a vendor-specific application hash).
 *
 * \note Only required if the ::MBED_CLOUD_CLIENT_FOTA_ENABLE build flag is specified.
 * \note Only required if the ::FOTA_CUSTOM_MAIN_APP_VERIFY_INSTALL is set to 1.
 *
 * \param[in] expected_header_info Expected candidate header information that the client can use to verify the newly installed app.
 *
 * \return ::FOTA_STATUS_SUCCESS to acknowledge that the verification succeeded.
 */
int fota_app_on_main_app_verify_install(const fota_header_info_t *expected_header_info);


#if defined(TARGET_LIKE_LINUX)

/**
 * Pelion FOTA install callback to be implemented by application.
 *
 * FOTA client expects the callback to install the candidate and return ::FOTA_STATUS_SUCCESS or reboot the system.
 *
 * \param[in] candidate_fs_name Candidate image file name.
 * \param[in] firmware_info Parsed update manifest.
 *
 * \return ::FOTA_STATUS_SUCCESS for successful installation; otherwise, return an error code.
 */

int fota_app_on_install_candidate(const char *candidate_fs_name, const manifest_firmware_info_t *firmware_info);

#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)

/**
 * Install main application by overwriting current executable file.
 *
 * This function overwrites the executable file and relaunches the process.
 * The client expects the ::fota_app_on_install_candidate() application
 * callback to call this API.
 * It is only available if there is a single main file.
 *
 * \note This function does not validate candidate file integrity or authenticity.
 *
 * \param[in] candidate_file_name Candidate image file name as found in the file system.
 *
 * \return ::FOTA_STATUS_SUCCESS for successful installation of the main application.
 */
int fota_app_install_main_app(const char *candidate_file_name);

#endif // defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)

#endif // defined(TARGET_LIKE_LINUX)

#ifdef __cplusplus
}
#endif

#endif  // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_APP_IFS_H_
