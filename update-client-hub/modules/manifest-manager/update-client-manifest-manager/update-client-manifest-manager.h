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

/**
 * @file draft-api.h
 * @brief Manifest Manager API
 * @details This file specifies the API used to interact with the manifest manager
 * # Expected API call pattern
 * The update hub should call the API in the following way:
 * - The update hub initializes the manifest manager: `manifest_manager_init()`
 *     - TODO: The manifest manager checks internal consistency of the latest manifest.
 * - The udpate hub passes a manifest to the manifest manager: `manifest_manager_insert()`
 * - The manifest manager:
 *     - checks for validity of the manifest and exits with a failure if it is invalid.
 *         - validates the integrity of the manifest (hash)
 *         - validates the authenticity of the manifest (signature)
 *         - checks that the manifest applies to the local hardware
 *             - reports the Device, Vendor, and Device Class GUIDs to the update hub for validation.
 *     - searches for a matching dependency placeholder
 *     - if a match is found,
 *         - stores the manifest as a dependency
 *     - otherwise
 *        - TODO: Validates the timestamp.
 *          NOTE: Timestamp cannot be validated before this point since it is only validated on root manifests
 *        - stores the maninfest as a new root manifest
 *     - stores the firmware URI and hash (HACK: Also embeds the firmware size, inip vector and AES key in the hash)
 *     - stores a placeholder for each linked manifest
 *     - stores the manifest timestamp
 *     - The manifest manager searches for dependency placeholders
 *         - If there is a placeholder, report it to the hub and exit pending.
 *         - otherwise, report DONE to the hub.
 * - If the update hub receives a manifest request,
 *     - It obtains that manifest and calls `manifest_manager_insert()` starting this process again.
 * - If the update hub receives a DONE report,
 *     - It initiates a firmware request, using the `ARM_UC_mmFetchFirmwareInfo()` API
 *     - The manifest manager:
 *         - finds the most recent root manifest
 *         - searches for any firmware placeholders
 *         - reports the firmware to the hub
 * - Until the hub receives a DONE report, it
 *     - extracts the firmware information using `ARM_UC_mmGetFirmwareInfo()`
 *     - fetches the firmware image
 *     - installs the firmware image
 *     - starts the search for the next firmware, using `ARM_UC_mmFetchNextFirmwareInfo()`
 */
#include "update-client-manifest-manager-context.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"
#include "update-client-manifest-manager/arm-pal-kv.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const size_t arm_uc_mmDynamicContextSize;
/**
 * @brief Result codes for the application event handler
 * @details These result codes are passed to the event handler. They are used to indicate action required by the calling
 * application and status of the manifest manager.
 */
enum arm_uc_mmResultCode {
    ARM_UC_MM_RC_ERROR = 0, /**< status: The manifest manager failed during the previous operation. Extract further
                             *           error information using `ARM_UC_mmGetError()` */
    ARM_UC_MM_RC_NONE,      ///< action: No action necessary
    ARM_UC_MM_RC_NEED_DEP,  /**< action: The firmware manager needs the manifest specified by
                             *           `ARM_UC_mmGetCurrentManifestDependency()` in order to keep processing the
                             *           firmware update */
    ARM_UC_MM_RC_NEED_FW,   /**< action: The firmware manager needs the firmware specified by
                             *           `ARM_UC_mmGetFirmwareInfo()` in order to keep processing the firmware update */
    ARM_UC_MM_RC_DONE       ///< status: The last operation completed successfully
};


/**
 * @brief Initialize module and register event handler.
 * @details The event handler is shared among all asynchronous calls.
 *
 * Walks the most recent manifest tree for validity of the tree and presence of the associated images
 *
 * @param[in] ctxbuf Context object for the manifest manager
 * @param  callback Function pointer to event handler.
 * @param  api Pointer to API structure for the key/value storage
 * @return Error code.
 */
arm_uc_error_t ARM_UC_mmInit(arm_uc_mmContext_t** ctxbuf, void (*event_handler)(uint32_t), const arm_pal_key_value_api* api);

/**
 * @brief Insert manifest.
 * @details Validates and parses manifest.
 *          Event is generated when call is complete.
 *
 * @param[in]  buffer Struct containing pointer to byte array, maximum length,
 *               and actual length.
 * @param[out] ID Pointer to a manifest handle. This handle will be populated on success.
 * @return Error code, indicating parsing errors, validity of the manifest, etc. Error codes are TBD.
 */
arm_uc_error_t ARM_UC_mmInsert(arm_uc_mmContext_t** ctx, arm_uc_buffer_t* buffer, arm_uc_buffer_t* certificateStorage, arm_uc_manifest_handle_t* ID);

/**
 * @brief Get manifest firmware information
 * @details Fills the manifest_firmware_info_t struct with URL information.
 *
 * struct manifest_firmware {
 *     uint32_t        size;       ///< The size of the firmware in bytes
 *     arm_uc_buffer_t hash;       ///< The hash of the firmware image
 *     arm_uc_buffer_t uri;        ///< The location of the firmware
 *     arm_uc_buffer_t initVector; ///< AES initialization vector
 *     arm_uc_buffer_t keyID;      ///< Identifier for a locally stored AES key
 *     arm_uc_buffer_t key;        ///< An encrypted AES key
 *     manifest_guid_t format;     ///< The format used for the firmware. This is either an enum when the first 96 bits
 *                                 ///  are 0. Otherwise, this is a RFC4122 GUID. * /
 *     arm_uc_buffer_t  version;   ///< A text representation of the version number.
 * };
 *
 *
 * @param[in]  ID   Value identifying the manifest.
 * @param[out] info Struct containing the URL.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_mmFetchFirmwareInfo(arm_uc_mmContext_t** ctx, struct manifest_firmware_info_t* info, const arm_uc_manifest_handle_t* ID);

/**
 * @brief Starts extracting firmware information from a tree of manifests
 * @details `ARM_UC_mmFetchFirmwareInfo()` begins the process of extracting firmware information in the config store
 * This API should only be called once for a root manifest. It always completes asynchronously on success: a return of
 *`MFST_ERR_NONE` will be followed by a callback with `ARM_UC_MM_RC_DONE`. Errors may be returned synchronously or
 * asynchronously.
 *
 * The caller should wait for a callback via the function pointer provided in `manifest_manager_init()`. If the event
 * provided to the callback is `ARM_UC_MM_RC_NEED_FW`, then a new firmware info block is ready for access via
 * `ARM_UC_mmGetFirmwareInfo()`. If the event is `ARM_UC_MM_RC_DONE` then no more firmware info blocks are provided via
 * this root manifest.
 *
 * @param[in]  ID a handle for the manifest to search. TODO: The manifest manager currently just selects the latest root
 *                manifest.
 * @return     An error code on failure, MFST_ERR_NONE on success, or MFST_ERR_PENDING if the find has not completed.
 */
// arm_uc_error_t ARM_UC_mmFetchFirmwareInfo(arm_uc_manifest_handle_t* ID);

/**
 * @brief Continues extracting firmware information from a tree of manifests
 * @details `ARM_UC_mmFetchNextFirmwareInfo()` obtains the next firmware information block in a tree of manifests. It
 * always completes asynchronously on success: a return of `MFST_ERR_NONE` will be followed by a callback with
 * `ARM_UC_MM_RC_DONE`.
 *
 * The caller should wait for a callback via the function pointer provided in `manifest_manager_init()`. If the event
 * provided to the callback is `ARM_UC_MM_RC_NEED_FW`, then a new firmware info block is ready for access via
 * `ARM_UC_mmGetFirmwareInfo()`. If the event is `ARM_UC_MM_RC_DONE` then no more firmware info blocks are provided via
 * this root manifest.
 *
 * @return     An error code on failure, MFST_ERR_NONE on success, or MFST_ERR_PENDING if the find has not completed.
 */
arm_uc_error_t ARM_UC_mmFetchNextFirmwareInfo(struct manifest_firmware_info_t* info);

/**
 * @brief Extract the last error reported to a callback with `ARM_UC_MM_RC_ERROR`
 * @details Retrieves the internal error code stored in the manifest manager. When an error occurs in the manifest
 * manager, during an asynchronous operation, it is not possible to pass this information directly to the application,
 * so it is stored internally for later retrieval and an error event is queued for handling by the application event
 * handler.
 *
 * @return The stored error code.
 */
arm_uc_error_t ARM_UC_mmGetError(void);

/**
 * @brief Extracts the current dependency manifest information
 * @details When the manifest manager reports `ARM_UC_MM_RC_NEED_DEP` to the application event handler, it stores the
 * manifest dependency that induced that request. When the application event handler processes the request, it can
 * extract the manifest URI from the manifest manager using this function.
 *
 * @param[out] uri The buffer where the manifest URI should be stored.
 * @return     An error code on failure or MFST_ERR_NONE on success.
 */
arm_uc_error_t ARM_UC_mmGetCurrentManifestDependency(arm_uc_buffer_t* uri);

#if ARM_UC_MM_ENABLE_TEST_VECTORS
arm_uc_error_t ARM_UC_mmRegisterTestHook(ARM_UC_mmTestHook_t hook);
#endif

#ifdef __cplusplus
}
#endif
