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

#ifndef ARM_UC_SOURCE_MANAGER_H
#define ARM_UC_SOURCE_MANAGER_H

#include "update-client-common/arm_uc_common.h"
#include "update-client-source/arm_uc_source.h"

typedef enum {
    ARM_UC_SM_EVENT_NOTIFICATION,
    ARM_UC_SM_EVENT_MANIFEST,
    ARM_UC_SM_EVENT_FIRMWARE,
    ARM_UC_SM_EVENT_KEYTABLE,
    ARM_UC_SM_EVENT_ERROR,
    ARM_UC_SM_EVENT_ERROR_SOURCE,
    ARM_UC_SM_EVENT_ERROR_BUFFER_SIZE,
} ARM_UC_SM_Event_t;

typedef struct _ARM_UC_SOURCE_MANAGER {

    /**
     * @brief Initialize module and register event handler.
     * @details The event handler is shared among all asynchronous calls.
     *
     * @param  callback Function pointer to event handler.
     * @return Error code.
     */
    arm_uc_error_t (*Initialize)(ARM_SOURCE_SignalEvent_t event_cb);
    arm_uc_error_t (*Uninitialize)(void);

    /**
     * @brief Add firmware source to manager.
     * @details Each source is represented as a pointer to a struct, containing
     *          function pointers.
     *
     *          For example:
     *          typedef struct _ARM_UPDATE_SOURCE {
     *              ARM_DRIVER_VERSION     (*GetVersion)     (void);
     *              ARM_SOURC_CAPABILITIES (*GetCapabilities)(void);
     *              int32_t                (*Initialize)     (ARM_SOURCE_SignalEvent_t event);
     *          } ARM_UPDATE_SOURCE;
     *
     * @param source Collection of function pointers to source.
     * @return Error code.
     */
    arm_uc_error_t (*AddSource)(const ARM_UPDATE_SOURCE *source);
    arm_uc_error_t (*RemoveSource)(const ARM_UPDATE_SOURCE *source);

    /**
     * @brief Copy manifest into provided buffer.
     * @details Default manifest location is used. An event is generated when the
     *          manifest has been received.
     *
     * @param buffer Struct holding a byte array, maximum size, and actual size.
     *
     * @return Error code.
     */
    arm_uc_error_t (*GetManifest)(arm_uc_buffer_t *buffer, uint32_t offset);

    /**
     * @brief Copy manifest into provided buffer.
     * @details Manifest location is provided. An event is generated when the
     *          manifest has been received.
     *
     * @param uri Struct containing the URI to the manifest.
     * @param buffer Struct holding a byte array, maximum size, and actual size.
     *
     * @return Error code.
     */
    arm_uc_error_t (*GetManifestFrom)(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer, uint32_t offset);

    /**
     * @brief Copy firmware fragment into provided buffer.
     * @details Firmware is downloaded one fragment at a time. Each call generates
     *          an event when the fragment has been received.
     *
     * @param uri Struct containing the URI to the manifest.
     * @param buffer Struct holding a byte array, maximum size, and actual size.
     * @param offset Firmware offset in bytes where the next fragment begins.
     * @return Error code.
     */
    arm_uc_error_t (*GetFirmwareFragment)(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer, uint32_t offset);

    /**
     * @brief Retrieve key table and write it into provided buffer.
     * @details An event is generated when the manifest has been received.
     *
     * @param uri Struct containing the URI to the keytable.
     * @param buffer Struct holding a byte array, maximum size, and actual size.
     * @return Error code.
     */
    arm_uc_error_t (*GetKeytable)(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer);

} ARM_UC_SOURCE_MANAGER_t;

extern ARM_UC_SOURCE_MANAGER_t ARM_UC_SourceManager;

extern arm_uc_error_t ARM_UCSM_GetError(void);
extern arm_uc_error_t ARM_UCSM_SetError(arm_uc_error_t an_error);


/**
 * Usage examples
 *
 * void callback(uint32_t event)
 * {
 *      switch (event)
 *      {
 *          // New manifest is available
 *          case ARM_UC_SM_EVENT_NOTIFICATION:
 *              break;
 *
 *          // Manifest received from default location
 *          case ARM_UC_SM_EVENT_MANIFEST:
 *              break;
 *
 *          // Manifest received from URL
 *          case ARM_UC_SM_EVENT_FIRMWARE:
 *              break;
 *
 *          // Firmware fragment received
 *          case ARM_UC_SM_EVENT_KEYTABLE:
 *              break;
 *      }
 * }
 *
 * void main(int)
 * {
 *      // initialize Source Manager with callback handler
 *      ARM_UC_SourceManager.Initialise(callback);
 * }
 *
 */

#endif /* SOURCE_MANAGER_H */
