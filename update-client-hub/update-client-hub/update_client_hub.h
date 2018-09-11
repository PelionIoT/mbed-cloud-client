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

#ifndef ARM_UPDATE_CLIENT_HUB_H
#define ARM_UPDATE_CLIENT_HUB_H

#include "update-client-common/arm_uc_common.h"
#include "update-client-source/arm_uc_source.h"
#include "update-client-monitor/arm_uc_monitor.h"
#include "update-client-control-center/arm_uc_control_center.h"
#include "update-client-paal/arm_uc_paal_update.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialization return codes.
 */
enum {
    ARM_UC_INIT_DONE
};

/**
 * @brief Start the initialization of the hub.
 * @details When initilisation finishes, the user callback function
 *          will be called. The "event" parameter to the callback
 *          is currently a placeholder that always returns ARM_UC_INIT_DONE.
 *
 * @param  function to be called when initilisation is finished.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_HUB_Initialize(void (*callback)(int32_t));

/**
 * @brief Process events in the event queue.
 * @details The update client is driven by events in an atomic queue,
 *          the user need to call this function periodically to process
 *          events in the queue and hence move the client forward.
 *
 * @return Error code.
 * @note Here's a code snippet to suggest how this API might be used by callers:
 * \code
 * int main() {
 *     retval = ARM_UC_Hub.Initialize(init_finish_cb);
 *     while(true) {
 *         ARM_UC_Hub.ProcessEvents();
 *         __WFI();
 *     }
 * }
 * \endcode
 */
arm_uc_error_t ARM_UC_HUB_ProcessEvents(void);

/**
 * @brief Register callback function for when callbacks are added to an
 *        empty queue.
 * @details This function is called at least once (maybe more) when
 *          callbacks are added to an empty queue. Useful for scheduling
 *          when the queue needs to be processed.
 * @param handler Function pointer to function to be called when elements are
 *        added to an empty queue.
 */
arm_uc_error_t ARM_UC_HUB_AddNotificationHandler(void (*handler)(void));

/**
 * @brief Add sources to the update client.
 * @details Sources are transport methods for manifest and firmwares.
 *
 * @param sources Pointer to an array of source pointers.
 * @param size Number of elements in the pointer array.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_HUB_SetSources(const ARM_UPDATE_SOURCE *sources[],
                                     uint8_t size);

/**
 * @brief Set implementation for storing firmware.
 * @details Storage abstraction for handling different storage medium.
 *
 * @param implementation Function pointer struct to Update PAL implementation.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_HUB_SetStorage(const ARM_UC_PAAL_UPDATE *implementation);

/**
 * @brief Add monitor to the update client.
 * @details Monitors send the update status and results.
 *
 * @param  monitor The monitor to be added to the update client.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_HUB_AddMonitor(const ARM_UPDATE_MONITOR *monitor);

/**
 * @brief Temporary error reporting function.
 * @details This function will be absorbed into the add monitor call.
 *
 * @param callback Error reporting function.
 */
void ARM_UC_HUB_AddErrorCallback(void (*callback)(int32_t error));

/**
 * @brief Authorize request.
 * @details Function is called when the user application authorizes
 *          requests from the Update Client.
 *
 * @param request Requests are passed through the callback function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_Authorize(arm_uc_request_t request);

/**
 * @brief Set callback for receiving download progress.
 * @details User application call for setting callback handler.
 *          The callback function takes the progreess in percent as argument.
 *
 * @param callback Function pointer to the progress function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetProgressHandler(void (*callback)(uint32_t progress, uint32_t total));

/**
 * @brief Set callback function for authorizing requests.
 * @details User application call for setting callback handler.
 *          The callback function takes an enum request and an authorization
 *          function pointer. To authorize the given request, the caller
 *          invokes the authorization function.
 *
 * @param callback Function pointer to the authorization function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetAuthorizeHandler(void (*callback)(int32_t));

/**
 * @brief Override update authorization handler.
 * @details Force download and update to progress regardless of authorization
 *          handler. This function is used for unblocking an update in a buggy
 *          application.
 */
void ARM_UC_OverrideAuthorization(void);

/**
 * @brief Add certificate.
 * @details [long description]
 *
 * @param certificate Pointer to certiface being added.
 * @param certificate_length Certificate length.
 * @param fingerprint Pointer to the fingerprint of the certificate being added.
 * @param fingerprint_length Fingerprint length.
 * @param callback Callback handler for certificate insertion events.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_AddCertificate(const uint8_t *certificate,
                                     uint16_t certificate_length,
                                     const uint8_t *fingerprint,
                                     uint16_t fingerprint_length,
                                     void (*callback)(arm_uc_error_t, const arm_uc_buffer_t *));

/**
 * @brief Set pointer to pre-shared-key with the given size.
 *
 * @param key Pointer to pre-shared-key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_AddPreSharedKey(const uint8_t *key, uint16_t bits);

/**
 * @brief Function for setting the vendor ID.
 * @details The ID is copied to a 16 byte struct. Any data after the first
 *          16 bytes will be ignored.
 * @param id Pointer to ID.
 * @param length Length of ID.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetVendorId(const uint8_t *id, uint8_t length);

/**
 * @brief Function for setting the class ID.
 * @details The ID is copied to a 16 byte struct. Any data after the first
 *          16 bytes will be ignored.
 * @param id Pointer to ID.
 * @param length Length of ID.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetClassId(const uint8_t *id, uint8_t length);

/**
 * @brief Function for setting the device ID.
 * @details The ID is copied to a 16 byte struct. Any data after the first
 *          16 bytes will be ignored.
 * @param id Pointer to ID.
 * @param length Length of ID.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetDeviceId(const uint8_t *id, uint8_t length);

/**
 * @brief Function for reporting the vendor ID.
 * @details 16 bytes are copied into the supplied buffer.
 * @param id Pointer to storage for ID. MUST be at least 16 bytes long.
 * @param id_max the size of the ID buffer
 * @param id_size pointer to a variable to receive the size of the ID
 *                written into the buffer (always 16).
 * @return Error code.
 */
arm_uc_error_t ARM_UC_GetVendorId(uint8_t *id,
                                  const size_t id_max,
                                  size_t *id_size);

/**
 * @brief Function for reporting the class ID.
 * @details 16 bytes are copied into the supplied buffer.
 * @param id Pointer to storage for ID. MUST be at least 16 bytes long.
 * @param id_max the size of the ID buffer
 * @param id_size pointer to a variable to receive the size of the ID
 *                written into the buffer (always 16).
 * @return Error code.
 */
arm_uc_error_t ARM_UC_GetClassId(uint8_t *id,
                                 const size_t id_max,
                                 size_t *id_size);

/**
 * @brief Function for reporting the device ID.
 * @details 16 bytes are copied into the supplied buffer.
 * @param id Pointer to storage for ID. MUST be at least 16 bytes long.
 * @param id_max the size of the ID buffer
 * @param id_size pointer to a variable to receive the size of the ID
 *                written into the buffer (always 16).
 * @return Error code.
 */
arm_uc_error_t ARM_UC_GetDeviceId(uint8_t *id,
                                  const size_t id_max,
                                  size_t *id_size);


/**
 * @brief Delete any global allocations.
 */
arm_uc_error_t ARM_UC_HUB_Uninitialize(void);

/**
 * @brief Return the details of the active firmware.
 * @param details Pointer to the firmware details structure.
 * @return ARM_UC_HUB_ERR_NOT_AVAILABLE if the active firmware details
 *         are not yet available, ERR_INVALID_PARAMETER if "details" is
 *         NULL or ERR_NONE for success.
 */
arm_uc_error_t ARM_UC_API_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details);

#ifdef __cplusplus
}
#endif

#endif /* ARM_UPDATE_CLIENT_HUB_H */
