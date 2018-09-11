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

#include "update-client-hub/update_client_hub.h"

#include "update-client-common/arm_uc_common.h"
#include "update-client-control-center/arm_uc_control_center.h"
#include "update-client-control-center/arm_uc_pre_shared_key.h"
#include "update-client-control-center/arm_uc_certificate.h"
#include "update-client-source-manager/arm_uc_source_manager.h"
#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-manifest-manager/update-client-manifest-manager.h"

#include "update_client_hub_state_machine.h"
#include "update_client_hub_event_handlers.h"
#include "update_client_hub_error_handler.h"

#include "pal4life-device-identity/pal_device_identity.h"

#define HANDLE_INIT_ERROR(retval, msg, ...)\
    if (retval.error != ERR_NONE)\
    {\
        ARM_UC_HUB_setState(ARM_UC_HUB_STATE_UNINITIALIZED);\
        UC_HUB_ERR_MSG(msg " error code %s", ##__VA_ARGS__, ARM_UC_err2Str(retval));\
        return retval;\
    }

static const ARM_UPDATE_SOURCE **arm_uc_sources = NULL;
static uint8_t arm_uc_sources_size = 0;
extern arm_uc_mmContext_t *pManifestManagerContext;

/**
 * @brief Handle any errors posted by the scheduler.
 * @details This explicitly runs *not* in interrupt context, the scheduler has a dedicated
 *            callback structure to ensure it can post at least this event.
 *          ARM_UC_HUB_ErrorHandler() will invoke the HUB callback that was set up.
 *          It is up to the external application to go about inducing a reset etc,
 *            if that is what it decides. Note that the HUB is no longer operable
 *            and the app should probably Uninitialize it and report an error.
 *            However, the HUB will attempt some cleanup after it returns.
 * @param an_event the type of the event causing the error callback.
 *        The only possible errors from the scheduler are currently:
 *            ARM_UC_EQ_ERR_POOL_EXHAUSTED
 *            ARM_UC_EQ_ERR_FAILED_TAKE
 *        These are passed on to the Hub error handler as an internal error,
 *          and the hub state is now considered unknown from this perspective.
 *          (An internal error is considered fatal by the hub.)
 */
void UC_HUB_scheduler_error_handler(uint32_t an_event)
{
    UC_HUB_ERR_MSG("scheduler error: %" PRIu32, an_event);
    ARM_UC_HUB_ErrorHandler(HUB_ERR_INTERNAL_ERROR, ARM_UC_HUB_getState());
}

/**
 * @brief Call initialiser of all components of the client.
 *        finish asynchronously, will invoke callback when initialization is done.
 * @param init_cb the callback to be invoked at the end of initialization.
 */
arm_uc_error_t ARM_UC_HUB_Initialize(void (*init_cb)(int32_t))
{
    arm_uc_error_t retval;

    if (ARM_UC_HUB_getState() != ARM_UC_HUB_STATE_UNINITIALIZED) {
        UC_HUB_ERR_MSG("Already Initialized/Initializing");
        return (arm_uc_error_t) { ERR_INVALID_STATE };
    }
    ARM_UC_HUB_setState(ARM_UC_HUB_STATE_INITIALIZING);

    ARM_UC_SchedulerInit();
    ARM_UC_HUB_setInitializationCallback(init_cb);
    ARM_UC_SetSchedulerErrorHandler(UC_HUB_scheduler_error_handler);

    /* Register event handler with Control Center. */
    retval = ARM_UC_ControlCenter_Initialize(ARM_UC_HUB_ControlCenterEventHandler);
    HANDLE_INIT_ERROR(retval, "Control Center init failed")

    /* Register event handler with Firmware Manager */
    retval = ARM_UC_FirmwareManager.Initialize(ARM_UC_HUB_FirmwareManagerEventHandler);
    HANDLE_INIT_ERROR(retval, "Firmware Manager init failed")

    /* Register event handler with Source Manager */
    retval = ARM_UC_SourceManager.Initialize(ARM_UC_HUB_SourceManagerEventHandler);
    HANDLE_INIT_ERROR(retval, "Source Manager init failed")

    for (uint8_t index = 0; index < arm_uc_sources_size; index++) {
        ARM_UC_SourceManager.AddSource(arm_uc_sources[index]);
    }

    /* Register event handler and add config store implementation to manifest
       manager.
    */
    retval = ARM_UC_mmInit(&pManifestManagerContext,
                           ARM_UC_HUB_ManifestManagerEventHandler,
                           NULL);
    HANDLE_INIT_ERROR(retval, "Manifest manager init failed")

    /* add hard coded certificates to the manifest manager */
    // retval = ARM_UC_mmStoreCertificate(CA_PATH, cert, CERT_SIZE);
    // if ((retval.error != ERR_NONE) && (retval.code != MFST_ERR_PENDING))
    // {
    //     HANDLE_INIT_ERROR(retval, "Manifest manager StoreCertificate failed")
    // }

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Process events in the event queue.
 */
arm_uc_error_t ARM_UC_HUB_ProcessEvents()
{
    ARM_UC_ProcessQueue();

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Register callback function for when callbacks are added to an empty queue.
 */
arm_uc_error_t ARM_UC_HUB_AddNotificationHandler(void (*handler)(void))
{
    ARM_UC_AddNotificationHandler(handler);

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * @brief Add source to the Update Client.
 */
arm_uc_error_t ARM_UC_HUB_SetSources(const ARM_UPDATE_SOURCE *sources[],
                                     uint8_t size)
{
    arm_uc_sources = sources;
    arm_uc_sources_size = size;

    return (arm_uc_error_t) { ERR_NONE };
}

/**
 * Set PAAL Update implementation
 */
arm_uc_error_t ARM_UC_HUB_SetStorage(const ARM_UC_PAAL_UPDATE *implementation)
{
    return ARM_UCP_SetPAALUpdate(implementation);
}

/**
 * @brief Add monitor to the control center.
 */
arm_uc_error_t ARM_UC_HUB_AddMonitor(const ARM_UPDATE_MONITOR *monitor)
{
    return ARM_UC_ControlCenter_AddMonitor(monitor);
}

/**
 * @brief Temporary error reporting function.
 */
void ARM_UC_HUB_AddErrorCallback(void (*callback)(int32_t error))
{
    ARM_UC_HUB_AddErrorCallbackInternal(callback);
}

/**
 * @brief Authorize request.
 */
arm_uc_error_t ARM_UC_Authorize(arm_uc_request_t request)
{
    return ARM_UC_ControlCenter_Authorize(request);
}

/**
 * @brief Set callback for receiving download progress.
 * @details User application call for setting callback handler.
 *          The callback function takes the progreess in percent as argument.
 *
 * @param callback Function pointer to the progress function.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetProgressHandler(void (*callback)(uint32_t progress, uint32_t total))
{
    return ARM_UC_ControlCenter_SetProgressHandler(callback);
}

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
arm_uc_error_t ARM_UC_SetAuthorizeHandler(void (*callback)(int32_t))
{
    return ARM_UC_ControlCenter_SetAuthorityHandler(callback);
}

/**
 * @brief Override update authorization handler.
 * @details Force download and update to progress regardless of authorization
 *          handler. This function is used for unblocking an update in a buggy
 *          application.
 */
void ARM_UC_OverrideAuthorization(void)
{
    ARM_UC_ControlCenter_OverrideAuthorization();
}

#if defined(ARM_UC_FEATURE_MANIFEST_PUBKEY) && (ARM_UC_FEATURE_MANIFEST_PUBKEY == 1)
/**
 * @brief Add certificate.
 * @details [long description]
 *
 * @param certificate Pointer to certiface being added.
 * @param certificate_length Certificate length.
 * @param fingerprint Pointer to the fingerprint of the certificate being added.
 * @param fingerprint_length Fingerprint length.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_AddCertificate(const uint8_t *certificate,
                                     uint16_t certificate_length,
                                     const uint8_t *fingerprint,
                                     uint16_t fingerprint_length,
                                     void (*callback)(arm_uc_error_t, const arm_uc_buffer_t *))
{
    return ARM_UC_Certificate_Add(certificate,
                                  certificate_length,
                                  fingerprint,
                                  fingerprint_length,
                                  callback);
}
#endif /* ARM_UC_FEATURE_MANIFEST_PUBKEY */

#if defined(ARM_UC_FEATURE_MANIFEST_PSK) && (ARM_UC_FEATURE_MANIFEST_PSK == 1)
/**
 * @brief Set pointer to pre-shared-key with the given size.
 *
 * @param key Pointer to pre-shared-key.
 * @param bits Key size in bits.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UC_AddPreSharedKey(const uint8_t *key, uint16_t bits)
{
    return ARM_UC_PreSharedKey_SetSecret(key, bits);
}
#endif

/**
 * @brief Function for setting the vendor ID.
 * @details The ID is copied to a 16 byte struct. Any data after the first
 *          16 bytes will be ignored.
 * @param id Pointer to ID.
 * @param length Length of ID.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetVendorId(const uint8_t *id, uint8_t length)
{
    arm_uc_guid_t uuid = { 0 };

    if (id) {
        for (uint8_t index = 0;
                (index < sizeof(arm_uc_guid_t) && (index < length));
                index++) {
            ((uint8_t *) uuid)[index] = id[index];
        }
    }

    return pal_setVendorGuid(&uuid);
}

/**
 * @brief Function for setting the class ID.
 * @details The ID is copied to a 16 byte struct. Any data after the first
 *          16 bytes will be ignored.
 * @param id Pointer to ID.
 * @param length Length of ID.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetClassId(const uint8_t *id, uint8_t length)
{
    arm_uc_guid_t uuid = { 0 };

    if (id) {
        for (uint8_t index = 0;
                (index < sizeof(arm_uc_guid_t) && (index < length));
                index++) {
            ((uint8_t *) uuid)[index] = id[index];
        }
    }

    return pal_setClassGuid(&uuid);
}

/**
 * @brief Function for setting the device ID.
 * @details The ID is copied to a 16 byte struct. Any data after the first
 *          16 bytes will be ignored.
 * @param id Pointer to ID.
 * @param length Length of ID.
 * @return Error code.
 */
arm_uc_error_t ARM_UC_SetDeviceId(const uint8_t *id, uint8_t length)
{
    arm_uc_guid_t uuid = { 0 };

    if (id) {
        for (uint8_t index = 0;
                (index < sizeof(arm_uc_guid_t) && (index < length));
                index++) {
            ((uint8_t *) uuid)[index] = id[index];
        }
    }

    return pal_setDeviceGuid(&uuid);
}

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
                                  size_t *id_size)
{
    arm_uc_guid_t guid = {0};
    arm_uc_error_t err = {ERR_NONE};
    if (id_max < sizeof(arm_uc_guid_t)) {
        err.code = ARM_UC_DI_ERR_SIZE;
    }
    if (err.error == ERR_NONE) {
        err = pal_getVendorGuid(&guid);
    }
    if (err.error == ERR_NONE) {
        memcpy(id, guid, sizeof(arm_uc_guid_t));
        if (id_size != NULL) {
            *id_size = sizeof(arm_uc_guid_t);
        }
    }
    return err;
}

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
                                 size_t *id_size)
{
    arm_uc_guid_t guid = {0};
    arm_uc_error_t err = {ERR_NONE};
    if (id_max < sizeof(arm_uc_guid_t)) {
        err.code = ARM_UC_DI_ERR_SIZE;
    }
    if (err.error == ERR_NONE) {
        err = pal_getClassGuid(&guid);
    }
    if (err.error == ERR_NONE) {
        memcpy(id, guid, sizeof(arm_uc_guid_t));
        if (id_size != NULL) {
            *id_size = sizeof(arm_uc_guid_t);
        }
    }
    return err;
}

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
                                  size_t *id_size)
{
    arm_uc_guid_t guid = {0};
    arm_uc_error_t err = {ERR_NONE};
    if (id_max < sizeof(arm_uc_guid_t)) {
        err.code = ARM_UC_DI_ERR_SIZE;
    }
    if (err.error == ERR_NONE) {
        err = pal_getDeviceGuid(&guid);
    }
    if (err.error == ERR_NONE) {
        memcpy(id, guid, sizeof(arm_uc_guid_t));
        if (id_size != NULL) {
            *id_size = sizeof(arm_uc_guid_t);
        }
    }
    return err;
}

arm_uc_error_t ARM_UC_HUB_Uninitialize(void)
{
    if (ARM_UC_HUB_getState() <= ARM_UC_HUB_STATE_INITIALIZED) {
        UC_HUB_ERR_MSG("Update Client not initialized");
        return (arm_uc_error_t) { ERR_INVALID_STATE };
    }

    arm_uc_error_t err = ARM_UC_SourceManager.Uninitialize();
    ARM_UC_HUB_setState(ARM_UC_HUB_STATE_UNINITIALIZED);
    return err;
}

/**
 * @brief Return the details of the active firmware.
 * @param details Pointer to the firmware details structure.
 * @return ARM_UC_HUB_ERR_NOT_AVAILABLE if the active firmware details
 *         are not yet available, ERR_INVALID_PARAMETER if "details" is
 *         NULL or ERR_NONE for success.
 */
arm_uc_error_t ARM_UC_API_GetActiveFirmwareDetails(arm_uc_firmware_details_t *details)
{
    arm_uc_error_t err = {ARM_UC_HUB_ERR_NOT_AVAILABLE};

    if (details == NULL) {
        err.code = ERR_INVALID_PARAMETER;
    } else {
        arm_uc_firmware_details_t *hub_details = ARM_UC_HUB_getActiveFirmwareDetails();
        if (hub_details) {
            memcpy(details, hub_details, sizeof(arm_uc_firmware_details_t));
            err.code = ERR_NONE;
        }
    }
    return err;
}
