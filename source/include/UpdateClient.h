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

#ifndef MBED_CLOUD_CLIENT_UPDATE_CLIENT_H
#define MBED_CLOUD_CLIENT_UPDATE_CLIENT_H

/** \internal \file UpdateClient.h */

#include "mbed-client/m2minterface.h"
#include "update-client-hub/update_client_public.h"
#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#include "fota/fota_shim_layer.h"
#endif
#include "eventOS_scheduler.h"
#include "eventOS_event.h"

#include <stdint.h>
#include <stddef.h>

class ServiceClient;

namespace UpdateClient
{
    /**
     * Error codes used by the Update Client.
     *
     * Warning: a recoverable error occured, no user action required.
     * Error  : a recoverable error occured, action required. E.g. the
     *          application has to free some space and let the Update
     *          Service try again.
     * Fatal  : a non-recoverable error occured, application should safe
     *          ongoing work and reboot the device.
     */
    enum {
        WarningBase                     = 0x0400, // Range reserved for Update Error from 0x0400 - 0x04FF
        WarningCertificateNotFound      = WarningBase + ARM_UC_WARNING_CERTIFICATE_NOT_FOUND,
        WarningIdentityNotFound         = WarningBase + ARM_UC_WARNING_IDENTITY_NOT_FOUND,
        WarningVendorMismatch           = WarningBase + ARM_UC_WARNING_VENDOR_MISMATCH,
        WarningClassMismatch            = WarningBase + ARM_UC_WARNING_CLASS_MISMATCH,
        WarningDeviceMismatch           = WarningBase + ARM_UC_WARNING_DEVICE_MISMATCH,
        WarningCertificateInvalid       = WarningBase + ARM_UC_WARNING_CERTIFICATE_INVALID,
        WarningSignatureInvalid         = WarningBase + ARM_UC_WARNING_SIGNATURE_INVALID,
        WarningBadKeytable              = WarningBase + ARM_UC_WARNING_BAD_KEYTABLE,
        WarningURINotFound              = WarningBase + ARM_UC_WARNING_URI_NOT_FOUND,
        WarningRollbackProtection       = WarningBase + ARM_UC_WARNING_ROLLBACK_PROTECTION,
        WarningAuthorizationRejected    = WarningBase + ARM_UC_WARNING_AUTHORIZATION_REJECTED,
        WarningAuthorizationUnavailable = WarningBase + ARM_UC_WARNING_AUTHORIZATION_UNAVAILABLE,
        WarningUnknown                  = WarningBase + ARM_UC_WARNING_UNKNOWN,
        WarningCertificateInsertion,
        ErrorBase,
        ErrorWriteToStorage             = ErrorBase + ARM_UC_ERROR_WRITE_TO_STORAGE,
        ErrorInvalidHash                = ErrorBase + ARM_UC_ERROR_INVALID_HASH,
        ErrorConnection                 = ErrorBase + ARM_UC_ERROR_CONNECTION,
        FatalBase
    };

    enum {
        RequestInvalid                  = ARM_UCCC_REQUEST_INVALID,
        RequestDownload                 = ARM_UCCC_REQUEST_DOWNLOAD,
        RequestInstall                  = ARM_UCCC_REQUEST_INSTALL
    };

    enum {
      RejectReasonUnauthorized          = ARM_UCCC_REJECT_REASON_UNAUTHORIZED,
      RejectReasonUnavailable           = ARM_UCCC_REJECT_REASON_UNAVAILABLE
    };

    enum UpdateClientEventType {
        UPDATE_CLIENT_EVENT_CREATE,
        UPDATE_CLIENT_EVENT_INITIALIZE,
        UPDATE_CLIENT_EVENT_PROCESS_QUEUE
    };

    /**
     * \brief Initialization function for the Update Client.
     * \param Callback to error handler.
     */
    void UpdateClient(FP1<void, int32_t> callback, M2MInterface *m2mInterface, ServiceClient *service, const int8_t tasklet_id);
    /**
     * \brief Populate M2MObjectList with Update Client objects.
     * \details The function takes an existing object list and adds LWM2M
     *          objects needed by the Update Client.
     *
     * \param list M2MObjectList reference.
     */
    void populate_object_list(M2MBaseList& list);

    /**
     * \brief Registers a callback function for authorizing firmware downloads and reboots.
     * \param handler Callback function.
     */
    void set_update_authorize_handler(void (*handler)(int32_t request)) __attribute__((deprecated("Use set_update_authorize_priority_handler instead")));

    /**
     * \brief Registers a callback function for authorizing update requests with priority.
     * \param handler Callback function.
     */
    void set_update_authorize_priority_handler(void (*handler)(int32_t request, uint64_t priority));

    /**
     * \brief Authorize request passed to authorization handler.
     * \param request Request being authorized.
     */
    void update_authorize(int32_t request);

    /**
     * \brief Reject request passed to authorization handler.
     * \param request Request being rejected.
     * \param reason Reason for rejecting the request.
     */
    void update_reject(int32_t request, int32_t reason);

    /**
     * \brief Registers a callback function for monitoring download progress.
     * \param handler Callback function.
     */
    void set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total));

    /**
     * \brief Fills the buffer with the 16-byte vendor UUID
     * \param buffer The buffer to fill with the UUID
     * \param buffer_size_max The maximum avaliable space in the buffer
     * \param value_size A pointer to a length variable to populate with the length of the UUID (always 16)
     * \retval CCS_STATUS_MEMORY_ERROR when the buffer is less than 16 bytes
     * \retval CCS_STATUS_KEY_DOESNT_EXIST when no vendor ID is present
     * \retval CCS_STATUS_SUCCESS on success
     */
    int getVendorId(uint8_t* buffer, size_t buffer_size_max, size_t* value_size);
    /**
     * \brief Fills the buffer with the 16-byte device class UUID
     * \param buffer The buffer to fill with the UUID
     * \param buffer_size_max The maximum avaliable space in the buffer
     * \param value_size A pointer to a length variable to populate with the length of the UUID (always 16)
     * \retval CCS_STATUS_MEMORY_ERROR when the buffer is less than 16 bytes
     * \retval CCS_STATUS_KEY_DOESNT_EXIST when no device class ID is present
     * \retval CCS_STATUS_SUCCESS on success
     */
    int getClassId(uint8_t* buffer, size_t buffer_size_max, size_t* value_size);

    void event_handler(arm_event_s* event);
}

#endif // MBED_CLOUD_CLIENT_UPDATE_CLIENT_H
