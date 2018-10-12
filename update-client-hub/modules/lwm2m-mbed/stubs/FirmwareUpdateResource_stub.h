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

#ifndef __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__
#define __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__

#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2minterface.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobject.h"
namespace FirmwareUpdateResource {

// New enums based on http://www.openmobilealliance.org/tech/profiles/lwm2m/10252.xml
typedef enum {
    ARM_UCS_LWM2M_STATE_FIRST                      = 0,
    ARM_UCS_LWM2M_STATE_UNINITIALISED              = ARM_UCS_LWM2M_STATE_FIRST, //Uninitialised
    ARM_UCS_LWM2M_STATE_IDLE                       = 1, //Idle
    ARM_UCS_LWM2M_STATE_PROCESSING_MANIFEST        = 2, //Processing manifest
    ARM_UCS_LWM2M_STATE_AWAITING_DOWNLOAD_APPROVAL = 3, //Awaiting download approval
    ARM_UCS_LWM2M_STATE_DOWNLOADING                = 4, //Downloading
    ARM_UCS_LWM2M_STATE_DOWNLOADED                 = 5, //Downloaded
    ARM_UCS_LWM2M_STATE_AWAITING_APP_APPROVAL      = 6, //Awaiting application approval
    ARM_UCS_LWM2M_STATE_UPDATING                   = 7, //Updating
    ARM_UCS_LWM2M_STATE_REBOOTING                  = 8, //Rebooting
    ARM_UCS_LWM2M_STATE_LAST                       = ARM_UCS_LWM2M_STATE_REBOOTING
} arm_ucs_lwm2m_state_t;

typedef enum {
    ARM_UCS_LWM2M_RESULT_FIRST                        = 0,
    ARM_UCS_LWM2M_RESULT_INITIAL                      = ARM_UCS_LWM2M_RESULT_FIRST, // Uninitialised
    ARM_UCS_LWM2M_RESULT_SUCCESS                      = 1,  //Success
    ARM_UCS_LWM2M_RESULT_MANIFEST_TIMEOUT             = 2,  //Manifest timeout. The Manifest URI has timed-out.
    ARM_UCS_LWM2M_RESULT_MANIFEST_NOT_FOUND           = 3,  //Manifest not found. The Manifest URI not found.
    ARM_UCS_LWM2M_RESULT_MANIFEST_FAILED_INTEGRITY    = 4,  //Manifest failed integrity check. The manifest integrity check failed.
    ARM_UCS_LWM2M_RESULT_MANIFEST_REJECTED            = 5,  //Manifest rejected. The Manifest attributes do not apply to this device.
    ARM_UCS_LWM2M_RESULT_MANIFEST_CERT_NOT_FOUND      = 6,  //Manifest certificate not found
    ARM_UCS_LWM2M_RESULT_MANIFEST_SIGNATURE_FAILED    = 7,  //Manifest signature failed. The Manifest signature is not recognised by this device.
    ARM_UCS_LWM2M_RESULT_DEPENDENT_MANIFEST_NOT_FOUND = 8,  //Dependent manifest not found
    ARM_UCS_LWM2M_RESULT_ERROR_STORAGE                = 9,  //Not enough storage for the new asset
    ARM_UCS_LWM2M_RESULT_ERROR_MEMORY                 = 10, //Out of memory during download process
    ARM_UCS_LWM2M_RESULT_ERROR_CONNECTION             = 11, //Connection lost during download process
    ARM_UCS_LWM2M_RESULT_ERROR_CRC                    = 12, //Asset failed integrity check
    ARM_UCS_LWM2M_RESULT_ERROR_TYPE                   = 13, //Unsupported asset type
    ARM_UCS_LWM2M_RESULT_ERROR_URI                    = 14, //Invalid asset URI
    ARM_UCS_LWM2M_RESULT_ERROR_UPDATE                 = 15, //Timed out downloading asset
    ARM_UCS_LWM2M_RESULT_UNSUPPORTED_DELTA_FORMAT     = 16, //Unsupported delta format
    ARM_UCS_LWM2M_RESULT_ERROR_HASH                   = 17, //Unsupported encryption format
    ARM_UCS_LWM2M_RESULT_ASSET_UPDATE_COMPLETED       = 18, //Asset update successfully completed
    ARM_UCS_LWM2M_RESULT_ASSET_UPDATED_AFTER_RECOVERY = 19, //Asset updated successfully after recovery
    ARM_UCS_LWM2M_RESULT_LAST                         = ARM_UCS_LWM2M_RESULT_ASSET_UPDATED_AFTER_RECOVERY
} arm_ucs_lwm2m_result_t;

void Initialize(void);
void Uninitialize(void);

M2MObject *getObject(void);

/* Add callback for resource /10252/0/1, Package */
int32_t addPackageCallback(void (*cb)(const uint8_t *buffer, uint16_t length));

#if 0
/* Add callback for resource /5/0/1, Package URI */
int32_t addPackageURICallback(void (*cb)(const uint8_t *buffer, uint16_t length));

/* Add callback for resource /5/0/2, Update */
int32_t addUpdateCallback(void (*cb)(void));
#endif
/* Add callback for when send{State, UpdateResult} is done */
int32_t addNotificationCallback(void (*notification_handler)(void));

/* Send state for resource /10252/0/2, State */
int32_t sendState(arm_ucs_lwm2m_state_t state);

/* Send result for resource /10252/0/3, Update Result */
int32_t sendUpdateResult(arm_ucs_lwm2m_result_t result);

/* Send name for resource /10252/0/5, PkgName */
int32_t sendPkgName(const uint8_t *name, uint16_t length);

/* Send version for resource /10252/0/6, PkgVersion */
int32_t sendPkgVersion(uint64_t version);

void packageCallback(void *, void *);
void packageCallbackUninitialized(void *, void *);
static void updateCallback(void *, void *);
/* function pointers to callback functions */
/* M2MInterface */
extern void (*externalPackageCallback)(const uint8_t *buffer, uint16_t length);
static M2MInterface *_m2m_interface;

int32_t setM2MInterface(M2MInterface *interface);

M2MInterface *getM2MInterface(void);
extern bool initialized;

}

#endif // __ARM_UCS_FIRMWARE_UPDATE_RESOURCE_H__
