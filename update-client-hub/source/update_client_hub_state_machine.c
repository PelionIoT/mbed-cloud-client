// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#if defined(ARM_UC_ENABLE) && (ARM_UC_ENABLE == 1)

// This is needed for PRIu64 on FreeRTOS. Note: the relative location is
// important, do not move this to "correct" location, ie. after local includes.
#include <stdio.h>

#include "update_client_hub_state_machine.h"
#include "update_client_hub_error_handler.h"
#include "update-client-hub/update_client_hub.h"

#include "update-client-common/arm_uc_common.h"
#include "update-client-common/arm_uc_hw_plat.h"
#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-manifest-manager/update-client-manifest-manager.h"
#include "update-client-source-manager/arm_uc_source_manager.h"
#include "update-client-control-center/arm_uc_control_center.h"
#include "update-client-control-center/arm_uc_pre_shared_key.h"
#include "eventOS_event_timer.h"
#include "mbedtls/aes.h"

#include <inttypes.h>

// Rootless update, stage 1: manifest must be written to a file. Include the
// header of the WriteManifest API
#if defined(ARM_UC_FEATURE_ROOTLESS_STAGE_1) && (ARM_UC_FEATURE_ROOTLESS_STAGE_1 == 1)
#include "update-client-pal-linux/arm_uc_pal_linux_ext.h"
#endif // ARM_UC_FEATURE_ROOTLESS_STAGE_1

#if defined (MBED_HEAP_STATS_ENABLED) || defined (MBED_STACK_STATS_ENABLED)
#include "mbed_stats.h"
#endif

/*****************************************************************************/
/* Global variables                                                          */
/*****************************************************************************/

// state of the hub state machine
static arm_uc_hub_state_t arm_uc_hub_state = ARM_UC_HUB_STATE_UNINITIALIZED;

// the call back function registered by the user to signal end of initialisation
static void (*arm_uc_hub_init_cb)(uintptr_t) = NULL;

static void arm_uc_get_next_fragment();

// The hub uses a double buffer system to speed up firmware download and storage
#define BUFFER_SIZE_MAX (ARM_UC_BUFFER_SIZE / 2) //  define size of the double buffers
#define BUFFER_SIZE_WORD ((BUFFER_SIZE_MAX + 3) / 4) // round up to 4 byte word
static uint32_t message[BUFFER_SIZE_WORD]; // use 32-bit array to ensure word alignment in RAM
// Keep the same initalization values for front_buffer in ARM_UC_HUB_setState function in `case ARM_UC_HUB_STATE_IDLE`, where front_buffer initialzed again.
static arm_uc_buffer_t front_buffer = {
    .size_max = BUFFER_SIZE_MAX,
    .size = 0,
    .ptr = (uint8_t*) message
};

union {
    manifest_firmware_info_t fwinfo;
    uint32_t data[BUFFER_SIZE_WORD]; // use 32-bit array to ensure word alignment in RAM
} message2;
// Keep the same initalization values for back_buffer in ARM_UC_HUB_setState function in `case ARM_UC_HUB_STATE_IDLE`,where back_buffer initialzed again.
static arm_uc_buffer_t back_buffer = {
    .size_max = BUFFER_SIZE_MAX,
    .size = 0,
    .ptr = (uint8_t*) message2.data
};

// Update priority is recieved from Manifest that will be overrun once we get to install request
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
static uint64_t campaign_priority = 0;
#endif

// version (timestamp) of the current running application
static arm_uc_firmware_details_t arm_uc_active_details = { 0 };
static bool arm_uc_active_details_available = false;

static arm_uc_delta_details_t arm_uc_hub_delta_details = { 0 };

// bootloader information
static arm_uc_installer_details_t arm_uc_installer_details = { 0 };

// variable to keep track of the offset into the firmware image during download
static uint32_t firmware_offset = 0;

// variable to store the firmware config during firmware manager setup
// Initialization with an enum silences a compiler warning for ARM ("188-D: enumerated type mixed with another type").
// @Todo this could be removed and us fwinfo struct directly?
static ARM_UCFM_Setup_t arm_uc_hub_firmware_config = { UCFM_MODE_UNINIT };

// buffer to store the decoded firmware key
#define PLAIN_FIRMWARE_KEY_SIZE 16
#if defined(ARM_UC_FEATURE_MANIFEST_PSK) && (ARM_UC_FEATURE_MANIFEST_PSK == 1)
static uint8_t plainFirmwareKey[PLAIN_FIRMWARE_KEY_SIZE];
static arm_uc_buffer_t arm_uc_hub_plain_key = {
    .size_max = PLAIN_FIRMWARE_KEY_SIZE,
    .size     = PLAIN_FIRMWARE_KEY_SIZE,
    .ptr      = plainFirmwareKey
};
#endif

static arm_uc_mmContext_t manifestManagerContext = { 0 };
arm_uc_mmContext_t *pManifestManagerContext = &manifestManagerContext;

#if defined(ARM_UC_FEATURE_ROOTLESS_STAGE_1) && (ARM_UC_FEATURE_ROOTLESS_STAGE_1 == 1)
// allocate dedicated space for fwinfo which stores the whole manifest
static manifest_firmware_info_t fwinfo_storage;
static manifest_firmware_info_t *fwinfo = (manifest_firmware_info_t *) &fwinfo_storage;
#else
// fwinfo is used in and before ARM_UC_HUB_STATE_CHECK_VERSION
// back_buffer is used only after ARM_UC_HUB_STATE_CHECK_VERSION
// hence we can re-use space allocated for the download buffer for fwinfo
static manifest_firmware_info_t *fwinfo = (manifest_firmware_info_t *) &message2.fwinfo;
#endif
// buffer pointing to the manifest storage inside fwinfo, used for manifest insert
// and rootless stage 1 on linux.
static arm_uc_buffer_t manifest_buffer = {0};
// Download size used to store payload size for different cases: Full/delta payloads
static uint32_t fw_downloadSize = 0;

// buffer to store a URI struct
// uri is used in and after ARM_UC_HUB_STATE_CHECK_VERSION
// manifestManagerContext is used before ARM_UC_HUB_STATE_CHECK_VERSION
// Hence the memory can be shared between these two structs
static arm_uc_uri_t uri = {
    .size_max = sizeof(arm_uc_mmContext_t),
    .size     = 0,
    .ptr      = (uint8_t *) &manifestManagerContext,
    .port     = 0,
    .scheme   = URI_SCHEME_NONE,
    .host     = NULL,
    .path     = NULL,
};

// true if the hub initialization callback was called, false otherwise
static bool init_cb_called = false;

// delay in seconds before actual reboot is to be done after state machine
// reaches ARM_UC_HUB_STATE_INITIALIZE_REBOOT_TIMER. If zero, the state machine
// proceeds immediately to ARM_UC_HUB_STATE_REBOOT
static uint32_t arm_uc_hub_reboot_delay = 0;
#define REBOOT_TIMER_ID 1
#define ARM_UC_REBOOT_TIMER_EVENT 1
static int8_t arm_uc_tasklet_id = -1;

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
static uint32_t arm_uc_hub_download_delay = 10;
#define ARM_UC_DOWNLOAD_TIMER_EVENT 2
#define DOWNLOAD_TIMER_ID 2
#endif

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
#include "eventOS_event.h"
#include "multicast.h"
#include "CloudClientStorage.h"
#include "common_functions.h"

const char external_app_version[] = "mbed.ExternalAppVersion";
static int8_t ota_lib_tasklet_id = -1;
static bool multicast_update = false;

static arm_event_storage_t _event;
uint8_t inserted_manifest_hash[ARM_UC_SHA256_SIZE];

#if defined(ARM_UC_MULTICAST_NODE_MODE)
static bool multicast_delta = false;
static bool external_update = false;
uint8_t multicast_delta_state = ARM_UC_HUB_STATE_MULTICAST_DELTA_PREPARE; // not static!
static uint32_t multicast_delta_read_offset;
static arm_uc_firmware_details_t multicast_delta_details = { 0 };
static uint32_t multicast_delta_delta_size;

// TODO! Check can arm_uc_hub_firmware_details to be used?
static uint32_t fw_size = 0;
static uint64_t timestamp;
static arm_uc_firmware_address_t firmware_address = {
    .start_address = 0,
    .size     = 0
};
#endif // #if defined(ARM_UC_MULTICAST_NODE_MODE)
#endif // #if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)

static void arm_uc_tasklet(struct arm_event_s *event)
{
    if (ARM_UC_REBOOT_TIMER_EVENT == event->event_type) {
        ARM_UC_HUB_setState(ARM_UC_HUB_STATE_REBOOT);
    }
#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
    else if (ARM_UC_DOWNLOAD_TIMER_EVENT == event->event_type) {
        arm_uc_get_next_fragment();
    }
#endif
}

/*****************************************************************************/
/* Debug                                                                     */
/*****************************************************************************/

#if ARM_UC_HUB_TRACE_ENABLE
static void arm_uc_hub_debug_output()
{
    printf("Manifest timestamp: %" PRIu64 "\r\n", fwinfo->timestamp);

    if (uri.scheme == URI_SCHEME_HTTP) {
        printf("Firmware URL http://%s:%" PRIu16 "%s\r\n",
               uri.host, uri.port, uri.path);
    }

#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
    printf("Firmware size: %" PRIu32 "\r\n", fwinfo->installedSize);

    printf("Payload size: %" PRIu32 "\r\n", fwinfo->size);
    printf("Firmware hash (%" PRIu32 "): ", fwinfo->installedHash.size);

    for (unsigned i = 0; i < fwinfo->installedHash.size; i++) {
        printf("%02" PRIx8, fwinfo->installedHash.ptr[i]);
#else
    printf("Firmware size: %" PRIu32 "\r\n", fwinfo->size);
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
    if (arm_uc_hub_firmware_config.is_delta) {
        printf("Firmware Delta payload size: %" PRIu32 "\r\n", fwinfo->vendorInfo.deltaSize);
    }
#endif
    printf("Firmware hash (%" PRIu32 "): ", fwinfo->hash.size);
    for (unsigned i = 0; i < fwinfo->hash.size; i++) {
        printf("%02" PRIx8, fwinfo->hash.ptr[i]);
#endif //ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST
    }
    printf("\r\n");

    if (fwinfo->cipherMode == ARM_UC_MM_CIPHERMODE_PSK) {
        printf("PSK ID: ");
        for (unsigned i = 0; i < fwinfo->psk.keyID.size; i++) {
            printf("%02" PRIx8, *(fwinfo->psk.keyID.ptr + i));
        }
        printf("\r\n");

        printf("cipherKey(16): ");
        for (unsigned i = 0; i < 16; i++) {
            printf("%02" PRIx8, *(fwinfo->psk.cipherKey.ptr + i));
        }
        printf("\r\n");

#if defined(ARM_UC_FEATURE_MANIFEST_PSK) && (ARM_UC_FEATURE_MANIFEST_PSK == 1)
        printf("Decrypted Firmware Symmetric Key(16): ");
        for (unsigned i = 0; i < 16; i++) {
            printf("%02" PRIx8, arm_uc_hub_plain_key.ptr[i]);
        }
        printf("\r\n");
#endif

        printf("fwinfo->initVector\r\n");
        for (unsigned i = 0; i < 16; i++) {
            printf("%02" PRIx8, *(fwinfo->initVector.ptr + i));
        }
        printf("\r\n");
    }

    printf("Storage location: %" PRIu32 "\r\n",
           arm_uc_hub_firmware_config.package_id);
}
#endif

/*****************************************************************************/
/* Heap statistic                                                            */
/*****************************************************************************/

#if defined (MBED_HEAP_STATS_ENABLED)
static void arm_uc_hub_printHeapStats()
{
    mbed_stats_heap_t heap_stats;
    mbed_stats_heap_get(&heap_stats);
    UC_HUB_TRACE("\r\nheap_stats_current_size: %" PRIu32
                 "\r\nheap_stats_alloc_cnt: %" PRIu32,
                 heap_stats.current_size,
                 heap_stats.alloc_cnt);
}
#endif

/*****************************************************************************/
/* Stack statistic                                                           */
/*****************************************************************************/

#if defined (MBED_STACK_STATS_ENABLED)
static void arm_uc_hub_printStackStats()
{
    int cnt = osThreadGetCount();
    mbed_stats_stack_t *stack_stats = (mbed_stats_stack_t*) malloc(cnt * sizeof(mbed_stats_stack_t));
    if (stack_stats) {
        cnt = mbed_stats_stack_get_each(stack_stats, cnt);
        for (int i = 0; i < cnt; i++) {
            UC_HUB_TRACE("Thread: 0x%" PRIx32 ", Stack size: %" PRIu32 ", Max stack used: %" PRIu32,
                         stack_stats[i].thread_id,
                         stack_stats[i].reserved_size,
                         stack_stats[i].max_size);
        }
        free(stack_stats);
    }
}
#endif

/*****************************************************************************/
/* State machine                                                             */
/*****************************************************************************/

/* Short hand for simple error handling code */
#define HANDLE_ERROR(retval, msg, ...)                  \
    if (retval.error != ERR_NONE)                       \
    {                                                   \
        UC_HUB_ERR_MSG(msg " error code %s",            \
                       ##__VA_ARGS__,                   \
                       ARM_UC_err2Str(retval));         \
        new_state = ARM_UC_HUB_STATE_IDLE;              \
        break;                                          \
    }

arm_uc_hub_state_t ARM_UC_HUB_getState()
{
    return arm_uc_hub_state;
}

void ARM_UC_HUB_setInitializationCallback(void (*callback)(uintptr_t))
{
    arm_uc_hub_init_cb = callback;
}

/**
 * @brief Return the active firmware details or NULL if they're not yet available.
 */
arm_uc_firmware_details_t *ARM_UC_HUB_getActiveFirmwareDetails(void)
{
    return arm_uc_active_details_available ? &arm_uc_active_details : NULL;
}

arm_uc_delta_details_t *ARM_UC_HUB_getDeltaDetails(void)
{
    return &arm_uc_hub_delta_details;
}

void ARM_UC_HUB_setRebootDelay(uint32_t delay)
{
    arm_uc_hub_reboot_delay = delay;
}

void ARM_UC_HUB_setState(arm_uc_hub_state_t new_state)
{
    arm_uc_error_t retval;

    /* Loop until state is unchanged.
       First loop is mandatory regardless of current state.
    */
    do {
        /* store new stage */
        arm_uc_hub_state = new_state;

        switch (arm_uc_hub_state) {
            /*****************************************************************/
            /* Initialization                                                */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_INITIALIZED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_INITIALIZED");

                /* report the active firmware hash to the Cloud in parallel
                   with the main user application.
                */
                arm_uc_active_details_available = false;
                new_state = ARM_UC_HUB_STATE_GET_ACTIVE_FIRMWARE_DETAILS;
                break;

            case ARM_UC_HUB_STATE_INITIALIZING:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_INITIALIZING");
                break;

            /*****************************************************************/
            /* Report current firmware hash                                  */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_GET_ACTIVE_FIRMWARE_DETAILS:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_GET_ACTIVE_FIRMWARE_DETAILS");

                retval = ARM_UC_FirmwareManager.GetActiveFirmwareDetails(&arm_uc_active_details);
                HANDLE_ERROR(retval, "Firmware manager GetActiveFirmwareDetails failed");
                break;

            case ARM_UC_HUB_STATE_REPORT_ACTIVE_HASH:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_REPORT_ACTIVE_HASH");

                /* copy hash to buffer */
                memcpy(front_buffer.ptr,
                       arm_uc_active_details.hash,
                       ARM_UC_SHA256_SIZE);

                front_buffer.size = ARM_UC_SHA256_SIZE;

                /* send hash to update service */
                ARM_UC_ControlCenter_ReportName(&front_buffer);

                /* signal to the API that the firmware details are now available */
                arm_uc_active_details_available = true;

                new_state = ARM_UC_HUB_STATE_REPORT_ACTIVE_VERSION;
                break;

            /*****************************************************************/
            /* Report current firmware version                               */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_REPORT_ACTIVE_VERSION:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_REPORT_ACTIVE_VERSION");

                UC_HUB_TRACE("Active version: %" PRIu64,
                             arm_uc_active_details.version);
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                uint8_t version_buf[8];
                size_t size = 0;
                /* check if software version is already set */
                ccs_status_e status = ccs_get_item(external_app_version,
                                                   version_buf, 8, &size, CCS_CONFIG_ITEM);
                if (status == CCS_STATUS_SUCCESS) {
                    uint64_t ext_app_version = common_read_64_bit(version_buf);
                    UC_HUB_TRACE("Active version from storage: %" PRIu64,
                                 ext_app_version);
                    if (ext_app_version > arm_uc_active_details.version) {
                        arm_uc_active_details.version = ext_app_version;
                    }
                }
#endif // defined(ARM_UC_MULTICAST_NODE_MODE)

                /* send timestamp to update service */
                ARM_UC_ControlCenter_ReportVersion(arm_uc_active_details.version);

                new_state = ARM_UC_HUB_STATE_GET_INSTALLER_DETAILS;
                break;

            /*****************************************************************/
            /* Report bootloader information                                 */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_GET_INSTALLER_DETAILS:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_GET_INSTALLER_DETAILS");

                retval = ARM_UC_FirmwareManager.GetInstallerDetails(&arm_uc_installer_details);
                HANDLE_ERROR(retval, "Firmware manager GetInstallerDetails failed");
                break;

            case ARM_UC_HUB_STATE_REPORT_INSTALLER_DETAILS: {
                UC_HUB_TRACE("ARM_UC_HUB_STATE_REPORT_INSTALLER_DETAILS");

#if 0
                printf("bootloader: ");
                for (uint32_t index = 0; index < 20; index++) {
                    printf("%02X", arm_uc_installer_details.arm_hash[index]);
                }
                printf("\r\n");

                printf("layout: %" PRIu32 "\r\n", arm_uc_installer_details.layout);
#endif

                /* report installer details to Device Management */
                arm_uc_buffer_t bootloader_hash = {
                    .size_max = ARM_UC_SHA256_SIZE,
                    .size = ARM_UC_SHA256_SIZE,
                    .ptr = (arm_uc_installer_details.arm_hash)
                };
                ARM_UC_ControlCenter_ReportBootloaderHash(&bootloader_hash);

                bootloader_hash.ptr = (arm_uc_installer_details.oem_hash);
                ARM_UC_ControlCenter_ReportOEMBootloaderHash(&bootloader_hash);

                /* set new state */
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;
            }

            /*****************************************************************/
            /* Idle                                                          */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_IDLE:
                UC_HUB_TRACE("ARM_UC_UPDATE_STATE_IDLE");

                /*Restore initial values of front_buffer and back_buffers.
                If we get here after update failure, the `ptr` members of the structures may point to the same variable - `message2`
                and cause data corruption during next update session.
                This state could be a result of value swapping of these two structures that performed at ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD state.
                We should ignore leftovers of the previous update session state and use initialized values of these variables.
                !!! Keep the same values in static initializer of front_buffer and of back_buffers :  `static arm_uc_buffer_t front_buffer = {`
                and  `static arm_uc_buffer_t back_buffer = {` where these buffers defined*/
                front_buffer.ptr = (uint8_t*) message;
                front_buffer.size_max = BUFFER_SIZE_MAX;
                front_buffer.size = 0;
                back_buffer.ptr = (uint8_t*) message2.data;
                back_buffer.size = 0;
                back_buffer.size_max = BUFFER_SIZE_MAX;

                /* signal monitor that device has entered IDLE state */
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_IDLE);
#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
                if (multicast_update) {
                    _event.data.data_ptr = NULL;
                    _event.data.event_data = 0;
                    _event.data.event_id = 0;
                    _event.data.sender = 0;
                    _event.data.event_type = ARM_UC_OTA_DELETE_SESSION_EVENT;
                    _event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
                    _event.data.receiver = ota_lib_tasklet_id;

                    eventOS_event_send_user_allocated(&_event);
                    multicast_update = false;
                }
#endif

                /* signal that the Hub is initialized if needed */
                if (!init_cb_called) {
                    if (arm_uc_hub_init_cb) {
                        arm_uc_hub_init_cb(ARM_UC_INIT_DONE);
                    }
                    init_cb_called = true;
                }

                break;

            /*****************************************************************/
            /* Download manifest                                             */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_NOTIFIED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_NOTIFIED");

                /* notification received of a new manifest, hence go get said manifest */
#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
                multicast_update = false;
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                multicast_delta = false;
#endif
#endif
                retval = ARM_UC_SourceManager.GetManifest(&front_buffer, 0);
                HANDLE_ERROR(retval, "Source manager GetManifest failed");
                break;

            case ARM_UC_HUB_STATE_MANIFEST_FETCHED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_MANIFEST_FETCHED");

                // reset the reboot delay after new manifest is fetched
                arm_uc_hub_reboot_delay = 0;

                /* Save the manifest for later */
                memcpy(&fwinfo->manifestBuffer, front_buffer.ptr,
                       ARM_UC_util_min(sizeof(fwinfo->manifestBuffer), front_buffer.size));
                /* Save the manifest size for later */
                fwinfo->manifestSize = front_buffer.size;
                /* prepare the buffer struct for inserting manifest into the manifest manager */
                manifest_buffer.size_max = ARM_UC_MM_MANIFEST_BUFFER_SIZE;
                manifest_buffer.size = fwinfo->manifestSize;
                manifest_buffer.ptr = (uint8_t *) &fwinfo->manifestBuffer;

                /* Insert the manifest we just fetched into manifest manager.
                 * front_buffer will be used by manifest manager to fetch the
                 * manifest certificate from storage. manifest_buffer uses storage
                 * allocated for fwinfo which shares its memory with back_buffer */
                retval = ARM_UC_mmInsert(&pManifestManagerContext, &manifest_buffer, &front_buffer,  NULL);

                new_state = ARM_UC_HUB_STATE_MANIFEST_AWAIT_INSERT;
                if (retval.code != MFST_ERR_PENDING) {
                    HANDLE_ERROR(retval, "Manifest manager Insert failed")
                }
                break;

            case ARM_UC_HUB_STATE_MANIFEST_AWAIT_INSERT:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_MANIFEST_AWAIT_INSERT");
                break;

            case ARM_UC_HUB_STATE_MANIFEST_INSERT_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_MANIFEST_INSERT_DONE");
#ifdef ARM_UC_MULTICAST_NODE_MODE
                if (ARM_UC_ControlCenter_CheckState(ARM_UC_UPDATE_STATE_DOWNLOADING_UPDATE)) {
                    // monitor is already in state 4 so need to report something else first
                    ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_PROCESSING_MANIFEST);
                    new_state = ARM_UC_HUB_STATE_MANIFEST_AWAIT_MONITOR_REPORT_DONE;
                }
                else {
                    // normal case, monitor is idle at this point so we can skip state 3
                    new_state = ARM_UC_HUB_STATE_MANIFEST_COMPLETE;
                }
#else
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_PROCESSING_MANIFEST);
                new_state = ARM_UC_HUB_STATE_MANIFEST_AWAIT_MONITOR_REPORT_DONE;
#endif
                break;

            case ARM_UC_HUB_STATE_MANIFEST_AWAIT_MONITOR_REPORT_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_MANIFEST_AWAIT_MONITOR_REPORT_DONE");
                break;

            /*****************************************************************/
            /* Rollback protection                                           */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_MANIFEST_COMPLETE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_MANIFEST_COMPLETE");

                /* get the firmware info out of the manifest we just inserted
                   into the manifest manager
                */

                retval = ARM_UC_mmFetchFirmwareInfo(&pManifestManagerContext, fwinfo, NULL);
                if (retval.code != MFST_ERR_PENDING) {
                    HANDLE_ERROR(retval, "Manifest manager fetch info failed")
                }
                break;

            case ARM_UC_HUB_STATE_CHECK_VERSION:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_CHECK_VERSION");

                /* give up if the format is unsupported */
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
                if (!ARM_UC_mmCheckFormatUint32(&fwinfo->format, ARM_UC_MM_FORMAT_RAW_BINARY) && !ARM_UC_mmCheckFormatUint32(&fwinfo->format, ARM_UC_MM_FORMAT_BSDIFF_STREAM)) {
#else
                if (!ARM_UC_mmCheckFormatUint32(&fwinfo->format, ARM_UC_MM_FORMAT_RAW_BINARY)) {
#endif

                    ARM_UC_SET_ERROR(retval, MFST_ERR_FORMAT);
                    HANDLE_ERROR(retval, "Firmware Format unsupported");
                }
                /* only continue if timestamp is newer than active version */
                else if (fwinfo->timestamp > arm_uc_active_details.version) {
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                    // new delta manifest format in use
                    if(ARM_UC_mmCheckFormatUint32(&fwinfo->format, ARM_UC_MM_FORMAT_BSDIFF_STREAM)) {
                        // this is delta update, check if precursor hash was given in manifest and if so,
                        // check that it matches
                        if (fwinfo->precursor.ptr) {
                            // precursor is set, check length and content
                            if (fwinfo->precursor.size != ARM_UC_SHA256_SIZE ||
                                memcmp(fwinfo->precursor.ptr, arm_uc_active_details.hash, ARM_UC_SHA256_SIZE) != 0) {
                                // precursor hash doesn't match
                                UC_HUB_ERR_MSG("Precursor hash mismatch.");
                                /* signal warning through external handler */
                                ARM_UC_HUB_ErrorHandler(HUB_ERR_PRECURSOR_MISMATCH,
                                                        ARM_UC_HUB_STATE_CHECK_VERSION);

                                /* set new state */
                                new_state = ARM_UC_HUB_STATE_IDLE;
                                break; // case
                            }
                        }
                    }
#endif
#endif
                    /* set new state */
                    new_state = ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP;
                } else {
                    UC_HUB_ERR_MSG("version: %" PRIu64 " <= %" PRIu64,
                                   fwinfo->timestamp,
                                   arm_uc_active_details.version);

                    /* signal warning through external handler */
                    ARM_UC_HUB_ErrorHandler(HUB_ERR_ROLLBACK_PROTECTION,
                                            ARM_UC_HUB_STATE_CHECK_VERSION);

                    /* set new state */
                    new_state = ARM_UC_HUB_STATE_IDLE;
                }
                break;

            /*****************************************************************/
            /* Parse manifest                                                */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP");

                /* store pointer to hash */
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                arm_uc_hub_firmware_config.hash = &fwinfo->installedHash;
#else
                arm_uc_hub_firmware_config.hash = &fwinfo->hash;
#endif
                /* parse the url string into a arm_uc_uri_t struct */
                retval = arm_uc_str2uri(fwinfo->uri.ptr, fwinfo->uri.size, &uri);

                /* URI-based errors are propagated to monitor */
                if (retval.error != ERR_NONE) {
                    /* make sure that the URI string is always 0-terminated */
                    fwinfo->uri.ptr[fwinfo->uri.size_max - 1] = '\0';
                    UC_HUB_ERR_MSG("Unable to parse URI string %s", fwinfo->uri.ptr);

                    /* signal warning through external handler */
                    ARM_UC_HUB_ErrorHandler(SOMA_ERR_INVALID_URI,
                                            ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP);

                    /* set new state */
                    new_state = ARM_UC_HUB_STATE_IDLE;
                    break;
                }

#if defined(ARM_UC_MULTICAST_NODE_MODE)
                external_update = false;
                fw_size = 0;
                timestamp = 0;
                if (fwinfo->vendorInfo.vendorBuffer.size == 15 &&
                    memcmp(fwinfo->vendorInfo.vendorBuffer.ptr, "external update", fwinfo->vendorInfo.vendorBuffer.size) == 0) {
                    UC_HUB_TRACE("ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP - external update");
                    external_update = true;
                    fw_size = fwinfo->size;
                    timestamp = fwinfo->timestamp;
                }
#endif // defined(ARM_UC_MULTICAST_NODE_MODE)

#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                // With new manifest fields the payload size is in manifest size-field
                arm_uc_hub_firmware_config.package_size = fwinfo->installedSize;
#else
                /* store firmware size */
                arm_uc_hub_firmware_config.package_size = fwinfo->size;
#endif // ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)

#if defined(ARM_UC_MULTICAST_NODE_MODE)
                if(ARM_UC_mmCheckFormatUint32(&fwinfo->format, ARM_UC_MM_FORMAT_BSDIFF_STREAM)) {

                    if (external_update)
                    {
                        // external update should never mark the payload as delta.
                        // potential handling of different types of payloads should be
                        // handled by the application and payload should always be marked
                        // as raw binary in the manifest
                        retval.code = MFST_ERR_FORMAT;
                        HANDLE_ERROR(retval, "Delta payload handling not supported for external update...");
                    }

                    if (multicast_update) {
                        // multicast delta case; bypass on-the-fly delta to enable missing/out-of-order fragments
                        arm_uc_hub_firmware_config.is_delta = 0;
                        multicast_delta = true;

                        multicast_delta_details.version = fwinfo->timestamp;
                        multicast_delta_details.size    = fwinfo->installedSize;
                        memcpy(multicast_delta_details.hash, fwinfo->installedHash.ptr, ARM_UC_SHA256_SIZE);
                        multicast_delta_delta_size = fwinfo->size;

                        // set the size and hash to refer to payload, not after-install values
                        arm_uc_hub_firmware_config.package_size = fwinfo->size;
                        arm_uc_hub_firmware_config.hash = &fwinfo->hash;

                    } else {
                        arm_uc_hub_firmware_config.is_delta = 1;
                        multicast_delta = false;
                    }
                } else {
                    arm_uc_hub_firmware_config.is_delta = 0;
                    multicast_delta = false;
                }
#else
                if(ARM_UC_mmCheckFormatUint32(&fwinfo->format, ARM_UC_MM_FORMAT_BSDIFF_STREAM)) {
                    arm_uc_hub_firmware_config.is_delta = 1;
                } else {
                    arm_uc_hub_firmware_config.is_delta = 0;
                }
#endif
#endif // #if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
                /* read cryptography mode to determine if firmware is encrypted */
                switch (fwinfo->cipherMode) {
                    case ARM_UC_MM_CIPHERMODE_NONE:
                        arm_uc_hub_firmware_config.mode = UCFM_MODE_NONE_SHA_256;
                        break;

#if defined(ARM_UC_FEATURE_MANIFEST_PSK) && (ARM_UC_FEATURE_MANIFEST_PSK == 1)
                    case ARM_UC_MM_CIPHERMODE_PSK: {
                        /* Get pre-shared-key from the Control Center */
                        /* TODO: this call should be asynchronous */
                        const uint8_t *arm_uc_pre_shared_key = NULL;
                        retval = ARM_UC_PreSharedKey_GetSecret(&arm_uc_pre_shared_key, 128);
                        HANDLE_ERROR(retval, "Unable to get PSK");

                        /* Decode the firmware key to be used to decode the firmware */
                        UC_HUB_TRACE("Decoding firmware AES key...");
                        mbedtls_aes_context ctx;
                        mbedtls_aes_init(&ctx);
                        mbedtls_aes_setkey_dec(&ctx, arm_uc_pre_shared_key, 128);
                        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, fwinfo->psk.cipherKey.ptr, arm_uc_hub_plain_key.ptr);

                        arm_uc_hub_firmware_config.mode = UCFM_MODE_AES_CTR_128_SHA_256;
                        arm_uc_hub_firmware_config.key  = &arm_uc_hub_plain_key;
                        arm_uc_hub_firmware_config.iv   = &fwinfo->initVector;
                    }
                    break;
#endif /* ARM_UC_FEATURE_MANIFEST_PSK */

                    case ARM_UC_MM_CIPHERMODE_CERT_CIPHERKEY:
                    case ARM_UC_MM_CIPHERMODE_CERT_KEYTABLE:
                    default:
                        retval.code = MFST_ERR_CRYPTO_MODE;
                        HANDLE_ERROR(retval, "Unsupported AES Key distribution mode...");
                        break;
                }

#if defined(ARM_UC_MULTICAST_NODE_MODE)
                if (multicast_delta) {
                    // multicast delta special case; no option to pre-define storage IDs
                    // initial delta payload is always stored to own specific slot and
                    // full update candidate is always stored to slot 0
                    arm_uc_hub_firmware_config.package_id = ARM_UC_DELTA_SLOT_ID;
                }
                else {
#endif
                    /* check if storage ID has been set */
                    if (fwinfo->strgId.size == 0 || fwinfo->strgId.ptr == NULL) {
                        /* no storage ID set, use default value 0 */
                        arm_uc_hub_firmware_config.package_id = 0;
                    } else {
                        /* check if storage ID is "default" */
                        uint32_t location = arm_uc_strnstrn(fwinfo->strgId.ptr,
                                                            fwinfo->strgId.size,
                                                            (const uint8_t *) "default",
                                                            7);

                        if (location != UINT32_MAX) {
                            arm_uc_hub_firmware_config.package_id = 0;
                        } else {
                            /* parse storage ID */
                            bool success = false;
                            arm_uc_hub_firmware_config.package_id =
                                arm_uc_str2uint32(fwinfo->strgId.ptr,
                                                  fwinfo->strgId.size,
                                                  &success);
                        }
                    }
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                }
#endif

#if ARM_UC_HUB_TRACE_ENABLE
                arm_uc_hub_debug_output();
#endif

                /* Set new state */
#ifdef ARM_UC_MULTICAST_NODE_MODE
                new_state = ARM_UC_HUB_STATE_REQUEST_DOWNLOAD_AUTHORIZATION;
#else
                new_state = ARM_UC_HUB_STATE_DOWNLOAD_AUTHORIZATION_MONITOR_REPORT;
#endif
                break;

            /*****************************************************************/
            /* Download authorization                                        */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_DOWNLOAD_AUTHORIZATION_MONITOR_REPORT:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_DONWLOAD_AUTHORIZATION_MONITOR_REPORT");

                /* Signal control center */
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_AWAITING_DOWNLOAD_APPROVAL);

                /* Set new state */
                new_state = ARM_UC_HUB_STATE_WAIT_FOR_DOWNLOAD_AUTHORIZATION_REPORT_DONE;
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_DOWNLOAD_AUTHORIZATION_REPORT_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_DOWNLOAD_AUTHORIZATION_REPORT_DONE");
                break;

            case ARM_UC_HUB_STATE_REQUEST_DOWNLOAD_AUTHORIZATION:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_REQUEST_DOWNLOAD_AUTHORIZATION");
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                campaign_priority = fwinfo->priority;
                ARM_UC_ControlCenter_GetAuthorization(ARM_UCCC_REQUEST_DOWNLOAD, campaign_priority);
#else
                ARM_UC_ControlCenter_GetAuthorization(ARM_UCCC_REQUEST_DOWNLOAD, 0 /* PRIORITY NOT USED */);
#endif // defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                /* Set new state */
                new_state = ARM_UC_HUB_STATE_WAIT_FOR_DOWNLOAD_AUTHORIZATION;
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_DOWNLOAD_AUTHORIZATION:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_DOWNLOAD_AUTHORIZATION");
                break;

            /*****************************************************************/
            /* Download firmware                                             */
            /*****************************************************************/

            /* The firmware is downloaded in fragments. While one fragment is
               written to storage, the next fragment is being downloaded.

               In the ARM_UC_HUB_STATE_FETCH_FIRST_FRAGMENT state, the first
               fragment is being downloaded. Once completed, the first fragment
               will be in the front_buffer and both the network stack and
               storage stack will be idle.

               In the ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD state, the front and
               back buffers are swapped. The front buffer is being used for
               downloading the next fragment while the back buffer is being
               written to storage.

               ARM_UC_FirmwareManager.Write and
               ARM_UC_SourceManager.GetFirmwareFragment will both finish
               asynchronously generating two events:
               ARM_UC_SM_EVENT_FIRMWARE and UCFM_EVENT_UPDATE_DONE.

               If the ARM_UC_SM_EVENT_FIRMWARE event is generated first, the
               system enters the ARM_UC_HUB_STATE_WAIT_FOR_STORAGE state.
               If the UCFM_EVENT_UPDATE_DONE event is generated first, the
               system enters the ARM_UC_HUB_STATE_WAIT_FOR_NETWORK state.
               The second generated event will move the system back to the
               ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD state.

               The download will stop once the fragment offset is larger than
               the firmware size written in the manifest. This moves the system
               to the ARM_UC_HUB_STATE_STORE_LAST_FRAGMENT state.

               Once the last fragment is written, the newly written firmware
               committed in the ARM_UC_HUB_STATE_FINALIZE_STORAGE state.
            */
            case ARM_UC_HUB_STATE_SETUP_FIRMWARE: {
                UC_HUB_TRACE("ARM_UC_HUB_STATE_SETUP_FIRMWARE");

                /* store the firmware info in the manifest_firmware_info_t struct */
                arm_uc_firmware_details_t arm_uc_hub_firmware_details = { 0 };

                /* use manifest timestamp as firmware header version */
                arm_uc_hub_firmware_details.version = fwinfo->timestamp;
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                arm_uc_hub_firmware_details.size    = fwinfo->installedSize;

                /* copy hash */
                memcpy(arm_uc_hub_firmware_details.hash,
                       fwinfo->installedHash.ptr,
                       ARM_UC_SHA256_SIZE);

#if defined(ARM_UC_MULTICAST_NODE_MODE)
                if (multicast_delta) {
                    arm_uc_hub_firmware_details.size = fwinfo->size;
                    /* copy hash */
                    memcpy(arm_uc_hub_firmware_details.hash,
                           fwinfo->hash.ptr,
                           ARM_UC_SHA256_SIZE);
                }
#endif // ARM_UC_MULTICAST_NODE_MODE

#else
                arm_uc_hub_firmware_details.size    = fwinfo->size;
#endif

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
                if(arm_uc_hub_firmware_config.is_delta == 1) {
                    arm_uc_hub_delta_details.is_delta = arm_uc_hub_firmware_config.is_delta;
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                    // New manifest 1.0 with new fields
                    UC_HUB_TRACE("ARM_UC_HUB_STATE_SETUP_FIRMWARE NEW MANIFEST 1.0 FORMAT WITH NEW FIELDS!");
                    arm_uc_hub_delta_details.delta_payload_size = fwinfo->size;
#else
                    arm_uc_hub_delta_details.delta_payload_size = fwinfo->vendorInfo.deltaSize;

                    /* copy hash */
                    memcpy(arm_uc_hub_firmware_details.hash,
                           fwinfo->hash.ptr,
                           ARM_UC_SHA256_SIZE);

                } else {
                    /* copy hash */
                    memcpy(arm_uc_hub_firmware_details.hash,
                           fwinfo->hash.ptr,
                           ARM_UC_SHA256_SIZE);
#endif
                }
#else
                /* copy hash */
                memcpy(arm_uc_hub_firmware_details.hash,
                       fwinfo->hash.ptr,
                       ARM_UC_SHA256_SIZE);
#endif // ARM_UC_FEATURE_DELTA_PAAL

#if 0
                memcpy(arm_uc_hub_firmware_details.campaign,
                       configuration.campaign,
                       ARM_UC_GUID_SIZE);
#endif
                // initialise offset here so we can always resume with FIRST_FRAGMENT.
                firmware_offset = 0;

                /* setup the firmware manager to get ready for firmware storage */
                retval = ARM_UC_FirmwareManager.Prepare(&arm_uc_hub_firmware_config,
                                                        &arm_uc_hub_firmware_details,
                                                        &front_buffer);
                new_state = ARM_UC_HUB_STATE_AWAIT_FIRMWARE_SETUP;
                if (retval.code != ERR_NONE) {
                    // @todo: no separate error for Prepare ?
                    ARM_UC_HUB_ErrorHandler(FIRM_ERR_WRITE,
                                            ARM_UC_HUB_STATE_SETUP_FIRMWARE);
                    HANDLE_ERROR(retval, "ARM_UC_FirmwareManager Setup failed")
                    /* signal warning through external handler */
                }
            }
            break;

            case ARM_UC_HUB_STATE_AWAIT_FIRMWARE_SETUP:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_AWAIT_FIRMWARE_SETUP");
                break;

            case ARM_UC_HUB_STATE_FIRMWARE_SETUP_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_FIRMWARE_SETUP_DONE");
                /* set state to Downloading after setup has been done */
                UC_HUB_TRACE("Setting Monitor State: ARM_UC_UPDATE_STATE_DOWNLOADING_UPDATE");
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_DOWNLOADING_UPDATE);
                new_state = ARM_UC_HUB_STATE_AWAIT_FIRMWARE_MONITOR_REPORT_DONE;
                break;

            case ARM_UC_HUB_STATE_AWAIT_FIRMWARE_MONITOR_REPORT_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_AWAIT_FIRMWARE_MONITOR_REPORT_DONE");
                break;

            case ARM_UC_HUB_STATE_FETCH_FIRST_FRAGMENT:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_FETCH_FIRST_FRAGMENT");


                /* Check firmware size before entering the download state machine.
                   An empty firmware is used for erasing a slot.
                   If true, then send next state to monitor service, close storage slot.
                */
                if (fwinfo->size == 0) {
                    UC_HUB_TRACE("Firmware empty, skip download phase and finalize");
                    UC_HUB_TRACE("Setting Monitor State: ARM_UC_UPDATE_STATE_DOWNLOADED_UPDATE");
                    ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_DOWNLOADED_UPDATE);
                    new_state = ARM_UC_HUB_STATE_FINALIZE_STORAGE;
                } else {
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                    // Wait ota process to complete
                    if (multicast_update) {
                        UC_HUB_TRACE("Wait OTA process to complete download");
                        new_state = ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST;
                    } else {
#endif // ARM_UC_MULTICAST_NODE_MODE
                    // Set downloadSize here already because fwinfo struct is sharing memory
                    // with backbuffer so fwinfo contents are overwritten starting in next state
                    fw_downloadSize = fwinfo->size;
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
#if !defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) || (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 0)
                    if (arm_uc_hub_firmware_config.is_delta) {
                        fw_downloadSize = fwinfo->vendorInfo.deltaSize;
                        UC_HUB_TRACE("ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD USING Delta payload download size: %" PRIu32, fwinfo->vendorInfo.deltaSize);
                    }
#endif
#endif

                    UC_HUB_TRACE("loading %" PRIu32 " byte first fragment at %" PRIu32,
                                 front_buffer.size_max, firmware_offset);
                    /* reset download values */
                    front_buffer.size = 0;
                    back_buffer.size = 0;
                    arm_uc_get_next_fragment();
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                    }
#endif // #if defined(ARM_UC_MULTICAST_NODE_MODE)
                }
                break;
            case ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD");

                // Note: fwinfo is not valid anymore from this stage onwards!

                /* swap the front and back buffers
                   the back buffer contained just downloaded firmware chunk
                   the front buffer can now be cleared and used to download new chunk
                */
                {
                    arm_uc_buffer_t temp_buf_ptr = front_buffer;
                    front_buffer = back_buffer;
                    back_buffer = temp_buf_ptr;
                }
                /* store the downloaded chunk in the back buffer */
                if (back_buffer.size > 0) {
                    UC_HUB_TRACE("writing %" PRIu32 " byte fragment at %" PRIu32,
                                 back_buffer.size, firmware_offset);

                    /* increase offset by the amount that we just downloaded */
                    firmware_offset += back_buffer.size;
                    retval = ARM_UC_FirmwareManager.Write(&back_buffer);
                    if (retval.code != ERR_NONE) {
                        // @todo: no separate error for Prepare ?
                        ARM_UC_HUB_ErrorHandler(FIRM_ERR_WRITE,
                                                ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD);
                        HANDLE_ERROR(retval, "ARM_UC_FirmwareManager Update failed")
                    }
                }
                /* go fetch a new chunk using the front buffer if more are expected */
                if (firmware_offset < fw_downloadSize) {
                    front_buffer.size = 0;
#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
                    UC_HUB_TRACE("Getting next fragment after %d", arm_uc_hub_download_delay);

                    if (eventOS_event_timer_request(DOWNLOAD_TIMER_ID, ARM_UC_DOWNLOAD_TIMER_EVENT, arm_uc_tasklet_id, arm_uc_hub_download_delay) == -1) {
                        UC_HUB_TRACE("Failed to start download timer");
                        arm_uc_get_next_fragment();
                    }

#else
                    arm_uc_get_next_fragment();
#endif
                } else {
                    // Terminate the process, but first ensure the last fragment has been stored.
                    UC_HUB_TRACE("Last fragment fetched.");
                    new_state = ARM_UC_HUB_STATE_AWAIT_LAST_FRAGMENT_STORED;
                }
                /* report progress */
                ARM_UC_ControlCenter_ReportProgress(firmware_offset, fw_downloadSize);
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_STORAGE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_STORAGE");
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_NETWORK:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_NETWORK");
                break;

            case ARM_UC_HUB_STATE_AWAIT_LAST_FRAGMENT_STORED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_AWAIT_LAST_FRAGMENT_STORED");
                break;

            case ARM_UC_HUB_STATE_LAST_FRAGMENT_STORE_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_LAST_FRAGMENT_STORE_DONE");
#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
                if (multicast_update) {
                    // Send event back to OTA lib to continue with process completed
                    new_state = ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST;
                    _event.data.data_ptr = NULL;
                    _event.data.event_data = 0;
                    _event.data.event_id = 0;
                    _event.data.sender = 0;
                    _event.data.event_type = ARM_UC_OTA_MULTICAST_DL_DONE_EVENT;
                    _event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
                    _event.data.receiver = ota_lib_tasklet_id;

                    eventOS_event_send_user_allocated(&_event);

                    // Clear flags so normal campaing can be run
                    fwinfo = &message2.fwinfo;
                    break;
                }
#endif
                /* set state to downloaded when the full size of the firmware has been fetched. */
                UC_HUB_TRACE("Setting Monitor State: ARM_UC_UPDATE_STATE_DOWNLOADED_UPDATE");
#ifdef ARM_UC_MULTICAST_NODE_MODE
                new_state = ARM_UC_HUB_STATE_FINALIZE_STORAGE;
#else
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_DOWNLOADED_UPDATE);
                new_state = ARM_UC_HUB_STATE_AWAIT_LAST_FRAGMENT_MONITOR_REPORT_DONE;
#endif
                break;

            case ARM_UC_HUB_STATE_AWAIT_LAST_FRAGMENT_MONITOR_REPORT_DONE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_AWAIT_LAST_FRAGMENT_MONITOR_REPORT_DONE");
                break;

            case ARM_UC_HUB_STATE_FINALIZE_STORAGE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_FINALIZE_STORAGE");

                retval = ARM_UC_FirmwareManager.Finalize(&front_buffer, &back_buffer);
                HANDLE_ERROR(retval, "ARM_UC_FirmwareManager Finalize failed")
                break;

            /*****************************************************************/
            /* Install authorization                                         */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_STORAGE_FINALIZED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_STORAGE_FINALIZED");

#if defined(ARM_UC_FEATURE_ROOTLESS_STAGE_1) && (ARM_UC_FEATURE_ROOTLESS_STAGE_1 == 1)
                {
                    /* the manifest must be saved in a file, because it will be used later
                    by the second stage of the update client */
                    arm_uc_buffer_t manifest_buffer = {
                        .size_max = fwinfo->manifestSize,
                        .size = fwinfo->manifestSize,
                        .ptr = fwinfo->manifestBuffer
                    };

                    retval = ARM_UC_PAL_Linux_WriteManifest(arm_uc_hub_firmware_config.package_id,
                                                            &manifest_buffer);
                    HANDLE_ERROR(retval, "Uanble to write manifest to file system");
                }
#endif
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                /* Signal control center */
                ARM_UC_ControlCenter_GetAuthorization(ARM_UCCC_REQUEST_INSTALL, campaign_priority);
#else
                ARM_UC_ControlCenter_GetAuthorization(ARM_UCCC_REQUEST_INSTALL, 0 /* PRIORITY NOT USED */);
#endif // defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
                /* Set new state */
                new_state = ARM_UC_HUB_STATE_WAIT_FOR_INSTALL_AUTHORIZATION;
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_INSTALL_AUTHORIZATION:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_INSTALL_AUTHORIZATION");
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_AWAITING_INSTALL_APPROVAL);
                break;

            case ARM_UC_HUB_STATE_INSTALL_AUTHORIZED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_INSTALL_AUTHORIZED");
                UC_HUB_TRACE("Setting Monitor State: ARM_UC_UPDATE_STATE_INSTALLING_UPDATE");
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_INSTALLING_UPDATE);

                /* TODO: set timeout on ReportState before relying on callback to progress state machine */
                break;

            case ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE");

                /* Firmware verification passes, activate firmware image.
                */
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                // External update
                if (external_update) {
                    UC_HUB_TRACE("ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE - external update");
                    /* send timestamp to update service */
                    ccs_delete_item(external_app_version, CCS_CONFIG_ITEM);
                    uint8_t version_buffer[8];
                    common_write_64_bit(timestamp, version_buffer);

                    if (ccs_set_item(external_app_version, version_buffer, 8, CCS_CONFIG_ITEM) != CCS_STATUS_SUCCESS) {
                        UC_HUB_TRACE("ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE - failed to store version info!");
                        retval.code = ERR_UNSPECIFIED;
                        ARM_UC_HUB_ErrorHandler(ERR_UNSPECIFIED,
                                                ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE);
                        HANDLE_ERROR(retval, "Failed to store version info");
                    }

                    ARM_UC_ControlCenter_ReportVersion(timestamp);

                    firmware_address.size = fw_size;
                    if (ARM_UCP_GetFirmwareStartAddress(0, &firmware_address.start_address).code != ERR_NONE) {
                        retval.code = ERR_UNSPECIFIED;
                        ARM_UC_HUB_ErrorHandler(ERR_UNSPECIFIED,
                                                ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE);
                        HANDLE_ERROR(retval, "Failed to read start address");
                    }

                    _event.data.data_ptr = &firmware_address;
                    _event.data.event_data = 0;
                    _event.data.event_id = 0;
                    _event.data.sender = 0;
                    _event.data.event_type = ARM_UC_OTA_MULTICAST_EXTERNAL_UPDATE_EVENT;
                    _event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
                    _event.data.receiver = ota_lib_tasklet_id;

                    eventOS_event_send_user_allocated(&_event);
                } else if (multicast_delta) {
                    // Need to start from 'beginning'
                    // 1. Prepare for new slot
                    // 2. Read from old slot
                    // 3. Write to new slot
                    // 4. While stuff to read, jump to 2
                    // 5. Finalize
                    // 6. Activate
                    new_state = ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA;
                    multicast_delta_state = ARM_UC_HUB_STATE_MULTICAST_DELTA_PREPARE;



                    arm_uc_hub_firmware_config.package_id = 0;
                    arm_uc_hub_firmware_config.is_delta = 1;
                    arm_uc_hub_firmware_config.package_size = multicast_delta_details.size;
                    arm_uc_hub_firmware_config.hash->ptr = &multicast_delta_details.hash;
                    arm_uc_hub_firmware_config.hash->size = sizeof(multicast_delta_details.hash);
                    arm_uc_hub_delta_details.is_delta = 1;
                    arm_uc_hub_delta_details.delta_payload_size = multicast_delta_delta_size;

                    retval = ARM_UC_FirmwareManager.Prepare(&arm_uc_hub_firmware_config,
                                                   &multicast_delta_details,
                                                   &front_buffer);
                    if (retval.code != ERR_NONE) {
                        // @todo: no separate error for Prepare ?
                        ARM_UC_HUB_ErrorHandler(FIRM_ERR_WRITE,
                                                ARM_UC_HUB_STATE_ACTIVATE_FIRMWARE);
                        HANDLE_ERROR(retval, "ARM_UC_FirmwareManager multicast delta prepare failed")
                    }
                } else {
#endif // defined(ARM_UC_MULTICAST_NODE_MODE)
                    ARM_UC_FirmwareManager.Activate(arm_uc_hub_firmware_config.package_id);
#if defined(ARM_UC_MULTICAST_NODE_MODE)
                }
#endif // defined(ARM_UC_MULTICAST_NODE_MODE)
                break;

            case ARM_UC_HUB_STATE_PREP_REBOOT:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_PREP_REBOOT");
#ifdef ARM_UC_MULTICAST_NODE_MODE
                new_state = ARM_UC_HUB_STATE_INITIALIZE_REBOOT_TIMER;
#else
                ARM_UC_ControlCenter_ReportState(ARM_UC_UPDATE_STATE_REBOOTING);
#endif
                break;

            case ARM_UC_HUB_STATE_INITIALIZE_REBOOT_TIMER:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_INITIALIZE_REBOOT_TIMER");
                if(arm_uc_hub_reboot_delay) {
                    UC_HUB_TRACE("ARM_UC_HUB_STATE_INITIALIZE_REBOOT_TIMER - reboot after %" PRIu32 " seconds", arm_uc_hub_reboot_delay);
                    if (eventOS_event_timer_request(REBOOT_TIMER_ID, ARM_UC_REBOOT_TIMER_EVENT, arm_uc_tasklet_id, arm_uc_hub_reboot_delay * 1000) == -1) {
                        UC_HUB_TRACE("ARM_UC_HUB_STATE_INITIALIZE_REBOOT_TIMER - failed to start timer");
                        new_state = ARM_UC_HUB_STATE_REBOOT;
                    }
                } else {
                    new_state = ARM_UC_HUB_STATE_REBOOT;
                }
                break;

            case ARM_UC_HUB_STATE_REBOOT:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_REBOOT");

                // Firmware activated, now reboot the system to apply the new image.
#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)
                arm_uc_plat_reboot();
#else
                pal_osReboot();
#endif

                /* Reboot not implemented on this platform.
                   Go to idle state.
                */
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;

            /*****************************************************************/
            /* Error                                                         */
            /*****************************************************************/
            case ARM_UC_HUB_STATE_ERROR_FIRMWARE_MANAGER:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_ERROR_FIRMWARE_MANAGER");
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;

            case ARM_UC_HUB_STATE_ERROR_MANIFEST_MANAGER:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_ERROR_MANIFEST_MANAGER");
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;

            case ARM_UC_HUB_STATE_ERROR_SOURCE_MANAGER:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_ERROR_SOURCE_MANAGER");
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;

            case ARM_UC_HUB_STATE_ERROR_CONTROL_CENTER:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_ERROR_CONTROL_CENTER");
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_ERROR_ACK:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_ERROR_ACK");
                /* Don't change state. The only place where this state is set is in
                   update_client_hub_error_handler.c, right after reporting the update
                   result, so we wait for a "report done" event (ARM_UCCC_EVENT_MONITOR_SEND_DONE
                   in arm_uc_hub_event_handlers.c). The handler for this particular
                   event will then set the state to 'idle' */
                break;

            case ARM_UC_HUB_STATE_UNINITIALIZED:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_UNINITIALIZED");
                /* do nothing and wait for ARM_UC_HUB_Initialize call to change the state */
                break;

            case ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST");
                /* do nothing and wait for multicast to change the state */
                break;
#if defined(ARM_UC_MULTICAST_NODE_MODE)
            case ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA:
                UC_HUB_TRACE("ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA");

                switch (multicast_delta_state) {
                    case ARM_UC_HUB_STATE_MULTICAST_DELTA_PREPARE:
                        // ARM_UC_HUB_FirmwareManagerEventHandler is triggering to a state ARM_UC_HUB_STATE_MULTICAST_DELTA_READ
                        multicast_delta_read_offset = 0;
                        break;
                    case ARM_UC_HUB_STATE_MULTICAST_DELTA_WRITE:
                        multicast_delta_read_offset += front_buffer.size;
                        UC_HUB_TRACE("Processing delta - Write %"PRIu32, front_buffer.size);
                        retval = ARM_UC_FirmwareManager.Write(&front_buffer);
                        HANDLE_ERROR(retval, "ARM_UC_FirmwareManager write failed")
                        multicast_delta_state = ARM_UC_HUB_STATE_MULTICAST_DELTA_READ;
                        break;
                    case ARM_UC_HUB_STATE_MULTICAST_DELTA_READ:
                        {
                            uint32_t read_size = multicast_delta_delta_size - multicast_delta_read_offset;
                            if (front_buffer.size_max < read_size) {
                                read_size = front_buffer.size_max;
                            }
                            front_buffer.size = read_size;
                            if (read_size > 0) {
                                UC_HUB_TRACE("Processing delta - Read %"PRIu32" , offset %"PRIu32, read_size, multicast_delta_read_offset);
                                retval = ARM_UC_FirmwareManager.ReadFromSlot(&front_buffer, ARM_UC_DELTA_SLOT_ID, multicast_delta_read_offset);
                                HANDLE_ERROR(retval, "ARM_UC_FirmwareManager read failed")
                                multicast_delta_state = ARM_UC_HUB_STATE_MULTICAST_DELTA_WRITE;
                            }
                            else {
                                multicast_delta_state = ARM_UC_HUB_STATE_MULTICAST_DELTA_FINALIZE;
                                new_state = ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA_FINALIZE;
                            }
                        }
                        break;
                    default:
                        UC_HUB_TRACE("ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA - unknown state (%d)", multicast_delta_state);
                        break;
                }
                break;

            case ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA_FINALIZE:
                switch (multicast_delta_state) {
                    case ARM_UC_HUB_STATE_MULTICAST_DELTA_FINALIZE:
                        multicast_delta_state = ARM_UC_HUB_STATE_MULTICAST_DELTA_ACTIVATE;
                        UC_HUB_TRACE("Processing delta - Finalize");
                        retval = ARM_UC_FirmwareManager.Finalize(&front_buffer, &back_buffer);
                        HANDLE_ERROR(retval, "ARM_UC_HUB_STATE_MULTICAST_DELTA_FINALIZE Finalize failed")
                        break;
                    case ARM_UC_HUB_STATE_MULTICAST_DELTA_ACTIVATE:
                        UC_HUB_TRACE("Processing delta - Activate");
                        ARM_UC_FirmwareManager.Activate(0);
                        break;
                    default:
                        UC_HUB_TRACE("ARM_UC_HUB_STATE_PROCESS_MULTICAST_DELTA_FINALIZE - unknown state (%d)", multicast_delta_state);
                        break;
                }
                break;
#endif // defined(ARM_UC_MULTICAST_NODE_MODE)
            default:
                new_state = ARM_UC_HUB_STATE_IDLE;
                break;
        }
    } while (arm_uc_hub_state != new_state);

    if (new_state == ARM_UC_HUB_STATE_IDLE || new_state == ARM_UC_HUB_STATE_PREP_REBOOT) {
#if defined (MBED_HEAP_STATS_ENABLED)
        arm_uc_hub_printHeapStats();
#endif

#if defined (MBED_STACK_STATS_ENABLED)
        arm_uc_hub_printStackStats();
#endif
    }
}

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
void ARM_UC_HUB_setExternalDownload(manifest_firmware_info_t *fw_info)
{
    fwinfo = fw_info;
    multicast_update = true;
}
#endif

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)
int8_t ARM_UC_HUB_createEventHandler()
{
    if (arm_uc_tasklet_id == -1) {
        arm_uc_tasklet_id = eventOS_event_handler_create(&arm_uc_tasklet, 0);
    }

    return arm_uc_tasklet_id;
}

void ARM_UC_HUB_setMulticastTaskletId(const int8_t tasklet_id)
{
    ota_lib_tasklet_id = tasklet_id;
}

int8_t ARM_UC_HUB_setManifest(uint8_t* buf, uint32_t len)
{
    arm_uc_mdHandle_t mdHandle = { 0 };
    arm_uc_buffer_t tempHash = { 0 };
    uint8_t buffer[ARM_UC_SHA256_SIZE];

    arm_uc_error_t result = ARM_UC_cryptoHashSetup(&mdHandle, ARM_UC_CU_SHA256);
    if (result.code == ERR_NONE) {

        // update hash using tempHash as container for given manifest
        tempHash.ptr = buf;
        tempHash.size_max = len;
        tempHash.size = len;
        ARM_UC_cryptoHashUpdate(&mdHandle, &tempHash);

        // then fetch the hash using tempHash as container for internal buffer
        tempHash.ptr = buffer;
        tempHash.size_max = ARM_UC_SHA256_SIZE;
        ARM_UC_cryptoHashFinish(&mdHandle, &tempHash);

        if (memcmp(inserted_manifest_hash, buffer, ARM_UC_SHA256_SIZE) == 0 &&
            ARM_UC_HUB_getState() == ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST) {
            // inserted manifest hash matches the one we're getting re-inserted here
            // and state is waiting for multicast so everything should be set already
            // => no need to re-initialize and re-send notifications
            UC_HUB_TRACE("ARM_UC_HUB_setManifest - skipping re-initialization; already in correct state with same manifest");
            return 0;
        }
    }

    if (len <= front_buffer.size_max) {
        memcpy(front_buffer.ptr, buf, len);
        front_buffer.size = len;
        multicast_update = true;
        memcpy(inserted_manifest_hash, buffer, ARM_UC_SHA256_SIZE);
    } else {
        UC_HUB_TRACE("ARM_UC_HUB_setManifest - manifest does not fit into buffer");
    }
    return 1;
}

bool ARM_UC_HUB_getIsMulticastUpdate()
{
    return multicast_update;
}

#endif // defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)

static void arm_uc_get_next_fragment()
{
    UC_HUB_TRACE("arm_uc_get_next_fragment - next fragment at offset: %" PRIu32, firmware_offset);
    arm_uc_error_t retval;
    retval = ARM_UC_SourceManager.GetFirmwareFragment(&uri, &front_buffer, firmware_offset);
    if (retval.code != ERR_NONE) {
        // @todo: no separate error for Prepare ?
        ARM_UC_HUB_ErrorHandler(SOMA_ERR_NO_ROUTE_TO_SOURCE,
                                ARM_UC_HUB_STATE_STORE_AND_DOWNLOAD);

        ARM_UC_HUB_setState(ARM_UC_HUB_STATE_IDLE);
        UC_HUB_TRACE("arm_uc_get_next_fragment - GetFirmwareFragment failed");
    }
}
#endif // ARM_UC_ENABLE
