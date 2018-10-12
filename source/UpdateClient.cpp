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

// Needed for PRIu64 on FreeRTOS
#include <stdio.h>
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
#include "update-client-hub/update_client_hub.h"

#include "update-client-source-http/arm_uc_source_http.h"
#include "update-client-lwm2m/lwm2m-source.h"
#include "update-client-lwm2m/lwm2m-monitor.h"
#include "update-client-lwm2m/lwm2m-control.h"
#include "update-client-lwm2m/FirmwareUpdateResource.h"
#include "update-client-lwm2m/DeviceMetadataResource.h"

#include "eventOS_scheduler.h"
#include "eventOS_event.h"

#include "include/UpdateClient.h"
#include "include/UpdateClientResources.h"
#include "include/CloudClientStorage.h"
#include "include/ServiceClient.h"

#include "pal.h"

#if (!defined(MBED_CONF_MBED_TRACE_ENABLE) || MBED_CONF_MBED_TRACE_ENABLE == 0) \
    && ARM_UC_ALL_TRACE_ENABLE == 1
#define tr_info(...) { printf(__VA_ARGS__); printf("\r\n"); }
#else
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "uccc"
#endif

/* To be removed once update storage is defined in user config file.
   Default to filesystem in the meantime.
*/
#ifndef MBED_CLOUD_CLIENT_UPDATE_STORAGE
#define MBED_CLOUD_CLIENT_UPDATE_STORAGE ARM_UCP_FILESYSTEM
#endif

#ifdef MBED_CLOUD_CLIENT_UPDATE_STORAGE
extern ARM_UC_PAAL_UPDATE MBED_CLOUD_CLIENT_UPDATE_STORAGE;
#else
#error Update client storage must be defined in user configuration file
#endif

namespace UpdateClient
{
    enum UpdateClientEventType {
        UPDATE_CLIENT_EVENT_INITIALIZE,
        UPDATE_CLIENT_EVENT_PROCESS_QUEUE
    };

    static int8_t update_client_tasklet_id = -1;
    static FP1<void, int32_t> error_callback;

    static void certificate_done(arm_uc_error_t error,
                                 const arm_uc_buffer_t* fingerprint);
    static void initialization(void);
    static void initialization_done(int32_t);
    static void event_handler(arm_event_s* event);
    static void queue_handler(void);
    static void schedule_event(void);
    static void error_handler(int32_t error);
    static M2MInterface *_m2m_interface;
    static ServiceClient *_service;
}

void UpdateClient::UpdateClient(FP1<void, int32_t> callback, M2MInterface *m2mInterface, ServiceClient *service)
{
    tr_info("Update Client External Initialization: %p", (void*)pal_osThreadGetId());

    /* store callback handler */
    error_callback = callback;

    if (m2mInterface) {
        _m2m_interface = m2mInterface;
    }
    if (service) {
        _service = service;
    }
    
    /* create event */
    eventOS_scheduler_mutex_wait();
    if (update_client_tasklet_id == -1) {
        update_client_tasklet_id = eventOS_event_handler_create(UpdateClient::event_handler,
                                                                UPDATE_CLIENT_EVENT_INITIALIZE);

        tr_info("UpdateClient::update_client_tasklet_id: %d",
                update_client_tasklet_id);
    }
    eventOS_scheduler_mutex_release();
}

/**
 * @brief Populate M2MObjectList with Update Client objects.
 */
void UpdateClient::populate_object_list(M2MBaseList& list)
{
    /* Setup Firmware Update LWM2M object */
    list.push_back(FirmwareUpdateResource::getObject());
    list.push_back(DeviceMetadataResource::getObject());
}

void UpdateClient::set_update_authorize_handler(void (*handler)(int32_t request))
{
    ARM_UC_SetAuthorizeHandler(handler);
}

void UpdateClient::update_authorize(int32_t request)
{
    switch (request)
    {
        case RequestDownload:
            ARM_UC_Authorize(ARM_UCCC_REQUEST_DOWNLOAD);
            break;
        case RequestInstall:
            ARM_UC_Authorize(ARM_UCCC_REQUEST_INSTALL);
            break;
        case RequestInvalid:
        default:
            break;
    }
}

void UpdateClient::set_update_progress_handler(void (*handler)(uint32_t progress, uint32_t total))
{
    ARM_UC_SetProgressHandler(handler);
}

static void UpdateClient::initialization(void)
{
    tr_info("internal initialization: %p", (void*)pal_osThreadGetId());

    /* Register sources */
#if defined(MBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL) && MBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL == MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_COAP
    static const ARM_UPDATE_SOURCE* sources[] = {
        &ARM_UCS_LWM2M_SOURCE
    };
#else
    static const ARM_UPDATE_SOURCE* sources[] = {
        &ARM_UCS_HTTPSource,
        &ARM_UCS_LWM2M_SOURCE
    };
#endif

    ARM_UC_HUB_SetSources(sources, sizeof(sources)/sizeof(ARM_UPDATE_SOURCE*));

#if defined(MBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL) && MBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL == MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_COAP
    /* LWM2M Source needs to have access to M2MInterface for calling
       API M2MInterface::get_data_request() for firmware over COAP
       Blockwise transfer
    */
    ARM_UC_CONTROL_SetM2MInterface(_m2m_interface);
#endif
    
    /* Register sink for telemetry */
    ARM_UC_HUB_AddMonitor(&ARM_UCS_LWM2M_MONITOR);

    /* Register local error handler */
    ARM_UC_HUB_AddErrorCallback(UpdateClient::error_handler);

    /* Link internal queue with external scheduler.
       The callback handler is called whenever a task is posted to
       an empty queue. This will trigger the queue to be processed.
    */
    ARM_UC_HUB_AddNotificationHandler(UpdateClient::queue_handler);

    /* The override function enables the LWM2M Firmware Update Object
       to authorize both download and installation. The intention is
       that a buggy user application can't block an update.
    */
    ARM_UC_CONTROL_SetOverrideCallback(ARM_UC_OverrideAuthorization);

#ifdef MBED_CLOUD_CLIENT_UPDATE_STORAGE
    /* Set implementation for storing firmware */
    ARM_UC_HUB_SetStorage(&MBED_CLOUD_CLIENT_UPDATE_STORAGE);
#endif

#ifdef MBED_CLOUD_DEV_UPDATE_PSK
    /* Add pre shared key */
    ARM_UC_AddPreSharedKey(arm_uc_default_psk, arm_uc_default_psk_bits);
#endif

    /* Insert default certificate if defined otherwise initialze
       Update client immediately.
    */
#ifdef MBED_CLOUD_DEV_UPDATE_CERT
    /* Add verification certificate */
    arm_uc_error_t result = ARM_UC_AddCertificate(arm_uc_default_certificate,
                                                  arm_uc_default_certificate_size,
                                                  arm_uc_default_fingerprint,
                                                  arm_uc_default_fingerprint_size,
                                                  UpdateClient::certificate_done);

    /* Certificate insertion failed, most likely because the certificate
       has already been inserted once before.

       Continue initialization regardlessly, since the Update Client can still
       work if verification certificates are inserted through the Factory
       Client or by other means.
    */
    if (result.code != ARM_UC_CM_ERR_NONE)
    {
        tr_info("ARM_UC_AddCertificate failed");

        ARM_UC_HUB_Initialize(UpdateClient::initialization_done);
    }
#else
    ARM_UC_HUB_Initialize(UpdateClient::initialization_done);
#endif
}

static void UpdateClient::certificate_done(arm_uc_error_t error,
                                           const arm_uc_buffer_t* fingerprint)
{
    (void) fingerprint;

    /* Certificate insertion failure is not necessarily fatal.
       If verification certificates have been injected by other means
       it is still possible to perform updates, which is why the
       Update client initializes anyway.
    */
    if (error.code != ARM_UC_CM_ERR_NONE)
    {
        error_callback.call(WarningCertificateInsertion);
    }

    ARM_UC_HUB_Initialize(UpdateClient::initialization_done);
}

static void UpdateClient::initialization_done(int32_t result)
{
    tr_info("internal initialization done: %" PRIu32 " %p", result, (void*)pal_osThreadGetId());
    if (_service) {
        _service->finish_initialization();
    }
}

static void UpdateClient::event_handler(arm_event_s* event)
{
    switch (event->event_type)
    {
        case UPDATE_CLIENT_EVENT_INITIALIZE:
            UpdateClient::initialization();
            break;

        case UPDATE_CLIENT_EVENT_PROCESS_QUEUE:
            {
                /* process a single callback, for better cooperability */
                bool queue_not_empty = ARM_UC_ProcessSingleCallback();

                if (queue_not_empty)
                {
                    /* reschedule event handler, if queue is not empty */
                    UpdateClient::schedule_event();
                }
            }
            break;

        default:
            break;
    }
}

static void UpdateClient::queue_handler(void)
{
    /* warning: queue_handler can be called from interrupt context.
    */
    UpdateClient::schedule_event();
}

static void UpdateClient::schedule_event()
{
    /* schedule event */
    arm_event_s event = {0};
    event.receiver = update_client_tasklet_id;
    event.sender = 0;
    event.event_type = UPDATE_CLIENT_EVENT_PROCESS_QUEUE;
    event.event_id = 0;
    event.data_ptr = NULL;
    event.priority = ARM_LIB_LOW_PRIORITY_EVENT;
    event.event_data = 0;

    eventOS_event_send(&event);
}

static void UpdateClient::error_handler(int32_t error)
{
    tr_info("error reported: %" PRIi32, error);

    /* add warning base if less severe than error */
    if (error < ARM_UC_ERROR)
    {
        error_callback.call(WarningBase + error);
    }
    /* add error base if less severe than fatal */
    else if (error < ARM_UC_FATAL)
    {
        error_callback.call(ErrorBase + error);
    }
    /* add fatal base */
    else
    {
        error_callback.call(FatalBase + error);
    }
}

int UpdateClient::getVendorId(uint8_t* buffer, size_t buffer_size_max, size_t* value_size)
{
    arm_uc_error_t err = ARM_UC_GetVendorId(buffer, buffer_size_max, value_size);
    if (err.code == ARM_UC_DI_ERR_SIZE)
    {
        return CCS_STATUS_MEMORY_ERROR;
    }
    if (err.error == ERR_NONE)
    {
        *value_size = 16;
        return CCS_STATUS_SUCCESS;
    }
    return CCS_STATUS_KEY_DOESNT_EXIST;
}
int UpdateClient::getClassId(uint8_t* buffer, size_t buffer_size_max, size_t* value_size)
{
    arm_uc_error_t err = ARM_UC_GetClassId(buffer, buffer_size_max, value_size);
    if (err.code == ARM_UC_DI_ERR_SIZE)
    {
        return CCS_STATUS_MEMORY_ERROR;
    }
    if (err.error == ERR_NONE)
    {
        *value_size = 16;
        return CCS_STATUS_SUCCESS;
    }
    return CCS_STATUS_KEY_DOESNT_EXIST;
}
int UpdateClient::getDeviceId(uint8_t* buffer, size_t buffer_size_max, size_t* value_size)
{
    arm_uc_error_t err = ARM_UC_GetDeviceId(buffer, buffer_size_max, value_size);
    if (err.code == ARM_UC_DI_ERR_SIZE)
    {
        return CCS_STATUS_MEMORY_ERROR;
    }
    if (err.error == ERR_NONE)
    {
        *value_size = 16;
        return CCS_STATUS_SUCCESS;
    }
    return CCS_STATUS_KEY_DOESNT_EXIST;
}

#endif
