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

#include "update-client-source-manager/arm_uc_source_manager.h"

#include "update-client-common/arm_uc_common.h"
#include "update-client-common/arm_uc_config.h"
#include "update-client-source/arm_uc_source.h"

#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)
#include "pal.h"
#endif

#include <stdint.h>
#include <stdlib.h>

// TRACE.
// ------

// to disable extra trace, uncomment UC_SRCE_TRACE_ENTRY/VERBOSE/EXIT(...)
// or to enable extra trace, uncomment UC_SRCE_TRACE_ENTRY/VERBOSE/EXIT UC_SRCE_TRACE
#define UC_SRCE_TRACE_ENTRY(...)
#define UC_SRCE_TRACE_VERBOSE(...)
#define UC_SRCE_TRACE_EXIT(...)
//#define UC_SRCE_TRACE_ENTRY UC_SRCE_TRACE
//#define UC_SRCE_TRACE_VERBOSE UC_SRCE_TRACE
//#define UC_SRCE_TRACE_EXIT UC_SRCE_TRACE

// DATA & CONFIG.
// --------------

static const ARM_UPDATE_SOURCE *source_registry[MAX_SOURCES];
static ARM_SOURCE_SignalEvent_t event_cb;

// storage set aside for adding event_cb to the event queue
static arm_uc_callback_t event_cb_storage = {0};

static arm_uc_error_t ucsm_last_error = {ERR_NONE};

typedef enum {
    QUERY_TYPE_UNKNOWN,
    QUERY_TYPE_MANIFEST_DEFAULT,
    QUERY_TYPE_MANIFEST_URL,
    QUERY_TYPE_FIRMWARE,
    QUERY_TYPE_KEYTABLE
} query_type_t;

typedef struct {
    arm_uc_uri_t *uri;             // the uri from which the resourced should be fetched
    arm_uc_buffer_t *buffer;       // buffer given by caller to contain the results of the fetch
    uint32_t offset;               // offset parameter passed to the source
    query_type_t type;             // type of request, whether is manifest, firmware or keytable
    uint8_t excludes[MAX_SOURCES]; // records the tried and failed sources during a get request
    uint8_t current_source;        // records the index of source use in the get request in progress
} request_t;

// Hold information about the request in flight, there will always only be one request in flight
static request_t request_in_flight;

// FORWARD DECLARATIONS.
// ---------------------

/**
 * @brief Initialise a request_t struct, called when a new request
 *        have been initiated from the hub
 */
static arm_uc_error_t ARM_UCSM_RequestStructInit(request_t *request);

/**
 * @brief The SourceRegistry is an array of ARM_UPDATE_SOURCE
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryInit(void);
static arm_uc_error_t ARM_UCSM_SourceRegistryAdd(const ARM_UPDATE_SOURCE *source);
static arm_uc_error_t ARM_UCSM_SourceRegistryRemove(const ARM_UPDATE_SOURCE *source);

/**
 * @brief return the index of the source with the smallest cost
 * @param url Struct containing URL. NULL for default Manifest.
 * @param type The type of current request.
 * @param excludes Pointer to an array of size MAX_SOURCES to indicate
 *                 sources we want to exclude in the search. Set excludes[i]=1 to
 *                 exclude source_registry[i]
 * @param index Used to return the index of the source with the smallest cost
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryGetLowestCost(arm_uc_uri_t *uri,
                                                           query_type_t type,
                                                           uint8_t *excludes,
                                                           uint32_t *index);

/**
 * @brief Find the source of lowest cost and call the corresponding method
 *        depending on the type of the request. Retry with source of the next
 *        smallest cost if previous sources failed until the source registry
 *        is exhausted.
 */
static arm_uc_error_t ARM_UCSM_Get(request_t *req);

/**
 * @brief Catch callbacks from sources to enable error handling
 */
static void ARM_UCSM_CallbackWrapper(uint32_t event);

#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)

static void ARM_UCSM_ScheduleAsyncBusyRetryGet(void);

// BUSY RETRY.
// -----------

// structs to enable timer callback.
static palTimerID_t async_retry_timer_id;
static arm_uc_callback_t async_retry_timer_callback_struct;

// default settings for retries.
#define BUSY_RETRY_DELAY_MS         500
#define MAX_BUSY_RETRIES            2

// number of retries that have taken place.
static uint32_t num_busy_retries = 0;

/**
 * @brief Retry Get if source was busy at previous attempt.
 * @details If source is busy ARM_UCSM_AsyncRetryGet is registered with event queue,
 *        so it is called again to retry same source. RetryGet is delayed a bit
 *        to allow the link to clear (if possible), and is retried multiple times,
 *        with a gap between tries.
 */
static void ARM_UCSM_DoAsyncBusyRetryGet(uint32_t unused)
{
    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    (void) unused;

    // if already retried as many times as allowed, bail out with error,
    //  otherwise try the Get, and schedule follow-up if fails.
    if (++num_busy_retries > MAX_BUSY_RETRIES) {
        num_busy_retries = 0;
        ARM_UCSM_RequestStructInit(&request_in_flight);
        // TODO this potentially aborts the whole download if on an intermediate fragment,
        //        so figure out if that is the desired behaviour or not.
        //      the resume engine is *really* only designed to protect a single fragment,
        //        but this seems way too fragile to have around.
        ARM_UCSM_SetError(ARM_UC_ERROR(SOMA_ERR_UNSPECIFIED));
        ARM_UC_PostCallback(&event_cb_storage, event_cb, ARM_UC_SM_EVENT_ERROR);
    } else if (ARM_UCSM_Get(&request_in_flight).error != ERR_NONE) {
        ARM_UCSM_ScheduleAsyncBusyRetryGet();
    }
    UC_SRCE_TRACE_EXIT(".. %s", __func__);
}

/**
 * @brief post scheduled action to event queue to avoid running in timer context.
 */
static void ARM_UCSM_PostAsyncBusyRetryGet(
    void const *unused)
{
    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    (void)unused;

    pal_osTimerStop(async_retry_timer_id);
    ARM_UC_PostCallback(&async_retry_timer_callback_struct, ARM_UCSM_DoAsyncBusyRetryGet, 0);
}

/**
 * @brief request timer-scheduled invocation, invokes post directly if timer fails.
 */
static void ARM_UCSM_ScheduleAsyncBusyRetryGet(void)
{
    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    palStatus_t pal_status = PAL_SUCCESS;
    // if delay timer has not already been initialized then do so.
    if (async_retry_timer_id == 0) {
        pal_status = pal_osTimerCreate(
                         ARM_UCSM_PostAsyncBusyRetryGet, NULL, palOsTimerOnce, &async_retry_timer_id);
    }
    // if timer has been successfully initialized then install delayed action.
    if (pal_status == PAL_SUCCESS) {
        pal_status = pal_osTimerStart(async_retry_timer_id, BUSY_RETRY_DELAY_MS);
    }
    // if not successfully installed delayed action then post action directly.
    if (pal_status != PAL_SUCCESS) {
        async_retry_timer_id = 0;
        ARM_UC_PostCallback(&async_retry_timer_callback_struct, ARM_UCSM_DoAsyncBusyRetryGet, 0);
    }
}

#else // ARM_UC_PROFILE_MBED_CLOUD_CLIENT

/**
 * @brief Retry get due to source being busy
 */
static void ARM_UCSM_AsyncRetryGet(uint32_t);

#endif // ARM_UC_PROFILE_MBED_CLOUD_CLIENT

// UTILITY.
// --------

/**
 * @brief Initialise the `Request` struct
 */
static arm_uc_error_t ARM_UCSM_RequestStructInit(request_t *request)
{
    memset(request, 0, sizeof(request_t));
    request->current_source = MAX_SOURCES;
    request->type           = QUERY_TYPE_UNKNOWN;

    return (arm_uc_error_t) { ERR_NONE };
}


// REGISTRY.
// ---------

/**
 * @brief Initialise the source_registry array to NULL
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryInit(void)
{
    memset(source_registry, 0, sizeof(source_registry));
    return (arm_uc_error_t) { ERR_NONE };
}
/**
 * @brief Returns the index of the given address (possibly NULL) in the source array,
 *        or MAX_SOURCES if the address is not found.
 */
static uint32_t ARM_UCSM_GetIndexOf(const ARM_UPDATE_SOURCE *source)
{
    uint32_t index = MAX_SOURCES;
    for (uint32_t i = 0; i < MAX_SOURCES; i++) {
        if (source_registry[i] == source) {
            index = i;
            break;
        }
    }
    return index;
}
/**
 * @brief Returns the index of the given source address in the source array,
 *        or MAX_SOURCES if the source is not found.
 */
static uint32_t ARM_UCSM_GetIndexOfSource(const ARM_UPDATE_SOURCE *source)
{
    return ARM_UCSM_GetIndexOf(source);
}

/**
 * @brief Add pointer to source to the source_registry array
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryAdd(const ARM_UPDATE_SOURCE *source)
{
    uint32_t index = ARM_UCSM_GetIndexOf(NULL);
    if (index == MAX_SOURCES) {
        return ARM_UCSM_SetError((arm_uc_error_t) { SOMA_ERR_SOURCE_REGISTRY_FULL });
    } else {
        source_registry[index] = source;
        return (arm_uc_error_t) { ERR_NONE };
    }

}

/**
 * @brief Remove pointer to source from the source_registry array
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryRemove(const ARM_UPDATE_SOURCE *source)
{
    uint32_t index = ARM_UCSM_GetIndexOfSource(source);

    if (index == MAX_SOURCES) { // source not found
        return ARM_UCSM_SetError((arm_uc_error_t) { SOMA_ERR_SOURCE_NOT_FOUND });
    }

    source_registry[index] = NULL;
    return (arm_uc_error_t) { ERR_NONE };
}

// SOURCE MANAGEMENT.
// ------------------

/**
 * @brief find the index of the source with the smallest cost
 * @param url Struct containing URL. NULL for default Manifest.
 * @param type The type of current request.
 * @param excludes Pointer to an array of size MAX_SOURCES to indicate
 *                 sources we want to exclude in the search. Set excludes[i]=1 to
 *                 exclude source_registry[i]
 * @param index Used to return the index of the source with the smalllest cost
 * @return error status.
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryGetLowestCost(arm_uc_uri_t *uri,
                                                           query_type_t type,
                                                           uint8_t *excludes,
                                                           uint32_t *index)
{
    uint32_t min_cost = UINT32_MAX;
    uint32_t min_cost_index = 0;

    // start with no route found, could be no sources are registered, skips loop.
    arm_uc_error_t retval = (arm_uc_error_t) { SOMA_ERR_NO_ROUTE_TO_SOURCE };

    UC_SRCE_TRACE_ENTRY(">> %s, type %" PRIu32, __func__, (uint32_t)type);

    // loop through all sources
    for (uint32_t i = 0; i < MAX_SOURCES; i++) {
        // assume no route to begin each loop, need to actually find one to change this.
        retval = (arm_uc_error_t) { SOMA_ERR_NO_ROUTE_TO_SOURCE };

        // if source is NULL or it has been explicitly excluded because of failure before
        if (source_registry[i] == NULL) {
            continue;
        } else if ((excludes != NULL) && (excludes[i] == 1)) {
            UC_SRCE_TRACE_VERBOSE("skipping excluded index %" PRIu32, i);
            continue;
        } else {
            UC_SRCE_TRACE_VERBOSE("testing index %" PRIu32, i);
        }

        ARM_SOURCE_CAPABILITIES cap  = source_registry[i]->GetCapabilities();
        uint32_t cost = UINT32_MAX;

        switch (type) {
            case QUERY_TYPE_UNKNOWN:
                break;
            case QUERY_TYPE_MANIFEST_DEFAULT:
                if ((uri == NULL) && (cap.manifest_default == 1)) {
                    UC_SRCE_TRACE_VERBOSE("getting manifest default cost, index %" PRIu32, i);
                    retval = source_registry[i]->GetManifestDefaultCost(&cost);
                }
                break;
            case QUERY_TYPE_MANIFEST_URL:
                if ((uri != NULL) && (cap.manifest_url == 1)) {
                    UC_SRCE_TRACE_VERBOSE("getting manifest url cost, index %" PRIu32, i);
                    retval = source_registry[i]->GetManifestURLCost(uri, &cost);
                }
                break;
            case QUERY_TYPE_FIRMWARE:
                if ((uri != NULL) && (cap.firmware == 1)) {
                    UC_SRCE_TRACE_VERBOSE("getting firmware url cost, index %" PRIu32, i);
                    retval = source_registry[i]->GetFirmwareURLCost(uri, &cost);
                }
                break;
            case QUERY_TYPE_KEYTABLE:
                if ((uri != NULL) && (cap.keytable == 1)) {
                    UC_SRCE_TRACE_VERBOSE("getting keytable url cost, index %" PRIu32, i);
                    retval = source_registry[i]->GetKeytableURLCost(uri, &cost);
                }
                break;
            default:
                break;
        }
        if (retval.error != ERR_NONE) {
            // get cost from source i failed, either no match or during assessment.
            // cost is invalid at this point, so skip to next iteration
            ARM_UCSM_SetError(retval);
            UC_SRCE_TRACE("invalid cost for index %" PRIu32 " type %" PRIu32, i, (uint32_t)type);
            continue;
        }
        // record the cost and i if cost is lower than stored minimum cost.
        if (cost < min_cost) {
            min_cost = cost;
            min_cost_index = i;
        }
    }
    // if no minimum cost was found, then no route was found.
    // otherwise return the best route available.
    if (min_cost == UINT32_MAX) {
        UC_SRCE_ERR_MSG(".. %s: Error - No route", __func__);
        return ARM_UCSM_SetError((arm_uc_error_t) { SOMA_ERR_NO_ROUTE_TO_SOURCE });
    } else {
        *index = min_cost_index;
        UC_SRCE_TRACE_VERBOSE("%s index = %" PRIu32, __func__, min_cost_index);
        return (arm_uc_error_t) { ERR_NONE };
    }
}

#if defined(ARM_UC_PROFILE_MBED_CLOUD_CLIENT) && (ARM_UC_PROFILE_MBED_CLOUD_CLIENT == 1)

/**
 * @brief find source of lowest cost and call consecutive sources until retrieved.
 * @details Find the source of lowest cost and call the corresponding method
 *        depending on the type of the request. Retry with source of the next
 *        smallest cost if previous sources failed until the source registry
 *        is exhausted.
 * @param pointer to struct containing details of requested info.
 * @return error status
 */
static arm_uc_error_t ARM_UCSM_Get(request_t *req)
{
    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    arm_uc_error_t retval = (arm_uc_error_t) { ERR_NONE };

    if (req->uri != NULL) {
        UC_SRCE_TRACE_VERBOSE("    with %" PRIxPTR ", host [%s], path [%s], type %" PRIu32,
                              (uintptr_t)req->uri, req->uri->host, req->uri->path, (uint32_t)req->type);
    } else {
        UC_SRCE_TRACE_VERBOSE("    with NULL, type %" PRIu32, (uint32_t)req->type);
    }

    uint32_t index = 0;
    if (retval.error == ERR_NONE) {
        // get the source of lowest cost, checking that call is valid.
        retval = ARM_UCSM_SourceRegistryGetLowestCost(
                     req->uri,
                     req->type,
                     req->excludes,
                     &index);
    }
    if (retval.error == ERR_NONE) {
        // call is known to be valid, no need to check URI again.
        switch (req->type) {
            case QUERY_TYPE_MANIFEST_DEFAULT:
                UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetManifestDefault", index);
                retval = source_registry[index]->GetManifestDefault(req->buffer, req->offset);
                break;
            case QUERY_TYPE_MANIFEST_URL:
                UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetManifestURL with %" PRIxPTR, index, (uintptr_t)req->uri);
                retval = source_registry[index]->GetManifestURL(req->uri, req->buffer, req->offset);
                break;
            case QUERY_TYPE_FIRMWARE:
                UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetFirmwareFragment with %" PRIxPTR, index, (uintptr_t)req->uri);
                retval = source_registry[index]->GetFirmwareFragment(req->uri, req->buffer, req->offset);
                break;
            case QUERY_TYPE_KEYTABLE:
                UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetKeytableURL with %" PRIxPTR, index, (uintptr_t)req->uri);
                retval = source_registry[index]->GetKeytableURL(req->uri, req->buffer);
                break;
            default:
                if (req->uri == NULL) {
                    UC_SRCE_ERR_MSG("-ARM_UCSM_Get: Error - Invalid parameter (URI == NULL)");
                    ARM_UCSM_SetError(retval = (arm_uc_error_t) { SOMA_ERR_INVALID_URI });
                } else {
                    UC_SRCE_ERR_MSG("-ARM_UCSM_Get: Error - Invalid parameter (unknown request type)");
                    ARM_UCSM_SetError(retval = (arm_uc_error_t) { SOMA_ERR_INVALID_REQUEST });
                }
                break;
        }
    } else {
        UC_SRCE_ERR_MSG("%s error retval.code %" PRIu32, __func__, retval.code);
    }

    // decide what to do based on the results of preceding efforts.
    if (retval.code == SRCE_ERR_BUSY) {
        UC_SRCE_TRACE_VERBOSE("%s Busy -> ScheduleAsyncBusyRetryGet", __func__);
        ARM_UCSM_ScheduleAsyncBusyRetryGet();
        retval = (arm_uc_error_t) { ERR_NONE };
    } else if (retval.code == SOMA_ERR_NO_ROUTE_TO_SOURCE) {
        UC_SRCE_ERR_MSG(".. %s: Error - no route available", __func__);
        return retval;
    } else if (retval.error != ERR_NONE) {
        // failure, try source with the next smallest cost.
        ARM_UCSM_SetError(retval);
        req->excludes[index] = 1;
        UC_SRCE_TRACE_VERBOSE(".. %s: Error - failure (try source with the next smallest cost)", __func__);
        retval = ARM_UCSM_Get(req);
    } else {
        // record the index of source handling the get request currently.
        req->current_source = index;
        UC_SRCE_TRACE_VERBOSE(".. %s: Using source %" PRIu32, __func__, index);
        retval = (arm_uc_error_t) { ERR_NONE };
    }
    if (ARM_UC_IS_ERROR(retval)) {
        ARM_UCSM_SetError(retval);
    }
    return retval;
}

#else // ARM_UC_PROFILE_MBED_CLOUD_CLIENT

/**
 * @brief Find the source of lowest cost and call the corresponding method
 *        depending on the type of the request. Retry with source of the next
 *        smallest cost if previous sources failed until the source registry
 *        is exhausted.
 */
static arm_uc_error_t ARM_UCSM_Get(request_t *req)
{
    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    if (req->uri != NULL) {
        UC_SRCE_TRACE_VERBOSE("    with %s" PRIx32 ", host [%s], path [%s], type %" PRId16,
                              req->uri->ptr, req->uri->host, req->uri->path, req->type);
    } else {
        UC_SRCE_TRACE_VERBOSE("    with NULL, type %" PRId16, req->type);
    }
    uint32_t index = 0;

    ARM_UC_INIT_ERROR(retval, ERR_NONE);

    // get the source of lowest cost
    retval = ARM_UCSM_SourceRegistryGetLowestCost(req->uri, req->type, req->excludes, &index);
    if (ARM_UC_IS_ERROR(retval)) {
        UC_SRCE_ERR_MSG(".. %s: error retval.code %" PRIx32, __func__, retval.code);
        return ARM_UCSM_SetError(retval);
    }

    if ((req->uri == NULL) && (req->type == QUERY_TYPE_MANIFEST_DEFAULT)) {
        UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetManifestDefault", index);
        retval = source_registry[index]->GetManifestDefault(req->buffer, req->offset);
    } else if ((req->uri != NULL) && (req->type == QUERY_TYPE_MANIFEST_URL)) {
        UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetManifestURL with %s", index, req->uri->ptr);
        retval = source_registry[index]->GetManifestURL(req->uri, req->buffer, req->offset);
    } else if ((req->uri != NULL) && (req->type == QUERY_TYPE_FIRMWARE)) {
        UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetFirmwareFragment with %s", index, req->uri->ptr);
        retval = source_registry[index]->GetFirmwareFragment(req->uri, req->buffer, req->offset);
    } else if ((req->uri != NULL) && (req->type == QUERY_TYPE_KEYTABLE)) {
        UC_SRCE_TRACE_VERBOSE("calling source %" PRIu32 " GetKeytableURL with %s", index, req->uri->ptr);
        retval = source_registry[index]->GetKeytableURL(req->uri, req->buffer);
    } else {
        if (req->uri == NULL) {
            UC_SRCE_TRACE(".. %s: Error - Invalid parameter (URI == NULL)", __func__);
            return ARM_UCSM_SetError(ARM_UC_ERROR(SOMA_ERR_INVALID_URI));
        } else {
            UC_SRCE_TRACE("..%s: Error - Invalid parameter (unknown request type)", __func__);
            return ARM_UCSM_SetError(ARM_UC_ERROR(SOMA_ERR_INVALID_REQUEST));
        }
    }
    if (ARM_UC_ERROR_MATCHES(retval, SRCE_ERR_BUSY)) {
        UC_SRCE_TRACE(".. %s: Error - Busy -> PostCallback AsyncRetryGet", __func__);
        ARM_UC_PostCallback(&event_cb_storage, ARM_UCSM_AsyncRetryGet, 0);
        return ARM_UC_ERROR(ERR_NONE);
    } else if (ARM_UC_IS_ERROR(retval)) {
        // failure, try source with the next smallest cost
        ARM_UCSM_SetError(retval);
        req->excludes[index] = 1;
        UC_SRCE_TRACE(".. %s: Error - failure (try source with the next smallest cost)", __func__);
        return ARM_UCSM_Get(req);
    }
    // record the index of source handling the get request currently
    req->current_source = index;
    UC_SRCE_TRACE_EXIT(".. %s, using source %" PRIu32, __func__, index);

    return ARM_UC_ERROR(ERR_NONE);
}

/**
 * @brief If source is busy ARM_UCSM_AsyncRetryGet is registered with
          the event queue so it is called again to retry the same source
 */
static void ARM_UCSM_AsyncRetryGet(uint32_t unused)
{
    (void) unused;

    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.error != ERR_NONE) {
        ARM_UCSM_RequestStructInit(&request_in_flight);
        ARM_UCSM_SetError(retval);
        ARM_UC_PostCallback(&event_cb_storage, event_cb, ARM_UC_SM_EVENT_ERROR);
    }
    UC_SRCE_TRACE_EXIT(".. %s", __func__);
}

#endif // ARM_UC_PROFILE_MBED_CLOUD_CLIENT

/**
 * @brief Translate source event into source manager event
 */
static ARM_UC_SM_Event_t ARM_UCSM_TranslateEvent(uint32_t source_event)
{
    ARM_UC_SM_Event_t event = ARM_UC_SM_EVENT_ERROR;

    switch (source_event) {
        case EVENT_NOTIFICATION:
            event = ARM_UC_SM_EVENT_NOTIFICATION;
            break;
        case EVENT_MANIFEST:
            event = ARM_UC_SM_EVENT_MANIFEST;
            break;
        case EVENT_FIRMWARE:
            event = ARM_UC_SM_EVENT_FIRMWARE;
            break;
        case EVENT_KEYTABLE:
            event = ARM_UC_SM_EVENT_KEYTABLE;
            break;
        case EVENT_ERROR:
            event = ARM_UC_SM_EVENT_ERROR;
            break;
        case EVENT_ERROR_SOURCE:
            event = ARM_UC_SM_EVENT_ERROR_SOURCE;
            break;
        case EVENT_ERROR_BUFFER_SIZE:
            event = ARM_UC_SM_EVENT_ERROR_BUFFER_SIZE;
            break;
    }

    return event;
}

/**
 * @brief Catch callbacks from sources to enable error handling
 */
static void ARM_UCSM_CallbackWrapper(uint32_t source_event)
{
    UC_SRCE_TRACE_ENTRY(">> %s", __func__);
    UC_SRCE_TRACE_VERBOSE("source_event == %" PRIu32, source_event);
    ARM_UC_SM_Event_t event = ARM_UCSM_TranslateEvent(source_event);

    if ((event == ARM_UC_SM_EVENT_ERROR)
            && (request_in_flight.type != QUERY_TYPE_UNKNOWN)) {
        UC_SRCE_TRACE("ARM_UCSM_TranslateEvent event error == %" PRId16, event);
        request_in_flight.excludes[request_in_flight.current_source] = 1;
        arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
        if (retval.code != ERR_NONE) {
            UC_SRCE_TRACE("ARM_UCSM_Get() retval.code == %" PRIx32, retval.code);
            ARM_UCSM_RequestStructInit(&request_in_flight);
            ARM_UCSM_SetError(retval);
            ARM_UC_PostCallback(&event_cb_storage, event_cb, event);
        }
    } else {
        ARM_UCSM_RequestStructInit(&request_in_flight);
        ARM_UC_PostCallback(&event_cb_storage, event_cb, event);
    }
    UC_SRCE_TRACE_EXIT(".. %s", __func__);
}

// PUBLIC API.
// -----------

/* further documentation of the API can be found in source_manager.h */

arm_uc_error_t ARM_UCSM_Initialize(ARM_SOURCE_SignalEvent_t callback)
{
    // remember the callback
    event_cb = callback;

    // init source_registry to NULL
    return ARM_UCSM_SourceRegistryInit();
}

arm_uc_error_t ARM_UCSM_Uninitialize()
{
    for (size_t i = 0; i < MAX_SOURCES; i++) {
        if (source_registry[i] != NULL) {
            source_registry[i]->Uninitialize();
            source_registry[i] = NULL;
        }
    }
    return (arm_uc_error_t) {ERR_NONE};
}

arm_uc_error_t ARM_UCSM_AddSource(const ARM_UPDATE_SOURCE *source)
{
    if (ARM_UCSM_GetIndexOfSource(source) != MAX_SOURCES) {
        // Source already added, don't add again
        // TODO should this return ERR_NONE or a new error
        // SOMA_ERR_ALREADY_PRESENT?
        return (arm_uc_error_t) { ERR_NONE };
    }
    source->Initialize(ARM_UCSM_CallbackWrapper);
    return ARM_UCSM_SourceRegistryAdd(source);
}

arm_uc_error_t ARM_UCSM_RemoveSource(const ARM_UPDATE_SOURCE *source)
{
    arm_uc_error_t err = ARM_UCSM_SourceRegistryRemove(source);
    if (err.code == ERR_NONE) {
        // Call 'uninitialize' only if the source was found (and removed)
        source->Uninitialize();
    }
    return err;
}

/* All the `Get` APIs map into `ARM_UCSM_Get` via ARM_UCSM_GetCommon() */

/**
 * @brief invoke Get after setting up params in in-flight store.
 */
arm_uc_error_t ARM_UCSM_GetCommon(
    arm_uc_uri_t *uri,
    arm_uc_buffer_t *buffer,
    uint32_t offset,
    query_type_t type)
{
    ARM_UCSM_RequestStructInit(&request_in_flight);
    request_in_flight.uri    = uri;
    request_in_flight.buffer = buffer;
    request_in_flight.offset = offset;
    request_in_flight.type   = type;

    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.code != ERR_NONE) {
        ARM_UCSM_SetError(retval);
        ARM_UCSM_RequestStructInit(&request_in_flight);
    }
    return retval;
}

arm_uc_error_t ARM_UCSM_GetManifest(arm_uc_buffer_t *buffer, uint32_t offset)
{
    arm_uc_error_t retval = ARM_UCSM_GetCommon(
                                NULL, buffer, offset, QUERY_TYPE_MANIFEST_DEFAULT);
    return retval;
}

arm_uc_error_t ARM_UCSM_GetManifestFrom(arm_uc_uri_t *uri,
                                        arm_uc_buffer_t *buffer,
                                        uint32_t offset)
{
    arm_uc_error_t retval = ARM_UCSM_GetCommon(
                                uri, buffer, offset, QUERY_TYPE_MANIFEST_URL);
    return retval;
}

arm_uc_error_t ARM_UCSM_GetFirmwareFragment(arm_uc_uri_t *uri,
                                            arm_uc_buffer_t *buffer,
                                            uint32_t offset)
{
    arm_uc_error_t retval = ARM_UCSM_GetCommon(
                                uri, buffer, offset, QUERY_TYPE_FIRMWARE);
    return retval;
}

arm_uc_error_t ARM_UCSM_GetKeytable(arm_uc_uri_t *uri, arm_uc_buffer_t *buffer)
{
    arm_uc_error_t retval = ARM_UCSM_GetCommon(
                                uri, buffer, 0, QUERY_TYPE_KEYTABLE);
    return retval;
}

arm_uc_error_t ARM_UCSM_GetError(void)
{
    return ucsm_last_error;
}

arm_uc_error_t ARM_UCSM_SetError(arm_uc_error_t an_error)
{
    return (ucsm_last_error = an_error);
}



// INTERFACE.
// ----------

ARM_UC_SOURCE_MANAGER_t ARM_UC_SourceManager = {
    .Initialize          = ARM_UCSM_Initialize,
    .Uninitialize        = ARM_UCSM_Uninitialize,
    .AddSource           = ARM_UCSM_AddSource,
    .RemoveSource        = ARM_UCSM_RemoveSource,
    .GetManifest         = ARM_UCSM_GetManifest,
    .GetManifestFrom     = ARM_UCSM_GetManifestFrom,
    .GetFirmwareFragment = ARM_UCSM_GetFirmwareFragment,
    .GetKeytable         = ARM_UCSM_GetKeytable
};

