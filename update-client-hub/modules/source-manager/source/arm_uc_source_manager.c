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
#include "update-client-source/arm_uc_source.h"

#include <stdint.h>
#include <stdlib.h>

static const ARM_UPDATE_SOURCE* source_registry[MAX_SOURCES];
static ARM_SOURCE_SignalEvent_t event_cb;

// storage set aside for adding event_cb to the event queue
static arm_uc_callback_t event_cb_storage = { 0 };

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

/* ==================================================================== *
 * Private Functions                                                    *
 * ==================================================================== */

/**
 * @brief Initialise a request_t struct, called when a new request
 *        have been initiated from the hub
 */
static arm_uc_error_t ARM_UCSM_RequestStructInit(request_t* request);

/**
 * @brief The SourceRegistry is an array of ARM_UPDATE_SOURCE
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryInit();
static arm_uc_error_t ARM_UCSM_SourceRegistryAdd(const ARM_UPDATE_SOURCE* source);
static arm_uc_error_t ARM_UCSM_SourceRegistryRemove(const ARM_UPDATE_SOURCE* source);

/**
 * @brief return the index of the source with the smallest cost
 * @param url Struct containing URL. NULL for default Manifest.
 * @param type The type of current request.
 * @param excludes Pointer to an array of size MAX_SOURCES to indicate
 *                 sources we want to exclude in the search. Set excludes[i]=1 to
 *                 exclude source_registry[i]
 * @param index Used to return the index of the source with the smallest cost
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryGetLowestCost(arm_uc_uri_t* uri,
                                                           query_type_t type,
                                                           uint8_t* excludes,
                                                           uint32_t* index);

/**
 * @brief Find the source of lowest cost and call the corresponding method
 *        depending on the type of the request. Retry with source of the next
 *        smallest cost if previous sources failed until the source registry
 *        is exhausted.
 */
static arm_uc_error_t ARM_UCSM_Get(request_t* req);

/**
 * @brief Catch callbacks from sources to enable error handling
 */
static void ARM_UCSM_CallbackWrapper(uint32_t event);

/**
 * @brief Retry get due to source being busy
 */
static void ARM_UCSM_AsyncRetryGet(uint32_t);

/**
 * @brief Initialise the `Request` struct
 */
static arm_uc_error_t ARM_UCSM_RequestStructInit(request_t* request)
{
    for (uint32_t i=0; i<MAX_SOURCES; i++)
    {
        request->excludes[i] = 0;
    }

    request->current_source = MAX_SOURCES;
    request->uri            = NULL;
    request->offset         = 0;
    request->type           = QUERY_TYPE_UNKNOWN;
    request->buffer         = NULL;

    return (arm_uc_error_t){ SOMA_ERR_NONE };
}

/**
 * @brief Initialise the source_registry array to NULL
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryInit()
{
    for(uint32_t i=0; i<MAX_SOURCES; i++)
    {
        source_registry[i] = NULL;
    }

    return (arm_uc_error_t){ SOMA_ERR_NONE };
}
/**
 * @brief Returns the index of the given source in the source array,
 *        or MAX_SOURCES if the source is not found
 */
static uint32_t ARM_UCSM_GetIndexOfSource(const ARM_UPDATE_SOURCE* source)
{
    uint32_t index = MAX_SOURCES;

    for(uint32_t i=0; i<MAX_SOURCES; i++)
    {
        if(source_registry[i] == source)
        {
            index = i;
            break;
        }
    }
    return index;
}

/**
 * @brief Add pointer to source to the source_registry array
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryAdd(const ARM_UPDATE_SOURCE* source)
{
    uint8_t added = 0;

    for(uint32_t i=0; i<MAX_SOURCES; i++)
    {
        if(source_registry[i] == NULL)
        {
            source_registry[i] = source;
            added = 1;
            break;
        }
    }

    if (added == 0) // registry full
    {
        return (arm_uc_error_t){ SOMA_ERR_SOURCE_REGISTRY_FULL };
    }

    return (arm_uc_error_t){ SOMA_ERR_NONE };
}

/**
 * @brief Remove pointer to source from the source_registry array
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryRemove(const ARM_UPDATE_SOURCE* source)
{
    uint32_t index = ARM_UCSM_GetIndexOfSource(source);

    if (index == MAX_SOURCES) // source not found
    {
        return (arm_uc_error_t){ SOMA_ERR_SOURCE_NOT_FOUND };
    }

    source_registry[index] = NULL;
    return (arm_uc_error_t){ SOMA_ERR_NONE };
}

/**
 * @brief return the index of the source with the smallest cost
 * @param url Struct containing URL. NULL for default Manifest.
 * @param type The type of current request.
 * @param excludes Pointer to an array of size MAX_SOURCES to indicate
 *                 sources we want to exclude in the search. Set excludes[i]=1 to
 *                 exclude source_registry[i]
 * @param index Used to return the index of the source with the smalllest cost
 */
static arm_uc_error_t ARM_UCSM_SourceRegistryGetLowestCost(arm_uc_uri_t* uri,
                                                           query_type_t type,
                                                           uint8_t* excludes,
                                                           uint32_t* index)
{
    uint32_t min_cost = UINT32_MAX;
    uint32_t min_cost_index = 0;
    arm_uc_error_t retval = (arm_uc_error_t){ SOMA_ERR_NONE };

    UC_SRCE_TRACE("+ARM_UCSM_SourceRegistryGetLowestCost");

    // loop through all sources
    for (uint32_t i=0; i<MAX_SOURCES; i++)
    {
        // if source is NULL or it has been explicitly excluded because of failure before
        if (source_registry[i] == NULL || (excludes != NULL && excludes[i] == 1))
        {
            continue;
        }

        ARM_SOURCE_CAPABILITIES cap  = source_registry[i]->GetCapabilities();

        uint32_t cost = UINT32_MAX;
        if (uri == NULL && type == QUERY_TYPE_MANIFEST_DEFAULT && cap.manifest_default == 1)
        {
            retval = source_registry[i]->GetManifestDefaultCost(&cost);
        }
        else if (uri != NULL && type == QUERY_TYPE_MANIFEST_URL && cap.manifest_url == 1)
        {
            retval = source_registry[i]->GetManifestURLCost(uri, &cost);
        }
        else if (uri != NULL && type == QUERY_TYPE_FIRMWARE && cap.firmware == 1)
        {
            retval = source_registry[i]->GetFirmwareURLCost(uri, &cost);
        }
        else if (uri != NULL && type == QUERY_TYPE_KEYTABLE && cap.keytable == 1)
        {
            retval = source_registry[i]->GetKeytableURLCost(uri, &cost);
        }

        if (retval.code != SRCE_ERR_NONE) // get cost from source i failed
        {
            // cost is invalid at this point, hence skip to next iteration
            UC_SRCE_TRACE("-ARM_UCSM_SourceRegistryGetLowestCost: invalid cost for %" PRIu32, i);
            continue;
        }

        // record the cost and i if cost is lower
        if (min_cost > cost)
        {
            min_cost = cost;
            min_cost_index = i;
        }
    }

    if (min_cost == UINT32_MAX)
    {
        UC_SRCE_TRACE("-ARM_UCSM_SourceRegistryGetLowestCost: Error - No route");
        return (arm_uc_error_t){ SOMA_ERR_NO_ROUTE_TO_SOURCE };
    }

    *index = min_cost_index;
    UC_SRCE_TRACE("-ARM_UCSM_SourceRegistryGetLowestCost: index = %" PRIu32, min_cost_index);
    return (arm_uc_error_t){ SOMA_ERR_NONE };
}

/**
 * @brief Find the source of lowest cost and call the corresponding method
 *        depending on the type of the request. Retry with source of the next
 *        smallest cost if previous sources failed until the source registry
 *        is exhausted.
 */
static arm_uc_error_t ARM_UCSM_Get(request_t* req)
{
    UC_SRCE_TRACE("+ARM_UCSM_Get");
    if (req->uri != NULL)
    {
        UC_SRCE_TRACE("with %" PRIx32 ", host [%s], path [%s], type %" PRIu32,
                req->uri, req->uri->host,req->uri->path, req->type);
    }
    else
    {
        UC_SRCE_TRACE("with NULL, type %" PRIu32,
                req->type);
    }

    uint32_t index = 0;

    // get the source of lowest cost
    arm_uc_error_t retval = ARM_UCSM_SourceRegistryGetLowestCost(req->uri,
                                                                 req->type,
                                                                 req->excludes,
                                                                 &index);
    if (retval.code != SOMA_ERR_NONE)
    {
        UC_SRCE_TRACE("-ARM_UCSM_Get: error retval.code %" PRIu32, retval.code);
        return retval;
    }

    if ((req->uri == NULL) && (req->type == QUERY_TYPE_MANIFEST_DEFAULT))
    {
        UC_SRCE_TRACE("calling source %" PRIu32 " GetManifestDefault", index);
        retval = source_registry[index]->GetManifestDefault(req->buffer, req->offset);
    }
    else if ((req->uri != NULL) && (req->type == QUERY_TYPE_MANIFEST_URL))
    {
        UC_SRCE_TRACE("calling source %" PRIu32 " GetManifestURL with %" PRIx32, index, req->uri);
        retval = source_registry[index]->GetManifestURL(req->uri, req->buffer, req->offset);
    }
    else if ((req->uri != NULL) && (req->type == QUERY_TYPE_FIRMWARE))
    {
        UC_SRCE_TRACE("calling source %" PRIu32 " GetFirmwareFragment with %" PRIx32, index, req->uri);
        retval = source_registry[index]->GetFirmwareFragment(req->uri, req->buffer, req->offset);
    }
    else if ((req->uri != NULL) && (req->type == QUERY_TYPE_KEYTABLE))
    {
        UC_SRCE_TRACE("calling source %" PRIu32 " GetKeytableURL with %" PRIx32, index, req->uri);
        retval = source_registry[index]->GetKeytableURL(req->uri, req->buffer);
    }
    else
    {
        if (req->uri == NULL ) {
            UC_SRCE_TRACE("-ARM_UCSM_Get: Error - Invalid parameter (URI == NULL)");
        } else {
        	UC_SRCE_TRACE("-ARM_UCSM_Get: Error - Invalid parameter (unknown request type)");
        }
        return (arm_uc_error_t){ SOMA_ERR_INVALID_PARAMETER };
    }

    if (retval.code == SRCE_ERR_BUSY)
    {
        UC_SRCE_TRACE("-ARM_UCSM_Get: Error - Busy -> PostCallback AsyncRetryGet");
        ARM_UC_PostCallback(&event_cb_storage, ARM_UCSM_AsyncRetryGet, 0);
        return (arm_uc_error_t){ SOMA_ERR_NONE };
    }
    else if (retval.error != ERR_NONE)
    {
        // failure, try source with the next smallest cost
        req->excludes[index] = 1;
        UC_SRCE_TRACE("-ARM_UCSM_Get: Error - failure (try source with the next smallest cost)");
        return ARM_UCSM_Get(req);
    }

    // record the index of source handling the get request currently
    req->current_source = index;
    UC_SRCE_TRACE("-ARM_UCSM_Get: Using source %" PRIu32, index);

    return (arm_uc_error_t){ SOMA_ERR_NONE };
}

/**
 * @brief If source is busy ARM_UCSM_AsyncRetryGet is registered with
          the event queue so it is called again to retry the same source
 */
static void ARM_UCSM_AsyncRetryGet(uint32_t unused)
{
    (void) unused;

    UC_SRCE_TRACE("+ARM_UCSM_AsyncRetryGet");
    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.error != ERR_NONE)
    {
        ARM_UCSM_RequestStructInit(&request_in_flight);
        ARM_UC_PostCallback(&event_cb_storage, event_cb, ARM_UC_SM_EVENT_ERROR);
    }
    UC_SRCE_TRACE("-ARM_UCSM_AsyncRetryGet");
}

/**
 * @brief Translate source event into source manager event
 */
static ARM_UC_SM_Event_t ARM_UCSM_TranslateEvent(uint32_t source_event)
{
    ARM_UC_SM_Event_t event = ARM_UC_SM_EVENT_ERROR;

    switch(source_event)
    {
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
    UC_SRCE_TRACE("+ARM_UCSM_CallbackWrapper");
    UC_SRCE_TRACE("source_event == %" PRIu32, source_event);
    ARM_UC_SM_Event_t event = ARM_UCSM_TranslateEvent(source_event);

    if (event == ARM_UC_SM_EVENT_ERROR && request_in_flight.type != QUERY_TYPE_UNKNOWN)
    {
        UC_SRCE_TRACE("ARM_UCSM_TranslateEvent event error == %" PRIu32, event);
        request_in_flight.excludes[request_in_flight.current_source] = 1;
        arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
        if (retval.code != SOMA_ERR_NONE)
        {
            UC_SRCE_TRACE("ARM_UCSM_Get() retval.code == %" PRIu32, retval.code);
            ARM_UCSM_RequestStructInit(&request_in_flight);
            ARM_UC_PostCallback(&event_cb_storage, event_cb, event);
        }
    }
    else
    {
        UC_SRCE_TRACE("");
        ARM_UCSM_RequestStructInit(&request_in_flight);
        ARM_UC_PostCallback(&event_cb_storage, event_cb, event);
    }
    UC_SRCE_TRACE("-ARM_UCSM_CallbackWrapper");
}

/* ==================================================================== *
 * Public API                                                           *
 * ==================================================================== */

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
    for (size_t i = 0; i < MAX_SOURCES; i++)
    {
        if (source_registry[i] != NULL)
        {
            source_registry[i]->Uninitialize();
            source_registry[i] = NULL;
        }
    }
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UCSM_AddSource(const ARM_UPDATE_SOURCE* source)
{
    if (ARM_UCSM_GetIndexOfSource(source) != MAX_SOURCES)
    {
        // Source already added, don't add again
        // TODO: should this return SOMA_ERR_NONE or a new error
        // SOMA_ERR_ALREADY_PRESENT?
        return (arm_uc_error_t){ SOMA_ERR_NONE };
    }
    source->Initialize(ARM_UCSM_CallbackWrapper);
    return ARM_UCSM_SourceRegistryAdd(source);
}

arm_uc_error_t ARM_UCSM_RemoveSource(const ARM_UPDATE_SOURCE* source)
{
    arm_uc_error_t err = ARM_UCSM_SourceRegistryRemove(source);
    if (err.code == SOMA_ERR_NONE)
    {
        // Call 'uninitialize' only if the source was found (and removed)
        source->Uninitialize();
    }
    return err;
}

/* All the `Get` APIs map into `ARM_UCSM_Get` */

arm_uc_error_t ARM_UCSM_GetManifest(arm_uc_buffer_t* buffer, uint32_t offset)
{
    UC_SRCE_TRACE("+ARM_UCSM_GetManifest");
    ARM_UCSM_RequestStructInit(&request_in_flight);
    request_in_flight.buffer = buffer;
    request_in_flight.offset = offset;
    request_in_flight.type   = QUERY_TYPE_MANIFEST_DEFAULT;

    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.code != SOMA_ERR_NONE)
    {
        ARM_UCSM_RequestStructInit(&request_in_flight);
    }

    UC_SRCE_TRACE("-ARM_UCSM_GetManifest");
    return retval;
}

arm_uc_error_t ARM_UCSM_GetManifestFrom(arm_uc_uri_t* uri,
                                        arm_uc_buffer_t* buffer,
                                        uint32_t offset)
{
    UC_SRCE_TRACE("+ARM_UCSM_GetManifestFrom");
    ARM_UCSM_RequestStructInit(&request_in_flight);
    request_in_flight.uri    = uri;
    request_in_flight.buffer = buffer;
    request_in_flight.offset = offset;
    request_in_flight.type   = QUERY_TYPE_MANIFEST_URL;

    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.code != SOMA_ERR_NONE)
    {
        ARM_UCSM_RequestStructInit(&request_in_flight);
    }

    UC_SRCE_TRACE("-ARM_UCSM_GetManifestFrom");
    return retval;
}

arm_uc_error_t ARM_UCSM_GetFirmwareFragment(arm_uc_uri_t* uri,
                                            arm_uc_buffer_t* buffer,
                                            uint32_t offset)
{
    UC_SRCE_TRACE("+ARM_UCSM_GetFirmwareFragment");
    ARM_UCSM_RequestStructInit(&request_in_flight);
    request_in_flight.uri    = uri;
    request_in_flight.buffer = buffer;
    request_in_flight.offset = offset;
    request_in_flight.type   = QUERY_TYPE_FIRMWARE;

    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.code != SOMA_ERR_NONE)
    {
        ARM_UCSM_RequestStructInit(&request_in_flight);
    }

    UC_SRCE_TRACE("-ARM_UCSM_GetFirmwareFragment");
    return retval;
}

arm_uc_error_t ARM_UCSM_GetKeytable(arm_uc_uri_t* uri, arm_uc_buffer_t* buffer)
{
    UC_SRCE_TRACE("+ARM_UCSM_GetKeytable");
    ARM_UCSM_RequestStructInit(&request_in_flight);
    request_in_flight.uri    = uri;
    request_in_flight.buffer = buffer;
    request_in_flight.type   = QUERY_TYPE_KEYTABLE;

    arm_uc_error_t retval = ARM_UCSM_Get(&request_in_flight);
    if (retval.code != SOMA_ERR_NONE)
    {
        ARM_UCSM_RequestStructInit(&request_in_flight);
    }

    UC_SRCE_TRACE("+ARM_UCSM_GetKeytable");
    return retval;
}

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
