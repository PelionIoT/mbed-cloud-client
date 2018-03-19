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

#include "update-client-source-http/arm_uc_source_http.h"
#include "update-client-source-http/arm_uc_source_http_extra.h"

#include "update-client-source-http-socket/arm_uc_http_socket.h"

#include <time.h>
#include <stdio.h>
#include <stdbool.h>

#define ARM_UCS_DEFAULT_COST (1000)
#define ARM_UCS_HASH_LENGTH  (40)

typedef struct _ARM_UCS_Configuration
{
    arm_uc_uri_t manifest;
    uint32_t interval;
    uint32_t currentCost;
    time_t lastPoll;
    int8_t hash[ARM_UCS_HASH_LENGTH];
    void (*eventHandler)(uint32_t event);
} ARM_UCS_Configuration_t;

static ARM_UCS_Configuration_t default_config = {
    .manifest = {
        .size_max = 0,
        .size = 0,
        .ptr = NULL,
        .scheme = URI_SCHEME_NONE,
        .port = 0,
        .host = NULL,
        .path = NULL
    },
    .interval = 0,
    .currentCost = 0xFFFFFFFF,
    .lastPoll = 0,
    .hash = { 0 },
    .eventHandler = 0
};

typedef enum {
    STATE_UCS_HTTP_IDLE,
    STATE_UCS_HTTP_MANIFEST,
    STATE_UCS_HTTP_FIRMWARE,
    STATE_UCS_HTTP_KEYTABLE,
    STATE_UCS_HTTP_HASH
} arm_ucs_http_state_t;

#define MAX_RETRY 3
typedef struct {
    arm_ucs_http_state_t stateHttp;
    arm_uc_uri_t *uri;
    arm_uc_buffer_t *buffer;
    uint32_t offset;
    uint8_t retryCount;
} arm_ucs_state_t;

static arm_ucs_state_t arm_ucs_state;

static arm_uc_http_socket_context_t arm_uc_http_socket_context = { 0 };

/* Helper function for resetting internal state */
static inline void uc_state_reset()
{
    arm_ucs_state.stateHttp  = STATE_UCS_HTTP_IDLE;
    arm_ucs_state.uri        = NULL;
    arm_ucs_state.buffer     = NULL;
    arm_ucs_state.offset     = 0;
    arm_ucs_state.retryCount = 0;
}

/* Helper function for checking if the stored hash is all zeros */
static inline bool hash_is_zero()
{
    bool result = true;

    for (uint32_t index = 0; index < ARM_UCS_HASH_LENGTH; index++)
    {
        if (default_config.hash[index] != 0)
        {
            result = false;
            break;
        }
    }

    return result;
}

static arm_uc_error_t ARM_UCS_Get(arm_uc_uri_t* uri,
                                  arm_uc_buffer_t* buffer,
                                  uint32_t offset,
                                  arm_ucs_http_state_t newHttpState);

/******************************************************************************/
/* ARM Update Client Source Extra                                             */
/******************************************************************************/

/**
 * @brief Set URI location for the default manifest.
 * @details The default manifest is polled regularly and generates a
 *          notification upon change. The URI struct and the content pointer to
 *          must be valid throughout the lifetime of the application.
 *
 * @param uri URI struct with manifest location.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_SetDefaultManifestURL(arm_uc_uri_t* uri)
{
    UC_SRCE_TRACE("ARM_UCS_SetDefaultManifestURL");

    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    if (uri != 0)
    {
        /* check scheme is http */
        if (uri->scheme == URI_SCHEME_HTTP)
        {
            /* copy pointers to local struct */
            default_config.manifest = *uri;

            result = (arm_uc_error_t){ SRCE_ERR_NONE };
        }
    }

    return result;
}

/**
 * @brief Set polling interval for notification generation.
 * @details The default manifest location is polled with this interval.
 *
 * @param seconds Seconds between each poll.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_SetPollingInterval(uint32_t seconds)
{
    UC_SRCE_TRACE("ARM_UCS_SetPollingInterval");

    default_config.interval = seconds;

    return (arm_uc_error_t){ SRCE_ERR_NONE };
}

/**
 * @brief Main function for the Source.
 * @details This function will query the default manifest location and generate
 *          a notification if it has changed since the last time it was checked.
 *          The number of queries generated is bound by the polling interval.
 *
 *          This function should be used on systems with timed callbacks.
 *
 * @return Seconds until the next polling interval.
 */
uint32_t ARM_UCS_CallMultipleTimes(arm_uc_buffer_t* hash_buffer)
{
    uint32_t result = default_config.interval;
    time_t unixtime = time(NULL);
    uint32_t elapsed = unixtime - default_config.lastPoll;

    if ((default_config.eventHandler == NULL) ||
        (arm_ucs_state.stateHttp != STATE_UCS_HTTP_IDLE) ||
        (hash_buffer == NULL))
    {
        return default_config.interval;
    }

    if (elapsed >= default_config.interval)
    {
        UC_SRCE_TRACE("ARM_UCS_CallMultipleTimes");

        // poll default URI
        default_config.lastPoll = unixtime;

        // get resource hash
        arm_ucs_state.stateHttp = STATE_UCS_HTTP_HASH;
        arm_ucs_state.buffer = hash_buffer;

        arm_uc_error_t retval = ARM_UCS_HttpSocket_GetHash(&default_config.manifest,
                                                           arm_ucs_state.buffer);
        if (retval.error != ERR_NONE)
        {
            uc_state_reset();
            return default_config.interval;
        }
    }
    else
    {
        result = (elapsed > 0) ? default_config.interval - elapsed : default_config.interval;
    }

    return result;
}


ARM_UCS_HTTPSourceExtra_t ARM_UCS_HTTPSourceExtra =
{
    .SetDefaultManifestURL = ARM_UCS_SetDefaultManifestURL,
    .SetPollingInterval    = ARM_UCS_SetPollingInterval,
    .CallMultipleTimes     = ARM_UCS_CallMultipleTimes
};

/******************************************************************************/
/* ARM Update Client Source                                                   */
/******************************************************************************/

static void ARM_UCS_ProcessHash()
{
    UC_SRCE_TRACE("ARM_UCS_ProcessHash");

#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
    printf("hash: ");
    for (uint32_t index = 0; index < arm_ucs_state.buffer->size; index++)
    {
        printf("%c", arm_ucs_state.buffer->ptr[index]);
    }
    printf("\r\n");
#endif

    bool hashIsNew = false;
    bool firstBoot = hash_is_zero();

    /* compare hash with previous check */
    for (uint32_t index = 0; index < arm_ucs_state.buffer->size; index++)
    {
        /* compare hash */
        if (default_config.hash[index] != arm_ucs_state.buffer->ptr[index])
        {
            /* store new hash */
            default_config.hash[index] = arm_ucs_state.buffer->ptr[index];

            hashIsNew = true;
        }
    }

    /* Request complete, reset state */
    uc_state_reset();

    /* Signal that a new manifest is available if the hash is non-zero
       and different from the last check.
    */
    if (hashIsNew && !firstBoot)
    {
        if (default_config.eventHandler)
        {
            default_config.eventHandler(EVENT_NOTIFICATION);
        }
    }
}

static void ARM_UCS_HTTPEvent(uint32_t event)
{
    UC_SRCE_TRACE("ARM_UCS_HTTPEvent");

    switch (event)
    {
        /* Hash received, process it */
        case UCS_HTTP_EVENT_HASH:
            UC_SRCE_TRACE("UCS_HTTP_EVENT_HASH");

            ARM_UCS_ProcessHash();
            break;

        /* Download complete */
        case UCS_HTTP_EVENT_DOWNLOAD:
            {
                UC_SRCE_TRACE("UCS_HTTP_EVENT_DOWNLOAD");

                /* cache state before resetting it */
                arm_ucs_http_state_t previous_state = arm_ucs_state.stateHttp;

                /* reset internal state */
                uc_state_reset();

                /* signal successful download based on request */
                if  (default_config.eventHandler)
                {
                    if (previous_state == STATE_UCS_HTTP_MANIFEST)
                    {
                        default_config.eventHandler(EVENT_MANIFEST);
                    }
                    else if (previous_state == STATE_UCS_HTTP_FIRMWARE)
                    {
                        default_config.eventHandler(EVENT_FIRMWARE);
                    }
                    else if (previous_state == STATE_UCS_HTTP_KEYTABLE)
                    {
                        default_config.eventHandler(EVENT_KEYTABLE);
                    }
                    else
                    {
                        default_config.eventHandler(EVENT_ERROR);
                    }
                }
            }
            break;

        /* Socket error */
        case UCS_HTTP_EVENT_ERROR:
            {
                UC_SRCE_TRACE("UCS_HTTP_EVENT_ERROR");

                /* Treat polling as retry when reading hash */
                if (arm_ucs_state.stateHttp == STATE_UCS_HTTP_HASH)
                {
                    /* If the stored hash is zero, this error is most likely
                       generated due to the default manifest not being uploaded
                       yet. Mark the stored hash as non-zero, so the first time
                       the device successfully retrieves a hash we download the
                       manifest.
                    */
                    bool result = hash_is_zero();

                    if (result)
                    {
                        default_config.hash[0] = 0xFF;
                    }

                    /* reset state but don't take any further action */
                    uc_state_reset();
                }
                /* Perform MAX_RETRY otherwise */
                else if (arm_ucs_state.retryCount < MAX_RETRY)
                {
                    /* restore buffer size on retry */
                    arm_ucs_state.buffer->size = arm_ucs_state.buffer->size_max;

                    /* restore stateHttp */
                    arm_ucs_http_state_t previous_state = arm_ucs_state.stateHttp;
                    arm_ucs_state.stateHttp = STATE_UCS_HTTP_IDLE;

                    arm_uc_error_t retval = ARM_UCS_Get(arm_ucs_state.uri,
                                                        arm_ucs_state.buffer,
                                                        arm_ucs_state.offset,
                                                        previous_state);

                    /* retry unsuccessful */
                    if (retval.error != ERR_NONE)
                    {
                        /* reset internal state */
                        uc_state_reset();

                        /* generate error event */
                        if (default_config.eventHandler)
                        {
                            default_config.eventHandler(EVENT_ERROR);
                        }
                    }
                }
                else
                {
                    /* reset internal state */
                    uc_state_reset();

                    /* generate error event */
                    if (default_config.eventHandler)
                    {
                        default_config.eventHandler(EVENT_ERROR);
                    }
                }
            }
            break;

        /* supplied buffer not large enough */
        case UCS_HTTP_EVENT_ERROR_BUFFER_SIZE:
            {
                /* reset internal state */
                uc_state_reset();

                /* generate error event */
                if (default_config.eventHandler)
                {
                    default_config.eventHandler(EVENT_ERROR_BUFFER_SIZE);
                }
            }
            break;

        default:
            UC_SRCE_TRACE("Unknown event");
            break;
    }
}

/**
 * @brief Get driver version.
 * @return Driver version.
 */
uint32_t ARM_UCS_GetVersion(void)
{
    UC_SRCE_TRACE("ARM_UCS_GetVersion");

    return 0;
}

/**
 * @brief Get Source capabilities.
 * @return Struct containing capabilites. See definition above.
 */
ARM_SOURCE_CAPABILITIES ARM_UCS_GetCapabilities(void)
{
    UC_SRCE_TRACE("ARM_UCS_GetCapabilities");

    ARM_SOURCE_CAPABILITIES result = {
        .notify = 0,
        .manifest_default = 0,
        .manifest_url = 0,
        .firmware = 0,
        .keytable = 0
    };

    /* the event handler must be set before module can be used */
    if (default_config.eventHandler != 0)
    {
        result.manifest_url = 1;
        result.firmware = 1;
        result.keytable = 1;

        /* notification requires that the default manifest is set */
        if ((default_config.manifest.port != 0) || (default_config.interval != 0))
        {
            result.notify = 1;
            result.manifest_default = 1;
        }
    }

    return result;
}

/**
 * @brief Initialize Source.
 * @details Function pointer to event handler is passed as argument.
 *
 * @param cb_event Function pointer to event handler. See events above.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Initialize(ARM_SOURCE_SignalEvent_t cb_event)
{
    UC_SRCE_TRACE("ARM_UCS_Initialize");

    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    if (cb_event != 0)
    {
        default_config.currentCost = ARM_UCS_DEFAULT_COST;
        default_config.eventHandler = cb_event;
        result = (arm_uc_error_t){ SRCE_ERR_NONE };

        /* register http callback handler */
        ARM_UCS_HttpSocket_Initialize(&arm_uc_http_socket_context,
                                      ARM_UCS_HTTPEvent);
    }

    uc_state_reset();
    return result;
}

/**
 * @brief Uninitialized Source.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_Uninitialize(void)
{
    UC_SRCE_TRACE("ARM_UCS_Uninitialize");

    return (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };
}

/**
 * @brief Cost estimation for retrieving manifest from the default location.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The manifest is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
 *
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetManifestDefaultCost(uint32_t* cost)
{
    UC_SRCE_TRACE("ARM_UCS_GetManifestDefaultCost");

    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    if (cost != 0)
    {
        *cost = default_config.currentCost;
        result = (arm_uc_error_t){ SRCE_ERR_NONE };
    }

    return result;
}

/**
 * @brief Cost estimation for retrieving manifest from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The manifest is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve manifest from this Source.
 *
 * @param uri URI struct with manifest location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetManifestURLCost(arm_uc_uri_t* uri, uint32_t* cost)
{
    UC_SRCE_TRACE("ARM_UCS_GetManifestURLCost");

    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    /* return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0))
    {
        *cost = default_config.currentCost;
        result = (arm_uc_error_t){ SRCE_ERR_NONE };
    }
    /* return no-path cost if URL is invalid */
    else if (cost != 0)
    {
        *cost = 0xFFFFFFFF;
        result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };
    }

    return result;
}

/**
 * @brief Cost estimation for retrieving firmware from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The firmware is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve firmware from this Source.
 *
 * @param uri URI struct with firmware location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetFirmwareURLCost(arm_uc_uri_t* uri, uint32_t* cost)
{
    UC_SRCE_TRACE("ARM_UCS_GetFirmwareURLCost");

    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    /* return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0))
    {
        *cost = default_config.currentCost;
        result = (arm_uc_error_t){ SRCE_ERR_NONE };
    }
    /* return no-path cost if URL is invalid */
    else if (cost != 0)
    {
        *cost = 0xFFFFFFFF;
        result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };
    }

    return result;
}

/**
 * @brief Cost estimation for retrieving key table from URL.
 * @details The estimation can vary over time and should not be cached too long.
 *          0x00000000 - The firmware is already downloaded.
 *          0xFFFFFFFF - Cannot retrieve firmware from this Source.
 *
 * @param uri URI struct with keytable location.
 * @param cost Pointer to variable for the return value.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetKeytableURLCost(arm_uc_uri_t* uri, uint32_t* cost)
{
    UC_SRCE_TRACE("ARM_UCS_GetKeytableURLCost");

    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    /* return default cost regardless of actual uri location */
    if ((uri != 0) && (cost != 0))
    {
        *cost = default_config.currentCost;
        result = (arm_uc_error_t){ SRCE_ERR_NONE };
    }
    /* return no-path cost if URL is invalid */
    else if (cost != 0)
    {
        *cost = 0xFFFFFFFF;
        result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };
    }

    return result;
}

/**
 * @brief (Internal) Retrieve resource according to the given parameters
 *        in arm_ucs_state and store the returned data in the buffer in arm_ucs_state.
 * @param uri URI struct with resource location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @param offset Offset to retrieve fragment from.
 * @param newHttpState The intended new http state to be assigned to arm_ucs_state.stateHttp
 */
static arm_uc_error_t ARM_UCS_Get(arm_uc_uri_t* uri,
                                  arm_uc_buffer_t* buffer,
                                  uint32_t offset,
                                  arm_ucs_http_state_t newHttpState)
{
    UC_SRCE_TRACE("ARM_UCS_Get");

    // check current state
    if (default_config.eventHandler == 0)
    {
        UC_SRCE_ERR_MSG("Uninitialized");

        return (arm_uc_error_t){ SRCE_ERR_UNINITIALIZED };
    }
    else if (arm_ucs_state.stateHttp != STATE_UCS_HTTP_IDLE)
    {
        UC_SRCE_ERR_MSG("Busy");

        return (arm_uc_error_t){ SRCE_ERR_BUSY };
    }

    // assign new state
    arm_ucs_state.stateHttp      = newHttpState;
    arm_ucs_state.uri            = uri;
    arm_ucs_state.buffer         = buffer;
    arm_ucs_state.offset         = offset;

    // Call the socket layer to get the requested data
    arm_uc_error_t result = (arm_uc_error_t){ SRCE_ERR_INVALID_PARAMETER };

    while ((result.error != ERR_NONE) && (arm_ucs_state.retryCount++ < MAX_RETRY))
    {
        // restore buffer size on retry
        arm_ucs_state.buffer->size = arm_ucs_state.buffer->size_max;

        switch(arm_ucs_state.stateHttp)
        {
            case STATE_UCS_HTTP_MANIFEST:
            case STATE_UCS_HTTP_FIRMWARE:
                if (arm_ucs_state.buffer != 0 && arm_ucs_state.uri != 0)
                {
                    result = ARM_UCS_HttpSocket_GetFragment(arm_ucs_state.uri,
                                                            arm_ucs_state.buffer,
                                                            arm_ucs_state.offset);
                }
                break;

            case STATE_UCS_HTTP_KEYTABLE:
                if (arm_ucs_state.buffer != 0 && arm_ucs_state.uri != 0)
                {
                    result = ARM_UCS_HttpSocket_GetFile(arm_ucs_state.uri,
                                                        arm_ucs_state.buffer);
                }
                break;

            default:
                UC_SRCE_ERR_MSG("Invalid request parameter");
                result = (arm_uc_error_t) { SRCE_ERR_INVALID_PARAMETER };
                break;
        }
    }

    if (result.error != ERR_NONE)
    {
        uc_state_reset();
    }

    return result;
}

/**
 * @brief Retrieve manifest from the default location.
 * @details Manifest is stored in supplied buffer.
 *          Event is generated once manifest is in buffer.
 *
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetManifestDefault(arm_uc_buffer_t* buffer, uint32_t offset)
{
    UC_SRCE_TRACE("ARM_UCS_GetManifestDefault");

    return ARM_UCS_Get(&default_config.manifest, buffer, offset, STATE_UCS_HTTP_MANIFEST);
}

/**
 * @brief Retrieve manifest from URL.
 * @details Manifest is stored in supplied buffer.
 *          Event is generated once manifest is in buffer.
 *
 * @param uri URI struct with manifest location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 *
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetManifestURL(arm_uc_uri_t* uri, arm_uc_buffer_t* buffer, uint32_t offset)
{
    UC_SRCE_TRACE("ARM_UCS_GetManifestURL");

    return ARM_UCS_Get(uri, buffer, offset, STATE_UCS_HTTP_MANIFEST);
}

/**
 * @brief Retrieve firmware fragment.
 * @details Firmware fragment is stored in supplied buffer.
 *          Event is generated once fragment is in buffer.
 *
 * @param uri URI struct with firmware location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @param offset Firmware offset to retrieve fragment from.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetFirmwareFragment(arm_uc_uri_t* uri, arm_uc_buffer_t* buffer, uint32_t offset)
{
    UC_SRCE_TRACE("ARM_UCS_GetFirmwareFragment");

    return ARM_UCS_Get(uri, buffer, offset, STATE_UCS_HTTP_FIRMWARE);
}

/**
 * @brief Retrieve a key table from a URL.
 * @details Key table is stored in supplied buffer.
 *          Event is generated once fragment is in buffer.
 *
 * @param uri URI struct with keytable location.
 * @param buffer Struct containing byte array, maximum size, and actual size.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_GetKeytableURL(arm_uc_uri_t* uri, arm_uc_buffer_t* buffer)
{
    UC_SRCE_TRACE("ARM_UCS_GetKeytableURL");

    return ARM_UCS_Get(uri, buffer, UINT32_MAX, STATE_UCS_HTTP_KEYTABLE);
}

ARM_UPDATE_SOURCE ARM_UCS_HTTPSource =
{
    .GetVersion             = ARM_UCS_GetVersion,
    .GetCapabilities        = ARM_UCS_GetCapabilities,
    .Initialize             = ARM_UCS_Initialize,
    .Uninitialize           = ARM_UCS_Uninitialize,
    .GetManifestDefaultCost = ARM_UCS_GetManifestDefaultCost,
    .GetManifestURLCost     = ARM_UCS_GetManifestURLCost,
    .GetFirmwareURLCost     = ARM_UCS_GetFirmwareURLCost,
    .GetKeytableURLCost     = ARM_UCS_GetKeytableURLCost,
    .GetManifestDefault     = ARM_UCS_GetManifestDefault,
    .GetManifestURL         = ARM_UCS_GetManifestURL,
    .GetFirmwareFragment    = ARM_UCS_GetFirmwareFragment,
    .GetKeytableURL         = ARM_UCS_GetKeytableURL
};
