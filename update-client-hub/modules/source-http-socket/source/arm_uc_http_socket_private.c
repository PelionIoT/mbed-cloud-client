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

#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_FEATURE_FW_SOURCE_HTTP) && (ARM_UC_FEATURE_FW_SOURCE_HTTP == 1)

/**
 * This file implements a streaming update source over HTTP.
 * See arm_uc_http.c for more info on the pre-fetch and caching.
 * The control of caching functionality resides largely in the open_* fields
 *   of the 'context' structure being used to manage the download.
 */

// If enabled, text messages will be printed to output to give live feedback for QA testing.
// This is intended for QA testing ***only***, and should not be enabled for any other reason.
#if defined(ARM_UC_HTTP_RESUME_TEST_MESSAGES_ENABLE) && (ARM_UC_HTTP_RESUME_TEST_MESSAGES_ENABLE == 1)
#define ARM_UC_QA_TRACE_ENABLE 1
#endif

#include "update-client-resume-engine/arm_uc_resume.h"
#include "arm_uc_http_socket_private.h"
#include <pal.h>

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "arm_uc_socket_help.h"

// FORWARD DECLARATIONS.
// ---------------------

#define ISR_EVENT_MASK (0x80)

static void arm_uc_http_socket_isr(
    void *an_event_origin);

static arm_uc_error_t arm_uc_http_install_isr_event(
    arm_uc_http_socket_event_t an_event);

static arm_uc_error_t arm_uc_http_install_app_event(
    arm_uc_http_socket_event_t an_event);


// DATA & CONFIG.
// --------------

/* Pointer to struct containing all global variables.
 * Can be dynamically allocated and deallocated.
 */
static arm_uc_http_socket_context_t *context = NULL;

/* Number of frags to be requested per GET request (burst) */
uint32_t frags_per_burst = ARM_UC_MULTI_FRAGS_PER_HTTP_BURST;

// This fills in the values from the header if specified non-default.

// Exponentiation factor tries to balance speed with power considerations.
// Resume is very aggressive to start but backs off more quickly too.
#if !defined(ARM_UC_HTTP_RESUME_EXPONENTIATION_FACTOR)
#define ARM_UC_HTTP_RESUME_EXPONENTIATION_FACTOR (ARM_UC_HTTP_RESUME_DEFAULT_EXPONENTIATION_FACTOR)
#elif ARM_UC_HTTP_RESUME_EXPONENTIATION_FACTOR < 0
#error "HTTP resume attempt delay exponentiation factor must be non-negative."
#endif

// Delay parameters have minimum and maximum values.
// In general the minimum is a hard limit, because going too low will interfere with the algorithm,
//   given that there are various phases which need to coordinate.
// The maximum delays have no hard limits, but issue a warning if they seem unreasonably long,
//   which is intended to catch errors like extra zeroes in the #defined values.

#define MIN_INITIAL_ATTEMPT_DELAY_LIMIT         (1*1000)
#define ADVISABLE_INITIAL_ATTEMPT_DELAY_LIMIT   (60*60*1000)
#define MAX_INITIAL_ATTEMPT_DELAY_LIMIT         (24*60*60*1000UL)

#define ADVISABLE_LONGEST_ATTEMPT_DELAY_LIMIT   (24*60*60*1000UL)
#define MAX_LONGEST_ATTEMPT_DELAY_LIMIT         (7*24*60*60*1000UL)

#define ADVISABLE_ACTIVITY_TIME_LIMIT           (30*24*60*60*1000UL)
#define MAX_ACTIVITY_TIME_LIMIT                 (30*24*60*60*1000UL)

// Initial delay between resumption attempts.
// Default and lower bound is 1 seconds, maximum is 1 hour.
// Because we now don't have retries at the source level, we cover that fault profile with resume/8.
#if !defined(ARM_UC_HTTP_RESUME_INITIAL_DELAY_SECS)
#define ARM_UC_HTTP_RESUME_INITIAL_DELAY_SECS   (ARM_UC_HTTP_RESUME_DEFAULT_INITIAL_DELAY_SECS)
#elif ARM_UC_HTTP_RESUME_INITIAL_DELAY_SECS < 0
#error "HTTP resume initial attempt delay must be non-negative."
#endif
#define ARM_UC_HTTP_RESUME_INITIAL_DELAY_MSECS  ((ARM_UC_HTTP_RESUME_INITIAL_DELAY_SECS)*1000UL)

// Greatest delay between resumption attempts.
// Default to 1 hour, lower bound is minimum delay, maximum 7 day.
#if !defined(ARM_UC_HTTP_RESUME_MAXIMUM_DELAY_SECS)
#define ARM_UC_HTTP_RESUME_MAXIMUM_DELAY_SECS   (ARM_UC_HTTP_RESUME_DEFAULT_MAXIMUM_DELAY_SECS)
#elif ARM_UC_HTTP_RESUME_MAXIMUM_DELAY_SECS < 0
#error "HTTP resume maximum attempt delay must be non-negative."
#endif
#define ARM_UC_HTTP_RESUME_MAXIMUM_DELAY_MSECS         ((ARM_UC_HTTP_RESUME_MAXIMUM_DELAY_SECS)*1000UL)

// Stop resumptions after this period has elapsed.
// Default to 24 hours, lower bound is maximum delay, maximum is 30 days.
#if !defined(ARM_UC_HTTP_RESUME_MAXIMUM_DOWNLOAD_TIME_SECS)
#define ARM_UC_HTTP_RESUME_MAXIMUM_DOWNLOAD_TIME_SECS (ARM_UC_HTTP_RESUME_DEFAULT_MAXIMUM_DOWNLOAD_TIME_SECS)
#elif ARM_UC_HTTP_RESUME_MAXIMUM_DOWNLOAD_TIME_SECS < 0
#error "HTTP resume maximum download time must be non-negative"
#endif
#define ARM_UC_HTTP_RESUME_MAXIMUM_DOWNLOAD_TIME_MSECS ((ARM_UC_HTTP_RESUME_MAXIMUM_DOWNLOAD_TIME_SECS)*1000UL)

// These values are not user-configurable because they are largely dependent on the resume settings,
//   inasmuch as the expected behaviour of the link implies the interval behaviour.

// The number of attempts to push the state machine along, assuming events have been dropped,
//   and the periods of time between the intervals.
#define ARM_UC_HTTP_RESUME_NUM_INTERVALS           2

// This is the period of time before a socket is timed out as being behind,
//   but not necessarily in error, given that events can go missing over the network.
//   Instead we use this to optimistically bump the socket along, in the expectation that it will
//   perhaps have had an event but not reported it, unlike what we would have expected in a perfect world.
#define ARM_UC_HTTP_RESUME_INTERVAL_DELAY_MSECS\
        (ARM_UC_HTTP_RESUME_INITIAL_DELAY_MSECS/(ARM_UC_HTTP_RESUME_NUM_INTERVALS+1))

// Runtime storage of current status of HTTP resumptions.
arm_uc_resume_t resume_http;

static void on_http_resume_interval(void *a_context_p)
{
    if (resume_http.num_intervals > resume_http.interval_count) {
        arm_uc_http_install_isr_event((arm_uc_http_socket_event_t) SOCKET_EVENT_RESUME_WAITING);
    } else {
        arm_uc_http_install_isr_event((arm_uc_http_socket_event_t) SOCKET_EVENT_RESUME_INTERVAL);
    }
}
static void on_http_resume_attempt(void *a_context_p)
{
    arm_uc_http_install_isr_event((arm_uc_http_socket_event_t) SOCKET_EVENT_RESUME_ATTEMPT);
}
static void on_http_resume_terminate(void *a_context_p)
{
    arm_uc_http_install_isr_event((arm_uc_http_socket_event_t) SOCKET_EVENT_RESUME_TERMINATED);
}
// Called from interrupt context!
// We can't afford to do much here, so just set a flag for later handling.
// This will be trapped by the socket event handler at some point, which is better than nothing.
static void on_http_resume_error(void *a_context_p)
{
}

// EVENT MANAGEMENT.
// -----------------

static uint32_t skip_to_event = 0;
static bool expecting_dns_callback = false;

/**
 * @brief Avoid cycling through the handler queue for trivially consecutive events.
 * @details Only used for event transitions that are fast and statically predetermined.
 * @param an_event The event to act on in the next cycle.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_prepare_skip_to_event(uint32_t an_event)
{
    skip_to_event = an_event;
    return ARM_UC_ERROR(SRCE_ERR_NONE);
}

// SOCKET MANAGEMENT.
// ------------------

// DNS RESOLUTION.
// ---------------

/**
 * These functions are used to implement DNS resolution in two variants:
 * asynchronous (PAL_DNS_API_VERSION is 1 or 2) or
 *   synchronous (with PAL_DNS_API_VERSION 0).
 * In addition, there is a distinction in that Linux does not currently support v2 API.
 */
#if (PAL_DNS_API_VERSION > 1) && !defined(TARGET_LIKE_MBED)
#error "Async PAL DNS API v2 or greater is only supported on Mbed."
#endif
#if (PAL_DNS_API_VERSION == 1) && defined(TARGET_LIKE_MBED)
#error "Async PAL DNS API v1 is not supported on Mbed."
#endif

// Internal caching of the cache-state of the DNS is broken, just use it directly.
bool arm_uc_dns_lookup_is_cached(void)
{
    return false;
}

#if (PAL_DNS_API_VERSION == 2)
// Mbed supports the v2 async API.
void arm_uc_dns_callback_handler(
    const char *url,
    palSocketAddress_t *address,
    palStatus_t status,
    void *argument);
#else
// Use the v1 async API.
void arm_uc_dns_callback_handler(
    const char *url,
    palSocketAddress_t *address,
    palSocketLength_t *address_length,
    palStatus_t status,
    void *argument);
#endif

#if (PAL_DNS_API_VERSION == 2)
// To cancel ongoing asynchronous DNS query with pal_cancelAddressInfoAsync().
palDNSQuery_t arm_uc_dns_query_handle = 0;

// Only used internally from a single location, no check for context == NULL.
static palStatus_t arm_uc_do_pal_dns_lookup(void)
{
    UC_SRCE_TRACE(">> %s [asynchronous v2])", __func__);
    // (hack) length is constant.
    context->cache_address_length = PAL_NET_MAX_ADDR_SIZE;
    palStatus_t result = pal_getAddressInfoAsync(
                             context->request_uri->host,
                             &context->cache_address,
                             arm_uc_dns_callback_handler,
                             NULL,
                             &arm_uc_dns_query_handle);
    UC_SRCE_TRACE(".. %s handle=%" PRIu32 ", result=%" PRIx32,
                  __func__, arm_uc_dns_query_handle, result);
    return result;
}
#elif (PAL_DNS_API_VERSION == 1)
// Only used internally from a single location, no check for context == NULL.
static palStatus_t arm_uc_do_pal_dns_lookup(void)
{
    UC_SRCE_TRACE(">> %s [asynchronous v1])", __func__);
    palStatus_t result = pal_getAddressInfoAsync(
                             context->request_uri->host,
                             &context->cache_address,
                             &context->cache_address_length,
                             arm_uc_dns_callback_handler,
                             NULL);
    UC_SRCE_TRACE(".. %s result=%" PRIx32, __func__, result);
    return result;
}
#elif (PAL_DNS_API_VERSION == 0)
/* Use synchronous DNS calls */

// Only used internally from a single location, no check for context == NULL.
static palStatus_t arm_uc_do_pal_dns_lookup(void)
{
    /* Run the synchronous DNS request and call the callback
     immediately after the request is done */
    UC_SRCE_TRACE(">> %s [synchronous])", __func__);
    palStatus_t result = pal_getAddressInfo(
                             context->request_uri->host,
                             &context->cache_address,
                             &context->cache_address_length);
    /* Call the callback with the result of arm_uc_do_dns_lookup.
     The callback will examine the status return and act
     accordingly (see arm_uc_dns_callback). */
    arm_uc_dns_callback_handler(
        context->request_uri->host,
        &context->cache_address,
        &context->cache_address_length,
        result,
        NULL);
    UC_SRCE_TRACE(".. %s result=%" PRIx32, __func__, result);
    return result;
}
#endif // PAL_DNS_API_VERSION

static arm_uc_error_t arm_uc_http_get_address_info(void)
{
    UC_SRCE_TRACE(">> %s", __func__);
    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: context == NULL, &context = %" PRIxPTR, (uintptr_t)context);
        return ARM_UC_ERROR(SRCE_ERR_UNINITIALIZED);
    } else {
#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
        UC_SRCE_TRACE("DNS lookup with type  %" PRIu16, context->cache_address.addressType);
        uint64_t data = 0;
        int index = 0;
        for (data = 0, index = 0; index < 8; ++index) {
            data = (data << 8) + context->cache_address.addressData[index];
        }
        UC_SRCE_TRACE("           with addr  %" PRIx64, data);
        UC_SRCE_TRACE("           with space %" PRIu32, context->cache_address_length);
#endif
        expecting_dns_callback = true;
        palStatus_t status = arm_uc_do_pal_dns_lookup();
        UC_SRCE_TRACE("arm_uc_do_pal_dns_lookup() returned");
        if (status != PAL_SUCCESS) {
            UC_SRCE_TRACE("  failed with %" PRIx32, (uint32_t)status);
        }
        /* Always return BUSY so that the caller can continue
         execution. The actual check for success/failure happens
         in the callback (see the comment above). */
        return ARM_UC_ERROR(SRCE_ERR_BUSY);
    }
}
#if (PAL_DNS_API_VERSION >= 2)
static arm_uc_error_t arm_uc_http_cancel_dns_lookup(void)
{
    expecting_dns_callback = false;
    // Cancel ongoing asynchronous DNS query (only if non-zero handle).
    if (arm_uc_dns_query_handle != 0) {
        UC_SRCE_TRACE("cancel address-info-async %" PRIu32, arm_uc_dns_query_handle);
        pal_cancelAddressInfoAsync(arm_uc_dns_query_handle);
        arm_uc_dns_query_handle = 0;
    }
    return ARM_UC_ERROR(ERR_NONE);
}
#endif


/**
 * @brief Simple null of some shared HTTP settings for init, close and terminate.
 * @details This is a simple refactored nulling routine, it has no failure modes.
 * @param a_context_p A pointer to the socket context that must be cleared.
 *                    these are only called internally, with context known non-null.
 */
static void arm_uc_http_clear_request_fields(void)
{
    context->request_uri = NULL;
    context->request_buffer = NULL;
    context->request_offset = 0;
    context->request_type = RQST_TYPE_NONE;
}
static void arm_uc_http_clear_cached_request_fields(void)
{
    context->open_request_offset = 0;
    context->open_request_type = RQST_TYPE_NONE;
    context->open_request_uri = NULL;
    context->open_burst_received = 0;
}
static void arm_uc_http_clear_socket_fields(void)
{
    context->socket = NULL;
    context->socket_state = STATE_DISCONNECTED;
    context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
}

static void arm_uc_http_clear_dns_cache_fields(void)
{
    context->cache_address.addressType = 0;
    memset(context->cache_address.addressData, 0, PAL_NET_MAX_ADDR_SIZE);
    context->cache_address_length = 0;
}
/**
 * @brief Initialize the HTTP stream module.
 * @details A memory struct is passed as well as a function pointer for event handling.
 * @param context Struct holding all socket-associated global variables.
 * @param handler Event handler for signaling when each operation is complete.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_initialize(
    arm_uc_http_socket_context_t *a_context_p,
    void (*a_handler_p)(uint32_t))
{
    UC_SRCE_TRACE(">> %s (%" PRIxPTR ", %" PRIxPTR ") ..", __func__,
                  (uintptr_t)a_context_p, (uintptr_t)a_handler_p);
    ARM_UC_INIT_ERROR(status, ERR_NONE);

    if ((a_context_p == NULL) || (a_handler_p == NULL)) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR ", &handler == %" PRIxPTR,
                        (uintptr_t)a_context_p, (uintptr_t)a_handler_p);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        context = a_context_p;

        /* Initialize global variables */
        arm_uc_http_clear_request_fields();
        arm_uc_http_clear_socket_fields();

        context->callback_handler = a_handler_p;

        arm_uc_http_clear_dns_cache_fields();
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket initialize = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Close socket, set internal state to disconnected.
 */
arm_uc_error_t arm_uc_http_socket_close(void)
{
    UC_SRCE_TRACE(">> %s ..", __func__);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Close socket if not NULL */
        if (context->socket != NULL) {
            context->socket_state = STATE_DISCONNECTED;
            context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
            palStatus_t pal_status = pal_close(&context->socket);
            if (pal_status != PAL_SUCCESS) {
                ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
            }
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket close = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Closes HTTP socket, resets to uninitialised state, clears memory struct, nulls context.
 * @details HTTP sockets must be initialised again before use.
 * @return Error code.
 */
arm_uc_error_t arm_uc_http_socket_terminate(void)
{
    UC_SRCE_TRACE(">> %s ..", __func__);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        status = arm_uc_http_socket_close();
        arm_uc_http_clear_request_fields();
        arm_uc_http_clear_cached_request_fields();
        arm_uc_http_clear_socket_fields();
        arm_uc_http_clear_dns_cache_fields();
        context = NULL;
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket terminate = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Clean-up after error, but hold on for possible resumes.
 * @details Close socket, set internal state to disconnected and generate error event.
 * @params error The type of error event that has occurred.
 * @return Error status.
 */
static arm_ucs_http_event_t last_http_error_event = ERR_NONE;
static arm_uc_error_t arm_uc_http_socket_error(
    arm_ucs_http_event_t an_error)
{
    UC_SRCE_TRACE(">> %s (%" PRIx32 ") ..", __func__, (uint32_t)an_error);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);
    last_http_error_event = an_error;

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    } else {
        arm_uc_http_clear_dns_cache_fields();
        if (context->socket_state != STATE_DISCONNECTED) {
            status = arm_uc_http_socket_close();
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket error = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Clean-up after final fatal error, no holding on for resumes.
 * @details Close socket, set internal state to disconnected and generate error event.
 * @params error The type of error event that has occurred.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_fatal_error(
    arm_ucs_http_event_t an_error)
{
    UC_SRCE_TRACE(">> %s (%" PRIx32 ") ..", __func__, (uint32_t)an_error);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    } else {
        arm_uc_http_socket_error(an_error);
        /* If callback handler is set, generate error event */
        if (context->callback_handler != NULL) {
            UC_SRCE_TRACE("posting to callback with event %d", an_error);
            ARM_UC_PostCallback(NULL, context->callback_handler, an_error);
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on fatal socket error = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

// RESOURCE-GET.
// -------------
/**
 * @brief Get resource at URI.
 * @details Download resource at URI from given offset and store in buffer.
 *          Events are generated when download finishes, or on error.
 *
 * @param uri Pointer to structure with resource location.
 * @param buffer Pointer to structure with buffer location, maxSize, and size.
 * @param offset Offset in resource to begin download from.
 * @param type Indicate what type of request that was initiated.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_get(
    arm_uc_uri_t *uri,
    arm_uc_buffer_t *buffer,
    uint32_t offset,
    arm_uc_http_rqst_t type)
{
    UC_SRCE_TRACE(">> %s (%" PRIxPTR ", %" PRIxPTR ", %" PRIx32 ", %" PRIx32 ") ..",
                  __func__, (uintptr_t)uri, (uintptr_t)buffer, offset, (uint32_t)type);

    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    /* Check for NULL pointers before dereferencing them */
    if ((context == NULL)
            || (uri == NULL)
            || (uri->scheme == URI_SCHEME_NONE)
            || (uri->host == NULL)
            || (uri->path == NULL)
            || (buffer == NULL)
            || (buffer->ptr == NULL)) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR " or null URI or buffer args", (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        context->request_uri = uri;
        context->request_buffer = buffer;
        context->request_offset = offset;
        context->request_type = type;
        context->request_buffer->size = 0;
        status = arm_uc_http_install_app_event(SOCKET_EVENT_INITIATE);
    }
    // Tracing for development debugging.
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket get = %" PRIx32, (uint32_t)status.code);
        UC_SRCE_TRACE("    context 0x%" PRIxPTR, (uintptr_t)context);
        UC_SRCE_TRACE("    uri 0x%" PRIxPTR, (uintptr_t)uri);
        if (uri != NULL) {
            UC_SRCE_TRACE("        scheme %" PRIu32, (uint32_t)uri->scheme);
            UC_SRCE_TRACE("        host 0x%" PRIxPTR, (uintptr_t)uri->host);
            if (uri->host != NULL) {
                UC_SRCE_TRACE("        host %s", uri->host);
            }
            UC_SRCE_TRACE("        path %" PRIxPTR, (uintptr_t)uri->path);
            if (uri->path != NULL) {
                UC_SRCE_TRACE("        path %s", uri->path);
            }
        }
        if (buffer != NULL) {
            UC_SRCE_TRACE("    buffer 0x%" PRIxPTR, (uintptr_t)buffer);
            UC_SRCE_TRACE("    buffer.ptr 0x%" PRIxPTR, (uintptr_t)buffer->ptr);
        }
    }
    return status;
}

// CONNECT MANAGEMENT.
// -------------------

// Connection to the server is optimised by caching an already open connection,
//   and also by caching an already (partially) filled stream. So there are three
//   levels of connection attempt:
//
//   1 - the socket is closed, and needs to be reopened from scratch, and new
//         data needs to be explicitly requested.
//   2 - the socket is open, but there is no data waiting there, presumably because
//         the last read from the socket consumed everything waiting, or because
//         there was an error that did not entail shutting down the socket. This
//         means the socket can be used to request stuff without re-making a new
//         connection to the server, but the new data must be explicitly requested.
//   3 - the socket is open and stream data is available, and more importantly the
//         correct stream data in that it matches what is requested, in which case
//         we do absolutely nothing beyond getting ready to read from the stream.
//         This manifests as a call to arm_uc_http_socket_soft_connect() after
//         arm_uc_open_http_socket_matches_request() has ensured that the necessary
//         conditions are met.

/**
 * @brief Do the full socket connection attempt, from scratch.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_connect_new(void)
{
    /* Default return value, all code is gated on ERR_NONE */
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);
    palStatus_t pal_inner = PAL_SUCCESS;

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
    } else if (context->cache_address.addressType == 0) {
        UC_SRCE_TRACE("warning: cache address type is 0");
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    } else if (context->cache_address_length == 0) {
        UC_SRCE_TRACE("warning: cache address length is 0");
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    /* Create new asynchronous PAL socket */
    if (ARM_UC_IS_NOT_ERROR(status)) {
        if (PAL_SUCCESS == (pal_inner = pal_asynchronousSocket(
                                            (palSocketDomain_t) context->cache_address.addressType,
                                            PAL_SOCK_STREAM,
                                            true,
                                            0,
                                            arm_uc_http_socket_isr,
                                            &context->socket))) {
            UC_SRCE_TRACE("socket: create success");
        } else {
            UC_SRCE_TRACE("socket creation failed with pal status: 0x%" PRIX32, (uint32_t)pal_inner);
            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
        }
    }

    /* Convert URI to PAL address *if* cache is not empty */
    if (ARM_UC_IS_NOT_ERROR(status)) {
        if (context->cache_address_length != 0) {
            /* Set PAL port */
            if (PAL_SUCCESS == (pal_inner = pal_setSockAddrPort(&context->cache_address,
                                                                context->request_uri->port))) {
                UC_SRCE_TRACE("socket: set socket address port");
            } else {
                UC_SRCE_TRACE("pal_setSockAddrPort returned: 0x%" PRIX32, (uint32_t)pal_inner);
                ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
            }
        } else {
            ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
        }
    }

    /* Connect to server */
    if (ARM_UC_IS_NOT_ERROR(status)) {
        pal_inner = pal_connect(context->socket,
                                &context->cache_address,
                                context->cache_address_length);
        UC_SRCE_TRACE("pal_connect returned: 0x%" PRIX32, (uint32_t)pal_inner);
        switch (pal_inner) {
            case PAL_SUCCESS: /* Synchronous finish */
                /* Move forward to idle state, and fake a connect-done event */
                context->socket_state = STATE_CONNECTED_IDLE;
                arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_CONNECT_DONE);
                break;
            case PAL_ERR_SOCKET_IN_PROGRES: /* Asynchronous finish */
                /* The next event should be connect-done, we wait for it */
                // Note that it is set here, not in the event handler, else it risks being lost.
                context->socket_state = STATE_CONNECTING;
                context->expected_socket_event = SOCKET_EVENT_CONNECT_DONE;
                arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_CONNECT_BLOCKED);
                break;
            default:
                UC_SRCE_TRACE("warning: socket connection failed");
#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
                if (context->cache_address.addressType == PAL_AF_INET) {
                    uint32_t address;
                    memcpy(&address, &context->cache_address.addressData[0], 4);
                    UC_SRCE_TRACE("IPv4 (cal %" PRIu32 ") ca %" PRIx32,
                                  context->cache_address_length, address);
                } else if (context->cache_address.addressType == PAL_AF_INET6) {
                    uint64_t part0, part1;
                    memcpy(&part0, &context->cache_address.addressData[0], 8);
                    memcpy(&part1, &context->cache_address.addressData[8], 8);
                    UC_SRCE_TRACE("IPv6 (cal %" PRIu32 ") ca %" PRIx64 ":%" PRIx64,
                                  context->cache_address_length, part0, part1);
                }
#endif
                ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                break;
        }
    }

    UC_SRCE_TRACE("%s = %s", __func__, ARM_UC_err2Str(status));
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket connect new = %" PRIx32, (uint32_t)status.code);
        arm_uc_http_socket_close();
    }
    return status;
}

/**
 * @brief Decide if a full connection attempt is needed, if not just skip ahead.
 * @details Note that we don't even get here if the stream is already active,
 *          because in that case the socket connection is reused.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_connect(void)
{
    UC_SRCE_TRACE(">> %s ..", __func__);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if ((context == NULL)
            || (context->request_uri == NULL)) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR " and URI = %" PRIxPTR,
                        (uintptr_t)context, (uintptr_t)(context->request_uri));
        ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        context->open_request_uri = context->request_uri;
        context->open_request_type = context->request_type;
        context->open_request_offset = context->request_offset;

        switch (context->socket_state) {
            case STATE_DISCONNECTED:
                // Make a new socket connection.
                status = arm_uc_http_socket_connect_new();
                break;
            case STATE_CONNECTED_IDLE:
                // Socket is already connected, but not busy, so progress state machine.
                status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_CONNECT_DONE);
                // Otherwise result is already set to the error condition.
                break;
            default:
                // Socket is already busy, either connecting or communicating.
                ARM_UC_SET_ERROR(status, SRCE_ERR_BUSY);
                break;
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket connect = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Connect softly with an already-open socket.
 * @details Avoids making a new connection to the server, just does setup.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_soft_connect(void)
{
    UC_SRCE_TRACE(">> %s", __func__);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket soft connect = %" PRIx32, (uint32_t)ARM_UC_GET_ERROR(status));
    }
    return status;
}

// SEND HANDLING.
// --------------

/**
 * @brief Construct and send the request packet that fetches the next chunk from the server.
 * @details If the state machine decides that it needs to get more data from the server,
 *          here is where it happens. (The FSM will not come here if the socket is already
 *          open and has data waiting, for example.) This routine constructs an HTTP request
 *          (either HEAD or GET), builds up the body with suitable parts, then sends the
 *          request to the server.
 *          HEAD is like GET with no body, and is sufficient for TAG and DATE information.
 *          The FILE and FRAG requests differ in that a fragment request has a range associated,
 *          and it requests only data in that range. A FILE request (which we don't currently use)
 *          asks for a whole file, from beginning to end.
 *          The streaming implementation uses the FRAG interface, but requests a fragment that
 *          is the size of all remaining (unfetched) data in the file, and then pulls that
 *          data out in pieces from the socket, thereafter short-circuiting calls to this
 *          routine wherever possible. This is because the cost of copying the next buffered
 *          data from the socket is tiny compared to the cost of constructing a new fragment
 *          GET, sending the GET (data tx time and link delays), awaiting a response, receiving
 *          (link delays and rx time) and then decoding the response.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_send_request(void)
{
    UC_SRCE_TRACE(">> %s ..", __func__);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
    }
    /* Get local references */
    arm_uc_buffer_t *request_buffer = context->request_buffer;
    arm_uc_uri_t *request_uri = context->request_uri;
    arm_uc_http_rqst_t request_type = context->request_type;

    /* Template for generating HTTP requests */
    static const char HTTP_HEADER_TEMPLATE[] =
        "%s %s HTTP/1.1\r\n" // Status line
        "Host: %s\r\n";// Mandated for HTTP 1.1

    char *req_type_str = NULL;

    /* Make appropriate HTTP request for required type */
    if (ARM_UC_IS_NOT_ERROR(status)) {
        switch (request_type) {
            case RQST_TYPE_HASH_ETAG:
            case RQST_TYPE_HASH_DATE:
                /* Construct ETag and Date request header */
                req_type_str = "HEAD";
                break;
            case RQST_TYPE_GET_FILE:
            case RQST_TYPE_GET_FRAG:
                /* Construct download header */
                req_type_str = "GET";
                break;
            default:
                UC_SRCE_TRACE("warning: on send request = %" PRIx32" (invalid request type)", (uint32_t)status.code);
                ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                break;
        }
    }

    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Construct download header */
        request_buffer->size = snprintf((char *) request_buffer->ptr,
                                        request_buffer->size_max,
                                        HTTP_HEADER_TEMPLATE,
                                        req_type_str,
                                        request_uri->path,
                                        request_uri->host);
        /* If fragment then construct the Range field that makes this a partial content request */
        if (request_type == RQST_TYPE_GET_FRAG) {
            context->open_burst_requested = request_buffer->size_max * frags_per_burst;
            request_buffer->size += snprintf((char *) request_buffer->ptr + request_buffer->size,
                                             request_buffer->size_max - request_buffer->size,
                                             "Range: bytes=%" PRIu32 "-%" PRIu32 "\r\n",
                                             context->request_offset,
                                             context->request_offset + context->open_burst_requested - 1);
        }
        /* Terminate request with a carriage return and newline */
        request_buffer->size += snprintf((char *) request_buffer->ptr + request_buffer->size,
                                         request_buffer->size_max - request_buffer->size,
                                         "\r\n");

        /* Terminate string */
        request_buffer->ptr[request_buffer->size] = '\0';
        UC_SRCE_TRACE("\r\n%s", request_buffer->ptr);
    }

    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Send HTTP request */
        size_t bytes_sent = 0;
        context->expected_socket_event = SOCKET_EVENT_SEND_DONE;
        palStatus_t pal_result = pal_send(context->socket,
                                          request_buffer->ptr,
                                          request_buffer->size,
                                          &bytes_sent);
        switch (pal_result) {
            case PAL_SUCCESS: /* Synchronous finish */
                UC_SRCE_TRACE("send success");
                /* Reset buffer and prepare to receive header */
                request_buffer->size = 0;
                context->socket_state = STATE_PROCESS_HEADER;
                context->expected_socket_event = SOCKET_EVENT_SEND_DONE;
                break;
            case PAL_ERR_SOCKET_WOULD_BLOCK: /* Asynchronous finish */
                UC_SRCE_TRACE("send would block, will retry");
                /* Keep current state and force callback to retry sending */
                // Note that it is set here, not in the event handler, else it risks being lost.
                arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_SEND_BLOCKED);
                break;
            default:
                context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
                arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_SEND_BLOCKED);
                break;
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket send request = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

// RECEIVE HANDLING.
// -----------------

/**
 * @brief Receive data from HTTP socket.
 * @details Data is stored in global buffer. The call will automatically retry
 *          if the socket is busy.
 * @return Error status.
 */
// Just receive more data, all processing is vectored from the event handler.
arm_uc_error_t arm_uc_http_socket_receive(void)
{
    UC_SRCE_TRACE(">> %s [expected-event %" PRIu32 "] ..", __func__, (uint32_t)context->expected_socket_event);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);
    palStatus_t pal_result = PAL_SUCCESS;

    if ((context == NULL)
            || (context->socket_state == STATE_DISCONNECTED)
            || (context->request_buffer == NULL)) {
        UC_SRCE_ERR_MSG("error: on socket receive = %" PRIx32 " (context uninitialised)", (uint32_t)status.code);
        ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
    }

    arm_uc_buffer_t *request_buffer = context->request_buffer;
    size_t available_space = request_buffer->size_max - request_buffer->size;

    UC_SRCE_TRACE("  space %" PRIu32, (uint32_t)available_space);

    if (ARM_UC_IS_NOT_ERROR(status)) {
        if (available_space <= 0) {
            ARM_UC_SET_ERROR(status, SRCE_ERR_ABORT);
            UC_SRCE_TRACE("warning: on socket receive = %" PRIx32 " (no buffer space)", (uint32_t)status.code);
            arm_uc_http_socket_error(UCS_HTTP_EVENT_ERROR_BUFFER_SIZE);
        }
    }

    if (ARM_UC_IS_NOT_ERROR(status)) {
        size_t received_bytes = 0;
        /* Append data from socket receive buffer to request buffer. */
        pal_result = pal_recv(context->socket,
                              &(request_buffer->ptr[request_buffer->size]),
                              available_space,
                              &received_bytes);
        switch (pal_result) {
            case PAL_SUCCESS:
                if (received_bytes <= 0) {
                    ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                    UC_SRCE_TRACE("warning: socket failed - received zero or less bytes");
                    arm_uc_http_socket_error(UCS_HTTP_EVENT_ERROR);
                } else {
                    /* Note: the proper formatter %zu is not supported on mbed's libc,
                     * hence the casts to difference type.
                     */
                    UC_SRCE_TRACE("recv success: %lu bytes received", (unsigned long)received_bytes);

                    if (received_bytes > available_space) {
                        ARM_UC_SET_ERROR(status, SRCE_ERR_ABORT);
                        UC_SRCE_TRACE("warning: socket receive - data exceeds space");
                        arm_uc_http_socket_error(UCS_HTTP_EVENT_ERROR_BUFFER_SIZE);
                        break;
                    }
                    /* Update buffer size with received bytes */
                    request_buffer->size += received_bytes;

                    // if this is a header then these actions will be temporarily wrong.
                    // the offset and received values will have to be adjusted later,
                    //   as they are intended to refer to the payload, not the total data received.
                    context->open_request_offset += received_bytes;
                    context->open_burst_received += received_bytes;

                    UC_SRCE_TRACE("open_request_offset %" PRIu32, context->open_request_offset);
                }
                break;
            case PAL_ERR_SOCKET_WOULD_BLOCK:
                UC_SRCE_TRACE("recv: pending: %" PRIu32, (request_buffer->size_max - request_buffer->size));
                // This error code is not actually an error, so don't report it if error-tracing is enabled.
                ARM_UC_SET_ERROR_NEVER_TRACE(status, SRCE_ERR_BUSY);
                break;
            default:
                ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                UC_SRCE_TRACE("warning: socket receive failed");
                arm_uc_http_socket_error(UCS_HTTP_EVENT_ERROR);
                break;
        }
    }
    /* There's an error, but it isn't just that we are going asynch */
    if (ARM_UC_IS_ERROR(status)
            && (ARM_UC_GET_ERROR(status) != SRCE_ERR_BUSY)) {
        UC_SRCE_TRACE("warning: on socket receive = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

// HEADER HANDLING.
// ----------------

/**
 * @brief Check to see if a header we are waiting for has arrived.
 * @param a_has_received_p (out) Indicator of header arrived or not.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_has_received_header(
    bool *a_has_received_p)
{
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    } else if (a_has_received_p == NULL) {
        UC_SRCE_ERR_MSG("error: flag * a_has_received_p = %" PRIxPTR, (uintptr_t)a_has_received_p);
        ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
    } else {
        context->header_end_index = arm_uc_strnstrn(
                                        context->request_buffer->ptr,
                                        context->request_buffer->size,
                                        (const uint8_t *) "\r\n\r\n",
                                        4);
        *a_has_received_p = (context->header_end_index <= context->request_buffer->size);
        // Raise an error if we have filled the buffer,
        //   but there isn't enough space to hold a full header.
        if (!*a_has_received_p
                && (context->request_buffer->size == context->request_buffer->size_max)) {
            UC_SRCE_TRACE("warning: socket receive - not enough space for a header");
#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
            context->request_buffer->ptr[context->request_buffer->size - 1] = 0;
            UC_SRCE_TRACE("received\r\n%s", context->request_buffer->ptr);
#endif
            arm_uc_http_socket_error(UCS_HTTP_EVENT_ERROR_BUFFER_SIZE);
            ARM_UC_SET_ERROR(status, SRCE_ERR_ABORT);
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket received header = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Received HTTP redirect codes, handle these.
 * @details If we received a redirect, we copy the redirect URI and rerequest.
 *        301: Moved Permanently
 *        302: Found [Elsewhere]
 *        303: See Other
 *        307: Temporary Redirect
 * @param an_http_status_code The actual code received.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_process_header_redirect_codes(
    uint32_t an_http_status_code)
{
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    arm_uc_buffer_t *request_buffer = context->request_buffer;
    arm_uc_uri_t *request_uri = context->request_uri;

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Move location to front of buffer */
        const char tag[] = "Location";
        bool found = arm_uc_http_socket_trim_value(request_buffer, tag, sizeof(tag) - 1);
        if (!found) {
            // The file isn't there, *and* there's no redirect, so abort the operation.
            UC_SRCE_TRACE("warning: unable to find redirect location");
            ARM_UC_SET_ERROR(status, SRCE_ERR_ABORT);
        }
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* NULL terminate string */
        request_buffer->ptr[request_buffer->size] = '\0';

        /* Parse location and store in URI */
        status = arm_uc_str2uri(request_buffer->ptr,
                                request_buffer->size,
                                request_uri);
        if (ARM_UC_IS_ERROR(status)
                || (request_uri->scheme != URI_SCHEME_HTTP)) {
            UC_SRCE_TRACE("unable to parse URI string");
            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
        }
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        UC_SRCE_TRACE("HTTP redirecting to http://%s:%" PRIu16 "/%s",
                      request_uri->host,
                      request_uri->port,
                      request_uri->path);

        // Drop anything remaining in the buffer, it has no value now,
        //   and just gets in the way in future operations.
        request_buffer->size = 0;

        // For now, assume that socket and DNS must be refreshed,
        //   since although it might be avoidable, it is complicated by the
        //   overwrite during parsing, and isn't a huge win anyway.
        bool host_is_new = true, port_is_new = true;
        // based on the changed values, refresh everything needing it.
        if (port_is_new) {
            // Need to close (and later reopen) the socket if the port differs.
            arm_uc_http_socket_close();
            arm_uc_http_socket_event_t event = SOCKET_EVENT_CONNECT_START;
            if (host_is_new) {
                // Need to refresh the DNS cache if the host differs.
                // Flush the socket DNS cache, and restart the process with the new URI.
                arm_uc_http_clear_dns_cache_fields();
                event = SOCKET_EVENT_LOOKUP_START;
            }
            arm_uc_http_install_app_event(event);
            ARM_UC_SET_ERROR(status, SRCE_ERR_BUSY);
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket received redirect header = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Post an invocation for the handler of a receive event.
 * @param a_http_event The type of event we want handled.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_process_header_post_callback(
    arm_ucs_http_event_t an_http_event)
{
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Was already successfully read - post callback */
        if (context->callback_handler) {
            ARM_UC_PostCallback(NULL, context->callback_handler, an_http_event);
        }
        /* Request complete - close socket */
        status = arm_uc_http_socket_close();
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket received header = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Got a header, check out the return code.
 * @param an_http_status_code The actual code received.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_process_header_return_codes(
    uint32_t an_http_status_code)
{
// TODO check out this below, because 206 = Partial Content, which is no error.

    /* NOTE: HTTP 1.1 Code 206 with Header "Connection:close" is not
     handled here, instead the execution falls through to error-
     handling in http_socket (ARM_UCS_HTTPEvent with UCS_HTTP_EVENT_ERROR)
     where the retry-mechanism will reestablish firmware download if
     the server closed the connection.
     */
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        arm_uc_buffer_t *request_buffer = context->request_buffer;

        switch (context->request_type) {
            case RQST_TYPE_HASH_ETAG: {
                /* Look for ETag and move to front of buffer */
                const char tag[] = "ETag";
                bool found = arm_uc_http_socket_trim_value(request_buffer, tag, sizeof(tag) - 1);
                if (!found) {
                    UC_SRCE_TRACE("unable to find ETag");
                    ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                } else {
                    /* ETag successfully read - post callback */
                    status = arm_uc_http_socket_process_header_post_callback(UCS_HTTP_EVENT_HASH);
                }
            }
            break;
            case RQST_TYPE_HASH_DATE: {
                /* Look for date and move to front of buffer */
                const char tag[] = "Last-Modified";
                bool found = arm_uc_http_socket_trim_value(request_buffer, tag, sizeof(tag) - 1);
                if (!found) {
                    UC_SRCE_TRACE("unable to find last modified date");
                    ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                } else {
                    /* Date successfully read - post callback */
                    status = arm_uc_http_socket_process_header_post_callback(UCS_HTTP_EVENT_DATE);
                }
            }
            break;
            case RQST_TYPE_GET_FILE:
            case RQST_TYPE_GET_FRAG: {
                /* Save current buffer size so we can recover body after the content length has been read. */
                uint32_t current_size = request_buffer->size;
                uint32_t content_length = 0;

                /* Find content length and move value to front of buffer */
                const char tag[] = "Content-Length";
                bool found = arm_uc_http_socket_trim_value(request_buffer, tag, sizeof(tag) - 1);
                if (!found) {
                    UC_SRCE_TRACE("unable find content length");
                    ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                }
                if (ARM_UC_IS_NOT_ERROR(status)) {
                    /* NULL-terminate string */
                    // Check this doesn't overrun, trim behaviour isn't guaranteed.
                    if (request_buffer->size < request_buffer->size_max) {
                        request_buffer->ptr[request_buffer->size] = '\0';
                    } else {
                        ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                    }
                }
                if (ARM_UC_IS_NOT_ERROR(status)) {
                    /* Parse full length of content */
                    int parsed = sscanf((char *) request_buffer->ptr, "%10" SCNu32, &content_length);
                    /* Only continue if exactly one argument was parsed */
                    if (parsed != 1) {
                        UC_SRCE_TRACE("unable to parse content length");
                        ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                    }
                }
                if (ARM_UC_IS_NOT_ERROR(status)) {
                    UC_SRCE_TRACE("content-length: %" PRIu32, content_length);

                    /* Replace HTTP header with body */
                    uint32_t header_size = context->header_end_index + 4;
                    uint32_t body_size = current_size - header_size;
                    memmove(request_buffer->ptr,
                            &(request_buffer->ptr[context->header_end_index + 4]),
                            body_size);

                    /* Set size of partial body, also reset burst info */
                    request_buffer->size = body_size;
                    context->open_request_offset = context->request_offset + request_buffer->size;
                    context->open_burst_expected = content_length;
                    context->open_burst_received = request_buffer->size;

                    if (content_length < (request_buffer->size_max * frags_per_burst)) {
                        UC_SRCE_TRACE("last burst in flight! %" PRIu32 " of burst %" PRIu32,
                                      content_length, (request_buffer->size_max * frags_per_burst));
                    }
                    if (request_buffer->size < request_buffer->size_max) {
                        /* Expecting more data - continue receiving */
                        UC_SRCE_TRACE("expecting more fragment data after header (got %" PRIu32 " of %" PRIu32 " max)",
                                      request_buffer->size,
                                      request_buffer->size_max);
                    }
                    UC_SRCE_TRACE("burst data received after header %" PRIu32,
                                  context->open_burst_received);
                    /* Continue processing body */
                    context->socket_state = STATE_PROCESS_BODY;
                    // Finishing with status.code == SRCE_ERR_NONE
                }

            }
            break;
            default:
                UC_SRCE_TRACE("unknown request type");
                ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                break;
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket process header return codes = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Received a header, process it.
 * @details This only runs if a header has actually arrived.
 *          First checks that the HTTP encoding is correct.
 *          Then checks that there is a status code and handles as appropriate.
 * @param an_http_status_code The actual code received.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_process_header(void)
{
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
    }

    arm_uc_buffer_t *request_buffer = context->request_buffer;
    uint32_t header_start = 0;

    if (ARM_UC_IS_NOT_ERROR(status)) {
        // Only arrives here if it actually has a header to process.
        /* Get local references */
        UC_SRCE_TRACE("HTTP header terminator found");
        const char header_tag[] = "HTTP/1.1 ";
        header_start = arm_uc_strnstrn(request_buffer->ptr,
                                       request_buffer->size,
                                       (const uint8_t *) header_tag,
                                       sizeof(header_tag) - 1);
        /* Found beginning of header */
        /* Do buffer size check */
        if (header_start < request_buffer->size) {
            UC_SRCE_TRACE("HTTP/1.1 header found");
            UC_SRCE_TRACE("HTTP header: \r\n%s", &(request_buffer->ptr[header_start]));
            /* Status code is after the header tag */
            header_start = header_start + sizeof(header_tag) - 1;
        } else {
            UC_SRCE_TRACE("Error: HTTP/1.1 header not found");
            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
        }
    }
    uint32_t http_status_code = 0;
    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Parse status code */
        bool header_parsed = false;
        http_status_code = arm_uc_str2uint32(
                               &(request_buffer->ptr[header_start]),
                               request_buffer->size - header_start,
                               &header_parsed);
        if (!header_parsed) {
            UC_SRCE_TRACE("warning: unable to read status code");
            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
        }
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        if (((http_status_code >= 301) && (http_status_code <= 303))
                || (http_status_code == 307)) {
            status = arm_uc_http_socket_process_header_redirect_codes(http_status_code);
            if (ARM_UC_IS_ERROR(status)) {
                UC_SRCE_TRACE("warning: processing HTTP status code %" PRIu32, http_status_code);
            }
        }
        /* All codes between 200 to 226 */
        else if ((http_status_code >= 200) && (http_status_code <= 226)) {
            status = arm_uc_http_socket_process_header_return_codes(http_status_code);
            if (ARM_UC_IS_ERROR(status)) {
                UC_SRCE_TRACE("warning: processing HTTP status code %" PRIu32, http_status_code);
            }
        } else {
            /* All remaining codes outside 200-226, are treated as errors */
            UC_SRCE_TRACE("warning: server returned HTTP status code %" PRIu32, http_status_code);
            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket process header = %" PRIu32, (uint32_t)status.code);
        arm_uc_http_socket_error(UCS_HTTP_EVENT_ERROR);
    }
    return status;
}

// BODY HANDLING.
// --------------

// TODO Check it still works if the code is exactly a page multiple in size, incl. empty.
/**
 * @brief Check to see if a fragment we are waiting for has fully arrived.
 * @param a_has_received_p (out) indicator of fragment arrived or not.
 * @return Error status.
 */
arm_uc_error_t arm_uc_http_socket_has_received_frag(
    bool *a_has_received_p)
{
    UC_SRCE_TRACE(">> %s ..", __func__);
    ARM_UC_INIT_ERROR(status, ERR_NONE);

    if ((context == NULL) || (context->request_buffer == NULL)) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR ", context->request_buffer = %" PRIxPTR,
                        (uintptr_t)context, (uintptr_t)(context->request_buffer));
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    } else if (a_has_received_p == NULL) {
        UC_SRCE_ERR_MSG("error: flag * a_has_received_p = %" PRIxPTR, (uintptr_t)a_has_received_p);
        ARM_UC_SET_ERROR(status, SRCE_ERR_INVALID_PARAMETER);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        // Check if this is enough to make up a full fragment.
        *a_has_received_p = context->request_buffer->size >= context->request_buffer->size_max;
        UC_SRCE_TRACE("  has received full frag? %s %" PRIu32 " of %" PRIu32,
                      (*a_has_received_p ? "yes" : "no"),
                      context->request_buffer->size,
                      context->request_buffer->size_max);
        // If not a full fragment, then maybe at the end of the transfer with a short burst.
        if (!*a_has_received_p) {
            *a_has_received_p = context->open_burst_received == context->open_burst_expected;
            if (*a_has_received_p) {
                UC_SRCE_TRACE("  received short burst complete");
            }
        }
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket has received fragment = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

/**
 * @brief Function drives the download and continues until the buffer is full
 *          or the expected amount of data has been downloaded.
 */
arm_uc_error_t arm_uc_http_socket_process_frag(void)
{
    UC_SRCE_TRACE(">> %s ..", __func__);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    }
    if (ARM_UC_IS_NOT_ERROR(status)) {
        /* Fragment or file successfully received */
        /* Reset buffers and state */
        context->socket_state = STATE_CONNECTED_IDLE;
        context->request_buffer = NULL;
        context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
    }
    if (ARM_UC_IS_ERROR(status)) {
        UC_SRCE_TRACE("warning: on socket process fragment = %" PRIx32, (uint32_t)status.code);
    }
    return status;
}

// CACHE HANDLING.
// ---------------
/**
 * @brief Check that the cache state is suitable to supply data as requested.
 * @return Whether or not the cache is able to satisfy this request.
 */

bool arm_uc_open_http_socket_matches_request(void)
{
    UC_SRCE_TRACE(">> %s ..", __func__);

    bool result = false;

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
    } else if (context->socket_state != STATE_CONNECTED_IDLE) {
        UC_SRCE_TRACE("!matches: context->socket_state %" PRIu32 " != STATE_CONNECTED_IDLE",
                      (uint32_t)context->socket_state);
    } else if (context->request_type != context->open_request_type) {
        UC_SRCE_TRACE("!matches: context->request_type %" PRIu32 " != %" PRIu32,
                      (uint32_t)context->request_type, (uint32_t)context->open_request_type);
    } else if (context->request_offset != context->open_request_offset) {
        UC_SRCE_TRACE("!matches: context->request_offset %" PRIu32 " != %" PRIu32,
                      context->request_offset, context->open_request_offset);
    } else if (context->open_burst_received >= context->open_burst_expected) {
        UC_SRCE_TRACE("!matches: context->open_burst_remaining == 0");
    }
    // We need to be VERY sure on what constitutes equality for the uri (e.g. port?)
    // It is NOT true that the address of the struct matters, because it could be reconstructed,
//   but keeping the host and path the same.
    else if (strcmp((const char *) context->request_uri->host, (const char *) context->open_request_uri->host)
             || strcmp((const char *) context->request_uri->path, (const char *) context->open_request_uri->path)) {
        UC_SRCE_TRACE("!matches: context->request_uri %" PRIxPTR " != %" PRIxPTR,
                      (uintptr_t)context->request_uri, (uintptr_t)context->open_request_uri);
    } else {
        result = true;
    }
    return result;
}

// EVENT HANDLING.
// ---------------

// If the buffer is empty on a read, the processing turnaround time allows for the possibility
//   that there will be data on a subsequent attempt, which this supports. This is only really
//   useful with stream processing of the HTTP socket, rather than manual fragments.
#if defined(TARGET_IS_PC_LINUX)
#define MAX_EMPTY_RECEIVES 8
#else
#define MAX_EMPTY_RECEIVES 2
#endif

/**
 * @brief Show HTTP resume settings if QA trace is enabled.
 */
static bool has_displayed_http_resume_settings = false;
static void arm_uc_display_http_resume_settings(arm_uc_resume_t *a_resume_p)
{
    if (a_resume_p == NULL) {
        UC_SRCE_ERR_MSG("error: a_resume_p = %" PRIxPTR, (uintptr_t)a_resume_p);
    } else if (!has_displayed_http_resume_settings) {
        has_displayed_http_resume_settings = true;
        UC_QA_TRACE("HTTP stream source - download resume settings - actual\r\n");
        UC_QA_TRACE("exponentiation factor: %" PRIu32
                    ", attempt initial delay: %" PRIu32 " ms"
                    ", attempt maximum delay: %" PRIu32 " ms"
                    ", download maximum time: %" PRIu32 " ms"
                    ", interval delay: %" PRIu32 " ms"
                    ", interval count: %" PRIu32 "\r\n",
                    a_resume_p->exponentiation_factor,
                    a_resume_p->attempt_initial_delay,
                    a_resume_p->attempt_max_delay,
                    a_resume_p->activity_max_time,
                    a_resume_p->interval_delay,
                    a_resume_p->interval_count);
    }
}

/**
 * Keep track of whether or not the HTTP resume settings have been checked for correctness.
 *   This occurs only once, which should be sufficient given that they are compile-time
 *   values and not modified over the lifetime of the application.
 */
static bool has_checked_http_resume_settings = false;
/**
 * @brief Check values being passed in for resume-struct initialization (once only).
 * @details Note that this struct *cannot* be constant, or the corrections will induce errors.
 *          Values are checked on every download cycle to accommodate dynamic value changes.
 * @param an_init_p Pointer to structure holding configuration values.
 * @return Return if the values were correct as passed in. It is expected that the caller will
 *           continue running even if false is returned, given that this function corrects the bad
 *           values, however this could be used to log and report an error upstream.
 */
static bool arm_uc_http_check_http_resume_parameters(arm_uc_resume_t *a_resume_p)
{
    bool result = true;
    if (a_resume_p == NULL) {
        UC_SRCE_ERR_MSG("error: a_resume_p = %" PRIxPTR, (uintptr_t)a_resume_p);
        return false;
    }
    // low/sensible/high bounds for attempt-initial-delay.
    if (a_resume_p->attempt_initial_delay < MIN_INITIAL_ATTEMPT_DELAY_LIMIT) {
        a_resume_p->attempt_initial_delay = MIN_INITIAL_ATTEMPT_DELAY_LIMIT;
        UC_SRCE_ERR_MSG("HTTP resume initial attempt delay cannot be less than %" PRIu32 " millisecs,"
                        " setting to default value of %" PRIu32 " millisecs.",
                        (uint32_t)MIN_INITIAL_ATTEMPT_DELAY_LIMIT, a_resume_p->attempt_initial_delay);
        result = false;
    }
    if (a_resume_p->attempt_initial_delay > ADVISABLE_INITIAL_ATTEMPT_DELAY_LIMIT) {
        UC_SRCE_TRACE("HTTP resume initial attempt delay should possibly not be more than %" PRIu32 " millisecs.",
                      (uint32_t)ADVISABLE_INITIAL_ATTEMPT_DELAY_LIMIT);
    }
    if (a_resume_p->attempt_initial_delay > MAX_INITIAL_ATTEMPT_DELAY_LIMIT) {
        a_resume_p->attempt_initial_delay = MAX_INITIAL_ATTEMPT_DELAY_LIMIT;
        UC_SRCE_ERR_MSG("HTTP resume initial attempt delay cannot be more than %" PRIu32 " millisecs,"
                        " setting it to that value.",
                        a_resume_p->attempt_initial_delay);
        result = false;
    }
    // low/sensible/high bounds for attempt-max-delay.
    if (a_resume_p->attempt_max_delay < a_resume_p->attempt_initial_delay) {
        a_resume_p->attempt_max_delay = a_resume_p->attempt_initial_delay;
        UC_SRCE_ERR_MSG("HTTP resume maximum attempt delay cannot be less than the initial attempt delay,"
                        " setting to value of %" PRIu32 " millisecs.",
                        a_resume_p->attempt_max_delay);
        result = false;
    }
    if (a_resume_p->attempt_max_delay > ADVISABLE_LONGEST_ATTEMPT_DELAY_LIMIT) {
        UC_SRCE_TRACE("HTTP resume maximum attempt delay should possibly not be greater than %" PRIu32 " millisecs.",
                      (uint32_t)ADVISABLE_LONGEST_ATTEMPT_DELAY_LIMIT);
    }
    if (a_resume_p->attempt_max_delay > MAX_LONGEST_ATTEMPT_DELAY_LIMIT) {
        a_resume_p->attempt_max_delay = MAX_LONGEST_ATTEMPT_DELAY_LIMIT;
        UC_SRCE_ERR_MSG("HTTP resume maximum attempt delay cannot be more than %" PRIu32 " millisecs,"
                        " setting it to that value.",
                        (uint32_t)MAX_LONGEST_ATTEMPT_DELAY_LIMIT);
        result = false;
    }
    // low/high bounds for activity-max-time.
    if (a_resume_p->activity_max_time < a_resume_p->attempt_max_delay) {
        a_resume_p->activity_max_time = a_resume_p->attempt_max_delay;
        UC_SRCE_ERR_MSG("HTTP resume maximum download time cannot be less than the maximum attempt delay,"
                        " setting to value of %" PRIu32 " millisecs.",
                        a_resume_p->activity_max_time);
        result = false;
    }
    if (a_resume_p->activity_max_time > MAX_ACTIVITY_TIME_LIMIT) {
        a_resume_p->activity_max_time = MAX_ACTIVITY_TIME_LIMIT;
        UC_SRCE_ERR_MSG("HTTP resume maximum download time cannot be greater than %" PRIu32 " millisecs,"
                        " setting it to that value.",
                        (uint32_t)MAX_ACTIVITY_TIME_LIMIT);
        result = false;
    }
    has_checked_http_resume_settings = true;

    return result;
}

/**
 * @brief Ensure the HTTP resume settings are valid.
 */
static void arm_uc_http_load_http_resume_parameters(void)
{
    resume_http.exponentiation_factor = ARM_UC_HTTP_RESUME_EXPONENTIATION_FACTOR;
    resume_http.attempt_initial_delay = ARM_UC_HTTP_RESUME_INITIAL_DELAY_MSECS;
    resume_http.attempt_max_delay = ARM_UC_HTTP_RESUME_MAXIMUM_DELAY_MSECS;
    resume_http.activity_max_time = ARM_UC_HTTP_RESUME_MAXIMUM_DOWNLOAD_TIME_MSECS;
    resume_http.interval_delay = ARM_UC_HTTP_RESUME_INTERVAL_DELAY_MSECS;
    resume_http.interval_count = ARM_UC_HTTP_RESUME_NUM_INTERVALS;
}

/**
 * @brief Ensure the HTTP resume settings are valid.
 */
static void arm_uc_http_resume_initialize(void)
{
    if (!has_checked_http_resume_settings) {
        arm_uc_http_load_http_resume_parameters();
        arm_uc_http_check_http_resume_parameters(&resume_http);
    }
}

static uint32_t empty_receive = 0;
static bool received_enough = false;

static char *skip_text_p = "";
#define UC_SRCE_TRACE_SM(s) UC_SRCE_TRACE(s " %s", skip_text_p)
/**
 * @brief PAL socket event handler.
 * @details Only handles passing-line code in general, failures handled in subroutines.
 * @param unused PAL API doesn't support parameters.
 */
// NOTE all external flow of control now takes place in the handler, not scattered around.
// Status codes are updated with each attempted operation, assume good to start.
void arm_uc_http_socket_callback(
    uint32_t an_event)
{
    UC_SRCE_TRACE(">> %s (%" PRIx32 ")", __func__, an_event);
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        UC_SRCE_ERR_MSG("error: &context = %" PRIxPTR, (uintptr_t)context);
        ARM_UC_SET_ERROR(status, SRCE_ERR_UNINITIALIZED);
    } else {
        do {
            an_event &= ~ISR_EVENT_MASK;
            switch (an_event) {
                // An event of an undefined type, this is a non-signalling error.
                case SOCKET_EVENT_UNDEFINED:
                    UC_SRCE_TRACE_SM("event: undefined, not expected");
                    break;

                // Everything is assumed to have been reset prior to reaching here.
                case SOCKET_EVENT_INITIATE:
                    /* Go direct to reading the stream body *if* already open and synchronised */
                    /* Else connect socket if not already connected, and start streaming */
                    UC_SRCE_TRACE_SM("event: initiate");
                    last_http_error_event = UCS_HTTP_EVENT_ERROR;

                    arm_uc_http_resume_initialize();
                    arm_uc_resume_initialize(
                        &resume_http,
                        resume_http.exponentiation_factor,
                        resume_http.attempt_initial_delay,
                        resume_http.attempt_max_delay,
                        resume_http.activity_max_time,
                        resume_http.interval_delay,
                        resume_http.interval_count,
                        on_http_resume_interval,
                        on_http_resume_attempt,
                        on_http_resume_terminate,
                        on_http_resume_error,
                        NULL
                    );
                    arm_uc_resume_start_monitoring(&resume_http);

                    context->resume_socket_phase = SOCKET_EVENT_UNDEFINED;
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_LOOKUP_START);
                    arm_uc_display_http_resume_settings(&resume_http);
                    break;

                case SOCKET_EVENT_LOOKUP_START:
                    UC_SRCE_TRACE_SM("event: lookup start");
                    context->resume_socket_phase = SOCKET_EVENT_LOOKUP_START;
                    if (arm_uc_dns_lookup_is_cached()) {
                        status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_LOOKUP_DONE);
                    } else {
                        status = arm_uc_http_get_address_info();
                        // The DNS lookup must *always* return BUSY, even if failed,
                        //   and then handle the error in the callback handler.
                        // There is no expected-event here, it must pass on its own merits.
                        status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_LOOKUP_WAITING);
                    }
                    break;

                case SOCKET_EVENT_LOOKUP_WAITING:
                    UC_SRCE_TRACE_SM("event: begin lookup waiting");
                    // Just a marker event to make code and trace more readable.
                    break;

                case SOCKET_EVENT_LOOKUP_FAILED:
                    UC_SRCE_TRACE_SM("event: lookup failed");
#if (PAL_DNS_API_VERSION >= 2)
                    // Cancel ongoing asynchronous DNS query (only if non-zero handle).
                    arm_uc_http_cancel_dns_lookup();
#endif
                    arm_uc_http_clear_dns_cache_fields();
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_WAITING);
                    break;

                case SOCKET_EVENT_LOOKUP_DONE:
                    UC_SRCE_TRACE_SM("event: lookup done");
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_CONNECT_START);
                    break;

                case SOCKET_EVENT_CONNECT_START:
                    UC_SRCE_TRACE_SM("event: connect start");
                    context->resume_socket_phase = SOCKET_EVENT_CONNECT_START;
                    context->number_of_pieces = 0;
                    empty_receive = 0;
                    if (arm_uc_open_http_socket_matches_request()) {
                        status = arm_uc_http_socket_soft_connect();
                        if (ARM_UC_IS_NOT_ERROR(status)) {
                            // SEPARATED TO AVOID THE SEND STAGES IF POSSIBLE!
                            status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_FRAG_MORE);
                        }
                    } else {
                        status = arm_uc_http_socket_connect();
                    }
                    break;

                case SOCKET_EVENT_CONNECT_BLOCKED:
                    UC_SRCE_TRACE_SM("event: connect blocked");
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_WAITING);
                    break;

                case SOCKET_EVENT_CONNECT_DONE:
                    UC_SRCE_TRACE_SM("event: connect done");
                    context->socket_state = STATE_CONNECTED_IDLE;
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_SEND_START);
                    break;

                case SOCKET_EVENT_SEND_START:
                    UC_SRCE_TRACE_SM("event: send start");
                    context->resume_socket_phase = SOCKET_EVENT_SEND_START;
                    status = arm_uc_http_socket_send_request();
                    break;

                case SOCKET_EVENT_SEND_BLOCKED:
                    UC_SRCE_TRACE_SM("event: send blocked");
                    context->expected_socket_event = SOCKET_EVENT_SEND_DONE;
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_WAITING);
                    break;

                case SOCKET_EVENT_SEND_DONE:
                    /* Request has been sent, receive response */
                    UC_SRCE_TRACE_SM("event: send done");
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_HEADER_START);
                    break;

                case SOCKET_EVENT_HEADER_START:
                    UC_SRCE_TRACE_SM("event: header start");
                    context->resume_socket_phase = SOCKET_EVENT_HEADER_START;
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_HEADER_MORE);
                    break;

                case SOCKET_EVENT_HEADER_MORE:
                    UC_SRCE_TRACE_SM("event: header more");
                    status = arm_uc_http_socket_receive();
                    switch (ARM_UC_GET_ERROR(status)) {
                        case SRCE_ERR_BUSY:
                            // Nothing to read from the socket (it returned WOULD_BLOCK),
                            //   so try again a few times, until must give up and wait,
                            UC_SRCE_TRACE("event: empty header receive");
                            if (++empty_receive < MAX_EMPTY_RECEIVES) {
                                status = arm_uc_http_install_app_event(SOCKET_EVENT_HEADER_MORE);
                            } else {
                                UC_SRCE_TRACE("event: awaiting non-empty header");
                                // Just wait for notification, the rest hasn't arrived yet.
                                context->expected_socket_event = SOCKET_EVENT_HEADER_MORE;
                                ARM_UC_SET_ERROR(status, SRCE_ERR_NONE);
                            }
                            break;
                        case SRCE_ERR_NONE:
                            empty_receive = 0;
                            received_enough = false;
                            status = arm_uc_http_socket_has_received_header(&received_enough);
                            if (ARM_UC_GET_ERROR(status) == SRCE_ERR_ABORT) {
                                // If an ABORT error is returned, terminate the whole resume cycle.
                                UC_SRCE_TRACE("event: aborted, unable to receive header");
                                status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_TERMINATED);
                            } else if (ARM_UC_IS_NOT_ERROR(status)) {
                                if (received_enough) {
                                    status = arm_uc_http_socket_process_header();
                                    if (ARM_UC_IS_NOT_ERROR(status)) {
                                        status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_HEADER_DONE);
                                    } else if (ARM_UC_GET_ERROR(status) == SRCE_ERR_ABORT) {
                                        // If an ABORT error is returned, terminate the whole resume cycle.
                                        UC_SRCE_TRACE("event: aborted with bad header");
                                        status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_TERMINATED);
                                    } else if (ARM_UC_GET_ERROR(status) == SRCE_ERR_BUSY) {
                                        // Special case here of a redirecting header.
                                        // Do nothing, just wait for the newly scheduled event.
                                        ARM_UC_SET_ERROR(status, SRCE_ERR_NONE);
                                    }
                                } else {
                                    status = arm_uc_http_install_app_event(SOCKET_EVENT_HEADER_MORE);
                                }
                            }
                            break;
                        default:
                            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                            break;
                    }
                    break;

                case SOCKET_EVENT_HEADER_BLOCKED:
                    // Should never occur, handler only goes between more and done
                    // (because this is managed by local code, not the socket.)
                    UC_SRCE_TRACE_SM("event: header blocked");
                    ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                    break;

                case SOCKET_EVENT_HEADER_DONE:
                    UC_SRCE_TRACE_SM("event: header done");
                    arm_uc_resume_resynch_monitoring(&resume_http);
                    empty_receive = 0;
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_FRAG_START);
                    break;

                case SOCKET_EVENT_FRAG_START:
                    UC_SRCE_TRACE_SM("event: frag start");
                    context->resume_socket_phase = SOCKET_EVENT_FRAG_MORE;
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_FRAG_MORE);
                    break;

                case SOCKET_EVENT_FRAG_MORE:
                    UC_SRCE_TRACE_SM("event: frag more");
                    status = arm_uc_http_socket_receive();
                    switch (ARM_UC_GET_ERROR(status)) {
                        case SRCE_ERR_BUSY:
                            // Nothing to read from the socket (it returned WOULD_BLOCK),
                            //   so carry on in the same state, waiting for a callback from the socket.
                            // The resume-monitor should catch timeout errors.
                            // mbedOS tries again because implementations are slow enough to benefit.
                            UC_SRCE_TRACE("event: empty fragment receive");
                            if (++empty_receive < MAX_EMPTY_RECEIVES) {
                                status = arm_uc_http_install_app_event(SOCKET_EVENT_FRAG_MORE);
                            } else {
                                UC_SRCE_TRACE_SM("event: max empty fragment receives");
                                // just wait for notification, the rest hasn't arrived yet.
                                context->expected_socket_event = SOCKET_EVENT_FRAG_MORE;
                                ARM_UC_SET_ERROR(status, SRCE_ERR_NONE);
                            }
                            break;
                        case SRCE_ERR_NONE:
                            arm_uc_resume_resynch_monitoring(&resume_http);
                            ++context->number_of_pieces;
                            empty_receive = 0;

                            received_enough = false;
                            status = arm_uc_http_socket_has_received_frag(&received_enough);
                            if (ARM_UC_IS_NOT_ERROR(status)) {
                                if (received_enough) {
                                    status = arm_uc_http_socket_process_frag();
                                    if (ARM_UC_IS_NOT_ERROR(status)) {
                                        status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_FRAG_DONE);
                                    }
                                } else {
                                    status = arm_uc_http_install_app_event(SOCKET_EVENT_FRAG_MORE);
                                }
                            }
                            break;
                        default:
                            ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                            break;
                    }
                    break;

                case SOCKET_EVENT_FRAG_BLOCKED:
                    // Should never occur, handler only goes between more and done.
                    // (because this is managed by local code, not the socket.)
                    UC_SRCE_TRACE_SM("event: frag blocked");
                    ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
                    break;

                case SOCKET_EVENT_FRAG_DONE:
                    UC_SRCE_TRACE_SM("event: frag done");
                    arm_uc_resume_end_monitoring(&resume_http);
                    context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
                    ARM_UC_PostCallback(NULL, context->callback_handler, UCS_HTTP_EVENT_DOWNLOAD);

                    // Socket has been mangled by bad link, give it a chance to clear itself up.
                    if (context->number_of_pieces >= frags_per_burst) {
                        arm_uc_http_socket_close();
                    }
                    break;

                case SOCKET_EVENT_TIMER_FIRED:
                    UC_SRCE_TRACE_SM("event: warning: socket timer fired");
                    break;

                case SOCKET_EVENT_RESUME_WAITING:
                    UC_SRCE_TRACE_SM("event: begin resume waiting");
                    // Just a marker event to make code and trace more readable.
                    break;

                case SOCKET_EVENT_RESUME_INTERVAL:
                    UC_SRCE_TRACE_SM("event: http-socket resume interval - timeout");
                    // The socket API isn't reliable, so we use the resume interval timer to
                    //   artificially propose that the expected event has in fact arrived.
                    // This should be set to be longer than the event would take if not lost.
                    if (context->expected_socket_event != 0) {
                        status = arm_uc_http_prepare_skip_to_event(context->expected_socket_event);
                        context->expected_socket_event = 0;
                    }
                    break;

                case SOCKET_EVENT_RESUME_ATTEMPT:
                    // Resume will attempt to pick up where the last events were happening.
                    UC_SRCE_TRACE_SM("event: http-socket resume attempt");
                    // Now try to actually get a fragment for the resumption.
                    UC_SRCE_TRACE("with resource state currently");
                    UC_SRCE_TRACE("     offset %" PRIu32, context->request_offset);
                    UC_SRCE_TRACE("     host %s", context->request_uri->host);
                    UC_SRCE_TRACE("     path %s", context->request_uri->path);
                    UC_SRCE_TRACE("     filled %" PRIu32, context->request_buffer->size);
                    UC_SRCE_TRACE("next attempt in %" PRIu32 " secs", resume_http.expected_delay / 1000);
                    UC_SRCE_TRACE("  (sum total is %" PRIu32 " secs)", resume_http.sum_total_period / 1000);
                    UC_SRCE_TRACE("  (max total is %" PRIu32 " secs)", resume_http.activity_max_time / 1000);

                    UC_QA_TRACE("\r\nHTTP download-resume attempt now, next in %"PRIu32" seconds.\r\n",
                                resume_http.jitter_delay / 1000);

                    // Now decide just how aggressive to be about resuming.
                    // Every attempt closes the socket, every second attempt flushes the DNS cache.
#if (PAL_DNS_API_VERSION >= 2)
                    // Cancel ongoing asynchronous DNS query (only if non-zero handle).
                    arm_uc_http_cancel_dns_lookup();
#endif
                    if (resume_http.num_attempts != 0) {
                        arm_uc_http_socket_close();
                        context->resume_socket_phase = SOCKET_EVENT_CONNECT_START;
                        if (resume_http.num_attempts % 2 == 0) {
                            arm_uc_http_clear_dns_cache_fields();
                        }
                    }
                    if (!arm_uc_dns_lookup_is_cached()) {
                        context->resume_socket_phase = SOCKET_EVENT_LOOKUP_START;
                    }
                    if (context->resume_socket_phase != 0) {
                        status = arm_uc_http_prepare_skip_to_event(context->resume_socket_phase);
                        context->resume_socket_phase = SOCKET_EVENT_UNDEFINED;
                    }
                    break;

                case SOCKET_EVENT_RESUME_TERMINATED:
                    // Note that this case will leave the switch with an error,
                    //   which will invoke clean-up as appropriate.
                    UC_SRCE_TRACE_SM("event: http-socket resume ended");

#if (PAL_DNS_API_VERSION >= 2)
                    // Cancel ongoing asynchronous DNS query (only if non-zero handle).
                    arm_uc_http_cancel_dns_lookup();
#endif
                    arm_uc_resume_end_monitoring(&resume_http);

                    UC_QA_TRACE("\r\nHTTP download-resume terminating now.\r\n");
                    UC_SRCE_ERR_MSG("event handler: failed with %" PRIu32 ", %" PRIx32 ", %s",
                                    an_event, (uint32_t)status.code, ARM_UC_err2Str(status));
                    arm_uc_http_socket_fatal_error(last_http_error_event);
                    break;

                case SOCKET_EVENT_RESUME_ERROR:
                    UC_SRCE_TRACE_SM("event: http-socket resume errored");
#if (PAL_DNS_API_VERSION >= 2)
                    // Cancel ongoing asynchronous DNS query (only if non-zero handle).
                    arm_uc_http_cancel_dns_lookup();
#endif
                    arm_uc_resume_end_monitoring(&resume_http);
                    arm_uc_http_socket_fatal_error(UCS_HTTP_EVENT_ERROR);
                    break;

                default:
                    UC_SRCE_TRACE_SM("error: unknown event type!");
#if (PAL_DNS_API_VERSION >= 2)
                    // Cancel ongoing asynchronous DNS query (only if non-zero handle).
                    arm_uc_http_cancel_dns_lookup();
#endif
                    status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_WAITING);
                    break;
            }
            if (ARM_UC_IS_ERROR(status)) {
                status = arm_uc_http_prepare_skip_to_event(SOCKET_EVENT_RESUME_WAITING);
            }
            an_event = 0;
            // Check if there is a skip-to-event to handle.
            skip_text_p = skip_to_event ? "auto" : "";
            if (skip_to_event != 0) {
                an_event = skip_to_event;
                skip_to_event = 0;
            }
        } while (an_event != 0);
    }
}

/**
 * @brief Callback handler for PAL socket events. Callbacks go through the task
 *        queue because we don't know what context we are running from.
 * @details Note that we don't do printing inside here, because we could be running
 *            from inside an interrupt context.
 */
arm_uc_error_t arm_uc_http_install_event(
    arm_uc_http_socket_event_t an_event)
{
    ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);

    if (context == NULL) {
        ARM_UC_SET_ERROR(status, SRCE_ERR_FAILED);
    } else {
        ARM_UC_PostCallback(
            NULL,
            arm_uc_http_socket_callback,
            an_event);
    }
    return status;
}

static inline arm_uc_error_t arm_uc_http_install_isr_event(
    arm_uc_http_socket_event_t an_event)
{
    return arm_uc_http_install_event(an_event | ISR_EVENT_MASK);
}

static inline arm_uc_error_t arm_uc_http_install_app_event(
    arm_uc_http_socket_event_t an_event)
{
    return arm_uc_http_install_event(an_event);
}

/**
 * @brief Filter socket events before installing as ISR events.
 */
void arm_uc_http_socket_isr(
    void *an_event)
{
    if (context != NULL) {
        // Only allow a single typeless socket event at a time.
        if (context->expected_socket_event == SOCKET_EVENT_UNDEFINED) {
            // Drop this event.
        } else {
            // Expected as the next event generated by the socket.
            arm_uc_http_socket_event_t event = context->expected_socket_event;
            ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);
            status = arm_uc_http_install_isr_event(event);
            if (ARM_UC_IS_NOT_ERROR(status)) {
                context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
            }
        }
    }
}

/**
 * @brief Callback handler for the asynchronous DNS resolver.
 *        Callbacks go through the task queue because we don't know
 *        what context we are running from.
 */
#if (PAL_DNS_API_VERSION >= 2)
void arm_uc_dns_callback_handler(
    const char *url,
    palSocketAddress_t *address,
    palStatus_t pal_status,
    void *argument)
#else
void arm_uc_dns_callback_handler(
    const char *url,
    palSocketAddress_t *address,
    palSocketLength_t *address_length,
    palStatus_t pal_status,
    void *argument)
#endif
{
    (void) url;
    (void) address;
#if (PAL_DNS_API_VERSION < 2)
    (void) address_length;
#endif
    (void) argument;

    if (context != NULL) {
        arm_uc_http_socket_event_t event;
#if (PAL_DNS_API_VERSION >= 2)
        arm_uc_dns_query_handle = 0;
#endif
        /* accept the DNS callback event only if we were expecting it. */
        if (expecting_dns_callback) {
            expecting_dns_callback = false;
            if (pal_status == PAL_SUCCESS) {
                event = ((arm_uc_http_socket_event_t) SOCKET_EVENT_LOOKUP_DONE);
            } else {
                /* Clear the address-related fields to signal an error */
                event = ((arm_uc_http_socket_event_t) SOCKET_EVENT_LOOKUP_FAILED);
            }
            ARM_UC_INIT_ERROR(status, SRCE_ERR_NONE);
            status = arm_uc_http_install_isr_event(event);
            // Only clear the resume expected-event if this has installed correctly.
            // Otherwise rely on the fake resume-interval-event to take care of things.
            if (ARM_UC_IS_NOT_ERROR(status)) {
                context->expected_socket_event = SOCKET_EVENT_UNDEFINED;
            }
        } else {
            UC_SRCE_TRACE("unexpected %s" PRIx32, __func__);
        }
    }
}

#endif // ARM_UC_FEATURE_FW_SOURCE_HTTP
