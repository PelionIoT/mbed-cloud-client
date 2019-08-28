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

#include <stdio.h>

#include "update_client_hub_error_handler.h"

#include "update-client-control-center/arm_uc_control_center.h"
#include "update-client-common/arm_uc_common.h"

#include <stdio.h> // for snprintf

static void (*arm_uc_error_callback_handler)(int32_t error) = NULL;

void ARM_UC_HUB_AddErrorCallbackInternal(void (*callback)(int32_t error))
{
    arm_uc_error_callback_handler = callback;
}

/**
 * @brief Error handler.
 * @details Generates error code for the user application and any registered
 *          monitors. Also responsible for setting the Hub back to a consistent state.
 *          Supported error codes: All elements of arm_uc_monitor_result_t.
 * @param error arm_uc_error_t code.
 * @param state Internal Hub state.
 */
void ARM_UC_HUB_ErrorHandler(int32_t error, arm_uc_hub_state_t state)
{
    UC_HUB_TRACE("error: %" PRIX32 " %d", (uint32_t) error, state);

#if ARM_UC_HUB_TRACE_ENABLE
    uint32_t trace_val = 0;
    char *trace_str = "";
    char trace_buf[sizeof("XX:65536")];
#define TRACE_ARGS(s) do { trace_val = ((uint32_t)error); trace_str = (s); } while(0);
#else
#define TRACE_ARGS(s)
#endif

    /* Use common defaults for code size optimisation - avoids duplicate assignments. */
    /* Returns these values for any not otherwise overridden. */
    int32_t error_external = ARM_UC_ERROR;
    arm_uc_monitor_result_t error_monitor = ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR;

    arm_uc_hub_state_t next_state = ARM_UC_HUB_STATE_WAIT_FOR_ERROR_ACK;

    switch (error) {
        /* Update Client */
        case ERR_UNSPECIFIED:
            TRACE_ARGS("ERR_UNSPECIFIED");
            break;
        case ERR_INVALID_PARAMETER:
            TRACE_ARGS("ERR_INVALID_PARAMETER");
            break;
        case ERR_NULL_PTR:
            TRACE_ARGS("ERR_NULL_PTR");
            break;
        case ERR_NOT_READY:
            TRACE_ARGS("ERR_NOT_READY");
            break;
        case ERR_INVALID_STATE:
            TRACE_ARGS("ERR_INVALID_STATE");
            break;
        case ERR_OUT_OF_MEMORY:
            TRACE_ARGS("ERR_OUT_OF_MEMORY");
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_INSUFFICIENT_MEMORY_SPACE;
            break;

        /* Update Authorization */
        case AUTH_ERR_INSTALL_REJECTED:
            TRACE_ARGS("AUTH_ERR_INSTALL_REJECTED");
            error_external = ARM_UC_WARNING_AUTHORIZATION_REJECTED;
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_AUTHORIZATON_REJECTED;
            break;
        case AUTH_ERR_INSTALL_UNAVAILABLE:
            TRACE_ARGS("AUTH_ERR_INSTALL_UNAVAILABLE");
            error_external = ARM_UC_WARNING_AUTHORIZATION_UNAVAILABLE;
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_AUTHORIZATON_UNAVAILABLE;
            break;
        case AUTH_ERR_DOWNLOAD_REJECTED:
            TRACE_ARGS("AUTH_ERR_DOWNLOAD_REJECTED");
            error_external = ARM_UC_WARNING_AUTHORIZATION_REJECTED;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_AUTHORIZATON_REJECTED;
            break;
        case AUTH_ERR_DOWNLOAD_UNAVAILABLE:
            TRACE_ARGS("AUTH_ERR_DOWNLOAD_UNAVAILABLE");
            error_external = ARM_UC_WARNING_AUTHORIZATION_UNAVAILABLE;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_AUTHORIZATON_UNAVAILABLE;
            break;

        /* Certificate Manager */
        case ARM_UC_CM_ERR_NOT_FOUND:
            TRACE_ARGS("ARM_UC_CM_ERR_NOT_FOUND");
            error_external = ARM_UC_WARNING_CERTIFICATE_NOT_FOUND;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_CERTIFICATE_NOT_FOUND;
            break;
        case ARM_UC_CM_ERR_INVALID_CERT:
        case ARM_UC_CM_ERR_BLACKLISTED:
            TRACE_ARGS("ARM_UC_CM_ERR_INVALID_CERT/BLACKLISTED");
            error_external = ARM_UC_WARNING_CERTIFICATE_INVALID;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_CERTIFICATE;
            break;

        /* DER Parser */
        case ARM_UC_DP_ERR_UNKNOWN:
        case ARM_UC_DP_ERR_NOT_FOUND:
        case ARM_UC_DP_ERR_NO_MORE_ELEMENTS:
            TRACE_ARGS("ARM_UC_DP_ERR_UNKNOWN/NOT_FOUND/NO_MORE_ELEMENTS");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_MANIFEST_FORMAT;
            break;

        /* Firmware Manager */
        case FIRM_ERR_WRITE:
            TRACE_ARGS("FIRM_ERR_WRITE");
            error_external = ARM_UC_ERROR_WRITE_TO_STORAGE;
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_WRITE_FAILURE;
            break;
        case FIRM_ERR_INVALID_PARAMETER:
        case FIRM_ERR_UNINITIALIZED:
            TRACE_ARGS("FIRM_ERR_INVALID_PARAMETER/UNINITIALIZED");
            error_external = ARM_UC_ERROR_WRITE_TO_STORAGE;
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_NONSPECIFIC_ERROR;
            break;
        case FIRM_ERR_ACTIVATE:
            TRACE_ARGS("FIRM_ERR_ACTIVATE");
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_ACTIVATION_FAILURE;
            break;
        case FIRM_ERR_INVALID_HASH:
            TRACE_ARGS("FIRM_ERR_INVALID_HASH");
            error_external = ARM_UC_ERROR_INVALID_HASH;
            error_monitor = ARM_UC_UPDATE_RESULT_WRITER_HASH_ERROR;
            break;
        case FIRM_ERR_FIRMWARE_TOO_LARGE:
            TRACE_ARGS("FIRM_ERR_FIRMWARE_TOO_LARGE");
            error_external = ARM_UC_ERROR_WRITE_TO_STORAGE;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INSUFFICIENT_STORAGE_SPACE;
            break;

        /* Manifest Manager */
        case MFST_ERR_NULL_PTR:
            TRACE_ARGS("MFST_ERR_NULL_PTR");
            error_external = ARM_UC_WARNING_IDENTITY_NOT_FOUND;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        case MFST_ERR_NOT_READY:
            TRACE_ARGS("MFST_ERR_NOT_READY");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        // case MFST_ERR_PENDING IS NOT AN ERROR!
        case MFST_ERR_SIZE:
            TRACE_ARGS("MFST_ERR_SIZE");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_MANIFEST_SIZE;
            break;
        case MFST_ERR_DER_FORMAT:
        case MFST_ERR_FORMAT:
            TRACE_ARGS("MFST_ERR_DER_FORMAT/MFST_ERR_FORMAT");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_MANIFEST_FORMAT;
            break;
        case MFST_ERR_VERSION:
            TRACE_ARGS("MFST_ERR_VERSION");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_UNSUPPORTED_MANIFEST_VERSION;
            break;
        case MFST_ERR_ROLLBACK:
            TRACE_ARGS("MFST_ERR_ROLLBACK");
            error_external = ARM_UC_WARNING_ROLLBACK_PROTECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_ROLLBACK_PROTECTION;
            break;
        case MFST_ERR_CRYPTO_MODE:
            TRACE_ARGS("MFST_ERR_CRYPTO_MODE");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_CRYPTO_MODE;
            break;
        case MFST_ERR_HASH:
            TRACE_ARGS("MFST_ERR_HASH");
            error_external = ARM_UC_WARNING_SIGNATURE_INVALID;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INTEGRITY_CHECK_FAILED;
            break;
        case MFST_ERR_GUID_VENDOR:
            TRACE_ARGS("MFST_ERR_GUID_VENDOR");
            error_external = ARM_UC_WARNING_VENDOR_MISMATCH;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_WRONG_VENDOR_ID;
            break;
        case MFST_ERR_GUID_DEVCLASS:
            TRACE_ARGS("MFST_ERR_GUID_DEVCLASS");
            error_external = ARM_UC_WARNING_CLASS_MISMATCH;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_WRONG_CLASS_ID;
            break;
        case MFST_ERR_GUID_DEVICE:
            TRACE_ARGS("MFST_ERR_GUID_DEVICE");
            error_external = ARM_UC_WARNING_DEVICE_MISMATCH;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        case MFST_ERR_CERT_INVALID:
            TRACE_ARGS("MFST_ERR_CERT_INVALID");
            error_external = ARM_UC_WARNING_CERTIFICATE_INVALID;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_CERTIFICATE;
            break;
        case MFST_ERR_CERT_NOT_FOUND:
        case MFST_ERR_CERT_READ:
            TRACE_ARGS("MFST_ERR_CERT_NOT_FOUND/READ");
            error_external = ARM_UC_WARNING_CERTIFICATE_NOT_FOUND;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_CERTIFICATE_NOT_FOUND;
            break;
        case MFST_ERR_INVALID_SIGNATURE:
            TRACE_ARGS("MFST_ERR_INVALID_SIGNATURE");
            error_external = ARM_UC_WARNING_SIGNATURE_INVALID;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_SIGNATURE;
            break;
        case MFST_ERR_INVALID_STATE:
            TRACE_ARGS("MFST_ERR_INVALID_STATE");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        case MFST_ERR_BAD_EVENT:
            TRACE_ARGS("MFST_ERR_BAD_EVENT");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        case MFST_ERR_EMPTY_FIELD:
            TRACE_ARGS("MFST_ERR_EMPTY_FIELD");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_MISSING_FIELD;
            break;
        case MFST_ERR_NO_MANIFEST:
            TRACE_ARGS("MFST_ERR_NO_MANIFEST");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_DEPENDENT_MANIFEST_NOT_FOUND;
            break;
        case MFST_ERR_SIGNATURE_ALGORITHM:
        case MFST_ERR_UNSUPPORTED_CONDITION:
            TRACE_ARGS("MFST_ERR_SIGNATURE_ALGORITHM/UNSUPPORTED_CONDITION");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        case MFST_ERR_CTR_IV_SIZE:
        case MFST_ERR_BAD_KEYTABLE:
            TRACE_ARGS("MFST_ERR_CTR_IV_SIZE/BAD_KEYTABLE");
            error_external = ARM_UC_WARNING_BAD_KEYTABLE;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_CORRUPTED_KEYTABLE;
            break;
        case MFST_ERR_MISSING_KEYTABLE:
            TRACE_ARGS("MFST_ERR_MISSING_KEYTABLE");
            error_external = ARM_UC_WARNING_BAD_KEYTABLE;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_MISSING_ITEM;
            break;
        case MFST_ERR_FIRMWARE_SIZE:
            TRACE_ARGS("MFST_ERR_FIRMWARE_SIZE");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;

        /* Source Manager */
        // case SOMA_ERR_UNSPECIFIED IS NOT USED!
        case SOMA_ERR_NETWORK_TIMEOUT:
            TRACE_ARGS("SOMA_ERR_NETWORK_TIMEOUT");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_TIMEOUT;
            break;
        case SOMA_ERR_CONNECTION_FAILURE:
            TRACE_ARGS("SOMA_ERR_CONNECTION_FAILURE");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_FAILURE;
            break;
        case SOMA_ERR_DNS_LOOKUP_FAILURE:
            TRACE_ARGS("SOMA_ERR_DNS_LOOKUP_FAILURE");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_DNS_LOOKUP_FAILURE;
            break;
        case SOMA_ERR_CONNECTION_LOSS:
            TRACE_ARGS("SOMA_ERR_CONNECTION_LOSS");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_LOSS;
            break;
        case SOMA_ERR_NO_ROUTE_TO_SOURCE:
            TRACE_ARGS("SOMA_ERR_NO_ROUTE_TO_SOURCE");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_NO_ROUTE_AVAILABLE;
            break;
        case SOMA_ERR_SOURCE_REGISTRY_FULL:
        case SOMA_ERR_SOURCE_NOT_FOUND:
            TRACE_ARGS("SOMA_ERR_SOURCE_REGISTRY_FULL/SOURCE_NOT_FOUND");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_NETWORK_ERROR;
            break;
        case SOMA_ERR_INVALID_URI:
            TRACE_ARGS("SOMA_ERR_INVALID_URI");
            error_external = ARM_UC_WARNING_URI_NOT_FOUND;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_INVALID_RESOURCE_URI;
            break;
        case SOMA_ERR_INVALID_REQUEST:
            TRACE_ARGS("SOMA_ERR_INVALID_REQUEST");
            error_external = ARM_UC_WARNING_URI_NOT_FOUND;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_INVALID_REQUEST_TYPE;
            break;
        case SOMA_ERR_INVALID_PARAMETER:
            TRACE_ARGS("SOMA_ERR_INVALID_PARAMETER");
            error_external = ARM_UC_WARNING_URI_NOT_FOUND;
            break;
        case SOMA_ERR_INVALID_MANIFEST_STATE:
            TRACE_ARGS("SOMA_ERR_INVALID_MANIFEST_STATE");
            error_external = ARM_UC_WARNING_UNKNOWN;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR;
            break;
        case SOMA_ERR_INVALID_FW_STATE:
            TRACE_ARGS("SOMA_ERR_INVALID_FW_STATE");
            error_external = ARM_UC_WARNING_UNKNOWN;
            break;
        case SOMA_ERR_INVALID_EVENT:
            TRACE_ARGS("SOMA_ERR_INVALID_EVENT");
            error_external = ARM_UC_WARNING_UNKNOWN;
            break;

        /* Source */
        case SRCE_ERR_UNINITIALIZED:
        case SRCE_ERR_INVALID_PARAMETER:
        case SRCE_ERR_FAILED:
        case SRCE_ERR_ABORT:
            TRACE_ARGS("SRCE_ERR_UNINITIALIZED/INVALID_PARAMETER/FAILED/ABORT");
            error_monitor = ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR;
            break;
        case SRCE_ERR_BUSY:
            /* Unexpected, normally used for flow control, not as error. */
            TRACE_ARGS("SRCE_ERR_BUSY");
            error_monitor = ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR;
            break;

        /* Crypto */
        case ARM_UC_CU_ERR_INVALID_PARAMETER:
            TRACE_ARGS("ARM_UC_CU_ERR_INVALID_PARAMETER");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_CRYPTO_MODE;
            break;

        /* Device Identity */
        case ARM_UC_DI_ERR_INVALID_PARAMETER:
            TRACE_ARGS("ARM_UC_DI_ERR_INVALID_PARAMETER");
            error_monitor = ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR;
            break;
        case ARM_UC_DI_ERR_NOT_READY:
        case ARM_UC_DI_ERR_NOT_FOUND:
            TRACE_ARGS("ARM_UC_DI_ERR_NOT_READY/NOT_FOUND");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_MISSING_ITEM;
            break;
        case ARM_UC_DI_ERR_SIZE:
            TRACE_ARGS("ARM_UC_DI_ERR_SIZE");
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_INSUFFICIENT_MEMORY_SPACE;
            break;

        /* Hub */
        case HUB_ERR_INTERNAL_ERROR:
            TRACE_ARGS("HUB_ERR_INTERNAL_ERROR");
            error_external = ARM_UC_FATAL;
            break;
        case HUB_ERR_ROLLBACK_PROTECTION:
            TRACE_ARGS("HUB_ERR_ROLLBACK_PROTECTION");
            error_external = ARM_UC_WARNING_ROLLBACK_PROTECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_MANIFEST_ROLLBACK_PROTECTION;
            break;
        case ARM_UC_HUB_ERR_NOT_AVAILABLE:
            TRACE_ARGS("ARM_UC_HUB_ERR_NOT_AVAILABLE");
            error_external = ARM_UC_ERROR_CONNECTION;
            break;
        /* LWM2M source */
        case HUB_ERR_CONNECTION:
            TRACE_ARGS("HUB_ERR_CONNECTION");
            error_external = ARM_UC_ERROR_CONNECTION;
            error_monitor = ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_FAILURE;
            /* Prevent a possible infinite loop: when HUB_ERR_CONNECTION is received,
               the next state was always set to ARM_UC_HUB_STATE_UNKNOWN. However,
               this function also sends a report which might fail, which will trigger
               the HUB_ERR_CONNECTION event and will repeat the whole process again,
               potentially in an infinite loop in case of network issues. So switch
               the state to "idle" directly to prevent this.*/
            next_state = ARM_UC_HUB_STATE_IDLE;
            break;

        default:
            UC_HUB_ERR_MSG("Unexpected error!");
#if ARM_UC_HUB_TRACE_ENABLE
            {
                arm_uc_error_t err;
                err.code = (uint32_t)error;
                snprintf(trace_buf, sizeof(trace_buf), "%c%c.%hu",
                    err.modulecc[0], err.modulecc[1], err.error);
            }
#endif
            TRACE_ARGS(trace_buf);
            error_external = ARM_UC_WARNING_UNKNOWN;
            break;
    }
    UC_HUB_TRACE("%s: %" PRIX32, trace_str, (uint32_t) trace_val);

    /* send error code to monitor */
    ARM_UC_ControlCenter_ReportUpdateResult(error_monitor);

    /* progress state in hub */
    ARM_UC_HUB_setState(next_state);

    /* Send the external code to the user application. */
    if (arm_uc_error_callback_handler) {
        arm_uc_error_callback_handler(error_external);
    }
}
