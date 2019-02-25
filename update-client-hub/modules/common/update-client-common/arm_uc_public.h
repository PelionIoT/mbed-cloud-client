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

#ifndef ARM_UPDATE_COMMON_PUBLIC_H
#define ARM_UPDATE_COMMON_PUBLIC_H

#include <stdint.h>
#include <stdbool.h>

#define ARM_UC_MAJOR_VERSION 1
#define ARM_UC_MINOR_VERSION 4
#define ARM_UC_PATCH_VERSION 1

#define ARM_UC_ENCODE_VERSION_INT(major, minor, patch) ((major)*100000 + (minor)*1000 + (patch))
#define ARM_UC_ENCODE_VERSION_STR(major, minor, patch) "Update Client " #major "." #minor "." #patch

#define ARM_UC_VERSION_STR ARM_UC_ENCODE_VERSION_STR(ARM_UC_MAJOR_VERSION, ARM_UC_MINOR_VERSION, ARM_UC_PATCH_VERSION)
#define ARM_UC_VERSION_INT ARM_UC_ENCODE_VERSION_INT(ARM_UC_MAJOR_VERSION, ARM_UC_MINOR_VERSION, ARM_UC_PATCH_VERSION)

#ifndef ARM_UPDATE_CLIENT_VERSION
#define ARM_UPDATE_CLIENT_VERSION ARM_UC_VERSION_STR
#endif

#ifndef ARM_UPDATE_CLIENT_VERSION_VALUE
#define ARM_UPDATE_CLIENT_VERSION_VALUE ARM_UC_VERSION_INT
#endif

/**
 * Public error codes for the Update Client.
 *
 * When modifying the error codes, you must also update the respective
 * codes in MbedCloudClient.h and UpdateClient.h in mbed-cloud-client
 */
enum {
    ARM_UC_WARNING,
    ARM_UC_WARNING_CERTIFICATE_NOT_FOUND,
    ARM_UC_WARNING_IDENTITY_NOT_FOUND,
    ARM_UC_WARNING_VENDOR_MISMATCH,
    ARM_UC_WARNING_CLASS_MISMATCH,
    ARM_UC_WARNING_DEVICE_MISMATCH,
    ARM_UC_WARNING_CERTIFICATE_INVALID,
    ARM_UC_WARNING_SIGNATURE_INVALID,
    ARM_UC_WARNING_BAD_KEYTABLE,
    ARM_UC_WARNING_URI_NOT_FOUND,
    ARM_UC_WARNING_ROLLBACK_PROTECTION,
    ARM_UC_WARNING_UNKNOWN,
    ARM_UC_ERROR,
    ARM_UC_ERROR_WRITE_TO_STORAGE,
    ARM_UC_ERROR_INVALID_HASH,
    ARM_UC_ERROR_CONNECTION,
    ARM_UC_FATAL,
    ARM_UC_UNKNOWN
};

/**
 * Public update requests
 */
typedef enum {
    ARM_UCCC_REQUEST_INVALID,
    ARM_UCCC_REQUEST_DOWNLOAD,
    ARM_UCCC_REQUEST_INSTALL,
} arm_uc_request_t;

/**
 * New State & Result -enums based on http://www.openmobilealliance.org/tech/profiles/lwm2m/10252.xml
 */

/**
 *  UPDATE STATE.
 *
 *      This enumeration lists the possible states of an Update Process finite state machine (FSM).
 *
 *      ARM_UC_UPDATE_STATE_UNINITIALISED
 *
 *          This is always the initial state of the FSM. All operations and events are ignored
 *            until the FSM has been initialized, at which point it transitions to the IDLE state.
 *
 *            UNINITIALISED {Initialize} -> IDLE
 *
 *      ARM_UC_UPDATE_STATE_IDLE
 *
 *          This is the state after initialization, but before an update has been initiated. Once
 *            an update has been started, the FSM state will transition to the following states in
 *            sequence.
 *
 *            IDLE {BeginUpdate} -> PROCESSING_MANIFEST
 *
 *          If at any point or state the update process fails, and a failure event is generated,
 *            the state will be reset to the default fallback state of IDLE.
 *
 *            <ANY_ACTIVE_STATE> {Fail} -> IDLE
 *
 *      ARM_UC_UPDATE_STATE_PROCESSING_MANIFEST
 *
 *          Once the manifest is received, it is checked for validity, and a request is made for
 *            download approval from the application.
 *
 *            PROCESSING_MANIFEST {ManifestProcessingDone} -> AWAITING_DOWNLOAD_APPROVAL
 *
 *      ARM_UC_UPDATE_STATE_AWAITING_DOWNLOAD_APPROVAL
 *
 *          This state is necessary to avoid interfering with possibly critical operations being
 *          undertaken by the application.
 *
 *            AWAITING_DOWNLOAD_APPROVAL {Approved} -> DOWNLOADING_UPDATE
 *            AWAITING_DOWNLOAD_APPROVAL {NotApproved} -> IDLE
 *
 *      ARM_UC_UPDATE_STATE_DOWNLOADING_UPDATE
 *
 *          After approval, the download begins. Once this completes and the full package has been
 *            downloaded and stored, the FSM requests approval for installation of the package.
 *
 *            DOWNLOADING_UPDATE {DownloadingDone} -> AWAITING_INSTALL_APPROVAL
 *
 *      ARM_UC_UPDATE_STATE_AWAITING_INSTALL_APPROVAL
 *
 *          Similar considerations apply as for ARM_UC_UPDATE_STATE_AWAITING_DOWNLOAD_APPROVAL above,
 *            but in this case the device will additionally reboot after installation has completed.
 *
 *            AWAITING_INSTALL_APPROVAL {Approved} -> INSTALLING_UPDATE
 *            AWAITING_INSTALL_APPROVAL {NotApproved} -> IDLE
 *
 *      ARM_UC_UPDATE_STATE_INSTALLING_UPDATE
 *
 *          Once the update has been installed, the device will reboot in order to start running
 *            with the newly installed download.
 *
 *            INSTALLING_UPDATE {InstallDone} -> REBOOTING
 *
 *      ARM_UC_UPDATE_STATE_REBOOTING
 *
 *          After a reboot the FSM will start up in the UNINITIALISED state.
 *
 *            REBOOTING {Rebooted} -> UNINITIALISED
 *
 */
typedef enum {
    ARM_UC_UPDATE_STATE_FIRST                                  = 0,
    ARM_UC_UPDATE_STATE_UNINITIALISED                          = ARM_UC_UPDATE_STATE_FIRST,
    ARM_UC_UPDATE_STATE_IDLE                                   = 1,
    ARM_UC_UPDATE_STATE_PROCESSING_MANIFEST                    = 2,
    ARM_UC_UPDATE_STATE_AWAITING_DOWNLOAD_APPROVAL             = 3,
    ARM_UC_UPDATE_STATE_DOWNLOADING_UPDATE                     = 4,
    ARM_UC_UPDATE_STATE_DOWNLOADED_UPDATE                      = 5,
    ARM_UC_UPDATE_STATE_AWAITING_INSTALL_APPROVAL              = 6,
    ARM_UC_UPDATE_STATE_INSTALLING_UPDATE                      = 7,
    ARM_UC_UPDATE_STATE_REBOOTING                              = 8,
    ARM_UC_UPDATE_STATE_LAST                                   = ARM_UC_UPDATE_STATE_REBOOTING
} arm_uc_update_state_t;

/**
 * UPDATE RESULT.
 *
 *      Update operations can either succeed or fail. Various possible failures are given here.
 *        Where any particular actual failure is not covered by a specific identifying error case,
 *        it will be classified as a NONSPECIFIC_ERROR.
 *
 *      ARM_UC_UPDATE_RESULT_UPDATE_ defines result codes general to the update process and not covered
 *        by the more specific result codes following. Within the ARM_UC_UPDATE_RESULT_UPDATE_ range,
 *        the result code can identify varying levels of specificity.
 *
 *      ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR defines an error result code that
 *        indicates an error which cannot be directly addressed by the customer, but must be reported
 *        to Arm for further examination.
 *
 *      ARM_UC_UPDATE_RESULT_MANIFEST_ codes indicate results related to manifest processing during
 *        the update process.
 *
 *      ARM_UC_UPDATE_RESULT_FETCHER_ codes indicate results related to fetching of updates from the
 *        cloud service.
 *
 *      ARM_UC_UPDATE_RESULT_PROCESSOR_ codes indicate results related to processing of updates fetched
 *        from the cloud service. Processing entails some manipulation of the update in such a way that
 *        it is made suitable for use by the device. This could be decryption, decompression, delta
 *        reconstruction etc.
 *
 *      ARM_UC_UPDATE_RESULT_WRITER_ codes indicate results related to writing or storing of the update
 *        to some medium necessary for further use by the device, eg flash or SD card.
 */

typedef enum {
    // General conditions.
    // -------------------
    ARM_UC_UPDATE_RESULT_UPDATE_FIRST                          = 100,
    ARM_UC_UPDATE_RESULT_UPDATE_SUCCEEDED                        = ARM_UC_UPDATE_RESULT_UPDATE_FIRST,
    ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_NETWORK_ERROR      = 101,
    ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_VALIDITY_ERROR     = 102,
    ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR       = 103,
    ARM_UC_UPDATE_RESULT_UPDATE_LAST                           = ARM_UC_UPDATE_RESULT_UPDATE_NONSPECIFIC_SYSTEM_ERROR,

    // Manifest-specific conditions.
    // -----------------------------
    ARM_UC_UPDATE_RESULT_MANIFEST_FIRST                        = 200,
    ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_ERROR            = ARM_UC_UPDATE_RESULT_MANIFEST_FIRST,
    ARM_UC_UPDATE_RESULT_MANIFEST_NONSPECIFIC_NETWORK_ERROR    = 201,
    ARM_UC_UPDATE_RESULT_MANIFEST_NETWORK_TIMEOUT              = 202,
    ARM_UC_UPDATE_RESULT_MANIFEST_NETWORK_CONNECTION_FAILURE   = 203,
    ARM_UC_UPDATE_RESULT_MANIFEST_DNS_LOOKUP_FAILURE           = 204,
    ARM_UC_UPDATE_RESULT_MANIFEST_NETWORK_CONNECTION_LOSS      = 205,
    ARM_UC_UPDATE_RESULT_MANIFEST_NOT_FOUND                    = 206,
    ARM_UC_UPDATE_RESULT_MANIFEST_INTEGRITY_CHECK_FAILED       = 207,
    ARM_UC_UPDATE_RESULT_MANIFEST_CERTIFICATE_NOT_FOUND        = 208,
    ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_CERTIFICATE          = 209,
    ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_SIGNATURE            = 210,
    ARM_UC_UPDATE_RESULT_MANIFEST_DEPENDENT_MANIFEST_NOT_FOUND = 211,
    ARM_UC_UPDATE_RESULT_MANIFEST_ALREADY_PROCESSING_ERROR     = 212,
    ARM_UC_UPDATE_RESULT_MANIFEST_RESOURCE_ALREADY_PRESENT_ERROR = 213,
    ARM_UC_UPDATE_RESULT_MANIFEST_UNSUPPORTED_MANIFEST_VERSION = 214,
    ARM_UC_UPDATE_RESULT_MANIFEST_WRONG_VENDOR_ID              = 215,
    ARM_UC_UPDATE_RESULT_MANIFEST_WRONG_CLASS_ID               = 216,
    ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_MANIFEST_SIZE        = 217,
    ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_MANIFEST_FORMAT      = 218,
    ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_CRYPTO_MODE          = 219,
    ARM_UC_UPDATE_RESULT_MANIFEST_MISSING_FIELD                = 220,
    ARM_UC_UPDATE_RESULT_MANIFEST_ROLLBACK_PROTECTION          = 221,
    ARM_UC_UPDATE_RESULT_MANIFEST_MISSING_ITEM                 = 222,
    ARM_UC_UPDATE_RESULT_MANIFEST_CORRUPTED_KEYTABLE           = 223,
    ARM_UC_UPDATE_RESULT_MANIFEST_INVALID_KEYTABLE_ENCODING    = 224,
    ARM_UC_UPDATE_RESULT_MANIFEST_INSUFFICIENT_STORAGE_SPACE   = 225,
    ARM_UC_UPDATE_RESULT_MANIFEST_INSUFFICIENT_MEMORY_SPACE    = 226,
    ARM_UC_UPDATE_RESULT_MANIFEST_WRITE_FAILURE                = 227,
    ARM_UC_UPDATE_RESULT_MANIFEST_LAST                         = ARM_UC_UPDATE_RESULT_MANIFEST_WRITE_FAILURE,

    // Fetcher-specific conditions.
    // ----------------------------
    ARM_UC_UPDATE_RESULT_FETCHER_FIRST                         = 300,
    ARM_UC_UPDATE_RESULT_FETCHER_NONSPECIFIC_ERROR             = ARM_UC_UPDATE_RESULT_FETCHER_FIRST,
    ARM_UC_UPDATE_RESULT_FETCHER_NONSPECIFIC_NETWORK_ERROR     = 301,
    ARM_UC_UPDATE_RESULT_FETCHER_NO_ROUTE_AVAILABLE            = 302,
    ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_TIMEOUT               = 303,
    ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_FAILURE    = 304,
    ARM_UC_UPDATE_RESULT_FETCHER_DNS_LOOKUP_FAILURE            = 305,
    ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_LOSS       = 306,
    ARM_UC_UPDATE_RESULT_FETCHER_INVALID_RESOURCE_URI          = 307,
    ARM_UC_UPDATE_RESULT_FETCHER_INVALID_REQUEST_TYPE          = 308,
    ARM_UC_UPDATE_RESULT_FETCHER_INTEGRITY_CHECK_FAILED        = 309,
    ARM_UC_UPDATE_RESULT_FETCHER_USER_DEFINED_ERROR_1          = 310,
    ARM_UC_UPDATE_RESULT_FETCHER_USER_DEFINED_ERROR_2          = 311,
    ARM_UC_UPDATE_RESULT_FETCHER_USER_DEFINED_ERROR_3          = 312,
    ARM_UC_UPDATE_RESULT_FETCHER_USER_DEFINED_ERROR_4          = 313,
    ARM_UC_UPDATE_RESULT_FETCHER_USER_DEFINED_ERROR_5          = 314,
    ARM_UC_UPDATE_RESULT_FETCHER_LAST                          = ARM_UC_UPDATE_RESULT_FETCHER_USER_DEFINED_ERROR_5,

    // Processor-specific conditions.
    // ------------------------------
    ARM_UC_UPDATE_RESULT_PROCESSOR_FIRST                       = 400,
    ARM_UC_UPDATE_RESULT_PROCESSOR_NONSPECIFIC_ERROR           = ARM_UC_UPDATE_RESULT_PROCESSOR_FIRST,
    ARM_UC_UPDATE_RESULT_PROCESSOR_USER_DEFINED_ERROR_1        = 401,
    ARM_UC_UPDATE_RESULT_PROCESSOR_USER_DEFINED_ERROR_2        = 402,
    ARM_UC_UPDATE_RESULT_PROCESSOR_USER_DEFINED_ERROR_3        = 403,
    ARM_UC_UPDATE_RESULT_PROCESSOR_USER_DEFINED_ERROR_4        = 404,
    ARM_UC_UPDATE_RESULT_PROCESSOR_USER_DEFINED_ERROR_5        = 405,
    ARM_UC_UPDATE_RESULT_PROCESSOR_PLUGIN_NOT_FOUND            = 406,
    ARM_UC_UPDATE_RESULT_PROCESSOR_INVALID_INPUT_PROCESSOR     = 407,
    ARM_UC_UPDATE_RESULT_PROCESSOR_INVALID_OUTPUT_PROCESSOR    = 408,
    ARM_UC_UPDATE_RESULT_PROCESSOR_INVALID_BUFFER              = 409,
    ARM_UC_UPDATE_RESULT_PROCESSOR_INSUFFICIENT_MEMORY_SPACE   = 410,
    ARM_UC_UPDATE_RESULT_PROCESSOR_BAD_DATA_FORMAT             = 411,
    ARM_UC_UPDATE_RESULT_PROCESSOR_INPUT_PROCESSOR_TIMED_OUT   = 412,
    ARM_UC_UPDATE_RESULT_PROCESSOR_OUTPUT_PROCESSOR_TIMED_OUT  = 413,
    ARM_UC_UPDATE_RESULT_PROCESSOR_LAST                        = ARM_UC_UPDATE_RESULT_PROCESSOR_OUTPUT_PROCESSOR_TIMED_OUT,

    // Writer-specific conditions.
    // ---------------------------
    ARM_UC_UPDATE_RESULT_WRITER_FIRST                          = 500,
    ARM_UC_UPDATE_RESULT_WRITER_NONSPECIFIC_ERROR              = ARM_UC_UPDATE_RESULT_WRITER_FIRST,
    ARM_UC_UPDATE_RESULT_WRITER_INSUFFICIENT_STORAGE_SPACE     = 501,
    ARM_UC_UPDATE_RESULT_WRITER_INSUFFICIENT_MEMORY_SPACE      = 502,
    ARM_UC_UPDATE_RESULT_WRITER_WRITE_FAILURE                  = 503,
    ARM_UC_UPDATE_RESULT_WRITER_HASH_ERROR                     = 504,
    ARM_UC_UPDATE_RESULT_WRITER_ACTIVATION_FAILURE             = 505,
    ARM_UC_UPDATE_RESULT_WRITER_USER_DEFINED_ERROR_1           = 506,
    ARM_UC_UPDATE_RESULT_WRITER_USER_DEFINED_ERROR_2           = 507,
    ARM_UC_UPDATE_RESULT_WRITER_USER_DEFINED_ERROR_3           = 508,
    ARM_UC_UPDATE_RESULT_WRITER_USER_DEFINED_ERROR_4           = 509,
    ARM_UC_UPDATE_RESULT_WRITER_USER_DEFINED_ERROR_5           = 510,
    ARM_UC_UPDATE_RESULT_WRITER_LAST                           = ARM_UC_UPDATE_RESULT_WRITER_USER_DEFINED_ERROR_5,

} arm_uc_update_result_t;

#ifdef __cplusplus
extern "C" {
#endif

extern bool ARM_UC_IsValidState(arm_uc_update_state_t an_update_state);
extern bool ARM_UC_IsValidResult(arm_uc_update_result_t an_update_result);

#ifdef __cplusplus
}
#endif

#endif // ARM_UPDATE_COMMON_PUBLIC_H
