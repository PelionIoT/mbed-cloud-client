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

#endif // ARM_UPDATE_COMMON_PUBLIC_H
