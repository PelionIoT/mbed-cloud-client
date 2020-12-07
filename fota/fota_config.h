// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef __FOTA_CONFIG_H_
#define __FOTA_CONFIG_H_

#if !defined(FOTA_UNIT_TEST)
#include "MbedCloudClientConfig.h"
#else
#include "fota_unittest_config.h"
#endif

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#if defined (__ICCARM__)
#define fota_deprecated
#else
#define fota_deprecated __attribute__ ((deprecated))
#endif

#define FOTA_RESUME_UNSUPPORTED     0
#define FOTA_RESUME_SUPPORT_RESTART 1
#define FOTA_RESUME_SUPPORT_RESUME  2

#define FOTA_INTERNAL_FLASH_BD      1
#define FOTA_CUSTOM_BD              2
#define FOTA_EXTERNAL_BD            3

#if defined(TARGET_LIKE_LINUX)
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR 0

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE 0x100000000
#endif

#define MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE FOTA_EXTERNAL_BD

#if !defined(FOTA_UNIT_TEST)
#define FOTA_CUSTOM_CURR_FW_STRUCTURE 1
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME)
#define MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME "fota_fw_metadata"
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME)
#define MBED_CLOUD_CLIENT_FOTA_LINUX_UPDATE_STORAGE_FILENAME "fota_candidate"
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME)
#define MBED_CLOUD_CLIENT_FOTA_LINUX_CANDIDATE_FILENAME "fota_raw_candidate"
#endif

#endif // defined(TARGET_LIKE_LINUX)

#ifndef MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE
#error Block device type must be defined
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE) || (MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE == 0)
#error Storage size should be defined and have a nonzero value
#endif

#if !defined(FOTA_MANIFEST_SCHEMA_VERSION)
#define FOTA_MANIFEST_SCHEMA_VERSION        3
#endif

#if !defined(FOTA_MANIFEST_URI_SIZE)
#define FOTA_MANIFEST_URI_SIZE            256
#endif

#if !defined(FOTA_MANIFEST_VENDOR_DATA_SIZE)
#define FOTA_MANIFEST_VENDOR_DATA_SIZE    0
#endif

#if (FOTA_MANIFEST_VENDOR_DATA_SIZE > 0)  // asn.1 (TLV) overhead 
#define __FOTA_VENDOR_DATA_OVERHEAD 4
#else
#define __FOTA_VENDOR_DATA_OVERHEAD 0
#endif

#if !defined(FOTA_CERT_MAX_SIZE)
#define FOTA_CERT_MAX_SIZE 600
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE 1024
#endif

#if defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY) && !defined(FOTA_USE_UPDATE_RAW_PUBLIC_KEY)
#define FOTA_USE_UPDATE_RAW_PUBLIC_KEY
#endif

#if !(FOTA_MANIFEST_SCHEMA_VERSION == 1)
// manifest schema V3 (and newer) support public key in both
// uncompressed elliptic curve point format (X9.62) and x509
// x509 is used by default. x9.62 is used for optimizations
// but requires integration with FCU tool and crypto backend.
#if !defined(FOTA_USE_UPDATE_RAW_PUBLIC_KEY)
#define FOTA_USE_UPDATE_X509
#endif
#else  // (FOTA_MANIFEST_SCHEMA_VERSION == 1)
// manifest schema V1 only supports public key in x.509 format
#define FOTA_USE_UPDATE_X509
#endif  //!(FOTA_MANIFEST_SCHEMA_VERSION == 1)

#if (FOTA_MANIFEST_SCHEMA_VERSION < 3)

#define FOTA_SOURCE_LEGACY_OBJECTS_REPORT 1

#if defined(FOTA_DISABLE_DELTA)
#define __FOTA_MANIFEST_BASE_SIZE 286
#else
#define __FOTA_MANIFEST_BASE_SIZE 361
#endif

#else  // (FOTA_MANIFEST_SCHEMA_VERSION < 3)
#define FOTA_SOURCE_LEGACY_OBJECTS_REPORT 0

#if defined(FOTA_DISABLE_DELTA)
#define __FOTA_MANIFEST_BASE_SIZE 172
#else
#define __FOTA_MANIFEST_BASE_SIZE 247
#endif

#endif  // (FOTA_MANIFEST_SCHEMA_VERSION < 3)

#if !defined(FOTA_MANIFEST_MAX_SIZE)
#define FOTA_MANIFEST_MAX_SIZE (__FOTA_MANIFEST_BASE_SIZE + FOTA_MANIFEST_URI_SIZE + __FOTA_VENDOR_DATA_OVERHEAD + FOTA_MANIFEST_VENDOR_DATA_SIZE)
#endif

#ifndef MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT
#define MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT FOTA_RESUME_SUPPORT_RESUME
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION)
#define MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION 3
#endif

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)

#define FOTA_HEADER_HAS_CANDIDATE_READY 1

#if !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)
// set candidate encryption flag to false by default for internal flash
#if (MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_INTERNAL_FLASH_BD)
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 0
#else
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 1
#endif

#endif  // !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)

#else  // LEGACY profile (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2)

#define FOTA_HEADER_HAS_CANDIDATE_READY 0

#if !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)
#define MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT 0
#elif (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
#error MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT enabled only for header version >= 3
#endif // !defined(MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT)

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
// force resume restart for legacy profile
#undef MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT
#define MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT FOTA_RESUME_SUPPORT_RESTART
#endif

#endif // (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)

#define MBED_CLOUD_CLIENT_FOTA_COAP_DOWNLOAD 1
#define MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD 2

#if !defined(MBED_CLOUD_CLIENT_FOTA_DOWNLOAD)
#if defined(TARGET_LIKE_LINUX)
#define MBED_CLOUD_CLIENT_FOTA_DOWNLOAD MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD
#else
#define MBED_CLOUD_CLIENT_FOTA_DOWNLOAD MBED_CLOUD_CLIENT_FOTA_COAP_DOWNLOAD
#endif // defined(TARGET_LIKE_LINUX)
#endif // !defined(MBED_CLOUD_CLIENT_FOTA_DOWNLOAD)

#if (MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD)
#if !defined(TARGET_LIKE_LINUX)
#error curl http download available only for linux
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_CURL_PAYLOAD_SIZE)
#define MBED_CLOUD_CLIENT_FOTA_CURL_PAYLOAD_SIZE 0x4000L
#endif

#endif  // (MBED_CLOUD_CLIENT_FOTA_DOWNLOAD == MBED_CLOUD_CLIENT_FOTA_CURL_HTTP_DOWNLOAD)

#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 1)
#define FOTA_MCCP_PROTOCOL_VERSION 3
#else
#define FOTA_MCCP_PROTOCOL_VERSION 4
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR)
#error "MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR must be set"
#endif

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE

#endif  // __FOTA_CONFIG_H_
