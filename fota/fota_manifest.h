// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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

#ifndef __FOTA_MANIFEST_H_
#define __FOTA_MANIFEST_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_crypto_defs.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef FOTA_MANIFEST_DEBUG
#define FOTA_MANIFEST_TRACE_DEBUG FOTA_TRACE_DEBUG
#else
#define FOTA_MANIFEST_TRACE_DEBUG(fmt, ...)
#endif

// Payload format types
#define FOTA_MANIFEST_PAYLOAD_FORMAT_RAW                 0x0001
#define FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA               0x0005
#define FOTA_MANIFEST_PAYLOAD_FORMAT_COMBINED            0x0006
//  V3 only
#define FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW       0x0101
#define FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_DELTA     0x0105 // not supported yet
#define FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED  0x0106

// Encryption key tags
#define FOTA_MANIFEST_ENCRYPTION_KEY_TAG_AES_128     0x1

/*
 * Update details as extracted from the Pelion FOTA manifest
 */
typedef struct {
    uint64_t       version;                                      /*< FW version (timestamp). */
    uint32_t       priority;                                     /*< Update priority. */
    uint32_t       payload_format;                               /*< Payload format. */
    size_t         payload_size;                                 /*< Payload size to be downloaded. */
    size_t         installed_size;                               /*< Installed FW size. In case payload_format equals FOTA_MANIFEST_PAYLOAD_FORMAT_RAW  the value is equal to payload_size. */
    uint8_t        payload_digest[FOTA_CRYPTO_HASH_SIZE];        /*< Payload SHA226 digest - for verifying downloaded payload integrity. */
    char           uri[FOTA_MANIFEST_URI_SIZE];                  /*< Payload URI for downloading the payload. */
    uint8_t        installed_digest[FOTA_CRYPTO_HASH_SIZE];      /*< Installed FW SHA256 digest. In case payload_format equals FOTA_MANIFEST_PAYLOAD_FORMAT_RAW  the value is equal to payload_digest. */
    uint8_t        precursor_digest[FOTA_CRYPTO_HASH_SIZE];      /*< Currently installed (before update) FW SHA256 digest.*/
    char           component_name[FOTA_COMPONENT_MAX_NAME_SIZE]; /*< Component name */
    uint8_t        vendor_data[FOTA_MANIFEST_VENDOR_DATA_SIZE];  /*< Vendor custom data as received in Pelion FOTA manifest. */
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    uint8_t        installed_signature[FOTA_IMAGE_RAW_SIGNATURE_SIZE]; /** Raw encoded signature over installed image */
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    uint8_t        vendor_id[FOTA_VENDOR_ID_LEN];                /*< Vendor ID of the device. */
    uint8_t        class_id[FOTA_CLASS_ID_LEN];                  /*< Class ID of the device. */
} manifest_firmware_info_t;

/*
 * Parse and validate Pelion FOTA manifest.
 *
 * Parse ASN.1 DER encoded manifest and assert it is suitable for current device.
 *
 * \param[in]  manifest_buf      Pionter to a buffer holding Pelion FOTA manifest to be parsed
 * \param[in]  manifest_size     Input manifest size
 * \param[out] fw_info           Pointer to a struct holding update details
 * \param[in]  current_fw_digest Currently installed FW SHA256 digest - required for asserting precursor digest
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_manifest_parse(
    const uint8_t *manifest_buf,
    size_t manifest_size,
    manifest_firmware_info_t *fw_info);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
/*
 * Parse and copy payload's encryption key from Pelion FOTA manifest.
 *
 * Parse ASN.1 DER encoded EncryptionKeySchema arrived after manifest.
 *
 * \param[in]  input_buf       Pionter to a buffer holding Pelion FOTA manifest and key to be parsed
 * \param[in]  input_size      Input buffer size
 * \param[out] encryption_key  Buffer holding the extracted key
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_encryption_key_parse(
    const uint8_t *input_data,
    size_t         input_size,
    uint8_t        encryption_key[FOTA_ENCRYPT_KEY_SIZE]);

#endif // (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_MANIFEST_H_
