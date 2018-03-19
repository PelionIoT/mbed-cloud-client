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

#ifndef UPDATE_CLIENT_MANIFEST_MANAGER_TYPES_H
#define UPDATE_CLIENT_MANIFEST_MANAGER_TYPES_H

#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_common.h"

#include <limits.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


#define RFC_4122_BYTES (128/CHAR_BIT)
#define RFC_4122_WORDS (RFC_4122_BYTES/sizeof(uint32_t))
#define ARM_UC_MANIFEST_HANDLE_BUFFER_BYTES (256/CHAR_BIT)

// NOTE: Manifest Handles are not used yet
typedef uint8_t arm_uc_manifest_handle_t[ARM_UC_MANIFEST_HANDLE_BUFFER_BYTES];


/**
 * @brief RFC 4122 GUID container
 * GUIDs are a fixed size, so this container provides a consistent storage for them. Accessors are provided for both
 * byte-wise and word-wise access.
 */
typedef struct manifest_guid_t {
    union {
        uint8_t  bytes[RFC_4122_BYTES];
        uint32_t words[RFC_4122_WORDS];
    };
} manifest_guid_t;

/**
 * @brief Allowed cryptographic modes
 * This list must be kept in sync with the manifest generator.
 * Only a minimum set of cryptographic modes should be permitted
 */
enum manifest_crypto_mode {
    MFST_CRYPT_UNINIT = 0,             //!< Uninitialized mode. This mode will always fail
    MFST_CRYPT_SHA256_ECC_AES128_PSK,  /*!< Manifest is signed with ECDSA. Firmware is encrypted with AES128-CTR, using a
                                        *   pre-shared key. Firmware plaintext is hashed with SHA256. */
    MFST_CRYPT_SHA256_ECC,             //!< Manifest is signed with ECDSA. Firmware is hashed with SHA256
    MFST_CRYPT_SHA256,                 //!< Manifest and firmware are hashed with SHA256. Not recommended for production
    // MFST_CRYPT_SHA256_HMAC,            //!< Manifest is signed with HMAC. Firmware is hashed with SHA256
    // MFST_CRYPT_SHA256_HMAC_AES128_PSK, /*!< Manifest is signed with HMAC. Firmware is encrypted with AES128-CTR, using a
    //                                     *   pre-shared key. Firmware plaintext is hashed with SHA256. */
    MFST_CRYPT_MAX,
};

/**
 * @brief Helper structure
 * This structure converts the cryptomode to testable flags
 */
typedef struct arm_uc_mm_crypto_flags_t {
    unsigned hash:2;
    unsigned hmac:1;
    unsigned rsa:2;
    unsigned ecc:2;
    unsigned aes:2;
    unsigned psk:1;
} arm_uc_mm_crypto_flags_t;

enum arm_uc_mmCipherMode_t {
    ARM_UC_MM_CIPHERMODE_NONE,
    ARM_UC_MM_CIPHERMODE_PSK,
    ARM_UC_MM_CIPHERMODE_CERT_CIPHERKEY,
    ARM_UC_MM_CIPHERMODE_CERT_KEYTABLE,
};

/**
 * @brief   Firmware Information
 * @details Contains the details about the firmware image referenced by the manifest
 */
struct manifest_firmware_info_t {
    uint64_t        timestamp;  ///< Root Manifest timestamp.
    manifest_guid_t format;     /**< The format used for the firmware. This is either an enum when the first 96 bits
                                 *   are 0. Otherwise, this is a RFC4122 GUID. */

    uint32_t            cryptoMode;
    uint32_t            size;       ///< The size of the firmware in bytes
    arm_uc_buffer_t     hash;       ///< The hash of the firmware image
    arm_uc_buffer_t     uri;        ///< The location of the firmware
    arm_uc_buffer_t     strgId;     ///< The location of the firmware

    uint32_t            cipherMode;
    arm_uc_buffer_t     initVector; ///< AES initialization vector. 0 is not permitted.
    union {
        struct {
            arm_uc_buffer_t keyID;      ///< Identifier for a locally stored AES key
            arm_uc_buffer_t cipherKey;        ///< An encrypted AES key
        } psk;
        struct {
            arm_uc_buffer_t certFingerPrint;
            arm_uc_buffer_t certURL;
            arm_uc_buffer_t cipherKey;
        } certCK;
        struct {
            arm_uc_buffer_t certFingerPrint;
            arm_uc_buffer_t certURL;
            arm_uc_buffer_t keyTableURL;
        } certKT;
    };
    uint32_t manifestSize;
    uint8_t  manifestBuffer[640];
};
typedef struct manifest_firmware_info_t manifest_firmware_info_t;


#ifdef __cplusplus
}
#endif
#endif // UPDATE_CLIENT_MANIFEST_MANAGER_TYPES_H
