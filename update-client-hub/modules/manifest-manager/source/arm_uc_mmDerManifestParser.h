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

#ifndef ARM_UC_MM_DERPARSE_H
#define ARM_UC_MM_DERPARSE_H

#include "update-client-common/arm_uc_types.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name DER constants
 * These constants comply with DER encoded the ANS1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::mbedtls_x509_buf.
 * \{
 */
#define ARM_UC_MM_ASN1_BOOLEAN                 0x01
#define ARM_UC_MM_ASN1_INTEGER                 0x02
#define ARM_UC_MM_ASN1_BIT_STRING              0x03
#define ARM_UC_MM_ASN1_OCTET_STRING            0x04
#define ARM_UC_MM_ASN1_NULL                    0x05
#define ARM_UC_MM_ASN1_OID                     0x06
#define ARM_UC_MM_ASN1_ENUMERATED              0x0A
#define ARM_UC_MM_ASN1_UTF8_STRING             0x0C
#define ARM_UC_MM_ASN1_SEQUENCE                0x10
#define ARM_UC_MM_ASN1_SET                     0x11
#define ARM_UC_MM_ASN1_PRINTABLE_STRING        0x13
#define ARM_UC_MM_ASN1_T61_STRING              0x14
#define ARM_UC_MM_ASN1_IA5_STRING              0x16
#define ARM_UC_MM_ASN1_UTC_TIME                0x17
#define ARM_UC_MM_ASN1_GENERALIZED_TIME        0x18
#define ARM_UC_MM_ASN1_UNIVERSAL_STRING        0x1C
#define ARM_UC_MM_ASN1_BMP_STRING              0x1E
#define ARM_UC_MM_ASN1_PRIMITIVE               0x00
#define ARM_UC_MM_ASN1_CONSTRUCTED             0x20
#define ARM_UC_MM_ASN1_CONTEXT_SPECIFIC        0x80
#define ARM_UC_MM_ASN1_CHOICE                  0xFF // NOTE: This is not a real ASN1 number; it is a marker for choices

/* \} name */

/**
 * \name ASN1 Error codes
 * These error codes are OR'ed to X509 error codes for
 * higher error granularity.
 * ASN1 is a standard to specify data structures.
 * \{
 */
#define ARM_UC_DP_ERR_ASN1_OUT_OF_DATA                      -0x0060  /**< Out of data when parsing an ASN1 data structure. */
#define ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG                   -0x0062  /**< ASN1 tag was of an unexpected value. */
#define ARM_UC_DP_ERR_ASN1_INVALID_LENGTH                   -0x0064  /**< Error when trying to determine the length or invalid length. */
#define ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH                  -0x0066  /**< Actual length differs from expected length. */
#define ARM_UC_DP_ERR_ASN1_INVALID_DATA                     -0x0068  /**< Data is invalid. (not used) */
#define ARM_UC_DP_ERR_ASN1_ALLOC_FAILED                     -0x006A  /**< Memory allocation failed */
#define ARM_UC_DP_ERR_ASN1_BUF_TOO_SMALL                    -0x006C  /**< Buffer too small when writing ASN.1 data structure. */

/* \} name */


#define ARM_UC_MM_DER_ID_LIST \
    ENUM_AUTO(ARM_UC_MM_DER_UNINIT)\
    ENUM_AUTO(ARM_UC_MM_DER_ROOT)\
    ENUM_AUTO(ARM_UC_MM_DER_RESOURCE)\
    ENUM_AUTO(ARM_UC_MM_DER_RESOURCE_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_RESOURCE_TYPE)\
    ENUM_AUTO(ARM_UC_MM_DER_RESOURCE_CHOICE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_VERSION)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DESC)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_TIMESTAMP)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_UUIDS)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_VENDOR_UUID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_CLASS_UUID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DEVICE_UUID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_NONCE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_VENDOR_INFO)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_APPLY_PERIOD)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_VALID_FROM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_VALID_TO)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_APPLY_IMMEDIATELY)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_ENCRYPTION_MODE_CHOICE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_ENC_ENUM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_ENC_OID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_RESOURCE_ALIASES)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_RESOURCE_ALIAS)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_RESOURCE_ALIAS_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_RESOURCE_ALIAS_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FIRMWARE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_CHOICE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_ENUM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_OID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_INFO)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_IV)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CHOICE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_LOCAL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_REF)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_FINGERPRINT)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CHOICE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CIPHERKEY)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_KEYTABLE_REF)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_STRG_ID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_VER)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DEPS)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DEP)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DEP_REF_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DEP_REF_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_DEP_REF_SIZE)\
    ENUM_AUTO(ARM_UC_MM_DER_FW_IMAGE)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_SIGNATURES)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_SIGNATURE_BLOCK)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_SIGNATURE)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_CERTS)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_CERT)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_CERT_FINGERPRINT)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_CERT_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MACS)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_BLOCK)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_PSKID)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_KEYTABLE_IV)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_KEYTABLE_REF)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_KEYTABLE_VERSION)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_KEYTABLE_INDEX_SIZE)\
    ENUM_AUTO(ARM_UC_MM_DER_SIG_MAC_KEYTABLE_RECORD_SIZE)\
    ENUM_AUTO(ARM_UC_MM_KT_ROOT)\
    ENUM_AUTO(ARM_UC_MM_KT_HASH)\
    ENUM_AUTO(ARM_UC_MM_KT_PAYLOAD_KEY)\


enum derIDs {
#define ENUM_AUTO(X) X,
    ARM_UC_MM_DER_ID_LIST
#undef ENUM_AUTO
};

#define ARM_UC_DER_PARSER_ERROR_PREFIX TWO_CC('D', 'P')

struct arm_uc_mmDerElement {
    uint32_t id;
    const struct arm_uc_mmDerElement *subElements;
    uint8_t tag;
    uint8_t optional;
    uint8_t nSubElements;
};

extern const struct arm_uc_mmDerElement arm_uc_mmManifestUUID[];
extern const struct arm_uc_mmDerElement arm_uc_mmManifestDependencies[];
extern const struct arm_uc_mmDerElement arm_uc_mmManifestFirmwareDescription[];
extern const struct arm_uc_mmDerElement arm_uc_mmResourceSignature[];
extern const struct arm_uc_mmDerElement arm_uc_mmSignatures[];
extern const struct arm_uc_mmDerElement arm_uc_mmSignatureCertificateReferences[];
extern const struct arm_uc_mmDerElement arm_uc_mmMacs[];
extern const struct arm_uc_mmDerElement arm_uc_mmKeyTableEntry[];
extern const struct arm_uc_mmDerElement arm_uc_mmMacs[];

int32_t ARM_UC_mmDERGetSignedResourceValues(arm_uc_buffer_t *buffer, uint32_t nValues, const int32_t *valueIDs,
                                            arm_uc_buffer_t *buffers);
uint32_t ARM_UC_mmDerBuf2Uint(arm_uc_buffer_t *buf);
uint64_t ARM_UC_mmDerBuf2Uint64(arm_uc_buffer_t *buf);
int32_t ARM_UC_mmDERGetSequenceElement(arm_uc_buffer_t *buffer, uint32_t index, arm_uc_buffer_t *element);
int32_t ARM_UC_mmDERParseTree(const struct arm_uc_mmDerElement *desc, arm_uc_buffer_t *buffer, uint32_t nValues,
                              const int32_t *valueIDs, arm_uc_buffer_t *buffers);


#ifdef __cplusplus
}
#endif


#endif // ARM_UC_MM_DERPARSE_H
