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

#include "arm_uc_mmDerManifestParser.h"

#include <stdio.h>

#define DER_MANDATORY 0
#define DER_OPTIONAL 1

#define ARM_UC_MM_DER_ELEMENT_INIT(ID, TAG, OPT, CHILDREN)\
    {.id = (ID), .subElements = (CHILDREN), .tag = (TAG), .optional = (OPT), .nSubElements = sizeof(CHILDREN)/sizeof(struct arm_uc_mmDerElement)}
#define ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ID, TAG, OPT)\
    {.id = (ID), .subElements = NULL, .tag = (TAG), .optional = (OPT), .nSubElements = 0}


/**
 * @brief Descriptor for the apply period of a manifest.
 *
 * applyPeriod SEQUENCE {
 *     validFrom     INTEGER,
 *     validTo       INTEGER
 * }
 */
static const struct arm_uc_mmDerElement ManifestApplyPeriod[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_VALID_FROM, ARM_UC_MM_ASN1_INTEGER, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_VALID_TO, ARM_UC_MM_ASN1_INTEGER, DER_MANDATORY),
};
/**
 * @brief Descriptor of the encryptionMode
 *
 * encryptionMode  CHOICE {
 *     enum    ENUMERATED {
 *         invalid(0),
 *         aes-128-ctr-ecc-secp256r1-sha256(1),
 *         none-ecc-secp256r1-sha256(2),
 *         none-none-sha256(3)
 *     },
 *     objectId    OBJECT IDENTIFIER
 * }
 */
static const struct arm_uc_mmDerElement encryptionModeChoice[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_ENC_ENUM, ARM_UC_MM_ASN1_ENUMERATED, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_ENC_OID, ARM_UC_MM_ASN1_OID, DER_MANDATORY),
};
/**
 * @brief Descriptor for resource aliases
 *
 * ResourceAlias ::= SEQUENCE {
 *     hash        OCTET STRING,
 *     url         Url
 * }
 */
static const struct arm_uc_mmDerElement manifestResourceAlias[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_RESOURCE_ALIAS_HASH, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_RESOURCE_ALIAS_URL, ARM_UC_MM_ASN1_UTF8_STRING, DER_MANDATORY),
};
/**
 * @brief Descriptor of an Alias container
 *
 */
static const struct arm_uc_mmDerElement manifestResourceAliases[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_RESOURCE_ALIAS, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, manifestResourceAlias)
};

/**
 * @brief Descriptor of the firmware format
 *
 * format      CHOICE {F
 *     enum    ENUMERATED {
 *         undefined(0), raw-binary(1), cbor(2), hex-location-length-data(3), elf(4)
 *     },
 *     objectId    OBJECT IDENTIFIER
 * },
 */
static const struct arm_uc_mmDerElement manifestFwFmtChoice[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_FMT_ENUM, ARM_UC_MM_ASN1_ENUMERATED, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_FMT_OID, ARM_UC_MM_ASN1_OID, DER_MANDATORY),
};

/**
 * @brief Descriptor of the certificate reference used for ECDH
 * @details References an ECC certificate, which is used to perform ECDH with the target device's private key. This will
 * allow derivation of a shared secret, which has been used to encrypt the symmetric encryption key.
 * NOTE: this is the same ASN.1 sequence as arm_uc_mmSignatureCertificateReference, but it is duplicated in the parser to reduce parsing time.
 *
 * CertificateReference ::= SEQUENCE {
 *     fingerprint  Bytes,
 *     url          Url
 * }
 *
 */
static const struct arm_uc_mmDerElement manifestFwCryptIdCertRef[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_FINGERPRINT, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_URL, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
};
/**
 * @brief Descriptor of the Local Info ID choice
 * @details Describes either a locally held pre-shared key or a certificate.
 *
 * id CHOICE {
 *     key OCTET STRING,
 *     certificate CertificateReference
 * },
 */
static const struct arm_uc_mmDerElement manifestFwCryptIdChoice[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_LOCAL, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_REF, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, manifestFwCryptIdCertRef),
};
/**
 * @brief Descriptor of the encryption key options
 * @details Encryption is currently not supported.
 * When supported, the encryption key will be delivered either as an encrypted blob in the manifest, or in a key table,
 * which is referenced in the Resource Reference below.
 *
 * key      CHOICE {
 *   keyTable  Url,
 *   cipherKey OCTET STRING
 * } OPTIONAL
 *
 */
static const struct arm_uc_mmDerElement manifestFwCryptKeyChoice[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_KEYTABLE_REF, ARM_UC_MM_ASN1_UTF8_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CIPHERKEY, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
};
/**
 * @brief Descriptor of cryptographic information block
 * @details Contains the information necessary to manage the encryption of the payload.
 * encryptionInfo SEQUENCE {
 *     initVector OCTET STRING,
 *     id,
 *     key
 * } OPTIONAL,
 */
static const struct arm_uc_mmDerElement manifestFwCryptInfo[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_CRYPT_IV, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CHOICE, ARM_UC_MM_ASN1_CHOICE, DER_MANDATORY, manifestFwCryptIdChoice),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CHOICE, ARM_UC_MM_ASN1_CHOICE, DER_OPTIONAL, manifestFwCryptKeyChoice),
};

/**
 * @brief Descriptor of a firmware resource reference.
 * @details Provides a hash, URL, and size of a payload
 *
 * ResourceReference ::= SEQUENCE {
 *   hash        OCTET STRING,
 *   url     Url OPTIONAL,
 *   size    INTEGER
 * }
 */
static const struct arm_uc_mmDerElement manifestFwRsrcRef[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE, ARM_UC_MM_ASN1_INTEGER, DER_MANDATORY),
};

/**
 * @brief Descriptor of a payload description block
 * @details Describes the payload, including:
 * * The payload format
 * * Any cryptographic information required to decrypt the payload
 * * The storage identifier for payload (where to store it on the target)
 * * The resource reference of the payload (where it is stored, etc)
 * * A free-text version field
 *
 * FirmwareDescription ::= SEQUENCE {
 *    format,
 *    encryptionInfo OPTIONAL,
 *    storageIdentifier UTF8String,
 *    reference    ResourceReference,
 *    version     UTF8String OPTIONAL
 * }
 */
static const struct arm_uc_mmDerElement arm_uc_mmManifestFirmwareDescriptionElements[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FW_FMT_CHOICE, ARM_UC_MM_ASN1_CHOICE, DER_MANDATORY, manifestFwFmtChoice),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FW_CRYPT_INFO, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_OPTIONAL, manifestFwCryptInfo),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_STRG_ID, ARM_UC_MM_ASN1_UTF8_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FW_RSRC_REF, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, manifestFwRsrcRef),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_FW_VER, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
};

const struct arm_uc_mmDerElement arm_uc_mmManifestFirmwareDescription[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FIRMWARE, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_OPTIONAL, arm_uc_mmManifestFirmwareDescriptionElements),
};

/**
 * @brief Descriptor of a manifest dependency reference
 * @details Provides a hash, URL, and size of a manifest dependency
 * ResourceReference ::= SEQUENCE {
 *     hash        OCTET STRING,
 *     url     Url OPTIONAL,
 *     size    INTEGER
 * }
 */
static const struct arm_uc_mmDerElement arm_uc_mmManifestDependency[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_DEP_REF_HASH, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_DEP_REF_URL, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_DEP_REF_SIZE, ARM_UC_MM_ASN1_INTEGER, DER_MANDATORY),
};
/**
 * @brief Descriptor of a manifest dependency container
 * @details Contains manifest dependency references
 */
const struct arm_uc_mmDerElement arm_uc_mmManifestDependencies[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_DEP, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmManifestDependency)
};

/**
 * @brief Descriptor of the manifest sequence
 * @details Contains all the information necessary to describe a manifest.
 *
 * Manifest ::= SEQUENCE {
 *     manifestVersion     ENUMERATED {
 *       v1(1)
 *     },
 *     description UTF8String OPTIONAL,
 *     timestamp   INTEGER,
 *     vendorId    UUID,
 *     classId     UUID,
 *     deviceId    UUID,
 *     nonce       OCTET STRING,
 *     vendorInfo  OCTET STRING,
 *     applyPeriod OPTIONAL,
 *     applyImmediately    BOOLEAN,
 *     encryptionMode  CHOICE {
 *         enum    ENUMERATED {
 *             invalid(0),
 *             aes-128-ctr-ecc-secp256r1-sha256(1),
 *             none-ecc-secp256r1-sha256(2),
 *             none-none-sha256(3)
 *         },
 *         objectId    OBJECT IDENTIFIER
 *     },
 *     aliases         SEQUENCE OF ResourceAlias,
 *     dependencies    SEQUENCE OF ResourceReference,
 *     firmware        FirmwareDescription OPTIONAL
 */
static const struct arm_uc_mmDerElement ManifestElements[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_VERSION, ARM_UC_MM_ASN1_ENUMERATED, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_DESC, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_TIMESTAMP, ARM_UC_MM_ASN1_INTEGER, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_VENDOR_UUID, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_CLASS_UUID, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_DEVICE_UUID, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_NONCE, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_VENDOR_INFO, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_APPLY_PERIOD, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_OPTIONAL, ManifestApplyPeriod),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_MFST_APPLY_IMMEDIATELY, ARM_UC_MM_ASN1_BOOLEAN, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_ENCRYPTION_MODE_CHOICE, ARM_UC_MM_ASN1_CHOICE, DER_OPTIONAL, encryptionModeChoice),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_RESOURCE_ALIASES, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, manifestResourceAliases),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_DEPS, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmManifestDependencies),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST_FIRMWARE, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_OPTIONAL, arm_uc_mmManifestFirmwareDescriptionElements),
};

/**
 * @brief Descriptor of the Resource Choice
 * @details The resource can be one of a limited number of options. Currently, the supported resource types are Manifest
 * and Firmware Image. The firmware image is simply an OCTET STRING, whereas the Manifest is an ASN.1 SEQUENCE (DER
 * encoded)
 *
 * resource CHOICE {
 *     manifest Manifest,
 *     firmware Firmware
 * }
 */
static const struct arm_uc_mmDerElement ResourceChoiceElements[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_MFST, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, ManifestElements),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_FW_IMAGE, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
};

/**
 * @brief Descriptor of a Resource object.
 * @details A resource is composed of an optional reference URL, a resource type identifier, and a resource.
 *
 * Resource ::= SEQUENCE {
 *     url     Url OPTIONAL,
 *     resourceType        ENUMERATED {
 *         manifest(0), firmware(1)
 *     },
 *     resource
 * }
 */
static const struct arm_uc_mmDerElement ResourceElements[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_RESOURCE_URL, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_RESOURCE_TYPE, ARM_UC_MM_ASN1_ENUMERATED, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_RESOURCE_CHOICE, ARM_UC_MM_ASN1_CHOICE, DER_MANDATORY, ResourceChoiceElements),
};
/**
* @brief Descriptor of the certificate reference used for ECDSA signature verification
* @details References an ECC certificate, which is used to perform ECDSA with the target device's public key. The
* certificate used to sign the manifest is used to determine the permissions to be applied to the manifest.
* NOTE: this is the same ASN.1 sequence as manifestFwCryptIdCertRef, but it is duplicated in the parser to reduce parsing time.
*
* CertificateReference ::= SEQUENCE {
*     fingerprint  Bytes,
*     url          Url
* }

 */
static const struct arm_uc_mmDerElement arm_uc_mmSignatureCertificateReference[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_SIG_CERT_FINGERPRINT, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_SIG_CERT_URL, ARM_UC_MM_ASN1_UTF8_STRING, DER_OPTIONAL),
};
/**
 * @brief Certificate Reference container
 */
const struct arm_uc_mmDerElement arm_uc_mmSignatureCertificateReferences[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_SIG_CERT, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmSignatureCertificateReference),
};

const struct arm_uc_mmDerElement arm_uc_mmSignatureBlock[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_SIG_SIGNATURE, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_SIG_CERTS, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmSignatureCertificateReferences),
};
const struct arm_uc_mmDerElement arm_uc_mmSignatures[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_SIG_SIGNATURE_BLOCK, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmSignatureBlock),
};
/**
 * @brief Descriptor of a resource signature
 * @details Contains the signature of the resource object. To facilitate fast integrity checking, a hash is also
 * provided. The certificate references allow the target device to establish a chain of trust.
 *
 * ResourceSignature ::= SEQUENCE {
 *     certificates SEQUENCE OF CertificateReference,
 *     hash        OCTET STRING,
 *     signature   OCTET STRING
 * }
 */
const struct arm_uc_mmDerElement arm_uc_mmResourceSignature[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT_LEAF(ARM_UC_MM_DER_SIG_HASH, ARM_UC_MM_ASN1_OCTET_STRING, DER_MANDATORY),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_SIG_SIGNATURES, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmSignatures),
};
/**
 * @brief Descriptor of a signed resource.
 * @details The signed resource is a container for a resource and a signature.
 * SignedResource ::= SEQUENCE {
 *     resource  Resource,
 *     signature ResourceSignature
 * }
 */
static const struct arm_uc_mmDerElement SignedResourceElements[] =
{
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_RESOURCE, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, ResourceElements),
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_SIG, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, arm_uc_mmResourceSignature),
};
/**
 * @brief Container of a Signed Resource.
 */
static const struct arm_uc_mmDerElement SignedResource =
    ARM_UC_MM_DER_ELEMENT_INIT(ARM_UC_MM_DER_ROOT, ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE, DER_MANDATORY, SignedResourceElements);

#include "update-client-common/arm_uc_trace.h"

enum arm_uc_mmDerParserLogLevels {
    DER_PARSER_LOG_LEVEL_NONE,
    DER_PARSER_LOG_LEVEL_DESCRIPTORS,
    DER_PARSER_LOG_LEVEL_TAGS,
    DER_PARSER_LOG_LEVEL_SIZES,
    DER_PARSER_LOG_LEVEL_VALUES,
    DER_PARSER_LOG_LEVEL_MAX
};
uint32_t arm_uc_mm_derRecurseDepth;

#ifndef ARM_UC_DER_PARSER_TRACE_ENABLE
#define ARM_UC_DER_PARSER_TRACE_ENABLE 0
#endif

#if ARM_UC_DER_PARSER_TRACE_ENABLE
volatile uint32_t arm_uc_mm_der_gDebugLevel = DER_PARSER_LOG_LEVEL_MAX;

#define DER_PARSER_LOG_INDENT(LOG_LEVEL)\
do { \
    if((LOG_LEVEL) <= arm_uc_mm_der_gDebugLevel) \
    { \
        for (uint32_t i = 0; i < arm_uc_mm_derRecurseDepth; i++) \
        { \
            printf("  "); \
        } \
    } \
} while(0)

#define DER_PARSER_LOG(LOG_LEVEL,...)\
    do { \
        if((LOG_LEVEL) <= arm_uc_mm_der_gDebugLevel) \
        { \
            printf(__VA_ARGS__); \
        } \
    } while(0)
#else
#define DER_PARSER_LOG_INDENT(LOG_LEVEL)
#define DER_PARSER_LOG(LOG_LEVEL,...)
#endif

/*
 * ASN.1 DER decoding routines
 */
int ARM_UC_MM_ASN1_get_len( unsigned char **p,
                  const unsigned char *end,
                  size_t *len )
{
    if( ( end - *p ) < 1 )
        return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

    if( ( **p & 0x80 ) == 0 )
        *len = *(*p)++;
    else
    {
        switch( **p & 0x7F )
        {
        case 1:
            if( ( end - *p ) < 2 )
                return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if( ( end - *p ) < 3 )
                return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

            *len = ( (size_t)(*p)[1] << 8 ) | (*p)[2];
            (*p) += 3;
            break;

        case 3:
            if( ( end - *p ) < 4 )
                return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

            *len = ( (size_t)(*p)[1] << 16 ) |
                   ( (size_t)(*p)[2] << 8  ) | (*p)[3];
            (*p) += 4;
            break;

        case 4:
            if( ( end - *p ) < 5 )
                return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

            *len = ( (size_t)(*p)[1] << 24 ) | ( (size_t)(*p)[2] << 16 ) |
                   ( (size_t)(*p)[3] << 8  ) |           (*p)[4];
            (*p) += 5;
            break;

        default:
            return( ARM_UC_DP_ERR_ASN1_INVALID_LENGTH );
        }
    }

    if( *len > (size_t) ( end - *p ) )
        return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

    return( 0 );
}

int ARM_UC_MM_ASN1_get_tag( unsigned char **p,
                  const unsigned char *end,
                  size_t *len, int tag )
{
    if( ( end - *p ) < 1 )
        return( ARM_UC_DP_ERR_ASN1_OUT_OF_DATA );

    if( **p != tag )
        return( ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;

    return( ARM_UC_MM_ASN1_get_len( p, end, len ) );
}


const char* ARM_UC_mmDERDescID2Str(uint32_t id)
{
    switch (id) {
        #define ENUM_AUTO(name) case name: return #name;
        ARM_UC_MM_DER_ID_LIST
        #undef ENUM_AUTO
    default:
        return "Unknown DER ID";
    }
}

/**
 * @brief Internal state of the parser
 */
struct ARM_UC_MM_DERParserState {
    uint32_t nValues;         //!< Number of values remaining to parse
    const uint32_t* valueIDs; //!< Current element of the value identifier array
    arm_uc_buffer_t* buffers; //!< Current buffer of the value output array
};
/**
 * @brief Converts a buffer to an unsigned 32-bit integer
 * @details Assumes that the buffer is an unsigned, big-endian integer and returns it.
 * Limitations:
 * * Expects the buffer to be 4 bytes long or less
 * * Does not trap NULL buffers
 * * Does not trap NULL pointers
 * * Does not permit sign extension of negative values
 * @param[in] buf The buffer to convert to an integer
 * @return The integer value of the buffer
 */
uint32_t ARM_UC_mmDerBuf2Uint(arm_uc_buffer_t* buf)
{
    uint32_t rc = 0;
    unsigned i;
    for (i = 0; i < buf->size && i < sizeof(uint32_t); i++)
    {
        rc = (rc << 8) | buf->ptr[i];
    }
    return rc;
}
/**
 * @brief Converts a buffer to an unsigned 64-bit integer
 * @details Assumes that the buffer is an unsigned, big-endian integer and returns it.
 * Limitations:
 * * Expects the buffer to be 8 bytes long or less
 * * Does not trap NULL buffers
 * * Does not trap NULL pointers
 * * Does not permit sign extension of negative values
 * @param[in] buf The buffer to convert to an integer
 * @return The integer value of the buffer
 */
uint64_t ARM_UC_mmDerBuf2Uint64(arm_uc_buffer_t* buf)
{
    uint64_t rc = 0;
    unsigned i;
    for (i = 0; i < buf->size && i < sizeof(uint64_t); i++)
    {
        rc = (rc << 8) | buf->ptr[i];
    }
    return rc;
}

/**
 * @brief Extracts the next tag in the DER string
 * @details Validates the length of the string, then extracts the next value, interpreting it as a tag.
 * Limitations:
 * * Does not verify that any of the pointers are non-NULL
 * * Does not validate tag values
 * @param[in] p The current position in DER string
 * @param[in] end The last position in the DER string
 * @param[out] tag The extracted DER tag
 * @retval 1 if the end has been encountered
 * @retval 0 if the tag was successfully retrieved
 */
int ARM_UC_mmDERPeekTag(uint8_t* p, uint8_t* end, int* tag)
{
    if( ( end - p ) < 1 )
    {
        return( 1 );
    }
    *tag = *p;
    return 0;
}

/**
 * @brief Extracts one or more tagged values from DER encoded data
 * @details Recursively traverses the DER tree, searching for the identified values.
 * The parser parses the input data, identified by `*pos` according to the following rules:
 *
 * * If the current descriptor is a choice, `ARM_UC_mmDERGetValues` attempts to resolve the choice.
 *     * Obtain the actual tag
 *     * Loop through each child of the choice element and compare it to the tag
 *     * If no tag mathces, return `ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG`
 *     * Otherwise replace `desc` with the descriptor of the matching tag
 * * Get the tag for the current descriptor
 * * If the tag is not found
 *     * If it was optional, exit with success
 *     * Otherwise, exit with ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG
 * * If the descriptor ID matches the current extraction ID
 *     * Extract the value into the current buffer.
 *     * Advance the ID pointer, the buffer pointer, and decrement the value pointer.
 * * If the descriptor is a sequence with more than one child, recurse into it (single-child sequences are SEQUENCE OF)
 *     * For each child element,
 *         * If the end has been not reached or the child descriptor is mandatory
 *             * call `ARM_UC_mmDERGetValues` with the child descriptor.
 * * If the end does not match pos
 *     * fail with `ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH`
 * * Otherwise
 *     * Update the current position
 * * return success
 *
 * WARNING: ARM_UC_mmDERGetValues cannot resolve choices between two different sequences.
 *
 * NOTE: Choices are not currently returnable
 * NOTE: An optimization should be possible to reduce the parsing time by skipping elements whose descriptors do not
 *       contain the next requested element ID
 * NOTE: Length mismatch checking is not currently supported.
 *
 * To parse a SEQUENCE OF element, search for the SEQUENCE OF. Then, iterate through its elements with
 * `ARM_UC_mmDERGetSequenceElement`. With each element, call `ARM_UC_mmDERParseTree` with the descriptor for the
 * contents of the SEQUENCE OF.
 *
 * @param[in] desc Contains the current parsing descriptor
 * @param[in] pos Pointer to pointer that holds the current parsing location
 * @param[in] end Pointer to the end of the current element's container
 * @param[in,out] state Parser state. Contains the parser's
 * @retval ARM_UC_DP_ERR_ASN1_OUT_OF_DATA     The parser has run out of data before running out of descriptors
 * @retval ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG  The parser has encountered an encoding error, or unsupported DER document
 * @retval ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH The elements of the DER tree do not have consistent lengths.
 * @retval 0                                Success!
 */
int32_t ARM_UC_mmDERGetValues(const struct arm_uc_mmDerElement* desc, uint8_t** pos, uint8_t* end, struct ARM_UC_MM_DERParserState* state)
{
    size_t len;
    int rc;
    uint8_t* ElementEnd;
    DER_PARSER_LOG_INDENT(DER_PARSER_LOG_LEVEL_DESCRIPTORS);
    DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, "%s", ARM_UC_mmDERDescID2Str(desc->id));

    // TODO: return a choice result when a choice ID is in the list.
    // Resolve the a choice. Cannot distinguish choices between two sequences.
    if (desc->tag == ARM_UC_MM_ASN1_CHOICE)
    {
        int tag;
        unsigned i;
        DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, "\n");
        // Get the tag of the next element and identify the descriptor that matches that tag.
        rc = ARM_UC_mmDERPeekTag(*pos, end, &tag);
        if (rc)
            return rc;
        rc = ( ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG );
        arm_uc_mm_derRecurseDepth++;
        for (i = 0; i < desc->nSubElements; i++)
        {
            if (tag == desc->subElements[i].tag)
            {
                // desc = &desc->subElements[i];
                // rc = 0;
                rc = ARM_UC_mmDERGetValues(&desc->subElements[i], pos, end, state);
                break;
            }
            else
            {
                DER_PARSER_LOG_INDENT(DER_PARSER_LOG_LEVEL_DESCRIPTORS);
                DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, "%s (skipped)\n", ARM_UC_mmDERDescID2Str(desc->subElements[i].id));
            }
        }
        arm_uc_mm_derRecurseDepth--;
        // If the matching tag is not in one of the desctiptors, then a parse error has been encountered.
        // if (rc)
        return rc;
    }
    // Store the entry position for saving sequences
    uint8_t* seqpos = *pos;
    // Get the next tag & length, advancing the parse position to just after the tag/length pair.
    rc = ARM_UC_MM_ASN1_get_tag(pos, end, &len, desc->tag);
    // If an optional tag was expected, but not encountered, it is not an error unless it was requested by the user.
    if (rc == ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG && desc->optional && desc->id != state->valueIDs[0])
    {
        DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, " (skipped)\n");
        return 0;
    } // TODO evaluate length handling in ARM_UC_MM_ASN1_get_tag
    // If an error was encountered, abort.
    if (rc)
    {
        DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, " (error %d)\n", rc);
        return rc;
    }
    // If the encountered tag is one of the requested IDs, record its location and size, then move on to the next value
    if (desc->id == state->valueIDs[0])
    {
        // If the element is a sequence, store the whole element, not just the content.
        if (desc->tag == (ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE) && desc->nSubElements != 1)
        {
            state->buffers[0].ptr = seqpos;
            state->buffers[0].size = len + (*pos - seqpos);
            state->buffers[0].size_max = len + (*pos - seqpos);
        }
        else
        {
            state->buffers[0].ptr = *pos;
            state->buffers[0].size = len;
            state->buffers[0].size_max = len;
        }
        state->nValues--;
        state->valueIDs++;
        state->buffers++;
        DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, " (stored)\n");
    }
    else
    {
        DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_DESCRIPTORS, "\n");
    }
    DER_PARSER_LOG_INDENT(DER_PARSER_LOG_LEVEL_TAGS);
    DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_TAGS, "%02X", desc->tag);
    DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_SIZES, " %X", len);
    if (desc->tag != (ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE))
    {
        DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_VALUES, " ");
        for (uint32_t i = 0; i < len; i++)
        {
            if (desc->tag == ARM_UC_MM_ASN1_UTF8_STRING)
            {
                DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_VALUES, "%c", (char)(*pos)[i]);
            }
            else
            {
                DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_VALUES, "%X", (*pos)[i]);
            }
        }
    }
    DER_PARSER_LOG(DER_PARSER_LOG_LEVEL_TAGS, "\n");

    // TODO: At this point, it should be possible to exit parsing of this element early if no requested ID is owned by
    // this element or one of its children.

    // Update the end of the current element to pos+len
    ElementEnd = *pos + len;
    // If the element is a sequence, parse the sequence.
    if (desc->tag == (ARM_UC_MM_ASN1_CONSTRUCTED | ARM_UC_MM_ASN1_SEQUENCE))
    {
        /* Sequences with only a single element are treated as a SEQUENCE OF, which has special semantics. In order to
         * extract the contents of a SEQUENCE OF, the caller must request the SEQUENCE OF element ID, then use
         * ARM_UC_mmDERGetSequenceElement to extract the contents of the sequence, passing each one to
         * ARM_UC_mmDERParseTree in order to extract any */
        if (desc->nSubElements != 1) // SEQUENCE
        {
            int i;
            end = *pos + len;
            arm_uc_mm_derRecurseDepth++;
            for ( i = 0; rc == 0 && state->nValues != 0 && i < desc->nSubElements; i++ )
            {
                // Escape if the end has been reached and the parsing elements are optional
                if (!(*pos >= end && desc->subElements[i].optional)) {
                    // Parse a sub-tree
                    rc = ARM_UC_mmDERGetValues(&desc->subElements[i], pos, end, state);
                }
            }
            arm_uc_mm_derRecurseDepth--;
        }
    }

    if (*pos > ElementEnd) // TODO: Add length mismatch check
    {
        // Fail if there is a length mismatch
        return ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH;
    }
    else
    {
        // Update the current parsing position
        *pos = ElementEnd;
    }
    return rc;
}

/**
 * @brief Extracts elements from an ASN.1 SEQUENCE OF by index
 * @details Parses a SEQUENCE OF element, skipping elements until it finds the requested element.
 * When the last element has been parsed, a further call to `ARM_UC_mmDERGetSequenceElement` will cause element to be
 * populated with a NULL buffer pointer and 0 length, but `ARM_UC_mmDERGetSequenceElement` will still return success.
 *
 * @param[in]  buffer  The data to parse
 * @param[in]  index   The element index to extract
 * @param[out] element The buffer to populate with the extracted element
 *
 * @retval ARM_UC_DP_ERR_ASN1_OUT_OF_DATA     The parser has run out of data before running out of descriptors
 * @retval ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG  The parser has encountered an encoding error, or unsupported DER document
 * @retval ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH The elements of the DER tree do not have consistent lengths.
 * @retval 0                                Success!
 */
int32_t ARM_UC_mmDERGetSequenceElement(arm_uc_buffer_t* buffer, uint32_t index, arm_uc_buffer_t* element)
{
    uint8_t* pos      = buffer->ptr;
    uint8_t* end      = pos + buffer->size;
    int rc            = 0;
    size_t len        = 0;
    element->ptr      = NULL;
    element->size     = 0;
    element->size_max = 0;
    for(; !rc; index--)
    {
        int tag;
        rc = ARM_UC_mmDERPeekTag(pos, end, &tag);
        if (rc)
        {
            // Peek-tag can only fail if pos >= end, so there was no element
            // This is not an error, since the parser may not know how many elements are in the sequence.
            return 0;
        }
        if (!index)
        {
            element->ptr = pos;
        }
        rc = ARM_UC_MM_ASN1_get_tag(&pos, end, &len, tag);
        if (!index && !rc)
        {
            element->size     = len + pos - element->ptr;
            element->size_max = element->size;
            break;
        }
        if (rc)
        {
            element->ptr = NULL;
            break;
        }
        pos += len;
    }
    return rc;
}

/**
 * @brief Parses a tree of DER data by calling `ARM_UC_mmDERGetValues`
 * @details Populates a parser state with the IDs to be extracted, the number of values and the buffers to extract into
 * @param[in]  desc     Contains the current parsing descriptor
 * @param[in]  buffer   The data to parse
 * @param[in]  nValues  The number of values to search for
 * @param[in]  valueIDs Array of value identifiers
 * @param[out] buffers  Array of buffers to populate with the elements matching valueIDs
 * @retval ARM_UC_DP_ERR_ASN1_OUT_OF_DATA     The parser has run out of data before running out of descriptors
 * @retval ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG  The parser has encountered an encoding error, or unsupported DER document
 * @retval ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH The elements of the DER tree do not have consistent lengths.
 * @retval 0                                Success!
 * @retval >0                               Number of remaining elements
 */
int32_t ARM_UC_mmDERParseTree(const struct arm_uc_mmDerElement* desc, arm_uc_buffer_t* buffer, uint32_t nValues, const int32_t* valueIDs, arm_uc_buffer_t* buffers)
{
    uint8_t *pos = buffer->ptr;
    uint8_t *end = pos + buffer->size;
    struct ARM_UC_MM_DERParserState state = {
        nValues, valueIDs, buffers
    };
    arm_uc_mm_derRecurseDepth = 0;
    int32_t rc = ARM_UC_mmDERGetValues(desc, &pos, end, &state);
    // printf("Failed at: index %lu: %lu with return code: %ld\n", nValues-state.nValues, *state.valueIDs, rc);
    if (rc == 0 && state.nValues != 0)
    {
        return state.nValues;
    }
    return rc;
}
/**
 * @brief Parses a tree of DER data by calling `ARM_UC_mmDERGetValues`
 * @details Populates a parser state with the IDs to be extracted, the number of values and the buffers to extract into
 * Calls `ARM_UC_mmDERParseTree` with `SignedResource`
 * @param[in]  buffer   The data to parse
 * @param[in]  nValues  The number of values to search for
 * @param[in]  valueIDs Array of value identifiers
 * @param[out] buffers  Array of buffers to populate with the elements matching valueIDs
 * @retval ARM_UC_DP_ERR_ASN1_OUT_OF_DATA     The parser has run out of data before running out of descriptors
 * @retval ARM_UC_DP_ERR_ASN1_UNEXPECTED_TAG  The parser has encountered an encoding error, or unsupported DER document
 * @retval ARM_UC_DP_ERR_ASN1_LENGTH_MISMATCH The elements of the DER tree do not have consistent lengths.
 * @retval 0                                Success!
 * @retval >0                               Number of remaining elements
 */
int32_t ARM_UC_mmDERGetSignedResourceValues(arm_uc_buffer_t* buffer, uint32_t nValues, const int32_t* valueIDs, arm_uc_buffer_t* buffers)
{
    return ARM_UC_mmDERParseTree(&SignedResource, buffer, nValues, valueIDs, buffers);
}
