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
#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#if (FOTA_MANIFEST_SCHEMA_VERSION == 3)

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#include "fota/fota_manifest.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"
#include "fota/fota_crypto.h"
#include "fota/fota_crypto_asn_extra.h"
#include "fota/fota_base.h"
#include "fota/fota_nvm.h"
#include "fota/fota_crypto.h"
#include "fota/fota_internal.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/x509_crt.h"

#define FOTA_IMAGE_DER_SIGNATURE_SIZE 72  // DER encoded signature max size

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_X509_PUBLIC_KEY_FORMAT)
static inline int der_encode_signature_helper(
    const mbedtls_mpi *r, const mbedtls_mpi *s,
    uint8_t *buffer, size_t buffer_size, size_t *bytes_written)
{
    FOTA_DBG_ASSERT(buffer_size == FOTA_IMAGE_DER_SIGNATURE_SIZE);
    int ret;
    unsigned char *p = buffer + buffer_size;  // pointer to the end of buffer
    int len = 0;
    // tags are written in the reverse order

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buffer, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buffer, r));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buffer, (size_t)len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    memmove(buffer, p, len);
    *bytes_written = (size_t)len;

    return FOTA_STATUS_SUCCESS;
}

static inline int fota_der_encode_signature(
    const uint8_t *raw_signature, size_t  raw_signature_size,
    uint8_t *buffer, size_t buffer_size, size_t *bytes_written)
{
    int ret;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    FOTA_DBG_ASSERT(raw_signature_size == FOTA_IMAGE_RAW_SIGNATURE_SIZE);

    const size_t curve_bytes = FOTA_IMAGE_RAW_SIGNATURE_SIZE / 2;

    // Read r component
    ret = mbedtls_mpi_read_binary(&r, raw_signature, curve_bytes);
    if (ret) {
        ret = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto cleanup;
    }
    // Read s component
    ret = mbedtls_mpi_read_binary(&s, raw_signature + curve_bytes, curve_bytes);
    if (ret) {
        ret = FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = der_encode_signature_helper(&r, &s, buffer, buffer_size, bytes_written);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}
#endif // #if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT==FOTA_X509_PUBLIC_KEY_FORMAT)

/*
 *  -- Metadata for payload reconstruction
 *  PayloadMetadata ::= SEQUENCE {
 *    -- represents reconstructed payload size
 *    installed-size INTEGER,
 *    -- represents reconstructed payload digest
 *    installed-digest OCTET STRING,
 *
 *    -- Used with 'arm-patch-stream' and 'encrypted-patch',
 *    -- never for other payload formats
 *    precursor-digest OCTET STRING OPTIONAL
 *  }
 */
#if !defined(FOTA_DISABLE_DELTA) || (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
static int parse_payload_metadata(
    const uint8_t *metadata, size_t metadata_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data
)
{
    unsigned char *p = (unsigned char *) metadata;
    const unsigned char *metadata_end = metadata + metadata_size;
    size_t len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadMetadata:installed-size @%d",  p - input_data);
    int tls_status = mbedtls_asn1_get_int(&p, metadata_end, (int *) &fw_info->installed_size);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadMetadata:installed-size %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("PayloadMetadata:installed-size %" PRIu32, fw_info->installed_size);

    FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadMetadata:installed-digest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, metadata_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading PayloadMetadata:installed-digest %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (FOTA_CRYPTO_HASH_SIZE != len) {
        FOTA_TRACE_ERROR("PayloadMetadata:installed-digest too long %zu", len);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    memcpy(fw_info->installed_digest, p, len);
    p += len;

#if !defined(FOTA_DISABLE_DELTA)
    if (fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        FOTA_MANIFEST_TRACE_DEBUG("Parse PayloadMetadata:precursor-digest @%d",  p - input_data);
        tls_status = mbedtls_asn1_get_tag(
                        &p, metadata_end, &len,
                        MBEDTLS_ASN1_OCTET_STRING);
        if (tls_status != 0) {
            FOTA_TRACE_ERROR("Error reading PayloadMetadata:precursor-digest %d", tls_status);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }

        if (FOTA_CRYPTO_HASH_SIZE != len) {
            FOTA_TRACE_ERROR("PayloadMetadata:precursor-digest too long %zu", len);
            return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
        }
        memcpy(fw_info->precursor_digest, p, len);
    }
#endif // !FOTA_DISABLE_DELTA

    return FOTA_STATUS_SUCCESS;

}
#endif // !FOTA_DISABLE_DELTA || (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)


/*
 *  Manifest ::= SEQUENCE {
 *
 *    -- identifier fields
 *    vendor-id OCTET STRING,
 *    class-id OCTET STRING,
 *
 *    -- update priority to be passed to an application callback
 *    update-priority INTEGER,
 *
 *    -- component name
 *    component-name UTF8String,
 *
 *    -- payload description --
 *    payload-version UTF8String,
 *    payload-digest OCTET STRING,
 *    payload-size INTEGER,
 *    payload-uri UTF8String,
 *    payload-format ENUMERATED {
 *      -- xx01-xxFF describe payload-format
 *      -- 01xx-FFxx describe encrypted-format
 *      raw-binary(1),
 *      arm-patch-stream(5),
 *      combined(6),
 *      encrypted-raw(257),  -- 0x0101
 *      encrypted-combined(263) -- 0x0106
 *    },
 *
 *    -- raw ECDSA signature (r||s) over installed payload
 *    installed-signature OCTET STRING,
 *
 *    -- Used with 'arm-patch-stream', 'encrypted-raw' and 'encrypted-patch'
 *    -- never for 'raw-binary'
 *    payload-metadata PayloadMetadata OPTIONAL,
 *
 *    -- custom data to be passed to an endpoint device
 *    vendor-data OCTET STRING OPTIONAL
 *  }
 */
int parse_manifest_internal(
    const uint8_t *manifest, size_t manifest_size,
    manifest_firmware_info_t *fw_info, const uint8_t *input_data)
{
    int fota_status = FOTA_STATUS_INTERNAL_ERROR;
    const unsigned char *manifest_end = manifest + manifest_size;
    unsigned char *p = (unsigned char *) manifest;
    size_t len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:vendor-id @%d",  p - input_data);
    int tls_status = mbedtls_asn1_get_tag(
                         &p, manifest_end, &len,
                         MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:vendor-id %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    uint8_t fota_id[FOTA_GUID_SIZE] = {0};
    fota_status = fota_nvm_get_vendor_id(fota_id);
    if (fota_status != FOTA_STATUS_SUCCESS) {
        FOTA_TRACE_ERROR("failed to get vendor_id error=%d", fota_status);
        return fota_status;
    }
    if (len != sizeof(fota_id) || (memcmp(fota_id, p, len))) {
        FOTA_TRACE_ERROR("vendor_id mismatch");
        return FOTA_STATUS_MANIFEST_WRONG_VENDOR_ID;
    }
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    memcpy(fw_info->vendor_id, p, len);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:class-id @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:class-id %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    memset(fota_id, 0, FOTA_GUID_SIZE);
    fota_status = fota_nvm_get_class_id(fota_id);
    if (fota_status != FOTA_STATUS_SUCCESS) {
        FOTA_TRACE_ERROR("failed to get class_id error=%d", fota_status);
        return fota_status;
    }
    if (len != sizeof(fota_id) || (memcmp(fota_id, p, len))) {
        FOTA_TRACE_ERROR("class_id mismatch");
        return FOTA_STATUS_MANIFEST_WRONG_CLASS_ID;
    }
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)
    memcpy(fw_info->class_id, p, len);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:update-priority @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int(&p, manifest_end, (int *) &fw_info->priority);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:update-priority %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Manifest:update-priority %" PRIu32, fw_info->priority);

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:component-name @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:component-name %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len >= FOTA_COMPONENT_MAX_NAME_SIZE) {
        FOTA_TRACE_ERROR("component-name too long %zu", len);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    memcpy(fw_info->component_name, p, len);
    FOTA_MANIFEST_TRACE_DEBUG("component-name %s", fw_info->component_name);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-version @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-version %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    if (len >= FOTA_COMPONENT_MAX_SEMVER_STR_SIZE) {
        FOTA_TRACE_ERROR("Manifest:payload-version too long %zu", len);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    char sem_ver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = { 0 };
    memcpy(sem_ver, p, len);
    fota_status = fota_component_version_semver_to_int(sem_ver, &fw_info->version);
    if (fota_status != FOTA_STATUS_SUCCESS) {
        return fota_status;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-version %d", sem_ver);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-digest @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-digest %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len > FOTA_CRYPTO_HASH_SIZE) {
        FOTA_TRACE_ERROR("Manifest:payload-digest size is too big %zu", len);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    memcpy(fw_info->payload_digest, p, len);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-size @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_int(&p, manifest_end, (int *) &fw_info->payload_size);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-size %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-size %" PRIu32, fw_info->payload_size);

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-url @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len, MBEDTLS_ASN1_UTF8_STRING);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-url %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len >= FOTA_MANIFEST_URI_SIZE) {
        FOTA_TRACE_ERROR("Manifest:payload-url too long %zu", len);
        return FOTA_STATUS_MANIFEST_INVALID_URI;
    }
    memcpy(fw_info->uri, p, len);
    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-url %s", fw_info->uri);
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-format @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_enumerated_value(&p, manifest_end,(int *)&fw_info->payload_format);
    if (tls_status != 0) {
        FOTA_TRACE_ERROR("Error reading Manifest:payload-format %d", tls_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Manifest:payload-format %d", fw_info->payload_format);
    switch (fw_info->payload_format) {
        case FOTA_MANIFEST_PAYLOAD_FORMAT_RAW:

#if !defined(FOTA_DISABLE_DELTA)
        case FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA:
#endif
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
        case FOTA_MANIFEST_PAYLOAD_FORMAT_COMBINED:
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        case FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED:
#endif
#endif
            break;
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        case FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW:
#if (MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE != FOTA_CLOUD_ENCRYPTION_BLOCK_SIZE)
            // reject manifest because we can't guarantee proper operation
            // when device's block size is different then payload's encryption size.
            FOTA_TRACE_ERROR("error device doesn't support encrypted-raw payload's block size");
            return FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
#endif
#endif
            break;

        // FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_DELTA not supported yet
        default:
            FOTA_TRACE_ERROR("error unsupported payload format %" PRIu32 " - ", fw_info->payload_format);
            return FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:installed-signature @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status == 0) {
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
        if (FOTA_IMAGE_RAW_SIGNATURE_SIZE != len) {
            FOTA_TRACE_ERROR("installed-signature len is invalid %d (expected %d)", len, FOTA_IMAGE_RAW_SIGNATURE_SIZE);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }
        memcpy(fw_info->installed_signature, p, len);
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
        p += len;
    } else {
        FOTA_MANIFEST_TRACE_DEBUG("installed-signature not found ptr=%p", p);
    }

#if !defined(FOTA_DISABLE_DELTA) || (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_RAW) {
        FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:payload-metadata @%d",  p - input_data);
        tls_status = mbedtls_asn1_get_tag(
                         &p, manifest_end, &len,
                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (tls_status != 0) {
            FOTA_TRACE_ERROR("Error reading Manifest:payload-metadata %d", tls_status);
            return FOTA_STATUS_MANIFEST_MALFORMED;
        }


        fota_status = parse_payload_metadata(p, len, fw_info, input_data);
        if (fota_status != 0) {
            FOTA_TRACE_ERROR("Error parse_payload_metadata %d", fota_status);
            return fota_status;
        }

        p += len;

    } else
#endif
    {
        /* FOTA_MANIFEST_PAYLOAD_FORMAT_RAW */
        /* for the ease of use we will fill in payload size and digest values */
        memcpy(fw_info->installed_digest, fw_info->payload_digest, FOTA_CRYPTO_HASH_SIZE);
        fw_info->installed_size = fw_info->payload_size;
    }

    FOTA_MANIFEST_TRACE_DEBUG("Parse Manifest:vendor-data @%d",  p - input_data);
    tls_status = mbedtls_asn1_get_tag(
                     &p, manifest_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tls_status == 0) {
        if (FOTA_MANIFEST_VENDOR_DATA_SIZE < len) {
            FOTA_TRACE_ERROR("Manifest:vendor-data too long %zu", len);
            return FOTA_STATUS_MANIFEST_CUSTOM_DATA_TOO_BIG;
        }
        memcpy(fw_info->vendor_data, p, len);

        p += len;
    } else {
        FOTA_MANIFEST_TRACE_DEBUG("vendor-data not found");
    }

    FOTA_DBG_ASSERT(p == manifest_end);

    return FOTA_STATUS_SUCCESS;
}

/*
 * Assuming SignedResource followed by EncryptionKeySchema
 *  when the payload is pre-encrypted
 * 
 *  SignedResource ::= SEQUENCE {
 *    manifest-version ENUMERATED {
 *      v3(3)
 *    },
 *    manifest Manifest,
 *
 *    -- raw ECDSA signature (r||s) over Manifest
 *    signature OCTET STRING
 *  }
 *
 * -- Encryption Key Schema:
 * --   the key used to encrypt the payload
 * --   added by service after SignedResource
 * EncryptionKeySchema DEFINITIONS IMPLICIT TAGS ::= BEGIN
 *   EncryptionKey ::= CHOICE {
 *     aes-128-bit [1] IMPLICIT OCTET STRING (SIZE(16))
 *   }
 */
int fota_manifest_parse(
    const uint8_t *input_data, size_t input_size,
    manifest_firmware_info_t *fw_info
)
{
    FOTA_DBG_ASSERT(input_data);
    FOTA_DBG_ASSERT(input_size);
    FOTA_DBG_ASSERT(fw_info);

    memset(fw_info, 0, sizeof(*fw_info));

    int ret = FOTA_STATUS_MANIFEST_MALFORMED;  // used by FOTA_FI_SAFE_COND
    int fota_sig_status = FOTA_STATUS_MANIFEST_MALFORMED;  // must be set to error
    int tmp_status;  // reusable status
    size_t len = input_size;
    unsigned char *p = (unsigned char *)input_data;
    unsigned char *signed_resource_end = p + len;

    unsigned char *int_manifest = 0;
    size_t int_manifest_size = 0;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_tag(
                     &p, signed_resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error SignedResource tag %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (p + len > signed_resource_end) {
        FOTA_TRACE_ERROR("Error got truncated manifest");
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    // input data size may be bigger than real SignedResource size
    // due to storage limitations or EncryptionKey.
    // set to exact SignedResource end
    signed_resource_end = p + len;

    int manifest_format_version = 0;
    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource:version @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_enumerated_value(&p, signed_resource_end, &manifest_format_version);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource:version %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    FOTA_MANIFEST_TRACE_DEBUG("SignedResource:version %d", manifest_format_version);

    if (FOTA_MANIFEST_SCHEMA_VERSION != manifest_format_version) {
        FOTA_TRACE_ERROR("wrong manifest schema version version %d", manifest_format_version);
        return FOTA_STATUS_MANIFEST_SCHEMA_UNSUPPORTED;
    }

    uint8_t *signed_data_ptr = p;
    size_t signed_data_size;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource:manifest @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_tag(
                     &p, signed_resource_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource:manifest %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    signed_data_size = p + len - signed_data_ptr;

    int_manifest = p;
    int_manifest_size = len;
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource:signature @%d",  p - input_data);
    tmp_status = mbedtls_asn1_get_tag(
                     &p, signed_resource_end, &len,
                     MBEDTLS_ASN1_OCTET_STRING);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading SignedResource:signature %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
#if !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT==FOTA_X509_PUBLIC_KEY_FORMAT)
    // signature in manifest schema v3 is a raw signature,
    // When using mbedtls_pk is used DER encoded signature is expected
    uint8_t der_encoded_sig[FOTA_IMAGE_DER_SIGNATURE_SIZE];
    size_t der_encoded_sig_size;

    tmp_status = fota_der_encode_signature(
                     p, len,
                     der_encoded_sig, sizeof(der_encoded_sig), &der_encoded_sig_size);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error fota_der_encode_signature failed %d", tmp_status);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }
    fota_sig_status = fota_verify_signature(
                          signed_data_ptr, signed_data_size,
                          der_encoded_sig, der_encoded_sig_size);
#elif (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT==FOTA_RAW_PUBLIC_KEY_FORMAT)

    fota_sig_status = fota_verify_signature(
                          signed_data_ptr, signed_data_size,
                          p, len);
#else
#error public key format not supported
#endif  // MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT
    FOTA_FI_SAFE_COND(
        fota_sig_status == FOTA_STATUS_SUCCESS,
        fota_sig_status,
        "fota_verify_signature failed %d", fota_sig_status
    );
#endif  // !defined(FOTA_TEST_MANIFEST_BYPASS_VALIDATION)

    p += len;

    tmp_status = parse_manifest_internal(
                     int_manifest, int_manifest_size,
                     fw_info, input_data);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("parse_manifest_internal failed %d", tmp_status);
        return tmp_status;
    }

    FOTA_MANIFEST_TRACE_DEBUG("status = %d", FOTA_STATUS_SUCCESS);
    return FOTA_STATUS_SUCCESS;
fail:
    return ret;
}

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
/*
 * Assuming SignedResource followed by EncryptionKeySchema
 *  when the payload is pre-encrypted
 * 
 *  SignedResource ::= SEQUENCE {
 *    manifest-version ENUMERATED {
 *      v3(3)
 *    },
 *    manifest Manifest,
 *
 *    -- raw ECDSA signature (r||s) over Manifest
 *    signature OCTET STRING
 *  }
 *
 * -- Encryption Key Schema:
 * --   the key used to encrypt the payload
 * --   added by service after SignedResource
 * EncryptionKeySchema DEFINITIONS IMPLICIT TAGS ::= BEGIN
 *   EncryptionKey ::= CHOICE {
 *     aes-128-bit [1] IMPLICIT OCTET STRING (SIZE(16))
 *   }
 */
int fota_encryption_key_parse(
    const uint8_t *input_data,
    size_t         input_size,
    uint8_t        encryption_key[FOTA_ENCRYPT_KEY_SIZE]
)
{
    FOTA_DBG_ASSERT(input_data);
    FOTA_DBG_ASSERT(input_size);

    size_t len = input_size;
    unsigned char *p = (unsigned char *)input_data;
    unsigned char *input_data_end = p + len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse SignedResource @%d",  p - input_data);
    int ret = mbedtls_asn1_get_tag(
                     &p, input_data_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        FOTA_TRACE_ERROR("Error SignedResource tag %d", ret);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (p + len > input_data_end) {
        FOTA_TRACE_ERROR("Error got truncated manifest");
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    // jump over SignedResource
    p += len;

    FOTA_MANIFEST_TRACE_DEBUG("Parse EncryptionKey @%d",  p - input_data);
    ret = mbedtls_asn1_get_tag(
                    &p, input_data_end, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | FOTA_MANIFEST_ENCRYPTION_KEY_TAG_AES_128);
    if (ret != 0) {
        FOTA_TRACE_ERROR("Error EncryptionKey tag %d", ret);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (len != FOTA_ENCRYPT_KEY_SIZE) {
        FOTA_TRACE_ERROR("Unexpected EncryptionKey size %zu", len);
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    if (p + len > input_data_end) {
        FOTA_TRACE_ERROR("Error got truncated manifest");
        return FOTA_STATUS_MANIFEST_MALFORMED;
    }

    fota_fi_memcpy(encryption_key, p, FOTA_ENCRYPT_KEY_SIZE);
    p += len;

    return FOTA_STATUS_SUCCESS;
}
#endif // (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)

#endif // (FOTA_MANIFEST_SCHEMA_VERSION == 3)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
