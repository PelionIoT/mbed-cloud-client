// ----------------------------------------------------------------------------
// Copyright 2022 Pelion Ltd.
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

#ifdef LWM2M_COMPLIANT

#define TRACE_GROUP "PKCS"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/asn1.h"
#include "mbed-trace/mbed_trace.h"
#include "est_defs.h"
#include "include/CertificatePkcs7Parser.h"

// NOTE: In the comments to functions below, we are using RFC 2315 definitions
// for the PKCS#7 syntax elements. These are formally obsolete (the current
// version is defined in RFC 5652), but we don't support any structures
// supported in newer versions anyway, so it's simpler this way.

static int process_ber_length(unsigned char **p,
                              const unsigned char *end,
                              long *out_len,
                              int result,
                              size_t ulen) 
{
    if (result == MBEDTLS_ERR_ASN1_INVALID_LENGTH && *p < end && **p == 0x80) {
        // BER indefinite length
        ++*p;
        *out_len = -1;
        return 0;
    }
    if (!result) {
        if (ulen > LONG_MAX) {
            return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
        }
        *out_len = (long) ulen;
    }
    return result;
}

#define ASN1_BER_EOC_TAG 0x00

static int
get_ber_tag(unsigned char **p, const unsigned char *end, long *len, int tag)
{
    // This is like mbedtls_asn1_get_tag() but allows BER indefinite length;
    // that's why the len parameter is a signed type here.
    size_t ulen;
    int result = mbedtls_asn1_get_tag(p, end, &ulen, tag);
    return process_ber_length(p, end, len, result, ulen);
}

static est_status_e
copy_security_info(struct cert_context_s *cert_ctx,
                   unsigned char *p,
                   const unsigned char *end)
{
    assert(cert_ctx);

    cert_ctx->cert_length = (uint16_t) (end - p);

    cert_ctx->cert = (uint8_t*)malloc(cert_ctx->cert_length);
    if (cert_ctx->cert == NULL) {
        tr_error("Failed to allocate certificate buffer");
        return EST_STATUS_PROTOCOL_ERROR;
    }
    memcpy(cert_ctx->cert, p, cert_ctx->cert_length);

    return EST_STATUS_SUCCESS;
}

static est_status_e pkcs7_x509_set_parse(unsigned char **p,
                                         const unsigned char *end,
                                         long total_len, 
                                         struct cert_chain_context_s* chain_ctx)
{
    est_status_e status = EST_STATUS_SUCCESS;

    struct cert_context_s *cert_ctx = NULL;

    uint8_t chain_length = 0;

    tr_debug("pkcs7_x509_set_parse - invoked");

     // Allocate new certificate context
    cert_ctx = (struct cert_context_s*)malloc(sizeof(struct cert_context_s));
    if (cert_ctx == NULL) {
        tr_error("Failed to allocate data for the certificate");
        return EST_STATUS_PROTOCOL_ERROR;            
    }

    memset(cert_ctx, 0, sizeof(struct cert_context_s));

    chain_ctx->certs = cert_ctx;

    // Note: we are inside an implicit SET
    // TODO!! total_Len isn't changed so not sure it's needed here
    while (*p < end && (total_len >= 0 || **p != ASN1_BER_EOC_TAG)) {
        unsigned char *len_cert_ptr = *p + 1;
        size_t len_cert;
        // We don't support indefinite length here, because Mbed TLS would not
        // be able to parse that anyway.
        if (mbedtls_asn1_get_len(&len_cert_ptr, end, &len_cert)
                || len_cert > (size_t) (end - len_cert_ptr)) {
            tr_error("Malformed data when parsing PKCS#7 data set");
            return EST_STATUS_PROTOCOL_ERROR;
        }        

        // Allocate new certificate context
        if(chain_length > 0) {
            cert_ctx->next = (struct cert_context_s*)malloc(sizeof(struct cert_context_s));
            if (cert_ctx->next == NULL) {
                tr_error("Failed to allocate data for the certificate");
                return EST_STATUS_PROTOCOL_ERROR;
            }
            cert_ctx = cert_ctx->next;
        }

        if ((status = copy_security_info(cert_ctx, *p, len_cert_ptr + len_cert)) != EST_STATUS_SUCCESS) {
            return status;
        }

        *p = len_cert_ptr + len_cert;
        cert_ctx->next = NULL;
        chain_length++;
    }

    chain_ctx->chain_length = chain_length;
    assert(total_len < 0 || *p == end);
    return EST_STATUS_SUCCESS;
}

static est_status_e pkcs7_inner_content_info_verify(unsigned char **p,
                                                    const unsigned char *end)
{
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content
    //     [0] EXPLICIT ANY DEFINED BY contentType }
    //
    // ContentType ::= OBJECT IDENTIFIER
    static const unsigned char ID_DATA_OID[] = { 0x06, 0x09, 0x2A, 0x86,
                                                 0x48, 0x86, 0xF7, 0x0D,
                                                 0x01, 0x07, 0x01 };

    long len;
    if (get_ber_tag(p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
            || (len >= 0 && len != sizeof(ID_DATA_OID))
            || *p + sizeof(ID_DATA_OID) > end
            || memcmp(*p, ID_DATA_OID, sizeof(ID_DATA_OID)) != 0) {
        goto malformed;
    }

    *p += sizeof(ID_DATA_OID);

    // for indefinite-length encoding, we expect EOC here
    if (len < 0 && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0)) {
        goto malformed;
    }

    return EST_STATUS_SUCCESS;
malformed:
    tr_error("Encapsulated content for PKCS#7 certs-only MUST be absent");
    return EST_STATUS_PROTOCOL_ERROR;
}

static est_status_e pkcs7_signed_data_parse(unsigned char **p,
                                            const unsigned char *end,
                                            struct cert_chain_context_s* chain_ctx)
{
    // SignedData ::= SEQUENCE {
    //   version Version,
    //   digestAlgorithms DigestAlgorithmIdentifiers,
    //   contentInfo ContentInfo,
    //   certificates
    //      [0] IMPLICIT ExtendedCertificatesAndCertificates
    //        OPTIONAL,
    //   crls
    //     [1] IMPLICIT CertificateRevocationLists OPTIONAL,
    //   signerInfos SignerInfos }
    //
    // Version ::= INTEGER
    //
    // DigestAlgorithmIdentifiers ::=
    //   SET OF DigestAlgorithmIdentifier
    //
    // ExtendedCertificatesAndCertificates ::=
    //   SET OF ExtendedCertificateOrCertificate
    //
    // ExtendedCertificateOrCertificate ::= CHOICE {
    //   certificate Certificate, -- X.509
    //
    //   extendedCertificate [0] IMPLICIT ExtendedCertificate }
    //
    // CertificateRevocationLists ::=
    //   SET OF CertificateRevocationList

    tr_debug("pkcs7_signed_data_parse - invoked");

    est_status_e status = EST_STATUS_SUCCESS;
    long signed_data_len;

    if (get_ber_tag(p, end, &signed_data_len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
            || (signed_data_len >= 0 && signed_data_len != (long) (end - *p))) {
        goto malformed;
    }

    int version;
    if (mbedtls_asn1_get_int(p, end, &version)) {
        goto malformed;
    }
    if (version != 1) {
        tr_error("Only version 1 of SignedData is currently supported");
        return EST_STATUS_PROTOCOL_ERROR;
    }

    // skip digestAlgorithms, we don't care about those
    long len;
    if (get_ber_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)
            || len > (long) (end - *p)) {
        goto malformed;
    }
    if (len >= 0) {
        *p += len;
    } else if (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0) {
        // we don't support indefinite-length digestAlgorithms properly,
        // but let's try to support zero-length case as best-effort
        goto malformed;
    }

    if ((status = pkcs7_inner_content_info_verify(p, end)) != EST_STATUS_SUCCESS) {
        return status;
    }

    static const unsigned char CERTIFICATES_TAG =
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0;
    if (*p < end && **p == CERTIFICATES_TAG) {
        if (get_ber_tag(p, end, &len, CERTIFICATES_TAG)
                || len > (long) (end - *p)) {
            goto malformed;
        }

        const unsigned char *certificates_end = len >= 0 ? *p + len : end;
        if ((status = pkcs7_x509_set_parse(p, certificates_end, len, chain_ctx)) != EST_STATUS_SUCCESS) {
            return status;
        }
        if ((len >= 0 && *p != certificates_end)
                || (len < 0
                    && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG)
                        || len != 0))) {
            goto malformed;
        }
    }

    static const unsigned char CRLS_TAG =
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1;
    if (*p < end && **p == CRLS_TAG) {
        tr_error("pkcs7_signed_data_parse CRLS_TAG found - they are skipped and not supported");
        if (get_ber_tag(p, end, &len, CRLS_TAG) || len > (long) (end - *p)) {
            goto malformed;
        }

        const unsigned char *crls_end = len >= 0 ? *p + len : end;

        tr_info("skip the CRLs");
        *p = *p + len;

        if ((len >= 0 && *p != crls_end)
                || (len < 0
                    && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG)
                        || len != 0))) {
            goto malformed;
        }
    }   

    if (get_ber_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)
            || len > (long) (end - *p)) {
        goto malformed;
    }

    if (len > 0
            || (len < 0
                && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0))) {
        tr_error("signerInfos field for PKCS#7 certs-only MUST be empty");
        goto malformed;
    }

    // for indefinite-length encoding, we expect EOC here
    if (signed_data_len < 0
            && (get_ber_tag(p, end, &signed_data_len, ASN1_BER_EOC_TAG)
                || signed_data_len != 0)) {
        tr_error("EOC tag is expected for indefinite-length encoding");
        goto malformed;
    }

    tr_debug("pkcs7_signed_data_parse - exit with success");

    return EST_STATUS_SUCCESS;
malformed:
    tr_error("Malformed data when parsing PKCS#7 SignedData");
    return EST_STATUS_PROTOCOL_ERROR;
}

struct cert_chain_context_s* parse_pkcs7_cert(uint8_t **cert_chain_data,
                                              uint16_t cert_chain_data_len,
                                              est_status_e *result)
{
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content
    //     [0] EXPLICIT ANY DEFINED BY contentType }
    //
    // ContentType ::= OBJECT IDENTIFIER   
    tr_debug("parse_pkcs7_cert - invoked"); 
    static const unsigned char SIGNED_DATA_OID[] = { 0x06, 0x09, 0x2A, 0x86,
                                                     0x48, 0x86, 0xF7, 0x0D,
                                                     0x01, 0x07, 0x02 };
    long content_info_len;

    assert(cert_chain_data);
    assert(cert_chain_data_len > 0);

    unsigned char **p = cert_chain_data;
    const unsigned char *end = *cert_chain_data + cert_chain_data_len;   

    struct cert_chain_context_s *chain_ctx = (struct cert_chain_context_s*)malloc(sizeof(struct cert_chain_context_s));
    if(chain_ctx == NULL) {
        tr_error("parse_pkcs7_cert - failure in allocating cert context. Out of memory");
        *result = EST_STATUS_MEMORY_ALLOCATION_FAILURE;
        return NULL;
    }

    memset(chain_ctx, 0, sizeof(*chain_ctx));

    if (get_ber_tag(p, end, &content_info_len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)
            || (content_info_len >= 0
                && content_info_len != (long) (end - *p))) {
        tr_debug("parse_pkcs7_cert - failed get_ber_tag");
        goto malformed;
    }

    if ((content_info_len >= 0
         && (size_t) content_info_len < sizeof(SIGNED_DATA_OID))
            || *p + sizeof(SIGNED_DATA_OID) > end
            || memcmp(*p, SIGNED_DATA_OID, sizeof(SIGNED_DATA_OID)) != 0) {
        tr_error("parse_pkcs7_cert - CMS Type for PKCS#7 certs-only MUST be SignedData");
        goto malformed;
    }

    *p += sizeof(SIGNED_DATA_OID);

    long len;
    if (get_ber_tag(p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC
                            | 0)
            || (len >= 0 && len != (long) (end - *p))) {
        goto malformed;
    }

    if (pkcs7_signed_data_parse(p, end, chain_ctx) != EST_STATUS_SUCCESS) {
        tr_error("parse_pkcs7_cert - failed to parse signed data");
        goto malformed;
    }

    // EOCs for indefinite-length encodings
    if (len < 0 && (get_ber_tag(p, end, &len, ASN1_BER_EOC_TAG) || len != 0)) {
        goto malformed;
    }
    if ((content_info_len < 0
         && (get_ber_tag(p, end, &content_info_len, ASN1_BER_EOC_TAG)
             || content_info_len != 0))
            || *p != end) {
        goto malformed;
    }

    *result = EST_STATUS_SUCCESS;

    tr_debug("parse_pkcs7_cert - exit with success");

    return chain_ctx;

malformed:
    tr_error("parse_pkcs7_cert - malformed data when parsing PKCS#7 ContentInfo");
    *result = EST_STATUS_PROTOCOL_ERROR;
    return chain_ctx;
}

#endif //LWM2M_COMPLIANT