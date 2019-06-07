// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#ifndef PAL_MBEDTLS_USER_CONFIG_H
#define PAL_MBEDTLS_USER_CONFIG_H


/*! All of the following definitions are mandatory requirements for correct
*   functionality of PAL TLS and Crypto components.
*   Please do not disable them.
*/

/* Platform has time function to provide time for certificates verifications */
#if 1 //Please set to 1 if you are using secure time
#ifndef MBEDTLS_HAVE_TIME
    #define MBEDTLS_HAVE_TIME
#endif //MBEDTLS_HAVE_TIME

#ifndef MBEDTLS_HAVE_TIME_DATE
    #define MBEDTLS_HAVE_TIME_DATE
#endif //MBEDTLS_HAVE_TIME_DATE

#ifndef MBEDTLS_PLATFORM_TIME_ALT
    #define MBEDTLS_PLATFORM_TIME_ALT
#endif //MBEDTLS_PLATFORM_TIME_ALT

/* System support */
#ifndef MBEDTLS_HAVE_ASM
    #define MBEDTLS_HAVE_ASM
#endif //MBEDTLS_HAVE_ASM
#endif
/* mbed TLS feature support */
#ifndef MBEDTLS_ECP_DP_SECP256R1_ENABLED
    #define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#endif //MBEDTLS_ECP_DP_SECP256R1_ENABLED

#ifndef MBEDTLS_ECP_NIST_OPTIM
    #define MBEDTLS_ECP_NIST_OPTIM
#endif //MBEDTLS_ECP_NIST_OPTIM

#ifndef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    #define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#endif //MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

#ifndef MBEDTLS_SSL_PROTO_TLS1_2
    #define MBEDTLS_SSL_PROTO_TLS1_2
#endif //MBEDTLS_SSL_PROTO_TLS1_2

#ifndef MBEDTLS_SSL_PROTO_DTLS
    #define MBEDTLS_SSL_PROTO_DTLS
#endif //MBEDTLS_SSL_PROTO_DTLS

#ifndef MBEDTLS_SSL_DTLS_ANTI_REPLAY
    #define MBEDTLS_SSL_DTLS_ANTI_REPLAY
#endif //MBEDTLS_SSL_DTLS_ANTI_REPLAY

#ifndef MBEDTLS_SSL_DTLS_HELLO_VERIFY
    #define MBEDTLS_SSL_DTLS_HELLO_VERIFY
#endif //MBEDTLS_SSL_DTLS_HELLO_VERIFY

#ifndef MBEDTLS_SSL_EXPORT_KEYS
    #define MBEDTLS_SSL_EXPORT_KEYS
#endif //MBEDTLS_SSL_EXPORT_KEYS

/* mbed TLS modules */
#ifndef MBEDTLS_AES_C
    #define MBEDTLS_AES_C
#endif //MBEDTLS_AES_C

/* Disable some of the speed optimizations on AES code to save
 * ~6200 bytes of ROM. According to comments on the mbedtls PR 394,
 * the speed on Cortex M4 is not even reduced by this. */
#ifndef MBEDTLS_AES_FEWER_TABLES
    #define MBEDTLS_AES_FEWER_TABLES
#endif // MBEDTLS_AES_FEWER_TABLES

#ifndef MBEDTLS_ASN1_PARSE_C
    #define MBEDTLS_ASN1_PARSE_C
#endif //MBEDTLS_ASN1_PARSE_C

#ifndef MBEDTLS_ASN1_WRITE_C
    #define MBEDTLS_ASN1_WRITE_C
#endif //MBEDTLS_ASN1_WRITE_C

#ifndef MBEDTLS_BIGNUM_C
    #define MBEDTLS_BIGNUM_C
#endif //MBEDTLS_BIGNUM_C

#ifndef MBEDTLS_CIPHER_C
    #define MBEDTLS_CIPHER_C
#endif //MBEDTLS_CIPHER_C

#ifndef MBEDTLS_CTR_DRBG_C
    #define MBEDTLS_CTR_DRBG_C
#endif //MBEDTLS_CTR_DRBG_C

#ifndef MBEDTLS_ECP_C
    #define MBEDTLS_ECP_C
#endif //MBEDTLS_ECP_C

#ifndef MBEDTLS_ENTROPY_C
    #define MBEDTLS_ENTROPY_C
#endif //MBEDTLS_ENTROPY_C

#ifndef MBEDTLS_MD_C
    #define MBEDTLS_MD_C
#endif //MBEDTLS_MD_C

#ifndef MBEDTLS_OID_C
    #define MBEDTLS_OID_C
#endif //MBEDTLS_OID_C

#ifndef MBEDTLS_PK_C
    #define MBEDTLS_PK_C
#endif //MBEDTLS_PK_C

#ifndef MBEDTLS_PK_PARSE_C
    #define MBEDTLS_PK_PARSE_C
#endif //MBEDTLS_PK_PARSE_C

#ifndef MBEDTLS_SHA256_C
    #define MBEDTLS_SHA256_C
#endif //MBEDTLS_SHA256_C

// Disable the speed optimizations of SHA256, makes binary size smaller
// on Cortex-M by 1800B with ARMCC5 and 1384B with GCC 6.3.
#ifndef MBEDTLS_SHA256_SMALLER
    #define MBEDTLS_SHA256_SMALLER
#endif // MBEDTLS_SHA256_SMALLER

#ifndef MBEDTLS_SSL_COOKIE_C
    #define MBEDTLS_SSL_COOKIE_C
#endif //MBEDTLS_SSL_COOKIE_C

#ifndef MBEDTLS_SSL_CLI_C
    #define MBEDTLS_SSL_CLI_C
#endif //MBEDTLS_SSL_CLI_C

#ifndef MBEDTLS_SSL_TLS_C
    #define MBEDTLS_SSL_TLS_C
#endif //MBEDTLS_SSL_TLS_C
// XXX mbedclient needs these: mbedtls_x509_crt_free, mbedtls_x509_crt_init, mbedtls_x509_crt_parse
#ifndef MBEDTLS_X509_USE_C
    #define MBEDTLS_X509_USE_C
#endif //MBEDTLS_X509_USE_C

#ifndef MBEDTLS_X509_CRT_PARSE_C
    #define MBEDTLS_X509_CRT_PARSE_C
#endif //MBEDTLS_X509_CRT_PARSE_C
// a bit wrong way to get mbedtls_ssl_conf_psk:
#ifndef MBEDTLS_CMAC_C
    #define MBEDTLS_CMAC_C
#endif //MBEDTLS_CMAC_C

#ifndef MBEDTLS_ECDH_C
    #define MBEDTLS_ECDH_C
#endif //MBEDTLS_ECDH_C

#ifndef MBEDTLS_ECDSA_C
    #define MBEDTLS_ECDSA_C
#endif //MBEDTLS_ECDSA_C

#ifndef MBEDTLS_GCM_C
    #define MBEDTLS_GCM_C
#endif //MBEDTLS_GCM_C

#ifndef MBEDTLS_X509_CRT_PARSE_C
    #define MBEDTLS_X509_CRT_PARSE_C
#endif //MBEDTLS_X509_CRT_PARSE_C

#ifndef MBEDTLS_X509_CSR_PARSE_C
    #define MBEDTLS_X509_CSR_PARSE_C
#endif //MBEDTLS_X509_CSR_PARSE_C

#ifndef MBEDTLS_X509_CREATE_C
    #define MBEDTLS_X509_CREATE_C
#endif //MBEDTLS_X509_CREATE_C

#ifndef MBEDTLS_X509_CSR_WRITE_C
    #define MBEDTLS_X509_CSR_WRITE_C
#endif //MBEDTLS_X509_CSR_WRITE_C

#ifndef MBEDTLS_CTR_DRBG_MAX_REQUEST
    #define MBEDTLS_CTR_DRBG_MAX_REQUEST 2048
#endif //MBEDTLS_CTR_DRBG_MAX_REQUEST

// Needed by update
#ifndef MBEDTLS_CIPHER_MODE_CTR
    #define MBEDTLS_CIPHER_MODE_CTR
#endif //MBEDTLS_CIPHER_MODE_CTR

// Save ROM and a few bytes of RAM by specifying our own ciphersuite list
// TODO: replace all suites with a single chachapoly suite
// TODO: try client lite with PSK with DTLS vs full client with certs and TLS
// TODO: generate cert with shorter EC curve(might already be done) -- look for ec key type secp_256512 via openssl x509 cert inspection.
// NOTE: PSK removes the need for x509 parser
// TODO: enable cryptocell and see if RAM usage drops (probably won't but worth a try)
// TODO: reach out to cryptocell folks for optimizations (Ron Elder)
// TODO: with https://tls.mbed.org/kb/how-to/reduce-mbedtls-memory-and-storage-footprint make sure that PDMC is using the correct API along with configuring things properly
#ifndef MBEDTLS_SSL_CIPHERSUITES
    #define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, \
                                     MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
                                     MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, \
                                     MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8, \
                                     MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8
#endif //MBEDTLS_SSL_CIPHERSUITES

/*! All of the following definitions are optimizations (reduce mbedTLS memory usage and size),
*   changing them is on the user responsibility since they can enlarge
*   the binary footprint and the memory usage
*/

// define to save 8KB RAM at the expense of ROM
#ifndef MBEDTLS_AES_ROM_TABLES
    #define MBEDTLS_AES_ROM_TABLES
#endif //MBEDTLS_AES_ROM_TABLES

// Read SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE from user config file
#ifdef MBED_CLIENT_USER_CONFIG_FILE
#include MBED_CLIENT_USER_CONFIG_FILE
#endif
// Reduce IO buffer to save RAM, default is 16KB
#ifndef MBEDTLS_SSL_MAX_CONTENT_LEN
    #define MBEDTLS_SSL_MAX_CONTENT_LEN SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE * 4
#endif //MBEDTLS_SSL_MAX_CONTENT_LEN

// needed for Base64 encoding Opaque data for
// registration payload, adds 500 bytes to flash.
#ifndef MBEDTLS_BASE64_C
    #define MBEDTLS_BASE64_C
#endif // MBEDTLS_BASE64_C

/**
 * \def MBEDTLS_SSL_RENEGOTIATION
 *
 * Enable support for TLS renegotiation.
 *
 * The two main uses of renegotiation are (1) refresh keys on long-lived
 * connections and (2) client authentication after the initial handshake.
 * If you don't need renegotiation, it's probably better to disable it, since
 * it has been associated with security issues in the past and is easy to
 * misuse/misunderstand.
 *
 * Comment this to disable support for renegotiation.
 *
 * \note   Even if this option is disabled, both client and server are aware
 *         of the Renegotiation Indication Extension (RFC 5746) used to
 *         prevent the SSL renegotiation attack (see RFC 5746 Sect. 1).
 *         (See \c mbedtls_ssl_conf_legacy_renegotiation for the
 *          configuration of this extension).
 *
 * \note   This feature is required by Device Management Client for Client-side
 *         certificate expiration verification. Disabling it will also require
 *         setting PAL_USE_SECURE_TIME to 0.
 *
 */
#define MBEDTLS_SSL_RENEGOTIATION

// Needed by provisioning
#undef MBEDTLS_PEM_WRITE_C

// Remove RSA, save 20KB at total
#if !MBED_CONF_MBED_CLIENT_PAL_RSA_REQUIRED
    #undef MBEDTLS_RSA_C
    #undef MBEDTLS_PK_RSA_ALT_SUPPORT
    #undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    #undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    #undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#endif // MBED_CONF_MBED_CLIENT_PAL_RSA_REQUIRED

// Remove error messages, save 10KB of ROM
#undef MBEDTLS_ERROR_C

// Remove selftesting and save 11KB of ROM
#undef MBEDTLS_SELF_TEST

#undef MBEDTLS_CERTS_C

// Reduces ROM size by 30 kB
#undef MBEDTLS_ERROR_STRERROR_DUMMY

#undef MBEDTLS_VERSION_FEATURES

#undef MBEDTLS_DEBUG_C

// needed for parsing the certificates
#undef MBEDTLS_PEM_PARSE_C

#undef MBEDTLS_SHA512_C

#undef MBEDTLS_SSL_SRV_C

#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP521R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
#undef MBEDTLS_ECP_DP_CURVE25519_ENABLED

// Tune elliptic curve configuration.
// This will hit the performance a bit but will decrease the RAM consumption by 4k.
#define MBEDTLS_ECP_WINDOW_SIZE 2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0

// Reduces size particularly in case PSA crypto is used
#undef MBEDTLS_CHACHA20_C
#undef MBEDTLS_CHACHAPOLY_C
#undef MBEDTLS_POLY1305_C

// Do not save a copy of the peer certificate.
// This will reduce the RAM consumption roughly by 1500 bytes.
#undef MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

#include "mbedtls/check_config.h"

#endif /* PAL_MBEDTLS_USER_CONFIG_H */
