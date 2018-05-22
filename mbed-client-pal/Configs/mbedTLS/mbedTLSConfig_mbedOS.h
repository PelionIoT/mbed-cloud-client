//----------------------------------------------------------------------------
// The confidential and proprietary information contained in this file may
// only be used by a person authorised under and to the extent permitted
// by a subsisting licensing agreement from ARM Limited or its affiliates.
//
// (C) COPYRIGHT 2016 ARM Limited or its affiliates.
// ALL RIGHTS RESERVED
//
// This entire notice must be reproduced on all copies of this file
// and copies of this file may only be made by a person if such person is
// permitted to do so under the terms of a subsisting license agreement
// from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#ifndef PAL_MBEDTLS_USER_CONFIG_H
#define PAL_MBEDTLS_USER_CONFIG_H


/*! All of the following definitions are mandatory requirements for correct 
*   fucntionality of PAL TLS and Crypto components.
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
#ifndef MBEDTLS_SSL_CIPHERSUITES
    #define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, \
                                     MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
                                     MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, \
                                     MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8, \
                                     MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8, \
                                     MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256
#endif //MBEDTLS_SSL_CIPHERSUITES

/*! All of the following definitions are optimizations (reduce mbedTLS memory usage and size),
*   changing them is on the user responsibility since they can enlarge
*   the binary footprint and the memory usage
*/

// define to save 8KB RAM at the expense of ROM
#ifndef MBEDTLS_AES_ROM_TABLES
    #define MBEDTLS_AES_ROM_TABLES
#endif //MBEDTLS_AES_ROM_TABLES

// Reduce IO buffer to save RAM, default is 16KB
#ifndef MBEDTLS_SSL_MAX_CONTENT_LEN
    #define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#endif //MBEDTLS_SSL_MAX_CONTENT_LEN

// needed for Base64 encoding Opaque data for
// registration payload, adds 500 bytes to flash.
#ifndef MBEDTLS_BASE64_C
    #define MBEDTLS_BASE64_C
#endif // MBEDTLS_BASE64_C

// Needed by provisioning
#undef MBEDTLS_PEM_WRITE_C

// Remove RSA, save 20KB at total
#undef MBEDTLS_RSA_C

#undef MBEDTLS_PK_RSA_ALT_SUPPORT

#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
   
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


#include "mbedtls/check_config.h"

#endif /* PAL_MBEDTLS_USER_CONFIG_H */
