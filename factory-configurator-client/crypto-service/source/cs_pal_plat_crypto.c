/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
#include "cs_pal_plat_crypto.h"
#if !defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) || defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)
#include "pal.h"
#endif
#include "mbedtls/aes.h"
#if (PAL_ENABLE_X509 == 1)
#include "mbedtls/asn1write.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#endif 
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/ccm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/cmac.h"
#include "mbedtls/asn1.h"
#include "mbedtls/ecp.h"

#include "mbedtls/ecdh.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_time.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "psa/crypto.h"
#endif
#include "pv_macros.h"

// Add ssl-platform include at the top
#include "ssl_platform.h"
#include <stdio.h>

#define TRACE_GROUP "PAL"

// Direct ssl-platform type mappings for simple types
typedef ssl_platform_entropy_context_t palEntropy_t;
typedef ssl_platform_pk_context_t palECKey_t;

typedef mbedtls_ccm_context palCCM_t;
typedef mbedtls_ecp_group palECGroup_t;
typedef mbedtls_ecp_point palECPoint_t;
typedef mbedtls_mpi palMP_t;
typedef mbedtls_x509write_csr palx509CSR_t;
typedef ssl_platform_cipher_context_t palCipherCtx_t;

typedef struct palSign{
    mbedtls_mpi r;  // Keep mbed-TLS for now - ssl-platform doesn't expose MPI operations
    mbedtls_mpi s;
}palSignature_t;

// Wrapper structures for ssl-platform contexts  
typedef struct palAes{
    ssl_platform_aes_context_t ssl_ctx;        // Use ssl-platform context
    unsigned char stream_block[PAL_CRYPT_BLOCK_SIZE];  //The saved stream-block for resuming. Is overwritten by the function.
    size_t nc_off;   //The offset in the current stream_block
}palAes_t;

typedef struct palCtrDrbgCtx{
    ssl_platform_ctr_drbg_context_t ssl_ctx;  // Use ssl-platform context
}palCtrDrbgCtx_t;

typedef struct palX509Ctx{
    ssl_platform_x509_crt_t ssl_crt;  // Use ssl-platform context
}palX509Ctx_t;


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
typedef struct palMD{
    ssl_platform_hash_context_t ssl_hash;  // Use ssl-platform context
} palMD_t;

#else

typedef struct palMD {
    psa_hash_operation_t md;
    psa_algorithm_t alg;
} palMD_t;

#endif

// Forward declarations for entropy functions
static int pal_plat_entropySource( void *data, unsigned char *output, size_t len);
static int pal_plat_entropySourceDRBG( void *data, unsigned char *output, size_t len);

// Forward declarations for stub functions
// Forward declarations for helper functions
static palStatus_t pal_plat_x509CertGetID(palX509Ctx_t* x509Cert, uint8_t *id, size_t outLenBytes, size_t* actualOutLenBytes);
static palStatus_t pal_plat_X509GetField(palX509Ctx_t* x509Ctx, const char* fieldName, void* output, size_t outLenBytes, size_t* actualOutLenBytes);

#define CRYPTO_PLAT_SUCCESS 0
#define CRYPTO_PLAT_GENERIC_ERROR (-1)

palStatus_t pal_plat_initCrypto()
{
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_cleanupCrypto()
{
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_initAes(palAesHandle_t *aes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palAes_t* localCtx = NULL;

    localCtx = (palAes_t*)malloc(sizeof(palAes_t));
    if (NULL == localCtx)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
    }
    else
    {
        ssl_platform_aes_init(&localCtx->ssl_ctx);
        memset(localCtx->stream_block, 0x00, PAL_CRYPT_BLOCK_SIZE);
        localCtx->nc_off = 0;
        *aes = (palAesHandle_t)localCtx;
    }

    return status;
}

palStatus_t pal_plat_freeAes(palAesHandle_t *aes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palAes_t* localCtx = NULL;

    localCtx = (palAes_t*)*aes;
    ssl_platform_aes_free(&localCtx->ssl_ctx);
    free(localCtx);
    *aes = NULLPTR;
    return status;
}

palStatus_t pal_plat_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palAes_t* localCtx = NULL;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    localCtx = (palAes_t*)aes;
    if (PAL_AES_ENCRYPT == keyTarget)
    {
        platStatus = ssl_platform_aes_setkey_enc(&localCtx->ssl_ctx, key, keybits);
    }
    else
    {
        platStatus = ssl_platform_aes_setkey_dec(&localCtx->ssl_ctx, key, keybits);
    }

    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_AES_INVALID_KEY_LENGTH;
    }

    return status;
}

palStatus_t pal_plat_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16], bool zeroOffset)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;

    if (zeroOffset)
    {
        localCtx->nc_off = 0;
        memset(localCtx->stream_block, 0, PAL_CRYPT_BLOCK_SIZE);
    }

    // Use ssl-platform AES CTR function with the ssl_ctx member
    platStatus = ssl_platform_aes_crypt_ctr(&localCtx->ssl_ctx, inLen, &localCtx->nc_off, iv, localCtx->stream_block, input, output);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        FCC_PAL_LOG_ERR("Crypto aes ctr status %" PRId32 "", platStatus);
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;

    platStatus = ssl_platform_aes_crypt_ecb(&localCtx->ssl_ctx, (PAL_AES_ENCRYPT == mode ? SSL_PLATFORM_AES_ENCRYPT : SSL_PLATFORM_AES_DECRYPT), input, output);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        FCC_PAL_LOG_ERR("Crypto aes ecb status  %" PRId32 "", platStatus);
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_sha256(const unsigned char* input, size_t inLen, unsigned char* output)
{    
    palStatus_t status = FCC_PAL_SUCCESS;
    ssl_platform_hash_context_t hash_ctx;
    int ret;

    ret = ssl_platform_hash_init(&hash_ctx, SSL_PLATFORM_HASH_SHA256);
    if (ret != SSL_PLATFORM_SUCCESS) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }

    ret = ssl_platform_hash_starts(&hash_ctx);
    if (ret != SSL_PLATFORM_SUCCESS) {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
        goto cleanup;
    }

    ret = ssl_platform_hash_update(&hash_ctx, input, inLen);
    if (ret != SSL_PLATFORM_SUCCESS) {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
        goto cleanup;
    }

    ret = ssl_platform_hash_finish(&hash_ctx, output);
    if (ret != SSL_PLATFORM_SUCCESS) {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
        goto cleanup;
    }

cleanup:
    ssl_platform_hash_free(&hash_ctx);
    return status;
}
#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_x509Initiate(palX509Handle_t* x509)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = NULL;

    localCtx = (palX509Ctx_t*)malloc(sizeof(palX509Ctx_t));
    if (NULL == localCtx)
    {
        status = FCC_PAL_ERR_CREATION_FAILED;
    }
    else
    {
        ssl_platform_x509_crt_init(&localCtx->ssl_crt);
        *x509 = (uintptr_t)localCtx;
    }

    return status;
}

palStatus_t pal_plat_x509CertParse(palX509Handle_t x509, const unsigned char* input, size_t inLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = NULL;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;

    localCtx = (palX509Ctx_t*)x509;
    
    platStatus = ssl_platform_x509_crt_parse(&localCtx->ssl_crt, input, inLen);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_X509_CERT_VERIFY_FAILED;
        goto finish;
    }

finish:
    return status;
}

// Duplicate function removed - already implemented above

// Helper functions that were accidentally removed
static palStatus_t pal_plat_x509CertGetID(palX509Ctx_t* x509Cert, uint8_t *id, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    unsigned char *cert_der = NULL;
    size_t cert_der_len = 0;
    unsigned char hash[32]; // SHA-256 hash size
    
    if (!x509Cert || !id || !actualOutLenBytes) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    
    // Get the raw DER data of the certificate
    if (ssl_platform_x509_get_tbs(&x509Cert->ssl_crt, &cert_der, &cert_der_len) != SSL_PLATFORM_SUCCESS) {
        return FCC_PAL_ERR_X509_UNKNOWN_OID;
    }
    
    // Compute SHA-256 hash of the certificate DER data
    status = pal_plat_sha256(cert_der, cert_der_len, hash);
    if (status != FCC_PAL_SUCCESS) {
        return status;
    }
    
    // Copy the hash to the output buffer (32 bytes + null terminator = 33 bytes)
    if (outLenBytes < PAL_CERT_ID_SIZE) {
        *actualOutLenBytes = PAL_CERT_ID_SIZE;
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    
    memcpy(id, hash, 32);
    id[32] = '\0'; // Null terminator
    *actualOutLenBytes = PAL_CERT_ID_SIZE;
    
    return FCC_PAL_SUCCESS;
}

static palStatus_t pal_plat_X509GetField(palX509Ctx_t* x509Ctx, const char* fieldName, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    
    if (strcmp(fieldName, "CN") == 0 || strcmp(fieldName, "L") == 0 || strcmp(fieldName, "OU") == 0) {
        // Get the full subject name and parse the requested field
        char subject_name[256];
        platStatus = ssl_platform_x509_get_subject_name(&x509Ctx->ssl_crt, subject_name, sizeof(subject_name));
        if (platStatus != SSL_PLATFORM_SUCCESS) {
            return FCC_PAL_ERR_GENERIC_FAILURE;
        }
        
        // Parse the subject name to find the requested field
        // Subject name format: "CN=device123,L=Helsinki,O=ARM"
        char field_prefix[8];
        snprintf(field_prefix, sizeof(field_prefix), "%s=", fieldName);
        
        char* field_start = strstr(subject_name, field_prefix);
        if (field_start == NULL) {
            return FCC_PAL_ERR_INVALID_X509_ATTR;
        }
        
        // Move past the field name and '='
        field_start += strlen(field_prefix);
        
        // Find the end of the field value (next comma or end of string)
        char* field_end = strchr(field_start, ',');
        size_t field_len;
        if (field_end != NULL) {
            field_len = field_end - field_start;
        } else {
            field_len = strlen(field_start);
        }
        
        // Check if output buffer is large enough
        if (field_len >= outLenBytes) {
            *actualOutLenBytes = field_len + 1; // +1 for null terminator
            return FCC_PAL_ERR_BUFFER_TOO_SMALL;
        }
        
        // Copy the field value and null-terminate
        memcpy(output, field_start, field_len);
        ((char*)output)[field_len] = '\0';
        *actualOutLenBytes = field_len + 1;
        
        status = FCC_PAL_SUCCESS;
    } else {
        status = FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
    }
    
    return status;
}

static bool pal_isLeapYear(uint16_t year)
{
    bool result = false;
    if (year % 4 != 0)
    {
        result = false;
    }
    else if ((year % 100) != 0)
    {
        result = true;
    } 
    else
    {
        result = ((year % 400) == 0);
    }
    return result;
}

static palStatus_t pal_timegm( struct tm *tm, uint64_t* outTime) 
{
    uint64_t epoc = 0;
    uint8_t palMonthDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (NULL == outTime || NULL == tm || tm->tm_year < 1970 || tm->tm_mon > 12)
    {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    for (uint16_t y = 1970; y < tm->tm_year; ++y)
    {
        if (pal_isLeapYear(y))
        {
            epoc += 366 * FCC_PAL_SECONDS_PER_DAY;
        }
        else
        {
            epoc += 365 * FCC_PAL_SECONDS_PER_DAY;
        }      
    }
    
    for (uint8_t m = 1; m < tm->tm_mon; ++m) 
    {
        epoc += (uint64_t)(palMonthDays[m - 1]) * FCC_PAL_SECONDS_PER_DAY;
        if (m == FCC_PAL_FEB_MONTH && pal_isLeapYear((uint16_t)tm->tm_year))
        {
            epoc += FCC_PAL_SECONDS_PER_DAY;
        }
    }

    epoc += (uint64_t)(tm->tm_mday - 1) * FCC_PAL_SECONDS_PER_DAY;
    epoc += (uint64_t)tm->tm_hour * FCC_PAL_SECONDS_PER_HOUR;
    epoc += (uint64_t)tm->tm_min * FCC_PAL_SECONDS_PER_MIN;
    epoc += (uint64_t)tm->tm_sec;
    *outTime = epoc;
    return FCC_PAL_SUCCESS;
}
#endif

palStatus_t pal_plat_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509Cert;
    unsigned char *buf_ptr;
    size_t buf_len;
    struct tm not_before, not_after;
    
    *actualOutLenBytes = 0;

    switch(attr)
    {
        case PAL_X509_ISSUER_ATTR:
            if (ssl_platform_x509_get_issuer_raw(&localCtx->ssl_crt, &buf_ptr, &buf_len) != SSL_PLATFORM_SUCCESS) {
                status = FCC_PAL_ERR_X509_UNKNOWN_OID;
                break;
            }
            if (buf_len <= outLenBytes) {
                memcpy(output, buf_ptr, buf_len);
            } else {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
            }
            *actualOutLenBytes = buf_len;
            break;

        case PAL_X509_SUBJECT_ATTR:
            if (ssl_platform_x509_get_subject_raw(&localCtx->ssl_crt, &buf_ptr, &buf_len) != SSL_PLATFORM_SUCCESS) {
                status = FCC_PAL_ERR_X509_UNKNOWN_OID;
                break;
            }
            if (buf_len <= outLenBytes) {
                memcpy(output, buf_ptr, buf_len);
            } else {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
            }
            *actualOutLenBytes = buf_len;
            break;

        case PAL_X509_VALID_FROM:
            if (ssl_platform_x509_get_validity(&localCtx->ssl_crt, &not_before, &not_after) != SSL_PLATFORM_SUCCESS) {
                status = FCC_PAL_ERR_X509_UNKNOWN_OID;
                break;
            }
            if (PAL_CRYPTO_CERT_DATE_LENGTH > outLenBytes) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
            } else {
                uint64_t timeOfDay;
                status = pal_timegm(&not_before, &timeOfDay);
                if (FCC_PAL_SUCCESS == status) {
                    memcpy(output, &timeOfDay, PAL_CRYPTO_CERT_DATE_LENGTH);
                }
            }
            *actualOutLenBytes = PAL_CRYPTO_CERT_DATE_LENGTH;
            break;

        case PAL_X509_VALID_TO:
            if (ssl_platform_x509_get_validity(&localCtx->ssl_crt, &not_before, &not_after) != SSL_PLATFORM_SUCCESS) {
                status = FCC_PAL_ERR_X509_UNKNOWN_OID;
                break;
            }
            if (PAL_CRYPTO_CERT_DATE_LENGTH > outLenBytes) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
            } else {
                uint64_t timeOfDay;
                status = pal_timegm(&not_after, &timeOfDay);
                if (FCC_PAL_SUCCESS == status) {
                    memcpy(output, &timeOfDay, PAL_CRYPTO_CERT_DATE_LENGTH);
                }
            }
            *actualOutLenBytes = PAL_CRYPTO_CERT_DATE_LENGTH;
            break;
        
        case PAL_X509_CN_ATTR:
            status = pal_plat_X509GetField(localCtx, "CN", output, outLenBytes, actualOutLenBytes);
            break; 

        case PAL_X509_L_ATTR:
            status = pal_plat_X509GetField(localCtx, "L", output, outLenBytes, actualOutLenBytes);
            break;

        case PAL_X509_OU_ATTR:
            status = pal_plat_X509GetField(localCtx, "OU", output, outLenBytes, actualOutLenBytes);
            break;
        
        case PAL_X509_CERT_ID_ATTR:
            if (PAL_CERT_ID_SIZE > outLenBytes) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = PAL_CERT_ID_SIZE;
            } else {
                status = pal_plat_x509CertGetID(localCtx, output, outLenBytes, actualOutLenBytes);
            }
            break;

        case PAL_X509_SIGNATUR_ATTR:
            if (ssl_platform_x509_get_signature(&localCtx->ssl_crt, &buf_ptr, &buf_len) != SSL_PLATFORM_SUCCESS) {
                status = FCC_PAL_ERR_X509_UNKNOWN_OID;
                break;
            }
            if (buf_len > outLenBytes) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
            } else {
                memcpy(output, buf_ptr, buf_len);
            }
            *actualOutLenBytes = buf_len;
            break;

        default:
           status = FCC_PAL_ERR_INVALID_X509_ATTR;
    }
    return status;
}

static const mbedtls_x509_crt_profile s_PALProfile =
{
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) | MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ),
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECKEY ) | MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECDSA ),
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ),
    0x7FFFFFFF // RSA not allowed
};

palStatus_t pal_plat_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCert = (palX509Ctx_t*)x509Cert;
    palX509Ctx_t* localCAChain = (palX509Ctx_t*)x509CertChain;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    uint32_t flags = 0;
    *verifyResult = 0;

    // TODO: Use ssl_platform_x509_crt_verify_with_profile() when implemented
    return FCC_PAL_ERR_NOT_SUPPORTED_CURVE; // Temporary - certificate verification not yet implemented

    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_X509_CERT_VERIFY_FAILED;
        //! please DO NOT change errors order
        if (MBEDTLS_X509_BADCERT_NOT_TRUSTED & flags)
        {
            *verifyResult |= FCC_PAL_ERR_X509_BADCERT_NOT_TRUSTED;
            status = FCC_PAL_ERR_X509_BADCERT_NOT_TRUSTED;
        }
        if (MBEDTLS_X509_BADCERT_BAD_KEY & flags)
        {
            *verifyResult |= FCC_PAL_ERR_X509_BADCERT_BAD_KEY;
            status = FCC_PAL_ERR_X509_BADCERT_BAD_KEY;
        }
        if (MBEDTLS_X509_BADCERT_BAD_PK & flags)
        {
            *verifyResult |= FCC_PAL_ERR_X509_BADCERT_BAD_PK;
            status = FCC_PAL_ERR_X509_BADCERT_BAD_PK;
        }
        if (MBEDTLS_X509_BADCERT_BAD_MD & flags)
        {
            *verifyResult |= FCC_PAL_ERR_X509_BADCERT_BAD_MD;
            status = FCC_PAL_ERR_X509_BADCERT_BAD_MD;
        }
        if (MBEDTLS_X509_BADCERT_FUTURE & flags)
        {
            *verifyResult |= FCC_PAL_ERR_X509_BADCERT_FUTURE;
            status = FCC_PAL_ERR_X509_BADCERT_FUTURE;
        }
        if (MBEDTLS_X509_BADCERT_EXPIRED & flags)
        {
            *verifyResult |= FCC_PAL_ERR_X509_BADCERT_EXPIRED;
            status = FCC_PAL_ERR_X509_BADCERT_EXPIRED;
        }
    }

    return status;
}

palStatus_t pal_plat_x509CertCheckExtendedKeyUsage(palX509Handle_t x509Cert, palExtKeyUsage_t usage)
{
    palX509Ctx_t *localCert = (palX509Ctx_t*)x509Cert;
    const char *oid = NULL;
    size_t oid_size;
    int ret;

    switch (usage) {
        case PAL_X509_EXT_KU_ANY:
            oid = MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE);
            break;
        case PAL_X509_EXT_KU_SERVER_AUTH:
            oid = MBEDTLS_OID_SERVER_AUTH;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
            break;
        case PAL_X509_EXT_KU_CLIENT_AUTH:
            oid = MBEDTLS_OID_CLIENT_AUTH;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH);
            break;
        case PAL_X509_EXT_KU_CODE_SIGNING:
            oid = MBEDTLS_OID_CODE_SIGNING;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_CODE_SIGNING);
            break;
        case PAL_X509_EXT_KU_EMAIL_PROTECTION:
            oid = MBEDTLS_OID_EMAIL_PROTECTION;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_EMAIL_PROTECTION);
            break;
        case PAL_X509_EXT_KU_TIME_STAMPING:
            oid = MBEDTLS_OID_TIME_STAMPING;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_TIME_STAMPING);
            break;
        case PAL_X509_EXT_KU_OCSP_SIGNING:
            oid = MBEDTLS_OID_OCSP_SIGNING;
            oid_size = MBEDTLS_OID_SIZE(MBEDTLS_OID_OCSP_SIGNING);
            break;
        default:
            return FCC_PAL_ERR_X509_UNKNOWN_OID;
    }

    // Use ssl_platform_x509_crt_check_extended_key_usage() 
    ret = ssl_platform_x509_crt_check_extended_key_usage(&localCert->ssl_crt, 
                                                        (const unsigned char *)oid, 
                                                        oid_size);
    if (ret != SSL_PLATFORM_SUCCESS) {
        return FCC_PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED;
    }

    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_x509Free(palX509Handle_t* x509)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = NULL;

    localCtx = (palX509Ctx_t*)*x509;
    ssl_platform_x509_crt_free(&localCtx->ssl_crt);
    free(localCtx);
    *x509 = NULLPTR;
    return status;
}

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palMD_t* localCtx = NULL;
    ssl_platform_hash_type_t ssl_hash_type;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;

    localCtx = (palMD_t*)malloc(sizeof(palMD_t));
    if (NULL == localCtx)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
        goto finish;
    }

    // Convert PAL hash type to ssl-platform hash type
    switch (mdType)
    {
        case PAL_SHA256:
            ssl_hash_type = SSL_PLATFORM_HASH_SHA256;
            break;
        default:
            status = FCC_PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    platStatus = ssl_platform_hash_init(&localCtx->ssl_hash, ssl_hash_type);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }

    platStatus = ssl_platform_hash_starts(&localCtx->ssl_hash);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }

    *md = (palMDHandle_t)localCtx;

finish:
    if (FCC_PAL_SUCCESS != status && NULL != localCtx)
    {
        free(localCtx);
    }
    return status;
}

palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    platStatus = ssl_platform_hash_update(&localCtx->ssl_hash, input, inLen);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }

    return status;
}

palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    // For SHA-256, output size is always 32 bytes
    // ssl-platform should provide ssl_platform_hash_get_size() function
    *bufferSize = 32; // SHA-256 output size

    return status;
}

palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    platStatus = ssl_platform_hash_finish(&localCtx->ssl_hash, output);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }

    return status;
}

palStatus_t pal_plat_mdFree(palMDHandle_t* md)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palMD_t* localCtx = NULL;

    localCtx = (palMD_t*)*md;
    ssl_platform_hash_free(&localCtx->ssl_hash);
    free(localCtx);
    *md = NULLPTR;
    return status;
}
#else //!MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

static palStatus_t palToPsaMdType(palMDType_t palMdType, psa_algorithm_t *psaAlg)
{
    switch (palMdType)
    {
        case PAL_SHA256:
            *psaAlg = PSA_ALG_SHA_256;
            return FCC_PAL_SUCCESS;    
        default:
            return FCC_PAL_ERR_INVALID_MD_TYPE;
    }
}

palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    palStatus_t palStatus = FCC_PAL_SUCCESS;
    psa_status_t status = PSA_SUCCESS;
    psa_algorithm_t alg = 0;
    palMD_t* localCtx = NULL;

    palStatus = palToPsaMdType(mdType, &alg);
    if (FCC_PAL_SUCCESS != palStatus)
    {
        return palStatus;
    }

    localCtx = (palMD_t*)malloc(sizeof(palMD_t));
    if (NULL == localCtx)
    {
        return FCC_PAL_ERR_CREATION_FAILED;
    }

    memset(localCtx, 0, sizeof(palMD_t));

    status = psa_hash_setup(&localCtx->md, alg);
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }

    localCtx->alg = alg;

    *md = (uintptr_t)localCtx;

finish:
    if (FCC_PAL_SUCCESS != palStatus)
    {
        free(localCtx);
    }
    return palStatus;
}

palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    psa_status_t status = PSA_SUCCESS;
    palStatus_t palStatus = FCC_PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    status = psa_hash_update(&localCtx->md, input, inLen);
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_GENERIC_FAILURE;
    }

    return palStatus;
}


palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    palMD_t* localCtx = (palMD_t*)md;
    
    *bufferSize = PSA_HASH_SIZE(localCtx->alg);
    if (0 == *bufferSize)
    {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    } 
    else
    {
        return FCC_PAL_SUCCESS;
    }
}

palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output)
{
    psa_status_t status = PSA_SUCCESS;
    palStatus_t palStatus = FCC_PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;
    size_t outputSize; // Size is determined by md when it was initialized, user should know it
    size_t bufSize;

    palStatus = pal_plat_mdGetOutputSize(md, &bufSize);
    if (FCC_PAL_SUCCESS != palStatus)
    {
        return palStatus;
    }

    status = psa_hash_finish(&localCtx->md, output, bufSize, &outputSize);
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_GENERIC_FAILURE;
    }

    return palStatus;
}

palStatus_t pal_plat_mdFree(palMDHandle_t* md)
{
    palMD_t* localCtx = (palMD_t*)*md;

    localCtx = (palMD_t*)*md;

    // Disragard psa_hash_abort() return value - not much we can do with it
    (void)psa_hash_abort(&localCtx->md);
    free(localCtx);
    *md = NULLPTR;
    return FCC_PAL_SUCCESS;
}

#endif //!MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509;
    ssl_platform_pk_context_t pk_ctx;
    ssl_platform_hash_type_t ssl_hash_type;

    // Convert PAL hash type to ssl-platform hash type
    switch (mdType)
    {
        case PAL_SHA256:
            ssl_hash_type = SSL_PLATFORM_HASH_SHA256;
            break;
        default:
            return FCC_PAL_ERR_INVALID_MD_TYPE;
    }

    // Extract public key from certificate
    ssl_platform_pk_init(&pk_ctx);
    platStatus = ssl_platform_x509_get_pubkey(&localCtx->ssl_crt, &pk_ctx);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_CERT_PARSING_FAILED;
        goto cleanup;
    }

    // Verify signature
    platStatus = ssl_platform_pk_verify(&pk_ctx, ssl_hash_type, hash, hashLen, sig, sigLen);
    if (SSL_PLATFORM_SUCCESS == platStatus)
    {
        status = FCC_PAL_SUCCESS;
    }
    else if (platStatus == SSL_PLATFORM_ERROR_MEMORY_ALLOCATION)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
    }
    else
    {
        status = FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
    }

cleanup:
    ssl_platform_pk_free(&pk_ctx);
    return status;
}
#endif 

palStatus_t pal_plat_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag )
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    int platTag = 0;

    switch (tag & PAL_ASN1_CLASS_BITS) 
    {
        case 0x00:
            //MBEDTLS_ASN1_PRIMITIVE
            break;
        case PAL_ASN1_CONTEXT_SPECIFIC:
            platTag |= MBEDTLS_ASN1_CONTEXT_SPECIFIC;
            break;
        default:
            status = FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG;
            goto finish;
    }

    if (tag & PAL_ASN1_CONSTRUCTED)
    {
        platTag |= MBEDTLS_ASN1_CONSTRUCTED;
    }


    switch(tag & PAL_ASN1_TAG_BITS)
    {
    case PAL_ASN1_BOOLEAN:
        platTag |= MBEDTLS_ASN1_BOOLEAN;
        break;
    case PAL_ASN1_INTEGER:
        platTag |= MBEDTLS_ASN1_INTEGER;
            break;
    case PAL_ASN1_BIT_STRING:
        platTag |= MBEDTLS_ASN1_BIT_STRING;
            break;
    case PAL_ASN1_OCTET_STRING:
        platTag |= MBEDTLS_ASN1_OCTET_STRING;
                break;
    case PAL_ASN1_NULL:
        platTag |= MBEDTLS_ASN1_NULL;
                break;
    case PAL_ASN1_OID:
        platTag |= MBEDTLS_ASN1_OID;
                break;
    case PAL_ASN1_UTF8_STRING:
        platTag |= MBEDTLS_ASN1_UTF8_STRING;
                break;
    case PAL_ASN1_SEQUENCE:
        platTag |= MBEDTLS_ASN1_SEQUENCE;
                break;
    case PAL_ASN1_SET:
        platTag |= MBEDTLS_ASN1_SET;
                break;
    case PAL_ASN1_PRINTABLE_STRING:
        platTag |= MBEDTLS_ASN1_PRINTABLE_STRING;
                break;
    case PAL_ASN1_T61_STRING:
        platTag |= MBEDTLS_ASN1_T61_STRING;
                break;
    case PAL_ASN1_IA5_STRING:
        platTag |= MBEDTLS_ASN1_IA5_STRING;
                break;
    case PAL_ASN1_UTC_TIME:
        platTag |= MBEDTLS_ASN1_UTC_TIME;
                break;
    case PAL_ASN1_GENERALIZED_TIME:
        platTag |= MBEDTLS_ASN1_GENERALIZED_TIME;
                break;
    case PAL_ASN1_UNIVERSAL_STRING:
        platTag |= MBEDTLS_ASN1_UNIVERSAL_STRING;
                break;
    case PAL_ASN1_BMP_STRING:
        platTag |= MBEDTLS_ASN1_BMP_STRING;
                break;
    default:
        status = FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG;
        goto finish;
    }

    platStatus =  mbedtls_asn1_get_tag(position, end, len, platTag);
    if (platStatus < CRYPTO_PLAT_SUCCESS)
    {
        status = FCC_PAL_ERR_ASN1_UNEXPECTED_TAG;
    }
finish:
    return status;
}

palStatus_t pal_plat_CCMInit(palCCMHandle_t* ctx)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = NULL;

    ccmCtx = (palCCM_t*)malloc(sizeof(palCCM_t));
    if (NULL == ccmCtx)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
    }
    else
    {
        mbedtls_ccm_init(ccmCtx);
        *ctx = (palCCMHandle_t)ccmCtx;
    }

    return status;
}

palStatus_t pal_plat_CCMFree(palCCMHandle_t* ctx)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)*ctx;

    mbedtls_ccm_free(ccmCtx);
    free(ccmCtx);
    *ctx = NULLPTR;
    return status;
}

palStatus_t pal_plat_CCMSetKey(palCCMHandle_t ctx, palCipherID_t id, const unsigned char *key, unsigned int keybits)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;
    mbedtls_cipher_id_t mbedtls_cipher_id;

    switch (id) 
    {
        case PAL_CIPHER_ID_AES:
            mbedtls_cipher_id = MBEDTLS_CIPHER_ID_AES;
            break;
        default:
            return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    platStatus = mbedtls_ccm_setkey(ccmCtx, mbedtls_cipher_id, key, keybits);

    switch(platStatus)
    {
    case CRYPTO_PLAT_SUCCESS:
        status = FCC_PAL_SUCCESS;
        break;
    default:
        {
            FCC_PAL_LOG_ERR("Crypto ccm setkey status %" PRId32 "", platStatus);
            status = FCC_PAL_ERR_GENERIC_FAILURE;
        }
    }
    return status;
}

palStatus_t pal_plat_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* tag, size_t tagLen, unsigned char* output)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;

    platStatus = mbedtls_ccm_auth_decrypt(ccmCtx, inLen, iv, ivLen, add, addLen, input, output, tag, tagLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        switch(platStatus)
        {
        default:
            {
                FCC_PAL_LOG_ERR("Crypto ccm decrypt status %" PRId32 "", platStatus);
                status = FCC_PAL_ERR_GENERIC_FAILURE;
            }
        }
    }
    return status;
}

palStatus_t pal_plat_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* output, unsigned char* tag, size_t tagLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;

    platStatus = mbedtls_ccm_encrypt_and_tag(ccmCtx, inLen, iv, ivLen, add, addLen, input, output, tag, tagLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        switch(platStatus)
        {
        default:
            {
                FCC_PAL_LOG_ERR("Crypto ccm encrypt status %" PRId32 "", platStatus);
                status = FCC_PAL_ERR_GENERIC_FAILURE;
            }
        }
    }
    return status;
}

palStatus_t pal_plat_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = NULL;

    palCtrDrbgCtx = (palCtrDrbgCtx_t*)malloc(sizeof(palCtrDrbgCtx_t));
    if (NULL == palCtrDrbgCtx)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
    }
    else
    {
        /**
         * Clean buffer before initialization. Some platform implementations
         * does not handle mutex initialization correctly when buffers are
         * dirty.
         */
        memset(palCtrDrbgCtx, 0, sizeof(palCtrDrbgCtx_t));
        ssl_platform_ctr_drbg_init(&palCtrDrbgCtx->ssl_ctx);
        *ctx = (palCtrDrbgCtxHandle_t)palCtrDrbgCtx;
    }

    return status;
}

palStatus_t pal_plat_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)*ctx;

    ssl_platform_ctr_drbg_free(&palCtrDrbgCtx->ssl_ctx);
    free(palCtrDrbgCtx);
    *ctx = NULLPTR;

    return status;
}

palStatus_t pal_plat_CtrDRBGIsSeeded(palCtrDrbgCtxHandle_t ctx)
{
    // If using mbedtls with entropy sources, if the reseed_counter is 0 - this means seeding has not been done yet and generating a random number will not work
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)ctx;
    // If f_entropy is set, this means that mbedtls_ctr_drbg_seed() has been
    // called. Otherwise, the DRBG is not seeded yet.
    if (palCtrDrbgCtx->ssl_ctx.f_entropy != 0)
    {
        return FCC_PAL_SUCCESS;
    }
    else
    {
        return FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED;
    }
#else
    // If not using mbedtls with entropy sources, reseed_counter will always be 0 and seeding is done in a lazy fashion
    // so we return the not seeded error so when pal_plat_CtrDRBGSeedFromEntropySources() is called, we will seed with the mock
    // entropy function and context as necessary
    return FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED;
#endif
}

// FIXME: Currently not public in cs_pal_plat_crypto.h and is called from pal_plat_drbg_w_entropy_sources.c
// With a forward declaration
// This function will later be public, deprecating pal_plat_CtrDRBGSeed() (pal_plat_CtrDRBGInit will call this directly).
// Changing this requires some work - therefore not done yet
/**
 * If ctx is not seeded - seed it
 * If ctx is already seeded - reseed it
 */
palStatus_t pal_plat_CtrDRBGSeedFromEntropySources(palCtrDrbgCtxHandle_t ctx, int (*f_entropy)(void *, unsigned char *, size_t), const void* additionalData, size_t additionalDataLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)ctx;

    status = pal_CtrDRBGIsSeeded(ctx);
    if (status == FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED) // First call - DRBG not seeded yet
    {
        // TODO: Use ssl_platform_ctr_drbg_seed() when enhanced version is available
        platStatus = ssl_platform_ctr_drbg_seed(&palCtrDrbgCtx->ssl_ctx, f_entropy, NULL, additionalData, additionalDataLen);
    } 
    
    /*
     * DRBG already seeded, so function was invoked for reseeding -
     * perhaps storage was deleted and new entropy injected.
     * Note that entropy callback and context are already in palCtrDrbgCtx->ssl_ctx context
     */
    else if (status == FCC_PAL_SUCCESS)
    {
        // Use ssl_platform_ctr_drbg_reseed for reseeding
        platStatus = ssl_platform_ctr_drbg_reseed(&palCtrDrbgCtx->ssl_ctx, additionalData, additionalDataLen);
    }
    else
    {
        return FCC_PAL_ERR_GENERIC_FAILURE; 
    }
    
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            status = FCC_PAL_SUCCESS;
            break;
        case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
            status = FCC_PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
            break;
        default:
            {
                FCC_PAL_LOG_ERR("Crypto ctrdrbg seed status %" PRId32 "", platStatus);
                status = FCC_PAL_ERR_GENERIC_FAILURE;
            }
    }

    return status;
}

// FIXME: When pal_plat_CtrDRBGSeedFromEntropySources is public, this function should no longer be used
palStatus_t pal_plat_CtrDRBGSeed(palCtrDrbgCtxHandle_t ctx, const void* seed, size_t len)
{
    return pal_plat_CtrDRBGSeedFromEntropySources(ctx, pal_plat_entropySourceDRBG, seed, len);
}

palStatus_t pal_plat_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len)
{
    palStatus_t status = pal_plat_CtrDRBGGenerateWithAdditional(ctx, out, len, NULL, 0);
    return status;
}

palStatus_t pal_plat_CtrDRBGGenerateWithAdditional(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len, unsigned char* additional, size_t additionalLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)ctx;

    // Note: ssl-platform doesn't expose additional data parameter yet
    // This is a simplified implementation
    platStatus = ssl_platform_ctr_drbg_random(palCtrDrbgCtx, out, len);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

#if PAL_CMAC_SUPPORT
palStatus_t pal_plat_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;

    // Convert key length from bits to bytes for ssl_platform_aes_cmac
    size_t keyLenInBytes = keyLenInBits / 8;
    
    platStatus = ssl_platform_aes_cmac(key, keyLenInBytes, input, inputLenInBytes, output);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        FCC_PAL_LOG_ERR("Crypto cipher cmac status %" PRId32 "", platStatus);
        status = FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    }

    return status;
}

palStatus_t pal_plat_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCipherCtx_t* localCipher = NULL;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;
    ssl_platform_cipher_type_t platType = SSL_PLATFORM_CIPHER_AES_128_ECB;

    switch(cipherID)
    {
        case PAL_CIPHER_ID_AES:
            platType = SSL_PLATFORM_CIPHER_AES_128_ECB;
            break;
        default:
            status = FCC_PAL_ERR_INVALID_CIPHER_ID;
            goto finish;
    }

    localCipher = (palCipherCtx_t*)malloc(sizeof(palCipherCtx_t));
    if (NULL == localCipher)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
        goto finish;
    }

    ssl_platform_cipher_init(localCipher);
    platStatus = ssl_platform_cipher_setup(localCipher, platType);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        FCC_PAL_LOG_ERR("Crypto cmac cipher setup status %" PRId32 ".", platStatus);
        status = FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
        goto finish;
    }

    platStatus = ssl_platform_cipher_cmac_starts(localCipher, key, keyLenBits);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_CMAC_START_FAILED;
        goto finish;
    }

    *ctx = (palCMACHandle_t)localCipher;
finish:
    if (FCC_PAL_SUCCESS != status && NULL != localCipher)
    {
        free(localCipher);
    }
    return status;
}

palStatus_t pal_plat_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCipherCtx_t* localCipher = (palCipherCtx_t*)ctx;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;

    platStatus = ssl_platform_cipher_cmac_update(localCipher, input, inLen);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_CMAC_UPDATE_FAILED;
    }

    return status;
}

palStatus_t pal_plat_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCipherCtx_t* localCipher = (palCipherCtx_t*)*ctx;
    int32_t platStatus = SSL_PLATFORM_SUCCESS;

    platStatus = ssl_platform_cipher_cmac_finish(localCipher, output);
    if (SSL_PLATFORM_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_CMAC_FINISH_FAILED;
    }
    else
    {
        *outLen = 16; // AES block size for CMAC output
    }

    ssl_platform_cipher_free(localCipher);
    free(localCipher);
    *ctx = NULLPTR;
    return status;
}
#endif //PAL_CMAC_SUPPORT
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_plat_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes)
{
    const mbedtls_md_info_t *md_info = NULL;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palStatus_t status = FCC_PAL_SUCCESS;

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (NULL == md_info)
    {
        FCC_PAL_LOG_ERR("Crypto hmac sha256 md info error");
        status = FCC_PAL_ERR_HMAC_GENERIC_FAILURE;
    }

    if (FCC_PAL_SUCCESS == status)
    {
        platStatus = mbedtls_md_hmac(md_info, key, keyLenInBytes, input, inputLenInBytes, output);
        if (platStatus != CRYPTO_PLAT_SUCCESS)
        {
            if (platStatus == MBEDTLS_ERR_MD_BAD_INPUT_DATA)
            {
                status = FCC_PAL_ERR_MD_BAD_INPUT_DATA;
            }
            else
            {
                FCC_PAL_LOG_ERR("Crypto hmac status %" PRId32 "", platStatus);
                status = FCC_PAL_ERR_HMAC_GENERIC_FAILURE;
            }
        }
    }

    if ((NULL != outputLenInBytes) && (FCC_PAL_SUCCESS == status))
    {
        *outputLenInBytes = (size_t)mbedtls_md_get_size(md_info);
    }

    return status;
}
#else
palStatus_t pal_plat_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes)
{
    palStatus_t palStatus = FCC_PAL_SUCCESS;
    psa_status_t status = PSA_SUCCESS;
    psa_key_handle_t keyHandle = 0;
    psa_key_attributes_t psa_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation = { 0 };
    size_t outLen = 0;

    // set key type
    psa_set_key_type(&psa_key_attr, PSA_KEY_TYPE_HMAC);
    // set key usage
    psa_set_key_usage_flags(&psa_key_attr, PSA_KEY_USAGE_SIGN);
    // set key algorithm
    psa_set_key_algorithm(&psa_key_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    // Import the key to PSA
    status = psa_import_key(&psa_key_attr, key, keyLenInBytes, &keyHandle);
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }

    /* FIXME - replace psa_mac_xxx calls below with one call to psa_mac_compute when it will be supported IOTCRYPT-881 */

    // Setup MAC sign process
    status = psa_mac_sign_setup(&operation, keyHandle, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_HMAC_GENERIC_FAILURE;
        goto finish;
    }

    status = psa_mac_update(&operation, input, inputLenInBytes);
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_HMAC_GENERIC_FAILURE;
        goto finish;
    }

    status = psa_mac_sign_finish(&operation, output, PAL_SHA256_SIZE, &outLen);
    if (PSA_SUCCESS != status)
    {
        palStatus = FCC_PAL_ERR_HMAC_GENERIC_FAILURE;
        goto finish;
    }

    // outputLenInBytes is optional and may be NULL
    if (outputLenInBytes)
    {
        *outputLenInBytes = outLen;
    }

finish:

    if (keyHandle)
    {
        // Nothing we can do if error occurs, so disregard the return value
        (void)psa_destroy_key(keyHandle);
    }
    return palStatus;
}

#endif
//! Check EC private key function. 
static palStatus_t pal_plat_ECCheckPrivateKey(palECGroup_t* ecpGroup, palECKeyHandle_t key, bool *verified)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* privateKey = (palECKey_t*)key;
    mbedtls_mpi* prvMP = NULL;
    mbedtls_pk_context *prv_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(privateKey);
    if(NULL == (mbedtls_ecp_keypair*)prv_mbedtls_ctx->pk_ctx)
    {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    prvMP = &((mbedtls_ecp_keypair*)prv_mbedtls_ctx->pk_ctx)->d;

    platStatus =  mbedtls_ecp_check_privkey(ecpGroup, prvMP);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_PRIVATE_KEY_VARIFICATION_FAILED;
    }
    else
    {
        *verified = true;
    }
    
    return status;
}

//! Check EC public key function.
static palStatus_t pal_plat_ECCheckPublicKey(palECGroup_t* ecpGroup, palECKeyHandle_t key, bool *verified)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* publicKey = (palECKey_t*)key;
    mbedtls_ecp_point* pubPoint = NULL;
    mbedtls_pk_context *pub_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(publicKey);
    if(NULL == (mbedtls_ecp_keypair*)pub_mbedtls_ctx->pk_ctx)
    {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    pubPoint = &((mbedtls_ecp_keypair*)pub_mbedtls_ctx->pk_ctx)->Q;

    platStatus =  mbedtls_ecp_check_pubkey(ecpGroup, pubPoint);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED;
    }
    else
    {
        *verified = true;
    }
    
    return status;
}

palStatus_t pal_plat_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palECGroup_t* ecpGroup = (palECGroup_t*)grp;

    *verified = false;

    if ((PAL_CHECK_PRIVATE_KEY & type) != 0)
    {
        status = pal_plat_ECCheckPrivateKey(ecpGroup, key, verified);
    }

    if ((FCC_PAL_SUCCESS == status) && ((PAL_CHECK_PUBLIC_KEY & type) != 0))
    {
        status = pal_plat_ECCheckPublicKey(ecpGroup, key, verified);
    }

    return status;
}


palStatus_t pal_plat_ECKeyNew(palECKeyHandle_t* key)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palECKey_t* localECKey = NULL;

    localECKey = (palECKey_t*)malloc(sizeof(palECKey_t));
    if (NULL == localECKey)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
    }
    else
    {
        ssl_platform_pk_init(localECKey);
        *key = (palECKeyHandle_t)localECKey;
    }
    
    return status;
}

palStatus_t pal_plat_ECKeyFree(palECKeyHandle_t* key)
{
    palECKey_t* localECKey = NULL;

    localECKey = (palECKey_t*)*key;
    ssl_platform_pk_free(localECKey);
    free(localECKey);
    *key = NULLPTR;
    return FCC_PAL_SUCCESS;
}


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

palStatus_t pal_plat_newKeyHandle( palKeyHandle_t *keyHandle, size_t keySize)
{

    palStatus_t palStatus = FCC_PAL_SUCCESS;

    //allocate palCryptoBuffer_t struct
    palCryptoBuffer_t* cryptoBuffer = (palCryptoBuffer_t*)malloc(sizeof(palCryptoBuffer_t));
    if (NULL == cryptoBuffer)
    {
        palStatus = FCC_PAL_ERR_NO_MEMORY;
        goto exit;
    }

    cryptoBuffer->buffer = NULL;
    cryptoBuffer->size = 0;

    //allocate buffer for the key
    cryptoBuffer->buffer = malloc(keySize);
    if (NULL == cryptoBuffer->buffer)
    {
        palStatus = FCC_PAL_ERR_NO_MEMORY;
        goto free_and_exit;
    }

    cryptoBuffer->size = (uint32_t)keySize;

    //init handle with pal_key_buffer address
    *keyHandle = (palKeyHandle_t)cryptoBuffer;

    goto exit;

free_and_exit:
    pal_plat_freeKeyHandle((palKeyHandle_t*)&cryptoBuffer);

exit:
    return palStatus;
}

palStatus_t pal_plat_freeKeyHandle( palKeyHandle_t *keyHandle)
{

    palCryptoBuffer_t* cryptoBuffer = (palCryptoBuffer_t*)*keyHandle;

    // free buffer
    if (cryptoBuffer->buffer != NULL) {
        free(cryptoBuffer->buffer);
    }

    //free struct
    free(cryptoBuffer);
    *keyHandle = 0;

    return FCC_PAL_SUCCESS;
}


#else //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

palStatus_t pal_plat_newKeyHandle( palKeyHandle_t *keyHandle, size_t keySize)
{
   *keyHandle = 0; 
   PV_UNUSED_PARAM(keySize);
   return FCC_PAL_SUCCESS;
}


palStatus_t pal_plat_freeKeyHandle( palKeyHandle_t *keyHandle)
{
    *keyHandle = 0; 
    return FCC_PAL_SUCCESS;
}

#endif


//! Check if the given data is a valid PEM format or not by checking the
//! the header and the footer of the data.
static bool pal_plat_isPEM(const unsigned char* key, size_t keyLen)
{
    bool result = false;
    const unsigned char *s1 = NULL;
    const unsigned char *s2 = NULL;

    PV_UNUSED_PARAM(keyLen);

    s1 = (unsigned char *) strstr( (const char *) key, "-----BEGIN ");
    if (NULL != s1)
    {
        result = true;
    }
    else
    {
        s2 = (unsigned char *) strstr( (const char *) key, "-----END " );
        if (NULL != s2)
        {
            result = true;
        }
    }

    return result;
}

static palStatus_t pal_plat_pkMbedtlsToPalError(int32_t platStatus)
{
    palStatus_t status = FCC_PAL_SUCCESS;

    switch (platStatus)
    {
    case CRYPTO_PLAT_SUCCESS:
        break;
    case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
        status = FCC_PAL_ERR_PK_UNKNOWN_PK_ALG;
        break;
    case MBEDTLS_ERR_PK_KEY_INVALID_VERSION:
        status = FCC_PAL_ERR_PK_KEY_INVALID_VERSION;
        break;
    case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
        status = FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
        break;
    case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
    case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + MBEDTLS_ERR_ASN1_OUT_OF_DATA: //It is done to parse status of mbedtls_pk_parse_public_key()
        status = FCC_PAL_ERR_PK_KEY_INVALID_FORMAT;
        break;
    case MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH: //This is how mbedTLS returns erros for this function
        status = FCC_PAL_ERR_PK_INVALID_PUBKEY_AND_ASN1_LEN_MISMATCH;
        break;
    case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
        status = FCC_PAL_ERR_PK_PASSWORD_REQUIRED;
        break;
    case MBEDTLS_ERR_ECP_INVALID_KEY:
        status = FCC_PAL_ERR_ECP_INVALID_KEY;
        break;
    default:
        status = FCC_PAL_ERR_CRYPTO_ERROR_BASE;
    }
    return status;

}
palStatus_t pal_plat_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key)
{
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;
    palStatus_t status = FCC_PAL_SUCCESS;

    if(pal_plat_isPEM(prvDERKey, keyLen))
    {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    platStatus = ssl_platform_pk_parse_key(localECKey, prvDERKey, keyLen, NULL, 0);

    status = pal_plat_pkMbedtlsToPalError(platStatus);

    if (status == FCC_PAL_ERR_CRYPTO_ERROR_BASE) {
        return FCC_PAL_ERR_PARSING_PRIVATE_KEY;
    }
    return status;
}
palStatus_t pal_plat_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key)
{
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;
    palStatus_t status = FCC_PAL_SUCCESS;

    if (pal_plat_isPEM(pubDERKey, keyLen))
    {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    platStatus = ssl_platform_pk_parse_public_key(localECKey, pubDERKey, keyLen);

    status = pal_plat_pkMbedtlsToPalError(platStatus);

    if (status == FCC_PAL_ERR_CRYPTO_ERROR_BASE) {
        return FCC_PAL_ERR_PARSING_PUBLIC_KEY;
    }
    return status;
}

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_plat_parseECPrivateKeyFromHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    psa_key_handle_t psaHandle = (psa_key_handle_t)prvKeyHandle;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)ECKeyHandle;

    platStatus = mbedtls_pk_setup_opaque(localECKey, psaHandle);

    return pal_plat_pkMbedtlsToPalError(platStatus);
}

static palStatus_t pal_plat_convertPublicRawKeyToDer(const uint8_t *rawKey, size_t rawKeyLength, uint8_t *derKeyDataOut, size_t derKeyDataMaxSize, size_t *derKeyDataActSizeOut)
{
    palStatus_t palStatus = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKeyHandle_t keyECHandle = NULLPTR;
    mbedtls_pk_context* localECKey;
    mbedtls_ecp_keypair *ecpKeyPair;

    //Create new key handler
    palStatus = pal_plat_ECKeyNew(&keyECHandle);
    if (palStatus != FCC_PAL_SUCCESS ) {
        return palStatus;
    }

    localECKey = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((ssl_platform_pk_context_t*)keyECHandle);

    platStatus = mbedtls_pk_setup(localECKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        palStatus = FCC_PAL_ERR_PARSING_PUBLIC_KEY;
        goto finish;
    }
    ecpKeyPair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    platStatus = mbedtls_ecp_group_load(&ecpKeyPair->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        palStatus = FCC_PAL_ERR_PARSING_PUBLIC_KEY;
        goto finish;
    }
    //Fill ecpKeyPair with raw public key data
    platStatus = mbedtls_ecp_point_read_binary(&ecpKeyPair->grp, &ecpKeyPair->Q, rawKey, rawKeyLength);
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        palStatus = FCC_PAL_ERR_PARSING_PUBLIC_KEY;
        goto finish;
    }

    palStatus = pal_writePublicKeyToDer(keyECHandle, derKeyDataOut, derKeyDataMaxSize, derKeyDataActSizeOut);
finish:
    //Free key handler
    (void)pal_plat_ECKeyFree(&keyECHandle);
    return palStatus;
}

palStatus_t pal_plat_parseECPublicKeyFromHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    psa_key_handle_t psaHandle = (psa_key_handle_t)pubKeyHandle;
    psa_status_t psa_status = PSA_SUCCESS;
    palStatus_t pal_status = FCC_PAL_SUCCESS;
    uint8_t rawPubKeyData[PAL_SECP256R1_MAX_PUB_KEY_RAW_SIZE] = { 0 };
    size_t actRawPubKeyDataSize = 0;
    uint8_t derPubKeyData[PAL_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE] = { 0 };
    size_t actDerPubKeyDataSize = 0;

    //Export public key
    psa_status = psa_export_public_key(psaHandle, rawPubKeyData, sizeof(rawPubKeyData), &actRawPubKeyDataSize);
    if (psa_status != PSA_SUCCESS || actRawPubKeyDataSize != PAL_SECP256R1_MAX_PUB_KEY_RAW_SIZE) {
        return FCC_PAL_ERR_PARSING_PUBLIC_KEY;
    }

    //Convert public raw key to DER format
    pal_status = pal_plat_convertPublicRawKeyToDer((const uint8_t *)rawPubKeyData, actRawPubKeyDataSize, derPubKeyData, sizeof(derPubKeyData), &actDerPubKeyDataSize);
    if (pal_status != FCC_PAL_SUCCESS || actDerPubKeyDataSize != PAL_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE) {
        return FCC_PAL_ERR_PARSING_PUBLIC_KEY;
    }

    //Parse the public key
    pal_status = pal_plat_parseECPublicKeyFromDER(derPubKeyData, actDerPubKeyDataSize, ECKeyHandle);
    return pal_status;
}
#else //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_plat_parseECPrivateKeyFromHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    palStatus_t status = FCC_PAL_SUCCESS;

    palCryptoBuffer_t* localkey = (palCryptoBuffer_t*) prvKeyHandle;

    status = pal_plat_parseECPrivateKeyFromDER(localkey->buffer, (size_t)localkey->size, ECKeyHandle);

    return status;
}

palStatus_t pal_plat_parseECPublicKeyFromHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    palStatus_t status = FCC_PAL_SUCCESS;

    palCryptoBuffer_t* localkey = (palCryptoBuffer_t*) pubKeyHandle;

    status = pal_plat_parseECPublicKeyFromDER(localkey->buffer, (size_t)localkey->size, ECKeyHandle);
    return status;
}

palStatus_t pal_plat_writePrivateKeyWithHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    size_t actualSize;
    
    palCryptoBuffer_t* localkey = (palCryptoBuffer_t*) prvKeyHandle;

    status = pal_plat_writePrivateKeyToDer(ECKeyHandle, localkey->buffer, (size_t)localkey->size, &actualSize);
    if (status != FCC_PAL_SUCCESS) {
        return status;
    }

    return status;
}

palStatus_t pal_plat_writePublicKeyWithHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    size_t actualSize;

    palCryptoBuffer_t* localkey = (palCryptoBuffer_t*) pubKeyHandle;

    status = pal_plat_writePublicKeyToDer(ECKeyHandle, localkey->buffer, (size_t)localkey->size, &actualSize);
    if (status != FCC_PAL_SUCCESS) {
        return status;
    }

    return status;
}

#endif//!MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

//! Move data from the end of the buffer to the begining, this function is needed since mbedTLS
//! write functions write the data at the end of the buffers.
static void moveDataToBufferStart(unsigned char* buffer, size_t bufferSize, size_t actualSize)
{
    size_t j = 0;
    size_t i = bufferSize - actualSize;
    if (bufferSize == actualSize)
    {
        return;
    }

    for( ; j < actualSize ; ++i , ++j)
    {
        buffer[j] = buffer[i];
        buffer[i] = (unsigned char)0;
    }
}

palStatus_t pal_plat_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;

    platStatus = ssl_platform_pk_write_key_der(localECKey, derBuffer, bufferSize);
    if (CRYPTO_PLAT_SUCCESS < platStatus)
    {
        *actualSize = (size_t)platStatus;
        moveDataToBufferStart(derBuffer, bufferSize, *actualSize);
    }
    else
    {
        switch (platStatus) {
            case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                break;
            default:
                status = FCC_PAL_ERR_FAILED_TO_WRITE_PRIVATE_KEY;
        }
    }

    return status;
}

palStatus_t pal_plat_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;

    platStatus = ssl_platform_pk_write_pubkey_der(localECKey, derBuffer, bufferSize);
    if (CRYPTO_PLAT_SUCCESS < platStatus)
    {
        *actualSize = (size_t)platStatus;
        moveDataToBufferStart(derBuffer, bufferSize, *actualSize);
    }
    else
    {
        switch (platStatus) {
            case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                break;
            default:
                status = FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
        }
    }

    return status;
}

palStatus_t pal_plat_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    mbedtls_ecp_group_id platCurve = MBEDTLS_ECP_DP_NONE;
    palECKey_t* localECKey = (palECKey_t*)key;
    mbedtls_ecp_keypair* keyPair = NULL;

    switch(grpID)
    {
        case PAL_ECP_DP_SECP256R1:
            platCurve = MBEDTLS_ECP_DP_SECP256R1;
            break;
        default: 
            status = FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
            goto finish;
    }

    mbedtls_pk_context *mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localECKey);
    platStatus = mbedtls_pk_setup(mbedtls_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        status = FCC_PAL_ERR_KEYPAIR_GEN_FAIL;
        goto finish;
    }

    keyPair = (mbedtls_ecp_keypair*)mbedtls_ctx->pk_ctx;

    platStatus = mbedtls_ecp_gen_key(platCurve, keyPair, pal_plat_entropySource, NULL);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_KEYPAIR_GEN_FAIL;
        ssl_platform_pk_free(localECKey);
    }

finish:
    return status;
}

palStatus_t pal_plat_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;
    mbedtls_ecp_keypair* keyPair = NULL;

    mbedtls_pk_context *mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localECKey);
    if (NULL == (mbedtls_ecp_keypair*)mbedtls_ctx->pk_ctx)
    {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    keyPair = (mbedtls_ecp_keypair*)mbedtls_ctx->pk_ctx;

    switch(keyPair->grp.id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
            *grpID = PAL_ECP_DP_SECP256R1;
            break;
        default:
            *grpID = PAL_ECP_DP_NONE;
            status = FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
    }
    return status;
}

palStatus_t pal_plat_ECGroupFree(palCurveHandle_t* grp)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palECGroup_t* localGroup = NULL;

    localGroup = (palECGroup_t*)*grp;
    mbedtls_ecp_group_free(localGroup);
    free(localGroup);
    *grp = NULLPTR;
    return status;
}

palStatus_t pal_plat_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    mbedtls_ecp_group_id platCurve = MBEDTLS_ECP_DP_NONE;
    palECGroup_t* localGroup = NULL;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    localGroup = (palECGroup_t*)malloc(sizeof(palECGroup_t));
    if (NULL == localGroup)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
        goto finish;
    }

    mbedtls_ecp_group_init(localGroup);
    switch(index)
    {
        case PAL_ECP_DP_SECP256R1:
            platCurve = MBEDTLS_ECP_DP_SECP256R1;
            break;
        default: 
            status = FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
            goto finish;
    }

    platStatus = mbedtls_ecp_group_load(localGroup ,platCurve);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_GROUP_LOAD_FAILED;
    }
    else
    {
        *grp = (palCurveHandle_t)localGroup;
    }
    
finish:
    if (FCC_PAL_SUCCESS != status && localGroup != NULL)
    {
        free(localGroup);
    }

    return status;
}


palStatus_t pal_plat_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, const palECKeyHandle_t privateKey, palECKeyHandle_t outKey)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECGroup_t* ecpGroup = (palECGroup_t*)grp;
    mbedtls_ecp_keypair* pubKeyPair = NULL;
    mbedtls_ecp_keypair* prvKeyPair = NULL;
    mbedtls_ecp_keypair* outKeyPair = NULL;
    mbedtls_ctr_drbg_context ctrDrbgCtx;

    mbedtls_ctr_drbg_init(&ctrDrbgCtx);

    mbedtls_pk_context *pub_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)peerPublicKey);
    mbedtls_pk_context *prv_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)privateKey);
    mbedtls_pk_context *out_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)outKey);
    pubKeyPair = (mbedtls_ecp_keypair*)pub_mbedtls_ctx->pk_ctx;
    prvKeyPair = (mbedtls_ecp_keypair*)prv_mbedtls_ctx->pk_ctx;
    outKeyPair = (mbedtls_ecp_keypair*)out_mbedtls_ctx->pk_ctx;

    if (NULL != pubKeyPair && NULL != prvKeyPair && NULL != outKeyPair)
    {
        platStatus = mbedtls_ecdh_compute_shared(ecpGroup, &outKeyPair->d, &pubKeyPair->Q, &prvKeyPair->d, mbedtls_ctr_drbg_random, (void*)&ctrDrbgCtx);
        if (CRYPTO_PLAT_SUCCESS != platStatus)
        {
            status = FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
        }
    }
    else 
    {
        status = FCC_PAL_ERR_INVALID_ARGUMENT;
    }


    mbedtls_ctr_drbg_free(&ctrDrbgCtx);

    return status;
}

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_plat_ECDHKeyAgreement(
    const uint8_t               *derPeerPublicKey,
    size_t                       derPeerPublicKeySize,
    const palECKeyHandle_t       privateKeyHandle,
    unsigned char               *rawSharedSecretOut,
    size_t                       rawSharedSecretMaxSize,
    size_t                      *rawSharedSecretActSizeOut)
{

    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKeyHandle_t peerPublicKeyHandle;
    mbedtls_ecdh_context ecdhContext;
    mbedtls_ecp_keypair* pubPeerKeyPair = NULL;
    mbedtls_ecp_keypair* prvKeyPair = NULL;

    //Initialize a new key handle
    status = pal_plat_ECKeyNew(&peerPublicKeyHandle);
    if (status != FCC_PAL_SUCCESS) {
        return status;
    }

 
    //Parse public peer key to initialized handle
    status = pal_plat_parseECPublicKeyFromDER(derPeerPublicKey, derPeerPublicKeySize, peerPublicKeyHandle);
    if (status != FCC_PAL_SUCCESS) {
        goto release_ec_context_and_finish;
    }

    //Init ecdh context
    mbedtls_ecdh_init(&ecdhContext);

    //Get ecp keys form private and public peer key handles
    mbedtls_pk_context *pub_peer_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)peerPublicKeyHandle);
    mbedtls_pk_context *prv_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)privateKeyHandle);
    pubPeerKeyPair = (mbedtls_ecp_keypair*)pub_peer_mbedtls_ctx->pk_ctx;
    prvKeyPair = (mbedtls_ecp_keypair*)prv_mbedtls_ctx->pk_ctx;

    if (NULL != pubPeerKeyPair && NULL != prvKeyPair)
    {
        //Set up the ECDH context from an EC private and peer public keys
        if ((platStatus = mbedtls_ecdh_get_params(&ecdhContext, prvKeyPair, MBEDTLS_ECDH_OURS)) != 0 ||
            (platStatus = mbedtls_ecdh_get_params(&ecdhContext, pubPeerKeyPair, MBEDTLS_ECDH_THEIRS)) != 0)
        {
            status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
            goto release_all_and_finish;
        }

        //Caluclate shared secret
        status = mbedtls_ecdh_calc_secret(&ecdhContext, rawSharedSecretActSizeOut, rawSharedSecretOut, rawSharedSecretMaxSize, pal_plat_entropySource, NULL);
        if (platStatus != CRYPTO_PLAT_SUCCESS || *rawSharedSecretActSizeOut != PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE)
        {
            status = FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
        }//platStatus != CRYPTO_PLAT_SUCCESS

    } else {//NULL == pubPeerKeyPair || NULL == prvKeyPair)
        status = FCC_PAL_ERR_INVALID_ARGUMENT;
    }

release_all_and_finish:
    mbedtls_ecdh_free(&ecdhContext);
release_ec_context_and_finish:
    (void)pal_plat_ECKeyFree(&peerPublicKeyHandle);
    return status;
}
#else //#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

palStatus_t pal_plat_ECDHKeyAgreement(
    const uint8_t               *derPeerPublicKey,
    size_t                       derPeerPublicKeySize,
    const palECKeyHandle_t       privateKeyHandle,
    unsigned char               *rawSharedSecretOut,
    size_t                       rawSharedSecretMaxSize,
    size_t                      *rawSharedSecretActSizeOut)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    palECKeyHandle_t peerPublicKeyHandle;
    mbedtls_ecp_keypair* pubPeerKeyPair = NULL;
    uint8_t raw_public_key[PAL_SECP256R1_MAX_PUB_KEY_RAW_SIZE] = { 0 };
    size_t act_raw_public_key_size = 0;
    //Set PSA handle
    mbedtls_pk_context *prv_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)privateKeyHandle);
    psa_key_handle_t *privatKeyPSAHandle =(psa_key_handle_t*)prv_mbedtls_ctx->pk_ctx;

    //Initialize a new key handle
    status = pal_plat_ECKeyNew(&peerPublicKeyHandle);
    if (status != FCC_PAL_SUCCESS) {
        return status;
    }

    //Parse public peer key to initialized handle
    status = pal_plat_parseECPublicKeyFromDER(derPeerPublicKey, derPeerPublicKeySize, peerPublicKeyHandle);
    if (status != FCC_PAL_SUCCESS) {
        goto finish;
    }

    //Set ecp key pair
    mbedtls_pk_context *pub_peer_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context((palECKey_t*)peerPublicKeyHandle);
    pubPeerKeyPair = (mbedtls_ecp_keypair*)pub_peer_mbedtls_ctx->pk_ctx;

    //Get raw public key data
    platStatus = mbedtls_ecp_point_write_binary(&pubPeerKeyPair->grp, &pubPeerKeyPair->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &act_raw_public_key_size, raw_public_key, sizeof(raw_public_key));
    if (platStatus != FCC_PAL_SUCCESS || act_raw_public_key_size!= PAL_SECP256R1_MAX_PUB_KEY_RAW_SIZE) {
        status = FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
        goto finish;
    }

    // create raw shared secret
    psa_status = psa_raw_key_agreement(PSA_ALG_ECDH, (psa_key_handle_t)*privatKeyPSAHandle,
                                        raw_public_key, act_raw_public_key_size,
                                        rawSharedSecretOut, rawSharedSecretMaxSize, rawSharedSecretActSizeOut);
    if (psa_status != PSA_SUCCESS) {
        status = FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
        goto finish;
    }

finish:
    //Release allocated resources
    (void)pal_plat_ECKeyFree(&peerPublicKeyHandle);
    return status;
}

#endif //#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

palStatus_t pal_plat_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t* sigLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)prvKey;
    mbedtls_ecp_keypair* keyPair = NULL;
    mbedtls_ecdsa_context localECDSA;
    palECGroup_t* localGroup = (palECGroup_t*)grp;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;

    mbedtls_pk_context *mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localECKey);
    keyPair = (mbedtls_ecp_keypair*)mbedtls_ctx->pk_ctx;

    mbedtls_ecdsa_init(&localECDSA);
    platStatus = mbedtls_ecdsa_from_keypair(&localECDSA, keyPair);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_FAILED_TO_COPY_KEYPAIR;
        goto finish;
    }

    platStatus = mbedtls_ecp_group_copy(&localECDSA.grp, localGroup);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_FAILED_TO_COPY_GROUP;
        goto finish;
    }

    switch (mdType)
    {
        case PAL_SHA256:
            mdAlg = MBEDTLS_MD_SHA256;
            break;
        default:
            status = FCC_PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    platStatus = mbedtls_ecdsa_write_signature(&localECDSA, mdAlg, dgst, dgstLen, sig, sigLen, NULL, NULL);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_FAILED_TO_WRITE_SIGNATURE;
    }

finish:
    mbedtls_ecdsa_free(&localECDSA);
    return status;
}

palStatus_t pal_plat_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t sigLen, bool* verified)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)pubKey;
    mbedtls_ecp_keypair* keyPair = NULL;
    mbedtls_ecdsa_context localECDSA;

    mbedtls_pk_context *mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localECKey);
    keyPair = (mbedtls_ecp_keypair*)mbedtls_ctx->pk_ctx;

    mbedtls_ecdsa_init(&localECDSA);
    platStatus = mbedtls_ecdsa_from_keypair(&localECDSA, keyPair);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_FAILED_TO_COPY_KEYPAIR;
        goto finish;
    }

    platStatus = mbedtls_ecdsa_read_signature(&localECDSA, dgst, dgstLen, sig, sigLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_FAILED_TO_VERIFY_SIGNATURE;
        *verified = false;
    }
    else
    {
        *verified = true;
    }
finish:
    mbedtls_ecdsa_free(&localECDSA);
    return status;
}

static palStatus_t pal_plat_convertDerSignatureToRaw(const unsigned char * derSignature, size_t derSignatureSize, unsigned char *outRawSignature, size_t curveRawSignatureSize)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    size_t len = 0;
    mbedtls_mpi r, s;
    unsigned char *p = (unsigned char *)derSignature;
    const unsigned char *end = derSignature + derSignatureSize;


    //Initialize mpis
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    //Check first asn1 tag
    platStatus = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (platStatus != CRYPTO_PLAT_SUCCESS) {
        status = FCC_PAL_ERR_ASN1_UNEXPECTED_TAG;
        goto cleanup;
    }

    //Check output len size
    if (p + len != end) {
        status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    } 

    //Get signature components:  r and s
    if ((platStatus = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (platStatus = mbedtls_asn1_get_mpi(&p, end, &s)) != 0)
    {
        status  = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    //Check size of each component
    if ((mbedtls_mpi_size(&r) > curveRawSignatureSize/2) || (mbedtls_mpi_size(&s) > curveRawSignatureSize/2))
    {
        status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    //Write the components to binary format
    platStatus = mbedtls_mpi_write_binary(&r, outRawSignature, curveRawSignatureSize/2);
    if (platStatus != CRYPTO_PLAT_SUCCESS )
    {
        status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    platStatus = mbedtls_mpi_write_binary(&s, outRawSignature + curveRawSignatureSize/2, curveRawSignatureSize/2);
    if (platStatus != CRYPTO_PLAT_SUCCESS)
    {
        status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return status;
}

static palStatus_t ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s, unsigned char *sig, size_t sigMaxSize ,size_t *sigActSizeOut)
{
    int ret;
    unsigned char buf[PAL_ECDSA_SECP256R1_SIGNATURE_DER_SIZE];
    unsigned char *p = buf + sizeof(buf);
    int len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, ssl_platform_asn1_write_mpi(&p, buf, (const mbedtls_mpi *)s));
    MBEDTLS_ASN1_CHK_ADD(len, ssl_platform_asn1_write_mpi(&p, buf, (const mbedtls_mpi *)r));

    MBEDTLS_ASN1_CHK_ADD(len, ssl_platform_asn1_write_len(&p, buf, (size_t)len));
    MBEDTLS_ASN1_CHK_ADD(len, ssl_platform_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    if (sigMaxSize < (size_t)len) {
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(sig, p, (size_t)len);
    *sigActSizeOut =(size_t) len;

    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_convertRawSignatureToDer(const unsigned char *rawSignature, size_t  rawSignatureSize, unsigned char *derSignatureOut, size_t derSignatureMaxSize, size_t *derSignatureActSizeOut)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    mbedtls_mpi r, s;
    
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    //Read r component
    platStatus = mbedtls_mpi_read_binary(&r, rawSignature, rawSignatureSize /2);
    if (platStatus != CRYPTO_PLAT_SUCCESS)
    {
        status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    //Read s component
    platStatus = mbedtls_mpi_read_binary(&s, rawSignature + rawSignatureSize /2, rawSignatureSize /2);
    if (platStatus != CRYPTO_PLAT_SUCCESS)
    {
        status = FCC_PAL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    status = ecdsa_signature_to_asn1(&r, &s, derSignatureOut, derSignatureMaxSize, derSignatureActSizeOut);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return status;
}

palStatus_t pal_plat_asymmetricSign( palECKeyHandle_t privateKeyHandle, palMDType_t mdType, const unsigned char *hash, size_t hashSize, unsigned char *outSignature, size_t maxSignatureSize, size_t *actualOutSignatureSize)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;
    palECKey_t* localECKey = (palECKey_t*)privateKeyHandle;
    unsigned char derSignature[PAL_ECDSA_SECP256R1_SIGNATURE_DER_SIZE] = { 0 };
    size_t derSignatureSize = sizeof(derSignature);
    size_t rawSignatureSize = PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE;

    //Set md algorithm
    switch (mdType)
    {
    case PAL_SHA256:
        mdAlg = MBEDTLS_MD_SHA256;
        break;
    default:
        return FCC_PAL_ERR_INVALID_MD_TYPE;
    }

    //Check if output buffer is big enough
    if (maxSignatureSize < rawSignatureSize)
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;

    //Create signature in asn1 format
    ssl_platform_hash_type_t ssl_md_alg = (mdAlg == MBEDTLS_MD_SHA256) ? SSL_PLATFORM_HASH_SHA256 : SSL_PLATFORM_HASH_SHA256;
    platStatus = ssl_platform_pk_sign(localECKey, ssl_md_alg, hash, hashSize, derSignature, &derSignatureSize, NULL, NULL);
    if (platStatus != SSL_PLATFORM_SUCCESS) {
        status = FCC_PAL_ERR_PK_SIGN_FAILED;
        return status;
    }


    //Convert asn1 signature to raw format
    platStatus = pal_plat_convertDerSignatureToRaw(derSignature, derSignatureSize, outSignature, rawSignatureSize);
    if (platStatus != CRYPTO_PLAT_SUCCESS) {
       return FCC_PAL_ERR_FAILED_TO_WRITE_SIGNATURE;
    }

    //Update the output signature size
    *actualOutSignatureSize = rawSignatureSize;

    return status;
}

palStatus_t pal_plat_asymmetricVerify(palECKeyHandle_t publicKeyHandle, palMDType_t mdType, const unsigned char *hash, size_t hashSize, const unsigned char *signature, size_t signatureSize)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;
    palECKey_t* localECKey = (palECKey_t*)publicKeyHandle;
    unsigned char derSignature[PAL_ECDSA_SECP256R1_SIGNATURE_DER_SIZE] = { 0 };
    size_t derSignatureSize = sizeof(derSignature);

    switch (mdType)
    {
    case PAL_SHA256:
        mdAlg = MBEDTLS_MD_SHA256;
        break;
    default:
        status = FCC_PAL_ERR_INVALID_MD_TYPE;
    }

    //Convert asn1 signature to raw format
    platStatus = pal_plat_convertRawSignatureToDer(signature, signatureSize, derSignature, sizeof(derSignature), &derSignatureSize);
    if (platStatus != CRYPTO_PLAT_SUCCESS) {
        return FCC_PAL_ERR_FAILED_TO_WRITE_SIGNATURE;
    }

    ssl_platform_hash_type_t ssl_md_alg = (mdAlg == MBEDTLS_MD_SHA256) ? SSL_PLATFORM_HASH_SHA256 : SSL_PLATFORM_HASH_SHA256;
    platStatus = ssl_platform_pk_verify(localECKey, ssl_md_alg, hash, hashSize, derSignature, derSignatureSize);
    if (platStatus != CRYPTO_PLAT_SUCCESS) {
        return FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
    }

    return status;
}



#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_x509CSRInit(palx509CSRHandle_t *x509CSR)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = NULL;

    localCSR = (palx509CSR_t*)malloc(sizeof(palx509CSR_t));
    if (NULL == localCSR)
    {
        status = FCC_PAL_ERR_NO_MEMORY;
    }
    else
    {
        mbedtls_x509write_csr_init(localCSR);
        *x509CSR = (palx509CSRHandle_t)localCSR;
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;

    platStatus = mbedtls_x509write_csr_set_subject_name(localCSR, subjectName);
    switch (platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            status = FCC_PAL_SUCCESS;
            break;
        case MBEDTLS_ERR_X509_UNKNOWN_OID:
            status = FCC_PAL_ERR_X509_UNKNOWN_OID;
            break;
        case MBEDTLS_ERR_X509_INVALID_NAME:
            status = FCC_PAL_ERR_X509_INVALID_NAME;
            break;
        default:
            {
                FCC_PAL_LOG_ERR("Crypto x509 CSR set subject status %" PRId32 ".", platStatus);
                status = FCC_PAL_ERR_GENERIC_FAILURE;
            }
    }

    return status;
}

palStatus_t pal_plat_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    palECKey_t* localPubKey = (palECKey_t*)pubKey;
    palECKey_t* localPrvKey = (palECKey_t*)prvKey;

    if (NULL != localPrvKey)
    {
        int32_t platStatus = CRYPTO_PLAT_SUCCESS;
        mbedtls_ecp_keypair* pubKeyPair = NULL;
        mbedtls_ecp_keypair* prvKeyPair = NULL;

        mbedtls_pk_context *pub_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localPubKey);
        mbedtls_pk_context *prv_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localPrvKey);
        pubKeyPair = (mbedtls_ecp_keypair*)pub_mbedtls_ctx->pk_ctx;
        prvKeyPair = (mbedtls_ecp_keypair*)prv_mbedtls_ctx->pk_ctx;

        if (NULL != pubKeyPair && NULL != prvKeyPair)
        {
            platStatus = mbedtls_mpi_copy(&(pubKeyPair->d), &(prvKeyPair->d));
            if (CRYPTO_PLAT_SUCCESS != platStatus)
            {
                status = FCC_PAL_ERR_FAILED_TO_COPY_KEYPAIR;
            }
        }
        else
        {
            status = FCC_PAL_ERR_INVALID_ARGUMENT;
        }
    }
    
    if (FCC_PAL_SUCCESS == status)
    {
        mbedtls_pk_context *pub_mbedtls_ctx = (mbedtls_pk_context*)ssl_platform_pk_get_backend_context(localPubKey);
        mbedtls_x509write_csr_set_key(localCSR, pub_mbedtls_ctx);
    }
    
    return status;
}
    
palStatus_t pal_plat_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;

    switch (mdType)
    {
        case PAL_SHA256:
            mdAlg = MBEDTLS_MD_SHA256;
            break;
        default:
            status = FCC_PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    mbedtls_x509write_csr_set_md_alg(localCSR, mdAlg);

finish:
    return status;
}

palStatus_t pal_plat_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    uint8_t localKeyUsage = 0;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    if (PAL_X509_KU_DIGITAL_SIGNATURE & keyUsage)
    {
        localKeyUsage |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    }
    if (PAL_X509_KU_KEY_CERT_SIGN & keyUsage)
    {
        localKeyUsage |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
    }
    if (PAL_X509_KU_NON_REPUDIATION & keyUsage)
    {
        localKeyUsage |= MBEDTLS_X509_KU_NON_REPUDIATION;
    }
    if (PAL_X509_KU_KEY_AGREEMENT & keyUsage) {
        localKeyUsage |= MBEDTLS_X509_KU_KEY_AGREEMENT;
    }

    if (0 == localKeyUsage)
    {
        status = FCC_PAL_ERR_INVALID_KEY_USAGE;
    }
    else
    {
        platStatus = mbedtls_x509write_csr_set_key_usage(localCSR, localKeyUsage);
        if (CRYPTO_PLAT_SUCCESS != platStatus)
        {
            status = FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
        }
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    // Max needed buffer if all option turned on
    // In details: sequence tag + sequence len + ((oid tag + oid len + oid) * (7 options))
    uint8_t value_buf[2 + (2 + MBEDTLS_OID_SIZE(MBEDTLS_OID_OCSP_SIGNING)) * 7];

    uint8_t *start = value_buf;
    uint8_t *end = value_buf + sizeof(value_buf);
    uint32_t all_bits = PAL_X509_EXT_KU_ANY | PAL_X509_EXT_KU_SERVER_AUTH | PAL_X509_EXT_KU_CLIENT_AUTH |
        PAL_X509_EXT_KU_CODE_SIGNING | PAL_X509_EXT_KU_EMAIL_PROTECTION | PAL_X509_EXT_KU_TIME_STAMPING |
        PAL_X509_EXT_KU_OCSP_SIGNING;

    // Check if all options valid
    if ((extKeyUsage == 0) || (extKeyUsage & (~all_bits))) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    /* As mbedTLS, build the DER in value_buf from end to start */

    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_OCSP_SIGNING & extKeyUsage) {
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_OCSP_SIGNING, MBEDTLS_OID_SIZE(MBEDTLS_OID_OCSP_SIGNING));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_TIME_STAMPING & extKeyUsage) {
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_TIME_STAMPING, MBEDTLS_OID_SIZE(MBEDTLS_OID_TIME_STAMPING));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_EMAIL_PROTECTION & extKeyUsage) {
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_EMAIL_PROTECTION, MBEDTLS_OID_SIZE(MBEDTLS_OID_EMAIL_PROTECTION));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_CODE_SIGNING & extKeyUsage) {
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_CODE_SIGNING, MBEDTLS_OID_SIZE(MBEDTLS_OID_CODE_SIGNING));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_CLIENT_AUTH & extKeyUsage){
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_CLIENT_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_SERVER_AUTH & extKeyUsage){
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_ANY & extKeyUsage){
        platStatus = ssl_platform_asn1_write_oid(&end, start, MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE));
    }

    if (platStatus < CRYPTO_PLAT_SUCCESS) {
        goto finish;
    }

    // Calc written len (from end to the end of value_buf) and write it to value_buf
    platStatus = ssl_platform_asn1_write_len(&end, start,(size_t)((value_buf + sizeof(value_buf)) - end));
    if (platStatus < CRYPTO_PLAT_SUCCESS) {
        goto finish;
    }
    // Write sequence tag
    platStatus = ssl_platform_asn1_write_tag(&end, start, (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    if (platStatus < CRYPTO_PLAT_SUCCESS) {
        goto finish;
    }

    // Set start and end pointer to the used part in value_buf and add the extension to the CSR 
    start = end;
    end = value_buf + sizeof(value_buf);
    platStatus = mbedtls_x509write_csr_set_extension(localCSR, MBEDTLS_OID_EXTENDED_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
                                                     start, (size_t)(end - start));
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        goto finish;
    }

finish:
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        status = FCC_PAL_ERR_FAILED_TO_SET_EXT_KEY_USAGE;
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    platStatus = mbedtls_x509write_csr_set_extension(localCSR, oid, oidLen, value, valueLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = FCC_PAL_ERR_SET_EXTENSION_FAILED;
    }
    return status;
}

palStatus_t pal_plat_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;

    platStatus = mbedtls_x509write_csr_der(localCSR, derBuf, derBufLen, pal_plat_entropySource, NULL);
    if (CRYPTO_PLAT_SUCCESS < platStatus)
    {
        *actualDerLen = (size_t)platStatus;
        moveDataToBufferStart(derBuf, derBufLen, *actualDerLen);
    } else {
        switch (platStatus) {
            case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                break;
            default:
                status = FCC_PAL_ERR_CSR_WRITE_DER_FAILED;
        }
    }

    return status;
}

palStatus_t pal_plat_x509CSRFree(palx509CSRHandle_t *x509CSR)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t* localCSR = (palx509CSR_t*)*x509CSR;

    mbedtls_x509write_csr_free(localCSR);
    free(localCSR);
    *x509CSR = NULLPTR;
    return status;
}

palStatus_t pal_plat_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t *crt_ctx = (palX509Ctx_t*)x509Cert;

    switch (hash_type) {
        case PAL_SHA256:
            if (outLenBytes < PAL_SHA256_SIZE) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                break;
            }
            // TODO: Use ssl_platform_x509_get_tbs() when implemented
            unsigned char *tbs_buf;
            size_t tbs_len;
            if (ssl_platform_x509_get_tbs(&crt_ctx->ssl_crt, &tbs_buf, &tbs_len) == SSL_PLATFORM_SUCCESS) {
                status = pal_plat_sha256(tbs_buf, tbs_len, output);
            } else {
                status = FCC_PAL_ERR_NOT_SUPPORTED_CURVE; // Temporary error
            }
            *actualOutLenBytes = PAL_SHA256_SIZE;
            break;
        default:
            status = FCC_PAL_ERR_INVALID_MD_TYPE;
            break;
    }
    
    return status;
}

static int copy_X509_v3_extensions_to_CSR(unsigned char *ext_v3_start, size_t ext_v3_len, palx509CSR_t *x509CSR)
{
    int ret;
    size_t len;
    unsigned char *p = ext_v3_start;
    const unsigned char *end = (ext_v3_start + ext_v3_len);

    // bail out if certificate has no extensions
    if (ext_v3_len == 0) {
        return(0);
    }

    // skip root ext.
    if ((ret = ssl_platform_asn1_get_tag_ext(&p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1)) != 0) {
        return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
    }

    while (p < end) {
        /*
        * Extension  ::=  SEQUENCE  {
        *      extnID      OBJECT IDENTIFIER,
        *      critical    BOOLEAN DEFAULT FALSE,
        *      extnValue   OCTET STRING  }
        */
        mbedtls_x509_buf extn_oid = { 0, 0, NULL };
        int is_critical = 0; /* DEFAULT FALSE */

        if ((ret = ssl_platform_asn1_get_tag_ext(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE, 1)) != 0) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        /* Get extension ID */
        extn_oid.tag = *p;

        if ((ret = ssl_platform_asn1_get_tag_ext(&p, end, &extn_oid.len, MBEDTLS_ASN1_OID, 0)) != 0) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        extn_oid.p = p;
        p += extn_oid.len;

        if ((end - p) < 1) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                   MBEDTLS_ERR_ASN1_OUT_OF_DATA);
        }

        /* Get optional critical */
        // Note: mbedtls_asn1_get_bool not available in ssl-platform yet, keeping original
        if ((ret = mbedtls_asn1_get_bool(&p, end, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        /* Data should be octet string type */
        if ((ret = ssl_platform_asn1_get_tag_ext(&p, end, &len,
            MBEDTLS_ASN1_OCTET_STRING, 0)) != 0) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        // some extensions should be set by the CA, skip those...
        if (memcmp(extn_oid.p, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER, extn_oid.len) == 0 ||
            memcmp(extn_oid.p, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER, extn_oid.len) == 0) {
            p += len;
            continue;
        }

        /* Set extension in CSR */
        ret = mbedtls_x509_set_extension(&x509CSR->extensions, (const char *)extn_oid.p, extn_oid.len, is_critical, p, len);
        if (ret != 0) {
            return ret;
        }

        p += len;
    }

    if (p != end) {
        return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return(0);
}

palStatus_t pal_plat_x509CSRFromCertWriteDER(palX509Handle_t x509Cert, palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerBufLen)
{
    palX509Ctx_t *localCert = (palX509Ctx_t*)x509Cert;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    char subject[512];
    int mbedtls_ret;

    /** Note - we assume that the x509CSR object is already 
    * initialized and contain at list a private key.
    */

    // Extract subject name from certificate and set it on CSR
    mbedtls_ret = ssl_platform_x509_get_subject_name(&localCert->ssl_crt, subject, sizeof(subject));
    if (mbedtls_ret < 0) {
        return FCC_PAL_ERR_X509_UNKNOWN_OID;
    }
    
    mbedtls_ret = pal_plat_x509CSRSetSubject(x509CSR, subject);
    if (mbedtls_ret != FCC_PAL_SUCCESS) {
        return mbedtls_ret;
    }
    
    // Get certificate TBS (To Be Signed) data and extract extensions
    unsigned char *tbs_ptr;
    size_t tbs_len;
    if (ssl_platform_x509_get_tbs(&localCert->ssl_crt, &tbs_ptr, &tbs_len) == SSL_PLATFORM_SUCCESS) {
        // Try to copy extensions from cert to CSR
        copy_X509_v3_extensions_to_CSR(tbs_ptr, tbs_len, localCSR);
    }

    // write CSR
    return pal_plat_x509CSRWriteDER(x509CSR, derBuf, derBufLen, actualDerBufLen);
}

#endif


static int pal_plat_entropySourceDRBG( void *data, unsigned char *output, size_t len)
{
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)data;
    
    PV_UNUSED_PARAM(output);
    PV_UNUSED_PARAM(len);
    // Simply signal to ourselves that the DRBG is seeded (we set the seed as the additional data when seeding)
    if (data)
    {
        // TODO: Use ssl_platform_ctr_drbg_set_seed_status() when available
        // Temporary stub - cannot access internal ssl-platform fields
    }
    return CRYPTO_PLAT_SUCCESS;
}

#if 0
palStatus_t pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;

    if (!g_palCtrDrbgCtx) {
        return FCC_PAL_ERR_NOT_INITIALIZED;
    }
    /*
    * If the DRBG is not yet seeded, try to seed it.
    * This check is important for the production flow where NV entropy is expected (MBEDTLS_ENTROPY_NV_SEED defined):
    * First run factory app:
    *  - Entropy is injected and DRBG is seeded
    * Then run Pelion client app (entropy exists in storage):
    *  - call pal_plat_osRandomBuffer_blocking(). DRBG is not seeded during pal_plat_DRBGInit() and pal_plat_osEntropyInject()
    *    will not be called so we should seed the DRBG with the entropy already in storage.
    */
    if (pal_CtrDRBGIsSeeded(g_palCtrDrbgCtx) == FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED) {
        status = pal_plat_DRBGSeed();
        // If seeding failed with source error, we assume that the NV source did not exist, and return a FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED error
        if (status == FCC_PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED) {
            return FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED;
        } else if (status != PAL_SUCCESS) {
            return status;
        }
    }

#if PAL_USE_HW_TRNG
    return pal_plat_generateDrbgWithNoiseAttempt(g_palCtrDrbgCtx, randomBuf, false, bufSizeBytes);
#else 
    // Note that calling pal_plat_generateDrbgWithNoiseAttempt here will also work
    // but that will add some unnecessary code to the image. Besides, it is more clear
    // this way.
    return pal_CtrDRBGGenerate(g_palCtrDrbgCtx, randomBuf, bufSizeBytes);
#endif
}
#endif
static int pal_plat_entropySource( void *data, unsigned char *output, size_t len)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    (void)data;
    
    status = pal_osRandomBuffer((uint8_t*) output, len);
    if (FCC_PAL_SUCCESS == status)
    {
        return CRYPTO_PLAT_SUCCESS;
    }
    else
    {
        return CRYPTO_PLAT_GENERIC_ERROR;
    }
}

#if defined(__CC_ARM) || (defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)) // ARMC5 and ARMC6
/* This function is provided for ARM-CC compiler, since mbedTLS uses it and it returns NULL
 * in ARM-CC, we need to provide replacement function to keep correct functionality
 * mbedTLS will change the internal implementation which uses gmtime()
 */
// For mbedtls version < 2.13.0
struct tm *gmtime(const time_t *timep)
{
    return localtime(timep);
}
// mbedtls version > 2.13.0
struct tm *gmtime_r(const time_t *timep, struct tm * result)
{
    return _localtime_r(timep, result);
}
#endif

// Stub function implementations  
// SSL-Platform X.509 functions are now properly implemented - no more stubs needed


