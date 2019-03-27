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
#include "pal.h"
#include "pal_plat_Crypto.h"
#include "pal_plat_rtos.h"
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

#define TRACE_GROUP "PAL"

typedef mbedtls_ccm_context palCCM_t;
typedef mbedtls_ecp_group palECGroup_t;
typedef mbedtls_ecp_point palECPoint_t;
typedef mbedtls_mpi palMP_t;
typedef mbedtls_pk_context palECKey_t;

#if (PAL_ENABLE_X509 == 1)
typedef mbedtls_x509write_csr palx509CSR_t; 
#endif

typedef mbedtls_cipher_context_t palCipherCtx_t;


//! forward declaration
//! This function is based on PAL random algorithm which uses CTR-DRBG algorithm
PAL_PRIVATE int pal_plat_entropySource( void *data, unsigned char *output, size_t len);

//! forward declarations
//! This function access directly to the plarform entropy source
//! it was added specialy for DRBG reseeding process
PAL_PRIVATE int pal_plat_entropySourceDRBG( void *data, unsigned char *output, size_t len);


typedef struct palSign{
    mbedtls_mpi r;
    mbedtls_mpi s;
}palSignature_t;

typedef struct palCtrDrbgCtx{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbgCtx;
}palCtrDrbgCtx_t;

typedef struct palAes{
    mbedtls_aes_context platCtx;
    unsigned char stream_block[PAL_CRYPT_BLOCK_SIZE];  //The saved stream-block for resuming. Is overwritten by the function.
    size_t nc_off;   //The offset in the current stream_block
}palAes_t;

#if (PAL_ENABLE_X509 == 1)
typedef struct palX509Ctx{
    mbedtls_x509_crt crt;
}palX509Ctx_t;
#endif

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
typedef struct palMD{
    mbedtls_md_context_t md;
} palMD_t;
#else

#include "crypto.h"

typedef struct palMD {
    psa_hash_operation_t md;
    psa_algorithm_t alg;
} palMD_t;

#endif

#define CRYPTO_PLAT_SUCCESS 0
#define CRYPTO_PLAT_GENERIC_ERROR (-1)

palStatus_t pal_plat_initCrypto()
{
    return PAL_SUCCESS;
}

palStatus_t pal_plat_cleanupCrypto()
{
    return PAL_SUCCESS;
}

palStatus_t pal_plat_initAes(palAesHandle_t *aes)
{
    palStatus_t status = PAL_SUCCESS;
    palAes_t* localCtx = NULL;

    localCtx = (palAes_t*)malloc(sizeof(palAes_t));
    if (NULL == localCtx)
    {
        status = PAL_ERR_CREATION_FAILED;
    }
    else
    {
        mbedtls_aes_init(&localCtx->platCtx);
        localCtx->nc_off = 0;
        memset(localCtx->stream_block, 0, 16);

        *aes = (palAesHandle_t)localCtx;
    }
    return status;
}

palStatus_t pal_plat_freeAes(palAesHandle_t *aes)
{
    palStatus_t status = PAL_SUCCESS;
    palAes_t* localCtx = NULL;
    
    localCtx = (palAes_t*)*aes;
    
    mbedtls_aes_free(&localCtx->platCtx);
    free(localCtx);
    *aes = NULLPTR;
    return status;
}

palStatus_t pal_plat_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;

    if (PAL_KEY_TARGET_ENCRYPTION == keyTarget)
    {
        platStatus = mbedtls_aes_setkey_enc(&localCtx->platCtx, key, keybits);
    }
    else
    {
        platStatus = mbedtls_aes_setkey_dec(&localCtx->platCtx, key, keybits);
    }

    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_AES_INVALID_KEY_LENGTH;
    }

    return status;    
}

palStatus_t pal_plat_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16], bool zeroOffset)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;

    if (true == zeroOffset)
    {
        localCtx->nc_off = 0;
        memset(localCtx->stream_block, 0, 16);
    }

    platStatus = mbedtls_aes_crypt_ctr(&localCtx->platCtx, inLen, &localCtx->nc_off, iv, localCtx->stream_block, input, output);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        PAL_LOG_ERR("Crypto aes ctr status %" PRId32 "", platStatus);
        status = PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;

    platStatus = mbedtls_aes_crypt_ecb(&localCtx->platCtx, (PAL_AES_ENCRYPT == mode ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT), input, output);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        PAL_LOG_ERR("Crypto aes ecb status  %" PRId32 "", platStatus);
        status = PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_sha256(const unsigned char* input, size_t inLen, unsigned char* output)
{    
    palStatus_t status = PAL_SUCCESS;

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    mbedtls_sha256(input, inLen, output, 0);
#else
    palMDHandle_t md = 0;

    status = pal_plat_mdInit(&md, PAL_SHA256);
    if (PAL_SUCCESS != status)
    {
        return status;
    }

    status = pal_plat_mdUpdate(md, input, inLen);
    if (status != PAL_SUCCESS)
    {
        goto finish;
    }

    status = pal_plat_mdFinal(md, output);

finish:
    if (0 != md)
    {
        (void)pal_plat_mdFree(&md);
    }
#endif
    return status;
}
#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_x509Initiate(palX509Handle_t* x509)
{
    palStatus_t status = PAL_SUCCESS;
    palX509Ctx_t* localCtx = NULL;

    localCtx = (palX509Ctx_t*)malloc(sizeof(palX509Ctx_t));
    if (NULL == localCtx)
    {
        status = PAL_ERR_CREATION_FAILED;
    }
    else
    {
        mbedtls_x509_crt_init(&localCtx->crt);
        *x509 = (uintptr_t)localCtx;
    }

    return status;
}


palStatus_t pal_plat_x509CertParse(palX509Handle_t x509, const unsigned char* input, size_t inLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509;

     platStatus = mbedtls_x509_crt_parse_der(&localCtx->crt, input, inLen);
    if (platStatus < CRYPTO_PLAT_SUCCESS)
    {
		if (MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE == platStatus)
		{
			status = PAL_ERR_NOT_SUPPORTED_CURVE;
		}
		
        else if (-(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) == ((-platStatus) & 0xFF80))
        {
            status = PAL_ERR_INVALID_MD_TYPE;
        }
        
        else
        {
            status = PAL_ERR_CERT_PARSING_FAILED;
        }
    }

    return status;
}

PAL_PRIVATE palStatus_t pal_plat_x509CertGetID(palX509Ctx_t* x509Cert, uint8_t *id, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    platStatus = mbedtls_ecp_point_write_binary( &((mbedtls_ecp_keypair *)((x509Cert->crt).pk).pk_ctx)->grp, &((mbedtls_ecp_keypair *)((x509Cert->crt).pk).pk_ctx)->Q,
         MBEDTLS_ECP_PF_COMPRESSED, actualOutLenBytes, id, outLenBytes);
    if (platStatus != CRYPTO_PLAT_SUCCESS)
    {
        status = PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }
    return status;
}

PAL_PRIVATE palStatus_t pal_plat_X509GetField(palX509Ctx_t* x509Ctx, const char* fieldName, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    const char *shortName = NULL;
    size_t fieldNameLength = 0;
    mbedtls_x509_name *x509Name = &x509Ctx->crt.subject;

    fieldNameLength = strlen(fieldName);
    while( x509Name ) 
    {
        platStatus = mbedtls_oid_get_attr_short_name(&x509Name->oid, &shortName);
        if (CRYPTO_PLAT_SUCCESS != platStatus)
        {
            status = PAL_ERR_INVALID_IOD; 
            break;  
        }
        if (strncmp(shortName, fieldName, fieldNameLength) == 0)
        {
            if (outLenBytes < (x509Name->val.len + 1))
            {
                status = PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = x509Name->val.len + 1;
                break;
            }
            memcpy(output, x509Name->val.p, x509Name->val.len);
            ((char*)output)[x509Name->val.len] = '\0';
            *actualOutLenBytes = x509Name->val.len + 1;
            break;
        }
        x509Name = x509Name->next;
    }
    return status;
}

PAL_PRIVATE bool pal_isLeapYear(uint16_t year)
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

PAL_PRIVATE palStatus_t pal_timegm( struct tm *tm, uint64_t* outTime) 
{
    uint64_t epoc = 0;
    uint8_t palMonthDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (NULL == outTime || NULL == tm || tm->tm_year < 1970 || tm->tm_mon > 12)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    for (uint16_t y = 1970; y < tm->tm_year; ++y)
    {
        if (pal_isLeapYear(y))
        {
            epoc += 366 * PAL_SECONDS_PER_DAY;
        }
        else
        {
            epoc += 365 * PAL_SECONDS_PER_DAY;
        }      
    }
    
    for (uint8_t m = 1; m < tm->tm_mon; ++m) 
    {
        epoc += palMonthDays[m - 1] * PAL_SECONDS_PER_DAY;
        if (m == PAL_FEB_MONTH && pal_isLeapYear(tm->tm_year))
        {
            epoc += PAL_SECONDS_PER_DAY;
        }
    }

    epoc += (tm->tm_mday - 1) * PAL_SECONDS_PER_DAY;
    epoc += tm->tm_hour * PAL_SECONDS_PER_HOUR;
    epoc += tm->tm_min * PAL_SECONDS_PER_MIN;
    epoc += tm->tm_sec;
    *outTime = epoc;
    return PAL_SUCCESS;
}


palStatus_t pal_plat_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = PAL_SUCCESS;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509Cert;
    *actualOutLenBytes = 0;

    switch(attr)
    {
        case PAL_X509_ISSUER_ATTR:
            if (localCtx->crt.issuer_raw.len <= outLenBytes)
            {
                memcpy(output, localCtx->crt.issuer_raw.p, localCtx->crt.issuer_raw.len);
            }
            else
            {
                status = PAL_ERR_BUFFER_TOO_SMALL;
            }
            *actualOutLenBytes = localCtx->crt.issuer_raw.len;
            break;

        case PAL_X509_SUBJECT_ATTR:
            if (localCtx->crt.subject_raw.len <= outLenBytes)
            {
                memcpy(output, localCtx->crt.subject_raw.p, localCtx->crt.subject_raw.len);
            }
            else
            {
                status = PAL_ERR_BUFFER_TOO_SMALL;
            }
            *actualOutLenBytes = localCtx->crt.subject_raw.len;
            break;

        case PAL_X509_VALID_FROM:
            if ( PAL_CRYPTO_CERT_DATE_LENGTH > outLenBytes)
            {
                status = PAL_ERR_BUFFER_TOO_SMALL;
            }
            else
            {
                struct tm time;
                uint64_t timeOfDay;
                time.tm_year = localCtx->crt.valid_from.year;
                time.tm_mon = localCtx->crt.valid_from.mon;
                time.tm_mday = localCtx->crt.valid_from.day;
                time.tm_hour = localCtx->crt.valid_from.hour;
                time.tm_min = localCtx->crt.valid_from.min;
                time.tm_sec = localCtx->crt.valid_from.sec;
                time.tm_isdst = -1;                                   //unknown DST 
                status = pal_timegm(&time, &timeOfDay);
                if (PAL_SUCCESS != status)
                {
                    status = PAL_ERR_TIME_TRANSLATE;
                }
                else
                {
                    memcpy(output, &timeOfDay, PAL_CRYPTO_CERT_DATE_LENGTH);
                }
            }
            *actualOutLenBytes = PAL_CRYPTO_CERT_DATE_LENGTH;
            break;
	    
        case PAL_X509_VALID_TO:
            if ( PAL_CRYPTO_CERT_DATE_LENGTH > outLenBytes)
            {
                status = PAL_ERR_BUFFER_TOO_SMALL;
            }
            else
            {
                struct tm time;
                uint64_t timeOfDay;
                time.tm_year = localCtx->crt.valid_to.year;
                time.tm_mon = localCtx->crt.valid_to.mon;
                time.tm_mday = localCtx->crt.valid_to.day;
                time.tm_hour = localCtx->crt.valid_to.hour;
                time.tm_min = localCtx->crt.valid_to.min;
                time.tm_sec = localCtx->crt.valid_to.sec;
                time.tm_isdst = -1;                                 //unknown DST
                status = pal_timegm(&time, &timeOfDay);
                if (PAL_SUCCESS != status)
                {
                    status = PAL_ERR_TIME_TRANSLATE;
                }
                else
                {
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
            if (PAL_CERT_ID_SIZE > outLenBytes)
            {
                status = PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = PAL_CERT_ID_SIZE;
            }
            else
            {
                status = pal_plat_x509CertGetID(localCtx, output, outLenBytes, actualOutLenBytes);
            }
            break;

        case PAL_X509_SIGNATUR_ATTR:
            if (localCtx->crt.sig.len > outLenBytes) {
                status = PAL_ERR_BUFFER_TOO_SMALL;
                break;
            }

            memcpy(output, localCtx->crt.sig.p, localCtx->crt.sig.len);
            *actualOutLenBytes = localCtx->crt.sig.len;
            break;

        default:
           status = PAL_ERR_INVALID_X509_ATTR;
    }
    return status;
}

PAL_PRIVATE const mbedtls_x509_crt_profile s_PALProfile =
{
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) | MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ),
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECKEY ) | MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_ECDSA ),
    MBEDTLS_X509_ID_FLAG( MBEDTLS_ECP_DP_SECP256R1 ),
    0x7FFFFFFF // RSA not allowed
};

palStatus_t pal_plat_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult)
{
    palStatus_t status = PAL_SUCCESS;
    palX509Ctx_t* localCert = (palX509Ctx_t*)x509Cert;
    palX509Ctx_t* localCAChain = (palX509Ctx_t*)x509CertChain;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    uint32_t flags = 0;
    *verifyResult = 0;

    if (NULL == localCAChain)
    {
        platStatus = mbedtls_x509_crt_verify_with_profile(&localCert->crt, NULL, NULL, &s_PALProfile, NULL, &flags, NULL, NULL);
    }
    else
    {
        platStatus = mbedtls_x509_crt_verify_with_profile(&localCert->crt, &localCAChain->crt, NULL, &s_PALProfile, NULL, &flags, NULL, NULL);
    }

    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_X509_CERT_VERIFY_FAILED;
        //! please DO NOT change errors order
        if (MBEDTLS_X509_BADCERT_NOT_TRUSTED & flags)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_NOT_TRUSTED;
            status = PAL_ERR_X509_BADCERT_NOT_TRUSTED;
        }
        if (MBEDTLS_X509_BADCERT_BAD_KEY & flags)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_BAD_KEY;
            status = PAL_ERR_X509_BADCERT_BAD_KEY;
        }
        if (MBEDTLS_X509_BADCERT_BAD_PK & flags)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_BAD_PK;
            status = PAL_ERR_X509_BADCERT_BAD_PK;
        }
        if (MBEDTLS_X509_BADCERT_BAD_MD & flags)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_BAD_MD;
            status = PAL_ERR_X509_BADCERT_BAD_MD;
        }
        if (MBEDTLS_X509_BADCERT_FUTURE & flags)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_FUTURE;
            status = PAL_ERR_X509_BADCERT_FUTURE;
        }
        if (MBEDTLS_X509_BADCERT_EXPIRED & flags)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_EXPIRED;
            status = PAL_ERR_X509_BADCERT_EXPIRED;
        }
    }

    return status;
}

palStatus_t pal_plat_x509Free(palX509Handle_t* x509)
{
    palStatus_t status = PAL_SUCCESS;
    palX509Ctx_t* localCtx = NULL;

    localCtx = (palX509Ctx_t*)*x509;
    mbedtls_x509_crt_free(&localCtx->crt);
    free(localCtx);
    *x509 = NULLPTR;
    return status;
}

#endif

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palMD_t* localCtx = NULL;
    const mbedtls_md_info_t* mdInfo = NULL;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;

    localCtx = (palMD_t*)malloc(sizeof(palMD_t));
    if (NULL == localCtx)
    {
        status = PAL_ERR_CREATION_FAILED;
        goto finish;
    }

    
    mbedtls_md_init(&localCtx->md);
    
    switch (mdType)
    {
        case PAL_SHA256:
            mdAlg = MBEDTLS_MD_SHA256;
            break;
        default:
            status = PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    mdInfo = mbedtls_md_info_from_type(mdAlg);
    if (NULL == mdInfo)
    {
        status = PAL_ERR_INVALID_MD_TYPE;
        goto finish;
    }

    platStatus = mbedtls_md_setup(&localCtx->md, mdInfo, 0); // 0 because we don't want to use HMAC in mbedTLS to save memory
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            break;
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            {
                status = PAL_ERR_MD_BAD_INPUT_DATA;
                goto finish;
            }
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
            {
                status = PAL_ERR_CREATION_FAILED;
                goto finish;
            }
        default: 
            {
                PAL_LOG_ERR("Crypto md start setup  %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
                goto finish;
            }
    }
    
    platStatus = mbedtls_md_starts(&localCtx->md);
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            break;
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            {
                status = PAL_ERR_MD_BAD_INPUT_DATA;
                goto finish;
            }
        default: 
            {
                PAL_LOG_ERR("Crypto md start status  %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
                goto finish;
            }
    }

    *md = (uintptr_t)localCtx;
finish:
    if (PAL_SUCCESS != status && NULL != localCtx)
    {
        free(localCtx);
    }
    return status;
}

palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    platStatus =  mbedtls_md_update(&localCtx->md, input, inLen);
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            break;
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            status = PAL_ERR_MD_BAD_INPUT_DATA;
            break;
        default: 
            {
                PAL_LOG_ERR("Crypto md update status %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
            }
    }
    return status;
}

palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    palStatus_t status = PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    if (NULL != localCtx->md.md_info)
    {
        *bufferSize = (size_t)mbedtls_md_get_size(localCtx->md.md_info);
    }
    else
    {
        PAL_LOG_ERR("Crypto md get size error");
        status = PAL_ERR_GENERIC_FAILURE;
    }
    
    return status;
}

palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    platStatus =  mbedtls_md_finish(&localCtx->md, output);
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            break;
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            status = PAL_ERR_MD_BAD_INPUT_DATA;
            break;
        default: 
            {
                PAL_LOG_ERR("Crypto md finish status %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
            }
    } 
    return status;
}

palStatus_t pal_plat_mdFree(palMDHandle_t* md)
{
    palStatus_t status = PAL_SUCCESS;
    palMD_t* localCtx = NULL;

    localCtx = (palMD_t*)*md;
    mbedtls_md_free(&localCtx->md);
    free(localCtx);
    *md = NULLPTR;
    return status;
}
#else //!MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

PAL_PRIVATE palStatus_t palToPsaMdType(palMDType_t palMdType, psa_algorithm_t *psaAlg)
{
    switch (palMdType)
    {
        case PAL_SHA256:
            *psaAlg = PSA_ALG_SHA_256;
            return PAL_SUCCESS;    
        default:
            return PAL_ERR_INVALID_MD_TYPE;
    }
}

palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    palStatus_t palStatus = PAL_SUCCESS;
    psa_status_t status = PSA_SUCCESS;
    psa_algorithm_t alg = 0;
    palMD_t* localCtx = NULL;

    palStatus = palToPsaMdType(mdType, &alg);
    if (PAL_SUCCESS != palStatus)
    {
        return palStatus;
    }

    localCtx = (palMD_t*)malloc(sizeof(palMD_t));
    if (NULL == localCtx)
    {
        return PAL_ERR_CREATION_FAILED;
    }

    memset(localCtx, 0, sizeof(palMD_t));

    status = psa_hash_setup(&localCtx->md, alg);
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }

    localCtx->alg = alg;

    *md = (uintptr_t)localCtx;

finish:
    if (PAL_SUCCESS != palStatus)
    {
        free(localCtx);
    }
    return palStatus;
}

palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    psa_status_t status = PSA_SUCCESS;
    palStatus_t palStatus = PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;

    status = psa_hash_update(&localCtx->md, input, inLen);
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_GENERIC_FAILURE;
    }

    return palStatus;
}


palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    palMD_t* localCtx = (palMD_t*)md;
    
    *bufferSize = PSA_HASH_SIZE(localCtx->alg);
    if (0 == *bufferSize)
    {
        return PAL_ERR_GENERIC_FAILURE;
    } 
    else
    {
        return PAL_SUCCESS;
    }
}

palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output)
{
    psa_status_t status = PSA_SUCCESS;
    palStatus_t palStatus = PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;
    size_t outputSize; // Size is determined by md when it was initialized, user should know it
    size_t bufSize;

    palStatus = pal_plat_mdGetOutputSize(md, &bufSize);
    if (PAL_SUCCESS != palStatus)
    {
        return palStatus;
    }

    status = psa_hash_finish(&localCtx->md, output, bufSize, &outputSize);
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_GENERIC_FAILURE;
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
    return PAL_SUCCESS;
}

#endif //!MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509;

    switch (mdType)
    {
        case PAL_SHA256:
            mdAlg = MBEDTLS_MD_SHA256;
            break;
        default:
            status = PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    platStatus = mbedtls_pk_verify(&localCtx->crt.pk, mdAlg, hash, hashLen, sig, sigLen);
    if (platStatus == CRYPTO_PLAT_SUCCESS) {
        status = PAL_SUCCESS;
    }
    // handling for allocation failed. Listed all mbedtls alloc errors
    else if (platStatus == MBEDTLS_ERR_X509_ALLOC_FAILED ||
             platStatus == MBEDTLS_ERR_ASN1_ALLOC_FAILED ||
             platStatus == MBEDTLS_ERR_MPI_ALLOC_FAILED ||
             platStatus == MBEDTLS_ERR_ECP_ALLOC_FAILED) {
        status = PAL_ERR_CRYPTO_ALLOC_FAILED;
    } else {
        status = PAL_ERR_PK_SIG_VERIFY_FAILED;
    }
finish:
    return status;
}
#endif 

palStatus_t pal_plat_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag )
{
    palStatus_t status = PAL_SUCCESS;
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
            status = PAL_ERR_NOT_SUPPORTED_ASN_TAG;
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
        status = PAL_ERR_NOT_SUPPORTED_ASN_TAG;
        goto finish;
    }

    platStatus =  mbedtls_asn1_get_tag(position, end, len, platTag);
    if (platStatus < CRYPTO_PLAT_SUCCESS)
    {
        status = PAL_ERR_ASN1_UNEXPECTED_TAG;
    }
finish:
    return status;
}

palStatus_t pal_plat_CCMInit(palCCMHandle_t* ctx)
{
    palStatus_t status = PAL_SUCCESS;
    palCCM_t* ccmCtx = NULL;

    ccmCtx = (palCCM_t*)malloc(sizeof(palCCM_t));
    if (NULL == ccmCtx)
    {
        status = PAL_ERR_NO_MEMORY;
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
    palStatus_t status = PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)*ctx;

    mbedtls_ccm_free(ccmCtx);
    free(ccmCtx);
    *ctx = NULLPTR;
    return status;
}

palStatus_t pal_plat_CCMSetKey(palCCMHandle_t ctx, palCipherID_t id, const unsigned char *key, unsigned int keybits)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;
    mbedtls_cipher_id_t mbedtls_cipher_id;

    switch (id) 
    {
        case PAL_CIPHER_ID_AES:
            mbedtls_cipher_id = MBEDTLS_CIPHER_ID_AES;
            break;
        default:
            return PAL_ERR_INVALID_ARGUMENT;
    }

    platStatus = mbedtls_ccm_setkey(ccmCtx, mbedtls_cipher_id, key, keybits);

    switch(platStatus)
    {
    case CRYPTO_PLAT_SUCCESS:
        status = PAL_SUCCESS;
        break;
    default:
        {
            PAL_LOG_ERR("Crypto ccm setkey status %" PRId32 "", platStatus);
            status = PAL_ERR_GENERIC_FAILURE;
        }
    }
    return status;
}

palStatus_t pal_plat_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* tag, size_t tagLen, unsigned char* output)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;

    platStatus = mbedtls_ccm_auth_decrypt(ccmCtx, inLen, iv, ivLen, add, addLen, input, output, tag, tagLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        switch(platStatus)
        {
        default:
            {
                PAL_LOG_ERR("Crypto ccm decrypt status %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
            }
        }
    }
    return status;
}

palStatus_t pal_plat_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* output, unsigned char* tag, size_t tagLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;

    platStatus = mbedtls_ccm_encrypt_and_tag(ccmCtx, inLen, iv, ivLen, add, addLen, input, output, tag, tagLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        switch(platStatus)
        {
        default:
            {
                PAL_LOG_ERR("Crypto ccm encrypt status %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
            }
        }
    }
    return status;
}

palStatus_t pal_plat_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx)
{
    palStatus_t status = PAL_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = NULL;

    palCtrDrbgCtx = (palCtrDrbgCtx_t*)malloc(sizeof(palCtrDrbgCtx_t));
    if (NULL == palCtrDrbgCtx)
    {
        status = PAL_ERR_NO_MEMORY;
    }
    else
    {
        mbedtls_ctr_drbg_init(&palCtrDrbgCtx->ctrDrbgCtx);
        mbedtls_entropy_init(&palCtrDrbgCtx->entropy);
        *ctx = (palCtrDrbgCtxHandle_t)palCtrDrbgCtx;
    }

    return status;
}

palStatus_t pal_plat_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx)
{
    palStatus_t status = PAL_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)*ctx;

    mbedtls_ctr_drbg_free(&palCtrDrbgCtx->ctrDrbgCtx);
    mbedtls_entropy_free(&palCtrDrbgCtx->entropy);
    free(palCtrDrbgCtx);
    *ctx = NULLPTR;

    return status;
}

palStatus_t pal_plat_CtrDRBGIsSeeded(palCtrDrbgCtxHandle_t ctx)
{
    // If using mbedtls with entropy sources, if the reseed_counter is 0 - this means seeding has not been done yet and generating a random number will not work
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)ctx;
    if (palCtrDrbgCtx->ctrDrbgCtx.reseed_counter > 0)
    {
        return PAL_SUCCESS;
    }
    else if (palCtrDrbgCtx->ctrDrbgCtx.reseed_counter == 0)
    {
        return PAL_ERR_CTR_DRBG_NOT_SEEDED;
    }
    else 
    {
        return PAL_ERR_GENERIC_FAILURE; // Having the reseed counter negative indicates some wierd error. Perhaps uninitialized context
    }
#else
    // If not using mbedtls with entropy sources, reseed_counter will always be 0 and seeding is done in a lazy fashion
    // so we return the not seeded error so when pal_plat_CtrDRBGSeedFromEntropySources() is called, we will seed with the mock
    // entropy function and context as necessary
    return PAL_ERR_CTR_DRBG_NOT_SEEDED;
#endif
}

// FIXME: Currently not public in pal_plat_Crypto.h and is called from pal_plat_drbg_w_entropy_sources.c
// With a forward declaration
// This function will later be public, deprecating pal_plat_CtrDRBGSeed() (pal_plat_CtrDRBGInit will call this directly).
// Changing this requires some work - therefore not done yet
/**
 * If ctx is not seeded - seed it
 * If ctx is already seeded - reseed it
 */
palStatus_t pal_plat_CtrDRBGSeedFromEntropySources(palCtrDrbgCtxHandle_t ctx, int (*f_entropy)(void *, unsigned char *, size_t), const void* additionalData, size_t additionalDataLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)ctx;

    status = pal_CtrDRBGIsSeeded(ctx);
    if (status == PAL_ERR_CTR_DRBG_NOT_SEEDED) // First call - DRBG not seeded yet
    {
        platStatus = mbedtls_ctr_drbg_seed(&palCtrDrbgCtx->ctrDrbgCtx, f_entropy, &palCtrDrbgCtx->entropy, additionalData, additionalDataLen);
    } 
    
    /*
     * DRBG already seeded, so function was invoked for reseeding -
     * perhaps storage was deleted and new entropy injected.
     * Note that entropy callback and context are already in palCtrDrbgCtx->ctrDrbgCtx context
     */
    else if (status == PAL_SUCCESS)
    {
        platStatus = mbedtls_ctr_drbg_reseed(&palCtrDrbgCtx->ctrDrbgCtx, additionalData, additionalDataLen);
    }
    else
    {
        return PAL_ERR_GENERIC_FAILURE; 
    }
    
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            status = PAL_SUCCESS;
            break;
        case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
            status = PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
            break;
        default:
            {
                PAL_LOG_ERR("Crypto ctrdrbg seed status %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
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
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)ctx;

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    // If using mbedtls with entropy sources, make sure the DRBG is seeded
    status = pal_plat_CtrDRBGIsSeeded(ctx);
    if (status != PAL_SUCCESS)
    {
        return status;
    }
#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    platStatus = mbedtls_ctr_drbg_random_with_add(&palCtrDrbgCtx->ctrDrbgCtx, out, len, additional, additionalLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        switch (platStatus)
        {
            case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
                status = PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
                break;
            case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
                status = PAL_ERR_CTR_DRBG_REQUEST_TOO_BIG;
                break;
            default:
            {
                PAL_LOG_ERR("Crypto ctrdrbg generate status %" PRId32 "", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
            }
        }
    }
    return status;
}

#if PAL_CMAC_SUPPORT
palStatus_t pal_plat_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    const mbedtls_cipher_info_t *cipherInfo;

    cipherInfo = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, keyLenInBits, MBEDTLS_MODE_ECB);
    if (NULL == cipherInfo)
    {
        PAL_LOG_ERR("Crypto cipher cmac error");
        status = PAL_ERR_CMAC_GENERIC_FAILURE;
        goto finish;
    }

    platStatus = mbedtls_cipher_cmac( cipherInfo, key, keyLenInBits, input, inputLenInBytes, output);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        PAL_LOG_ERR("Crypto cipher cmac status %" PRId32 "", platStatus);
        status = PAL_ERR_CMAC_GENERIC_FAILURE;
    }
finish:
    return status;
}

palStatus_t pal_plat_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID)
{
    palStatus_t status = PAL_SUCCESS;
    palCipherCtx_t* localCipher = NULL;
    const mbedtls_cipher_info_t* cipherInfo = NULL;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    mbedtls_cipher_type_t platType = MBEDTLS_CIPHER_NONE;

    switch(cipherID)
    {
        case PAL_CIPHER_ID_AES:
            platType = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        default:
            status = PAL_ERR_INVALID_CIPHER_ID;
            goto finish;
    }

    cipherInfo = mbedtls_cipher_info_from_type(platType);
    if (NULL == cipherInfo)
    {
        PAL_LOG_ERR("Crypto cmac cipher info error");
        status = PAL_ERR_CMAC_GENERIC_FAILURE;
        goto finish;
    }

    localCipher = (palCipherCtx_t*)malloc(sizeof(palCipherCtx_t));
    if (NULL == localCipher)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }

    mbedtls_cipher_init(localCipher);
    platStatus = mbedtls_cipher_setup(localCipher, cipherInfo);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        PAL_LOG_ERR("Crypto cmac cipher setup status %" PRId32 ".", platStatus);
        status = PAL_ERR_CMAC_GENERIC_FAILURE;
        goto finish;
    }

    platStatus = mbedtls_cipher_cmac_starts(localCipher, key, keyLenBits);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_CMAC_START_FAILED;
        goto finish;
    }

    *ctx = (palCMACHandle_t)localCipher;
finish:
    if (PAL_SUCCESS != status && NULL != localCipher)
    {
        free(localCipher);
    }
    return status;
}

palStatus_t pal_plat_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen)
{
    palStatus_t status = PAL_SUCCESS;
    palCipherCtx_t* localCipher = (palCipherCtx_t*)ctx;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    platStatus = mbedtls_cipher_cmac_update(localCipher, input, inLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_CMAC_UPDATE_FAILED;
    }

    return status;
}

palStatus_t pal_plat_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen)
{
    palStatus_t status = PAL_SUCCESS;
    palCipherCtx_t* localCipher = (palCipherCtx_t*)*ctx;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    platStatus = mbedtls_cipher_cmac_finish(localCipher, output);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_CMAC_FINISH_FAILED;
    }
    else
    {
        *outLen = localCipher->cipher_info->block_size;
    }

    

    mbedtls_cipher_free(localCipher);
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
    palStatus_t status = PAL_SUCCESS;

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (NULL == md_info)
    {
        PAL_LOG_ERR("Crypto hmac sha256 md info error");
        status = PAL_ERR_HMAC_GENERIC_FAILURE;
    }

    if (PAL_SUCCESS == status)
    {
        platStatus = mbedtls_md_hmac(md_info, key, keyLenInBytes, input, inputLenInBytes, output);
        if (platStatus != CRYPTO_PLAT_SUCCESS)
        {
            if (platStatus == MBEDTLS_ERR_MD_BAD_INPUT_DATA)
            {
                status = PAL_ERR_MD_BAD_INPUT_DATA;
            }
            else
            {
                PAL_LOG_ERR("Crypto hmac status %" PRId32 "", platStatus);
                status = PAL_ERR_HMAC_GENERIC_FAILURE;
            }
        }
    }

    if ((NULL != outputLenInBytes) && (PAL_SUCCESS == status))
    {
        *outputLenInBytes = (size_t)mbedtls_md_get_size(md_info);
    }

    return status;
}
#else
palStatus_t pal_plat_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes)
{
    psa_status_t status = PSA_SUCCESS;
    palStatus_t palStatus = PAL_SUCCESS;
    psa_key_handle_t keyHandle = 0;
    psa_mac_operation_t operation = { 0 };
    psa_key_policy_t policy = {0};
    size_t outLen = 0;

    // Create volatile key handle
    status = psa_allocate_key(&keyHandle);
    if (PSA_SUCCESS != status)
    {
        return PAL_ERR_CRYPTO_ALLOC_FAILED;
    }

    // Set key policy to creat HMACs based on SHA256
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_SIGN ,PSA_ALG_HMAC(PSA_ALG_SHA_256));
    status = psa_set_key_policy(keyHandle, &policy);
    if (PSA_SUCCESS != status) {
        palStatus = PAL_ERR_GENERIC_FAILURE; 
        goto finish;
    }

    // Import the key to the PSA handle
    status = psa_import_key(keyHandle, PSA_KEY_TYPE_HMAC, key, keyLenInBytes);
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }

    // Setup MAC sign process
    status = psa_mac_sign_setup(&operation, keyHandle, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_HMAC_GENERIC_FAILURE;
        goto finish;
    }

    status = psa_mac_update(&operation, input, inputLenInBytes);
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_HMAC_GENERIC_FAILURE;
        goto finish;
    }

    status = psa_mac_sign_finish(&operation, output, PAL_SHA256_SIZE, &outLen);
    if (PSA_SUCCESS != status)
    {
        palStatus = PAL_ERR_HMAC_GENERIC_FAILURE;
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
PAL_PRIVATE palStatus_t pal_plat_ECCheckPrivateKey(palECGroup_t* ecpGroup, palECKeyHandle_t key, bool *verified)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* privateKey = (palECKey_t*)key;
    mbedtls_mpi* prvMP = NULL;
    if(NULL == (mbedtls_ecp_keypair*)privateKey->pk_ctx)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    prvMP = &((mbedtls_ecp_keypair*)privateKey->pk_ctx)->d;

    platStatus =  mbedtls_ecp_check_privkey(ecpGroup, prvMP);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_PRIVATE_KEY_VARIFICATION_FAILED;
    }
    else
    {
        *verified = true;
    }
    
    return status;
}

//! Check EC public key function.
PAL_PRIVATE palStatus_t pal_plat_ECCheckPublicKey(palECGroup_t* ecpGroup, palECKeyHandle_t key, bool *verified)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* publicKey = (palECKey_t*)key;
    mbedtls_ecp_point* pubPoint = NULL;
    if(NULL == (mbedtls_ecp_keypair*)publicKey->pk_ctx)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

	pubPoint = &((mbedtls_ecp_keypair*)publicKey->pk_ctx)->Q;

    platStatus =  mbedtls_ecp_check_pubkey(ecpGroup, pubPoint);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED;
    }
    else
    {
        *verified = true;
    }
    
    return status;
}

palStatus_t pal_plat_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified)
{
    palStatus_t status = PAL_SUCCESS;
    palECGroup_t* ecpGroup = (palECGroup_t*)grp;

    *verified = false;

    if ((PAL_CHECK_PRIVATE_KEY & type) != 0)
    {
        status = pal_plat_ECCheckPrivateKey(ecpGroup, key, verified);
    }

    if ((PAL_SUCCESS == status) && ((PAL_CHECK_PUBLIC_KEY & type) != 0))
    {
        status = pal_plat_ECCheckPublicKey(ecpGroup, key, verified);
    }

    return status;
}


palStatus_t pal_plat_ECKeyNew(palECKeyHandle_t* key)
{
    palStatus_t status = PAL_SUCCESS;
    palECKey_t* localECKey = NULL;

    localECKey = (palECKey_t*)malloc(sizeof(palECKey_t));
    if (NULL == localECKey)
    {
        status = PAL_ERR_NO_MEMORY;
    }
    else
    {
        mbedtls_pk_init(localECKey);
        *key = (palECKeyHandle_t)localECKey;
    }
    
    return status;
}

palStatus_t pal_plat_ECKeyFree(palECKeyHandle_t* key)
{
    palECKey_t* localECKey = NULL;

    localECKey = (palECKey_t*)*key;
    mbedtls_pk_free(localECKey);
    free(localECKey);
    *key = NULLPTR;
    return PAL_SUCCESS;
}

//! Check if the given data is a valid PEM format or not by checking the
//! the header and the footer of the data.
PAL_PRIVATE bool pal_plat_isPEM(const unsigned char* key, size_t keyLen)
{
    bool result = false;
    const unsigned char *s1 = NULL;
    const unsigned char *s2 = NULL;

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

palStatus_t pal_plat_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;

    if(pal_plat_isPEM(prvDERKey, keyLen))
    {
    	return PAL_ERR_INVALID_ARGUMENT;
    }

    platStatus = mbedtls_pk_parse_key(localECKey, prvDERKey, keyLen, NULL, 0);
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            break;
        case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
            status = PAL_ERR_PK_UNKNOWN_PK_ALG;
            break;
        case MBEDTLS_ERR_PK_KEY_INVALID_VERSION:
            status = PAL_ERR_PK_KEY_INVALID_VERSION;
            break;
        case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
            status = PAL_ERR_PK_KEY_INVALID_FORMAT;
            break;
        case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
            status = PAL_ERR_PK_PASSWORD_REQUIRED;
            break;
        default:
            status = PAL_ERR_PARSING_PRIVATE_KEY;
    }

    return status;
}

palStatus_t pal_plat_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;

    if (pal_plat_isPEM(pubDERKey, keyLen))
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    platStatus = mbedtls_pk_parse_public_key(localECKey, pubDERKey, keyLen);
    switch(platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            break;
        case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
            status = PAL_ERR_PK_UNKNOWN_PK_ALG;
            break;
        case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
            status = PAL_ERR_NOT_SUPPORTED_CURVE;
            break;
        case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
            status = PAL_ERR_PK_KEY_INVALID_FORMAT;
            break;
        case MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH: //This is how mbedTLS returns erros for this function
            status = PAL_ERR_PK_INVALID_PUBKEY_AND_ASN1_LEN_MISMATCH;
            break;
        case MBEDTLS_ERR_ECP_INVALID_KEY:
            status = PAL_ERR_ECP_INVALID_KEY;
            break;
        default:
            status = PAL_ERR_PARSING_PUBLIC_KEY;
    }

    return status;
}

//! Move data from the end of the buffer to the begining, this function is needed since mbedTLS
//! write functions write the data at the end of the buffers.
PAL_PRIVATE void moveDataToBufferStart(unsigned char* buffer, size_t bufferSize, size_t actualSize)
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
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;

    platStatus = mbedtls_pk_write_key_der(localECKey, derBuffer, bufferSize);
    if (CRYPTO_PLAT_SUCCESS < platStatus)
    {
        *actualSize = platStatus;
        moveDataToBufferStart(derBuffer, bufferSize, *actualSize);
    }
    else
    {
        switch (platStatus) {
            case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
                status = PAL_ERR_BUFFER_TOO_SMALL;
                break;
            default:
                status = PAL_ERR_FAILED_TO_WRITE_PRIVATE_KEY;
        }
    }

    return status;
}

palStatus_t pal_plat_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;

    platStatus = mbedtls_pk_write_pubkey_der(localECKey, derBuffer, bufferSize);
    if (CRYPTO_PLAT_SUCCESS < platStatus)
    {
        *actualSize = platStatus;
        moveDataToBufferStart(derBuffer, bufferSize, *actualSize);
    }
    else
    {
        switch (platStatus) {
            case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
                status = PAL_ERR_BUFFER_TOO_SMALL;
                break;
            default:
                status = PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
        }
    }

    return status;
}

palStatus_t pal_plat_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key)
{
    palStatus_t status = PAL_SUCCESS;
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
            status = PAL_ERR_NOT_SUPPORTED_CURVE;
            goto finish;
    }

    platStatus = mbedtls_pk_setup(localECKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        status = PAL_ERR_KEYPAIR_GEN_FAIL;
        goto finish;
    }

    keyPair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    platStatus = mbedtls_ecp_gen_key(platCurve, keyPair, pal_plat_entropySource, NULL);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_KEYPAIR_GEN_FAIL;
        mbedtls_pk_free(localECKey);
    }

finish:
    return status;
}

palStatus_t pal_plat_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID)
{
    palStatus_t status = PAL_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)key;
    mbedtls_ecp_keypair* keyPair = NULL;

    if (NULL == (mbedtls_ecp_keypair*)localECKey->pk_ctx)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    keyPair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    switch(keyPair->grp.id)
    {
        case MBEDTLS_ECP_DP_SECP256R1:
            *grpID = PAL_ECP_DP_SECP256R1;
            break;
        default:
            *grpID = PAL_ECP_DP_NONE;
            status = PAL_ERR_NOT_SUPPORTED_CURVE;
    }
    return status;
}

palStatus_t pal_plat_ECGroupFree(palCurveHandle_t* grp)
{
    palStatus_t status = PAL_SUCCESS;
    palECGroup_t* localGroup = NULL;

    localGroup = (palECGroup_t*)*grp;
    mbedtls_ecp_group_free(localGroup);
    free(localGroup);
    *grp = NULLPTR;
    return status;
}

palStatus_t pal_plat_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index)
{
    palStatus_t status = PAL_SUCCESS;
    mbedtls_ecp_group_id platCurve = MBEDTLS_ECP_DP_NONE;
    palECGroup_t* localGroup = NULL;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    localGroup = (palECGroup_t*)malloc(sizeof(palECGroup_t));
    if (NULL == localGroup)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }

    mbedtls_ecp_group_init(localGroup);
    switch(index)
    {
        case PAL_ECP_DP_SECP256R1:
            platCurve = MBEDTLS_ECP_DP_SECP256R1;
            break;
        default: 
            status = PAL_ERR_NOT_SUPPORTED_CURVE;
            goto finish;
    }

    platStatus = mbedtls_ecp_group_load(localGroup ,platCurve);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_GROUP_LOAD_FAILED;
    }
    else
    {
        *grp = (palCurveHandle_t)localGroup;
    }
    
finish:
    if (PAL_SUCCESS != status && localGroup != NULL)
    {
        free(localGroup);
    }

    return status;
}


palStatus_t pal_plat_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, const palECKeyHandle_t privateKey, palECKeyHandle_t outKey)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECGroup_t* ecpGroup = (palECGroup_t*)grp;
    mbedtls_ecp_keypair* pubKeyPair = NULL;
    mbedtls_ecp_keypair* prvKeyPair = NULL;
    mbedtls_ecp_keypair* outKeyPair = NULL;
    mbedtls_ctr_drbg_context ctrDrbgCtx;

    mbedtls_ctr_drbg_init(&ctrDrbgCtx);

    pubKeyPair = (mbedtls_ecp_keypair*)((palECKey_t*)peerPublicKey)->pk_ctx;
    prvKeyPair = (mbedtls_ecp_keypair*)((palECKey_t*)privateKey)->pk_ctx;
    outKeyPair = (mbedtls_ecp_keypair*)((palECKey_t*)outKey)->pk_ctx;

    if (NULL != pubKeyPair && NULL != prvKeyPair && NULL != outKeyPair)
    {
        platStatus = mbedtls_ecdh_compute_shared(ecpGroup, &outKeyPair->d, &pubKeyPair->Q, &prvKeyPair->d, mbedtls_ctr_drbg_random, (void*)&ctrDrbgCtx);
        if (CRYPTO_PLAT_SUCCESS != platStatus)
        {
            status = PAL_ERR_FAILED_TO_COMPUTE_SHRED_KEY;
        }
    }
    else 
    {
        status = PAL_ERR_INVALID_ARGUMENT;
    }


    mbedtls_ctr_drbg_free(&ctrDrbgCtx);

    return status;
}


palStatus_t pal_plat_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t* sigLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)prvKey;
    mbedtls_ecp_keypair* keyPair = NULL;
    mbedtls_ecdsa_context localECDSA;
    palECGroup_t* localGroup = (palECGroup_t*)grp;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;

    keyPair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    mbedtls_ecdsa_init(&localECDSA);
    platStatus = mbedtls_ecdsa_from_keypair(&localECDSA, keyPair);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_FAILED_TO_COPY_KEYPAIR;
        goto finish;
    }

    platStatus = mbedtls_ecp_group_copy(&localECDSA.grp, localGroup);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_FAILED_TO_COPY_GROUP;
        goto finish;
    }

    switch (mdType)
    {
        case PAL_SHA256:
            mdAlg = MBEDTLS_MD_SHA256;
            break;
        default:
            status = PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    platStatus = mbedtls_ecdsa_write_signature(&localECDSA, mdAlg, dgst, dgstLen, sig, sigLen, NULL, NULL);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_FAILED_TO_WRITE_SIGNATURE;
    }

finish:
    mbedtls_ecdsa_free(&localECDSA);
    return status;
}

palStatus_t pal_plat_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t sigLen, bool* verified)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)pubKey;
    mbedtls_ecp_keypair* keyPair = NULL;
    mbedtls_ecdsa_context localECDSA;

    keyPair = (mbedtls_ecp_keypair*)localECKey->pk_ctx;

    mbedtls_ecdsa_init(&localECDSA);
    platStatus = mbedtls_ecdsa_from_keypair(&localECDSA, keyPair);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_FAILED_TO_COPY_KEYPAIR;
        goto finish;
    }

    platStatus = mbedtls_ecdsa_read_signature(&localECDSA, dgst, dgstLen, sig, sigLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_FAILED_TO_VERIFY_SIGNATURE;
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
#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_x509CSRInit(palx509CSRHandle_t *x509CSR)
{
    palStatus_t status = PAL_SUCCESS;
    palx509CSR_t *localCSR = NULL;

    localCSR = (palx509CSR_t*)malloc(sizeof(palx509CSR_t));
    if (NULL == localCSR)
    {
        status = PAL_ERR_NO_MEMORY;
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
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;

    platStatus = mbedtls_x509write_csr_set_subject_name(localCSR, subjectName);
    switch (platStatus)
    {
        case CRYPTO_PLAT_SUCCESS:
            status = PAL_SUCCESS;
            break;
        case MBEDTLS_ERR_X509_UNKNOWN_OID:
            status = PAL_ERR_X509_UNKNOWN_OID;
            break;
        case MBEDTLS_ERR_X509_INVALID_NAME:
            status = PAL_ERR_X509_INVALID_NAME;
            break;
        default:
            {
                PAL_LOG_ERR("Crypto x509 CSR set subject status %" PRId32 ".", platStatus);
                status = PAL_ERR_GENERIC_FAILURE;
            }
    }

    return status;
}

palStatus_t pal_plat_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey)
{
    palStatus_t status = PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    palECKey_t* localPubKey = (palECKey_t*)pubKey;
    palECKey_t* localPrvKey = (palECKey_t*)prvKey;

    if (NULL != localPrvKey)
    {
        int32_t platStatus = CRYPTO_PLAT_SUCCESS;
        mbedtls_ecp_keypair* pubKeyPair = NULL;
        mbedtls_ecp_keypair* prvKeyPair = NULL;

        pubKeyPair = (mbedtls_ecp_keypair*)localPubKey->pk_ctx;
        prvKeyPair = (mbedtls_ecp_keypair*)localPrvKey->pk_ctx;

        if (NULL != pubKeyPair && NULL != prvKeyPair)
        {
            platStatus = mbedtls_mpi_copy(&(pubKeyPair->d), &(prvKeyPair->d));
            if (CRYPTO_PLAT_SUCCESS != platStatus)
            {
                status = PAL_ERR_FAILED_TO_COPY_KEYPAIR;
            }
        }
        else
        {
            status = PAL_ERR_INVALID_ARGUMENT;
        }
    }
    
    if (PAL_SUCCESS == status)
    {
        mbedtls_x509write_csr_set_key(localCSR, localPubKey);
    }
    
    return status;
}
    
palStatus_t pal_plat_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType)
{
    palStatus_t status = PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    mbedtls_md_type_t mdAlg = MBEDTLS_MD_NONE;

    switch (mdType)
    {
        case PAL_SHA256:
            mdAlg = MBEDTLS_MD_SHA256;
            break;
        default:
            status = PAL_ERR_INVALID_MD_TYPE;
            goto finish;
    }

    mbedtls_x509write_csr_set_md_alg(localCSR, mdAlg);

finish:
    return status;
}

palStatus_t pal_plat_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage)
{
    palStatus_t status = PAL_SUCCESS;
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
        status = PAL_ERR_INVALID_KEY_USAGE;
    }
    else
    {
        platStatus = mbedtls_x509write_csr_set_key_usage(localCSR, localKeyUsage);
        if (CRYPTO_PLAT_SUCCESS != platStatus)
        {
            status = PAL_ERR_FAILED_TO_SET_KEY_USAGE;
        }
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage)
{
    palStatus_t status = PAL_SUCCESS;
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
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* As mbedTLS, build the DER in value_buf from end to start */

    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_OCSP_SIGNING & extKeyUsage) {
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_OCSP_SIGNING, MBEDTLS_OID_SIZE(MBEDTLS_OID_OCSP_SIGNING));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_TIME_STAMPING & extKeyUsage) {
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_TIME_STAMPING, MBEDTLS_OID_SIZE(MBEDTLS_OID_TIME_STAMPING));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_EMAIL_PROTECTION & extKeyUsage) {
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_EMAIL_PROTECTION, MBEDTLS_OID_SIZE(MBEDTLS_OID_EMAIL_PROTECTION));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_CODE_SIGNING & extKeyUsage) {
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_CODE_SIGNING, MBEDTLS_OID_SIZE(MBEDTLS_OID_CODE_SIGNING));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_CLIENT_AUTH & extKeyUsage){
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_CLIENT_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_SERVER_AUTH & extKeyUsage){
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH));
    }
    if (platStatus >= CRYPTO_PLAT_SUCCESS && PAL_X509_EXT_KU_ANY & extKeyUsage){
        platStatus = mbedtls_asn1_write_oid(&end, start, MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE));
    }

    if (platStatus < CRYPTO_PLAT_SUCCESS) {
        goto finish;
    }

    // Calc written len (from end to the end of value_buf) and write it to value_buf
    platStatus = mbedtls_asn1_write_len(&end, start, (value_buf + sizeof(value_buf)) - end);
    if (platStatus < CRYPTO_PLAT_SUCCESS) {
        goto finish;
    }
    // Write sequence tag
    platStatus = mbedtls_asn1_write_tag(&end, start, (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    if (platStatus < CRYPTO_PLAT_SUCCESS) {
        goto finish;
    }

    // Set start and end pointer to the used part in value_buf and add the extension to the CSR 
    start = end;
    end = value_buf + sizeof(value_buf);
    platStatus = mbedtls_x509write_csr_set_extension(localCSR, MBEDTLS_OID_EXTENDED_KEY_USAGE, MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
                                                     start, (end - start));
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        goto finish;
    }

finish:
    if (CRYPTO_PLAT_SUCCESS != platStatus) {
        status = PAL_ERR_FAILED_TO_SET_EXT_KEY_USAGE;
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen)
{
    palStatus_t status = PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;

    platStatus = mbedtls_x509write_csr_set_extension(localCSR, oid, oidLen, value, valueLen);
    if (CRYPTO_PLAT_SUCCESS != platStatus)
    {
        status = PAL_ERR_SET_EXTENSION_FAILED;
    }
    return status;
}

palStatus_t pal_plat_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;

    platStatus = mbedtls_x509write_csr_der(localCSR, derBuf, derBufLen, pal_plat_entropySource, NULL);
    if (CRYPTO_PLAT_SUCCESS < platStatus)
    {
        *actualDerLen = platStatus;
        moveDataToBufferStart(derBuf, derBufLen, *actualDerLen);
    } else {
        switch (platStatus) {
            case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
                status = PAL_ERR_BUFFER_TOO_SMALL;
                break;
            default:
                status = PAL_ERR_CSR_WRITE_DER_FAILED;
        }
    }

    return status;
}

palStatus_t pal_plat_x509CSRFree(palx509CSRHandle_t *x509CSR)
{
    palStatus_t status = PAL_SUCCESS;
    palx509CSR_t* localCSR = (palx509CSR_t*)*x509CSR;

    mbedtls_x509write_csr_free(localCSR);
    free(localCSR);
    *x509CSR = NULLPTR;
    return status;
}

palStatus_t pal_plat_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = PAL_SUCCESS;
    palX509Ctx_t *crt_ctx = (palX509Ctx_t*)x509Cert;

    switch (hash_type) {
        case PAL_SHA256:
            if (outLenBytes < PAL_SHA256_SIZE) {
                status = PAL_ERR_BUFFER_TOO_SMALL;
                break;
            }
            status = pal_plat_sha256(crt_ctx->crt.tbs.p, crt_ctx->crt.tbs.len, output);
            *actualOutLenBytes = PAL_SHA256_SIZE;
            break;
        default:
            status = PAL_ERR_INVALID_MD_TYPE;
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
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
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

        if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        /* Get extension ID */
        extn_oid.tag = *p;

        if ((ret = mbedtls_asn1_get_tag(&p, end, &extn_oid.len, MBEDTLS_ASN1_OID)) != 0) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        extn_oid.p = p;
        p += extn_oid.len;

        if ((end - p) < 1) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                   MBEDTLS_ERR_ASN1_OUT_OF_DATA);
        }

        /* Get optional critical */
        if ((ret = mbedtls_asn1_get_bool(&p, end, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)) {
            return(MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret);
        }

        /* Data should be octet string type */
        if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_OCTET_STRING)) != 0) {
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

    // subject

    mbedtls_ret = mbedtls_x509_dn_gets(subject, sizeof(subject), &localCert->crt.subject);
    if (mbedtls_ret < 0) {
        return PAL_ERR_INVALID_X509_ATTR;
    }

    mbedtls_ret = mbedtls_x509write_csr_set_subject_name(localCSR, subject);
    if (mbedtls_ret != 0) {
        return PAL_ERR_INVALID_X509_ATTR;
    }

    // message digest alg
    mbedtls_x509write_csr_set_md_alg(localCSR, localCert->crt.sig_md);

    // optional extensions

#if !defined(MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3)
    if (localCert->crt.version == 3)
#endif
    {
        mbedtls_ret = copy_X509_v3_extensions_to_CSR((unsigned char *)localCert->crt.v3_ext.p, localCert->crt.v3_ext.len, localCSR);
        if (mbedtls_ret != 0) {
            return PAL_ERR_SET_EXTENSION_FAILED;
        }
    }

    // write CSR
    return pal_plat_x509CSRWriteDER(x509CSR, derBuf, derBufLen, actualDerBufLen);
}
#endif
PAL_PRIVATE int pal_plat_entropySourceDRBG( void *data, unsigned char *output, size_t len)
{
    palCtrDrbgCtx_t* palCtrDrbgCtx = (palCtrDrbgCtx_t*)data;
    
    // Simply signal to ourselves that the DRBG is seeded (we set the seed as the additional data when seeding)
    if (data)
    {
        palCtrDrbgCtx->ctrDrbgCtx.reseed_counter = 1;
    }
    return CRYPTO_PLAT_SUCCESS;
}

PAL_PRIVATE int pal_plat_entropySource( void *data, unsigned char *output, size_t len)
{
	palStatus_t status = PAL_SUCCESS;
    (void)data;
    
    status = pal_osRandomBuffer((uint8_t*) output, len);
    if (PAL_SUCCESS == status)
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
