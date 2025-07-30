/*******************************************************************************
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
 *******************************************************************************/

#include "mbed-client/m2mconfig.h"
#if (MBED_CLOUD_CLIENT_USE_OPENSSL == 1)

#include "cs_pal_plat_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pv_macros.h"
#if (PAL_ENABLE_X509 == 1)
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif
#include <openssl/rand.h>
#include <openssl/cmac.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


#define TRACE_GROUP "PAL_OPENSSL"

typedef EC_GROUP palECGroup_t;

typedef struct {
    EVP_PKEY *pkey;
} palECKey_t;

typedef struct palX509Ctx {
    X509 *crt;
} palX509Ctx_t;

typedef struct palx509CSR {
    X509_REQ *req;
} palx509CSR_t;

typedef CMAC_CTX palCMACCtx_t;

//! forward declaration
//! This function is based on PAL random algorithm which uses CTR-DRBG algorithm
static int pal_plat_entropySource( void *data, unsigned char *output, size_t len);

//! forward declarations
//! This function access directly to the plarform entropy source
//! it was added specialy for DRBG reseeding process
static int pal_plat_entropySourceDRBG( void *data, unsigned char *output, size_t len);

typedef struct palCtrDrbgCtx{
    RAND_DRBG *drbg;
} palCtrDrbgCtx_t;

typedef struct palAes{
    EVP_CIPHER_CTX *platCtx;
    unsigned char stream_block[PAL_CRYPT_BLOCK_SIZE];  //The saved stream-block for resuming. Is overwritten by the function.
    size_t nc_off;   //The offset in the current stream_block
}palAes_t;

typedef struct palMD {
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md_type;
} palMD_t;

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

    // EVP_default_properties_enable_fips(NULL, 1);
    if (EVP_default_properties_is_fips_enabled(NULL)) {
        FCC_PAL_LOG_DBG("FIPS mode enabled");
    } else {
        FCC_PAL_LOG_DBG("FIPS mode NOT enabled");
    }

    localCtx = (palAes_t*)malloc(sizeof(palAes_t));
    if (NULL == localCtx)
    {
        status = FCC_PAL_ERR_CREATION_FAILED;
    }
    else
    {
        // OpenSSL replacement
        localCtx->platCtx = EVP_CIPHER_CTX_new();
        if (!localCtx->platCtx) {
            free(localCtx);
            return FCC_PAL_ERR_CREATION_FAILED;
        }
        localCtx->nc_off = 0;
        memset(localCtx->stream_block, 0, 16);
        *aes = (palAesHandle_t)localCtx;
    }
    return status;
}

palStatus_t pal_plat_freeAes(palAesHandle_t *aes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palAes_t* localCtx = NULL;
    localCtx = (palAes_t*)*aes;
    // OpenSSL replacement
    EVP_CIPHER_CTX_free(localCtx->platCtx);
    free(localCtx);
    *aes = NULLPTR;
    return status;
}

palStatus_t pal_plat_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    int32_t platStatus = CRYPTO_PLAT_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;
    int ret = 1;
    // OpenSSL replacement
    const EVP_CIPHER *cipher = NULL;
    if (keybits == 128) {
        cipher = EVP_aes_128_ctr();
    } else if (keybits == 192) {
        cipher = EVP_aes_192_ctr();
    } else if (keybits == 256) {
        cipher = EVP_aes_256_ctr();
    } else {
        return FCC_PAL_ERR_AES_INVALID_KEY_LENGTH;
    }
    if (PAL_KEY_TARGET_ENCRYPTION == keyTarget) {
        ret = EVP_EncryptInit_ex(localCtx->platCtx, cipher, NULL, key, NULL);
    } else {
        ret = EVP_DecryptInit_ex(localCtx->platCtx, cipher, NULL, key, NULL);
    }
    if (ret != 1) {
        status = FCC_PAL_ERR_AES_INVALID_KEY_LENGTH;
    }
    return status;
}

palStatus_t pal_plat_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16], bool zeroOffset)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;
    int outlen = 0;
    int ret = 1;
    if (true == zeroOffset)
    {
        localCtx->nc_off = 0;
        memset(localCtx->stream_block, 0, 16);
    }
    // OpenSSL replacement
    // Re-init with IV for each operation if needed
    ret = EVP_EncryptInit_ex(localCtx->platCtx, NULL, NULL, NULL, iv);
    if (ret != 1) {
        FCC_PAL_LOG_ERR("EVP_EncryptInit_ex failed in pal_plat_aesCTR");
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    ret = EVP_EncryptUpdate(localCtx->platCtx, output, &outlen, input, (int)inLen);
    if (ret != 1) {
        FCC_PAL_LOG_ERR("EVP_EncryptUpdate failed in pal_plat_aesCTR");
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palAes_t* localCtx = (palAes_t*)aes;
    int outlen = 0;
    int ret = 1;
    // OpenSSL replacement
    // TODO: If key size is tracked, select the correct EVP_aes_*_ecb cipher. Here we assume 128-bit for example.
    const EVP_CIPHER *cipher = EVP_aes_128_ecb();
    if (mode == PAL_AES_ENCRYPT) {
        ret = EVP_EncryptInit_ex(localCtx->platCtx, cipher, NULL, NULL, NULL);
        if (ret != 1) {
            FCC_PAL_LOG_ERR("EVP_EncryptInit_ex failed in pal_plat_aesECB (ENCRYPT)");
            return FCC_PAL_ERR_GENERIC_FAILURE;
        }
        ret = EVP_EncryptUpdate(localCtx->platCtx, output, &outlen, input, PAL_CRYPT_BLOCK_SIZE);
        if (ret != 1) {
            FCC_PAL_LOG_ERR("EVP_EncryptUpdate failed in pal_plat_aesECB (ENCRYPT)");
            return FCC_PAL_ERR_GENERIC_FAILURE;
        }
    } else {
        ret = EVP_DecryptInit_ex(localCtx->platCtx, cipher, NULL, NULL, NULL);
        if (ret != 1) {
            FCC_PAL_LOG_ERR("EVP_DecryptInit_ex failed in pal_plat_aesECB (DECRYPT)");
            return FCC_PAL_ERR_GENERIC_FAILURE;
        }
        ret = EVP_DecryptUpdate(localCtx->platCtx, output, &outlen, input, PAL_CRYPT_BLOCK_SIZE);
        if (ret != 1) {
            FCC_PAL_LOG_ERR("EVP_DecryptUpdate failed in pal_plat_aesECB (DECRYPT)");
            return FCC_PAL_ERR_GENERIC_FAILURE;
        }
    }
    return status;
}

palStatus_t pal_plat_sha256(const unsigned char* input, size_t inLen, unsigned char* output)
{
    if (!input || !output) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    if (!SHA256(input, inLen, output)) {
        return FCC_PAL_ERR_CRYPTO_ERROR_BASE;
    }
    return FCC_PAL_SUCCESS;
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
        localCtx->crt = X509_new(); // OpenSSL replacement
        if (!localCtx->crt) {
            free(localCtx);
            return FCC_PAL_ERR_CREATION_FAILED;
        }
        *x509 = (uintptr_t)localCtx;
    }
    return status;
}

palStatus_t pal_plat_x509CertParse(palX509Handle_t x509, const unsigned char* input, size_t inLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509;
    const unsigned char *p = input;
    X509 *crt = d2i_X509(NULL, &p, inLen);
    if (!crt) {
        status = FCC_PAL_ERR_CERT_PARSING_FAILED;
    } else {
        if (localCtx->crt) X509_free(localCtx->crt);
        localCtx->crt = crt;
    }
    return status;
}

palStatus_t pal_plat_x509Free(palX509Handle_t* x509)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = NULL;
    localCtx = (palX509Ctx_t*)*x509;
    if (localCtx->crt) X509_free(localCtx->crt); // OpenSSL replacement
    free(localCtx);
    *x509 = NULLPTR;
    return status;
}


static palStatus_t pal_plat_x509CertGetID(palX509Ctx_t* x509Cert, uint8_t *id, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    const EC_POINT *ec_point = NULL;
    const EC_GROUP *ec_group = NULL;
    int len = 0;

    if (!x509Cert || !x509Cert->crt || !id || !actualOutLenBytes) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    pkey = X509_get_pubkey(x509Cert->crt);
    if (!pkey) {
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }

    ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    if (!ec_key) {
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }

    ec_point = EC_KEY_get0_public_key(ec_key);
    ec_group = EC_KEY_get0_group(ec_key);
    if (!ec_point || !ec_group) {
        EC_KEY_free(ec_key);
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }

    // Get the size needed for the compressed point
    len = EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    if (len <= 0) {
        EC_KEY_free(ec_key);
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }

    if ((size_t)len > outLenBytes) {
        *actualOutLenBytes = (size_t)len;
        EC_KEY_free(ec_key);
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }

    // Write the compressed point to the output buffer
    len = EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, id, outLenBytes, NULL);
    if (len <= 0) {
        EC_KEY_free(ec_key);
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }

    *actualOutLenBytes = (size_t)len;
    EC_KEY_free(ec_key);
    return status;
}

static palStatus_t pal_plat_X509GetField(palX509Ctx_t* x509Ctx, const char* fieldName, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    X509 *crt = x509Ctx->crt;
    X509_NAME *subject = NULL;
    int nid = NID_undef;
    int idx = -1;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_STRING *data = NULL;
    unsigned char *utf8 = NULL;
    int utf8len = 0;

    if (!crt || !fieldName || !output || !actualOutLenBytes) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    subject = X509_get_subject_name(crt);
    if (!subject) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    nid = OBJ_txt2nid(fieldName);
    if (nid == NID_undef) {
        // Try to map common short names to NIDs
        if (strcmp(fieldName, "CN") == 0) nid = NID_commonName;
        else if (strcmp(fieldName, "OU") == 0) nid = NID_organizationalUnitName;
        else if (strcmp(fieldName, "O") == 0) nid = NID_organizationName;
        else if (strcmp(fieldName, "L") == 0) nid = NID_localityName;
        else if (strcmp(fieldName, "C") == 0) nid = NID_countryName;
        else if (strcmp(fieldName, "ST") == 0) nid = NID_stateOrProvinceName;
        else {
            return FCC_PAL_ERR_INVALID_IOD;
        }
    }

    idx = X509_NAME_get_index_by_NID(subject, nid, -1);
    if (idx < 0) {
        return FCC_PAL_ERR_ITEM_NOT_EXIST;
    }

    entry = X509_NAME_get_entry(subject, idx);
    if (!entry) {
        return FCC_PAL_ERR_ITEM_NOT_EXIST;
    }

    data = X509_NAME_ENTRY_get_data(entry);
    if (!data) {
        return FCC_PAL_ERR_ITEM_NOT_EXIST;
    }

    utf8len = ASN1_STRING_to_UTF8(&utf8, data);
    if (utf8len < 0) {
        return FCC_PAL_ERR_CRYPTO_ERROR_BASE;
    }

    if ((size_t)(utf8len + 1) > outLenBytes) {
        status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
        *actualOutLenBytes = utf8len + 1;
        OPENSSL_free(utf8);
        return status;
    }

    memcpy(output, utf8, utf8len);
    ((char*)output)[utf8len] = '\0';
    *actualOutLenBytes = utf8len + 1;
    OPENSSL_free(utf8);

    return status;
}

palStatus_t pal_plat_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509Cert;
    *actualOutLenBytes = 0;
    X509 *crt = localCtx->crt;
    switch(attr)
    {
        case PAL_X509_ISSUER_ATTR: {
            X509_NAME *issuer = X509_get_issuer_name(crt);
            // TODO: Use X509_NAME_print_ex or X509_NAME_oneline for string conversion
            char buf[256];
            X509_NAME_oneline(issuer, buf, sizeof(buf));
            size_t len = strlen(buf);
            if (len <= outLenBytes) {
                memcpy(output, buf, len);
                *actualOutLenBytes = len;
            } else {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = len;
            }
            break;
        }
        case PAL_X509_SUBJECT_ATTR: {
            X509_NAME *subject = X509_get_subject_name(crt);
            char buf[256];
            X509_NAME_oneline(subject, buf, sizeof(buf));
            size_t len = strlen(buf);
            if (len <= outLenBytes) {
                memcpy(output, buf, len);
                *actualOutLenBytes = len;
            } else {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = len;
            }
            break;
        }
        case PAL_X509_VALID_FROM:
        case PAL_X509_VALID_TO: {
            // TODO: Use X509_get0_notBefore / X509_get0_notAfter and ASN1_TIME_to_tm
            const ASN1_TIME *time = (attr == PAL_X509_VALID_FROM) ? X509_get0_notBefore(crt) : X509_get0_notAfter(crt);
            struct tm t = {0};
            ASN1_TIME_to_tm(time, &t);
            uint64_t epoch = mktime(&t);
            if (outLenBytes < sizeof(epoch)) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
            } else {
                memcpy(output, &epoch, sizeof(epoch));
            }
            *actualOutLenBytes = sizeof(epoch);
            break;
        }
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
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = PAL_CERT_ID_SIZE;
            }
            else
            {
                status = pal_plat_x509CertGetID(localCtx, output, outLenBytes, actualOutLenBytes);
            }
            break;

        case PAL_X509_SIGNATUR_ATTR: {
            // Fix: Use OpenSSL API to get the signature from the X509 certificate
            if (!localCtx || !localCtx->crt) {
                status = FCC_PAL_ERR_INVALID_X509_ATTR;
                break;
            }
            const ASN1_BIT_STRING *sig = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            sig = localCtx->crt->signature;
#else
            const X509_ALGOR *alg = NULL;
            X509_get0_signature(&sig, &alg, localCtx->crt);
            if (!sig) {
                sig = X509_get0_pubkey_bitstr(localCtx->crt); // fallback, but not signature
            }
            if (!sig) {
                status = FCC_PAL_ERR_INVALID_X509_ATTR;
                break;
            }
#endif
            if (!sig) {
                status = FCC_PAL_ERR_INVALID_X509_ATTR;
                break;
            }
            if ((size_t)sig->length > outLenBytes) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                *actualOutLenBytes = sig->length;
                break;
            }
            memcpy(output, sig->data, sig->length);
            *actualOutLenBytes = sig->length;
            break;
        }
        default:
            status = FCC_PAL_ERR_INVALID_X509_ATTR;
    }
    return status;
}

palStatus_t pal_plat_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t* localCert = (palX509Ctx_t*)x509Cert;
    palX509Ctx_t* localCAChain = (palX509Ctx_t*)x509CertChain;
    *verifyResult = 0;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!store || !ctx) {
        if (store) X509_STORE_free(store);
        if (ctx) X509_STORE_CTX_free(ctx);
        return FCC_PAL_ERR_X509_CERT_VERIFY_FAILED;
    }
    if (localCAChain && localCAChain->crt) {
        X509_STORE_add_cert(store, localCAChain->crt);
    }
    if (!X509_STORE_CTX_init(ctx, store, localCert->crt, NULL)) {
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return FCC_PAL_ERR_X509_CERT_VERIFY_FAILED;
    }
    int ret = X509_verify_cert(ctx);
    if (ret != 1) {
        status = FCC_PAL_ERR_X509_CERT_VERIFY_FAILED;
        *verifyResult = X509_STORE_CTX_get_error(ctx);
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return status;
}

palStatus_t pal_plat_x509CertCheckExtendedKeyUsage(palX509Handle_t x509Cert, palExtKeyUsage_t usage)
{
    palX509Ctx_t *localCert = (palX509Ctx_t*)x509Cert;
    int expected_nid = NID_undef;
    int found = 0;

    switch (usage) {
        case PAL_X509_EXT_KU_ANY:
            expected_nid = NID_anyExtendedKeyUsage;
            break;
        case PAL_X509_EXT_KU_SERVER_AUTH:
            expected_nid = NID_server_auth;
            break;
        case PAL_X509_EXT_KU_CLIENT_AUTH:
            expected_nid = NID_client_auth;
            break;
        case PAL_X509_EXT_KU_CODE_SIGNING:
            expected_nid = NID_code_sign;
            break;
        case PAL_X509_EXT_KU_EMAIL_PROTECTION:
            expected_nid = NID_email_protect;
            break;
        case PAL_X509_EXT_KU_TIME_STAMPING:
            expected_nid = NID_time_stamp;
            break;
        case PAL_X509_EXT_KU_OCSP_SIGNING:
            expected_nid = NID_OCSP_sign;
            break;
        default:
            return FCC_PAL_ERR_X509_UNKNOWN_OID;
    }

    STACK_OF(ASN1_OBJECT) *eku = X509_get_ext_d2i(localCert->crt, NID_ext_key_usage, NULL, NULL);
    if (!eku) {
        // No EKU extension present, fail as mbedtls does
        return FCC_PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED;
    }

    int num = sk_ASN1_OBJECT_num(eku);
    for (int i = 0; i < num; i++) {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(eku, i);
        if (OBJ_obj2nid(obj) == expected_nid) {
            found = 1;
            break;
        }
    }
    sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);

    if (!found) {
        return FCC_PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED;
    }

    return FCC_PAL_SUCCESS;
}
#endif

palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)malloc(sizeof(palMD_t));
    if (NULL == localCtx) {
        return FCC_PAL_ERR_CREATION_FAILED;
    }
    localCtx->md_ctx = EVP_MD_CTX_new();
    if (!localCtx->md_ctx) {
        free(localCtx);
        return FCC_PAL_ERR_CREATION_FAILED;
    }
    switch (mdType) {
        case PAL_SHA256:
            localCtx->md_type = EVP_sha256();
            break;
        default:
            EVP_MD_CTX_free(localCtx->md_ctx);
            free(localCtx);
            return FCC_PAL_ERR_INVALID_MD_TYPE;
    }
    if (EVP_DigestInit_ex(localCtx->md_ctx, localCtx->md_type, NULL) != 1) {
        EVP_MD_CTX_free(localCtx->md_ctx);
        free(localCtx);
        FCC_PAL_LOG_ERR("EVP_DigestInit_ex failed in pal_plat_mdInit");
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    *md = (palMDHandle_t)localCtx;
    return status;
}

palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;
    if (EVP_DigestUpdate(localCtx->md_ctx, input, inLen) != 1) {
        FCC_PAL_LOG_ERR("EVP_DigestUpdate failed in pal_plat_mdUpdate");
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    palMD_t* localCtx = (palMD_t*)md;
    *bufferSize = EVP_MD_size(localCtx->md_type);
    if (*bufferSize == 0) {
        FCC_PAL_LOG_ERR("EVP_MD_size returned 0 in pal_plat_mdGetOutputSize");
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palMD_t* localCtx = (palMD_t*)md;
    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(localCtx->md_ctx, output, &outlen) != 1) {
        FCC_PAL_LOG_ERR("EVP_DigestFinal_ex failed in pal_plat_mdFinal");
        status = FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_mdFree(palMDHandle_t* md)
{
    palMD_t* localCtx = (palMD_t*)*md;
    if (localCtx) {
        if (localCtx->md_ctx) EVP_MD_CTX_free(localCtx->md_ctx);
        free(localCtx);
        *md = NULLPTR;
    }
    return FCC_PAL_SUCCESS;
}

#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    const EVP_MD *md = NULL;
    palX509Ctx_t* localCtx = (palX509Ctx_t*)x509;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int verify_ret = 0;

    if (!localCtx || !localCtx->crt || !hash || !sig) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    switch (mdType)
    {
        case PAL_SHA256:
            md = EVP_sha256();
            break;
        default:
            return FCC_PAL_ERR_INVALID_MD_TYPE;
    }

    pkey = X509_get_pubkey(localCtx->crt);
    if (!pkey) {
        return FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) {
        EVP_PKEY_free(pkey);
        return FCC_PAL_ERR_CRYPTO_ALLOC_FAILED;
    }

    if (EVP_PKEY_verify_init(pctx) <= 0) {
        FCC_PAL_LOG_ERR("EVP_PKEY_verify_init failed in pal_plat_verifySignature");
        status = FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
        goto cleanup;
    }

    // Set the signature MD if possible (for RSA, not needed for ECDSA)
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA || EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0) {
            FCC_PAL_LOG_ERR("EVP_PKEY_CTX_set_signature_md failed in pal_plat_verifySignature");
            status = FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
            goto cleanup;
        }
    }

    verify_ret = EVP_PKEY_verify(pctx, sig, sigLen, hash, hashLen);
    if (verify_ret == 1) {
        status = FCC_PAL_SUCCESS;
    } else if (verify_ret == 0) {
        status = FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
    } else {
        // OpenSSL error, check for alloc errors
        unsigned long err = ERR_peek_last_error();
        if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE) {
            status = FCC_PAL_ERR_CRYPTO_ALLOC_FAILED;
        } else {
            FCC_PAL_LOG_ERR("EVP_PKEY_verify failed in pal_plat_verifySignature");
            status = FCC_PAL_ERR_PK_SIG_VERIFY_FAILED;
        }
    }

cleanup:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (pkey) EVP_PKEY_free(pkey);
    return status;
}
#endif 

palStatus_t pal_plat_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag )
{
    palStatus_t status = FCC_PAL_SUCCESS;

    if (!position || !*position || !end || !len) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    // OpenSSL expects: 
    // - *position points to the start of the ASN.1 object
    // - end points to the end (one past last valid byte)
    // - *len will be set to the content length
    // - tag is the expected tag value

    // Read tag
    int class = (*(*position) & 0xC0);
    int tagnum = (*(*position) & 0x1F);

    // Check class
    if ((tag & PAL_ASN1_CLASS_BITS) == PAL_ASN1_CONTEXT_SPECIFIC) {
        if (class != V_ASN1_CONTEXT_SPECIFIC) {
            return FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG;
        }
    } else if ((tag & PAL_ASN1_CLASS_BITS) == 0x00) {
        if (class != V_ASN1_UNIVERSAL) {
            return FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG;
        }
    } else {
        return FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG;
    }

    // Check constructed
    if ((tag & PAL_ASN1_CONSTRUCTED) && !(*(*position) & V_ASN1_CONSTRUCTED)) {
        return FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG;
    }

    // Check tag number
    if ((tag & PAL_ASN1_TAG_BITS) != tagnum) {
        return FCC_PAL_ERR_ASN1_UNEXPECTED_TAG;
    }

    // Use OpenSSL ASN1_get_object to parse the tag and length
    long content_len = 0;
    int tag_ret = 0;
    int xclass = 0;
    int ret = ASN1_get_object((const unsigned char **)position, &content_len, &tag_ret, &xclass, end - *position);

    if (ret & 0x80) { // 0x80 = ASN1_R_HEADER_TOO_LONG or ASN1_R_BAD_OBJECT_HEADER
        return FCC_PAL_ERR_ASN1_UNEXPECTED_TAG;
    }

    // Check tag matches expected
    if (tag_ret != (tag & PAL_ASN1_TAG_BITS)) {
        return FCC_PAL_ERR_ASN1_UNEXPECTED_TAG;
    }

    *len = (size_t)content_len;

    return status;
}

typedef struct palCCM {
    EVP_CIPHER_CTX *ctx;
    int keybits;
} palCCM_t;

palStatus_t pal_plat_CCMInit(palCCMHandle_t* ctx)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)malloc(sizeof(palCCM_t));
    if (NULL == ccmCtx) {
        status = FCC_PAL_ERR_NO_MEMORY;
    } else {
        ccmCtx->ctx = EVP_CIPHER_CTX_new();
        if (!ccmCtx->ctx) {
            free(ccmCtx);
            return FCC_PAL_ERR_NO_MEMORY;
        }
        ccmCtx->keybits = 0;
        *ctx = (palCCMHandle_t)ccmCtx;
    }
    return status;
}

palStatus_t pal_plat_CCMFree(palCCMHandle_t* ctx)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)*ctx;
    if (ccmCtx) {
        if (ccmCtx->ctx) EVP_CIPHER_CTX_free(ccmCtx->ctx);
        free(ccmCtx);
        *ctx = NULLPTR;
    }
    return status;
}

palStatus_t pal_plat_CCMSetKey(palCCMHandle_t ctx, palCipherID_t id, const unsigned char *key, unsigned int keybits)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;
    const EVP_CIPHER *cipher = NULL;
    switch (keybits) {
        case 128:
            cipher = EVP_aes_128_ccm();
            break;
        case 192:
            cipher = EVP_aes_192_ccm();
            break;
        case 256:
            cipher = EVP_aes_256_ccm();
            break;
        default:
            return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    if (EVP_EncryptInit_ex(ccmCtx->ctx, cipher, NULL, NULL, NULL) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_EncryptInit_ex(ccmCtx->ctx, NULL, NULL, key, NULL) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    ccmCtx->keybits = keybits;
    return status;
}

palStatus_t pal_plat_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* output, unsigned char* tag, size_t tagLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;
    int outlen = 0;
    if (EVP_EncryptInit_ex(ccmCtx->ctx, NULL, NULL, NULL, iv) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_CIPHER_CTX_ctrl(ccmCtx->ctx, EVP_CTRL_CCM_SET_IVLEN, ivLen, NULL) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_CIPHER_CTX_ctrl(ccmCtx->ctx, EVP_CTRL_CCM_SET_TAG, tagLen, NULL) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_EncryptUpdate(ccmCtx->ctx, NULL, &outlen, NULL, inLen) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (addLen > 0 && EVP_EncryptUpdate(ccmCtx->ctx, NULL, &outlen, add, addLen) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_EncryptUpdate(ccmCtx->ctx, output, &outlen, input, inLen) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_CIPHER_CTX_ctrl(ccmCtx->ctx, EVP_CTRL_CCM_GET_TAG, tagLen, tag) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* tag, size_t tagLen, unsigned char* output)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palCCM_t* ccmCtx = (palCCM_t*)ctx;
    int outlen = 0;
    if (EVP_DecryptInit_ex(ccmCtx->ctx, NULL, NULL, NULL, iv) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_CIPHER_CTX_ctrl(ccmCtx->ctx, EVP_CTRL_CCM_SET_IVLEN, ivLen, NULL) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_CIPHER_CTX_ctrl(ccmCtx->ctx, EVP_CTRL_CCM_SET_TAG, tagLen, tag) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_DecryptUpdate(ccmCtx->ctx, NULL, &outlen, NULL, inLen) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (addLen > 0 && EVP_DecryptUpdate(ccmCtx->ctx, NULL, &outlen, add, addLen) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_DecryptUpdate(ccmCtx->ctx, output, &outlen, input, inLen) != 1) {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    // If tag is wrong, OpenSSL will return error here
    return status;
}

palStatus_t pal_plat_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx)
{
    *ctx = 0;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx)
{
    *ctx = 0;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_CtrDRBGIsSeeded(palCtrDrbgCtxHandle_t ctx)
{
    // If using mbedtls with entropy sources, if the reseed_counter is 0 - this means seeding has not been done yet and generating a random number will not work
    // If not using mbedtls with entropy sources, reseed_counter will always be 0 and seeding is done in a lazy fashion
    // so we return the not seeded error so when pal_plat_CtrDRBGSeedFromEntropySources() is called, we will seed with the mock
    // entropy function and context as necessary
    return FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED;

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
    // Not needed for RAND_bytes
    return FCC_PAL_SUCCESS;
}

// FIXME: When pal_plat_CtrDRBGSeedFromEntropySources is public, this function should no longer be used
palStatus_t pal_plat_CtrDRBGSeed(palCtrDrbgCtxHandle_t ctx, const void* seed, size_t len)
{
    // Use seed as personalization string
    return pal_plat_CtrDRBGSeedFromEntropySources(ctx, NULL, seed, len);
}

palStatus_t pal_plat_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len)
{
    if (RAND_bytes(out, len) != 1) {
        return FCC_PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_CtrDRBGGenerateWithAdditional(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len, unsigned char* additional, size_t additionalLen)
{
    // RAND_bytes does not support additional input, just call RAND_bytes
    return pal_plat_CtrDRBGGenerate(ctx, out, len);
}

#if PAL_CMAC_SUPPORT
palStatus_t pal_plat_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    if (!ctx) return FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    const EVP_CIPHER *cipher = NULL;
    if (keyLenInBits == 128) {
        cipher = EVP_aes_128_cbc();
    } else if (keyLenInBits == 192) {
        cipher = EVP_aes_192_cbc();
    } else if (keyLenInBits == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        CMAC_CTX_free(ctx);
        return FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    }
    if (!CMAC_Init(ctx, key, keyLenInBits/8, cipher, NULL)) {
        CMAC_CTX_free(ctx);
        return FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    }
    if (!CMAC_Update(ctx, input, inputLenInBytes)) {
        CMAC_CTX_free(ctx);
        return FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    }
    size_t outlen = 0;
    if (!CMAC_Final(ctx, output, &outlen)) {
        CMAC_CTX_free(ctx);
        return FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    }
    CMAC_CTX_free(ctx);
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID)
{
    if (!ctx) return FCC_PAL_ERR_INVALID_ARGUMENT;
    CMAC_CTX *cmacCtx = CMAC_CTX_new();
    if (!cmacCtx) return FCC_PAL_ERR_NO_MEMORY;
    const EVP_CIPHER *cipher = NULL;
    if (keyLenBits == 128) {
        cipher = EVP_aes_128_cbc();
    } else if (keyLenBits == 192) {
        cipher = EVP_aes_192_cbc();
    } else if (keyLenBits == 256) {
        cipher = EVP_aes_256_cbc();
    } else {
        CMAC_CTX_free(cmacCtx);
        return FCC_PAL_ERR_INVALID_CIPHER_ID;
    }
    if (!CMAC_Init(cmacCtx, key, keyLenBits/8, cipher, NULL)) {
        CMAC_CTX_free(cmacCtx);
        return FCC_PAL_ERR_CMAC_GENERIC_FAILURE;
    }
    *ctx = (palCMACHandle_t)cmacCtx;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen)
{
    if (!ctx) return FCC_PAL_ERR_INVALID_ARGUMENT;
    CMAC_CTX *cmacCtx = (CMAC_CTX*)ctx;
    if (!CMAC_Update(cmacCtx, input, inLen)) {
        return FCC_PAL_ERR_CMAC_UPDATE_FAILED;
    }
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen)
{
    if (!ctx || !*ctx) return FCC_PAL_ERR_INVALID_ARGUMENT;
    CMAC_CTX *cmacCtx = (CMAC_CTX*)*ctx;
    size_t outlen = 0;
    if (!CMAC_Final(cmacCtx, output, &outlen)) {
        CMAC_CTX_free(cmacCtx);
        *ctx = NULLPTR;
        return FCC_PAL_ERR_CMAC_FINISH_FAILED;
    }
    if (outLen) *outLen = outlen;
    CMAC_CTX_free(cmacCtx);
    *ctx = NULLPTR;
    return FCC_PAL_SUCCESS;
}
#endif //PAL_CMAC_SUPPORT

palStatus_t pal_plat_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes)
{
    unsigned int outlen = 0;
    palStatus_t status = FCC_PAL_SUCCESS;

    if (!key || !input || !output) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    // OpenSSL HMAC with SHA256
    if (!HMAC(EVP_sha256(), key, (int)keyLenInBytes, input, inputLenInBytes, output, &outlen)) {
        FCC_PAL_LOG_ERR("Crypto HMAC-SHA256 failed");
        status = FCC_PAL_ERR_HMAC_GENERIC_FAILURE;
    } else {
        if (outputLenInBytes) {
            *outputLenInBytes = (size_t)outlen;
        }
    }

    return status;
}
//! Check EC private key function. 
static palStatus_t pal_plat_ECCheckPrivateKey(palECGroup_t* ecpGroup, palECKeyHandle_t key, bool *verified)
{
    palECKey_t* privateKey = (palECKey_t*)key;
    *verified = false;
    if (!privateKey || !privateKey->pkey) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(privateKey->pkey);
    if (!ec) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    // If ecpGroup is provided, check that the EC_KEY's group matches
    if (ecpGroup != NULL) {
        const EC_GROUP *key_group = EC_KEY_get0_group(ec);
        if (!key_group || EC_GROUP_cmp(key_group, ecpGroup, NULL) != 0) {
            EC_KEY_free(ec);
            return FCC_PAL_ERR_INVALID_ARGUMENT;
        }
    }

    int ok = EC_KEY_check_key(ec);
    EC_KEY_free(ec);
    if (ok == 1) {
        *verified = true;
        return FCC_PAL_SUCCESS;
    } else {
        return FCC_PAL_ERR_PRIVATE_KEY_VARIFICATION_FAILED;
    }
}

//! Check EC public key function.
static palStatus_t pal_plat_ECCheckPublicKey(palECGroup_t* ecpGroup, palECKeyHandle_t key, bool *verified)
{
    palECKey_t* publicKey = (palECKey_t*)key;
    *verified = false;
    if (!publicKey || !publicKey->pkey) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(publicKey->pkey);
    if (!ec) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    // If ecpGroup is provided, check that the EC_KEY's group matches
    if (ecpGroup != NULL) {
        const EC_GROUP *key_group = EC_KEY_get0_group(ec);
        if (!key_group || EC_GROUP_cmp(key_group, ecpGroup, NULL) != 0) {
            EC_KEY_free(ec);
            return FCC_PAL_ERR_INVALID_ARGUMENT;
        }
    }

    const EC_POINT *pub = EC_KEY_get0_public_key(ec);
    if (!pub) {
        EC_KEY_free(ec);
        return FCC_PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED;
    }
    int ok = EC_KEY_check_key(ec);
    EC_KEY_free(ec);
    if (ok == 1) {
        *verified = true;
        return FCC_PAL_SUCCESS;
    } else {
        return FCC_PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED;
    }
}

palStatus_t pal_plat_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified)
{
    *verified = false;
    palStatus_t status = FCC_PAL_SUCCESS;
    if ((PAL_CHECK_PRIVATE_KEY & type) != 0)
        status = pal_plat_ECCheckPrivateKey(NULL, key, verified);
    if ((FCC_PAL_SUCCESS == status) && ((PAL_CHECK_PUBLIC_KEY & type) != 0))
        status = pal_plat_ECCheckPublicKey(NULL, key, verified);
    return status;
}

palStatus_t pal_plat_ECKeyNew(palECKeyHandle_t* key)
{
    palECKey_t* localECKey = (palECKey_t*)malloc(sizeof(palECKey_t));
    if (!localECKey) {
        return FCC_PAL_ERR_NO_MEMORY;
    }
    localECKey->pkey = NULL;
    *key = (palECKeyHandle_t)localECKey;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_ECKeyFree(palECKeyHandle_t* key)
{
    if (!key || !*key) return FCC_PAL_SUCCESS;
    palECKey_t* localECKey = (palECKey_t*)*key;
    if (localECKey->pkey) {
        EVP_PKEY_free(localECKey->pkey);
        localECKey->pkey = NULL;
    }
    free(localECKey);
    *key = NULLPTR;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key)
{
    palECKey_t* localECKey = (palECKey_t*)key;
    if (!localECKey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    int nid;
    switch (grpID) {
        case PAL_ECP_DP_SECP256R1:
            nid = NID_X9_62_prime256v1;
            break;
        default:
            return FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
    }
    EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) return FCC_PAL_ERR_KEYPAIR_GEN_FAIL;
    if (EC_KEY_generate_key(ec) != 1) {
        EC_KEY_free(ec);
        return FCC_PAL_ERR_KEYPAIR_GEN_FAIL;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(ec);
        return FCC_PAL_ERR_KEYPAIR_GEN_FAIL;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EVP_PKEY_free(pkey);
        EC_KEY_free(ec);
        return FCC_PAL_ERR_KEYPAIR_GEN_FAIL;
    }
    if (localECKey->pkey) EVP_PKEY_free(localECKey->pkey);
    localECKey->pkey = pkey;
    return FCC_PAL_SUCCESS;
}


palStatus_t pal_plat_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID)
{
    palECKey_t* localECKey = (palECKey_t*)key;
    if (!localECKey || !localECKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(localECKey->pkey);
    if (!ec) return FCC_PAL_ERR_INVALID_ARGUMENT;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    int nid = group ? EC_GROUP_get_curve_name(group) : 0;
    EC_KEY_free(ec);
    switch (nid) {
        case NID_X9_62_prime256v1:
            *grpID = PAL_ECP_DP_SECP256R1;
            break;
        default:
            *grpID = PAL_ECP_DP_NONE;
            return FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
    }
    return FCC_PAL_SUCCESS;
}

// typedef EC_GROUP palECGroupOpenSSL_t;

palStatus_t pal_plat_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index)
{
    int nid;
    switch (index) {
        case PAL_ECP_DP_SECP256R1:
            nid = NID_X9_62_prime256v1;
            break;
        default:
            return FCC_PAL_ERR_NOT_SUPPORTED_CURVE;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
    if (!group) return FCC_PAL_ERR_GROUP_LOAD_FAILED;
    *grp = (palCurveHandle_t)group;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_ECGroupFree(palCurveHandle_t* grp)
{
    if (!grp || !*grp) return FCC_PAL_SUCCESS;
    EC_GROUP *group = (EC_GROUP*)*grp;
    EC_GROUP_free(group);
    *grp = NULLPTR;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, const palECKeyHandle_t privateKey, palECKeyHandle_t outKey)
{
    // Use OpenSSL ECDH APIs to compute the shared secret
    if (!peerPublicKey || !privateKey || !outKey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    palECKey_t* peerKey = (palECKey_t*)peerPublicKey;
    palECKey_t* privKey = (palECKey_t*)privateKey;
    palECKey_t* outECKey = (palECKey_t*)outKey;
    if (!peerKey->pkey || !privKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    EC_KEY *ec_priv = EVP_PKEY_get1_EC_KEY(privKey->pkey);
    EC_KEY *ec_peer = EVP_PKEY_get1_EC_KEY(peerKey->pkey);
    if (!ec_priv || !ec_peer) {
        if (ec_priv) EC_KEY_free(ec_priv);
        if (ec_peer) EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    const EC_POINT *pub_point = EC_KEY_get0_public_key(ec_peer);
    const EC_GROUP *group = EC_KEY_get0_group(ec_priv);
    int field_size = EC_GROUP_get_degree(group);
    int secret_len = (field_size + 7) / 8;
    unsigned char *secret = (unsigned char*)malloc(secret_len);
    if (!secret) {
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_NO_MEMORY;
    }
    int ret = ECDH_compute_key(secret, secret_len, pub_point, ec_priv, NULL);
    if (ret <= 0) {
        free(secret);
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
    }
    // Store the shared secret in outKey as a new EC_KEY with the secret as private value (for compatibility)
    // In practice, you may want to return the secret directly, or use a different API
    // Here, we just set the private value of outKey to the shared secret (not standard usage)
    // You may want to adapt this to your needs
    EC_KEY *ec_out = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(group));
    if (!ec_out) {
        free(secret);
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_NO_MEMORY;
    }
    BIGNUM *bn = BN_bin2bn(secret, ret, NULL);
    if (!bn) {
        EC_KEY_free(ec_out);
        free(secret);
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_NO_MEMORY;
    }
    if (EC_KEY_set_private_key(ec_out, bn) != 1) {
        BN_free(bn);
        EC_KEY_free(ec_out);
        free(secret);
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
    }
    BN_free(bn);
    EVP_PKEY *pkey_out = EVP_PKEY_new();
    if (!pkey_out) {
        EC_KEY_free(ec_out);
        free(secret);
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_NO_MEMORY;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey_out, ec_out) != 1) {
        EVP_PKEY_free(pkey_out);
        EC_KEY_free(ec_out);
        free(secret);
        EC_KEY_free(ec_priv);
        EC_KEY_free(ec_peer);
        return FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
    }
    if (outECKey->pkey) EVP_PKEY_free(outECKey->pkey);
    outECKey->pkey = pkey_out;
    free(secret);
    EC_KEY_free(ec_priv);
    EC_KEY_free(ec_peer);
    return FCC_PAL_SUCCESS;
}

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

/**
 * Map OpenSSL error codes to PAL error codes.
 * This function is a replacement for the mbedtls error mapping, using OpenSSL error codes.
 */
static palStatus_t pal_plat_pkOpensslToPalError(int32_t opensslErr)
{
    palStatus_t status = FCC_PAL_SUCCESS;

    // OpenSSL error codes are negative, 0 means success
    if (opensslErr == 0) {
        return FCC_PAL_SUCCESS;
    }

    // Map some common OpenSSL error codes to PAL error codes
    // See openssl/err.h and openssl/x509.h for error codes
    switch (opensslErr) {
        case EVP_R_UNKNOWN_KEY_TYPE:
        case EVP_R_UNSUPPORTED_ALGORITHM:
            status = FCC_PAL_ERR_PK_UNKNOWN_PK_ALG;
            break;
        case EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM:
            status = FCC_PAL_ERR_PK_KEY_INVALID_FORMAT;
            break;
        case EVP_R_DECODE_ERROR:
        case EVP_R_BAD_DECRYPT:
        case EVP_R_BAD_KEY_LENGTH:
        case EVP_R_MISSING_PARAMETERS:
        case EVP_R_NO_KEY_SET:
        case EVP_R_PRIVATE_KEY_DECODE_ERROR:
        case EVP_R_EXPECTING_AN_RSA_KEY:
        case EVP_R_EXPECTING_A_DSA_KEY:
        case EVP_R_EXPECTING_A_DH_KEY:
        case EVP_R_EXPECTING_A_EC_KEY:
        case EVP_R_INVALID_KEY_LENGTH:
            status = FCC_PAL_ERR_ECP_INVALID_KEY;
            break;
        case PEM_R_BAD_PASSWORD_READ:
            status = FCC_PAL_ERR_PK_PASSWORD_REQUIRED;
            break;
        default:
            // For unknown errors, return a generic crypto error
            status = FCC_PAL_ERR_CRYPTO_ERROR_BASE;
            break;
    }
    return status;
}
palStatus_t pal_plat_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key)
{
    palECKey_t* localECKey = (palECKey_t*)key;
    if (!localECKey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    if (pal_plat_isPEM(prvDERKey, keyLen)) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    const unsigned char *p = prvDERKey;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, keyLen);
    if (!pkey) {
        return FCC_PAL_ERR_PARSING_PRIVATE_KEY;
    }
    if (localECKey->pkey) EVP_PKEY_free(localECKey->pkey);
    localECKey->pkey = pkey;
    return FCC_PAL_SUCCESS;
}
palStatus_t pal_plat_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key)
{
    palECKey_t* localECKey = (palECKey_t*)key;
    if (!localECKey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    if (pal_plat_isPEM(pubDERKey, keyLen)) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    const unsigned char *p = pubDERKey;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, keyLen);
    if (!pkey) {
        return FCC_PAL_ERR_PARSING_PUBLIC_KEY;
    }
    if (localECKey->pkey) EVP_PKEY_free(localECKey->pkey);
    localECKey->pkey = pkey;
    return FCC_PAL_SUCCESS;
}
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
    palECKey_t* localECKey = (palECKey_t*)key;
    if (!localECKey || !localECKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    int len = i2d_PrivateKey(localECKey->pkey, NULL);
    if (len <= 0 || (size_t)len > bufferSize) {
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    unsigned char* p = derBuffer;
    int written = i2d_PrivateKey(localECKey->pkey, &p);
    if (written != len) {
        return FCC_PAL_ERR_FAILED_TO_WRITE_PRIVATE_KEY;
    }
    *actualSize = (size_t)written;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    palECKey_t* localECKey = (palECKey_t*)key;
    if (!localECKey || !localECKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;
    int len = i2d_PUBKEY(localECKey->pkey, NULL);
    if (len <= 0 || (size_t)len > bufferSize) {
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    unsigned char* p = derBuffer;
    int written = i2d_PUBKEY(localECKey->pkey, &p);
    if (written != len) {
        return FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY;
    }
    *actualSize = (size_t)len;

    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_convertRawSignatureToDer(
    const unsigned char *rawSignature, size_t rawSignatureSize,
    unsigned char *derSignatureOut, size_t derSignatureMaxSize, size_t *derSignatureActSizeOut)
{
    if (rawSignatureSize != PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE) return FCC_PAL_ERR_INVALID_ARGUMENT;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) return FCC_PAL_ERR_NO_MEMORY;

    BIGNUM *r = BN_bin2bn(rawSignature, rawSignatureSize/2, NULL);
    BIGNUM *s = BN_bin2bn(rawSignature + rawSignatureSize/2, rawSignatureSize/2, NULL);
    if (!r || !s) {
        ECDSA_SIG_free(sig);
        if (r) BN_free(r);
        if (s) BN_free(s);
        return FCC_PAL_ERR_NO_MEMORY;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_free(sig->r);
    BN_free(sig->s);
    sig->r = r;
    sig->s = s;
#else
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
#endif
    int derlen = i2d_ECDSA_SIG(sig, NULL);
    if (derlen <= 0 || (size_t)derlen > derSignatureMaxSize) {
        ECDSA_SIG_free(sig);
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    unsigned char *p = derSignatureOut;
    derlen = i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    if (derlen <= 0) return FCC_PAL_ERR_GENERIC_FAILURE;
    *derSignatureActSizeOut = (size_t)derlen;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_asymmetricSign(
    palECKeyHandle_t privateKeyHandle,
    palMDType_t mdType,
    const unsigned char *hash,
    size_t hashSize,
    unsigned char *outSignature,
    size_t maxSignatureSize,
    size_t *actualOutSignatureSize)
{
    palECKey_t* localECKey = (palECKey_t*)privateKeyHandle;
    size_t rawSignatureSize = PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE;

    if (!localECKey || !localECKey->pkey) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    if (mdType != PAL_SHA256) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    if (maxSignatureSize < rawSignatureSize) {
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }

    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(localECKey->pkey);
    if (!ec) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    ECDSA_SIG *sig = ECDSA_do_sign(hash, hashSize, ec);
    EC_KEY_free(ec);
    if (!sig) {
        return FCC_PAL_ERR_FAILED_TO_WRITE_SIGNATURE;
    }

    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2binpad(r, outSignature, rawSignatureSize/2);
    BN_bn2binpad(s, outSignature + rawSignatureSize/2, rawSignatureSize/2);
    *actualOutSignatureSize = rawSignatureSize;
    ECDSA_SIG_free(sig);
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_ECDHKeyAgreement(
    const uint8_t               *derPeerPublicKey,
    size_t                       derPeerPublicKeySize,
    const palECKeyHandle_t       privateKeyHandle,
    unsigned char               *rawSharedSecretOut,
    size_t                       rawSharedSecretMaxSize,
    size_t                      *rawSharedSecretActSizeOut)
{
    palECKey_t* privKey = (palECKey_t*)privateKeyHandle;
    if (!privKey || !privKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;

    // Parse peer public key
    const unsigned char *p = derPeerPublicKey;
    EVP_PKEY *peerPkey = d2i_PUBKEY(NULL, &p, derPeerPublicKeySize);
    if (!peerPkey) return FCC_PAL_ERR_PARSING_PUBLIC_KEY;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey->pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peerPkey);
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peerPkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerPkey);
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, NULL, &secretLen) <= 0 ||
        secretLen > rawSharedSecretMaxSize) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerPkey);
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    if (EVP_PKEY_derive(ctx, rawSharedSecretOut, &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerPkey);
        return FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY;
    }
    *rawSharedSecretActSizeOut = secretLen;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerPkey);
    return FCC_PAL_SUCCESS;
}


palStatus_t pal_plat_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t* sigLen)
{
    (void)grp; // Not needed for OpenSSL
    palECKey_t* localECKey = (palECKey_t*)prvKey;
    if (!localECKey || !localECKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return FCC_PAL_ERR_NO_MEMORY;

    int rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, localECKey->pkey);
    if (rc != 1) {
        EVP_MD_CTX_free(mdctx);
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    size_t outlen = *sigLen;
    rc = EVP_DigestSign(mdctx, sig, &outlen, dgst, dgstLen);
    EVP_MD_CTX_free(mdctx);
    if (rc != 1) return FCC_PAL_ERR_FAILED_TO_WRITE_SIGNATURE;
    *sigLen = outlen;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t sigLen, bool* verified)
{
    palECKey_t* localECKey = (palECKey_t*)pubKey;
    if (!localECKey || !localECKey->pkey) return FCC_PAL_ERR_INVALID_ARGUMENT;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return FCC_PAL_ERR_NO_MEMORY;

    int rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, localECKey->pkey);
    if (rc != 1) {
        EVP_MD_CTX_free(mdctx);
        *verified = false;
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
    rc = EVP_DigestVerify(mdctx, sig, sigLen, dgst, dgstLen);
    EVP_MD_CTX_free(mdctx);
    if (rc == 1) {
        *verified = true;
        return FCC_PAL_SUCCESS;
    } else {
        *verified = false;
        return FCC_PAL_ERR_FAILED_TO_VERIFY_SIGNATURE;
    }
}

palStatus_t pal_plat_asymmetricVerify(
    palECKeyHandle_t publicKeyHandle,
    palMDType_t mdType,
    const unsigned char *hash,
    size_t hashSize,
    const unsigned char *signature,
    size_t signatureSize)
{
    palECKey_t* localECKey = (palECKey_t*)publicKeyHandle;
    if (!localECKey || !localECKey->pkey) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    if (mdType != PAL_SHA256) {
        return FCC_PAL_ERR_INVALID_MD_TYPE;
    }
    if (hashSize != PAL_SHA256_SIZE) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    if (signatureSize != PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    // Convert raw signature to ECDSA_SIG
    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) return FCC_PAL_ERR_NO_MEMORY;
    BIGNUM *r = BN_bin2bn(signature, signatureSize/2, NULL);
    BIGNUM *s = BN_bin2bn(signature + signatureSize/2, signatureSize/2, NULL);
    if (!r || !s) {
        ECDSA_SIG_free(sig);
        if (r) BN_free(r);
        if (s) BN_free(s);
        return FCC_PAL_ERR_NO_MEMORY;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_free(sig->r);
    BN_free(sig->s);
    sig->r = r;
    sig->s = s;
#else
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
#endif
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(localECKey->pkey);
    if (!ec) {
        ECDSA_SIG_free(sig);
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }
    int rc = ECDSA_do_verify(hash, hashSize, sig, ec);
    EC_KEY_free(ec);
    ECDSA_SIG_free(sig);
    if (rc == 1) {
        return FCC_PAL_SUCCESS;
    } else if (rc == 0) {
        return FCC_PAL_ERR_FAILED_TO_VERIFY_SIGNATURE;
    } else {
        return FCC_PAL_ERR_GENERIC_FAILURE;
    }
}



#if (PAL_ENABLE_X509 == 1)
palStatus_t pal_plat_x509CSRInit(palx509CSRHandle_t *x509CSR)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)malloc(sizeof(palx509CSR_t));
    if (NULL == localCSR) {
        status = FCC_PAL_ERR_NO_MEMORY;
    } else {
        localCSR->req = X509_REQ_new();
        if (!localCSR->req) {
            free(localCSR);
            return FCC_PAL_ERR_NO_MEMORY;
        }
        *x509CSR = (palx509CSRHandle_t)localCSR;
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    X509_NAME *name = X509_NAME_new();
    if (!name) return FCC_PAL_ERR_NO_MEMORY;
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)subjectName, -1, -1, 0)) {
        X509_NAME_free(name);
        return FCC_PAL_ERR_X509_INVALID_NAME;
    }
    if (!X509_REQ_set_subject_name(localCSR->req, name)) {
        X509_NAME_free(name);
        return FCC_PAL_ERR_X509_INVALID_NAME;
    }
    X509_NAME_free(name);
    return status;
}

palStatus_t pal_plat_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    palECKey_t* localPrvKey = (palECKey_t*)prvKey;
    // Only private key is needed for signing
    EVP_PKEY *pkey = NULL;
    // TODO: Convert palECKey_t to EVP_PKEY*
    // For now, assume palECKey_t is a wrapper for EVP_PKEY*
    pkey = (EVP_PKEY*)localPrvKey->pkey;
    if (!X509_REQ_set_pubkey(localCSR->req, pkey)) {
        return FCC_PAL_ERR_FAILED_TO_COPY_KEYPAIR;
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType)
{
    // OpenSSL does not set the digest on the X509_REQ directly; it is set during signing
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    X509_EXTENSION *ext = NULL;
    ASN1_BIT_STRING *usage = NULL;
    int openssl_usage = 0;

    // Map PAL key usage flags to OpenSSL X509v3 KeyUsage bits
    if (PAL_X509_KU_DIGITAL_SIGNATURE & keyUsage)
        openssl_usage |= KU_DIGITAL_SIGNATURE;
    if (PAL_X509_KU_NON_REPUDIATION & keyUsage)
        openssl_usage |= KU_NON_REPUDIATION;
    if (PAL_X509_KU_KEY_CERT_SIGN & keyUsage)
        openssl_usage |= KU_KEY_CERT_SIGN;
    if (PAL_X509_KU_KEY_AGREEMENT & keyUsage)
        openssl_usage |= KU_KEY_AGREEMENT;

    if (openssl_usage == 0) {
        return FCC_PAL_ERR_INVALID_KEY_USAGE;
    }

    // Create ASN1_BIT_STRING for key usage
    usage = ASN1_BIT_STRING_new();
    if (!usage) {
        return FCC_PAL_ERR_NO_MEMORY;
    }
    if (!ASN1_BIT_STRING_set_bit(usage, 0, (openssl_usage & KU_DIGITAL_SIGNATURE) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 1, (openssl_usage & KU_NON_REPUDIATION) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 2, (openssl_usage & KU_KEY_ENCIPHERMENT) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 3, (openssl_usage & KU_DATA_ENCIPHERMENT) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 4, (openssl_usage & KU_KEY_AGREEMENT) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 5, (openssl_usage & KU_KEY_CERT_SIGN) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 6, (openssl_usage & KU_CRL_SIGN) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 7, (openssl_usage & KU_ENCIPHER_ONLY) ? 1 : 0) ||
        !ASN1_BIT_STRING_set_bit(usage, 8, (openssl_usage & KU_DECIPHER_ONLY) ? 1 : 0)) {
        ASN1_BIT_STRING_free(usage);
        return FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
    }

    // Create the extension
    ext = X509_EXTENSION_create_by_NID(NULL, NID_key_usage, 0, usage);
    ASN1_BIT_STRING_free(usage);
    if (!ext) {
        return FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
    }

    // Add the extension to the CSR
    if (!X509_REQ_add_extensions(localCSR->req, sk_X509_EXTENSION_new_null())) {
        X509_EXTENSION_free(ext);
        return FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
    }
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(localCSR->req);
    if (!exts) {
        X509_EXTENSION_free(ext);
        return FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
    }
    if (!sk_X509_EXTENSION_push(exts, ext)) {
        X509_EXTENSION_free(ext);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        return FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
    }
    // Set the extensions back to the CSR
    if (!X509_REQ_add_extensions(localCSR->req, exts)) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        return FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE;
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return status;
}

palStatus_t pal_plat_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    STACK_OF(ASN1_OBJECT) *eku_stack = NULL;
    X509_EXTENSION *ext = NULL;
    int failed = 0;

    // Define mapping from PAL_X509_EXT_KU_* to OIDs
    struct {
        uint32_t bit;
        const char *oid;
    } eku_oids[] = {
        { PAL_X509_EXT_KU_ANY,           "2.5.29.37.0" }, // anyExtendedKeyUsage
        { PAL_X509_EXT_KU_SERVER_AUTH,   "1.3.6.1.5.5.7.3.1" }, // serverAuth
        { PAL_X509_EXT_KU_CLIENT_AUTH,   "1.3.6.1.5.5.7.3.2" }, // clientAuth
        { PAL_X509_EXT_KU_CODE_SIGNING,  "1.3.6.1.5.5.7.3.3" }, // codeSigning
        { PAL_X509_EXT_KU_EMAIL_PROTECTION, "1.3.6.1.5.5.7.3.4" }, // emailProtection
        { PAL_X509_EXT_KU_TIME_STAMPING, "1.3.6.1.5.5.7.3.8" }, // timeStamping
        { PAL_X509_EXT_KU_OCSP_SIGNING,  "1.3.6.1.5.5.7.3.9" }, // OCSPSigning
    };

    uint32_t all_bits = 0;
    for (size_t i = 0; i < sizeof(eku_oids)/sizeof(eku_oids[0]); i++) {
        all_bits |= eku_oids[i].bit;
    }

    // Check if all options valid
    if ((extKeyUsage == 0) || (extKeyUsage & (~all_bits))) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    eku_stack = sk_ASN1_OBJECT_new_null();
    if (!eku_stack) {
        return FCC_PAL_ERR_NO_MEMORY;
    }

    for (size_t i = 0; i < sizeof(eku_oids)/sizeof(eku_oids[0]); i++) {
        if (extKeyUsage & eku_oids[i].bit) {
            ASN1_OBJECT *obj = OBJ_txt2obj(eku_oids[i].oid, 1);
            if (!obj) {
                failed = 1;
                break;
            }
            if (!sk_ASN1_OBJECT_push(eku_stack, obj)) {
                ASN1_OBJECT_free(obj);
                failed = 1;
                break;
            }
        }
    }

    if (!failed) {
        // Create the extension
        ext = X509V3_EXT_i2d(NID_ext_key_usage, 0, eku_stack);
        if (!ext) {
            failed = 1;
        }
    }

    if (!failed) {
        // Add the extension to the CSR
        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(localCSR->req);
        if (!exts) {
            exts = sk_X509_EXTENSION_new_null();
            if (!exts) {
                failed = 1;
            }
        }
        if (!failed && !sk_X509_EXTENSION_push(exts, ext)) {
            failed = 1;
        }
        if (!failed) {
            if (!X509_REQ_add_extensions(localCSR->req, exts)) {
                failed = 1;
            }
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        // Ownership of ext is transferred to exts, so don't free ext here
        ext = NULL;
    }

    if (eku_stack) {
        sk_ASN1_OBJECT_pop_free(eku_stack, ASN1_OBJECT_free);
    }
    if (ext) {
        X509_EXTENSION_free(ext);
    }

    if (failed) {
        status = FCC_PAL_ERR_FAILED_TO_SET_EXT_KEY_USAGE;
    }
    return status;
}

palStatus_t pal_plat_x509CSRSetExtension(palx509CSRHandle_t x509CSR, const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    ASN1_OBJECT *obj = NULL;
    X509_EXTENSION *ext = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    int failed = 0;

    if (!localCSR || !oid || oidLen == 0 || !value || valueLen == 0) {
        return FCC_PAL_ERR_SET_EXTENSION_FAILED;
    }

    // Create ASN1_OBJECT from OID string
    char oid_str[128] = {0};
    if (oidLen >= sizeof(oid_str)) {
        return FCC_PAL_ERR_SET_EXTENSION_FAILED;
    }
    memcpy(oid_str, oid, oidLen);
    oid_str[oidLen] = '\0';

    obj = OBJ_txt2obj(oid_str, 1);
    if (!obj) {
        failed = 1;
        goto cleanup;
    }

    // Create ASN1_OCTET_STRING from value
    ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
    if (!octet) {
        failed = 1;
        goto cleanup;
    }
    if (!ASN1_OCTET_STRING_set(octet, value, valueLen)) {
        ASN1_OCTET_STRING_free(octet);
        failed = 1;
        goto cleanup;
    }

    // Create the extension
    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, octet);
    ASN1_OCTET_STRING_free(octet);
    if (!ext) {
        failed = 1;
        goto cleanup;
    }

    // Get or create the extensions stack
    exts = X509_REQ_get_extensions(localCSR->req);
    if (!exts) {
        exts = sk_X509_EXTENSION_new_null();
        if (!exts) {
            failed = 1;
            goto cleanup;
        }
    }

    if (!sk_X509_EXTENSION_push(exts, ext)) {
        failed = 1;
        goto cleanup;
    }

    // Add the extensions to the CSR
    if (!X509_REQ_add_extensions(localCSR->req, exts)) {
        failed = 1;
        goto cleanup;
    }

cleanup:
    if (exts) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    } else if (ext) {
        X509_EXTENSION_free(ext);
    }
    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    if (failed) {
        status = FCC_PAL_ERR_SET_EXTENSION_FAILED;
    }
    return status;
}

palStatus_t pal_plat_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen)
{
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;
    int len = i2d_X509_REQ(localCSR->req, NULL);
    if (len < 0 || (size_t)len > derBufLen) {
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    unsigned char *p = derBuf;
    len = i2d_X509_REQ(localCSR->req, &p);
    if (len < 0) {
        return FCC_PAL_ERR_CSR_WRITE_DER_FAILED;
    }
    *actualDerLen = (size_t)len;
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_x509CSRFree(palx509CSRHandle_t *x509CSR)
{
    palx509CSR_t* localCSR = (palx509CSR_t*)*x509CSR;
    if (localCSR) {
        if (localCSR->req) X509_REQ_free(localCSR->req);
        free(localCSR);
        *x509CSR = NULLPTR;
    }
    return FCC_PAL_SUCCESS;
}

palStatus_t pal_plat_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    palX509Ctx_t *crt_ctx = (palX509Ctx_t*)x509Cert;

    if (!crt_ctx || !crt_ctx->crt || !output || !actualOutLenBytes) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    switch (hash_type) {
        case PAL_SHA256:
            if (outLenBytes < PAL_SHA256_SIZE) {
                status = FCC_PAL_ERR_BUFFER_TOO_SMALL;
                break;
            }
            {
                // Get the TBS (to-be-signed) portion of the certificate
                // In OpenSSL, this is available as X509_CINF* in X509->cert_info
                // We need to DER-encode this structure and hash it
                int tbs_len = i2d_X509_CINF(crt_ctx->crt, NULL);
                if (tbs_len <= 0) {
                    status = FCC_PAL_ERR_CRYPTO_ERROR_BASE;
                    break;
                }
                unsigned char *tbs_buf = (unsigned char*)malloc(tbs_len);
                if (!tbs_buf) {
                    status = FCC_PAL_ERR_NO_MEMORY;
                    break;
                }
                unsigned char *p = tbs_buf;
                int tbs_len2 = i2d_X509_CINF(crt_ctx->crt, &p);
                if (tbs_len2 != tbs_len) {
                    free(tbs_buf);
                    status = FCC_PAL_ERR_CRYPTO_ERROR_BASE;
                    break;
                }
                status = pal_plat_sha256(tbs_buf, tbs_len, output);
                free(tbs_buf);
                if (status == FCC_PAL_SUCCESS) {
                    *actualOutLenBytes = PAL_SHA256_SIZE;
                }
            }
            break;
        default:
            status = FCC_PAL_ERR_INVALID_MD_TYPE;
            break;
    }
    return status;
}

palStatus_t pal_plat_x509CSRFromCertWriteDER(palX509Handle_t x509Cert, palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerBufLen)
{
    palX509Ctx_t *localCert = (palX509Ctx_t*)x509Cert;
    palx509CSR_t *localCSR = (palx509CSR_t*)x509CSR;

    if (!localCert || !localCert->crt || !localCSR || !localCSR->req || !derBuf || !actualDerBufLen) {
        return FCC_PAL_ERR_INVALID_ARGUMENT;
    }

    // 1. Extract subject from certificate and set it to CSR
    X509_NAME *subject = X509_get_subject_name(localCert->crt);
    if (!subject) {
        return FCC_PAL_ERR_INVALID_X509_ATTR;
    }
    // Set subject name to CSR
    if (X509_REQ_set_subject_name(localCSR->req, subject) != 1) {
        return FCC_PAL_ERR_INVALID_X509_ATTR;
    }

    // 2. Set message digest algorithm for CSR
    // Use the same digest as the certificate, if possible
    const X509_ALGOR *sigalg = NULL;
    int pknid = NID_undef;
    int mdnid = NID_undef;
    X509_get0_signature(NULL, &sigalg, localCert->crt);
    if (sigalg) {
        OBJ_find_sigid_algs(OBJ_obj2nid(sigalg->algorithm), &mdnid, &pknid);
    }
    const EVP_MD *md = NULL;
    if (mdnid != NID_undef) {
        md = EVP_get_digestbynid(mdnid);
    }
    if (!md) {
        md = EVP_sha256(); // fallback to SHA256
    }

    // 3. Copy extensions from certificate to CSR (if needed)
    // OpenSSL does not natively support copying extensions to CSR in a simple way.
    // This is a TODO for future implementation if needed.

    // 4. Sign the CSR with the same digest
    // The private key must already be set in the CSR object
    EVP_PKEY *pkey = X509_REQ_get_pubkey(localCSR->req);
    if (!pkey) {
        // Try to get private key from CSR (if set)
        pkey = X509_REQ_get0_pubkey(localCSR->req);
    }
    // Actually, for signing, we need the private key, which should be set in palx509CSR_t
    // We assume the palx509CSR_t->req has the private key set via X509_REQ_set_pubkey before this call

    // Write the CSR to DER buffer
    int len = i2d_X509_REQ(localCSR->req, NULL);
    if (len <= 0 || (size_t)len > derBufLen) {
        return FCC_PAL_ERR_BUFFER_TOO_SMALL;
    }
    unsigned char *p = derBuf;
    int written = i2d_X509_REQ(localCSR->req, &p);
    if (written != len) {
        return FCC_PAL_ERR_CRYPTO_ERROR_BASE;
    }
    *actualDerBufLen = (size_t)written;

    return FCC_PAL_SUCCESS;
}

#endif

static int pal_plat_entropySourceDRBG( void *data, unsigned char *output, size_t len)
{
    PV_UNUSED_PARAM(data);
    PV_UNUSED_PARAM(output);
    PV_UNUSED_PARAM(len);
    // No-op for OpenSSL RAND_bytes; always return success
    return CRYPTO_PLAT_SUCCESS;
}

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
        FCC_PAL_LOG_ERR("pal_osRandomBuffer failed in pal_plat_entropySource");
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


#endif // MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL