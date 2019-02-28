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

#define TRACE_GROUP "PAL"

palStatus_t pal_initAes(palAesHandle_t *aes)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes))

    status = pal_plat_initAes(aes);
    return status;
}

palStatus_t pal_freeAes(palAesHandle_t *aes)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == aes || (uintptr_t)NULL == *aes))

    status = pal_plat_freeAes(aes);
    return status;
}

palStatus_t pal_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == key))

    status = pal_plat_setAesKey(aes, key, keybits, keyTarget);
    return status;
}

palStatus_t pal_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16])
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == input || NULL == output || NULL == iv))

    status = pal_plat_aesCTR(aes, input, output, inLen, iv, false);
    return status;
}

palStatus_t pal_aesCTRWithZeroOffset(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16])
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == input || NULL == output || NULL == iv))

    status = pal_plat_aesCTR(aes, input, output, inLen, iv, true);
    return status;
}

palStatus_t pal_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == input || NULL == output))

    status = pal_plat_aesECB(aes, input, output, mode);
    return status;
}

palStatus_t pal_sha256(const unsigned char* input, size_t inLen, unsigned char* output)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == input || NULL == output))

    status = pal_plat_sha256(input, inLen, output);
    return status;
}

palStatus_t pal_x509Initiate(palX509Handle_t* x509Cert)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS( (NULL == x509Cert))

    status = pal_plat_x509Initiate(x509Cert);
    return status;
#else
	return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CertParse(palX509Handle_t x509Cert, const unsigned char* input, size_t inLen)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert || NULL == input))

    status = pal_plat_x509CertParse(x509Cert, input, inLen);
    return status;
#else
	return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert || NULL == output || NULL == actualOutLenBytes))

    status = pal_plat_x509CertGetAttribute(x509Cert, attr, output, outLenBytes, actualOutLenBytes);
    return status;
#else
	return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert) || (NULL == verifyResult))
    *verifyResult = 0;
#if (PAL_ENABLE_X509 == 1)
    status = pal_plat_x509CertVerifyExtended(x509Cert, x509CertChain, verifyResult);
    if (0 != *verifyResult)
    {
        status = PAL_ERR_X509_CERT_VERIFY_FAILED;
        *verifyResult = *verifyResult ^ PAL_ERR_MODULE_BITMASK_BASE; //! in order to turn off the MSB bit.
    }
#endif
    return status;
}

palStatus_t pal_x509CertVerify(palX509Handle_t x509Cert, palX509Handle_t x509CertChain)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    int32_t verifyResult = 0;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert))

    status = pal_plat_x509CertVerifyExtended(x509Cert, x509CertChain, &verifyResult);
    return status;
#else
	return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509Free(palX509Handle_t* x509Cert)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert || NULLPTR == *x509Cert))

    status = pal_plat_x509Free(x509Cert);
    return status;
#else
	return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md))

    status = pal_plat_mdInit(md, mdType);
    return status;
}

palStatus_t pal_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULL == input))

    status = pal_plat_mdUpdate(md, input, inLen);
    return status;
}

palStatus_t pal_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULL == bufferSize))

    status = pal_plat_mdGetOutputSize(md, bufferSize);
    return status;
}

palStatus_t pal_mdFinal(palMDHandle_t md, unsigned char* output)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULL == output))

    status = pal_plat_mdFinal(md, output);
    return status;
}

palStatus_t pal_mdFree(palMDHandle_t* md)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULLPTR == *md))

    status = pal_plat_mdFree(md);
    return status;
}

palStatus_t pal_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509 || NULL == hash || NULL == sig))

    status = pal_plat_verifySignature(x509, mdType, hash, hashLen, sig, sigLen);
    return status;
#else
	return PAL_ERR_NOT_SUPPORTED;
#endif
}
 
palStatus_t pal_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag )
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == position || NULL == end || NULL == len))
    
    status = pal_plat_ASN1GetTag(position, end, len, tag);
    return status;
}

palStatus_t pal_CCMInit(palCCMHandle_t* ctx)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == ctx))

    status = pal_plat_CCMInit(ctx);
    return status;
}

palStatus_t pal_CCMFree(palCCMHandle_t* ctx)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == ctx || NULLPTR == *ctx))

    status = pal_plat_CCMFree(ctx);
    return status;
}

palStatus_t pal_CCMSetKey(palCCMHandle_t ctx, const unsigned char *key, uint32_t keybits, palCipherID_t id)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == key))

    status = pal_plat_CCMSetKey(ctx, id, key, keybits);
    return status;
}

palStatus_t pal_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, 
							unsigned char* iv, size_t ivLen, unsigned char* add, 
							size_t addLen, unsigned char* tag, size_t tagLen, 
							unsigned char* output)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == input || NULL == iv || NULL == add || NULL == tag || NULL == output))

    status = pal_plat_CCMDecrypt(ctx, input, inLen, iv, ivLen, add, addLen, tag, tagLen, output);
    return status;
}

palStatus_t pal_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, 
							size_t inLen, unsigned char* iv, size_t ivLen, 
							unsigned char* add, size_t addLen, unsigned char* output, 
							unsigned char* tag, size_t tagLen)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == input || NULL == iv || NULL == add || NULL == tag || NULL == output))

    status = pal_plat_CCMEncrypt(ctx, input, inLen, iv, ivLen, add, addLen, output, tag, tagLen);
    return status;
}

palStatus_t pal_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx, const void* seed, size_t len)
{
    palStatus_t status = PAL_SUCCESS;

    PAL_VALIDATE_ARGUMENTS((NULL == ctx || NULL == seed))

    status = pal_plat_CtrDRBGInit(ctx);
    if (PAL_SUCCESS == status)
    {
        status = pal_plat_CtrDRBGSeed(*ctx, seed, len);
        if (PAL_SUCCESS != status)
        {
            palStatus_t tmpStatus = PAL_SUCCESS;
            tmpStatus = pal_CtrDRBGFree(ctx);
            if (PAL_SUCCESS != tmpStatus)
            {
                PAL_LOG_ERR("Failed to release CTR-DRBG context %" PRId32 ".", tmpStatus);
            }
        }
    }

    return status;
}

palStatus_t pal_CtrDRBGIsSeeded(palCtrDrbgCtxHandle_t ctx)
{
    palStatus_t status = PAL_SUCCESS;

    PAL_VALIDATE_ARGUMENTS(NULLPTR == ctx)

    status = pal_plat_CtrDRBGIsSeeded(ctx);
    return status;
}

palStatus_t pal_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len)
{
    palStatus_t status = PAL_SUCCESS;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == out))

    status = pal_plat_CtrDRBGGenerate(ctx, out, len);
    return status;
}

palStatus_t pal_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == ctx || NULLPTR == *ctx))

    status = pal_plat_CtrDRBGFree(ctx);
    return status;
}

palStatus_t pal_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output)
{
	palStatus_t status = PAL_SUCCESS;
	PAL_VALIDATE_ARGUMENTS((NULL == key || NULL == input || NULL == output))
#if PAL_CMAC_SUPPORT
    status = pal_plat_cipherCMAC(key, keyLenInBits, input, inputLenInBytes, output);
#else   // no CMAC support		
    status = PAL_ERR_NOT_SUPPORTED;
    PAL_LOG_ERR("CMAC support in PAL is disabled");
#endif 
    return status;
}

palStatus_t pal_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID)
{
	palStatus_t status = PAL_SUCCESS;
	PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == key))
#if PAL_CMAC_SUPPORT
    status = pal_plat_CMACStart(ctx, key, keyLenBits, cipherID);
#else   // no CMAC support		
    status = PAL_ERR_NOT_SUPPORTED;
    PAL_LOG_ERR("CMAC support in PAL is disabled");
#endif
    return status;
}

palStatus_t pal_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen)
{
#if PAL_CMAC_SUPPORT
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == input))

    status = pal_plat_CMACUpdate(ctx, input, inLen);
#else   // no CMAC support		
    palStatus_t status = PAL_ERR_NOT_SUPPORTED;		
    PAL_LOG_ERR("CMAC support in PAL is disabled");
#endif 
    return status;
}

palStatus_t pal_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen)
{
#if PAL_CMAC_SUPPORT
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS(NULLPTR == ctx || NULLPTR == *ctx || NULL == output || NULL == outLen)

    status = pal_plat_CMACFinish(ctx, output, outLen);
#else   // no CMAC support		
    palStatus_t status = PAL_ERR_NOT_SUPPORTED;		
    PAL_LOG_ERR("CMAC support in PAL is disabled");
#endif 
    return status;
}

palStatus_t pal_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == key || NULL == input || NULL == output))

    status = pal_plat_mdHmacSha256(key, keyLenInBytes, input, inputLenInBytes, output, outputLenInBytes);
    return status;
}

palStatus_t pal_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp || NULLPTR == key || NULL == verified))

    status = pal_plat_ECCheckKey(grp, key, type, verified);
    return status;
}

palStatus_t pal_ECKeyNew(palECKeyHandle_t* key)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == key))

    status = pal_plat_ECKeyNew(key);
    return status;
}

palStatus_t pal_ECKeyFree(palECKeyHandle_t* key)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == key || NULLPTR == *key))

    status = pal_plat_ECKeyFree(key);
    return status;
}

palStatus_t pal_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == prvDERKey || NULLPTR == key))

    status = pal_plat_parseECPrivateKeyFromDER(prvDERKey, keyLen, key);
    return status;
}

palStatus_t pal_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == pubDERKey || NULLPTR == key))

    status = pal_plat_parseECPublicKeyFromDER(pubDERKey, keyLen, key);
    return status;
}

palStatus_t pal_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key || NULL == derBuffer || NULL == actualSize))

    status = pal_plat_writePrivateKeyToDer(key, derBuffer, bufferSize, actualSize);
    return status;
}

palStatus_t pal_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key || NULL == derBuffer || NULL == actualSize))

    status = pal_plat_writePublicKeyToDer(key, derBuffer, bufferSize, actualSize);
    return status;
}
palStatus_t pal_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp))

    status = pal_plat_ECGroupInitAndLoad(grp, index);
    return status;
}

palStatus_t pal_ECGroupFree(palCurveHandle_t* grp)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == grp || NULLPTR == *grp))

    status = pal_plat_ECGroupFree(grp);
    return status;
}

palStatus_t pal_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key))

    status = pal_plat_ECKeyGenerateKey(grpID, key);
    return status;
}

palStatus_t pal_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key || NULL == grpID))

    status = pal_plat_ECKeyGetCurve(key, grpID);
    return status;
}

palStatus_t pal_x509CSRInit(palx509CSRHandle_t *x509CSR)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == x509CSR))

    status = pal_plat_x509CSRInit(x509CSR);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULL == subjectName))

    status = pal_plat_x509CSRSetSubject(x509CSR, subjectName);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULLPTR == pubKey))

    status = pal_plat_x509CSRSetKey(x509CSR, pubKey, prvKey);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR))

    status = pal_plat_x509CSRSetMD(x509CSR, mdType);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR))

    status = pal_plat_x509CSRSetKeyUsage(x509CSR, keyUsage);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR))

    status = pal_plat_x509CSRSetExtendedKeyUsage(x509CSR, extKeyUsage);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULL == oid || NULL == value))

    status = pal_plat_x509CSRSetExtension(x509CSR, oid, oidLen, value, valueLen);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULL == derBuf))

    status = pal_plat_x509CSRWriteDER(x509CSR, derBuf, derBufLen, actualDerLen);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRFromCertWriteDER(palX509Handle_t x509Cert, palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerBufLen)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((0 == x509Cert || 0 == x509CSR || NULL == derBuf || NULL == actualDerBufLen))

    status = pal_plat_x509CSRFromCertWriteDER(x509Cert, x509CSR, derBuf, derBufLen, actualDerBufLen);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRFree(palx509CSRHandle_t *x509CSR)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == x509CSR || NULLPTR == *x509CSR))

    status = pal_plat_x509CSRFree(x509CSR);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, 
                            const palECKeyHandle_t privateKey, palECKeyHandle_t outKey)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp || NULLPTR == peerPublicKey || NULLPTR == privateKey || NULLPTR == outKey))

    status = pal_plat_ECDHComputeKey(grp, peerPublicKey, privateKey, outKey);
    return status;
}

palStatus_t pal_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, 
							uint32_t dgstLen, unsigned char *sig, size_t *sigLen)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp || NULLPTR == prvKey || NULL == dgst || NULL == sig || NULL == sigLen))
    
    status = pal_plat_ECDSASign(grp, mdType, prvKey, dgst, dgstLen, sig, sigLen);
    return status;
}

palStatus_t pal_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, 
                            unsigned char* sig, size_t sigLen, bool* verified)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULLPTR == pubKey || NULL == dgst || NULL == sig || NULL == verified))
    
    status = pal_plat_ECDSAVerify(pubKey, dgst, dgstLen, sig, sigLen, verified);
    return status;
}

palStatus_t pal_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char *output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    palStatus_t status = PAL_SUCCESS;
    PAL_VALIDATE_ARGUMENTS((NULL == output || NULL == actualOutLenBytes || NULLPTR == x509Cert));

    status = pal_plat_x509CertGetHTBS(x509Cert, hash_type, output, outLenBytes, actualOutLenBytes);
    return status;
}
