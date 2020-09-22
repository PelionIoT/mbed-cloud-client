/*******************************************************************************
 * Copyright 2016-2019 ARM Ltd.
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
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes))

    return pal_plat_initAes(aes);
}

palStatus_t pal_freeAes(palAesHandle_t *aes)
{
    PAL_VALIDATE_ARGUMENTS((NULL == aes || (uintptr_t)NULL == *aes))

    return pal_plat_freeAes(aes);
}

palStatus_t pal_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == key))

    return pal_plat_setAesKey(aes, key, keybits, keyTarget);
}

palStatus_t pal_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16])
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == input || NULL == output || NULL == iv))

    return pal_plat_aesCTR(aes, input, output, inLen, iv, false);
}

palStatus_t pal_aesCTRWithZeroOffset(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16])
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == input || NULL == output || NULL == iv))

    return pal_plat_aesCTR(aes, input, output, inLen, iv, true);
}

palStatus_t pal_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == aes || NULL == input || NULL == output))

    return pal_plat_aesECB(aes, input, output, mode);
}

palStatus_t pal_sha256(const unsigned char* input, size_t inLen, unsigned char* output)
{
    PAL_VALIDATE_ARGUMENTS((NULL == input || NULL == output))

    return pal_plat_sha256(input, inLen, output);
}

palStatus_t pal_x509Initiate(palX509Handle_t* x509Cert)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS( (NULL == x509Cert))

    return pal_plat_x509Initiate(x509Cert);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CertParse(palX509Handle_t x509Cert, const unsigned char* input, size_t inLen)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert || NULL == input))

    return pal_plat_x509CertParse(x509Cert, input, inLen);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert || NULL == output || NULL == actualOutLenBytes))

    return pal_plat_x509CertGetAttribute(x509Cert, attr, output, outLenBytes, actualOutLenBytes);
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

palStatus_t pal_x509CertCheckExtendedKeyUsage(palX509Handle_t x509Cert, palExtKeyUsage_t usage)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS(NULLPTR == x509Cert);
    return pal_plat_x509CertCheckExtendedKeyUsage(x509Cert, usage);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CertVerify(palX509Handle_t x509Cert, palX509Handle_t x509CertChain)
{
#if (PAL_ENABLE_X509 == 1)
    int32_t verifyResult = 0;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert))

    return pal_plat_x509CertVerifyExtended(x509Cert, x509CertChain, &verifyResult);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509Free(palX509Handle_t* x509Cert)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509Cert || NULLPTR == *x509Cert))

    return pal_plat_x509Free(x509Cert);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_mdInit(palMDHandle_t* md, palMDType_t mdType)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md))

    return pal_plat_mdInit(md, mdType);
}

palStatus_t pal_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULL == input))

    return pal_plat_mdUpdate(md, input, inLen);
}

palStatus_t pal_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULL == bufferSize))

    return pal_plat_mdGetOutputSize(md, bufferSize);
}

palStatus_t pal_mdFinal(palMDHandle_t md, unsigned char* output)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULL == output))

    return pal_plat_mdFinal(md, output);
}

palStatus_t pal_mdFree(palMDHandle_t* md)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == md || NULLPTR == *md))

    return pal_plat_mdFree(md);
}

palStatus_t pal_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509 || NULL == hash || NULL == sig))

    return pal_plat_verifySignature(x509, mdType, hash, hashLen, sig, sigLen);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}
 
palStatus_t pal_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag )
{
    PAL_VALIDATE_ARGUMENTS((NULL == position || NULL == end || NULL == len))
    
    return pal_plat_ASN1GetTag(position, end, len, tag);
}

palStatus_t pal_CCMInit(palCCMHandle_t* ctx)
{
    PAL_VALIDATE_ARGUMENTS((NULL == ctx))

    return pal_plat_CCMInit(ctx);
}

palStatus_t pal_CCMFree(palCCMHandle_t* ctx)
{
    PAL_VALIDATE_ARGUMENTS((NULL == ctx || NULLPTR == *ctx))

    return pal_plat_CCMFree(ctx);
}

palStatus_t pal_CCMSetKey(palCCMHandle_t ctx, const unsigned char *key, uint32_t keybits, palCipherID_t id)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == key))

    return pal_plat_CCMSetKey(ctx, id, key, keybits);
}

palStatus_t pal_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, 
                           unsigned char* iv, size_t ivLen, unsigned char* add, 
                           size_t addLen, unsigned char* tag, size_t tagLen, 
                           unsigned char* output)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == input || NULL == iv || NULL == add || NULL == tag || NULL == output))

    return pal_plat_CCMDecrypt(ctx, input, inLen, iv, ivLen, add, addLen, tag, tagLen, output);
}

palStatus_t pal_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, 
                           size_t inLen, unsigned char* iv, size_t ivLen, 
                           unsigned char* add, size_t addLen, unsigned char* output, 
                           unsigned char* tag, size_t tagLen)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == input || NULL == iv || NULL == add || NULL == tag || NULL == output))

    return pal_plat_CCMEncrypt(ctx, input, inLen, iv, ivLen, add, addLen, output, tag, tagLen);
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
    PAL_VALIDATE_ARGUMENTS(NULLPTR == ctx)

    return pal_plat_CtrDRBGIsSeeded(ctx);
}

palStatus_t pal_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == out))

    return pal_plat_CtrDRBGGenerate(ctx, out, len);
}

palStatus_t pal_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx)
{
    PAL_VALIDATE_ARGUMENTS((NULL == ctx || NULLPTR == *ctx))

    return pal_plat_CtrDRBGFree(ctx);
}

palStatus_t pal_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output)
{
    PAL_VALIDATE_ARGUMENTS((NULL == key || NULL == input || NULL == output))
#if PAL_CMAC_SUPPORT
    return pal_plat_cipherCMAC(key, keyLenInBits, input, inputLenInBytes, output);
#else   // no CMAC support
    PAL_LOG_ERR("CMAC support in PAL is disabled");
    return PAL_ERR_NOT_SUPPORTED;
#endif 
}

palStatus_t pal_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == key))
#if PAL_CMAC_SUPPORT
    return pal_plat_CMACStart(ctx, key, keyLenBits, cipherID);
#else   // no CMAC support
    PAL_LOG_ERR("CMAC support in PAL is disabled");
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen)
{
#if PAL_CMAC_SUPPORT
    PAL_VALIDATE_ARGUMENTS((NULLPTR == ctx || NULL == input))

    return pal_plat_CMACUpdate(ctx, input, inLen);
#else   // no CMAC support
    PAL_LOG_ERR("CMAC support in PAL is disabled");
    return  PAL_ERR_NOT_SUPPORTED;
#endif 
}

palStatus_t pal_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen)
{
#if PAL_CMAC_SUPPORT
    PAL_VALIDATE_ARGUMENTS(NULLPTR == ctx || NULLPTR == *ctx || NULL == output || NULL == outLen)

    return pal_plat_CMACFinish(ctx, output, outLen);
#else   // no CMAC support
    PAL_LOG_ERR("CMAC support in PAL is disabled");
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes)
{
    PAL_VALIDATE_ARGUMENTS((NULL == key || NULL == input || NULL == output))

    return pal_plat_mdHmacSha256(key, keyLenInBytes, input, inputLenInBytes, output, outputLenInBytes);
}

palStatus_t pal_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp || NULLPTR == key || NULL == verified))

    return pal_plat_ECCheckKey(grp, key, type, verified);
}

palStatus_t pal_ECKeyNew(palECKeyHandle_t* key)
{
    PAL_VALIDATE_ARGUMENTS((NULL == key))

    return pal_plat_ECKeyNew(key);
}


palStatus_t pal_ECKeyFree(palECKeyHandle_t* key)
{
    PAL_VALIDATE_ARGUMENTS((NULL == key || NULLPTR == *key))

    return pal_plat_ECKeyFree(key);
}


palStatus_t pal_newKeyHandle(palKeyHandle_t *keyHandle, size_t key_size)
{
    PAL_VALIDATE_ARGUMENTS((NULL == keyHandle) || (key_size== 0));

    return pal_plat_newKeyHandle(keyHandle, key_size);
}


palStatus_t pal_freeKeyHandle(palKeyHandle_t *keyHandle)
{
    PAL_VALIDATE_ARGUMENTS((NULL == keyHandle) || (NULLPTR == *keyHandle));

    return pal_plat_freeKeyHandle(keyHandle);
}


palStatus_t pal_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key)
{
    PAL_VALIDATE_ARGUMENTS((NULL == prvDERKey || NULLPTR == key))

    return pal_plat_parseECPrivateKeyFromDER(prvDERKey, keyLen, key);
}

palStatus_t pal_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key)
{
    PAL_VALIDATE_ARGUMENTS((NULL == pubDERKey || NULLPTR == key))

    return pal_plat_parseECPublicKeyFromDER(pubDERKey, keyLen, key);
}

palStatus_t pal_parseECPrivateKeyFromHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    PAL_VALIDATE_ARGUMENTS(( NULLPTR == ECKeyHandle ))

    return pal_plat_parseECPrivateKeyFromHandle(prvKeyHandle, ECKeyHandle);
}


palStatus_t pal_parseECPublicKeyFromHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    PAL_VALIDATE_ARGUMENTS( NULLPTR == ECKeyHandle)

    return pal_plat_parseECPublicKeyFromHandle(pubKeyHandle, ECKeyHandle);
}

palStatus_t  pal_convertRawSignatureToDer(const unsigned char *rawSignature, size_t  rawSignatureSize, unsigned char *derSignatureOut, size_t derSignatureMaxSize, size_t *derSignatureActSizeOut)
{
    PAL_VALIDATE_ARGUMENTS(NULL == rawSignature || NULL == derSignatureOut || NULL == derSignatureActSizeOut)
    PAL_VALIDATE_ARGUMENTS(rawSignatureSize != PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE || derSignatureMaxSize < PAL_ECDSA_SECP256R1_SIGNATURE_DER_SIZE)

    return pal_plat_convertRawSignatureToDer(rawSignature, rawSignatureSize, derSignatureOut, derSignatureMaxSize, derSignatureActSizeOut);
}

palStatus_t pal_asymmetricSign(palECKeyHandle_t privateKeyHanlde, palMDType_t mdType, const unsigned char *hash,size_t hashSize, unsigned char *outSignature, size_t maxSignatureSize, size_t *actualOutSignatureSize)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == privateKeyHanlde || NULL == hash || NULL == outSignature || NULL == actualOutSignatureSize)

    return pal_plat_asymmetricSign(privateKeyHanlde, mdType, hash, hashSize, outSignature, maxSignatureSize, actualOutSignatureSize);
}

palStatus_t pal_asymmetricVerify(palECKeyHandle_t publicKeyHandle, palMDType_t mdType, const unsigned char *hash, size_t hashSize, const unsigned char *signature, size_t signatureSize)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == publicKeyHandle || NULL == hash || NULL == signature))

    return pal_plat_asymmetricVerify(publicKeyHandle, mdType, hash, hashSize, signature, signatureSize);
}


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
palStatus_t pal_writePrivateKeyWithHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle)
{

    PAL_VALIDATE_ARGUMENTS(0 == prvKeyHandle || ECKeyHandle == 0);

    return pal_plat_writePrivateKeyWithHandle(prvKeyHandle, ECKeyHandle);
}


palStatus_t pal_writePublicKeyWithHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle)
{
    PAL_VALIDATE_ARGUMENTS(0 == pubKeyHandle || ECKeyHandle == 0);

    return pal_plat_writePublicKeyWithHandle(pubKeyHandle, ECKeyHandle);
}
#endif

palStatus_t pal_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key || NULL == derBuffer || NULL == actualSize))

    return pal_plat_writePrivateKeyToDer(key, derBuffer, bufferSize, actualSize);
}

palStatus_t pal_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key || NULL == derBuffer || NULL == actualSize))

    return pal_plat_writePublicKeyToDer(key, derBuffer, bufferSize, actualSize);
}

palStatus_t pal_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp))

    return pal_plat_ECGroupInitAndLoad(grp, index);
}

palStatus_t pal_ECGroupFree(palCurveHandle_t* grp)
{
    PAL_VALIDATE_ARGUMENTS((NULL == grp || NULLPTR == *grp))

    return pal_plat_ECGroupFree(grp);
}

palStatus_t pal_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key))

    return pal_plat_ECKeyGenerateKey(grpID, key);
}

palStatus_t pal_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == key || NULL == grpID))

    return pal_plat_ECKeyGetCurve(key, grpID);
}

palStatus_t pal_x509CSRInit(palx509CSRHandle_t *x509CSR)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULL == x509CSR))

    return pal_plat_x509CSRInit(x509CSR);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULL == subjectName))

    return pal_plat_x509CSRSetSubject(x509CSR, subjectName);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULLPTR == pubKey))

    return pal_plat_x509CSRSetKey(x509CSR, pubKey, prvKey);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR))

    return pal_plat_x509CSRSetMD(x509CSR, mdType);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR))

    return pal_plat_x509CSRSetKeyUsage(x509CSR, keyUsage);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR))

    return pal_plat_x509CSRSetExtendedKeyUsage(x509CSR, extKeyUsage);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULL == oid || NULL == value))

    return pal_plat_x509CSRSetExtension(x509CSR, oid, oidLen, value, valueLen);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULLPTR == x509CSR || NULL == derBuf))

    return pal_plat_x509CSRWriteDER(x509CSR, derBuf, derBufLen, actualDerLen);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRFromCertWriteDER(palX509Handle_t x509Cert, palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerBufLen)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((0 == x509Cert || 0 == x509CSR || NULL == derBuf || NULL == actualDerBufLen))

    return pal_plat_x509CSRFromCertWriteDER(x509Cert, x509CSR, derBuf, derBufLen, actualDerBufLen);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_x509CSRFree(palx509CSRHandle_t *x509CSR)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS((NULL == x509CSR || NULLPTR == *x509CSR))

    return pal_plat_x509CSRFree(x509CSR);
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, 
                            const palECKeyHandle_t privateKey, palECKeyHandle_t outKey)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp || NULLPTR == peerPublicKey || NULLPTR == privateKey || NULLPTR == outKey))

    return pal_plat_ECDHComputeKey(grp, peerPublicKey, privateKey, outKey);
}

palStatus_t pal_ECDHKeyAgreement(
    const uint8_t               *derPeerPublicKey,
    size_t                       derPeerPublicKeySize,
    const palECKeyHandle_t       privateKeyHandle,
    unsigned char               *rawSharedSecretOut,
    size_t                       rawSharedSecretMaxSize,
    size_t                      *rawSharedSecretActSizeOut)
{

    PAL_VALIDATE_ARGUMENTS(( NULLPTR == derPeerPublicKey || NULLPTR == privateKeyHandle || NULLPTR == rawSharedSecretOut || NULLPTR == rawSharedSecretActSizeOut))

    return pal_plat_ECDHKeyAgreement(derPeerPublicKey, derPeerPublicKeySize, privateKeyHandle, rawSharedSecretOut, rawSharedSecretMaxSize, rawSharedSecretActSizeOut);
}

palStatus_t pal_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, 
                          uint32_t dgstLen, unsigned char *sig, size_t *sigLen)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == grp || NULLPTR == prvKey || NULL == dgst || NULL == sig || NULL == sigLen))
    
    return pal_plat_ECDSASign(grp, mdType, prvKey, dgst, dgstLen, sig, sigLen);
}

palStatus_t pal_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, 
                            unsigned char* sig, size_t sigLen, bool* verified)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == pubKey || NULL == dgst || NULL == sig || NULL == verified))
    
    return pal_plat_ECDSAVerify(pubKey, dgst, dgstLen, sig, sigLen, verified);
}

palStatus_t pal_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char *output, size_t outLenBytes, size_t* actualOutLenBytes)
{
    PAL_VALIDATE_ARGUMENTS((NULL == output || NULL == actualOutLenBytes || NULLPTR == x509Cert));

    return pal_plat_x509CertGetHTBS(x509Cert, hash_type, output, outLenBytes, actualOutLenBytes);
}
