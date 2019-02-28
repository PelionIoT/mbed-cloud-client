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

#ifndef _PAL_CRYPTO_H_
#define _PAL_CRYPTO_H_

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

/*! \file pal_Crypto.h
*  \brief PAL cryptographic.
*   This file contains cryptographic APIs and is part of the PAL service API.
*
*     It contains a variety of cryptographic APIs, such as:
*       - AES-CTR
        - AES-DRBG
        - CMAC
        - Message Digest
*/

typedef uintptr_t palAesHandle_t;
typedef uintptr_t palX509Handle_t;
typedef uintptr_t palMDHandle_t;
typedef uintptr_t palCCMHandle_t;
typedef uintptr_t palCMACHandle_t;
typedef uintptr_t palCtrDrbgCtxHandle_t;
typedef uintptr_t palCurveHandle_t;
typedef uintptr_t palGroupIDHandle_t;
typedef uintptr_t palECKeyHandle_t;
typedef uintptr_t palSignatureHandle_t;
typedef uintptr_t palx509CSRHandle_t;

//! Key types to be set to the AES engine.
typedef enum palAesKeyType{
    PAL_KEY_TARGET_ENCRYPTION,
    PAL_KEY_TARGET_DECRYPTION
}palAesKeyType_t;

//! Message digest algorithms supported by PAL.
typedef enum palMDType{
    PAL_SHA256
}palMDType_t;

//! AES mode for ECB encryption and decryption.
typedef enum palAesMode{
    PAL_AES_ENCRYPT,
    PAL_AES_DECRYPT
}palAesMode_t;

//! The enum tags supported by PAL for ASN.1.
typedef enum palASNTag{
    PAL_ASN1_BOOLEAN                 = 0x01,
    PAL_ASN1_INTEGER                 = 0x02,
    PAL_ASN1_BIT_STRING              = 0x03,
    PAL_ASN1_OCTET_STRING            = 0x04,
    PAL_ASN1_NULL                    = 0x05,
    PAL_ASN1_OID                     = 0x06,
    PAL_ASN1_UTF8_STRING             = 0x0C,
    PAL_ASN1_SEQUENCE                = 0x10,
    PAL_ASN1_SET                     = 0x11,
    PAL_ASN1_PRINTABLE_STRING        = 0x13,
    PAL_ASN1_T61_STRING              = 0x14,
    PAL_ASN1_IA5_STRING              = 0x16,
    PAL_ASN1_UTC_TIME                = 0x17,
    PAL_ASN1_GENERALIZED_TIME        = 0x18,
    PAL_ASN1_UNIVERSAL_STRING        = 0x1C,
    PAL_ASN1_BMP_STRING              = 0x1E,
    PAL_ASN1_PRIMITIVE               = 0x00,
    PAL_ASN1_CONSTRUCTED             = 0x20,
    PAL_ASN1_CONTEXT_SPECIFIC        = 0x80,
}palASNTag_t;

#define PAL_ASN1_CLASS_BITS 0xC0
#define PAL_ASN1_TAG_BITS 0x1F
#define PAL_CRYPT_BLOCK_SIZE 16
#define PAL_SHA256_SIZE 32

typedef enum palFormat{
    PAL_POINT_CONVERSION_UNCOMPRESSED
    /*PAL_POINT_CONVERSION_COMPRESSED*/
}palFormat_t;

typedef enum palCipherID{
    PAL_CIPHER_ID_AES
    /*PAL_CIPHER_ID_DES*/
}palCipherID_t;

//! Supported curves.
typedef enum palGroupIndex{
    PAL_ECP_DP_NONE,
    PAL_ECP_DP_SECP256R1
}palGroupIndex_t;

//! Key usage options
typedef enum palKeyUsage{
    PAL_X509_KU_DIGITAL_SIGNATURE = 0x1,
    PAL_X509_KU_NON_REPUDIATION = 0x2,
    PAL_X509_KU_KEY_CERT_SIGN = 0x4,
    PAL_X509_KU_KEY_AGREEMENT = 0x8
}palKeyUsage_t;

//! Extended key usage options
typedef enum palExtKeyUsage {
    PAL_X509_EXT_KU_ANY =              (1 << 0),
    PAL_X509_EXT_KU_SERVER_AUTH =      (1 << 1),
    PAL_X509_EXT_KU_CLIENT_AUTH =      (1 << 2),
    PAL_X509_EXT_KU_CODE_SIGNING =     (1 << 3),
    PAL_X509_EXT_KU_EMAIL_PROTECTION = (1 << 4),
    PAL_X509_EXT_KU_TIME_STAMPING =    (1 << 8),
    PAL_X509_EXT_KU_OCSP_SIGNING =     (1 << 9)
}palExtKeyUsage_t;

//! Key check options.
typedef enum palKeyToCheck{
    PAL_CHECK_PRIVATE_KEY = 0x01,
    PAL_CHECK_PUBLIC_KEY = 0x10,
    PAL_CHECK_BOTH_KEYS = 0x11
}palKeyToCheck_t;

//! Attributes to be retrieved from the X.509 certificate.
typedef enum palX509Attr{
    PAL_X509_ISSUER_ATTR,
    PAL_X509_SUBJECT_ATTR,
    PAL_X509_CN_ATTR,
    PAL_X509_OU_ATTR,
    PAL_X509_VALID_FROM,
    PAL_X509_VALID_TO,
    PAL_X509_CERT_ID_ATTR,
    PAL_X509_SIGNATUR_ATTR,
    PAL_X509_L_ATTR
}palX509Attr_t;


/***************************************************/
/**** PAL Crypto Client APIs ***********************/
/***************************************************/

/*! \brief Initialize an AES context
 *
 * @param[in,out] aes: The AES context to be initialized.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_initAes(palAesHandle_t *aes);

/*! \brief Free an AES context.
 *
 * @param[in,out] aes: The AES context to be deallocated.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_freeAes(palAesHandle_t *aes);

/*! \brief Set an AES key context for encryption or decryption.
 *
 * @param[in] aes: The AES context.
 * @param[in] key: The AES key.
 * @param[in] keybits: The size of the key in bits.
 * @param[in] keyTarget: The key target, either encryption or decryption.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget);

/*! \brief Use AES-CTR encryption or decryption on a buffer.
 *
 * @param[in] aes: The AES context.
 * @param[in] input: The input data buffer.
 * @param[out] output: The output data buffer.
 * @param[in] inLen: The input data buffer length in bytes.
 * @param[in] iv: The initialization vector for AES-CTR.
 *
 \note Due to the nature of CTR, you should use the same key schedule for
 * both encryption and decryption. So before calling this function, you *must* set the key
 * by calling `pal_setAesKey()` with key target `PAL_KEY_TARGET_ENCRYPTION`.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16]);

/*! \brief Use AES-CTR encryption or decryption with zero offset on a buffer.
 *
 * @param[in] aes: The AES context.
 * @param[in] input: The input data buffer.
 * @param[out] output: The output data buffer.
 * @param[in] inLen: The input data length in bytes.
 * @param[in] iv: The initialization vector for AES-CTR.
 *
 \note Due to the nature of CTR, you should use the same key schedule for
 * both encryption and decryption. So before calling this function, you *must* set the key
 * by calling `pal_setAesKey()` with key target `PAL_KEY_TARGET_ENCRYPTION`.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_aesCTRWithZeroOffset(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16]);

/*! \brief Use AES-ECB encryption or decryption on a block.
 *
 * @param[in] aes: The AES context.
 * @param[in] input: A 16-byte input block.
 * @param[out] output: A 16-byte output block.
 * @param[in] mode: Defines whether to encrypt or decrypt. Set as `PAL_AES_ENCRYPT` for encryption or `PAL_AES_DECRYPT` for decryption.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode);

/*! \brief Run a SHA-256 operation on the input data.
 *
 * @param[in] input: A buffer for the input data.
 * @param[in] inLen: The length of the input data in bytes.
 * @param[out] output: The SHA-256 checksum result.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_sha256(const unsigned char* input, size_t inLen, unsigned char output[PAL_SHA256_SIZE]);

/*! \brief Initialize a certificate chain context.
 *
 * @param[in,out] x509Cert: The certificate chain to initialize.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509Initiate(palX509Handle_t* x509Cert);

/*! \brief Parse one or more certificates and add them to the chained list.
 *
 * @param[in] x509Cert: The beginning of the chain.
 * @param[in] input: A buffer holding the certificate data in PEM or DER format.
 * @param[in] inLen: The size of the input buffer in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CertParse(palX509Handle_t x509Cert, const unsigned char* input, size_t inLen);

/*! \brief Get an attribute from the parsed certificate.
 *
 * @param[in] x509Cert: The parsed certificate.
 * @param[in] attr: The required attribute.
 * @param[out] output: A buffer to hold the attribute value.
 * @param[in] outLenBytes: The size of the allocated buffer in bytes.
 * @param[out] actualOutLenBytes: The actual size of the attribute in bytes.
 *
 \note In case of PAL_ERR_BUFFER_TOO_SMALL, the required size is assigned into the `actualOutLen` parameter.
 \note `PAL_X509_CERT_ID_ATTR` requires a 33 bytes buffer size.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes);

/*! \brief Verify one or more DER encoded X.509 certificates.
 *
 * @param[in] x509Cert: A handle holding the parsed certificate.
 * @param[in] x509CertChain: Optional. The beginning of the chain to verify the X.509 DER certificate with.
 *
 \return PAL_SUCCESS on success. In case of failure:
 *      - PAL_ERR_X509_BADCERT_EXPIRED
 *      - PAL_ERR_X509_BADCERT_FUTURE
 *      - PAL_ERR_X509_BADCERT_BAD_MD
 *      - PAL_ERR_X509_BADCERT_BAD_PK
 *      - PAL_ERR_X509_BADCERT_NOT_TRUSTED
 *      - PAL_ERR_X509_BADCERT_BAD_KEY
 */
palStatus_t pal_x509CertVerify(palX509Handle_t x509Cert, palX509Handle_t x509CertChain);

/*! \brief Verify one or more DER-encoded X.509 certificates.
 *
 * @param[in] x509Cert: A handle holding the parsed certificate.
 * @param[in] x509CertChain: The beginning of the chain to verify the X509 DER certificate with. Optional.
 * @param[out] verifyResult: A bitmask of the errors that cause the failure. This value is relevant only in case failure.
 *
 \return PAL_SUCCESS on success. In case of failure returns `PAL_ERR_X509_CERT_VERIFY_FAILED`.
 */
palStatus_t pal_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult);

/*! \brief Deallocate all certificate data.
 *
 * @param[in,out] x509Cert: The certificate chain to free.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509Free(palX509Handle_t* x509Cert);

/*! \brief Initialize the Message Digest (MD) context and set it up according to the given algorithm.
 *
 * @param[in,out] md: The MD context to be initialized.
 * @param[in] mdType: The MD algorithm to be used.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_mdInit(palMDHandle_t* md, palMDType_t mdType);

/*! \brief Apply an Message Digest (MD) process on a buffer.
 *
 * @param[in] md: The MD context.
 * @param[in] input: A buffer holding the input data.
 * @param[in] inLen: The length of the input data in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen);

/*! \brief Get the length of the Message Digest (MD) output.
 *
 * @param[in] md: The MD context.
 * @param[out] bufferSize: A pointer to hold the output size of the `pal_mdFinal()` for the given handle.
 *
 \note This function should be called \b before calling `pal_mdFinal()`.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize);

/*! \brief Calculate the final Message Digest (MD).
 *
 * @param[in] md: The MD context.
 * @param[out] output: The checksum result of the MD.
 *
 \note `pal_mdGetOutputSize()` should be called \b before calling `pal_mdFinal()` to get the needed size for the output.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_mdFinal(palMDHandle_t md, unsigned char* output);

/*! \brief Free and clear a Message Digest (MD) context.
 *
 * @param[in,out] md: The MD context to be freed.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_mdFree(palMDHandle_t* md);

/*! \brief Verify the signature.
 *
 * @param[in] x509: The certificate context that holds the PK data.
 * @param[in] mdType: The MD algorithm used.
 * @param[in] hash: The hash of the message to sign.
 * @param[in] hashLen: The hash length in bytes.
 * @param[in] sig: The signature to verify.
 * @param[in] sigLen: The signature length.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen);

/*! \brief Check for a tag in ASN.1 data.
 *
 *  The function updates the pointer position to immediately after the tag and its length.
 *
 * @param[in,out] position: The position in the ASN.1 data.
 * @param[in] end: The end of data.
 * @param[out] len: The tag length in bytes.
 * @param[in] tag: The expected tag.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag);

/*! Initialize the CCM context.
 *
 * @param[in] ctx: The CCM context to be initialized.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CCMInit(palCCMHandle_t* ctx);

/*! \brief Destroy a CCM context.
 *
 * @param[in] ctx: The CCM context to destroy.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CCMFree(palCCMHandle_t* ctx);

/*! \brief Encrypt a CCM context  using a set key.
 *
 * @param[in] ctx:       The CCM context to be initialized.
 * @param[in] id:        The 128-bit block cipher to use.
 * @param[in] key:       The encryption key.
 * @param[in] keybits:   The key size in bits. The size must be acceptable by the cipher.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CCMSetKey(palCCMHandle_t ctx, const unsigned char *key, uint32_t keybits, palCipherID_t id);

/*! \brief Use authenticated decryption on a CCM buffer .
 *
 * @param[in] ctx:       The CCM context to be initialized.
 * @param[in] input      A buffer holding the input data.
 * @param[in] inLen:     The length of the input data in bytes.
 * @param[in] iv:        The initialization vector.
 * @param[in] ivLen:     The length of the initialization vector in bytes.
 * @param[in] add:       Additional data.
 * @param[in] addLen:    The length of the additional data in bytes.
 * @param[in] tag:       A buffer holding the tag.
 * @param[in] tagLen:    The length of the tag.
 * @param[out] output:   A buffer for holding the output data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen,
                            unsigned char* iv, size_t ivLen, unsigned char* add,
                            size_t addLen, unsigned char* tag, size_t tagLen,
                            unsigned char* output);

/*! \brief Encrypt a CCM buffer.
 *
 * @param[in] ctx:       The CCM context to be initialized.
 * @param[in] input      A buffer holding the input data.
 * @param[in] inLen:     The length of the input data.
 * @param[in] iv:        The initialization vector.
 * @param[in] ivLen:     The length of the initalization vector in bytes.
 * @param[in] add:       Additional data.
 * @param[in] addLen:    The length of additional data.
 * @param[out] output:   A buffer for holding the output data, must be at least `inLen` bytes wide.
 * @param[out] tag:      A buffer for holding the tag.
 * @param[out] tagLen:   The length of the tag to generate in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input,
                            size_t inLen, unsigned char* iv, size_t ivLen,
                            unsigned char* add, size_t addLen, unsigned char* output,
                            unsigned char* tag, size_t tagLen);

/*! \brief Initialize a Counter mode Deterministic Random Byte Generator (CTR-DRBG) context with a given seed.
 *
 * @param[in] ctx:        The CTR-DRBG context to be seeded.
 * @param[in] seed:       The seed data.
 * @param[in] len:        The length of the seed data in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx, const void* seed, size_t len);

/*! \brief Check whether a Counter mode Deterministic Random Byte Generator (CTR-DRBG) context is seeded.
 *
 * Calls to `pal_CtrDRBGGenerate()` only succeed when the context is seeded.
 *
 * @param[in] ctx:	The CTR-DRBG context to be checked.
 *
 * \return PAL_SUCCESS if the CTR-DRBG is seeded.
 * \return PAL_ERR_CTR_DRBG_NOT_SEEDED if the CTR-DRBG is not yet seeded, meaning calls to `pal_CtrDRBGGenerate()` will fail.
 * \return Any other negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CtrDRBGIsSeeded(palCtrDrbgCtxHandle_t ctx);

/*! \brief Generate a pseudo random number using the Counter mode Deterministic Random Byte Generator (CTR-DRBG).
 *
 * @param[in] ctx:        The CTR-DRBG context.
 * @param[out] out:       The buffer to fill.
 * @param[in] len:        The length of the buffer in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len);

/*! \brief Destroy a Counter mode Deterministic Random Byte Generator (CTR-DRBG) context.
 *
 * @param[in] ctx:   The CTR-DRBG context to destroy.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx);


/*! \brief Apply a one-shot CMAC cipher.
 *
 * @param[in] ctx:               The CMAC context to initialize.
 * @param[in] key:               The encryption key.
 * @param[in] keyLenInBits:      The key size in bits.
 * @param[in] input:             A buffer for the input data.
 * @param[in] inputLenInBytes:   The length of the input data in bytes.
 * @param[out] output:           The generic CMAC result.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output);

/*! \brief Start an iterative CMAC cipher.
 *
 * @param[in] ctx:        The CMAC context.
 * @param[in] key:        The CMAC key.
 * @param[in] keyLenBits: The key size in bits.
 * @param[in] cipherID:   A buffer for the input data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID);

/*! \brief Update an iterative CMAC cipher.
 *
 * @param[in] ctx:      The CMAC context.
 * @param[in] input:    A buffer for the input data.
 * @param[in] inLen:    The length of the input data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen);

/*! \brief Finish an iterative CMAC cipher.
 *
 * @param[in] ctx:          The CMAC context.
 * @param[out] output:      A buffer for the output data.
 * @param[out] outLen:      The length of the output data in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen);

/*! \brief Apply a one-shot Message Digest HMAC cipher.
 *
 * @param[in] key:               The encryption key.
 * @param[in] keyLenInBytes:     The key size in bytes.
 * @param[in] input:             A buffer for the input data.
 * @param[in] inputLenInBytes:   The input data length in bytes.
 * @param[out] output:           The generic HMAC result.
 * @param[out] outputLenInBytes: Optional. Size of the HMAC result. If not given, the default is 32 bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes);


/*! \brief Check that the private key, public key, or both are valid and that the public key is on the curve.
 *
 * @param[in] grp:          The curve or group that the point should belong to.
 * @param[in] key:          A pointer to a struct holding the raw data of the keys to check.
 * @param[in] type:         Determines whether to check the private key, public key or both should be checked. See `palKeyToCheck_t` for values.
 * @param[out] verified:    The result of verification.
 *
 \note  The key can contain only private or public key or both.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified);

/*! \brief Allocate a key context and initialize a key pair as an invalid pair.
 *
 * @param[in] key: The key to initialize.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECKeyNew(palECKeyHandle_t* key);

/*! \brief Release a private or public key context from memory.
 *
 * @param[in] key: A handle for the key context to be freed.
 *
 \note This function should be called \b before calling `pal_ECKeyGenerateKey()`.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECKeyFree(palECKeyHandle_t* key);

/*! \brief Parse a DER-encoded private key.
 *
 * @param[in] prvDERKey:	A buffer that holds the DER-encoded private key.
 * @param[in] keyLen:       The key length in bytes.
 * @param[out] key:         A handle for the context that holds the parsed key.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key);

/*! \brief Parse a DER-encoded public key.
 *
 * @param[in] pubDERKey:    A buffer that holds the DER encoded public key.
 * @param[in] keyLen:       The key length in bytes.
 * @param[out] key:         A handle for the context that holds the parsed key.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key);

/*! \brief DER encode a private key from a key handle.
 *
 * @param[in] key:          A handle to the private key.
 * @param[out] derBuffer:   A buffer to hold the result of the DER encoding.
 * @param[in] bufferSize:   The size of the allocated buffer.
 * @param[out] actualSize:  The actual size of the written data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize);

/*! \brief DER encode a public key from a key handle.
 *
 * @param[in] key:          A handle to the public key.
 * @param[out] derBuffer:   A buffer to hold the result of the DER encoding.
 * @param[in] bufferSize:   The size of the allocated buffer in bytes.
 * @param[out] actualSize:  The actual size of the written data in bytes.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize);

/*! \brief Generate a key pair for a given Elliptic Curve.
 *
 * @param[in] grpID:        The ECP group identifier.
 * @param[in,out] key:      The destination handle for the key pair .
 *
 \note `pal_ECKeyNew()` should be called \b before calling `pal_ECKeyGenerateKey()`
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key);

/*! \brief Retrieve the curve ID if it exists in the given key.
 *
 * @param[in] key: The key where the curve is retrieved from.
 * @param[out] grpID: The group ID for the given key. In case of error, this pointer contains `PAL_ECP_DP_NONE`.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID);

/*! \brief Initialize and set an ECP group using well-known domain parameters.
 *
 * @param[in] grp:      The destination group.
 * @param[in] index:    The index position in the list of well-known domain parameters.
 *
 \return PAL_SUCCESS on success, negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index);

/*! \brief Free the ECP group context.
 *
 * @param[in] grp: The curve or group to free.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECGroupFree(palCurveHandle_t* grp);

/*! \brief Allocate and initialize X.509 certificate signing request (CSR) context.
 *
 * @param[in] x509CSR:  The CSR context to allocate and initialize.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRInit(palx509CSRHandle_t *x509CSR);

/*! \brief Set the subject name for a certificate signing request (CSR). Subject names should contain a comma-separated list of OIDs and values.
 *
 * @param[in] x509CSR:    The CSR context to use.
 * @param[in] subjectName: The subject name to set
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName);

/*! Set the type of Message Digest (MD) algorithm to use for the signature.
 *
 * @param[in] x509CSR:   The CSR context to use.
 * @param[in] mdType:    The MD algorithm to use.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType);

/*! \brief Set the key for a CSR.
 *
 * @param[in] x509CSR:   The CSR context to use.
 * @param[in] pubKey:    The public key to include. To use a key pair handle, see the note.
 * @param[in] prvKey:    The public key to sign with.
 *
 \note To use a key pair, send the desired key pair as `pubKey` and NULL as `prvKey`.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey);

/*! \brief Set the key usage extension flags for a CSR context.
 *
 * @param[in] x509CSR:   The CSR context to configure.
 * @param[in] keyUsage:  The key usage flags. See `palKeyUsage_t` for options.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage);

/*! \brief Set the extended key usage flags.
 *
 * @param[in] x509CSR:   The CSR context to configure.
 * @param[in] extKeyUsage:  The extended key usage flags, should be taken from `palExtKeyUsage_t`.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage);

/*! \brief Generic function to extend a CSR context.
 *
 * @param[in] x509CSR:   The CSR context to extend.
 * @param[in] oid:          The OID of the extension.
 * @param[in] oidLen:       The OID length.
 * @param[in] value:        The value of the extension OCTET STRING.
 * @param[in] valueLen:     The value length.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen,
                                    const unsigned char* value, size_t valueLen);

/*! \brief Write a CSR to a DER structure
 *
 * @param[in] x509CSR:      The CSR context to use.
 * @param[in] derBuf:       A buffer to write to.
 * @param[in] derBufLen:    The buffer length.
 * @param[in] actualDerLen: The actual length of the written data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen);

/*! \brief Writes a CSR from a given X.509 Certificate
 *
 * @param[in] x509Cert:         The parsed X.509 certificate on which we generate the CSR from.
 * @param[in,out] x509CSR:      The X.509 CSR that has been already initialized with a private key.
 * @param[out] derBuf:          A buffer to write to.
 * @param[in] derBufLen:        The buffer length.
 * @param[out] actualDerBufLen: The actual length of the written data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRFromCertWriteDER(palX509Handle_t x509Cert, palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerBufLen);

/*! \brief Free the X.509 CSR context.
 *
 * @param[in] x509CSR:  The CSR context to free.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_x509CSRFree(palx509CSRHandle_t *x509CSR);

/*! \brief Compute the shared secret using elliptic curve Diffie–Hellman.
 *
 * @param[in] grp:              The ECP group.
 * @param[in] peerPublicKey:    The public key from a peer.
 * @param[in] privateKey:       The private key.
 * @param[out] outKey:          The shared secret.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey,
                                const palECKeyHandle_t privateKey, palECKeyHandle_t outKey);

/*! \brief Compute the Elliptic Curve Digital Signature Algorithm (ECDSA) signature of a previously hashed message.
 *
 * @param[in] grp:          The ECP group.
 * @param[in] mdType: The MD algorithm to be used.
 * @param[in] prvKey:       The private signing key.
 * @param[in] dgst:         The message hash.
 * @param[in] dgstLen:      The length ofthe  message buffer.
 * @param[out] sig:         A buffer to hold the computed signature.
 * @param[out] sigLen:      The length of the computed signature.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst,
                                    uint32_t dgstLen, unsigned char *sig, size_t *sigLen);

/*! \brief Verify the Elliptic Curve Digital Signature Algorithm (ECDSA) signature of a previously hashed message.
 *
 * @param[in] pubKey:       The public key for verification.
 * @param[in] dgst:         The message hash.
 * @param[in] dgstLen:      The length of the message buffer.
 * @param[in] sign:         The signature.
 * @param[in] sig:          A buffer to hold the computed signature.
 * @param[in] sigLen:       The length of the computed signature.
 * @param[out] verified:    A boolean to hold the verification result.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen,
                                    unsigned char* sig, size_t sigLen, bool* verified);


/*! \brief Calculate the hash of the part of an X.509 certificate that is to be signed.
 *
 * This function may be used to validate a certificate signature: Simply retrieve this hash, verify the signature using this hash, the public key and the signature of the X509
 *
 * @param[in] x509Cert:             Handle to the certificate to hash the TBS (to be signed part).
 * @param[in] hash_type:            The hash type. Currently only PAL_SHA256 supported
 * @param[out] output:              Pointer to a buffer that will contain the hash digest. This buffer must be at least the size of the digest. If hash_type is PAL_SHA256, then buffer pointed to by output must be at least 32 bytes.
 * @param[in] outLenBytes:          The size of the buffer pointed to by output. Must be at least the size of the digest
 * @param[out] actualOutLenBytes:   Size of the digest copied to output. In case of success, will always be the length of the hash digest
 *
 \return PAL_SUCCESS on success.    A negative value indicating a specific error code in case of failure.
 */

palStatus_t pal_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char *output, size_t outLenBytes, size_t* actualOutLenBytes);

#endif //_PAL_CRYPTO_H_
