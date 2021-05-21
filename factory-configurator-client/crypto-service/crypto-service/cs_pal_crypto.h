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

#ifndef _CS_PAL_CRYPTO_H_
#define _CS_PAL_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stddef.h>
#include "cs_pal_crypto_configuration.h"
#include "mbed-trace/mbed_trace.h"
#if !defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) ||  defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)
#include "pal.h"
#endif

#define NULLPTR 0
typedef int32_t palStatus_t;

/*! \file cs_pal_crypto.h
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
typedef uintptr_t palKeyHandle_t;

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
#define PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE 64
#define PAL_SECP256R1_MAX_PUB_KEY_RAW_SIZE 65
#define PAL_ECDSA_SECP256R1_SIGNATURE_DER_SIZE 74
#define PAL_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE 91
#define PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE 32

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

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
//! Crypto buffer structure.
typedef struct palCryptoBuffer{
    uint8_t* buffer;
    uint32_t size;
} palCryptoBuffer_t;
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT


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
 \note In case of FCC_PAL_ERR_BUFFER_TOO_SMALL, the required size is assigned into the `actualOutLen` parameter.
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
 *      - FCC_PAL_ERR_X509_BADCERT_EXPIRED
 *      - FCC_PAL_ERR_X509_BADCERT_FUTURE
 *      - FCC_PAL_ERR_X509_BADCERT_BAD_MD
 *      - FCC_PAL_ERR_X509_BADCERT_BAD_PK
 *      - FCC_PAL_ERR_X509_BADCERT_NOT_TRUSTED
 *      - FCC_PAL_ERR_X509_BADCERT_BAD_KEY
 */
palStatus_t pal_x509CertVerify(palX509Handle_t x509Cert, palX509Handle_t x509CertChain);

/*! \brief Verify one or more DER-encoded X.509 certificates.
 *
 * @param[in] x509Cert: A handle holding the parsed certificate.
 * @param[in] x509CertChain: The beginning of the chain to verify the X509 DER certificate with. Optional.
 * @param[out] verifyResult: A bitmask of the errors that cause the failure. This value is relevant only in case failure.
 *
 \return PAL_SUCCESS on success. In case of failure returns `FCC_PAL_ERR_X509_CERT_VERIFY_FAILED`.
 */
palStatus_t pal_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult);

/*! Check usage of certificate against extended-key-usage extension
*
* @param[in] x509Cert: A handle holding the parsed certificate.
* @param[in] option: Intended usage (e.g.: PAL_X509_EXT_KU_CLIENT_AUTH)
*
\return PAL_SUCCESS if this use of the certificate is allowed, FCC_PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED if not
*       or FCC_PAL_ERR_X509_UNKNOWN_OID if the given usage is unknown or not supported.
*/
palStatus_t pal_x509CertCheckExtendedKeyUsage(palX509Handle_t x509Cert, palExtKeyUsage_t usage);

/*! \brief Deallocate all certificate data.
 *
 * @param[in,out] x509Cert: The certificate chain to free.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
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
 * @param[in] ivLen:     The length of the initialization vector in bytes.
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
 * \return FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED if the CTR-DRBG is not yet seeded, meaning calls to `pal_CtrDRBGGenerate()` will fail.
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

/*! \brief Initialize a pal key handle.
 *
 * In non-PSA configuration, allocate a key buffer, according to its size and initialize the pal key handle. 
 * 
 * @param[in] keyHandle: Pal key handle to be initialized.
 * @param[in] keySize: size of the key to be allocated
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_newKeyHandle( palKeyHandle_t *keyHandle, size_t keySize); 


/*! \brief frees a pal key handle.
 *
 * In non-PSA configuration, free the allocated key buffer.
 *
 * @param[in] keyHandle: A handle for the key
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_freeKeyHandle(palKeyHandle_t *keyHandle); 


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


/*! \brief Parse a private key.
 *
 * @param[in] prvKeyHandle:   A palKey_t object - either a PSA private key handle or a buffer and size of private key
 * @param[out] ECKeyHandle:   A handle for the context that holds the parsed private key.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_parseECPrivateKeyFromHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle);

/*! \brief Parse a public key.
 *
 * @param[in] pubKeyHandle:      A palKey_t object - either a PSA public key handle or a buffer and the size of a public key. 
 * @param[out] ECKeyHandle:      A handle for the context that holds the parsed public key.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_parseECPublicKeyFromHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle);

/*!	\brief Convert ECDSA signature in RAW format to DER format.
*
* @param[in] rawSignature:             The RAW signature buffer.
* @param[in] rawSignatureSize:         The RAW signature buffer size in bytes.
* @param[out] derSignatureOut:         A buffer to hold the converted DER signature.
* @param[in] derSignatureMaxSize:      The size of the DER signature buffer.
* @param[out] derSignatureActSizeOut:  The actual size of the converted DER signature.
*
* \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_convertRawSignatureToDer(
        const unsigned char         *rawSignature,
        size_t                       rawSignatureSize,
        unsigned char               *derSignatureOut,
        size_t                       derSignatureMaxSize,
        size_t                      *derSignatureActSizeOut);

/*! \brief Compute the Elliptic Curve Digital Signature Algorithm (ECDSA) raw signature of a previously hashed message.
* 
*  The function supports keys with PAL_ECP_DP_SECP256R1 curve only.
*
* @param[in] privateKeyHanlde         A parsed private key.
* @param[in] mdType:                  The MD algorithm to be used.
* @param[in] hash:                    The message hash.
* @param[in] hashSize:                The size of the  message buffer.
* @param[in/out] outSignature:        A buffer to hold the computed raw signature.
* @param[in] maxSignatureSize:        The size of the signature buffer.
* @param[out] actualOutSignatureSize: The actual size of the calculated signature.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_asymmetricSign(const palECKeyHandle_t privateKeyHanlde, palMDType_t mdType, const unsigned char *hash, size_t hashSize, unsigned char *outSignature, size_t maxSignatureSize, size_t *actualOutSignatureSize);

/*! \brief Verify the Elliptic Curve Digital Signature Algorithm (ECDSA) raw signature of a previously hashed message.
*
*  The function supports keys with PAL_ECP_DP_SECP256R1 curve only.
* 
* @param[in] publicKeyHanlde:    The public key for verification.
* @param[in] mdType:             The MD algorithm to be used.
* @param[in] hash:               The message hash.
* @param[in] hashSize:           The size of the message buffer.
* @param[in] signature:          The raw signature.
* @param[in] signatureSize:      The size of the signature.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_asymmetricVerify(const palECKeyHandle_t publicKeyHanlde, palMDType_t mdType, const unsigned char *hash, size_t hashSize, const unsigned char *signature, size_t signatureSize);


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
/*! \brief Write a pal private key handle from an EC key handle
 *
 * @param[in] prvKeyHandle:  A pal pivate key handle. Its buffer field is filled by the function
 * @param[in] ECKeyHandle:   A handle to EC Key handle.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_writePrivateKeyWithHandle(palKeyHandle_t prvKeyHandle, const palECKeyHandle_t ECKeyHandle);

/*! \brief Write a pal public key handle from an EC key handle
 *
 * @param[in] prvKeyHandle:  A pal public key handle. Its buffer field is filled by the function
 * @param[in] ECKeyHandle:   A handle to EC Key handle.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_writePublicKeyWithHandle(palKeyHandle_t pubKeyHandle, const palECKeyHandle_t ECKeyHandle);
#endif

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

/*! \brief Compute the raw shared secret using elliptic curve Diffie–Hellman.
*
* @param[in] derPeerPublicKey:            The DER public key from a peer.
* @param[in] derPeerPublicKeySize:        The size of the DER public key from a peer.
* @param[in] privateKeyHandle:            The private key handle.
* @param[in/out] rawSharedSecretOut:      A buffer to hold the computed raw shared secret.
* @param[in] rawSharedSecretMaxSize:      The size of the raw shared secret buffer.
* @param[out] rawSharedSecretActSizeOut:  The actual size of the  raw shared secret buffer.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_ECDHKeyAgreement(
    const uint8_t               *derPeerPublicKey,
    size_t                       derPeerPublicKeySize,
    const palECKeyHandle_t       privateKeyHandle,
    unsigned char               *rawSharedSecretOut,
    size_t                       rawSharedSecretMaxSize,
    size_t                      *rawSharedSecretActSizeOut);

/*! \brief Compute the Elliptic Curve Digital Signature Algorithm (ECDSA) signature of a previously hashed message.
 *
 * @param[in] grp:          The ECP group.
 * @param[in] mdType: The MD algorithm to be used.
 * @param[in] prvKey:       The private signing key.
 * @param[in] dgst:         The message hash.
 * @param[in] dgstLen:      The length of the message buffer.
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
 * @param[out] verified:    A Boolean to hold the verification result.
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

#if defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) &&  !defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)
/*! \brief Generate random number into given buffer with given size in bytes.
*
* @param[out] randomBuf A buffer to hold the generated number.
* @param[in] bufSizeBytes The size of the buffer and the size of the required random number to generate.
*
* \note `pal_init()` MUST be called before this function.
* \note If non-volatile entropy is expected, the entropy must have been injected before this function is called. If entropy has not been injected to non-volatile memory, us `pal_plat_osEntropyInject()`.
* \return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes);

/*! \brief Generate a 32-bit random number.
*
* @param[out] randomInt A 32-bit buffer to hold the generated number.
*
\note `pal_init()` MUST be called before this function.
\note If non-volatile entropy is expected, the entropy must be in storage when this function is called. Non-volatile entropy may be injected using `pal_plat_osEntropyInject()`.
\return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osRandom32bit(uint32_t *randomInt);
#endif

#define FCC_PAL_ONE_SEC                   1
#define FCC_PAL_SECONDS_PER_MIN           60
#define FCC_PAL_MINUTES_PER_HOUR          60
#define FCC_PAL_HOURS_PER_DAY              24
#define FCC_PAL_SECONDS_PER_HOUR          FCC_PAL_MINUTES_PER_HOUR * FCC_PAL_SECONDS_PER_MIN
#define FCC_PAL_SECONDS_PER_DAY           FCC_PAL_HOURS_PER_DAY * FCC_PAL_SECONDS_PER_HOUR
#define FCC_PAL_FEB_MONTH 2
/*! 
*  \FCC CRYPTO PAL errors.
*   This section contains enumeration for FCC CRYPTO PAL errors.
*/

//Error base
#define FCC_PAL_ERR_MODULE_CRYPTO_BASE              ((int32_t)0xFF000000) // -1 << 0x18
#define FCC_PAL_ERR_MODULE_BITMASK_BASE             ((int32_t)0xE0000000)
#define FCC_PAL_ERR_MODULE_GENERAL_BASE             ((int32_t)0xFFFFFFF0) // -1 << 0x4
#define FCC_PAL_ERR_MODULE_PAL_BASE                 ((int32_t)0xFFFFFFC0) // -1 << 0x6

//Error enumeration
typedef enum {
    FCC_PAL_SUCCESS = 0,
    //General errors
    FCC_PAL_ERR_GENERAL_BASE =                                  FCC_PAL_ERR_MODULE_GENERAL_BASE,
    FCC_PAL_ERR_GENERIC_FAILURE =                               FCC_PAL_ERR_GENERAL_BASE,          /*!< Generic failure*/ // Try to use a more specific error message whenever possible.
    FCC_PAL_ERR_INVALID_ARGUMENT =                              FCC_PAL_ERR_GENERAL_BASE + 0x01,
    FCC_PAL_ERR_NO_MEMORY =                                     FCC_PAL_ERR_GENERAL_BASE + 0x02,   /*!< Failure due to a failed attempt to allocate memory. */
    FCC_PAL_ERR_BUFFER_TOO_SMALL =                              FCC_PAL_ERR_GENERAL_BASE + 0x03,   /*!< The buffer given is too small. */
    FCC_PAL_ERR_NOT_SUPPORTED =                                 FCC_PAL_ERR_GENERAL_BASE + 0x04,   /*!< The operation is not supported by PAL for the current configuration. */
    FCC_PAL_ERR_NOT_INITIALIZED =                               FCC_PAL_ERR_GENERAL_BASE + 0x06,   /*!< Component is not initialized */
    FCC_PAL_ERR_CREATION_FAILED =                               FCC_PAL_ERR_GENERAL_BASE + 0x08,   /*!< Failure in creation of the given type, such as mutex or thread. */
    FCC_PAL_ERR_TIME_TRANSLATE =                                FCC_PAL_ERR_GENERAL_BASE + 0x0C,   /*!< Failure to translate the time from "struct tm" to epoch time. */
    FCC_PAL_ERR_NOT_IMPLEMENTED =                               FCC_PAL_ERR_MODULE_PAL_BASE,            /*! Failure due to being currently not implemented. */
    FCC_PAL_ERR_ITEM_NOT_EXIST =                                FCC_PAL_ERR_NOT_IMPLEMENTED + 0x01,     /*! Failure, item does not exist. Used in Storage RBP */
    FCC_PAL_ERR_ITEM_EXIST =                                    FCC_PAL_ERR_NOT_IMPLEMENTED + 0x02,     /*! Failure, item exists. Used in Storage RBP */
    //Crypto errors
    FCC_PAL_ERR_CRYPTO_ERROR_BASE =                             FCC_PAL_ERR_MODULE_CRYPTO_BASE,
    FCC_PAL_ERR_AES_INVALID_KEY_LENGTH =                        FCC_PAL_ERR_CRYPTO_ERROR_BASE,
    FCC_PAL_ERR_CERT_PARSING_FAILED =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 1,
    FCC_PAL_ERR_INVALID_MD_TYPE =                               FCC_PAL_ERR_CRYPTO_ERROR_BASE + 2,
    FCC_PAL_ERR_MD_BAD_INPUT_DATA =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 3,
    FCC_PAL_ERR_PK_SIG_VERIFY_FAILED =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 4,
    FCC_PAL_ERR_ASN1_UNEXPECTED_TAG =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 5,
    FCC_PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED =                FCC_PAL_ERR_CRYPTO_ERROR_BASE + 6,
    FCC_PAL_ERR_CTR_DRBG_REQUEST_TOO_BIG =                      FCC_PAL_ERR_CRYPTO_ERROR_BASE + 7,
    FCC_PAL_ERR_ECP_BAD_INPUT_DATA =                            FCC_PAL_ERR_CRYPTO_ERROR_BASE + 8,
    FCC_PAL_ERR_MPI_ALLOC_FAILED =                              FCC_PAL_ERR_CRYPTO_ERROR_BASE + 9,
    FCC_PAL_ERR_ECP_FEATURE_UNAVAILABLE =                       FCC_PAL_ERR_CRYPTO_ERROR_BASE + 10,
    FCC_PAL_ERR_ECP_BUFFER_TOO_SMALL =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 11,
    FCC_PAL_ERR_MPI_BUFFER_TOO_SMALL =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 12,
    FCC_PAL_ERR_CMAC_GENERIC_FAILURE =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 13,
    FCC_PAL_ERR_NOT_SUPPORTED_ASN_TAG =                         FCC_PAL_ERR_CRYPTO_ERROR_BASE + 14,
    FCC_PAL_ERR_PRIVATE_KEY_BAD_DATA =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 15,
    FCC_PAL_ERR_PRIVATE_KEY_VARIFICATION_FAILED =               FCC_PAL_ERR_CRYPTO_ERROR_BASE + 16,
    FCC_PAL_ERR_PUBLIC_KEY_BAD_DATA =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 17,
    FCC_PAL_ERR_PUBLIC_KEY_VARIFICATION_FAILED =                FCC_PAL_ERR_CRYPTO_ERROR_BASE + 18,
    FCC_PAL_ERR_NOT_SUPPORTED_CURVE =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 19,
    FCC_PAL_ERR_GROUP_LOAD_FAILED =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 20,
    FCC_PAL_ERR_PARSING_PRIVATE_KEY =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 21,
    FCC_PAL_ERR_PARSING_PUBLIC_KEY =                            FCC_PAL_ERR_CRYPTO_ERROR_BASE + 22,
    FCC_PAL_ERR_KEYPAIR_GEN_FAIL =                              FCC_PAL_ERR_CRYPTO_ERROR_BASE + 23,
    FCC_PAL_ERR_X509_UNKNOWN_OID =                              FCC_PAL_ERR_CRYPTO_ERROR_BASE + 24,
    FCC_PAL_ERR_X509_INVALID_NAME =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 25,
    FCC_PAL_ERR_FAILED_TO_SET_KEY_USAGE =                       FCC_PAL_ERR_CRYPTO_ERROR_BASE + 26,
    FCC_PAL_ERR_INVALID_KEY_USAGE =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 27,
    FCC_PAL_ERR_SET_EXTENSION_FAILED =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 28,
    FCC_PAL_ERR_CSR_WRITE_DER_FAILED =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 29,
    FCC_PAL_ERR_FAILED_TO_COPY_KEYPAIR =                        FCC_PAL_ERR_CRYPTO_ERROR_BASE + 30,
    FCC_PAL_ERR_FAILED_TO_COPY_GROUP =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 31,
    FCC_PAL_ERR_FAILED_TO_WRITE_SIGNATURE =                     FCC_PAL_ERR_CRYPTO_ERROR_BASE + 32,
    FCC_PAL_ERR_FAILED_TO_VERIFY_SIGNATURE =                    FCC_PAL_ERR_CRYPTO_ERROR_BASE + 33,
    FCC_PAL_ERR_FAILED_TO_WRITE_PRIVATE_KEY =                   FCC_PAL_ERR_CRYPTO_ERROR_BASE + 34,
    FCC_PAL_ERR_FAILED_TO_WRITE_PUBLIC_KEY  =                   FCC_PAL_ERR_CRYPTO_ERROR_BASE + 35,
    FCC_PAL_ERR_FAILED_TO_COMPUTE_SHARED_KEY =                  FCC_PAL_ERR_CRYPTO_ERROR_BASE + 36,
    FCC_PAL_ERR_INVALID_X509_ATTR =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 37,
    FCC_PAL_ERR_INVALID_CIPHER_ID =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 38,
    FCC_PAL_ERR_CMAC_START_FAILED =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 39,
    FCC_PAL_ERR_CMAC_UPDATE_FAILED =                            FCC_PAL_ERR_CRYPTO_ERROR_BASE + 40,
    FCC_PAL_ERR_CMAC_FINISH_FAILED =                            FCC_PAL_ERR_CRYPTO_ERROR_BASE + 41,
    FCC_PAL_ERR_INVALID_IOD =                                   FCC_PAL_ERR_CRYPTO_ERROR_BASE + 42,
    FCC_PAL_ERR_PK_UNKNOWN_PK_ALG =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 43,
    FCC_PAL_ERR_PK_KEY_INVALID_VERSION =                        FCC_PAL_ERR_CRYPTO_ERROR_BASE + 44,
    FCC_PAL_ERR_PK_KEY_INVALID_FORMAT =                         FCC_PAL_ERR_CRYPTO_ERROR_BASE + 45,
    FCC_PAL_ERR_PK_PASSWORD_REQUIRED =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 46,
    FCC_PAL_ERR_PK_INVALID_PUBKEY_AND_ASN1_LEN_MISMATCH =       FCC_PAL_ERR_CRYPTO_ERROR_BASE + 47,
    FCC_PAL_ERR_ECP_INVALID_KEY =                               FCC_PAL_ERR_CRYPTO_ERROR_BASE + 48,
    FCC_PAL_ERR_FAILED_SET_TIME_CB =                            FCC_PAL_ERR_CRYPTO_ERROR_BASE + 49,
    FCC_PAL_ERR_HMAC_GENERIC_FAILURE =                          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 50,
    FCC_PAL_ERR_X509_CERT_VERIFY_FAILED =                       FCC_PAL_ERR_CRYPTO_ERROR_BASE + 51,
    FCC_PAL_ERR_FAILED_TO_SET_EXT_KEY_USAGE =                   FCC_PAL_ERR_CRYPTO_ERROR_BASE + 52,
    FCC_PAL_ERR_CRYPTO_ALLOC_FAILED =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 53,
    FCC_PAL_ERR_ENTROPY_EXISTS =                                FCC_PAL_ERR_CRYPTO_ERROR_BASE + 54,
    FCC_PAL_ERR_ENTROPY_TOO_LARGE =                             FCC_PAL_ERR_CRYPTO_ERROR_BASE + 55,
    FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED =                           FCC_PAL_ERR_CRYPTO_ERROR_BASE + 56,
    FCC_PAL_ERR_PK_SIGN_FAILED =                                FCC_PAL_ERR_CRYPTO_ERROR_BASE + 57,
    FCC_PAL_ERR_PARSING_KEY =                                   FCC_PAL_ERR_CRYPTO_ERROR_BASE + 58,
    FCC_PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED =          FCC_PAL_ERR_CRYPTO_ERROR_BASE + 59,
    FCC_PAL_ERR_SSL_FATAL_ALERT_MESSAGE =                       FCC_PAL_ERR_CRYPTO_ERROR_BASE + 60,
    FCC_PAL_ERR_X509_BADCERT_EXPIRED =                          FCC_PAL_ERR_MODULE_BITMASK_BASE + 0x01, //!< Value must not be changed in order to be able to create bit mask
    FCC_PAL_ERR_X509_BADCERT_FUTURE =                           FCC_PAL_ERR_MODULE_BITMASK_BASE + 0x02, //!< Value must not be changed in order to be able to create bit mask
    FCC_PAL_ERR_X509_BADCERT_BAD_MD =                           FCC_PAL_ERR_MODULE_BITMASK_BASE + 0x04, //!< Value must not be changed in order to be able to create bit mask
    FCC_PAL_ERR_X509_BADCERT_BAD_PK =                           FCC_PAL_ERR_MODULE_BITMASK_BASE + 0x08, //!< Value must not be changed in order to be able to create bit mask
    FCC_PAL_ERR_X509_BADCERT_NOT_TRUSTED =                      FCC_PAL_ERR_MODULE_BITMASK_BASE + 0x10, //!< Value must not be changed in order to be able to create bit mask
    FCC_PAL_ERR_X509_BADCERT_BAD_KEY =                          FCC_PAL_ERR_MODULE_BITMASK_BASE + 0x20, //!< Value must not be changed in order to be able to create bit mask

} fcc_palError_t; /*! errors returned by the pal service API  */


#if (defined(MBED_DEBUG) && !defined(DEBUG))
#define DEBUG
#endif

/*!
*  \FCC CRYPTO PAL trace macros.
*/
#define FCC_PAL_LOG_ERR_FUNC  tr_err
#define FCC_PAL_LOG_WARN_FUNC tr_warn
#define FCC_PAL_LOG_INFO_FUNC tr_info
#define FCC_PAL_LOG_DBG_FUNC  tr_debug
#define FCC_PAL_LOG_LEVEL_ERR  TRACE_LEVEL_ERROR
#define FCC_PAL_LOG_LEVEL_WARN TRACE_LEVEL_WARN
#define FCC_PAL_LOG_LEVEL_INFO TRACE_LEVEL_INFO
#define FCC_PAL_LOG_LEVEL_DBG  TRACE_LEVEL_DEBUG

#define FCC_PAL_LOG_ERR( ARGS...)   FCC_PAL_LOG_ERR_FUNC(ARGS);
#define FCC_PAL_LOG_WARN( ARGS...)  FCC_PAL_LOG_WARN_FUNC(ARGS);
#define FCC_PAL_LOG_INFO( ARGS...)  FCC_PAL_LOG_INFO_FUNC(ARGS);
#define FCC_PAL_LOG_DBG( ARGS...)   FCC_PAL_LOG_DBG_FUNC(ARGS);

#ifdef DEBUG
#define FCC_PAL_VALIDATE_CONDITION_WITH_ERROR(condition, error) \
    {\
        if ((condition)) \
        { \
            FCC_PAL_LOG_ERR("(%s,%d): Parameters  values is illegal\r\n",__FUNCTION__,__LINE__); \
            return error; \
        } \
    }
#define FCC_PAL_VALIDATE_ARGUMENTS(condition) FCC_PAL_VALIDATE_CONDITION_WITH_ERROR(condition,FCC_PAL_ERR_INVALID_ARGUMENT)

#else
    #define FCC_PAL_VALIDATE_ARGUMENTS(condition)
    #define FCC_PAL_VALIDATE_CONDITION_WITH_ERROR(condition, error)
#endif

#ifdef __cplusplus
}
#endif

#endif //_PAL_CRYPTO_H_
