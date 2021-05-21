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

#ifndef _CS_PAL_PLAT_CRYPTO_H_
#define _CS_PAL_PLAT_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cs_pal_crypto.h"
/*! \file cs_pal_plat_crypto.h
 *  \brief PAL cryptographic - platform.
 *   This file contains cryptographic APIs that need to be implemented in the platform layer.
 */

/*!	\brief Initiate the Crypto library.
 *
 * Initialization is not required for some crypto libraries. In such
 * cases, the implementation may be empty.
 *
 * \note This function must be called in the general PAL initializtion function.
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_initCrypto(void);

/*!	\brief Free resources for the Crypto library.
 *
 * \note This function must be called in the general PAL cleanup function.
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_cleanupCrypto(void);

/*! \brief Initialize an AES context.
 *
 * @param[in,out] aes: The AES context to be initialized.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_initAes(palAesHandle_t *aes);

/*! \brief Free an AES context.
 *
 * @param[in,out] aes: The AES context to be deallocated.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_freeAes(palAesHandle_t *aes);

/*! \brief Set an AES key context for encryption or decryption.
 *
 * @param[in] aes: The AES context.
 * @param[in] key: AES key.
 * @param[in] keybits: The size of the key in bits.
 * @param[in] keyTarget: The key target, either encryption or decryption.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget);

/*! \brief Use AES-CTR encryption or decryption on a buffer.
 *
 * @param[in] aes: The AES context.
 * @param[in] input: The input data buffer.
 * @param[out] output: The output data buffer.
 * @param[in] inLen: The length of the input data in bytes.
 * @param[in] iv: The initialization vector for AES-CTR.
 * @param[in] zeroOffset: Send offset value zero to platform function.
 *
 * \note Due to the nature of CTR you should use the same key schedule for both encryption and decryption.
 * So before calling this function you MUST call `pal_setAesKey()` with the key target PAL_KEY_TARGET_ENCRYPTION to set the key.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16], bool zeroOffset);

/*! \brief Use AES-ECB encryption or decryption on a block.
 *
 * @param[in] aes: The AES context.
 * @param[in] input: A 16-byte input block.
 * @param[out] output: A 16-byte output block.
 * @param[in] mode: Choose between encryption (PAL_AES_ENCRYPT) or decryption (PAL_AES_DECRYPT).
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode);

/*! \brief Process SHA-256 over the input buffer.
 *
 * @param[in] input: A buffer for the input data.
 * @param[in] inLen: The length of the input data in bytes.
 * @param[out] output: SHA-256 checksum result.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_sha256(const unsigned char* input, size_t inLen, unsigned char* output);

/*! \brief Initialize a certificate chain context.
 *
 * @param[in,out] x509: The certificate chain to initialize.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509Initiate(palX509Handle_t* x509);

/*! \brief Parse one or more certificates and add them to the chained list.
 *
 * @param[in] x509: The start of the chain.
 * @param[in] input: A buffer holding the certificate data in PEM or DER format.
 * @param[in] inLen: The size of the input buffer in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CertParse(palX509Handle_t x509, const unsigned char* input, size_t inLen);

/*! \brief Get attributes from the parsed certificate.
*
* @param[in] x509Cert: The parsed certificate.
* @param[in] attr: The required attribute.
* @param[out] output: A buffer to hold the attribute value.
* @param[in] outLenBytes: The size of the allocated buffer in bytes.
* @param[out] actualOutLenBytes: The actual size of the attribute in bytes.
*
* \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes);

/*! \brief Verify one or more X.509 DER formatted certificates.
 *
 * @param[in] x509Cert: A handle holding the parsed certificate.
 * @param[in] x509CertChain: The start of the chain to verify the X.509 DER certificate with. This is optional.
 * @param[out] verifyResult: Bitmask of errors that cause the failure. This value is
 *						 relevant ONLY in case that the return value of the function is `PAL_ERR_X509_CERT_VERIFY_FAILED`.
 *
 * \note In case a platform doesn't support multiple errors for certificate verification, please return `PAL_ERR_X509_CERT_VERIFY_FAILED` and the reason should be specified in the `verifyResult`
 * \return PAL_SUCCESS on success.
 * \return PAL_ERR_X509_CERT_VERIFY_FAILED in case of failure.
 */
palStatus_t pal_plat_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult);

/*! Check usage of certificate against extended-key-usage extension
*
* @param[in] x509Cert: A handle holding the parsed certificate.
* @param[in] option: Intended usage (e.g.: PAL_X509_EXT_KU_CLIENT_AUTH)
*
\return PAL_SUCCESS if this use of the certificate is allowed, PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED if not
*       or PAL_ERR_X509_UNKNOWN_OID if the given usage is unknown or not supported.
*/
palStatus_t pal_plat_x509CertCheckExtendedKeyUsage(palX509Handle_t x509Cert, palExtKeyUsage_t usage);

/*! \brief Deallocate all certificate data.
 *
 * @param[in,out] x509: The certificate chain to free.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509Free(palX509Handle_t* x509);

/*! \brief Initialize an message digest (MD) context and set up the required data according to the given algorithm.
 *
 * @param[in,out] md: The MD context to be initialized.
 * @param[in] mdType: The MD algorithm.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType);

/*! \brief Generic message digest (MD) process buffer.
 *
 * @param[in] md: The MD context.
 * @param[in] input: A buffer holding the input data.
 * @param[in] inLen: The length of the input data in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen);

/*! \brief Generic message digest (MD) output buffer size getter.
 *
 * @param[in] md: The MD context.
 * @param[out] bufferSize: A pointer to hold the output size of the `pal_mdFinal()` for the given handle.
 *
 * \note You SHOULD call this function before calling `pal_mdFinal()`.
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize);

/*! \brief Generic message digest (MD) final digest.
 *
 * @param[in] md: The MD context.
 * @param[in] output: The generic message digest checksum result.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output);

/*! \brief Free and clear the message digest (MD) context.
 *
 * @param[in,out] md: The MD context to be freed.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdFree(palMDHandle_t* md);

/*! \brief Verify the signature.
 *
 * @param[in] x509: The certificate context that holds the PK data.
 * @param[in] mdType: The MD algorithm used.
 * @param[in] hash: The hash of the message to sign.
 * @param[in] hashLen: The hash length in bytes.
 * @param[in] sig: The signature to verify.
 * @param[in] sigLen: The signature length in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen );

/*! \brief Check for a specific tag.
*   Updates the pointer to immediately after the tag and length.
 *
 * @param[in,out] position: The initial position in the ASN.1 data.
 * @param[in] end: The end of data.
 * @param[out] len: The tag length in bytes.
 * @param[in] tag: The expected tag.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag );

/*!	\brief Initialize a CCM context.
 *
 * @param[in] ctx: The CCM context to be initialized.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CCMInit(palCCMHandle_t* ctx);

/*!	\brief Destroy a CCM context.
 *
 * @param[in] ctx: The CCM context to destroy.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CCMFree(palCCMHandle_t* ctx);

/*!	\brief Set the CCM key.
 *
 * @param[in] ctx:       The CCM context.
 * @param[in] id:        The cipher to use (a 128-bit block cipher).
 * @param[in] key:       The encryption key.
 * @param[in] keybits:   The key size in bits. Must be acceptable by the cipher.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CCMSetKey(palCCMHandle_t ctx, palCipherID_t id, const unsigned char *key, unsigned int keybits);

/*!	\brief Apply authenticated CCM decryption on a buffer.
 *
 * @param[in] ctx:       The CCM context.
 * @param[in] input      A buffer holding the input data.
 * @param[in] inLen:     The length of the input data in bytes.
 * @param[in] iv:        The initialization vector.
 * @param[in] ivLen:     The length of the IV in bytes.
 * @param[in] add:       Additional data.
 * @param[in] addLen:    The length of the additional data in bytes.
 * @param[in] tag:       A buffer holding the tag.
 * @param[in] tagLen:  	 The length of the tag in bytes.
 * @param[out] output:   A buffer for holding the output data.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* tag, size_t tagLen, unsigned char* output);

/*!	\brief Apply CCM encryption on a buffer.
 *
 * @param[in] ctx:       The CCM context.
 * @param[in] input      A buffer holding the input data.
 * @param[in] inLen:    	The length of the input data in bytes.
 * @param[in] iv:        The initialization vector.
 * @param[in] ivLen:    	The length of the IV in bytes.
 * @param[in] add:       Additional data.
 * @param[in] addLen:   	The length of additional data in bytes.
 * @param[out] output:   A buffer for holding the output data, must be at least 'inLen' bytes wide.
 * @param[out] tag:      A buffer for holding the tag.
 * @param[out] tagLen:   The length of the tag to generate in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* output, unsigned char* tag, size_t tagLen);

/*!	\brief Initializes a Counter mode Deterministic Random Byte Generation (CTR-DRBG) context.
 *
 * @param[in] ctx:   The CTR-DRBG context to be initialized.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx);

/*!	\brief Destroys a Counter mode Deterministic Random Byte Generation (CTR-DRBG) context.
 *
 * @param[in] ctx:   The CTR-DRBG context to destroy.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx);

/*! \brief Check whether a Counter mode Deterministic Random Byte Generator (CTR-DRBG) context is seeded.
 *
 * Calls to `pal_plat_CtrDRBGGenerate()` only succeed when the context is seeded.
 *
 * @param[in] ctx:	The CTR-DRBG context to be checked.
 *
 * \return PAL_SUCCESS if the CTR-DRBG is seeded.
 * \return PAL_ERR_CTR_DRBG_NOT_SEEDED if the CTR-DRBG is not yet seeded, meaning calls to `pal_plat_CtrDRBGGenerate()` will fail.
 * \return Any other negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CtrDRBGIsSeeded(palCtrDrbgCtxHandle_t ctx);

/*!	\brief Set the initial seed for a Counter mode Deterministic Random Byte Generation (CTR-DRBG) context.
 *
 * @param[in] ctx:	The CTR-DRBG context to be seeded.
 * @param[in] seed:	The seed data.
 * @param[in] len:	The seed data length in bytes.
 *
 * \return PAL_SUCCESS on success, negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CtrDRBGSeed(palCtrDrbgCtxHandle_t ctx, const void* seed, size_t len);

/*!	\brief Generate a random value using a Counter mode Deterministic Random Byte Generation (CTR-DRBG) context.
 *
 * @param[in] ctx:	The CTR-DRBG context.
 * @param[in] out:	The buffer to fill.
 * @param[in] len:	The length of the buffer in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len);

/*!	\brief Generate a random value with additional input using a Counter mode Deterministic Random Byte Generation (CTR-DRBG) context.
 *
 * @param[in] ctx:	The CTR-DRBG context.
 * @param[in] out:	The buffer to fill.
 * @param[in] len:	The length of the buffer in bytes.
 * @param[in] additional:	Additional data to update with.
 * @param[in] additionalLen:	Length of additional data in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CtrDRBGGenerateWithAdditional(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len, unsigned char* additional, size_t additionalLen);

#if PAL_CMAC_SUPPORT

/*!	\brief Initialize a Cipher-based Message Authentication Code (CMAC) context with a AES cipher.
 *
 * @param[in] ctx:               The CMAC context to initialize.
 * @param[in] key:               The encryption key.
 * @param[in] keyLenInBits:      The key size in bits.
 * @param[in] input:             A buffer for the input data.
 * @param[in] inputLenInBytes:   The input data length in bytes.
 * @param[out] output:           Generic CMAC result.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output);

/*!	\brief Start an iterative cipher CMAC context.
 *
 * @param[in] ctx:   	 The CMAC context to initialize.
 * @param[in] key:  		 The CMAC key.
 * @param[in] keyLenBits: The key size in bits.
 * @param[in] cipherID:   A buffer for the input data.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID);

/*!	\brief Update an iterative cipher CMAC context.
 *
 * @param[in] ctx:   	The CMAC context to initialize.
 * @param[in] input:  	A buffer for the input data.
 * @param[in] inputLen:  The input data length in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen);

/*!	\brief Finish an iterative cipher CMAC context.
 *
 * @param[in] ctx:   	The CMAC context to initialize.
 * @param[out] output:  	A buffer for the output data.
 * @param[out] outLen:   The output data length in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen);

#endif //PAL_CMAC_SUPPORT

/*! \brief Apply a one-shot Message Digest HMAC cipher.
 *
 * @param[in] key:  				The encryption key.
 * @param[in] keyLenInBytes:   	The key size in bytes.
 * @param[in] input:  	        A buffer for the input data.
 * @param[in] inputLenInBytes:   The input data length in bytes.
 * @param[out] output:           The generic HMAC result.
 * @param[out] outputLenInBytes: Size of the HMAC result in bytes. Optional.
 *
 * \note Expects output to be 32 bytes long
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes);

/*!	\brief Check that a private or public key is a valid key and the public key is on this curve.
 *
 * @param[in] grp:		The curve the point should belong to.
 * @param[in] key:		A pointer to the struct that holds the keys to check.
 * @param[in] type:      Determines whether to check the private key (PAL_CHECK_PRIVATE_KEY), public key (PAL_CHECK_PUBLIC_KEY), or both (PAL_CHECK_BOTH_KEYS).
 * @param[out] verified:	The result of the verification.
 *
 * \note	The key can contain only private or public key or both.
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified);

/*!	\brief Allocate key context and initialize a key pair as an invalid pair.
 *
 * @param[in] key:	The key pair context to initialize
 *
 * \return PAL_SUCCESS on success, negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECKeyNew(palECKeyHandle_t* key);

/*!	\brief Free the components of a key pair.
 *
 * @param[in] key:	The key pair to free.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECKeyFree(palECKeyHandle_t* key);

/*! \brief Initialize a pal key handle.
 *
 * In non-PSA configuration, allocate a key buffer, according to its size and initialize the pal key handle. 
 * 
 * @param[in] keyHandle: Pal key handle to be initialized.
 * @param[in] keySize: size of the key to be allocated
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_newKeyHandle( palKeyHandle_t *keyHandle, size_t keySize);

/*! \brief frees a pal key handle.
 *
 * In non-PSA configuration, free the allocated key buffer.
 *
 * @param[in] keyHandle: A handle for the key
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_freeKeyHandle( palKeyHandle_t *keyHandle);


/*!	\brief Parse a DER encoded private key.
 *
 * @param[in] prvDERKey:	A buffer that holds the DER encoded private key.
 * @param[in] keyLen:   The key length in bytes.
 * @param[out] key:		A handle for the context that holds the parsed key.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key);

/*!	\brief Parse a DER encoded public key.
 *
 * @param[in] pubDERKey:	A buffer that holds the DER encoded public key.
 * @param[in] keyLen:    The key length in bytes.
 * @param[out] key:		A handle for the context that holds the parsed key.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key);

/*! \brief Parse a private key.
*
* @param[in] prvKeyHandle:   A palKey_t object - either a PSA handle or a buffer and size of private key
* @param[out] ECKeyHandle:   A handle for the context that holds the parsed private key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_parseECPrivateKeyFromHandle(const palKeyHandle_t prvKeyHandle, palECKeyHandle_t ECKeyHandle);
/*! \brief Parse a public key.
*
* @param[in] pubKeyHandle:      A palKey_t object - either a PSA handle or a buffer and size of public key
* @param[out] ECKeyHandle:      A handle for the context that holds the parsed public key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_parseECPublicKeyFromHandle(const palKeyHandle_t pubKeyHandle, palECKeyHandle_t ECKeyHandle);

/*! \brief Encode the given private key from the key handle to the DER buffer.
 *
 * @param[in] key: 		 A handle to the private key.
 * @param[out] derBuffer: A buffer to hold the result of the DER encoding.
 * @param[in] bufferSize: The size of the allocated buffer in bytes.
 * @param[out] actualSize: The actual size of the written data in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize);

/*! \brief Encode the given public key from the key handle to the DER buffer.
 *
 * @param[in] key: 		 A handle to the public key.
 * @param[out] derBuffer: A buffer to hold the result of the DER encoding.
 * @param[in] bufferSize: The size of the allocated buffer in bytes.
 * @param[out] actualSize: The actual size of the written data in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize);

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
/*! \brief Write a pal private key handle from an EC key handle
 *
 * @param[in] prvKeyHandle:  A pal pivate key handle. Its buffer field is filled by the function
 * @param[in] ECKeyHandle:   A handle to EC Key handle.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_writePrivateKeyWithHandle(palKeyHandle_t prvKeyHandle, const palECKeyHandle_t ECKeyHandle);

/*! \brief Write a pal public key handle from an EC key handle
 *
 * @param[in] prvKeyHandle:  A pal public key handle. Its buffer field is filled by the function
 * @param[in] ECKeyHandle:   A handle to EC Key handle.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_writePublicKeyWithHandle(palKeyHandle_t pubKeyHandle, const palECKeyHandle_t ECKeyHandle);
#endif

/*! \brief Generate a curve ID for a keypair.
 *
 * @param[in] grpID:	The generated curve ID.
 * @param[in] key:	A handle to the destination keypair.
 *
 * \note The `key` parameter must be first allocated by `pal_ECKeyNew()`.
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key);

/*! \brief Retrieve the curve ID, if it exists, from the given key.
 *
 * @param[in] key: The key from which to retrieve the curve ID.
 * @param[out] grpID: The curve ID for the given key. In case of error, this pointer contains "PAL_ECP_DP_NONE".
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID);

/*! \brief Allocate and initialize the X.509 certificate signing request (CSR) context.
 *
 * @param[in] x509CSR:	The CSR context to allocate and initialize.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRInit(palx509CSRHandle_t *x509CSR);

/*! \brief Set the subject name for a certificate signing request (CSR). The subject name should contain a comma-separated list of OIDs and values.
 *
 * @param[in] x509CSR: 	  The CSR context to use.
 * @param[in] subjectName: The subject name to set.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName);

/*! \brief Set the message digest (MD) algorithm to use for the signature.
 *
 * @param[in] x509CSR:   The CSR context to use.
 * @param[in] mdType:    The MD algorithm to use.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType);

/*! \brief Set the key for a CSR.
 *
 * @param[in] x509CSR:   The CSR context to use.
 * @param[in] pubKey:    The public key to include. To use a keypair handle, see the note.
 * @param[in] prvKey:    The public key to sign with.
 *
 * \note To use a keypair, please send it as `pubKey` and NULL as `prvKey`.
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey);

/*! \brief Set flags for key usage extension.
 *
 * @param[in] x509CSR:   The CSR context to use.
 * @param[in] keyUsage:  The key usage flags. See `palKeyUsage_t` for options.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage);

/*! \brief Set flags for extended key usage extension.
 *
 * @param[in] x509CSR:   The CSR context to use.
 * @param[in] extKeyUsage:  The extended key usage flags, should be taken from `palExtKeyUsage_t`.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage);

/*! \brief Generic function to add to the CSR.
 *
 * @param[in] x509CSR:  The CSR context to use.
 * @param[in] oid:  	   The OID of the extension.
 * @param[in] oidLen: 	The OID length in bytes.
 * @param[in] value: 	The value of the extension OCTET STRING.
 * @param[in] valueLen:  The value length in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen);

/*! \brief Write a CSR to a DER structure.
 *
 * @param[in] x509CSR:       The CSR context to use.
 * @param[in] derBuf:  		A buffer to write to.
 * @param[in] derBufLen: 	The buffer length in bytes.
 * @param[in] actualDerLen: 	The actual length of the written data in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen);

/*! \brief Write a CSR from a given X.509 Certificate
 *
 * @param[in] x509Cert:      The parsed X.509 certificate.
 * @param[in,out] x509CSR:   A valid handle to a CSR that has already been initialized with at least private key.
 * @param[out] derBuf:  		A buffer to write to.
 * @param[out] derBufLen: 	The buffer length in bytes.
 * @param[out] actualDerBufLen: The actual length of the written data in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRFromCertWriteDER(palX509Handle_t x509Cert, palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerBufLen);

/*! \brief Calculate the hash of the To Be Signed (TBS) part of an X.509 certificate.
 *
 * This function may be used to validate a certificate signature. To do so, use this function to retrieve the hash, then verify the signature using the hash, the public key and the signature of the X.509
 *
 * @param[in] x509Cert:	        Handle to the certificate to hash the TBS.
 * @param[in] hash_type:	        The hash type. Currently only PAL_SHA256 supported
 * @param[out] output:	        Pointer to a buffer that will contain the hash digest. This buffer must be at least the size of the digest. When `hash_type` is PAL_SHA256, then buffer pointed to by output must be at least 32 bytes.
 * @param[in] outLenBytes:       The size of the buffer pointed to by output in bytes. Must be at least the size of the digest.
 * @param[out] actualOutLenBytes:    Size of the digest copied to output in bytes. In case of success, will always be the length of the hash digest.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char* output, size_t outLenBytes, size_t* actualOutLenBytes);

/*! \brief Free the X.509 CSR context.
 *
 * @param[in] x509CSR:	The CSR context to free.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CSRFree(palx509CSRHandle_t *x509CSR);

/*!	\brief Compute a shared secret.
 *
 * @param[in] grp:			The ECP group.
 * @param[in] peerPublicKey:	The public key from a peer.
 * @param[in] privateKey:	The private key.
 * @param[out] outKey:		The shared secret.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, const palECKeyHandle_t privateKey, palECKeyHandle_t outKey);

/*! \brief Compute the raw shared secret using elliptic curve Diffie�Hellman.
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

palStatus_t pal_plat_ECDHKeyAgreement(
    const uint8_t               *derPeerPublicKey,
    size_t                       derPeerPublicKeySize,
    const palECKeyHandle_t       privateKeyHandle,
    unsigned char               *rawSharedSecretOut,
    size_t                       rawSharedSecretMaxSize,
    size_t                      *rawSharedSecretActSizeOut);


/*!	\brief Compute the ECDSA signature of a previously hashed message.
 *
 * @param[in] grp:		The ECP group.
 * @param[in] prvKey:	The private signing key-
 * @param[in] dgst:		The message hash.
 * @param[in] dgstLen:	The length of the message buffer in bytes.
 * @param[out] sig:		A buffer to hold the computed signature.
 * @param[out] sigLen:  The length of the computed signature in bytes.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, uint32_t dgstLen, unsigned char *sig, size_t *sigLen);

/*!	\brief Verify the ECDSA signature of a previously hashed message.
 *
 * @param[in] pubKey:	The public key for verification.
 * @param[in] dgst:		The message hash.
 * @param[in] dgstLen:	The length of the message buffer in bytes.
 * @param[in] sign:		The signature.
 * @param[in] sig:		A buffer to hold the computed signature.
 * @param[in] sigLen:    The length of the computed signature in bytes.
 * @param[out] verified: The boolean to hold the verification result.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t sigLen, bool* verified);

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
palStatus_t pal_plat_convertRawSignatureToDer(
        const unsigned char         *rawSignature,
        size_t                       rawSignatureSize,
        unsigned char               *derSignatureOut,
        size_t                       derSignatureMaxSize,
        size_t                      *derSignatureActSizeOut);

/*!	\brief Compute the ECDSA raw signature of a previously hashed message.
*
*   The function supports keys with PAL_ECP_DP_SECP256R1 curve only.
*
* @param[in] privateKeyHandle:         The private signing key handle.
* @param[in] mdType:                   The MD algorithm to be used.
* @param[in] hash:                     The message hash.
* @param[in] hashSize:                 The size of the message buffer in bytes.
* @param[in/out] outSignature:         A buffer to hold the computed signature.
* @param[in] maxSignatureSize:         A size of the signature buffer.
* @param[out] actualOutSignatureSize:  The actual size of calculated signature.
*
* \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_asymmetricSign(const palECKeyHandle_t privateKeyHandle,  palMDType_t mdType, const unsigned char *hash, size_t hashSize, unsigned char *outSignature, size_t maxSignatureSize, size_t *actualOutSignatureSize);

/*!	\brief Verify the ECDSA raw signature of a previously hashed message.
*
* @param[in] publicKeyHanlde: The public key for verification.
* @param[in] mdType:          The MD algorithm to be used.
* @param[in] hash:            The message hash.
* @param[in] hashSize:        The size of the message buffer in bytes.
* @param[in] signature:       The raw signature.
* @param[in] signatureSize:   The size of the computed signature in bytes.
*
* \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_asymmetricVerify(const palECKeyHandle_t publicKeyHanlde, palMDType_t mdType, const unsigned char *hash, size_t hashSize, const unsigned char *signature, size_t signatureSize);

/*!	\brief Free the components of an ECP group.
 *
 * @param[in] grp:	The group to free.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECGroupFree(palCurveHandle_t* grp);

/*!	\brief Initialize an ECP group and set it using well-known domain parameters.
 *
 * @param[in] grp:	The destination group.
 * @param[in] index:	The index in the list of well-known domain parameters.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index);

#if defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) &&  !defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)
// This is the kv_key value used by Mbed OS PSA APIs for entropy initialization. Using the save value for DRBG to maintain
// backwards compatibility. This was added for backwards compatibility between Mbed OS 5.15 and Mbed OS 6.
// Previously all non-TRNG targets used PSA to inject entropy, but if application now uses direct KVStore mode (which is default)
// we need to ensure that we use the same name for the kv_key.
#define ENTROPY_RANDOM_SEED "B#S9---D"
/*! \brief Initialize all data structures (semaphores, mutexes, memory pools, message queues) at system initialization.
*
*   In case of a failure in any of the initializations, the function returns an error and stops the rest of the initializations.
* \return PAL_SUCCESS(0) in case of success, PAL_ERR_CREATION_FAILED in case of failure.
*/
palStatus_t pal_plat_DRBGInit(void);

/*! \brief De-initialize thread objects.
*/
palStatus_t pal_plat_DRBGDestroy(void);

// XXX: following two are really easy to mix up, a better naming needs to be done
//
// * pal_plat_osRandomBuffer_public() - The one which is called by pal_osRandomBuffer(), one which
//                                      will block until there is enough entropy harvested
//
// * pal_plat_osRandomBuffer() - The lower level part, used by pal_plat_osRandomBuffer_public(),
//                                  this is nonblocking version which will return as much as possible.
//                               Perhaps this should be pal_plat_GetosRandomBufferFromHW() to align
//                               with logic used with similar purpose function as pal_plat_osGetRoTFromHW().



/*! \brief Generate random number into given buffer with given size in bytes.
*
* @param[out] randomBuf A buffer to hold the generated number.
* @param[in] bufSizeBytes The size of the buffer and the size of the required random number to generate.
*
* \note `pal_init()` MUST be called before this function
* \note If non-volatile entropy is expected, the entropy must have been injected before this function is called. Non-volatile entropy may be injected using `pal_plat_osEntropyInject()`.
* \return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t  pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes);
/*! \brief De-initialize thread objects.
*/
palStatus_t pal_plat_DRBGDestroy(void);
#endif

#ifdef __cplusplus
}
#endif
#endif //_PAL_PLAT_CRYPTO_H_
