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

#ifndef _PAL_PLAT_CRYPTO_H_
#define _PAL_PLAT_CRYPTO_H_

#include "pal_Crypto.h"

/*! \file pal_plat_Crypto.h
*  \brief PAL cryptographic - platform.
*   This file contains cryptographic APIs that need to be implemented in the platform layer.
*/

/*!	Initiate the Crypto library. Initialization may not be required for some crypto libraries. In such
 * cases, the implementation may be empty.
 *
\note This function must be called in the general PAL initializtion function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_initCrypto(void);

/*!	Free resources for the Crypto library.
*
\note This function must be called in the general PAL cleanup function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_cleanupCrypto(void);

/*! Initialize AES context.
 *
 * @param[in,out] aes: AES context to be initialized.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_initAes(palAesHandle_t *aes);

/*! Free AES context.
 *
 * @param[in,out] aes: AES context to be deallocated.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_freeAes(palAesHandle_t *aes);

/*! Set AES key context for encryption or decryption.
 *
 * @param[in] aes: AES context.
 * @param[in] key: AES key.
 * @param[in] keybits: The size of the key in bits.
 * @param[in] keyTarget: The key target (encryption/decryption).
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_setAesKey(palAesHandle_t aes, const unsigned char* key, uint32_t keybits, palAesKeyType_t keyTarget);

/*! AES-CTR buffer encryption/decryption.
 *
 * @param[in] aes: AES context.
 * @param[in] input: The input data buffer.
 * @param[out] output: The output data buffer.
 * @param[in] inLen: The length of the input data.
 * @param[in] iv: The initialization vector for AES-CTR.
 * @param[in] zeroOffset: Send offset value zero to platform function.
 *
 \note Due to the nature of CTR you should use the same key schedule for both encryption and decryption. 
 * So before calling this function you MUST call `pal_setAesKey()` with the key target PAL_KEY_TARGET_ENCRYPTION to set the key.
 * 
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_aesCTR(palAesHandle_t aes, const unsigned char* input, unsigned char* output, size_t inLen, unsigned char iv[16], bool zeroOffset);

/*! AES-ECB block encryption/decryption.
 *
 * @param[in] aes: AES context.
 * @param[in] input: A 16-byte input block.
 * @param[out] output: A 16-byte output block.
 * @param[in] mode: PAL_AES_ENCRYPT or PAL_AES_DECRYPT
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_aesECB(palAesHandle_t aes, const unsigned char input[PAL_CRYPT_BLOCK_SIZE], unsigned char output[PAL_CRYPT_BLOCK_SIZE], palAesMode_t mode);

/*! Process SHA256 over the input buffer.
 *
 * @param[in] input: A buffer for the input data.
 * @param[in] inLen: The length of the input data.
 * @param[out] output: SHA256 checksum result.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_sha256(const unsigned char* input, size_t inLen, unsigned char* output);

/*! Initialize a certificate (chain) context.
 *
 * @param[in,out] x509Cert: The certificate chain to initialize.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509Initiate(palX509Handle_t* x509);

/*! Parse one or more certificates and add them to the chained list.
 *
 * @param[in] x509Cert: The start of the chain.
 * @param[in] input: A buffer holding the certificate data in PEM or DER format.
 * @param[in] inLen: The size of the input buffer.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509CertParse(palX509Handle_t x509, const unsigned char* input, size_t inLen);

/*! Get attributes from the parsed certificate.
*
* @param[in] x509Cert: The parsed certificate.
* @param[in] attr: The required attribute.
* @param[out] output: A buffer to hold the attribute value.
* @param[in] outLenBytes: The size of the allocated buffer.
* @param[out] actualOutLenBytes: The actual size of the attribute.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CertGetAttribute(palX509Handle_t x509Cert, palX509Attr_t attr, void* output, size_t outLenBytes, size_t* actualOutLenBytes);

/*! Verify one or more X509 DER formatted certificates.
 *
 * @param[in] x509Cert: A handle holding the parsed certificate.
 * @param[in] x509CertChain: The start of the chain to verify the X509 DER certificate with. (Optional) 
 * @param[out] verifyResult: bitmask of errors that cause the failure, this value is 
*							relevant ONLY in case that the return value of the function is `PAL_ERR_X509_CERT_VERIFY_FAILED`.
*
\note In case platform doesn't support multipule errors for certificate verification, please return `PAL_ERR_X509_CERT_VERIFY_FAILED` and the reason should be specified in the `verifyResult`
\return PAL_SUCCESS on success. In case of failure returns `PAL_ERR_X509_CERT_VERIFY_FAILED`.
*/
palStatus_t pal_plat_x509CertVerifyExtended(palX509Handle_t x509Cert, palX509Handle_t x509CertChain, int32_t* verifyResult);

/*! Deallocate all certificate data.
 *
 * @param[in,out] x509: The certificate chain to free. 
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_x509Free(palX509Handle_t* x509);

/*! Initialize an MD context and set up the required data according to the given algorithm.
 *
 * @param[in,out] md: The MD context to be initialized.
 * @param[in] mdType: The MD algorithm.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdInit(palMDHandle_t* md, palMDType_t mdType);

/*! Generic message digest process buffer.
 *
 * @param[in] md: The MD context.
 * @param[in] input: A buffer holding the input data.
 * @param[in] inLen: The length of the input data.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdUpdate(palMDHandle_t md, const unsigned char* input, size_t inLen);

/*! Generic message digest output buffer size getter.
 *
 * @param[in] md: The MD context.
 * @param[out] bufferSize: A pointer to hold the output size of the` pal_mdFinal()` for the given handle. 
 *
 \note You SHOULD call this function before calling `pal_mdFinal()`.
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdGetOutputSize(palMDHandle_t md, size_t* bufferSize);

/*! Generic message digest final digest.
 *
 * @param[in] md: The MD context.
 * @param[in] output: The generic message digest checksum result.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdFinal(palMDHandle_t md, unsigned char* output);

/*! Free and clear the MD context.
 *
 * @param[in,out] md: The AES context to be freed.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_mdFree(palMDHandle_t* md);

/*! Verify the signature.
 *
 * @param[in] x509: The certificate context that holds the PK data.
 * @param[in] mdType: The MD algorithm used.
 * @param[in] hash: The hash of the message to sign.
 * @param[in] hashLen: The hash length.
 * @param[in] sig: The signature to verify.
 * @param[in] sigLen: The signature length.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_verifySignature(palX509Handle_t x509, palMDType_t mdType, const unsigned char *hash, size_t hashLen, const unsigned char *sig, size_t sigLen ); 

/*! Get the tag and its length, check for the requested tag.
*   Updates the pointer to immediately after the tag and length. 
 *
 * @param[in,out] position: The position in the ASN.1 data.
 * @param[in] end: The end of data.
 * @param[out] len: The tag length.
 * @param[in] tag: The expected tag.
 *
 \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_ASN1GetTag(unsigned char **position, const unsigned char *end, size_t *len, uint8_t tag );

/*!	CCM initialization.
*
* @param[in] ctx: The CCM context to be initialized.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CCMInit(palCCMHandle_t* ctx);

/*!	CCM destruction.
*
* @param[in] ctx: The CCM context to destroy.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CCMFree(palCCMHandle_t* ctx);

/*!	CCM set key.
*
* @param[in] ctx:       The CCM context.
* @param[in] id:        The cipher to use (a 128-bit block cipher).
* @param[in] key:       The encryption key.
* @param[in] keybits:   The key size in bits (must be acceptable by the cipher).
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CCMSetKey(palCCMHandle_t ctx, palCipherID_t id, const unsigned char *key, unsigned int keybits);

/*!	CCM buffer authenticated decryption.
*
* @param[in] ctx:       The CCM context.
* @param[in] input      A buffer holding the input data.
* @param[in] inLen:    	The length of the input data.
* @param[in] iv:        The initialization vector.
* @param[in] ivLen:    	The length of the IV.
* @param[in] add:       Additional data.
* @param[in] addLen:   	The length of additional data.
* @param[in] tag:      	A buffer holding the tag.
* @param[in] tag_len:  	The length of the tag.
* @param[out] output:   A buffer for holding the output data.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CCMDecrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* tag, size_t tagLen, unsigned char* output);

/*!	CCM buffer encryption.
*
* @param[in] ctx:       The CCM context.
* @param[in] input      A buffer holding the input data.
* @param[in] inLen:    	The length of the input data.
* @param[in] iv:        The initialization vector.
* @param[in] ivLen:    	The length of the IV.
* @param[in] add:       Additional data.
* @param[in] addLen:   	The length of additional data.
* @param[out] output:   A buffer for holding the output data, must be at least 'inLen' bytes wide.
* @param[out] tag:      A buffer for holding the tag.
* @param[out] tag_len:  The length of the tag to generate in bytes.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CCMEncrypt(palCCMHandle_t ctx, unsigned char* input, size_t inLen, unsigned char* iv, size_t ivLen, unsigned char* add, size_t addLen, unsigned char* output, unsigned char* tag, size_t tagLen);

/*!	CTR_DRBG initialization.
*
* @param[in] ctx:   The CTR_DRBG context to be initialized.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CtrDRBGInit(palCtrDrbgCtxHandle_t* ctx);

/*!	CTR_DRBG destroy.
*
* @param[in] ctx:   The CTR_DRBG context to destroy.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CtrDRBGFree(palCtrDrbgCtxHandle_t* ctx);

/*!	CTR_DRBG initial seeding.
*
* @param[in] ctx:	The CTR_DRBG context to be seeded.
* @param[in] seed:	The seed data.
* @param[in] len:	The seed data length.
*
\return PAL_SUCCESS on success, negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CtrDRBGSeed(palCtrDrbgCtxHandle_t ctx, const void* seed, size_t len);

/*!	CTR_DRBG generate random.
*
* @param[in] ctx:	The CTR_DRBG context.
* @param[in] out:	The buffer to fill.
* @param[in] len:	The length of the buffer.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CtrDRBGGenerate(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len);

/*!	CTR_DRBG generate random with additional update input.
*
* @param[in] ctx:	The CTR_DRBG context.
* @param[in] out:	The buffer to fill.
* @param[in] len:	The length of the buffer.
* @param[in] additional:	Additional data to update with.
* @param[in] additionalLen:	Length of additional data.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CtrDRBGGenerateWithAdditional(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len, unsigned char* additional, size_t additionalLen);

#if PAL_CMAC_SUPPORT

/*!	AES cipher CMAC.
*
* @param[in] ctx:               The CMAC context to initialize.
* @param[in] key:               The encryption key.
* @param[in] keyLenInBits:      The key size in bits.
* @param[in] input:             A buffer for the input data.
* @param[in] inputLenInBytes:   The input data length in bytes.
* @param[out] output:           Generic CMAC result.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_cipherCMAC(const unsigned char *key, size_t keyLenInBits, const unsigned char *input, size_t inputLenInBytes, unsigned char *output);

/*!	Iterative cipher CMAC start.
*
* @param[in] ctx:   	 The CMAC context to initialize.
* @param[in] key:  		 The CMAC key.
* @param[in] keyLenBits: The key size in bits.
* @param[in] cipherID:   A buffer for the input data.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CMACStart(palCMACHandle_t *ctx, const unsigned char *key, size_t keyLenBits, palCipherID_t cipherID);

/*!	Iterative cipher CMAC update.
*
* @param[in] ctx:   	The CMAC context to initialize.
* @param[in] input:  	A buffer for the input data.
* @param[in] inputLen:  The input data length.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CMACUpdate(palCMACHandle_t ctx, const unsigned char *input, size_t inLen);

/*!	Iterative cipher CMAC finish.
*
* @param[in] ctx:   	The CMAC context to initialize.
* @param[out] output:  	A buffer for the output data.
* @param[out] outLen:   The output data length.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_CMACFinish(palCMACHandle_t *ctx, unsigned char *output, size_t* outLen);

#endif //PAL_CMAC_SUPPORT

/*! One shot md HMAC.
*
* @param[in] key:  				The encryption key.
* @param[in] keyLenInBytes:   	The key size in bytes.
* @param[in] input:  	        A buffer for the input data.
* @param[in] inputLenInBytes:   The input data length in bytes.
* @param[out] output:           The generic HMAC result.
* @param[out] outputLenInBytes: Size of the HMAC result (optional).
*
\note Expects output to be 32 bytes long
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_mdHmacSha256(const unsigned char *key, size_t keyLenInBytes, const unsigned char *input, size_t inputLenInBytes, unsigned char *output, size_t* outputLenInBytes);


/*!	Check that the private and/or public key is a valid key and the public key is on this curve.
*
* @param[in] grp:		The curve/group the point should belong to.
* @param[in] key:		A pointer to the struct that holds the keys to check.
* @param[in] type:      PAL_CHECK_PRIVATE_KEY/PAL_CHECK_PUBLIC_KEY/PAL_CHECK_BOTH_KEYS
* @param[out] verified:	The result of the verification.
*
\note	The key can contain only private or public key or both.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECCheckKey(palCurveHandle_t grp, palECKeyHandle_t key, uint32_t type, bool *verified);

/*!	Allocate key context and initialize a key pair (as an invalid one).
*
* @Param[in] key:	The key pair context to initialize
*
\return PAL_SUCCESS on success, negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECKeyNew(palECKeyHandle_t* key);

/*!	Free the components of a key pair.
*
* @param[in] key:	The key to free.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECKeyFree(palECKeyHandle_t* key);

/*!	Parse a DER encoded private key.
*
* @param[in] prvDERKey:	A buffer that holds the DER encoded private key.
* @param[in] keyLen:   The key length.
* @param[out] key:		A handle for the context that holds the parsed key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_parseECPrivateKeyFromDER(const unsigned char* prvDERKey, size_t keyLen, palECKeyHandle_t key);

/*!	Parse a DER encoded public key.
*
* @param[in] pubDERKey:	A buffer that holds the DER encoded public key.
* @param[in] keyLen:    The key length.
* @param[out] key:		A handle for the context that holds the parsed key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_parseECPublicKeyFromDER(const unsigned char* pubDERKey, size_t keyLen, palECKeyHandle_t key);

/*! Encode the given private key from the key handle to the DER buffer.
*
* @param[in] key: 		 A handle to the private key.
* @param[out] derBuffer: A buffer to hold the result of the DER encoding.
* @param[in] bufferSize: The size of the allocated buffer.
* @param[out] actualSize: The actual size of the written data.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_writePrivateKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize);

/*! Encode the given public key from the key handle to the DER buffer.
*
* @param[in] key: 		 A handle to the public key.
* @param[out] derBuffer: A buffer to hold the result of the DER encoding.
* @param[in] bufferSize: The size of the allocated buffer.
* @param[out] actualSize: The actual size of the written data.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_writePublicKeyToDer(palECKeyHandle_t key, unsigned char* derBuffer, size_t bufferSize, size_t* actualSize);

/*!	 Generate a keypair.
*
* @param[in] grpID:	The ECP group identifier.
* @param[in] key:	A handle to the destination keypair.
*
\note The `key` parameter must be first allocated by `pal_ECKeyNew()`.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECKeyGenerateKey(palGroupIndex_t grpID, palECKeyHandle_t key);

/*! Retrieve the curve ID if it exists in the given key. 
*
* @param[in] key: The key to retrieve its curve. 
* @param[out] grpID: The curve/group ID for the given key. In case of error, this pointer contains "PAL_ECP_DP_NONE".
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECKeyGetCurve(palECKeyHandle_t key, palGroupIndex_t* grpID);

/*! Allocate and initialize the x509 CSR context.
*
* @param[in] x509CSR:	The CSR context to allocate and initialize. 
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRInit(palx509CSRHandle_t *x509CSR);

/*! Set the subject name for a CSR. The subject names should contain a comma-separated list of OIDs and values.
*
* @param[in] x509CSR: 	  The CSR context to use.
* @param[in] subjectName: The subject name to set.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRSetSubject(palx509CSRHandle_t x509CSR, const char* subjectName);

/*! Set the MD algorithm to use for the signature.
*
* @param[in] x509CSR:   The CSR context to use.
* @param[in] mdType:    The MD algorithm to use.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRSetMD(palx509CSRHandle_t x509CSR, palMDType_t mdType);

/*! Set the key for a CSR.
*
* @param[in] x509CSR:   The CSR context to use.
* @param[in] pubKey:    The public key to include. To use the keypair handle, see the note.
* @param[in] prvKey:    The public key to sign with.
*
\note To use the keypair, please send it as `pubKey` and NULL as `prvKey`.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRSetKey(palx509CSRHandle_t x509CSR, palECKeyHandle_t pubKey, palECKeyHandle_t prvKey);

/*! Set the key usage extension flags.
*
* @param[in] x509CSR:   The CSR context to use.
* @param[in] keyUsage:  The key usage flags that should be taken from `palKeyUsage_t`.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRSetKeyUsage(palx509CSRHandle_t x509CSR, uint32_t keyUsage);

/*! Set the extended key usage extension.
*
* @param[in] x509CSR:   The CSR context to use.
* @param[in] extKeyUsage:  The extended key usage flags, should be taken from `palExtKeyUsage_t`.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRSetExtendedKeyUsage(palx509CSRHandle_t x509CSR, uint32_t extKeyUsage);

/*! Generic function to add to the CSR.
*
* @param[in] x509CSR:  The CSR context to use.
* @param[in] oid:  	   The OID of the extension.
* @param[in] oidLen: 	The OID length.
* @param[in] value: 	The value of the extension OCTET STRING.
* @param[in] valueLen:  The value length.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRSetExtension(palx509CSRHandle_t x509CSR,const char* oid, size_t oidLen, const unsigned char* value, size_t valueLen);

/*! Write a CSR to a DER structure.
*
* @param[in] x509CSR:      The CSR context to use.
* @param[in] derBuf:  		A buffer to write to.
* @param[in] derBufLen: 	The buffer length.
* @param[in] actualDerLen: 	The actual length of the written data.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRWriteDER(palx509CSRHandle_t x509CSR, unsigned char* derBuf, size_t derBufLen, size_t* actualDerLen);

/*! Calculate the hash of the To Be Signed part of an X509 certificate.
* This function may be used to validate a certificate signature: Simply retrieve this hash, verify the signature using this hash, the public key and the signature of the X509
*
* @param[in] x509Cert:	        Handle to the certificate to hash the TBS (to be signed part). 
* @param[in] hash_type:	        The hash type. Currently only PAL_SHA256 supported
* @param[out] output:	        Pointer to a buffer that will contain the hash digest. This buffer must be at least the size of the digest. If hash_type is PAL_SHA256, then buffer pointed to by output must be at least 32 bytes. 
* @param[in] outLenBytes:       The size of the buffer pointed to by output. Must be at least the size of the digest
* @param[out] actualOutLenBytes:    Size of the digest copied to output. In case of success, will always be the length of the hash digest
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CertGetHTBS(palX509Handle_t x509Cert, palMDType_t hash_type, unsigned char* output, size_t outLenBytes, size_t* actualOutLenBytes);

/*! Free the x509 CSR context.
*
* @param[in] x509CSR:	The CSR context to free.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_x509CSRFree(palx509CSRHandle_t *x509CSR);

/*!	Compute a shared secret.
*
* @param[in] grp:			The ECP group.
* @param[in] peerPublicKey:	The public key from a peer.
* @param[in] privateKey:	The private key.
* @param[out] outKey:		The shared secret.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECDHComputeKey(const palCurveHandle_t grp, const palECKeyHandle_t peerPublicKey, const palECKeyHandle_t privateKey, palECKeyHandle_t outKey);

/*!	Compute the ECDSA signature of a previously hashed message.
*
* @param[in] grp:		The ECP group.
* @param[in] prvKey:	The private signing key-
* @param[in] dgst:		The message hash.
* @param[in] dgstLen:	The length of the message buffer.
* @param[out] sig:		A buffer to hold the computed signature.
* @param[out] sigLen:  The length of the computed signature.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECDSASign(palCurveHandle_t grp, palMDType_t mdType, palECKeyHandle_t prvKey, unsigned char* dgst, uint32_t dgstLen, unsigned char *sig, size_t *sigLen);

/*!	Verify the ECDSA signature of a previously hashed message.
*
* @param[in] pubKey:	The public key for verification.
* @param[in] dgst:		The message hash.
* @param[in] dgstLen:	The length of the message buffer.
* @param[in] sign:		The signature.
* @param[in] sig:		A buffer to hold the computed signature.
* @param[in] sigLen:    The length of the computed signature.
* @param[out] verified: The boolean to hold the verification result.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECDSAVerify(palECKeyHandle_t pubKey, unsigned char* dgst, uint32_t dgstLen, unsigned char* sig, size_t sigLen, bool* verified);

/*!	Free the components of an ECP group.
*
* @param[in] grp:	The curve/group to free.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECGroupFree(palCurveHandle_t* grp);

/*!	ECP group initialize and set a group using well-known domain parameters.
*
* @param[in] grp:	The destination group.
* @param[in] index:	The index in the list of well-known domain parameters.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_ECGroupInitAndLoad(palCurveHandle_t* grp, palGroupIndex_t index);


#endif //_PAL_PLAT_CRYPTO_H_
