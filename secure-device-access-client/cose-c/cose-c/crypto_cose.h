// --------------------------------------------------------------------------------
//   Copyright (c) 2015, cose-wg
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer.
//   
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   
//   * Neither the name of COSE-C nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//   
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------------

#ifndef __COSE_CRYPTO_COSE_H__
#define __COSE_CRYPTO_COSE_H__

#include "cose.h"
#define COSE_Key_EC_Curve -1
#define COSE_Key_EC_X -2
#define COSE_Key_EC_Y -3

// groupSizeBytes is always the size of the key / 2.
// keySize has an extra byte containing compression type, so the actual key size is keySize - 1
#define EC_GROUP_SIZE(keySize) ((keySize - 1) / 2)
#ifdef USE_CN_CBOR
/**
* Perform an AES-CCM Decryption operation
*
* @param[in]   COSE_Enveloped Pointer to COSE Encryption context object
* @param[in]   int          Size of the Tag value to be create
* @param[in]   int          Size of the Message Length field
* @param[in]   byte *       Pointer to authenticated data structure
* @param[in]   int          Size of authenticated data structure
* @return                   Did the function succeed?
*/
bool AES_CCM_Decrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbitKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);
bool AES_GCM_Decrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbCrypto, size_t cbCrypto, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);
bool AES_KW_Decrypt(COSE_Enveloped * pcose, const byte * pbKeyIn, size_t cbitKey, const byte * pbCipherText, size_t cbCipherText, byte * pbKeyOut, int * pcbKeyOut, cose_errback * perr);

/**
* Perform an AES-CCM Encryption operation
*
* @param[in]   COSE_Enveloped Pointer to COSE Encryption context object
* @param[in]   int          Size of the Tag value to be create
* @param[in]   int          Size of the Message Length field
* @param[in]   byte *       Pointer to authenticated data structure
* @param[in]   int          Size of authenticated data structure
* @return                   Did the function succeed?
*/
bool AES_CCM_Encrypt(COSE_Enveloped * pcose, int TSize, int LSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);
bool AES_GCM_Encrypt(COSE_Enveloped * pcose, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);
bool AES_KW_Encrypt(COSE_RecipientInfo * pcose, const byte * pbKeyIn, int cbitKey, const byte *  pbContent, int  cbContent, cose_errback * perr);


extern bool AES_CMAC_Validate(COSE_MacMessage * pcose, int KeySize, int TagSize, const byte * pbKey, int cbitKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);

extern bool AES_CBC_MAC_Create(COSE_MacMessage * pcose, int TagSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);
extern bool AES_CBC_MAC_Validate(COSE_MacMessage * pcose, int TagSize, const byte * pbKey, size_t cbitKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);

/**
* Perform an HMAC Creation operation
*
* @param[in]	COSE_Enveloped	Pointer to COSE Encryption context object
* @param[in]	int				Hash function to be used
* @param[in]	int				Size of Tag value to be created
* @param[in]	byte *			Pointer to authenticated data structure
* @param[in]	int				Size of authenticated data structure
* @param[in]	cose_errback *	Error return location
* @return						Did the function succeed?
*/
bool HMAC_Create(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, size_t cbKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);
bool HMAC_Validate(COSE_MacMessage * pcose, int HSize, int TSize, const byte * pbKey, size_t cbitKey, const byte * pbAuthData, size_t cbAuthData, cose_errback * perr);

bool HKDF_Extract(COSE * pcose, const byte * pbKey, size_t cbKey, size_t cbitDigest, byte * rgbDigest, size_t * pcbDigest, CBOR_CONTEXT_COMMA cose_errback * perr);
bool HKDF_Expand(COSE * pcose, size_t cbitDigest, const byte * pbPRK, size_t cbPRK, const byte * pbInfo, size_t cbInfo, byte * pbOutput, size_t cbOutput, cose_errback * perr);

bool HKDF_AES_Expand(COSE * pcose, size_t cbitKey, const byte * pbPRK, size_t cbPRK, const byte * pbInfo, size_t cbInfo, byte * pbOutput, size_t cbOutput, cose_errback * perr);

/**
* Perform a signature operation
*
* @param[in]	COSE_SignerInfo Pointer to COSE SignerInfo context object
* @param[in]	byte *			Pointer to text to be signed
* @param[in]	size_t			size of text to be signed
* @param[in]	cose_errback *	Error return location
* @return						Did the function succeed?
*/
bool ECDSA_Sign(COSE * pSigner, int index, const cn_cbor * pKey, int cbitsDigest, const byte * rgbToSign, size_t cbToSign, cose_errback * perr);
bool ECDSA_Verify(COSE * pSigner, int index, const byte *pKey, size_t keySize, int cbitsDigest, const byte * rgbToSign, size_t cbToSign, cose_errback * perr);

bool ECDH_ComputeSecret(COSE * pReciient, cn_cbor ** ppKeyMe, const cn_cbor * pKeyYou, byte ** ppbSecret, size_t * pcbSecret, CBOR_CONTEXT_COMMA cose_errback *perr);

/**
*  Generate random bytes in a buffer
*
* @param[in]   byte *      Pointer to buffer to be filled
* @param[in]   size_t      Size of buffer to be filled
* @return                  none
*/
void rand_bytes(byte * pb, size_t cb);
#else

bool ECDSA_Verify_tiny(COSE *pSigner, int index, const byte *pKey, size_t keySize, int cbitDigest, const unsigned char *rgbToSign, size_t cbToSign, cose_errback *perr);
#endif
#endif

