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

#ifndef _PAL_DTLS_H_
#define _PAL_DTLS_H_

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

/*! \file pal_TLS.h
*  \brief PAL TLS/DTLS.
*   This file contains TLS/DTLS APIs and is a part of the PAL service API.
*   It provides TLS/DTLS handshake functionalities, read/write from peer in a secure way.
*/

/***************************************************/
/**** PAL DTLS data structures *********************/
/***************************************************/

// Index in the static array of the TLSs.
typedef uintptr_t palTLSHandle_t;
typedef uintptr_t palTLSConfHandle_t;

typedef enum palTLSTranportMode{
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
	PAL_TLS_MODE, //(STREAM)
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
	PAL_DTLS_MODE //(DATAGRAM)
}palTLSTransportMode_t;

typedef struct palTLSSocket{
    palSocket_t socket;
    palSocketAddress_t* socketAddress;
    palSocketLength_t addressLength;
    palTLSTransportMode_t transportationMode;
}palTLSSocket_t;


typedef struct palTLSBuffer{
	const void* buffer;
	uint32_t size;
}palTLSBuffer_t;

typedef palTLSBuffer_t palX509_t;
typedef palTLSBuffer_t palX509CRL_t;
typedef palTLSBuffer_t palPrivateKey_t;

//! This callback is useful ONLY when mbed TLS used as TLS platform library. In other platforms,
//! you should NOT use this callback in the code. The related function is not supported in other
//! platforms than mbedTLS.
typedef int(*palEntropySource_f)(void *data, unsigned char *output, size_t len, size_t *olen);

/***************************************************/
/**** PAL DTLS Client APIs *************************/
/***************************************************/

/*!	Initiate the TLS library.
*
\note You must call this function in the general PAL initializtion function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_initTLSLibrary(void);

/*!	Free resources for the TLS library.
*
\note You must call this function in the general PAL cleanup function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_cleanupTLS(void);

/*! Initiate a new TLS context.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[out] palTLSHandle: The index to the TLS context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle);

/*! Destroy and free resources for the TLS context.
*
* @param[in] palTLSHandle: The index to the TLS context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_freeTLS(palTLSHandle_t* palTLSHandle);

/*! Add entropy source to the TLS/DTLS library. (This API may NOT be available in all TLS/DTLS platforms, see note.) 
*
* @param[in] entropyCallback: The entropy callback to be used in TLS/DTLS handshake.
*
\note This function is available ONLY when the TLS/DTLS platform supports this functionality. In other platforms,
      PAL_ERR_NOT_SUPPORTED should be returned.
\note This function MUST be called (if needed) before calling the `pal_initTLSConfiguration()` function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure, or PAL_ERR_NOT_SUPPORTED.
*/
palStatus_t pal_addEntropySource(palEntropySource_f entropyCallback);

/*! Initiate a new configuration context.
*
* @param[out] palTLSConf: The context that holds the TLS configuration.
* @param[in] transportationMode: The connection type (TLS OR DTLS). See `palTranportVersion_t`.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_initTLSConfiguration(palTLSConfHandle_t* palTLSConf, palTLSTransportMode_t transportationMode);

/*! Destroy and free resources for the TLS configurtion context.
*
* @param[in] palTLSConf: The TLS configuration context to free.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_tlsConfigurationFree(palTLSConfHandle_t* palTLSConf);

/*! Set your own certificate chain and private key.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] ownCert: Your own public certificate chain.
* @param[in] privateKey: Your own private key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_setOwnCertAndPrivateKey(palTLSConfHandle_t palTLSConf, palX509_t* ownCert, palPrivateKey_t* privateKey);

/*! Set the data required to verify the peer certificate.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] caChain: The trusted CA chain.
* @param[in] caCRL: The trusted CA CRLs.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL);

/*! Set the Pre-Shared Key (PSK) and the expected identity name.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] identity: A pointer to the pre-shared key identity.
* @param[in] maxIdentityLenInBytes: The length of the key identity.
* @param[in] psk: A pointer to the pre-shared key.
* @param[in] maxPskLenInBytes: The length of the pre-shared key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_setPSK(palTLSConfHandle_t palTLSConf, const unsigned char *identity, uint32_t maxIdentityLenInBytes, const unsigned char *psk, uint32_t maxPskLenInBytes);

/*! Set the socket used by the TLS configuration context.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] socket: The socket to be used by the TLS context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket);

/*! Perform the TLS handshake (blocking).
*
* This function sets the TLS configuration context into the TLS context and performs the handshake 
* with the peer.
* @param[in] palTLSHandle: The TLS context.
* @param[in] palTLSConf: The TLS configuration context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_handShake(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);

/*! Set the retransmit timeout values for the DTLS handshake.
*	(DTLS only, no effect on TLS.)
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] timeoutInMilliSec: The timeout value in seconds.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t timeoutInMilliSec);

/*! Return the result of the certificate verification.
*
* @param[in] ssl: The SSL context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_sslGetVerifyResult(palTLSHandle_t palTLSHandle);

/*! Return the result of the certificate verification.
*
* @param[in] ssl: The SSL context.
* @param[out] verifyResult: bitmask of errors that cause the failure, this value is 
*							relevant ONLY in case that the return value of the function is `PAL_ERR_X509_CERT_VERIFY_FAILED`.
*
\return PAL_SUCCESS on success. In case of failure returns `PAL_ERR_X509_CERT_VERIFY_FAILED`.
*/
palStatus_t pal_sslGetVerifyResultExtended(palTLSHandle_t palTLSHandle, int32_t* verifyResult);

/*! Read the application data bytes (the max number of bytes).
*
* @param[in] palTLSHandle: The TLS context.
* @param[out] buffer: A buffer that holds the data.
* @param[in] len: The maximum number of bytes to read.
* @param[out] actualLen: The the actual number of bytes read.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen);

/*! Write the exact length of application data bytes.
*
* @param[in] palTLSHandle: The TLS context.
* @param[in] buffer: A buffer holding the data.
* @param[in] len: The number of bytes to be written.
* @param[out] bytesWritten: The number of bytes actually written.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten);

/*! Turn on/off the TLS library debugging for the given configuration handle. The logs are sent via the mbedTrace.
*   In case of release mode, an error will be returned.
*
* @param[in] palTLSConf : the TLS confuguraiton to modify
* @param[in] turnOn: if greater than 0 turn on debugging, otherwise turn it off
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_sslSetDebugging(palTLSConfHandle_t palTLSConf,uint8_t turnOn);



/*! Turn on/off debugging from the TLS library. The logs are sent via the mbedTrace.
*   In case of release mode, an error will be returned.
*
* @param[in] turnOn if greater than 0 turn on debugging, otherwise turn it off
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_sslDebugging(uint8_t turnOn);

#endif // _PAL_DTLS_H_
