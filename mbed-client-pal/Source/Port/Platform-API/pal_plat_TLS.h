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

#ifndef _PAL_PLAT_TLS_H_
#define _PAL_PLAT_TLS_H_
#include "pal_TLS.h"

/*! \file pal_plat_TLS.h
*  \brief PAL TLS/DTLS - platform.
*   This file contains TLS/DTLS APIs that need to be implemented in the platform layer. 
*/

/***************************************************/
/**** PAL DTLS internal data structures ************/
/***************************************************/
typedef enum palDTLSSide{
#ifdef PAL_TLS_SUPPORT_SERVER_MODE
	PAL_TLS_IS_SERVER,
#endif // PAL_TLS_SUPPORT_SERVER_MODE
	PAL_TLS_IS_CLIENT
} palDTLSSide_t;

typedef enum palTLSAuthMode{
	PAL_TLS_VERIFY_NONE,		//! Server mode: The peer certificate is not verified. For client mode, this is insecure!
	PAL_TLS_VERIFY_OPTIONAL,	//! The peer certificate verification can be failed and handshake continues.
	PAL_TLS_VERIFY_REQUIRED		//! The peer certificate verification MUST pass.
}palTLSAuthMode_t;

//! This is the list of the available cipher suites, this code MUST be 
//! defined in the `pal_plat_TLS.c` with the proper values for the SSL platform:
typedef enum palTLSSuites{
	PAL_TLS_PSK_WITH_AES_128_CBC_SHA256,
	PAL_TLS_PSK_WITH_AES_128_CCM_8,
	PAL_TLS_PSK_WITH_AES_256_CCM_8,
	PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
}palTLSSuites_t;

typedef void* palTLSSocketHandle_t;
typedef void* palTimerCtx_t;

//! This prototype can be re-defined by the platform side.
//! Consider moving them to separate header.
typedef int (*palBIOSend_f)(palTLSSocketHandle_t socket, const unsigned char *buf, size_t len);
typedef int (*palBIORecv_f)(palTLSSocketHandle_t socket, unsigned char *buf, size_t len);
typedef int (*palVerifyCallback_f)(void *, void *, int, uint32_t *);
typedef void (*palSetTimer_f)( void *data, uint32_t intMs, uint32_t finMs ); 
typedef int (*palGetTimer_f)(void* data);
typedef void (*palLogFunc_f)(void *context, int debugLevel, const char *fileName, int line, const char *message);


/*!	Initiate the TLS library. This API is not required for each TLS library.
* 	For example for mbed TLS, it will be an empty function.
*
\note You must call this function in the general PAL initializtion function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_initTLSLibrary(void);

/*!	Free resources for the TLS library.
*
\note You must call this function in the general PAL cleanup function.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_cleanupTLS(void);

/*! Initiate new configuration context.
*
* @param[out] palTLSConf: The TLS configuration context.
* @param[in] tranportVersion: The `palTLSTransportMode_t` type deciding the transportation version (for example tlsv1.2).
* @param[in] methodType: The `palDTLSSide_t` type deciding the endpoint type (server or client).
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_initTLSConf(palTLSConfHandle_t* confCtx, palTLSTransportMode_t transportVersion, palDTLSSide_t methodType);

/*! Destroy and release resources for the TLS configuration context.
*
* @param[inout] palTLSConf: The TLS configuration context to free.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_tlsConfigurationFree(palTLSConfHandle_t* palTLSConf);

/*!	Initiate a new TLS context.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[out] palTLSHandle: The index to the TLS context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle);

/*! Destroy and release resources for the TLS context.
*
* @param[inout] ssl: The TLS context to free.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_freeTLS(palTLSHandle_t* palTLSHandle);

/*! Add an entropy source to the TLS/DTLS library (this API may NOT be available in all TLS/DTLS platforms, see the note).
*
* @param[in] entropyCallback: The entropy callback to be used in the TLS/DTLS handshake.
*
\note This function is available ONLY when the TLS/DTLS platform supports this functionality. In other platforms,
      PAL_ERR_NOT_SUPPORTED should be returned.
\return PAL_SUCCESS on success. A negative value indicating a specific error code or PAL_ERR_NOT_SUPPORTED in case of failure.
*/
palStatus_t pal_plat_addEntropySource(palEntropySource_f entropyCallback);

/*!	Set the supported cipher suites to the configuration context.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] palSuites: The supported cipher suites to be added.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setCipherSuites(palTLSConfHandle_t sslConf, palTLSSuites_t palSuite);

/*!	 Return the result of the certificate verification. The handshake API calls this.
*
* @param[in] ssl: The TLS context.
* @param[out] verifyResult: bitmask of errors that cause the failure, this value is 
*							relevant ONLY in case that the return value of the function is `PAL_ERR_X509_CERT_VERIFY_FAILED`.
*
\note In case platform doesn't support multipule errors for certificate verification, please return `PAL_ERR_X509_CERT_VERIFY_FAILED` and the reason should be specified in the `verifyResult`
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_sslGetVerifyResultExtended(palTLSHandle_t palTLSHandle, int32_t* verifyResult);

/*!  Read at most 'len' application data bytes.
*
* @param[in] ssl: The TLS context.
* @param[out] buffer: A buffer holding the data.
* @param[in] len: The maximum number of bytes to read.
* @param[out] actualLen: The actual number of bytes read.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen);

/*! Try to write exactly 'len' application data bytes.
*
* @param[in] ssl: The TLS context.
* @param[in] buffer: A buffer holding the data.
* @param[in] len: The number of bytes to be written.
* @param[out] bytesWritten: The number of bytes actually written.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten);

/*! Set the retransmit timeout values for the DTLS handshake.
*	(DTLS only, no effect on TLS.)
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] timeoutInMilliSec: The maximum timeout value in milliseconds.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t timeoutInMilliSec);

/*!	Set up a TLS context for use.
*
* @param[in/out] ssl: The TLS context.
* @param[in] palTLSConf: The TLS configuration context.
*
\return The function returns `palTLSHandle_t`, the index to the TLS context.
*/
palStatus_t pal_plat_sslSetup(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);

/*! Perform the TLS handshake.
*
* @param[in] ssl: The TLS context.
* @param[out] serverTime: The server time recieved in the server hello message during handshake.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_handShake(palTLSHandle_t palTLSHandle, uint64_t* serverTime);

#if PAL_USE_SECURE_TIME
/*! Perform the TLS handshake renegotiation.
*
* @param[in] ssl: The TLS context.
* @param[in] serverTime: The server time used to update the TLS time during handshake renegotiate.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_renegotiate(palTLSHandle_t palTLSHandle, uint64_t sreverTime);
#endif //PAL_USE_SECURE_TIME

/*! Set the socket for the TLS configuration context.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] socket: The socket for the TLS context.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket);

/*! Set your own certificate chain and private key.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] ownCert: Your own public certificate chain.
* @param[in] privateKey: Your own private key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setOwnCertAndPrivateKey(palTLSConfHandle_t palTLSConf, palX509_t* ownCert, palPrivateKey_t* privateKey);

/*! Set the data required to verify a peer certificate.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] caChain: The trusted CA chain.
* @param[in] caCRL: The trusted CA CRLs.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL);

/*! Set the Pre-Shared Key (PSK) and the expected identity name.
*
* @param[in] sslConf: The TLS configuration context.
* @param[in] identity: A pointer to the pre-shared key identity.
* @param[in] maxIdentityLenInBytes: The maximum length of the identity key.
* @param[in] psk: A pointer to the pre-shared key.
* @param[in] maxPskLenInBytes: The maximum length of the pre-shared key.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setPSK(palTLSConfHandle_t sslConf, const unsigned char *identity, uint32_t maxIdentityLenInBytes, const unsigned char *psk, uint32_t maxPskLenInBytes);


/*!	Set the certificate verification mode.
*
* @param[in] sslConf: The TLS configuration context.
* @param[in] authMode: The authentication mode.
*
\note In some platforms, a verification callback MAY be needed. In this case, it must be provided by the porting side.
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setAuthenticationMode(palTLSConfHandle_t sslConf, palTLSAuthMode_t authMode);


/*! Turn on/off the TLS library debugging for the given configuration handle. The logs are sent via the mbedTrace.
*   In case of release mode, an error will be returned.
*
* @param[in] palTLSConf : the TLS confuguraiton to modify
* @param[in] turnOn: if greater than 0 turn on debugging, otherwise turn it off
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_sslSetDebugging(palTLSConfHandle_t palTLSConf, uint8_t turnOn);

/*! Set the IO callbacks for the TLS context. 
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] palIOCtx: The shared context by BIO callbacks.
* @param[in] palBIOSend: A pointer to send BIO function.
* @param[in] palBIORecv: A pointer to receive BIO function.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_sslSetIOCallBacks(palTLSConfHandle_t palTLSConf, palTLSSocket_t* palIOCtx, palBIOSend_f palBIOSend, palBIORecv_f palBIORecv);

/*!	Set the timer callbacks.
*
* @param[in] palTLSHandle: The TLS context.
* @param[in] timerCtx: The shared context by BIO callbacks.
* @param[in] setTimer: The set timer callback.
* @param[in] getTimer: The get timer callback.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_setTimeCB(palTLSHandle_t* palTLSHandle, palTimerCtx_t timerCtx, palSetTimer_f setTimer, palGetTimer_f getTimer);

/*! Set the logging function.
*
* @param[in] palTLSConf: The TLS configuration context.
* @param[in] palLogFunction: A pointer to the logging function.
* @param[in] logContext: The context for the logging function.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_SetLoggingCb(palTLSConfHandle_t palTLSConf, palLogFunc_f palLogFunction, void *logContext);

#endif //_PAL_PLAT_TLS_H_
