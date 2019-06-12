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

#ifndef _PAL_DTLS_H_
#define _PAL_DTLS_H_

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

/*! \file pal_TLS.h
*  \brief PAL TLS/DTLS.
*   This file contains TLS and DTLS APIs and is a part of the PAL service API.
*
*   It provides Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) handshake functionalities, allowing read and write from peers in a secure way.
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
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
typedef uintptr_t palPrivateKey_t;
#else
typedef palTLSBuffer_t palPrivateKey_t;
#endif
/*! \brief This callback is useful ONLY when mbed TLS is used as TLS platform library.
 *
 * In other platforms, you should NOT use this callback in the code.
 * The related function is not supported in other platforms than mbedTLS.
 */
typedef int(*palEntropySource_f)(void *data, unsigned char *output, size_t len, size_t *olen);

/***************************************************/
/**** PAL DTLS Client APIs *************************/
/***************************************************/

/*! \brief Initiate the TLS library.
 *
 * \note You must call this function in the general PAL initializtion function.
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_initTLSLibrary(void);

/*! \brief Free resources for the TLS library.
 *
 * \note You must call this function in the general PAL cleanup function.
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_cleanupTLS(void);

/*! \brief Initiate a new TLS context.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[out] palTLSHandle: The index to the TLS context.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle);

/*! \brief Destroy and free the resources of the TLS context.
 *
 * @param[in] palTLSHandle: The index to the TLS context.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_freeTLS(palTLSHandle_t* palTLSHandle);

/*! \brief Add an entropy source to the TLS/DTLS library. NOT available in all TLS/DTLS platforms, see note.
 *
 * @param[in] entropyCallback: The entropy callback to be used in the TLS or DTLS handshake.
 *
 * \note This function is available ONLY when the TLS or DTLS platform supports this functionality. In other platforms,
 *      PAL_ERR_NOT_SUPPORTED should be returned.
 * \note This function MUST be called (if needed) before calling the `pal_initTLSConfiguration()` function.
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure, or PAL_ERR_NOT_SUPPORTED.
 */
palStatus_t pal_addEntropySource(palEntropySource_f entropyCallback);

/*! \brief Initiate a new configuration context.
*
* @param[out] palTLSConf: The context that holds the TLS configuration.
* @param[in] transportationMode: The connection type: TLS or DTLS. See `palTranportVersion_t`.
*
* \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_initTLSConfiguration(palTLSConfHandle_t* palTLSConf, palTLSTransportMode_t transportationMode);

/*! \brief Destroy and free the resources of the TLS configurtion context.
 *
 * @param[in] palTLSConf: The TLS configuration context to free.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_tlsConfigurationFree(palTLSConfHandle_t* palTLSConf);

/*! \brief Set your own certificate chain.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[in] ownCert: Your own public certificate chain.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_setOwnCertChain(palTLSConfHandle_t palTLSConf, palX509_t* ownCert);

/*! Initialize a private key object
*
* @param[in] buf:         If MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined - pointer to a `uintptr_t` type, which contains the PSA handle.
*                         If MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is not defined - pointer to a private key.
* @param[in] buf_size:    If MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined - not relevant, as it is expected that buf points to a `uintptr_t` type.
*                         If MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is not defined - the size of the private key pointed to by buf.
* @param[out] privateKey: Pointer to an uninitialized `palPrivateKey_t` object.
*
\return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_initPrivateKey(const void *buf, size_t buf_size, palPrivateKey_t* privateKey);

/*! \brief Set your own private key.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[in] privateKey: Your own private key.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_setOwnPrivateKey(palTLSConfHandle_t palTLSConf, palPrivateKey_t* privateKey);

/*! \brief Set the data required to verify the peer certificate.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[in] caChain: The trusted CA chain.
 * @param[in] caCRL: The trusted CA CRLs.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL);

/*! \brief Set the Pre-Shared Key (PSK) and the expected identity name.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[in] identity: A pointer to the pre-shared key identity.
 * @param[in] maxIdentityLenInBytes: The length of the key identity.
 * @param[in] psk: A pointer to the pre-shared key.
 * @param[in] maxPskLenInBytes: The length of the pre-shared key.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_setPSK(palTLSConfHandle_t palTLSConf, const unsigned char *identity, uint32_t maxIdentityLenInBytes, const unsigned char *psk, uint32_t maxPskLenInBytes);

/*! \brief Set the socket used by the TLS configuration context.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[in] socket: The socket to be used by the TLS context.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket);

/*! \brief Perform the TLS handshake. This function is blocking.
 *
 * This function sets the TLS configuration context into the TLS context and performs the handshake
 * with the peer.
 * @param[in] palTLSHandle: The TLS context.
 * @param[in] palTLSConf: The TLS configuration context.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_handShake(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);

/*! \brief Set the retransmit timeout values for the DTLS handshake.
 *  DTLS only, no effect on TLS.
 *
 * @param[in] palTLSConf: The DTLS configuration context.
 * @param[in] timeoutInMilliSec: The timeout value in milliseconds.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t timeoutInMilliSec);

/*! \brief Return the result of the certificate verification.
 *
 * @param[in] palTLSHandle: The TLS context.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_sslGetVerifyResult(palTLSHandle_t palTLSHandle);

/*! \brief Return the result of the certificate verification.
 *
 * @param[in] palTLSHandle: The TLS context.
 * @param[out] verifyResult: Bitmask of errors that cause the failure. This value is
 *                           relevant ONLY in case that the return value of the function is `PAL_ERR_X509_CERT_VERIFY_FAILED`.
 *
 * \return PAL_SUCCESS on success.
 * \return PAL_ERR_X509_CERT_VERIFY_FAILED in case of failure.
 */
palStatus_t pal_sslGetVerifyResultExtended(palTLSHandle_t palTLSHandle, int32_t* verifyResult);

/*! \brief Read the application data bytes (the max number of bytes).
 *
 * @param[in] palTLSHandle: The TLS context.
 * @param[out] buffer: A buffer that holds the data.
 * @param[in] len: The maximum number of bytes to read.
 * @param[out] actualLen: The the actual number of bytes read.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen);

/*! \brief Write the exact length of application data bytes.
 *
 * @param[in] palTLSHandle: The TLS context.
 * @param[in] buffer: A buffer holding the data.
 * @param[in] len: The number of bytes to be written.
 * @param[out] bytesWritten: The number of bytes actually written.
 *
 * \return PAL_SUCCESS on success, or a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten);

/*! \brief Turn the debugging on or off for the given TLS library configuration handle. The logs are sent via the `mbedTrace`.
 *   In case of release mode, an error will be returned.
 *
 * @param[in] palTLSConf : The TLS confuguraiton to modify.
 * @param[in] turnOn: If greater than 0, turn on debugging. Otherwise turn it off.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_sslSetDebugging(palTLSConfHandle_t palTLSConf,uint8_t turnOn);

/*! Turn debugging on or off for the whole TLS library. The logs are sent via the `mbedTrace`.
 *   In case of release mode, an error will be returned.
 *
 * @param[in] turnOn: If greater than 0, turn on debugging. Otherwise turn it off.
 *
 * \return PAL_SUCCESS on success. A negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_sslDebugging(uint8_t turnOn);

#if (PAL_USE_SSL_SESSION_RESUME == 1)
/*! \brief Enable SSL session storing. Disabled by default.
 *
 * @param[in] palTLSConf: The TLS configuration context.
 * @param[in] enable: Enable session storing.
 *
 * \note This function MUST be called (if needed) before calling the `pal_initTLS()` function.
 *
 */
void pal_enableSslSessionStoring(palTLSConfHandle_t palTLSConf, bool enable);

#endif // PAL_USE_SSL_SESSION_RESUME

#endif // _PAL_DTLS_H_
