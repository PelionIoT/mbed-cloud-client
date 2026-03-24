/*******************************************************************************
 * Copyright 2016-2021 Pelion.
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
#include "pal_plat_TLS.h"
#include "cs_pal_crypto.h"

#include "eventOS_scheduler.h"
#include "eventOS_event_timer.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <stdio.h>

#define TRACE_GROUP "PAL"

#define SSL_LIB_SUCCESS 0

typedef SSL platTlsContext;
typedef SSL_CTX platTlsConfigurationContext;

#define PalTimerEvent 100

typedef struct palTimingDelayContext
{
    uint64_t                              start_ticks;
    arm_event_storage_t*                  timer_event;
    bool                                  timer_expired;
    void*                                 callback_argument;
    palSocketCallback_f                   socket_cb;
} palTimingDelayContext_t;


//! the full structures will be defined later in the implemetation.
typedef struct palTLS {
    platTlsContext* tlsCtx;
    bool tlsInit;
    char* psk; //NULL terminated
    char* identity; //NULL terminated
    bool wantReadOrWrite;
}palTLS_t;


//! the full structures will be defined later in the implemetation.
typedef struct palTLSConf {
    platTlsConfigurationContext* confCtx;
    palTLSSocketHandle_t palIOCtx; // which will be used as bio context for mbedTLS
    palTLS_t* tlsContext; // to help us to get the index of the containing palTLS_t in the array. will be updated in the init
                          // maybe we need to make this an array, since index can be shared for more than one TLS context
    palTimingDelayContext_t timerCtx;
    // OpenSSL does not need explicit DRBG, X509, or PK context here
    bool hasKeys;
    bool hasChain;
    // Optionally, store the last cipher suite string set (for debugging)
    char lastCipherSuite[128];
} palTLSConf_t;

PAL_PRIVATE palStatus_t translateTLSHandShakeErrToPALError(palTLS_t* tlsCtx, int32_t ssl_ret)
{
    palStatus_t status;
    int err = SSL_get_error(tlsCtx->tlsCtx, ssl_ret);

    // Print detailed error information
    unsigned long ssl_err;
    while ((ssl_err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
        PAL_LOG_ERR("SSL error: %s", err_buf);
    }

    switch (err) {
        case SSL_ERROR_NONE:
            status = PAL_SUCCESS;
            tlsCtx->wantReadOrWrite = false;
            break;
        case SSL_ERROR_WANT_READ:
            status = PAL_ERR_TLS_WANT_READ;
            tlsCtx->wantReadOrWrite = true;
            break;
        case SSL_ERROR_WANT_WRITE:
            status = PAL_ERR_TLS_WANT_WRITE;
            tlsCtx->wantReadOrWrite = true;
            break;
        case SSL_ERROR_ZERO_RETURN:
            status = PAL_ERR_TLS_PEER_CLOSE_NOTIFY;
            break;
        case SSL_ERROR_SYSCALL:
            status = PAL_ERR_GENERIC_FAILURE;
            break;
        case SSL_ERROR_SSL:
            PAL_LOG_ERR("SSL_ERROR_SSL (protocol error)");
            status = PAL_ERR_GENERIC_FAILURE;
            break;
        default:
            PAL_LOG_ERR("Unknown SSL error: %d", err);
            status = PAL_ERR_GENERIC_FAILURE;
            break;
    }
    return status;
}

int pal_plat_entropySourceTLS( void *data, unsigned char *output, size_t len, size_t *olen );

palStatus_t pal_plat_initTLSLibrary(void)
{
    palStatus_t status = PAL_SUCCESS;

    // OpenSSL 1.1.0+ initializes itself automatically, but explicit init is safe and portable
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
    OPENSSL_init_crypto(0, NULL);
    // Error strings loaded by default, but can be loaded explicitly if needed
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
#endif
    return status;
}


palStatus_t pal_plat_cleanupTLS(void)
{
    // No explicit cleanup required for OpenSSL in most cases.
    // If you dynamically allocated any OpenSSL resources globally, free them here.
    // Otherwise, this is a no-op.
    return PAL_SUCCESS;
}


palStatus_t pal_plat_addEntropySource(palEntropySource_f entropyCallback)
{
    // OpenSSL manages entropy sources internally.
    // This function is a no-op for OpenSSL.
    (void)entropyCallback;
    return PAL_SUCCESS;
}

// Certificate verification callback
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    if (!preverify_ok) {
        int err = X509_STORE_CTX_get_error(ctx);
        PAL_LOG_ERR("Certificate verification failed: %s", 
               X509_verify_cert_error_string(err));
    }
    return preverify_ok;
}

palStatus_t pal_plat_initTLSConf(palTLSConfHandle_t* palConfCtx, palTLSTransportMode_t transportVersion, palDTLSSide_t methodType)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = NULL;

    if (NULLPTR == palConfCtx)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    localConfigCtx = (palTLSConf_t*)malloc(sizeof(palTLSConf_t));
    if (NULL == localConfigCtx)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }

    const SSL_METHOD* method = TLS_method();
    localConfigCtx->confCtx = SSL_CTX_new(method);
    if (NULL == localConfigCtx->confCtx)
    {
        free(localConfigCtx);
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }

    // Set security options to prevent protocol errors
    long ssl_options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    
    // Disable TLS 1.3 if not supported by the server
    #ifdef SSL_OP_NO_TLSv1_3
    ssl_options |= SSL_OP_NO_TLSv1_3;
    #endif
    
    SSL_CTX_set_options(localConfigCtx->confCtx, ssl_options);
    
    // Set security level to 1 (minimum required for most servers)
    SSL_CTX_set_security_level(localConfigCtx->confCtx, 1);
    
    // Enable automatic hostname verification
    SSL_CTX_set_verify_depth(localConfigCtx->confCtx, 4);
    
    // Set session cache mode
    SSL_CTX_set_session_cache_mode(localConfigCtx->confCtx, SSL_SESS_CACHE_CLIENT);
    
    // Set verification callback for better error reporting
    SSL_CTX_set_verify(localConfigCtx->confCtx, SSL_VERIFY_PEER, verify_callback);
    
    localConfigCtx->tlsContext = NULL;
    localConfigCtx->hasKeys = false;
    localConfigCtx->hasChain = false;
    memset(&(localConfigCtx->timerCtx), 0, sizeof(palTimingDelayContext_t));
    *palConfCtx = (uintptr_t)localConfigCtx;

finish:
    if (PAL_SUCCESS != status && NULL != localConfigCtx)
    {
        if (NULL != localConfigCtx->confCtx)
        {
            SSL_CTX_free(localConfigCtx->confCtx);
        }
        free(localConfigCtx);
        *palConfCtx = NULLPTR;
    }
    return status;
}


palStatus_t pal_plat_tlsConfigurationFree(palTLSConfHandle_t* palTLSConf)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = NULL;
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    psa_status_t psa_status = PSA_SUCCESS;
#endif

    if (NULLPTR == palTLSConf || NULLPTR == *palTLSConf)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    localConfigCtx = (palTLSConf_t*)*palTLSConf;

    // Only free OpenSSL resources
    if (localConfigCtx->confCtx) {
        SSL_CTX_free(localConfigCtx->confCtx);
    }

    // Cancel possible outstanding timer event
    eventOS_cancel(localConfigCtx->timerCtx.timer_event);

    memset(localConfigCtx, 0, sizeof(palTLSConf_t));
    free(localConfigCtx);
    *palTLSConf = NULLPTR;
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    if (psa_status != PSA_SUCCESS)
    {
        return PAL_ERR_TLS_ERROR_BASE;
    }
#endif
    return status;
}


palStatus_t pal_plat_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;

    palTLS_t* localTLSHandle = (palTLS_t*)malloc(sizeof(palTLS_t));
    if (NULL == localTLSHandle) {
        status = PAL_ERR_TLS_RESOURCE;
        goto finish;
    }
    memset(localTLSHandle, 0, sizeof(palTLS_t));
    localTLSHandle->tlsCtx = SSL_new(localConfigCtx->confCtx);
    if (NULL == localTLSHandle->tlsCtx) {
        free(localTLSHandle);
        status = PAL_ERR_TLS_RESOURCE;
        goto finish;
    }
    SSL_set_connect_state(localTLSHandle->tlsCtx);
    localConfigCtx->tlsContext = localTLSHandle;
    localTLSHandle->tlsInit = true;
    memset(&localConfigCtx->timerCtx, 0, sizeof(palTimingDelayContext_t));
    *palTLSHandle = (palTLSHandle_t)localTLSHandle;

finish:
    return status;
}

palStatus_t pal_plat_freeTLS(palTLSHandle_t* palTLSHandle)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = NULL;

    localTLSCtx = (palTLS_t*)*palTLSHandle;
    if (false == localTLSCtx->tlsInit) {
        status = PAL_ERR_TLS_CONTEXT_NOT_INITIALIZED;
        goto finish;
    }

    if (localTLSCtx->tlsCtx) {
        SSL_free(localTLSCtx->tlsCtx);
    }
    free(localTLSCtx);
    *palTLSHandle = NULLPTR;

finish:
    return status;
}


palStatus_t pal_plat_setAuthenticationMode(palTLSConfHandle_t sslConf, palTLSAuthMode_t authMode)
{
    palStatus_t status = PAL_SUCCESS;
    int openssl_mode = SSL_VERIFY_NONE;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)sslConf;

    switch(authMode)
    {
        case PAL_TLS_VERIFY_NONE:
            openssl_mode = SSL_VERIFY_NONE;
            break;
        case PAL_TLS_VERIFY_OPTIONAL:
            // OpenSSL does not have a direct equivalent for 'optional' on the client side.
            // On the server side, you can use SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
            // but for most cases, SSL_VERIFY_PEER is used.
            openssl_mode = SSL_VERIFY_PEER;
            break;
        case PAL_TLS_VERIFY_REQUIRED:
            openssl_mode = SSL_VERIFY_PEER;
            break;
        default:
            return PAL_ERR_INVALID_ARGUMENT;
    }
    SSL_CTX_set_verify(localConfigCtx->confCtx, openssl_mode, NULL);
    return status;
}

palStatus_t pal_plat_setCipherSuites(palTLSConfHandle_t sslConf, palTLSSuites_t palSuite)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)sslConf;
    const char* openssl_cipher = NULL;

    switch(palSuite)
    {
        case PAL_TLS_PSK_WITH_AES_128_CCM_8:
            openssl_cipher = "PSK-AES128-CCM8";
            break;
        case PAL_TLS_PSK_WITH_AES_256_CCM_8:
            openssl_cipher = "PSK-AES256-CCM8";
            break;
        case PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
            openssl_cipher = "ECDHE-ECDSA-AES128-CCM8";
            break;
        case PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            openssl_cipher = "ECDHE-ECDSA-AES128-GCM-SHA256";
            break;
        case PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            openssl_cipher = "ECDHE-ECDSA-AES256-GCM-SHA384";
            break;

        default:
            tr_error("ERROR - pal_plat_TLS.c, no cipher suite!");
            status = PAL_ERR_TLS_INVALID_CIPHER;
            goto finish;
    }

    // For TLS 1.2 and below
    if (!SSL_CTX_set_cipher_list(localConfigCtx->confCtx, openssl_cipher)) {
        tr_error("ERROR - pal_plat_TLS.c, SSL_CTX_set_cipher_list failed for %s", openssl_cipher);
        status = PAL_ERR_TLS_INVALID_CIPHER;
        goto finish;
    }

finish:
    return status;
}

palStatus_t pal_plat_sslGetVerifyResultExtended(palTLSHandle_t palTLSHandle, int32_t* verifyResult)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    *verifyResult = 0;

    // Use OpenSSL's SSL_get_verify_result if needed
    long openssl_verify = SSL_get_verify_result(localTLSCtx->tlsCtx);
    if (openssl_verify != X509_V_OK) {
        status = PAL_ERR_X509_CERT_VERIFY_FAILED;
        *verifyResult = (int32_t)openssl_verify;
    }
    return status;
}

palStatus_t pal_plat_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    
    // Clear any previous errors
    ERR_clear_error();
    
    int ret = SSL_read(localTLSCtx->tlsCtx, (unsigned char*)buffer, len);
    
    if (ret > 0)
    {
        *actualLen = ret;
    }
    else
    {
        status = translateTLSHandShakeErrToPALError(localTLSCtx, ret);
        if (status != PAL_ERR_TLS_WANT_READ && status != PAL_ERR_TLS_PEER_CLOSE_NOTIFY)
        {
            PAL_LOG_ERR("SSL Read return code -0x%" PRIx32 ".", -status);
        }
        else
        {
            PAL_LOG_DBG("SSL Read return code -0x%" PRIx32 ".", -status);
        }
    }
    return status;
}

palStatus_t pal_plat_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    
    // Clear any previous errors
    ERR_clear_error();
    
    int ret = SSL_write(localTLSCtx->tlsCtx, (const unsigned char*)buffer, len);
    
    if (ret > 0)
    {
        *bytesWritten = ret;
    }
    else
    {
        status = translateTLSHandShakeErrToPALError(localTLSCtx, ret);
        if (status != PAL_ERR_TLS_WANT_WRITE && status != PAL_ERR_TLS_PEER_CLOSE_NOTIFY)
        {
            PAL_LOG_ERR("SSL Write platform return code -0x%" PRIx32 ".", -status);
        }
        else
        {
            PAL_LOG_ERR("SSL Write platform return code -0x%" PRIx32 ".", -status);
        }
    }
    return status;
}


palStatus_t pal_plat_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t minTimeout, uint32_t maxTimeout)
{
    // OpenSSL does not provide a direct API to set handshake timeouts.
    // You must implement handshake timeouts at the application/socket level.
    (void)palTLSConf;
    (void)minTimeout;
    (void)maxTimeout;
    return PAL_SUCCESS;
}


palStatus_t pal_plat_sslSetup(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;

    // In OpenSSL, SSL_new() already binds the context to the config.
    // If you need to set max fragment length, do it here (optional):
    // SSL_set_max_send_fragment(localTLSCtx->tlsCtx, desired_length);

    // If you want to keep the pointer for bookkeeping:
    localConfigCtx->tlsContext = localTLSCtx;

    // No error expected here, so just return success.
    return status;
}

palStatus_t pal_plat_handShake(palTLSHandle_t palTLSHandle, uint64_t* serverTime)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    int ret = 0;

    // Clear any previous errors
    ERR_clear_error();
    
    ret = SSL_do_handshake(localTLSCtx->tlsCtx);
    
    if (ret == 1) {
        // Handshake successful
        if (serverTime) {
            // Extract the first 4 bytes of the server random (if needed)
            unsigned char server_random[SSL3_RANDOM_SIZE];
            if (SSL_get_server_random(localTLSCtx->tlsCtx, server_random, sizeof(server_random)) == SSL3_RANDOM_SIZE) {
                *serverTime = ((uint64_t)server_random[0] << 24) |
                              ((uint64_t)server_random[1] << 16) |
                              ((uint64_t)server_random[2] << 8)  |
                              ((uint64_t)server_random[3]);
            } else {
                *serverTime = 0;
            }
        }
        return PAL_SUCCESS;
    } else {
        status = translateTLSHandShakeErrToPALError(localTLSCtx, ret);
        
        // Print additional debugging information
        PAL_LOG_DBG("SSL state: %s", SSL_state_string_long(localTLSCtx->tlsCtx));
        PAL_LOG_DBG("SSL alert: %s", SSL_alert_desc_string_long(SSL_get_error(localTLSCtx->tlsCtx, ret)));
    }
    return status;
}


#if (PAL_ENABLE_X509 == 1)

palStatus_t pal_plat_setOwnPrivateKey(palTLSConfHandle_t palTLSConf, palPrivateKey_t* privateKey)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;

    bio = BIO_new_mem_buf(privateKey->buffer, privateKey->size);
    if (!bio) {
        status = PAL_ERR_TLS_FAILED_TO_PARSE_KEY;
        goto finish;
    }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    if (!pkey) {
        BIO_reset(bio);
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    BIO_free(bio);
    if (!pkey) {
        status = PAL_ERR_TLS_FAILED_TO_PARSE_KEY;
        goto finish;
    }
    if (SSL_CTX_use_PrivateKey(localConfigCtx->confCtx, pkey) != 1) {
        EVP_PKEY_free(pkey);
        status = PAL_ERR_TLS_FAILED_TO_SET_CERT;
        goto finish;
    }
    EVP_PKEY_free(pkey);
    localConfigCtx->hasKeys = true;
finish:
    return status;
}

palStatus_t pal_plat_setOwnCertChain(palTLSConfHandle_t palTLSConf, palX509_t* ownCert)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    X509* cert = NULL;
    BIO* bio = NULL;

    bio = BIO_new_mem_buf(ownCert->buffer, ownCert->size);
    if (!bio) {
        status = PAL_ERR_TLS_FAILED_TO_PARSE_CERT;
        goto finish;
    }
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!cert) {
        BIO_reset(bio);
        cert = d2i_X509_bio(bio, NULL);
    }
    BIO_free(bio);
    if (!cert) {
        status = PAL_ERR_TLS_FAILED_TO_PARSE_CERT;
        goto finish;
    }
    if (SSL_CTX_use_certificate(localConfigCtx->confCtx, cert) != 1) {
        X509_free(cert);
        status = PAL_ERR_TLS_FAILED_TO_SET_CERT;
        goto finish;
    }
    X509_free(cert);
    localConfigCtx->hasKeys = true;
finish:
    return status;
}

palStatus_t pal_plat_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    X509_STORE* store = NULL;
    X509* cacert = NULL;
    BIO* bio = NULL;

    bio = BIO_new_mem_buf(caChain->buffer, caChain->size);
    if (!bio) {
        status = PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }
    cacert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!cacert) {
        BIO_reset(bio);
        cacert = d2i_X509_bio(bio, NULL);
    }
    BIO_free(bio);
    if (!cacert) {
        status = PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }
    store = SSL_CTX_get_cert_store(localConfigCtx->confCtx);
    if (!store || X509_STORE_add_cert(store, cacert) != 1) {
        X509_free(cacert);
        status = PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }
    X509_free(cacert);
    localConfigCtx->hasChain = true;
finish:
    return status;
}
#endif // PAL_ENABLE_X509

palStatus_t pal_plat_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;

    // Store the socket context for bookkeeping if needed
    localConfigCtx->palIOCtx = socket;

    // Set the socket file descriptor on the SSL object
    if (localConfigCtx->tlsContext && localConfigCtx->tlsContext->tlsCtx) {
        int fd = (int)(intptr_t)socket->socket; // Fix: cast pointer to int
        if (SSL_set_fd(localConfigCtx->tlsContext->tlsCtx, fd) != 1) {
            status = PAL_ERR_GENERIC_FAILURE;
        }
    } else {
        status = PAL_ERR_INVALID_ARGUMENT;
    }

    return status;
}

// pal_plat_sslSetIOCallBacks is not needed for OpenSSL unless you want to use custom BIOs.
// If you do, you would create a BIO and use SSL_set_bio(). For most cases, you can remove this function.
palStatus_t pal_plat_sslSetIOCallBacks(palTLSConfHandle_t palTLSConf, palTLSSocket_t* palIOCtx, palBIOSend_f palBIOSend, palBIORecv_f palBIORecv)
{
    // Not needed for OpenSSL with standard sockets.
    (void)palTLSConf;
    (void)palIOCtx;
    (void)palBIOSend;
    (void)palBIORecv;
    return PAL_SUCCESS;
}

// Example info callback for OpenSSL
static void openssl_info_callback(const SSL *ssl, int where, int ret)
{
    if (where & SSL_CB_HANDSHAKE_START)
        PAL_LOG_DBG("Handshake started");
    if (where & SSL_CB_HANDSHAKE_DONE)
        PAL_LOG_DBG("Handshake done");
    if (where & SSL_CB_ALERT)
        PAL_LOG_DBG("Alert %s", (where & SSL_CB_READ) ? "read" : "write");
    // You can add more detailed logging here if needed
}

palStatus_t pal_plat_sslSetDebugging(palTLSConfHandle_t palTLSConf, uint8_t turnOn)
{
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    if (turnOn) {
        SSL_CTX_set_info_callback(localConfigCtx->confCtx, openssl_info_callback);
    } else {
        SSL_CTX_set_info_callback(localConfigCtx->confCtx, NULL);
    }
    return PAL_SUCCESS;
}

palStatus_t pal_plat_SetLoggingCb(palTLSConfHandle_t palTLSConf, palLogFunc_f palLogFunction, void *logContext)
{
    // OpenSSL does not support per-connection debug callbacks like mbedTLS.
    // You can use SSL_CTX_set_info_callback as above, or leave this as a no-op.
    (void)palTLSConf;
    (void)palLogFunction;
    (void)logContext;
    return PAL_SUCCESS;
}

void pal_plat_SetDTLSSocketCallback(palTLSConfHandle_t palTLSHandle, palSocketCallback_f cb, void *argument)
{
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSHandle;
    localConfigCtx->timerCtx.socket_cb = cb;
    localConfigCtx->timerCtx.callback_argument = argument;
}

int pal_plat_entropySourceTLS( void *data, unsigned char *output, size_t len, size_t *olen )
{
    palStatus_t status = PAL_SUCCESS;
    (void)data;

    status = pal_osRandomBuffer((uint8_t*) output, len);
    if (PAL_SUCCESS == status)
    {
        if (NULL != olen)
        {
            *olen = len;
        }
        return 0;
    }
    else
    {
        return -1;
    }
}