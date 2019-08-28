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
#include "pal.h"
#include "pal_plat_TLS.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl_internal.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "crypto.h"
#include "stdio.h"
#endif


#include <stdlib.h>
#include <string.h>

#define TRACE_GROUP "PAL"

#define SSL_LIB_SUCCESS 0

#if PAL_USE_SECURE_TIME
#include "platform_time.h"
PAL_PRIVATE mbedtls_time_t g_timeFromHS = 0;
PAL_PRIVATE palMutexID_t g_palTLSTimeMutex = NULLPTR;
#ifdef MBEDTLS_PLATFORM_TIME_ALT
PAL_PRIVATE mbedtls_time_t pal_mbedtlsTimeCB(mbedtls_time_t* timer);
#endif
#endif //PAL_USE_SECURE_TIME

#if defined(MBEDTLS_DEBUG_C)
//! Add forward declaration for the function from mbedTLS
void mbedtls_debug_set_threshold( int threshold );
#endif

typedef mbedtls_ssl_context platTlsContext;
typedef mbedtls_ssl_config platTlsConfigurationContext;

#if (PAL_USE_SSL_SESSION_RESUME == 1)
/** Following items need to be stored from mbedtls_ssl_session info structure
    to do the ssl session resumption.*/
//int ciphersuite;            /*!< chosen ciphersuite */
//size_t id_len;              /*!< session id length  */
//unsigned char id[32];       /*!< session identifier */
//unsigned char master[48];   /*!< the master secret  */

// Size of the session data
static const int ssl_session_size = 92;
#endif

PAL_PRIVATE mbedtls_entropy_context *g_entropy = NULL;
PAL_PRIVATE bool g_entropyInitiated = false;

typedef struct palTimingDelayContext
{
    uint64_t                              start_ticks;
    uint32_t                              int_ms;
    uint32_t                              fin_ms;
} palTimingDelayContext_t;


//! the full structures will be defined later in the implemetation.
typedef struct palTLS {
    platTlsContext tlsCtx;
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
    mbedtls_ctr_drbg_context ctrDrbg;
    palTimingDelayContext_t timerCtx;
#if (PAL_ENABLE_X509 == 1)
    mbedtls_x509_crt owncert;
    mbedtls_x509_crt cacert;
#endif
    mbedtls_pk_context pkey;
    bool hasKeys;
    bool hasChain;
    int cipherSuites[PAL_MAX_ALLOWED_CIPHER_SUITES + 1];  // The +1 is for the Zero Termination required by mbedTLS
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    bool hasKeyHandle;
    psa_key_handle_t key_handle;
#endif

}palTLSConf_t;

PAL_PRIVATE palStatus_t translateTLSErrToPALError(int32_t error)
{
    palStatus_t status;
    switch(error)
    {
        case SSL_LIB_SUCCESS:
            status = PAL_ERR_END_OF_FILE;
            break;
        case MBEDTLS_ERR_SSL_WANT_READ:
            status = PAL_ERR_TLS_WANT_READ;
            break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            status = PAL_ERR_TLS_WANT_WRITE;
            break;
        case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
            status = PAL_ERR_TLS_HELLO_VERIFY_REQUIRED;
            break;
        case MBEDTLS_ERR_SSL_TIMEOUT:
            status = PAL_ERR_TIMEOUT_EXPIRED;
            break;
        case MBEDTLS_ERR_SSL_BAD_INPUT_DATA:
            status = PAL_ERR_TLS_BAD_INPUT_DATA;
            break;
        case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            status = PAL_ERR_TLS_CLIENT_RECONNECT;
            break;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            status = PAL_ERR_TLS_PEER_CLOSE_NOTIFY;
            break;
#if (PAL_ENABLE_X509 == 1)
        case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
            status = PAL_ERR_X509_CERT_VERIFY_FAILED;
            break;
#endif
        case MBEDTLS_ERR_X509_ALLOC_FAILED:
        case MBEDTLS_ERR_SSL_ALLOC_FAILED:
        case MBEDTLS_ERR_PK_ALLOC_FAILED:
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:
            status = PAL_ERR_NO_MEMORY;
            break;

        default:
            // Caller prints out error
            status = PAL_ERR_GENERIC_FAILURE;
    }
    return status;

}


PAL_PRIVATE palStatus_t translateTLSHandShakeErrToPALError(palTLS_t* tlsCtx, int32_t error)
{
    palStatus_t status;
    switch(error)
    {
        case SSL_LIB_SUCCESS:
            status = PAL_SUCCESS;
            tlsCtx->wantReadOrWrite = false;
            break;
        case MBEDTLS_ERR_SSL_WANT_READ:
            status = PAL_ERR_TLS_WANT_READ;
            tlsCtx->wantReadOrWrite = true;
            break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            status = PAL_ERR_TLS_WANT_WRITE;
            tlsCtx->wantReadOrWrite = true;
            break;
        case MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED:
            status = PAL_ERR_TLS_HELLO_VERIFY_REQUIRED;
            break;
        case MBEDTLS_ERR_SSL_TIMEOUT:
            status = PAL_ERR_TIMEOUT_EXPIRED;
            break;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            status = PAL_ERR_TLS_PEER_CLOSE_NOTIFY;
            break;
        case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            status = PAL_ERR_TLS_CLIENT_RECONNECT;
            break;
#if (PAL_ENABLE_X509 == 1)
        case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
            status = PAL_ERR_X509_CERT_VERIFY_FAILED;
            break;
#endif
        case MBEDTLS_ERR_X509_ALLOC_FAILED:
        case MBEDTLS_ERR_SSL_ALLOC_FAILED:
        case MBEDTLS_ERR_PK_ALLOC_FAILED:
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:
            status = PAL_ERR_NO_MEMORY;
            break;

        default:
            PAL_LOG_ERR("SSL handshake return code 0x%" PRIx32 ".", error);
            status = PAL_ERR_GENERIC_FAILURE;

    }
    return status;
}

//! Forward declaration
PAL_PRIVATE int palBIORecv_timeout(palTLSSocketHandle_t socket, unsigned char *buf, size_t len, uint32_t timeout);
PAL_PRIVATE int palBIORecv(palTLSSocketHandle_t socket, unsigned char *buf, size_t len);
PAL_PRIVATE int palBIOSend(palTLSSocketHandle_t socket, const unsigned char *buf, size_t len);
PAL_PRIVATE void palDebug(void *ctx, int debugLevel, const char *fileName, int line, const char *message);
int pal_plat_entropySourceTLS( void *data, unsigned char *output, size_t len, size_t *olen );
PAL_PRIVATE int palTimingGetDelay( void *data );
PAL_PRIVATE void palTimingSetDelay( void *data, uint32_t intMs, uint32_t finMs );

palStatus_t pal_plat_initTLSLibrary(void)
{
    palStatus_t status = PAL_SUCCESS;

    g_entropy = (mbedtls_entropy_context*)malloc(sizeof(mbedtls_entropy_context));
    if (NULL == g_entropy)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }
    else
    {
        mbedtls_entropy_init(g_entropy);
        g_entropyInitiated = false;
    }

#if PAL_USE_SECURE_TIME
    #ifdef MBEDTLS_PLATFORM_TIME_ALT
        // this scope is here to keep warnings away from gotos which skip over variable initialization
        {
            int32_t platStatus = SSL_LIB_SUCCESS;
            platStatus = mbedtls_platform_set_time(pal_mbedtlsTimeCB);
            if (SSL_LIB_SUCCESS != platStatus)
            {
                status = PAL_ERR_FAILED_SET_TIME_CB;
                goto finish;
            }
        }
    #endif //MBEDTLS_PLATFORM_TIME_ALT
        status = pal_osMutexCreate(&g_palTLSTimeMutex);
        if(PAL_SUCCESS != status)
        {
            PAL_LOG_ERR("Failed to Create TLS time Mutex error: %" PRId32 ".", status);
        }
#endif //PAL_USE_SECURE_TIME
finish:
    return status;
}


palStatus_t pal_plat_cleanupTLS(void)
{
    palStatus_t status = PAL_SUCCESS;
    if(g_entropy != NULL)
    {
        mbedtls_entropy_free(g_entropy);
    }
    g_entropyInitiated = false;
    free(g_entropy);
    g_entropy = NULL;

#if PAL_USE_SECURE_TIME
    //! Try to catch the Mutex in order to prevent situation of deleteing under use mutex
    status = pal_osMutexWait(g_palTLSTimeMutex, PAL_RTOS_WAIT_FOREVER);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to get TLS time Mutex error: %" PRId32 ".", status);
    }

    status = pal_osMutexRelease(g_palTLSTimeMutex);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to release TLS time Mutex error: %" PRId32 ".", status);
    }

    status = pal_osMutexDelete(&g_palTLSTimeMutex);
    if(PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to Delete TLS time Mutex");
    }
#endif //PAL_USE_SECURE_TIME
    return status;
}


palStatus_t pal_plat_addEntropySource(palEntropySource_f entropyCallback)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = SSL_LIB_SUCCESS;

    if (NULL == entropyCallback)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    if (!g_entropyInitiated)
    {
        platStatus = mbedtls_entropy_add_source(g_entropy, entropyCallback, NULL, PAL_INITIAL_RANDOM_SIZE, MBEDTLS_ENTROPY_SOURCE_STRONG );
        if (SSL_LIB_SUCCESS != platStatus)
        {
            status = PAL_ERR_TLS_CONFIG_INIT;
        }
        else
        {
            g_entropyInitiated = true;
        }

    }

    return status;
}


palStatus_t pal_plat_initTLSConf(palTLSConfHandle_t* palConfCtx, palTLSTransportMode_t transportVersion, palDTLSSide_t methodType)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = NULL;
    int32_t platStatus = SSL_LIB_SUCCESS;
    int32_t endpoint = 0;
    int32_t transport = 0;

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

    localConfigCtx->confCtx = (platTlsConfigurationContext*)malloc(sizeof(platTlsConfigurationContext));
    if (NULL == localConfigCtx->confCtx)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }
    localConfigCtx->tlsContext = NULL;
    localConfigCtx->hasKeys = false;
    localConfigCtx->hasChain = false;

    memset(localConfigCtx->cipherSuites, 0,(sizeof(int)* (PAL_MAX_ALLOWED_CIPHER_SUITES+1)) );
    mbedtls_ssl_config_init(localConfigCtx->confCtx);

#if (PAL_ENABLE_X509 == 1)
    mbedtls_x509_crt_init(&localConfigCtx->owncert);
    mbedtls_x509_crt_init(&localConfigCtx->cacert);
#endif

    if (PAL_TLS_IS_CLIENT == methodType)
    {
        endpoint = MBEDTLS_SSL_IS_CLIENT;
    }
    else
    {
        endpoint = MBEDTLS_SSL_IS_SERVER;
    }

    if (PAL_TLS_MODE == transportVersion)
    {
        transport = MBEDTLS_SSL_TRANSPORT_STREAM;
    }
    else
    {
        transport = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
    }
    platStatus = mbedtls_ssl_config_defaults(localConfigCtx->confCtx, endpoint, transport, MBEDTLS_SSL_PRESET_DEFAULT);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        PAL_LOG_ERR("TLS Init conf status %" PRId32 ".", platStatus);
        status = PAL_ERR_TLS_CONFIG_INIT;
        goto finish;
    }

    mbedtls_ctr_drbg_init(&localConfigCtx->ctrDrbg);
    status = pal_plat_addEntropySource(pal_plat_entropySourceTLS);
    if (PAL_SUCCESS != status)
    {
        goto finish;
    }

    platStatus = mbedtls_ctr_drbg_seed(&localConfigCtx->ctrDrbg, mbedtls_entropy_func, g_entropy, NULL, 0); //Custom data can be defined in
                                                                                          //pal_TLS.h header and to be defined by
                                                                                          //Service code. But we need to check if other platform support this
                                                                                          //input!
    if (SSL_LIB_SUCCESS != platStatus)
    {
        status = PAL_ERR_TLS_CONFIG_INIT;
        goto finish;
    }

    mbedtls_ssl_conf_rng(localConfigCtx->confCtx, mbedtls_ctr_drbg_random, &localConfigCtx->ctrDrbg);
    *palConfCtx = (uintptr_t)localConfigCtx;

finish:
    if (PAL_SUCCESS != status && NULL != localConfigCtx)
    {
        if (NULL != localConfigCtx->confCtx)
        {
            free(localConfigCtx->confCtx);
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

    if (true == localConfigCtx->hasKeys)
    {
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

        if (true == localConfigCtx->hasKeyHandle && localConfigCtx->key_handle != 0)
        {
            psa_status = psa_close_key(localConfigCtx->key_handle);
        }
#endif
        mbedtls_pk_free(&localConfigCtx->pkey);
#if (PAL_ENABLE_X509 == 1)
        mbedtls_x509_crt_free(&localConfigCtx->owncert);
    }

    if (true == localConfigCtx->hasChain)
    {
        mbedtls_x509_crt_free(&localConfigCtx->cacert);
#endif
    }

    mbedtls_ssl_config_free(localConfigCtx->confCtx);
    mbedtls_ctr_drbg_free(&localConfigCtx->ctrDrbg);

    free(localConfigCtx->confCtx);

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

    palTLS_t* localTLSHandle = (palTLS_t*)malloc( sizeof(palTLS_t));
    if (NULL == localTLSHandle)
    {
        status = PAL_ERR_TLS_RESOURCE;
        goto finish;
    }

    memset(localTLSHandle, 0 , sizeof(palTLS_t));
    mbedtls_ssl_init(&localTLSHandle->tlsCtx);
    localConfigCtx->tlsContext = localTLSHandle;
    localTLSHandle->tlsInit = true;
    mbedtls_ssl_set_timer_cb(&localTLSHandle->tlsCtx, &localConfigCtx->timerCtx, palTimingSetDelay, palTimingGetDelay);
    *palTLSHandle = (palTLSHandle_t)localTLSHandle;

finish:
    return status;
}


palStatus_t pal_plat_freeTLS(palTLSHandle_t* palTLSHandle)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = NULL;

    localTLSCtx = (palTLS_t*)*palTLSHandle;
    if (false == localTLSCtx->tlsInit)
    {
        status = PAL_ERR_TLS_CONTEXT_NOT_INITIALIZED;
        goto finish;
    }


    mbedtls_ssl_free(&localTLSCtx->tlsCtx);
    free(localTLSCtx);
    *palTLSHandle = NULLPTR;

finish:
    return status;
}


palStatus_t pal_plat_setAuthenticationMode(palTLSConfHandle_t sslConf, palTLSAuthMode_t authMode)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platAuthMode;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)sslConf;

    switch(authMode)
    {
        case PAL_TLS_VERIFY_NONE:
            platAuthMode = MBEDTLS_SSL_VERIFY_NONE;
            break;
        case PAL_TLS_VERIFY_OPTIONAL:
            platAuthMode = MBEDTLS_SSL_VERIFY_OPTIONAL;
            break;
        case PAL_TLS_VERIFY_REQUIRED:
            platAuthMode = MBEDTLS_SSL_VERIFY_REQUIRED;
            break;
        default:
            status = PAL_ERR_INVALID_ARGUMENT;
            goto finish;
    };
    mbedtls_ssl_conf_authmode(localConfigCtx->confCtx, platAuthMode );

finish:
    return status;
}

palStatus_t pal_plat_setCipherSuites(palTLSConfHandle_t sslConf, palTLSSuites_t palSuite)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)sslConf;

    switch(palSuite)
    {
        case PAL_TLS_PSK_WITH_AES_128_CCM_8:
            localConfigCtx->cipherSuites[0] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8;
            break;
        case PAL_TLS_PSK_WITH_AES_256_CCM_8:
            localConfigCtx->cipherSuites[0] = MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8;
            break;
        case PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
            localConfigCtx->cipherSuites[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
            break;
        case PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            localConfigCtx->cipherSuites[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
            break;
        case PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            localConfigCtx->cipherSuites[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
            break;
#ifdef MBEDTLS_ARIA_C
        case PAL_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:
            localConfigCtx->cipherSuites[0] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256;
            break;
#endif
        default:
            localConfigCtx->cipherSuites[0] = 0;
            status = PAL_ERR_TLS_INVALID_CIPHER;
            goto finish;
    }

    mbedtls_ssl_conf_ciphersuites(localConfigCtx->confCtx, localConfigCtx->cipherSuites);
finish:
    return status;
}

palStatus_t pal_plat_sslGetVerifyResultExtended(palTLSHandle_t palTLSHandle, int32_t* verifyResult)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    int32_t platStatus = SSL_LIB_SUCCESS;
    *verifyResult = 0;

    platStatus = mbedtls_ssl_get_verify_result(&localTLSCtx->tlsCtx);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        status = PAL_ERR_X509_CERT_VERIFY_FAILED;
#if (PAL_ENABLE_X509 == 1)
        //! please DO NOT change errors order
        if (MBEDTLS_X509_BADCERT_NOT_TRUSTED & platStatus)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_NOT_TRUSTED;
            status = PAL_ERR_X509_BADCERT_NOT_TRUSTED;
        }
        if (MBEDTLS_X509_BADCERT_BAD_KEY & platStatus)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_BAD_KEY;
            status = PAL_ERR_X509_BADCERT_BAD_KEY;
        }
        if (MBEDTLS_X509_BADCERT_BAD_PK & platStatus)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_BAD_PK;
            status = PAL_ERR_X509_BADCERT_BAD_PK;
        }
        if (MBEDTLS_X509_BADCERT_BAD_MD & platStatus)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_BAD_MD;
            status = PAL_ERR_X509_BADCERT_BAD_MD;
        }
        if (MBEDTLS_X509_BADCERT_FUTURE & platStatus)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_FUTURE;
            status = PAL_ERR_X509_BADCERT_FUTURE;
        }
        if (MBEDTLS_X509_BADCERT_EXPIRED & platStatus)
        {
            *verifyResult |= PAL_ERR_X509_BADCERT_EXPIRED;
            status = PAL_ERR_X509_BADCERT_EXPIRED;
        }
#endif
    }
    return status;
}

palStatus_t pal_plat_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = SSL_LIB_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;

    platStatus = mbedtls_ssl_read(&localTLSCtx->tlsCtx, (unsigned char*)buffer, len);
    if (platStatus > SSL_LIB_SUCCESS)
    {
        *actualLen = platStatus;
    }
    else
    {
        status = translateTLSErrToPALError(platStatus);
        if (MBEDTLS_ERR_SSL_WANT_READ != platStatus)
        {
            PAL_LOG_ERR("SSL Read return code %" PRId32 ".", platStatus);
        }
        else
        {
            PAL_LOG_DBG("SSL Read return code %" PRId32 ".", platStatus);
        }
    }

    return status;
}


palStatus_t pal_plat_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = SSL_LIB_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;

    platStatus = mbedtls_ssl_write(&localTLSCtx->tlsCtx, (unsigned char*)buffer, len);
    if (platStatus > SSL_LIB_SUCCESS)
    {
        *bytesWritten = platStatus;
    }
    else
    {
        status = translateTLSErrToPALError(platStatus);
        if (MBEDTLS_ERR_SSL_WANT_WRITE != platStatus)
        {
            PAL_LOG_ERR("SSL Write platform return code %" PRId32 ".", platStatus);
        }
        else
        {
            PAL_LOG_DBG("SSL Write platform return code %" PRId32 ".", platStatus);
        }
    }

    return status;
}


palStatus_t pal_plat_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t timeoutInMilliSec)
{
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    uint32_t minTimeout = PAL_DTLS_PEER_MIN_TIMEOUT;
    uint32_t maxTimeout = timeoutInMilliSec >> 1; //! faster dividing by 2
    //! Since mbedTLS algorithm for UDP handshake algorithm is as follow:
    //! wait 'minTimeout' ..=> 'minTimeout = 2*minTimeout' while 'minTimeout < maxTimeout'
    //! if 'minTimeout >= maxTimeout' them wait 'maxTimeout'.
    //! The whole waiting time is the sum of the different intervals waited.
    //! Therefore we need divide the 'timeoutInMilliSec' by 2 to give a close approximation of the desired 'timeoutInMilliSec'
    //! 1 + 2 + ... + 'timeoutInMilliSec/2' ~= 'timeoutInMilliSec'

    if (maxTimeout < PAL_DTLS_PEER_MIN_TIMEOUT)
    {
        minTimeout = (timeoutInMilliSec+1) >> 1; //to prevent 'minTimeout == 0'
        maxTimeout = timeoutInMilliSec;
    }

    mbedtls_ssl_conf_handshake_timeout(localConfigCtx->confCtx, minTimeout, maxTimeout);

    return PAL_SUCCESS;
}


palStatus_t pal_plat_sslSetup(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    int32_t platStatus = SSL_LIB_SUCCESS;

    if (!localTLSCtx->wantReadOrWrite)
    {
        platStatus = mbedtls_ssl_setup(&localTLSCtx->tlsCtx, localConfigCtx->confCtx);
        if (SSL_LIB_SUCCESS != platStatus)
        {
            PAL_LOG_ERR("SSL setup return code %" PRId32 ".", platStatus);
            if (MBEDTLS_ERR_SSL_ALLOC_FAILED == platStatus)
            {
                status = PAL_ERR_NO_MEMORY;
                goto finish;
            }
            status = PAL_ERR_GENERIC_FAILURE;
            goto finish;
        }

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && (PAL_MAX_FRAG_LEN > 0)
        platStatus = mbedtls_ssl_conf_max_frag_len(localConfigCtx->confCtx, PAL_MAX_FRAG_LEN);
        if (SSL_LIB_SUCCESS != platStatus)
        {
            PAL_LOG_ERR("SSL fragment setup error code %" PRId32 ".", platStatus);
            if (MBEDTLS_ERR_SSL_BAD_INPUT_DATA == platStatus)
            {
                status = PAL_ERR_TLS_BAD_INPUT_DATA;
                goto finish;
            }
            status = PAL_ERR_TLS_INIT;
            goto finish;
        }
#endif // #if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
        localConfigCtx->tlsContext = localTLSCtx;
    }
finish:
    return status;
}

palStatus_t pal_plat_handShake(palTLSHandle_t palTLSHandle, uint64_t* serverTime)
{
    palStatus_t status = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    int32_t platStatus = SSL_LIB_SUCCESS;

    while( (MBEDTLS_SSL_HANDSHAKE_OVER != localTLSCtx->tlsCtx.state) && (PAL_SUCCESS == status) )
    {
        platStatus = mbedtls_ssl_handshake_step( &localTLSCtx->tlsCtx );

        /* Extract the first 4 bytes of the ServerHello random */
        if( MBEDTLS_SSL_SERVER_HELLO_DONE == localTLSCtx->tlsCtx.state )
        {
            *serverTime = (uint64_t)
                ( (uint32_t)localTLSCtx->tlsCtx.handshake->randbytes[32 + 0] << 24 ) |
                ( (uint32_t)localTLSCtx->tlsCtx.handshake->randbytes[32 + 1] << 16 ) |
                ( (uint32_t)localTLSCtx->tlsCtx.handshake->randbytes[32 + 2] << 8  ) |
                ( (uint32_t)localTLSCtx->tlsCtx.handshake->randbytes[32 + 3] << 0  );
        }

        if (SSL_LIB_SUCCESS != platStatus)
        {
            status = translateTLSHandShakeErrToPALError(localTLSCtx, platStatus);
        }
    }

    return status;
}

#if PAL_USE_SECURE_TIME
palStatus_t pal_plat_renegotiate(palTLSHandle_t palTLSHandle, uint64_t serverTime)
{
    palStatus_t status = PAL_SUCCESS;
    palStatus_t mutexStatus = PAL_SUCCESS;
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    int32_t platStatus = SSL_LIB_SUCCESS;

    status = pal_osMutexWait(g_palTLSTimeMutex, PAL_RTOS_WAIT_FOREVER);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to get TLS time Mutex error: %" PRId32 ".", status);
        goto finish;
    }


    if (0 == g_timeFromHS)
    {
        g_timeFromHS = (mbedtls_time_t)serverTime;
    }
    else
    { //! need to change the code for multi-threading mode (Erez)
        status = PAL_ERR_TLS_MULTIPLE_HANDSHAKE;
        goto finish;
    }

    platStatus = mbedtls_ssl_renegotiate(&localTLSCtx->tlsCtx);
    status = translateTLSHandShakeErrToPALError(localTLSCtx, platStatus);

finish:
    g_timeFromHS = 0;

    mutexStatus = pal_osMutexRelease(g_palTLSTimeMutex);
    if (PAL_SUCCESS != mutexStatus)
    {
        PAL_LOG_ERR("Failed to get TLS time Mutex error: %" PRId32 ".", mutexStatus);
    }
    if (PAL_SUCCESS == status)
    {
        status = mutexStatus;
    }

    return status;
}
#endif //PAL_USE_SECURE_TIME


#if (PAL_ENABLE_X509 == 1)

palStatus_t pal_plat_setOwnPrivateKey(palTLSConfHandle_t palTLSConf, palPrivateKey_t* privateKey)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    int32_t platStatus = SSL_LIB_SUCCESS;

    mbedtls_pk_init(&localConfigCtx->pkey);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    platStatus = mbedtls_pk_setup_opaque(&localConfigCtx->pkey, *privateKey);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        status = PAL_ERR_TLS_FAILED_TO_PARSE_KEY;
        goto finish;
    }
    localConfigCtx->key_handle = *privateKey;
    localConfigCtx->hasKeyHandle = true;

#else //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
     platStatus = mbedtls_pk_parse_key(&localConfigCtx->pkey, (const unsigned char *)privateKey->buffer, privateKey->size, NULL, 0);
     if (SSL_LIB_SUCCESS != platStatus)
     {
         status = PAL_ERR_TLS_FAILED_TO_PARSE_KEY;
         goto finish;
     }
#endif

    localConfigCtx->hasKeys = true;

finish:
    PAL_LOG_DBG("Privatekey set and parse status %" PRIu32 ".", platStatus);
    return status;
}

palStatus_t pal_plat_setOwnCertChain(palTLSConfHandle_t palTLSConf, palX509_t* ownCert)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    int32_t platStatus = SSL_LIB_SUCCESS;

    platStatus = mbedtls_x509_crt_parse_der(&localConfigCtx->owncert, (const unsigned char *)ownCert->buffer, ownCert->size);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        status = PAL_ERR_TLS_FAILED_TO_PARSE_CERT;
        goto finish;
    }

    platStatus = mbedtls_ssl_conf_own_cert(localConfigCtx->confCtx, &localConfigCtx->owncert, &localConfigCtx->pkey);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        status = PAL_ERR_TLS_FAILED_TO_SET_CERT;
    }

    localConfigCtx->hasKeys = true;

finish:
    PAL_LOG_DBG("Own cert chain set and parse status %" PRIu32 ".", platStatus);
    return status;
}


palStatus_t pal_plat_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    int32_t platStatus = SSL_LIB_SUCCESS;

    platStatus = mbedtls_x509_crt_parse_der(&localConfigCtx->cacert, (const unsigned char *)caChain->buffer, caChain->size);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        PAL_LOG_ERR("TLS CA chain status %" PRId32 ".", platStatus);
        status = PAL_ERR_GENERIC_FAILURE;
        goto finish;
    }
    mbedtls_ssl_conf_ca_chain(localConfigCtx->confCtx, &localConfigCtx->cacert, NULL );

    localConfigCtx->hasChain = true;
finish:
    return status;
}
#endif

#if (PAL_ENABLE_PSK == 1)
palStatus_t pal_plat_setPSK(palTLSConfHandle_t palTLSConf, const unsigned char *identity, uint32_t maxIdentityLenInBytes, const unsigned char *psk, uint32_t maxPskLenInBytes)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    int32_t platStatus = SSL_LIB_SUCCESS;

    platStatus = mbedtls_ssl_conf_psk(localConfigCtx->confCtx, psk, maxPskLenInBytes, identity, maxIdentityLenInBytes);
    if (SSL_LIB_SUCCESS != platStatus)
    {
        if (MBEDTLS_ERR_SSL_ALLOC_FAILED == platStatus)
        {
            status = PAL_ERR_TLS_INIT;
            goto finish;
        }
        PAL_LOG_ERR("TLS set psk status %" PRId32 ".", platStatus);
        status = PAL_ERR_GENERIC_FAILURE;
    }
finish:
    return status;
}

#endif
palStatus_t pal_plat_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket)
{
    palStatus_t status = PAL_SUCCESS;

    status = pal_plat_sslSetIOCallBacks(palTLSConf, socket, palBIOSend, palBIORecv);
    return status;
}

palStatus_t pal_plat_sslSetIOCallBacks(palTLSConfHandle_t palTLSConf, palTLSSocket_t* palIOCtx, palBIOSend_f palBIOSend, palBIORecv_f palBIORecv)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;
    bool isNonBlocking = false;

    localConfigCtx->palIOCtx = palIOCtx;

    status = pal_isNonBlocking(palIOCtx->socket, &isNonBlocking);
    if (PAL_SUCCESS != status)
    {
        return status;
    }

    if (isNonBlocking)
    {
        mbedtls_ssl_set_bio(&localConfigCtx->tlsContext->tlsCtx, palIOCtx, palBIOSend, palBIORecv, NULL);
    }
    else
    {
        mbedtls_ssl_set_bio(&localConfigCtx->tlsContext->tlsCtx, palIOCtx, palBIOSend, NULL, palBIORecv_timeout);
    }

    return PAL_SUCCESS;
}



palStatus_t pal_plat_sslSetDebugging(palTLSConfHandle_t palTLSConf, uint8_t turnOn)
{
    palStatus_t status = PAL_SUCCESS;
    palLogFunc_f func = NULL;
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(PAL_TLS_DEBUG_THRESHOLD);
#endif

    if (turnOn)
    {
        func = palDebug;
    }
    status = pal_plat_SetLoggingCb(palTLSConf, func, NULL);
    return  status;
}

palStatus_t pal_plat_SetLoggingCb(palTLSConfHandle_t palTLSConf, palLogFunc_f palLogFunction, void *logContext)
{
    palTLSConf_t* localConfigCtx = (palTLSConf_t*)palTLSConf;

    mbedtls_ssl_conf_dbg(localConfigCtx->confCtx, palLogFunction, logContext);
    return PAL_SUCCESS;
}

PAL_PRIVATE uint64_t palTimingGetTimer(uint64_t *start_ticks, int reset)
{
    uint64_t delta_ms;
    uint64_t ticks = pal_osKernelSysTick();

    if (reset)
    {
        *start_ticks = ticks;
        delta_ms = 0;
    }
    else
    {
        delta_ms = pal_osKernelSysMilliSecTick(ticks - *start_ticks);
    }

    return delta_ms;
}


/*
 * Set delays to watch
 */
PAL_PRIVATE void palTimingSetDelay( void *data, uint32_t intMs, uint32_t finMs )
{

    palTimingDelayContext_t *ctx = data;

    ctx->int_ms = intMs;
    ctx->fin_ms = finMs;

    if( finMs != 0 )
    {
        (void) palTimingGetTimer( &ctx->start_ticks, 1 );
    }
}

/*
 * Get number of delays expired
 */
PAL_PRIVATE int palTimingGetDelay( void *data )
{
    int result = 0;
    palTimingDelayContext_t *ctx = data;
    uint64_t elapsed_ms;

    if( ctx->fin_ms == 0 )
    {
        result = -1;
        goto finish;
    }

    elapsed_ms = palTimingGetTimer( &ctx->start_ticks, 0 );

    if( elapsed_ms >= ctx->fin_ms )
    {
        result = 2;
        goto finish;
    }

    if( elapsed_ms >= ctx->int_ms )
    {
        result = 1;
        goto finish;
    }

finish:
    return result;
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

PAL_PRIVATE int palBIOSend(palTLSSocketHandle_t socket, const unsigned char *buf, size_t len)
{
    palStatus_t status = PAL_SUCCESS;
    size_t sentDataSize = 0;
    palTLSSocket_t* localSocket = (palTLSSocket_t*)socket;

    if (NULLPTR == socket)
    {
        status = -1;
        goto finish;
    }

    if (PAL_TLS_MODE == localSocket->transportationMode)
    {
        status = pal_send(localSocket->socket, buf, len, &sentDataSize);
    }
    else if (PAL_DTLS_MODE == localSocket->transportationMode)
    {
        #if defined(PAL_UDP_MTU_SIZE)
        if(len > PAL_UDP_MTU_SIZE) {
            len = PAL_UDP_MTU_SIZE;
        }
        #endif
        status = pal_sendTo(localSocket->socket, buf, len, localSocket->socketAddress, localSocket->addressLength, &sentDataSize);
    }
    else
    {
        PAL_LOG_ERR("TLS BIO send error");
        status = PAL_ERR_GENERIC_FAILURE;
    }
    if (PAL_SUCCESS == status || PAL_ERR_NO_MEMORY == status || PAL_ERR_SOCKET_WOULD_BLOCK == status)
    {
        if (PAL_ERR_NO_MEMORY == status)
        {
            PAL_LOG_DBG("Network module returned out of memory error, retrying..."); //Network module can return NO_MEMORY error since it was not able to allocate
                                                                                      //memory at this point of time. In this case we translate the error to WANT_WRITE
                                                                                      //in order to let the Network module retry to allocate the memory.
                                                                                      //In case of real out of memory the handshake timeout will break the handshake process.
        }

        if (0 != sentDataSize)
        {
            status = sentDataSize;
        }
        else
        {
            status = MBEDTLS_ERR_SSL_WANT_WRITE;
        }
    }
finish:
    return status;
}

PAL_PRIVATE int palBIORecv(palTLSSocketHandle_t socket, unsigned char *buf, size_t len)
{
    palStatus_t status = PAL_SUCCESS;
    size_t recievedDataSize = 0;
    palTLSSocket_t* localSocket = (palTLSSocket_t*)socket;

    if (NULLPTR == socket)
    {
        status = -1;
        goto finish;
    }

    if (PAL_TLS_MODE == localSocket->transportationMode)
    {
        status = pal_recv(localSocket->socket, buf, len, &recievedDataSize);
        if (PAL_SUCCESS == status)
        {
            status = recievedDataSize;
        }
        else if (PAL_ERR_SOCKET_WOULD_BLOCK == status)
        {
            status = MBEDTLS_ERR_SSL_WANT_READ;
        }
    }
    else if (PAL_DTLS_MODE == localSocket->transportationMode)
    {
        #if defined(PAL_UDP_MTU_SIZE)
        if(len > PAL_UDP_MTU_SIZE) {
            len = PAL_UDP_MTU_SIZE;
        }
        #endif
        status = pal_receiveFrom(localSocket->socket, buf, len, localSocket->socketAddress, &localSocket->addressLength, &recievedDataSize);
        if (PAL_SUCCESS == status)
        {
            if (0 != recievedDataSize)
            {
                status = recievedDataSize;
            }
            else
            {
                status = MBEDTLS_ERR_SSL_WANT_READ;
            }
        }
        else if (PAL_ERR_SOCKET_WOULD_BLOCK == status)
        {
            status = MBEDTLS_ERR_SSL_WANT_READ;
        }
    }
    else
    {
        PAL_LOG_ERR("TLS BIO recv error");
        status = PAL_ERR_GENERIC_FAILURE;
    }

finish:
    return status;
}

PAL_PRIVATE int palBIORecv_timeout(palTLSSocketHandle_t socket, unsigned char *buf, size_t len, uint32_t timeout)
{
    palStatus_t status = PAL_SUCCESS;
    size_t recievedDataSize = 0;
    uint32_t localTimeOut = timeout;
    palTLSSocket_t* localSocket = (palTLSSocket_t*)socket;
    bool isNonBlocking = false;

    if (NULLPTR == socket)
    {
        status = -1;
        goto finish;
    }

    status = pal_isNonBlocking(localSocket->socket, &isNonBlocking);
    if (PAL_SUCCESS != status)
    {
        goto finish;
    }

    if (PAL_TLS_MODE == localSocket->transportationMode)
    {
        status = pal_recv(localSocket->socket, buf, len, &recievedDataSize);
        if (PAL_SUCCESS == status)
        {
            status = recievedDataSize;
        }
        else if (PAL_ERR_SOCKET_WOULD_BLOCK == status)
        {
            status = MBEDTLS_ERR_SSL_WANT_READ;
        }
    }
    else if (PAL_DTLS_MODE == localSocket->transportationMode)
    {
        if (false == isNonBlocking) // timeout is relevant only if socket is blocking
        {
            status = pal_setSocketOptions(localSocket->socket, PAL_SO_RCVTIMEO, &localTimeOut, sizeof(localTimeOut));
            if (PAL_SUCCESS != status)
            {
                goto finish;
            }
        }

        status = pal_receiveFrom(localSocket->socket, buf, len, localSocket->socketAddress, &localSocket->addressLength, &recievedDataSize);

        if (PAL_SUCCESS == status)
        {
            if (0 != recievedDataSize)
            {
                status = recievedDataSize;
            }
            else
            {
                status = MBEDTLS_ERR_SSL_WANT_READ;
            }
        }
        else if (PAL_ERR_SOCKET_WOULD_BLOCK == status)
        {
            status = MBEDTLS_ERR_SSL_TIMEOUT;
        }
    }
    else
    {
        PAL_LOG_ERR("TLS BIO recv timeout error");
        status = PAL_ERR_GENERIC_FAILURE;
    }

finish:
    return status;
}

#if PAL_USE_SECURE_TIME
#ifdef MBEDTLS_PLATFORM_TIME_ALT
PAL_PRIVATE mbedtls_time_t pal_mbedtlsTimeCB(mbedtls_time_t* timer)
{
    palStatus_t status = PAL_SUCCESS;
    mbedtls_time_t mbedtlsTime = 0;

    status = pal_osMutexWait(g_palTLSTimeMutex, PAL_RTOS_WAIT_FOREVER);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to get TLS time Mutex error: %" PRId32 ".", status);
        goto finish;
    }

    if (0 != g_timeFromHS)
    {
        mbedtlsTime = g_timeFromHS;
    }
    else
    {
        uint64_t currentTime = pal_osGetTime();
        //mbedtls_time_t is defined to time_t, so we can do a safe copy since till 2038 the value in currentTime is less than MAX_TIME_T_VALUE
        mbedtlsTime = (mbedtls_time_t)currentTime;
    }
    status = pal_osMutexRelease(g_palTLSTimeMutex);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to release TLS time Mutex error: %" PRId32 ".", status);
    }
finish:
    if (PAL_SUCCESS != status)
    {
        mbedtlsTime = 0;
    }
    return mbedtlsTime;
}
#endif
#endif //PAL_USE_SECURE_TIME

PAL_PRIVATE void palDebug(void *ctx, int debugLevel, const char *fileName, int line, const char *message)
{
    (void)ctx;
    PAL_LOG_DBG("%s: %d: %s", fileName, line, message);
}

#ifdef MBEDTLS_ENTROPY_NV_SEED
int mbedtls_platform_std_nv_seed_read( unsigned char *buf, size_t buf_len )
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_osRandomBuffer(buf, buf_len);
    if (PAL_SUCCESS != status)
    {
        return -1;
    }
    return 0;
}

int mbedtls_platform_std_nv_seed_write( unsigned char *buf, size_t buf_len )
{
    return 0;
}
#endif //MBEDTLS_ENTROPY_NV_SEED

#if (PAL_USE_SSL_SESSION_RESUME == 1)
uint8_t* pal_plat_GetSslSessionBuffer(palTLSHandle_t palTLSHandle, size_t *buffer_size)
{
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;
    uint8_t* session_buffer = (uint8_t*)malloc(ssl_session_size);
    if (session_buffer == NULL)
    {
        PAL_LOG_ERR("pal_plat_GetSslSessionBuffer - failed to allocate buffer");
        return NULL;
    }

    mbedtls_ssl_session saved_ssl_session = {0};
    int32_t platStatus = mbedtls_ssl_get_session(&localTLSCtx->tlsCtx, &saved_ssl_session);
    if (platStatus == SSL_LIB_SUCCESS)
    {
        memcpy(session_buffer, (uint8_t*)&saved_ssl_session.id_len, sizeof(saved_ssl_session.id_len));
        memcpy(session_buffer + sizeof(saved_ssl_session.id_len),
               (uint8_t*)&saved_ssl_session.id, sizeof(saved_ssl_session.id));
        memcpy(session_buffer + sizeof(saved_ssl_session.id_len) + sizeof(saved_ssl_session.id),
               (uint8_t*)&saved_ssl_session.master, sizeof(saved_ssl_session.master));
        memcpy(session_buffer + sizeof(saved_ssl_session.id_len) + sizeof(saved_ssl_session.id) + sizeof(saved_ssl_session.master),
               (uint8_t*)&saved_ssl_session.ciphersuite, sizeof(saved_ssl_session.ciphersuite));

        mbedtls_ssl_session_free(&saved_ssl_session);
    }
    else
    {
        PAL_LOG_ERR("pal_plat_GetSslSessionBuffer - failed to get ssl session %" PRId32, platStatus);
        free(session_buffer);
        return NULL;
    }

    *buffer_size = ssl_session_size;
    return session_buffer;
}

void pal_plat_SetSslSession(palTLSHandle_t palTLSHandle, const uint8_t *session_buffer)
{
    palTLS_t* localTLSCtx = (palTLS_t*)palTLSHandle;

    mbedtls_ssl_session saved_ssl_session = {0};
    memcpy(&saved_ssl_session.id_len, session_buffer, sizeof(saved_ssl_session.id_len));
    memcpy(&saved_ssl_session.id, session_buffer + sizeof(saved_ssl_session.id_len), sizeof(saved_ssl_session.id));
    memcpy(&saved_ssl_session.master, session_buffer + sizeof(saved_ssl_session.id_len) + sizeof(saved_ssl_session.id), sizeof(saved_ssl_session.master));
    memcpy(&saved_ssl_session.ciphersuite, session_buffer + sizeof(saved_ssl_session.id_len) + sizeof(saved_ssl_session.id) + sizeof(saved_ssl_session.master), sizeof(saved_ssl_session.ciphersuite));

    int32_t platStatus = mbedtls_ssl_set_session(&localTLSCtx->tlsCtx, &saved_ssl_session);
    if (platStatus != SSL_LIB_SUCCESS) {
        PAL_LOG_ERR("pal_plat_SetSslSession - session set failed %" PRId32, platStatus);
    }
}
#endif // PAL_USE_SSL_SESSION_RESUME
