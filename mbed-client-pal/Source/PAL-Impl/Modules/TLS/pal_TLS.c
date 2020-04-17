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

// do not require storage unless this modules is configured to use it
#if PAL_USE_SECURE_TIME
#include "storage_kcm.h"
#endif

#if (PAL_USE_SSL_SESSION_RESUME == 1)
#include "key_config_manager.h"
static const char* kcm_session_item_name = "sslsession";
static void pal_loadSslSessionFromStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);
static void pal_saveSslSessionToStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);
static void pal_removeSslSessionFromStorage(palTLSConfHandle_t palTLSConf);
#endif

#define TRACE_GROUP "PAL"

PAL_PRIVATE bool g_trustedServerValid = false;
PAL_PRIVATE palMutexID_t g_palTLSHandshakeMutex = NULLPTR;

typedef struct palTLSService
{
    bool retryHandShake;
    uint64_t serverTime;
    palTLSHandle_t platTlsHandle;
}palTLSService_t;

typedef struct palTLSConfService
{
    bool trustedTimeServer;
    palTLSConfHandle_t platTlsConfHandle;
    bool useSslSessionResume;
}palTLSConfService_t;

palStatus_t pal_initTLSLibrary(void)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_osMutexCreate(&g_palTLSHandshakeMutex);
    if(PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to Create TLS handshake Mutex error: %" PRId32 ".", status);
    }
    else
    {
        status = pal_plat_initTLSLibrary();
    }
    return status;
}

palStatus_t pal_cleanupTLS(void)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_osMutexDelete(&g_palTLSHandshakeMutex);
    if(PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to Delete TLS handshake Mutex error: %" PRId32 ".", status);
    }
    status = pal_plat_cleanupTLS();
    return status;
}


palStatus_t pal_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle)
{
    palStatus_t status = PAL_SUCCESS;
    palStatus_t mutexStatus = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palTLSService_t* palTLSCtx = NULL;

    PAL_VALIDATE_ARGUMENTS ((NULLPTR == palTLSConf || NULLPTR == palTLSHandle));

    mutexStatus = pal_osMutexWait(g_palTLSHandshakeMutex, PAL_RTOS_WAIT_FOREVER);
    if (PAL_SUCCESS != mutexStatus)
    {
        PAL_LOG_ERR("Failed to get TLS context init Mutex error: %" PRId32 ".", mutexStatus);
        goto finish;
    }

    palTLSCtx = (palTLSService_t*)malloc(sizeof(palTLSService_t));
    if (NULL == palTLSCtx)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }
    status = pal_plat_initTLS(palTLSConfCtx->platTlsConfHandle, &palTLSCtx->platTlsHandle);
    if (PAL_SUCCESS == status)
    {
        *palTLSHandle = (palTLSHandle_t)palTLSCtx;
    }

    g_trustedServerValid = false;
    palTLSCtx->retryHandShake = false;
    palTLSCtx->serverTime = 0;

    status = pal_plat_sslSetup(palTLSCtx->platTlsHandle, palTLSConfCtx->platTlsConfHandle);
    if (PAL_SUCCESS == status)
    {
#if (PAL_USE_SSL_SESSION_RESUME == 1)
        pal_loadSslSessionFromStorage(*palTLSHandle, palTLSConf);
#endif //PAL_USE_SSL_SESSION_RESUME
    }

finish:
    if (PAL_SUCCESS == mutexStatus)
    {
        mutexStatus = pal_osMutexRelease(g_palTLSHandshakeMutex);
        if (PAL_SUCCESS != mutexStatus)
        {
            PAL_LOG_ERR("Failed to release TLS context init Mutex error: %" PRId32 ".", mutexStatus);
        }
    }

    if (PAL_SUCCESS == status)
    {
        status = mutexStatus;
    }

    if (PAL_SUCCESS != status)
    {
        free(palTLSCtx);
        *palTLSHandle = NULLPTR;
    }
    return status;
}


palStatus_t pal_freeTLS(palTLSHandle_t* palTLSHandle)
{
    palStatus_t status = PAL_SUCCESS;
    palStatus_t mutexStatus = PAL_SUCCESS;

    palTLSService_t* palTLSCtx = NULL;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSHandle || NULLPTR == *palTLSHandle);

    mutexStatus = pal_osMutexWait(g_palTLSHandshakeMutex, PAL_RTOS_WAIT_FOREVER);
    if (PAL_SUCCESS != mutexStatus)
    {
        PAL_LOG_ERR("Failed to get TLS context init Mutex error: %" PRId32 ".", mutexStatus);
        goto finish;
    }

    palTLSCtx = (palTLSService_t*)*palTLSHandle;
    status = pal_plat_freeTLS(&palTLSCtx->platTlsHandle);
    if (PAL_SUCCESS == status)
    {
        free(palTLSCtx);
        *palTLSHandle = NULLPTR;
    }

    mutexStatus = pal_osMutexRelease(g_palTLSHandshakeMutex);
    if (PAL_SUCCESS != mutexStatus)
    {
        PAL_LOG_ERR("Failed to release TLS context init Mutex error: %" PRId32 ".", mutexStatus);
    }
finish:
    if (PAL_SUCCESS == status)
    {
        status = mutexStatus;
    }
    return status;
}


palStatus_t pal_initTLSConfiguration(palTLSConfHandle_t* palTLSConf, palTLSTransportMode_t transportationMode)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = NULL;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConf);


    palTLSConfCtx = (palTLSConfService_t*)malloc(sizeof(palTLSConfService_t));
    if (NULL == palTLSConfCtx)
    {
        status = PAL_ERR_NO_MEMORY;
        goto finish;
    }

    status = pal_plat_initTLSConf(&palTLSConfCtx->platTlsConfHandle, transportationMode, PAL_TLS_IS_CLIENT);
    if (PAL_SUCCESS != status)
    {
        goto finish;
    }

    status = pal_plat_setAuthenticationMode(palTLSConfCtx->platTlsConfHandle, PAL_TLS_VERIFY_OPTIONAL);
    if (PAL_SUCCESS != status)
    {
        goto finish;
    }
#if (PAL_TLS_CIPHER_SUITE & PAL_TLS_PSK_WITH_AES_128_CCM_8_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_PSK_WITH_AES_128_CCM_8);
#elif (PAL_TLS_CIPHER_SUITE & PAL_TLS_PSK_WITH_AES_256_CCM_8_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_PSK_WITH_AES_256_CCM_8);
#elif (PAL_TLS_CIPHER_SUITE & PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
#elif (PAL_TLS_CIPHER_SUITE & PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
#elif (PAL_TLS_CIPHER_SUITE & PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
#elif (PAL_TLS_CIPHER_SUITE & PAL_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256);
#else
    #error : No CipherSuite was defined!
#endif
    if (PAL_SUCCESS != status)
    {
        goto finish;
    }

    palTLSConfCtx->trustedTimeServer = false;
    palTLSConfCtx->useSslSessionResume = false;
    *palTLSConf = (palTLSHandle_t)palTLSConfCtx;
finish:
    if (PAL_SUCCESS != status)
    {
        free(palTLSConfCtx);
    }

    return status;
}


palStatus_t pal_tlsConfigurationFree(palTLSConfHandle_t* palTLSConf)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = NULL;

    PAL_VALIDATE_ARGUMENTS ((NULLPTR == palTLSConf || NULLPTR == *palTLSConf));

    palTLSConfCtx = (palTLSConfService_t*)*palTLSConf;
    status = pal_plat_tlsConfigurationFree(&palTLSConfCtx->platTlsConfHandle);
    if (PAL_SUCCESS == status)
    {
        free(palTLSConfCtx);
        *palTLSConf = NULLPTR;
    }
    return status;
}


palStatus_t pal_addEntropySource(palEntropySource_f entropyCallback)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_plat_addEntropySource(entropyCallback);
    return status;
}

palStatus_t pal_setOwnCertChain(palTLSConfHandle_t palTLSConf, palX509_t* ownCert)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx =  (palTLSConfService_t*)palTLSConf;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConf);
    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx->platTlsConfHandle || NULL == ownCert);

    status = pal_plat_setOwnCertChain(palTLSConfCtx->platTlsConfHandle, ownCert);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_initPrivateKey(const void *buf, size_t buf_size, palPrivateKey_t* privateKey)
{
#if (PAL_ENABLE_X509 == 1)
    PAL_VALIDATE_ARGUMENTS(NULL == buf || NULL == privateKey);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    PAL_VALIDATE_ARGUMENTS(sizeof(*privateKey) != buf_size);
    memcpy(privateKey, buf, sizeof(*privateKey));

#else
    privateKey->buffer = buf;
    privateKey->size = buf_size;
#endif // MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif // PAL_ENABLE_X509 == 1
    return PAL_SUCCESS;
}
palStatus_t pal_setOwnPrivateKey(palTLSConfHandle_t palTLSConf, palPrivateKey_t* privateKey)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx =  (palTLSConfService_t*)palTLSConf;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConf);
    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx->platTlsConfHandle || NULL == privateKey);

    status = pal_plat_setOwnPrivateKey(palTLSConfCtx->platTlsConfHandle, privateKey);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}

palStatus_t pal_setCAChain(palTLSConfHandle_t palTLSConf, palX509_t* caChain, palX509CRL_t* caCRL)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palX509Handle_t x509Ctx = NULLPTR;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConf);
    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx->platTlsConfHandle || NULL == caChain);


    status = pal_plat_setCAChain(palTLSConfCtx->platTlsConfHandle, caChain, caCRL);
#if PAL_USE_SECURE_TIME
    if (PAL_SUCCESS == status)
    {
        uint8_t certID[PAL_CERT_ID_SIZE] = {0};
        size_t actualCertIDLen = 0;

        status = pal_x509Initiate(&x509Ctx);
        if (PAL_SUCCESS != status)
        {
            goto finish;
        }

        status = pal_x509CertParse(x509Ctx, caChain->buffer, caChain->size);
        if (PAL_SUCCESS != status)
        {
            goto finish;
        }

        status = pal_x509CertGetAttribute(x509Ctx, PAL_X509_CERT_ID_ATTR, certID, sizeof(certID), &actualCertIDLen);
        if (PAL_SUCCESS != status)
        {
            goto finish;
        }

        uint8_t g_storedCertSerial[PAL_CERT_ID_SIZE] __attribute__ ((aligned(4))) = {0};
        if (!g_trustedServerValid)
        {
            size_t actualLenBytes;
            palStatus_t internal_status;

            internal_status = storage_rbp_read(STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME, (uint8_t*)g_storedCertSerial, (uint16_t)sizeof(g_storedCertSerial), &actualLenBytes);
            if (PAL_SUCCESS == internal_status)
            {
                g_trustedServerValid = true;
            }
        }

        if ( (sizeof(g_storedCertSerial) == actualCertIDLen) && (0 == memcmp(certID, g_storedCertSerial, sizeof(g_storedCertSerial))))
        {
            palTLSConfCtx->trustedTimeServer = true;
        }
    }
    finish:
#endif //PAL_USE_SECURE_TIME
    if (NULLPTR != x509Ctx)
    {
        pal_x509Free(&x509Ctx);
    }
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}


palStatus_t pal_setPSK(palTLSConfHandle_t palTLSConf, const unsigned char *identity, uint32_t maxIdentityLenInBytes, const unsigned char *psk, uint32_t maxPskLenInBytes)
{
#if (PAL_ENABLE_PSK == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConf);
    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx->platTlsConfHandle || NULL == identity || NULL == psk);


    status = pal_plat_setPSK(palTLSConfCtx->platTlsConfHandle, identity, maxIdentityLenInBytes, psk, maxPskLenInBytes);
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}


palStatus_t pal_tlsSetSocket(palTLSConfHandle_t palTLSConf, palTLSSocket_t* socket)
{	//palSocket_t depend on the library (socket or bio pointer)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConf);
    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx->platTlsConfHandle || NULL == socket);

    status = pal_plat_tlsSetSocket(palTLSConfCtx->platTlsConfHandle, socket);
    return status;
}

#if PAL_USE_SECURE_TIME
PAL_PRIVATE palStatus_t pal_updateTime(uint64_t serverTime, bool trustedTimeServer)
{
    palStatus_t status = PAL_SUCCESS;
    if (trustedTimeServer)
    {
        status = pal_osSetStrongTime(serverTime);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_DBG("Setting strong time failed! return code %" PRId32 ".", status);
        }
    }
    else
    {
        status = pal_osSetWeakTime(serverTime);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_DBG("Setting weak time failed! return code %" PRId32 ".", status);
        }
    }
    return status;
}
#endif //PAL_USE_SECURE_TIME

palStatus_t pal_handShake(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSConfCtx || NULLPTR == palTLSCtx));
    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSCtx->platTlsHandle || NULLPTR == palTLSConfCtx->platTlsConfHandle));

    if (!palTLSCtx->retryHandShake)
    {
        status = pal_plat_handShake(palTLSCtx->platTlsHandle, &palTLSCtx->serverTime);
        if (PAL_SUCCESS == status)
        {
#if PAL_USE_SECURE_TIME
            int32_t verifyResult = 0;
            status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
            if (PAL_ERR_X509_CERT_VERIFY_FAILED == status)
            {
                if ((PAL_ERR_X509_BADCERT_FUTURE & verifyResult) || ((true == palTLSConfCtx->trustedTimeServer) && (PAL_ERR_X509_BADCERT_EXPIRED & verifyResult)))
                {
                    PAL_LOG_DBG("SSL EXPIRED OR FUTURE - retry");
                    palTLSCtx->retryHandShake = true;
                    status = PAL_SUCCESS;
                }
                else if (PAL_SUCCESS != status)
                {
                    status = PAL_ERR_X509_CERT_VERIFY_FAILED;
                    palTLSCtx->serverTime = 0;
#if (PAL_USE_SSL_SESSION_RESUME == 1)
                    pal_removeSslSessionFromStorage(palTLSConfCtx->platTlsConfHandle);
#endif
                }
            }
#else
            if (PAL_SUCCESS != status)
            {
                status = PAL_ERR_X509_CERT_VERIFY_FAILED;
                palTLSCtx->serverTime = 0;
            }

#endif //PAL_USE_SECURE_TIME
        }
    }
#if PAL_USE_SECURE_TIME
    if ((PAL_SUCCESS == status) && (palTLSCtx->retryHandShake))
    {
        PAL_LOG_DBG("SSL START RENEGOTIATE");
        if (!palTLSConfCtx->trustedTimeServer) //! if we are not proccessing handshake with the time trusted server we
        {                                      //! will use PAL_TLS_VERIFY_REQUIRED authentication mode
            status = pal_plat_setAuthenticationMode(palTLSConfCtx->platTlsConfHandle, PAL_TLS_VERIFY_REQUIRED);
            if (PAL_SUCCESS != status)
            {
#if (PAL_USE_SSL_SESSION_RESUME == 1)
                pal_removeSslSessionFromStorage(palTLSConfCtx->platTlsConfHandle);
#endif
                goto finish;
            }
        }
        status = pal_plat_renegotiate(palTLSCtx->platTlsHandle, palTLSCtx->serverTime);
        if (PAL_SUCCESS == status)
        {
            int32_t verifyResult = 0;
            status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
            if ((palTLSConfCtx->trustedTimeServer) &&
                ((PAL_ERR_X509_CERT_VERIFY_FAILED == status) && ((PAL_ERR_X509_BADCERT_EXPIRED & verifyResult) || (PAL_ERR_X509_BADCERT_FUTURE & verifyResult))))
            {
                status = PAL_SUCCESS;
            }
        }
    }

    if (PAL_SUCCESS == status)
    {
        //! We ignore the pal_updateTime() result, because it should not cause a failure to the handshake process.
        //! Logs are printed in the pal_updateTime() function in case of failure.
        pal_updateTime(palTLSCtx->serverTime, palTLSConfCtx->trustedTimeServer);
#if (PAL_USE_SSL_SESSION_RESUME == 1)
        pal_saveSslSessionToStorage(palTLSHandle, palTLSConf);
#endif
    }

#endif //PAL_USE_SECURE_TIME
finish:
    return status;
}

#if PAL_USE_SECURE_TIME
palStatus_t pal_sslGetVerifyResultExtended(palTLSHandle_t palTLSHandle, int32_t* verifyResult)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSService_t* palTLSCtx = NULL;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSHandle) || (NULL == verifyResult));

    palTLSCtx = (palTLSService_t*)palTLSHandle;
    PAL_VALIDATE_ARGUMENTS(NULLPTR == palTLSCtx->platTlsHandle);

    status = pal_plat_sslGetVerifyResultExtended(palTLSCtx->platTlsHandle, verifyResult);
    if (0 != *verifyResult)
    {
        status = PAL_ERR_X509_CERT_VERIFY_FAILED;
        *verifyResult = *verifyResult ^ PAL_ERR_MODULE_BITMASK_BASE; //! in order to turn off the MSB bit.
    }

    return status;
}


palStatus_t pal_sslGetVerifyResult(palTLSHandle_t palTLSHandle)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSService_t* palTLSCtx = NULL;
    int32_t verifyResult = 0;

    PAL_VALIDATE_ARGUMENTS(NULLPTR == palTLSHandle);

    palTLSCtx = (palTLSService_t*)palTLSHandle;
    PAL_VALIDATE_ARGUMENTS(NULLPTR == palTLSCtx->platTlsHandle);

    status = pal_plat_sslGetVerifyResultExtended(palTLSCtx->platTlsHandle, &verifyResult);
    return status;
}
#endif //PAL_USE_SECURE_TIME

palStatus_t pal_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t timeoutInMilliSec)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx =  (palTLSConfService_t*)palTLSConf;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx || 0 == timeoutInMilliSec);

    status = pal_plat_setHandShakeTimeOut(palTLSConfCtx->platTlsConfHandle, timeoutInMilliSec);
    return status;
}


palStatus_t pal_sslRead(palTLSHandle_t palTLSHandle, void *buffer, uint32_t len, uint32_t* actualLen)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSHandle);
    PAL_VALIDATE_ARGUMENTS ((NULLPTR == palTLSCtx->platTlsHandle || NULL == buffer || NULL == actualLen));

    status = pal_plat_sslRead(palTLSCtx->platTlsHandle, buffer, len, actualLen);
    return status;
}


palStatus_t pal_sslWrite(palTLSHandle_t palTLSHandle, const void *buffer, uint32_t len, uint32_t *bytesWritten)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSHandle || NULL == buffer || NULL == bytesWritten));

    status = pal_plat_sslWrite(palTLSCtx->platTlsHandle, buffer, len, bytesWritten);
    return status;
}

palStatus_t pal_sslDebugging(uint8_t turnOn)
{
    return PAL_ERR_NOT_SUPPORTED;
}

palStatus_t pal_sslSetDebugging(palTLSConfHandle_t palTLSConf, uint8_t turnOn)
{
    palStatus_t status = PAL_SUCCESS;

    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;

    status = pal_plat_sslSetDebugging(palTLSConfCtx->platTlsConfHandle, turnOn);
    return status;
}

#if (PAL_USE_SSL_SESSION_RESUME == 1)
void pal_enableSslSessionStoring(palTLSConfHandle_t palTLSConf, bool enable)
{
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palTLSConfCtx->useSslSessionResume = enable;
}

void pal_removeSslSessionFromStorage(palTLSConfHandle_t palTLSConf)
{
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    if (!palTLSConfCtx->useSslSessionResume)
    {
        PAL_LOG_ERR("pal_removeSslSessionFromStorage - feature not enabled!");
        return;
    }

    kcm_item_delete((uint8_t *)kcm_session_item_name,
                    strlen(kcm_session_item_name),
                    KCM_CONFIG_ITEM);
}

void pal_saveSslSessionToStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    uint8_t *session_data;
    size_t session_size = 0;

    if (!palTLSConfCtx->useSslSessionResume)
    {
        PAL_LOG_ERR("pal_saveSslSessionToStorage - feature not enabled!");
        return;
    }

    session_data = pal_plat_GetSslSessionBuffer(palTLSCtx->platTlsHandle, &session_size);
    if (!session_data)
    {
        PAL_LOG_ERR("pal_saveSslSessionToStorage - failed to get session buffer!");
        return;
    }

    bool replace = false;
    size_t act_size = 0;
    kcm_status_e kcm_status = kcm_item_get_data_size((uint8_t *)kcm_session_item_name,
                                   strlen(kcm_session_item_name),
                                   KCM_CONFIG_ITEM, &act_size);

    if (kcm_status != KCM_STATUS_SUCCESS)
    {
        replace = true;
    }


    // Check existing data before writing it again to storage
    if (!replace)
    {
        replace = true;
        uint8_t *existing_session = (uint8_t*)malloc(act_size);
        if (!existing_session)
        {
            PAL_LOG_ERR("pal_saveSslSessionToStorage - failed to allocate buffer!");
            free(session_data);
            return;
        }

        size_t data_out = 0;
        kcm_status = kcm_item_get_data((uint8_t *)kcm_session_item_name,
                                       strlen(kcm_session_item_name),
                                       KCM_CONFIG_ITEM, existing_session, act_size, &data_out);

        if (kcm_status == KCM_STATUS_SUCCESS && memcmp(session_data, existing_session, act_size) == 0)
        {
            replace = false;
        }

        free(existing_session);
    }

    // Store only if session has changed or there is no data yet
    if (replace)
    {
        PAL_LOG_DBG("pal_saveSslSessionToStorage - save a new session");
        kcm_item_delete((uint8_t *)kcm_session_item_name,
                                     strlen(kcm_session_item_name),
                                     KCM_CONFIG_ITEM);

        kcm_status = kcm_item_store((uint8_t *)kcm_session_item_name,
                                    strlen(kcm_session_item_name),
                                    KCM_CONFIG_ITEM,
                                    false,
                                    session_data,
                                    session_size,
                                    NULL);

        if (kcm_status != KCM_STATUS_SUCCESS)
        {
            PAL_LOG_DBG("pal_saveSslSessionToStorage - failed to store data: %d", kcm_status);
        }
    }
    else
    {
        PAL_LOG_DBG("pal_saveSslSessionToStorage - keep old session");
    }

    free(session_data);
}

void pal_loadSslSessionFromStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    if (!palTLSConfCtx->useSslSessionResume)
    {
        PAL_LOG_ERR("pal_loadSslSessionFromStorage - feature not enabled!");
        return;
    }

    size_t act_size = 0;
    kcm_status_e kcm_status = kcm_item_get_data_size((uint8_t *)kcm_session_item_name,
                                   strlen(kcm_session_item_name),
                                   KCM_CONFIG_ITEM, &act_size);

    if (kcm_status != KCM_STATUS_SUCCESS)
    {
        PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to get item size!");
        return;
    }

    uint8_t *existing_session = (uint8_t*)malloc(act_size);
    if (!existing_session)
    {
        PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to allocate buffer!");
        return;
    }

    size_t data_out = 0;
    kcm_status = kcm_item_get_data((uint8_t *)kcm_session_item_name,
                                   strlen(kcm_session_item_name),
                                   KCM_CONFIG_ITEM, existing_session, act_size, &data_out);

    if (kcm_status != KCM_STATUS_SUCCESS)
    {
        PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to get item!");
        free(existing_session);
        return;
    }

    pal_plat_SetSslSession(palTLSCtx->platTlsHandle, existing_session);
    free(existing_session);
}

#endif //PAL_USE_SSL_SESSION_RESUME

void pal_setDTLSSocketCallback(palTLSConfHandle_t palTLSConf, palSocketCallback_f callback, void *argument)
{
    //palSocket_t depend on the library (socket or bio pointer)
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    pal_plat_SetDTLSSocketCallback(palTLSConfCtx->platTlsConfHandle, callback, argument);
}
