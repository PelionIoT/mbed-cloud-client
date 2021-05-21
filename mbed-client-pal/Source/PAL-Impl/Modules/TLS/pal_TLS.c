/*******************************************************************************
 * Copyright 2016-2020 ARM Ltd.
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

// do not require storage unless this modules is configured to use it
#if PAL_USE_SECURE_TIME
#include "storage_kcm.h"
#endif

#if (PAL_USE_SSL_SESSION_RESUME == 1)
#include "key_config_manager.h"
static const char* kcm_session_item_name = "sslsession";
static void pal_saveSslSessionToStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);
static void pal_removeSslSessionFromStorage(palTLSConfHandle_t palTLSConf);
static int32_t pal_loadSslSessionFromStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf);
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
    bool isDtlsMode;
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


palStatus_t pal_initTLS(palTLSConfHandle_t palTLSConf, palTLSHandle_t* palTLSHandle, bool is_server_ping)
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
        if(!is_server_ping) {
            palStatus_t tmp_status = pal_loadSslSessionFromStorage(*palTLSHandle, palTLSConf);
            // if returned other than PAL_SUCCESS or PAL_ERR_GENERIC_FAILURE
            if (PAL_SUCCESS != tmp_status && PAL_ERR_GENERIC_FAILURE != tmp_status) {
                PAL_LOG_ERR("Failed to load ssl session:-0x%" PRIx32 ".", tmp_status);
                status = tmp_status;
            }
        }
#endif
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
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
#elif (PAL_TLS_CIPHER_SUITE & PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_SUITE)
    status = pal_plat_setCipherSuites(palTLSConfCtx->platTlsConfHandle, PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
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
    palTLSConfCtx->isDtlsMode = true;
    if(transportationMode == PAL_TLS_MODE) {
        palTLSConfCtx->isDtlsMode = false;
    }
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

#if (PAL_USE_SSL_SESSION_RESUME == 1)
void pal_print_cid(palTLSHandle_t palTLSHandle)
{
    uint8_t data_ptr[32];// MBEDTLS_SSL_CID_OUT_LEN_MAX = 32
    size_t data_len = 0;
    pal_plat_get_cid_value(palTLSHandle, data_ptr, &data_len);
    if (data_len) {
        PAL_LOG_DBG("CID: %s", PAL_LOG_ARRAY_FUNC(data_ptr, data_len));
    }
}
#endif

palStatus_t pal_handShake(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf, bool skipResume)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSConfCtx || NULLPTR == palTLSCtx));
    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSCtx->platTlsHandle || NULLPTR == palTLSConfCtx->platTlsConfHandle));

#if (PAL_USE_SSL_SESSION_RESUME == 1)
    if (!skipResume && palTLSConfCtx->isDtlsMode) {
        if (pal_plat_sslSessionAvailable()) {
            PAL_LOG_DBG("pal_handShake: using stored session");
            pal_print_cid(palTLSCtx->platTlsHandle);
            return status;
        }
    }
#endif //PAL_USE_SSL_SESSION_RESUME

    if (!palTLSCtx->retryHandShake)
    {
        status = pal_plat_handShake(palTLSCtx->platTlsHandle, &palTLSCtx->serverTime);
        if (PAL_SUCCESS == status)
        {
            int32_t verifyResult = 0;
            status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
            if (PAL_ERR_X509_CERT_VERIFY_FAILED == status)
            {
#if PAL_USE_SECURE_TIME
                // if cert verification fails _only_ on certificate time being wrong (and we use 'secure time' feature),
                // try to renegotiate using server's time

                // Cert being in future means client is actually in the past, so we're allowed to correct it always (sleepy device...)
                // Cert being in the past (expired) means client is in future, so we only trust it when talking to Time RoT (trustedTimeServer)
                if ((PAL_ERR_X509_BADCERT_FUTURE == verifyResult) || ((true == palTLSConfCtx->trustedTimeServer) && (PAL_ERR_X509_BADCERT_EXPIRED == verifyResult)))
                {
                    PAL_LOG_DBG("SSL EXPIRED OR FUTURE - renegotiate");
                    palTLSCtx->retryHandShake = true;
                    status = PAL_SUCCESS;
                }
#else
                // If PAL_USE_SECURE_TIME is not on, don't do time verification from certificate
                if ((PAL_ERR_X509_BADCERT_FUTURE == verifyResult) || (PAL_ERR_X509_BADCERT_EXPIRED == verifyResult))
                {
                    PAL_LOG_WARN("SSL EXPIRED OR FUTURE - passing due to PAL_USE_SECURE_TIME not set");
                    status = PAL_SUCCESS;
                }
#endif
                if (PAL_SUCCESS != status)
                {
                    palTLSCtx->serverTime = 0;
#if (PAL_USE_SSL_SESSION_RESUME == 1)
                    pal_removeSslSessionFromStorage(palTLSConfCtx->platTlsConfHandle);
#endif
                }
            }
        }
    }
#if PAL_USE_SECURE_TIME
    if ((PAL_SUCCESS == status) && (palTLSCtx->retryHandShake))
    {
        PAL_LOG_DBG("SSL START RENEGOTIATE");
        // We can now set verify required which does full certificate verification inside pal_plat_renegotiate call
        // since time should be fine as we just got it from the server.
        status = pal_plat_setAuthenticationMode(palTLSConfCtx->platTlsConfHandle, PAL_TLS_VERIFY_REQUIRED);
        if (PAL_SUCCESS != status)
        {
#if (PAL_USE_SSL_SESSION_RESUME == 1)
            pal_removeSslSessionFromStorage(palTLSConfCtx->platTlsConfHandle);
#endif
            goto finish;
        }

        status = pal_plat_renegotiate(palTLSCtx->platTlsHandle, palTLSCtx->serverTime);
    }

    if (PAL_SUCCESS == status)
    {
        //! We ignore the pal_updateTime() result, because it should not cause a failure to the handshake process.
        //! Logs are printed in the pal_updateTime() function in case of failure.
        pal_updateTime(palTLSCtx->serverTime, palTLSConfCtx->trustedTimeServer);
    }
#endif //PAL_USE_SECURE_TIME
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    if (PAL_SUCCESS == status) {
        pal_saveSslSessionToStorage(palTLSHandle, palTLSConf);
        PAL_LOG_DBG("pal_handShake: handshake done, storing session!");
        if (palTLSConfCtx->isDtlsMode) {
            pal_print_cid(palTLSCtx->platTlsHandle);
        }
    }

#endif // PAL_USE_SSL_SESSION_RESUME
#if PAL_USE_SECURE_TIME
finish:
#endif //PAL_USE_SECURE_TIME
    return status;
}

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
    }

    return status;
}


palStatus_t pal_setHandShakeTimeOut(palTLSConfHandle_t palTLSConf, uint32_t minTimeout, uint32_t maxTimeout)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfService_t* palTLSConfCtx =  (palTLSConfService_t*)palTLSConf;

    PAL_VALIDATE_ARGUMENTS (NULLPTR == palTLSConfCtx || 0 == minTimeout|| 0 == maxTimeout);

    status = pal_plat_setHandShakeTimeOut(palTLSConfCtx->platTlsConfHandle, minTimeout, maxTimeout);
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


palStatus_t pal_sslWrite(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf, const void *buffer, uint32_t len, uint32_t *bytesWritten)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    PAL_VALIDATE_ARGUMENTS((NULLPTR == palTLSHandle || NULL == buffer || NULL == bytesWritten));
    status = pal_plat_sslWrite(palTLSCtx->platTlsHandle, buffer, len, bytesWritten);
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    if (palTLSConfCtx->isDtlsMode) {
        PAL_LOG_DBG("pal_plat_sslWrite, using stored session!");
        pal_print_cid(palTLSCtx->platTlsHandle);
        pal_saveSslSessionToStorage(palTLSHandle, palTLSConf);
}
#endif // (PAL_USE_SSL_SESSION_RESUME == 1)
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
    if(palTLSConfCtx->isDtlsMode) {
        if(!enable) {
            pal_plat_removeSslSession();
        }
    }
    palTLSConfCtx->useSslSessionResume = enable;
}
#endif

void pal_store_cid()
{
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    (void) kcm_item_delete((uint8_t *)kcm_session_item_name,
                                 strlen(kcm_session_item_name),
                                 KCM_CONFIG_ITEM);

    const uint8_t *context = NULL;
    size_t size = 0;
    context = pal_plat_get_cid(&size);

    if(context != NULL && size != 0) {
        PAL_LOG_DBG("pal_store_cid - Save CID persistently");
        kcm_status_e kcm_status = kcm_item_store((uint8_t *)kcm_session_item_name,
                                    strlen(kcm_session_item_name),
                                    KCM_CONFIG_ITEM,
                                    false,
                                    context,
                                    size,
                                    NULL);
        if (kcm_status != KCM_STATUS_SUCCESS) {
            PAL_LOG_ERR("pal_store_cid - Failed to save CID persistently");
        }
    }
#endif
}

void pal_remove_cid()
{
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    PAL_LOG_DBG("pal_remove_cid - remove CID");
    (void) kcm_item_delete((uint8_t *)kcm_session_item_name,
                                 strlen(kcm_session_item_name),
                                 KCM_CONFIG_ITEM);

    pal_plat_removeSslSession();
#endif
}

bool pal_is_cid_available()
{
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    return pal_plat_sslSessionAvailable();
#else
    return false;
#endif
}

#if (PAL_USE_SSL_SESSION_RESUME == 1)
void pal_removeSslSessionFromStorage(palTLSConfHandle_t palTLSConf)
{
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    if (!palTLSConfCtx->useSslSessionResume)
    {
        PAL_LOG_ERR("pal_removeSslSessionFromStorage - feature not enabled!");
        return;
    }

    if(palTLSConfCtx->isDtlsMode) {
        pal_plat_removeSslSession();
    } else {
        (void) kcm_item_delete((uint8_t *)kcm_session_item_name,
                        strlen(kcm_session_item_name),
                        KCM_CONFIG_ITEM);
    }
}

void pal_saveSslSessionToStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    uint8_t *session_data;
    size_t session_size = 0;

    if (!palTLSConfCtx->useSslSessionResume)
    {
        PAL_LOG_DBG("pal_saveSslSessionToStorage - feature not enabled!");
        return;
    }
    if(!palTLSConfCtx->isDtlsMode) {
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
            (void) kcm_item_delete((uint8_t *)kcm_session_item_name,
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
    }else {
        if(pal_plat_saveSslSessionBuffer(palTLSCtx->platTlsHandle) == 0) {
            pal_loadSslSessionFromStorage(palTLSHandle, palTLSConf);
        }
    }
}

int32_t pal_loadSslSessionFromStorage(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf)
{
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;

    int32_t return_value = PAL_ERR_GENERIC_FAILURE;
    if (!palTLSConfCtx->useSslSessionResume)
    {
        PAL_LOG_DBG("pal_loadSslSessionFromStorage - feature not enabled !");
        return return_value;
    }
    if(!palTLSConfCtx->isDtlsMode) {
        size_t act_size = 0;
        kcm_status_e kcm_status = kcm_item_get_data_size((uint8_t *)kcm_session_item_name,
                                       strlen(kcm_session_item_name),
                                       KCM_CONFIG_ITEM, &act_size);

        if (kcm_status != KCM_STATUS_SUCCESS)
        {
            PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to get item size!");
            return return_value;
        }

        uint8_t *existing_session = (uint8_t*)malloc(act_size);
        if (!existing_session)
        {
            PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to allocate buffer!");
            return PAL_ERR_NO_MEMORY;
        }

        size_t data_out = 0;
        kcm_status = kcm_item_get_data((uint8_t *)kcm_session_item_name,
                                       strlen(kcm_session_item_name),
                                       KCM_CONFIG_ITEM, existing_session, act_size, &data_out);

        if (kcm_status != KCM_STATUS_SUCCESS)
        {
            PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to get item!");
            free(existing_session);
            return return_value;
        }

        pal_plat_SetSslSession(palTLSCtx->platTlsHandle, existing_session);
        free(existing_session);
        return_value = 0;
    } else {
        size_t act_size = 0;
        kcm_status_e kcm_status = kcm_item_get_data_size((uint8_t *)kcm_session_item_name,
                                       strlen(kcm_session_item_name),
                                       KCM_CONFIG_ITEM, &act_size);

        if (kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND)
        {
            PAL_LOG_ERR("pal_loadSslSessionFromStorage - failed to get item size!");
            return return_value;
        }

        if(pal_plat_sslSessionAvailable()) {
            return_value = pal_plat_loadSslSession(palTLSCtx->platTlsHandle);
        } else if(act_size > 0) {
            size_t data_out = 0;
            uint8_t *existing_session = (uint8_t*)malloc(act_size);
            kcm_item_get_data((uint8_t *)kcm_session_item_name,
                              strlen(kcm_session_item_name),
                              KCM_CONFIG_ITEM, existing_session, act_size, &data_out);
            pal_plat_set_cid(existing_session, act_size);
            free(existing_session);
            return_value = pal_plat_loadSslSession(palTLSCtx->platTlsHandle);
            (void) kcm_item_delete((uint8_t *)kcm_session_item_name,
                            strlen(kcm_session_item_name),
                            KCM_CONFIG_ITEM);
        }

    }
    return return_value;
}

#endif //PAL_USE_SSL_SESSION_RESUME

void pal_setDTLSSocketCallback(palTLSConfHandle_t palTLSConf, palSocketCallback_f callback, void *argument)
{
    //palSocket_t depend on the library (socket or bio pointer)
    palTLSConfService_t* palTLSConfCtx = (palTLSConfService_t*)palTLSConf;
    pal_plat_SetDTLSSocketCallback(palTLSConfCtx->platTlsConfHandle, callback, argument);
}

void pal_set_cid_value(palTLSHandle_t palTLSHandle, palTLSConfHandle_t palTLSConf, const uint8_t *data_ptr, const size_t data_len)
{
#if (PAL_USE_SSL_SESSION_RESUME == 1)
    palTLSService_t* palTLSCtx = (palTLSService_t*)palTLSHandle;
    pal_plat_set_cid_value(palTLSCtx->platTlsHandle, data_ptr, data_len);
    pal_loadSslSessionFromStorage(palTLSHandle, palTLSConf);
#endif
}
