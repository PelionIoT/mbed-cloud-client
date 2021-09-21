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


#include "unity.h"
#include "unity_fixture.h"
#include "pal.h"
#include "cs_pal_crypto.h"
#include "pal_tls_utils.h"
#include "storage_kcm.h"
#include "test_runners.h"
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "sotp.h"
#endif

#include "ns_hal_init.h"

#if !PAL_USE_HW_TRNG
#include "pal_plat_entropy.h"
#endif

#if (PAL_USE_SSL_SESSION_RESUME == 1)
#include "key_config_manager.h"
#endif

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "psa/crypto.h"
#endif


#include <stdlib.h>
#define TRACE_GROUP "PAL"
#if (PAL_ENABLE_PSK == 1)
#define PAL_TEST_PSK_IDENTITY "Client_identity"
#define PAL_TEST_PSK {0x12,0x34,0x45,0x67,0x89,0x10}
#endif

#define PAL_WAIT_TIME	3

#define HOSTNAME_STR_MAX_LEN 256

#if (PAL_USE_SSL_SESSION_RESUME == 1)
static bool isSslSessionAvailable();
static void removeSslSession();
static const char* ssl_session_item_name = "sslsession";
#endif

PAL_PRIVATE palSocket_t g_socket = 0;
extern void * g_palTestTLSInterfaceCTX; // this is set by the palTestMain funciton
PAL_PRIVATE uint32_t g_interfaceCTXIndex = 0;

#if (PAL_USE_INTERNAL_FLASH == 1)
    PAL_PRIVATE uint8_t g_trustedServerID[PAL_CERT_ID_SIZE] __attribute__((aligned(4))) = { 0 };
    PAL_PRIVATE size_t g_actualServerIDSize = 0;
#endif

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_ENABLE_X509 == 1))
PAL_PRIVATE palMutexID_t g_mutex1 = NULLPTR;
#if (PAL_ENABLE_X509 == 1)
    PAL_PRIVATE palMutexID_t g_mutex2 = NULLPTR;
#endif
PAL_PRIVATE palMutexID_t g_mutexHandShake1 = NULLPTR;
PAL_PRIVATE bool g_retryHandshake = false;
#endif

#define PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(a, b) \
    if (a != b) \
    {\
        PAL_LOG_ERR("Expected: %" PRId32 " , Actual: %" PRId32 " , Line: %d\n", (int32_t)a, (int32_t)b, __LINE__);\
        goto finish;\
    }

#if (PAL_DNS_API_VERSION == 2) || (PAL_DNS_API_VERSION == 3)

static palSemaphoreID_t s_asyncDnsSemaphore = NULLPTR;

// callback invoked from the call to pal_getAddressInfoAsync
#if (PAL_DNS_API_VERSION == 2)

PAL_PRIVATE void getAddressInfoAsyncCallback(const char* url, palSocketAddress_t* address, palStatus_t status, void* callbackArgument)
{
#else // (PAL_DNS_API_VERSION == 3)
static palAddressInfo_t *global_addrInfo = NULLPTR;
static palDNSQuery_t dns_query_t = 0;
PAL_PRIVATE void getAddressInfoAsyncCallback(const char* url, palAddressInfo_t *addrInfo, palStatus_t status, void* callbackArgument)
{
    global_addrInfo = addrInfo;
#endif
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    pal_osSemaphoreRelease(s_asyncDnsSemaphore);
}
#endif

#if !(PAL_USE_SECURE_TIME)
// If testing without PAL secure time, some tests require faking the time to mbedtls to get desired effect
// from certificate verification
#include "mbedtls/ssl.h"
#include "mbedtls/platform.h"
static mbedtls_time_t time_to_return;
static mbedtls_time_t definately_in_future = 1935316090; // Wednesday, April 30, 2031 11:48:10 AM
static int return_fake_time = 0;
mbedtls_time_t pal_mbedtlsTimeCB(mbedtls_time_t* timer)
{
    if(return_fake_time) {
        return time_to_return++;
    }
    else {
        // this is what mbedtls calls by default if mbedtls_platform_set_time was not called
        return MBEDTLS_PLATFORM_STD_TIME(timer);
    }
}
#endif


PAL_PRIVATE palStatus_t doDnsQuery(const char* hostname, palSocketAddress_t *address, palSocketLength_t *addrlen)
{
    palStatus_t result = PAL_SUCCESS;
#if (PAL_DNS_API_VERSION == 2)
    result = pal_osSemaphoreCreate(0, &s_asyncDnsSemaphore);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    result = pal_getAddressInfoAsync(hostname,
                                     address,
                                     &getAddressInfoAsyncCallback,
                                     NULL,
                                     NULL);

    result = pal_osSemaphoreWait(s_asyncDnsSemaphore, 5000, NULL);
#elif (PAL_DNS_API_VERSION == 3)
    result = pal_osSemaphoreCreate(0, &s_asyncDnsSemaphore);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    result = pal_getAddressInfoAsync(hostname,
                                     &getAddressInfoAsyncCallback,
                                     NULL,
                                     &dns_query_t);
    result = pal_osSemaphoreWait(s_asyncDnsSemaphore, 5000, NULL);
    result = pal_free_addressinfoAsync(dns_query_t);
    result = pal_getDNSAddress(global_addrInfo, 0, address);
    *addrlen = sizeof(palSocketAddress_t);
    pal_freeAddrInfo(global_addrInfo);
    global_addrInfo = NULLPTR;
    dns_query_t = 0;
#else
    result = pal_getAddressInfo(hostname, address, addrlen);
#endif
    return result;
}



static palSemaphoreID_t s_semaphoreID = NULLPTR;
PAL_PRIVATE void socketCallback1( void * arg)
{
    palStatus_t result;
    result = pal_osSemaphoreRelease(s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
}

static void setCredentials(palTLSConfHandle_t handle);
static void setCredentialsWrongCA(palTLSConfHandle_t handle);
static void do_handshake(palTLSTransportMode_t mode, bool enable_session_storing);

//! This structre is for tests only and MUST be the same structure as in the pal_TLS.c file
//! For any change done in the original structure, please make sure to change this structure too.
typedef struct palTLSService
{
    bool retryHandShake;
    uint64_t serverTime;
    palTLSHandle_t platTlsHandle;
}palTLSTest_t;

TEST_GROUP(pal_tls);

TEST_SETUP(pal_tls)
{
    palStatus_t status = PAL_SUCCESS;

    // This time is used as current time during tests. It needs to be a time when the test server certificate is valid.
    // (by default, connects to bootstrap server)
    // Running following one-liner in bash should output suitable date, one day before certificate expiration.
    //
    // Get cert from remote                                                                     // parse the cert    // extract expiration date           // to timestamp // subtract one day            // echo it, use date to produce the human readable comment
    // openssl s_client -showcerts -connect bootstrap.us-east-1.mbedcloud.com:5684 2>/dev/null | openssl x509 -text | sed -n "s/Not After : \(.*\)/\1/p" | date -f - +%s | { read num; ((sum=num-86400)); echo "uint64_t currentTime = $sum; // `date -R -u --date=@$sum`"; }
    uint64_t currentTime = 1546497053; // Thu, 03 Jan 2019 06:30:53 +0000

    //init pal
    ns_hal_init(NULL, 1024, NULL, NULL);
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    sotp_reset();
#else
    // Reset storage before pal_initTime since there might be CMAC lefovers
    // in internal flash which might fail storage access in pal_initTime
    pal_SSTReset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#if !PAL_USE_HW_TRNG
    // If no hardware trng - entropy must be injected for random to work
    uint8_t entropy_buf[48] = { 0 };
    status = pal_osEntropyInject(entropy_buf, sizeof(entropy_buf));
    TEST_ASSERT(status == PAL_SUCCESS || status == PAL_ERR_ENTROPY_EXISTS);
#endif

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    // psa_crypto_init required to generate random buffer in PSA implementation
    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);
#endif

    // Initialize the time module, as this test uses time functionality
    status = pal_initTime();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    if (g_palTestTLSInterfaceCTX == NULL)
    {
        PAL_LOG_ERR("error: net interface not configutred correctly");
    }
    else
    {
        status = pal_registerNetworkInterface(g_palTestTLSInterfaceCTX, &g_interfaceCTXIndex);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    g_socket = 0;

    status = pal_osSetTime(currentTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#if !(PAL_USE_SECURE_TIME)
    mbedtls_platform_set_time(pal_mbedtlsTimeCB);
#endif
}

TEST_TEAR_DOWN(pal_tls)
{
#if !(PAL_USE_SECURE_TIME)
    return_fake_time = 0;
#endif
    if (0 != g_socket)
    {
        pal_close(&g_socket);
    }

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    // Reset storage before pal_initTime since there might be CMAC lefovers
    // in internal flash which might fail storage access in pal_initTime
    pal_SSTReset();
#else
    sotp_reset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    pal_destroy();
}

/**
* @brief Test TLS cofiguration initialization and uninitialization.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize TLS configuration using `pal_initTLSConfiguration`.       | PAL_SUCCESS |
* | 2 | Uninitialize TLS configuration using `pal_tlsConfigurationFree`.     | PAL_SUCCESS |
*/
TEST(pal_tls, tlsConfiguration)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    /*#1*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(NULLPTR != palTLSConf);
    /*#2*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(NULLPTR, palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

int palTestEntropySource(void *data, unsigned char *output, size_t len, size_t *olen)
{
    palStatus_t status = PAL_SUCCESS;
    (void)data;

    status = pal_osRandomBuffer(output, len);
    if (PAL_SUCCESS == status)
    {
        *olen = len;
    }
    else
    {
        return -1;
    }
    return 0;
}

struct server_address
{
    char hostname[HOSTNAME_STR_MAX_LEN];
    uint16_t port;
};

static void parseServerAddress(struct server_address *data, const char* const url)
{
    const char* start;
    size_t str_len;

    data->port = 0;

    // Extract hostname from url
    start = strchr(url, ':');
    if (start != NULL && *(start+1) == '/')
    {
        start = start + 3;
    }
    else
    {
        start = url;
    }

    const char* end = strchr(start, ':');
    if (end == NULL)
    {
        end = strchr(start, '/');
        if (end == NULL)
        {
            end = start + strlen(start);
        }
    }
    else
    {
        data->port = atoi(end+1);
    }

    str_len = end-start;

    TEST_ASSERT_TRUE(str_len > 0 && str_len < HOSTNAME_STR_MAX_LEN);

    TEST_ASSERT_EQUAL_PTR(data->hostname, strncpy(data->hostname, start, str_len));
    data->hostname[str_len] = '\0';
}


/**
* @brief Test TLS initialization and uninitialization.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize TLS configuration using `pal_initTLSConfiguration`.       | PAL_SUCCESS |
* | 2 | Initialize TLS context using `pal_initTLS`.                          | PAL_SUCCESS |
* | 3 | Add a NULL entropy source using `pal_addEntropySource`.             | PAL_ERR_INVALID_ARGUMENT |
* | 4 | Add a valid entropy source using `pal_addEntropySource`.             | PAL_SUCCESS |
* | 5 | Uninitialize TLS context using `pal_freeTLS`.                        | PAL_SUCCESS |
* | 6 | Uninitialize TLS configuration using `pal_tlsConfigurationFree`.     | PAL_SUCCESS |
*/
TEST(pal_tls, tlsInitTLS)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_TLS_MODE;
    /*#1*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#ifdef DEBUG
    /*#3*/
    status = pal_addEntropySource(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif
    /*#4*/
    status = pal_addEntropySource(palTestEntropySource);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#6*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

}



/**
* @brief Test TLS initialization and uninitialization with additional keys.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize TLS configuration using `pal_initTLSConfiguration`.       | PAL_SUCCESS |
* | 2 | Add keys to the configuration using `pal_setOwnCertChain`.           | PAL_SUCCESS |
* | 3 | Add keys to the configuration using `pal_setOwnPrivateKey`.          | PAL_SUCCESS |
* | 4 | Initialize TLS context using `pal_initTLS`.                          | PAL_SUCCESS |
* | 5 | Uninitialize TLS context using `pal_freeTLS`.                        | PAL_SUCCESS |
* | 6 | Uninitialize TLS configuration using `pal_tlsConfigurationFree`.     | PAL_SUCCESS |
*/
TEST(pal_tls, tlsPrivateAndPublicKeys)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT


#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};

    palPrivateKey_t prvKey;
    status = pal_initPrivateKey((const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#1*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_setOwnCertChain(palTLSConf, &pubKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_setOwnPrivateKey(palTLSConf, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#6*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test TLS initialization and uninitialization with additional certificate and pre-shared keys.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize TLS configuration using `pal_initTLSConfiguration`.       | PAL_SUCCESS |
* | 2 | Set pre-shared keys to the configuration using `pal_setPSK`.         | PAL_SUCCESS |
* | 3 | Initialize TLS context using `pal_initTLS`.                         | PAL_SUCCESS
* | 4 | Uninitialize TLS context using `pal_freeTLS`.              			 |PAL_SUCCESS |
* | 5 | Uninitialize TLS configuration using `pal_tlsConfigurationFree`.     | PAL_SUCCESS |
*/
TEST(pal_tls, tlsCACertandPSK)
{
#if (PAL_ENABLE_PSK == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    /*#1*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_setPSK(palTLSConf, g_psk_id, sizeof(g_psk_id) - 1, g_psk, sizeof(g_psk));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_PSK not set");
#endif
}

/**
* @brief Test TLS handshake (TCP non-blocking).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 2 | Create a TCP socket.                                                       | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 8 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 9 | Perform a TLS handshake with the server using `pal_handShaket` in a loop. | PAL_SUCCESS |
* | 10 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 11 | Write data over the open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 12 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 13 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 14 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 15 | Close the TCP socket.                                                   | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    #if (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t curTimeInSec, timePassedInSec;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds
    int32_t verifyResult = 0;
    struct server_address server;

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);

    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 100, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);

    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        /*#7*/
        setCredentials(palTLSConf);
    #elif (PAL_ENABLE_PSK == 1)
        /*#7 + 8*/
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif

    /*#8*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#9*/
    status = pal_osSetTime(minSecSinceEpoch);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); // More than current epoch time -> success
    do
    {
        curTimeInSec = pal_osGetTime();
        TEST_ASSERT_TRUE(curTimeInSec >= minSecSinceEpoch);
        timePassedInSec = curTimeInSec - minSecSinceEpoch;
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while ((PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status) &&
            (timePassedInSec < PAL_SECONDS_PER_MIN)); //2 minutes to wait for handshake

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#10*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#11*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#12*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#13*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#14*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#15*/
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test (D)TLS handshake.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 2 | Create a UDP socket.                                                       | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 5 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 6 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 7 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 8 | Set the timeout for the handshake using `pal_setHandShakeTimeOut`.         | PAL_SUCCESS |
* | 9 | Perform a TLS handshake with the server using `pal_handShaket` in a loop. | PAL_SUCCESS |
* | 10 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 11 | Write data over the open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 12 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 13 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 14 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 15 | Close the UDP socket.                                                   | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeUDP)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_DTLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    #if (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = {g_socket, &socketAddr, 0, transportationMode};
    int32_t verifyResult = 0;
    struct server_address server;
    int32_t temp;

    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_DGRAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        /*#6*/
        setCredentials(palTLSConf);
    #elif (PAL_ENABLE_PSK == 1)
        /*#6 + #7*/
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif

    /*#7*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#8*/
    status = pal_setHandShakeTimeOut(palTLSConf, 5000, 30000);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#9*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#10*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#11*/
    status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_UDP_REQUEST_MESSAGE, sizeof(PAL_TLS_UDP_REQUEST_MESSAGE), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#12*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#13*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#14*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#15*/
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test (D)TLS handshake (UDP) with a very short timeout to see if you get a timeout.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on server adderss.                                | PAL_SUCCESS |
* | 2 | Create a UDP socket.                                                   | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 5 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 6 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 7 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 8 | Set a short timeout for the handshake using `pal_setHandShakeTimeOut`.   | PAL_SUCCESS |
* | 9 | Perform a TLS handshake with the server using `pal_handShake` in a loop. | PAL_ERR_TIMEOUT_EXPIRED |
* | 10 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 11 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeUDPTimeOut)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_DTLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    #if (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    struct server_address server;
    int32_t temp;
    uint64_t curTimeInSec;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds

    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_DGRAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, DTLS_SERVER_PORT_TIMEOUT);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        /*#6*/
        setCredentials(palTLSConf);
    #elif (PAL_ENABLE_PSK == 1)
        /*#6 + #7*/
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif

    /*#7*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#8*/
    status = pal_setHandShakeTimeOut(palTLSConf, 50, 100);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osSetTime(minSecSinceEpoch);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); // More than current epoch time -> success

    /*#9*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    curTimeInSec = pal_osGetTime();
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_TIMEOUT_EXPIRED, status);
    TEST_ASSERT_TRUE(curTimeInSec - minSecSinceEpoch <= PAL_WAIT_TIME); //less than PAL_WAIT_TIME seconds

    /*#10*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#11*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
        TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test TLS handshake (TCP).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on the server address.                              | PAL_SUCCESS |
* | 2 | Create a TCP socket.                                                     | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 8 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 9 | Set device time to be in future.                                          | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShaket`.           | PAL_SUCCESS |
* | 11 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 12 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 13 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 14 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 15 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 16 | Close the TCP socket.                                                   | PAL_SUCCESS |
* | 17 | Check that time is updated.                                               | PAL_SUCCESS |
* | 18 | Verify that the storage time value was updated.                          | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureLWM2M)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    uint32_t written = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };

    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint64_t deviceTime = pal_osGetTime(); //get device time to update it in case of failure
    uint64_t currentTime = 0;
    size_t actualSavedTimeSize = 0;
    uint64_t initialTime = 0;
    int32_t verifyResult = 0;
    struct server_address server;
    int32_t temp;

    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#7*/
    setCredentials(palTLSConf);

    /*#8*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#9*/
    status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&initialTime, (uint16_t)sizeof(initialTime), false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_osSetTime(0);//back in the past to set time to the future during handhsake
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#10*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    if (PAL_SUCCESS != status)
    {
        pal_osSetTime(deviceTime);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#11*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#12*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);

    status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#13*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#14*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#15*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#16*/
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#17*/
    deviceTime = pal_osGetTime();
    TEST_ASSERT_NOT_EQUAL(0, deviceTime);

    /*#18*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(0 != currentTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
            TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test TLS handshake (TCP) with near future time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from storage, move backward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Update `STORAGE_RBP_SAVED_TIME_NAME` directly in storage to the new time from #1  | PAL_SUCCESS |
* | 3 | Perform a DNS lookup on the server address.                             | PAL_SUCCESS |
* | 4 | Create a TCP socket.                                                    | PAL_SUCCESS |
* | 5 | Set the server port.                                                    | PAL_SUCCESS |
* | 6 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 7 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 8 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 9 | Set the certificate and keys.| PAL_SUCCESS |
* | 10 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 11 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 12 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 13 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 14 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 15 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 16 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 17 | Verify that the time was NOT updated during the handshake.                        | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureLWM2M_NoTimeUpdate)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    uint32_t written = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t currentTime = 0;
    uint64_t tmpTime = 0;
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    int32_t verifyResult = 0;
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    //get and save valid time since the storage was cleared during TEST_SETUP
    do_handshake(PAL_TLS_MODE, false);

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    /*#1*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&tmpTime, sizeof(tmpTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    currentTime = tmpTime - (PAL_SECONDS_PER_DAY / 2); //going back half day to simulate future server by half day (in order to prevent time update)
    status = pal_osSetTime(currentTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, (uint16_t)sizeof(currentTime), false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#6*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#7*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#8*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#9*/
    setCredentials(palTLSConf);

    /*#10*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#11*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#12*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
    }

    /*#13*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#14*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#15*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#16*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#17*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX(currentTime, updatedTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
                TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}


/**
* @brief Test TLS handshake (TCP) with future time to make handshake to fail when PAL_USE_SECURE_TIME is set
*        and pass if unset, due to bad cert time from server.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 2 | Create a TCP socket.                                                       | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 8 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 9 | Setsystem time to be far in the future `pal_osSetTime`.                   | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_ERR_X509_CERT_VERIFY_FAILED OR PAL_SUCCESS |
* | 11 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_ERR_X509_BADCERT_EXPIRED |
* | 12 | Set tme back to the original time before the test.                        | PAL_SUCCESS |
* | 13 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 14 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 15 | Verify that the storage time value was not changed.                          | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_ExpiredLWM2MCert)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if (PAL_USE_INTERNAL_FLASH)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
#if PAL_USE_SECURE_TIME
    uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t currentTime = 0;
    size_t actualSavedTimeSize = 0;
#endif
    int32_t verifyResult = 0;
    struct server_address server;

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    //get and save valid time since the storage was cleared during TEST_SETUP
    do_handshake(PAL_TLS_MODE, false);

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#7*/
    setCredentials(palTLSConf);

    /*#8*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#9*/
#if PAL_USE_SECURE_TIME
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_osSetTime(futureTime);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
#else
    // Set time to future
    return_fake_time = 1;
    time_to_return = definately_in_future;
#endif

    /*#10*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

#if PAL_USE_SECURE_TIME
    if (PAL_ERR_X509_CERT_VERIFY_FAILED != status)
    {
        pal_osSetTime(currentTime);
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_CERT_VERIFY_FAILED, status);
    }
#else
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
#endif

    /*#11*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    if ((PAL_ERR_X509_CERT_VERIFY_FAILED != status) || (0 == (PAL_ERR_X509_BADCERT_EXPIRED & verifyResult)))
    {
#if PAL_USE_SECURE_TIME
        pal_osSetTime(currentTime);
#endif
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
    }

#if PAL_USE_SECURE_TIME
    /*#12*/
    status = pal_osSetTime(currentTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif

    /*#13*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#14*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_SECURE_TIME
    /*#15*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(futureTime > currentTime);
#endif
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif
}

/**
* @brief Test TLS handshake (TCP) with future time to make handshake update the device time according to the server time.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 2 | Create a TCP socket.                                                       | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 5 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 6 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 7 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 8 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 9 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 10 | Set the certificate and keys.                                             | PAL_SUCCESS |
* | 11 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 12 | Set system time to be far in the future `pal_osSetTime`.                   | PAL_SUCCESS |
* | 13 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 14 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 15 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 16 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 17 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 18 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 19 | Free X509 handle.                                                   | PAL_SUCCESS |
* | 20 | Verify that the time updated during the handshake.                        | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_ExpiredServerCert_Trusted)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;
    struct server_address server;

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#1*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#4*/
    status = pal_x509Initiate(&trustedServerCA);
    TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(trustedServerCA, (const unsigned char *)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#5*/
    status = pal_x509CertGetAttribute(trustedServerCA, PAL_X509_CERT_ID_ATTR, g_trustedServerID, sizeof(g_trustedServerID), &g_actualServerIDSize);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#6*/
    status = storage_rbp_write(STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME, (uint8_t*)g_trustedServerID, g_actualServerIDSize, false);
    if (PAL_SUCCESS != status)
    {
        status = pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#7*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }

    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#8*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#9*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#10*/
    setCredentials(palTLSConf);

    /*#11*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#12*/
    status = pal_osSetStrongTime(futureTime);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#13*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#14*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
    }

    /*#15*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_BADCERT_EXPIRED, status);
    }

    /*#16*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_BADCERT_EXPIRED, status);
    }

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#17*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#18*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#19*/
    status = pal_x509Free(&trustedServerCA);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#20*/
    updatedTime = pal_osGetTime();
    TEST_ASSERT_TRUE(updatedTime < futureTime);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(updatedTime <= futureTime);

    status = storage_rbp_read(STORAGE_RBP_LAST_TIME_BACK_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(updatedTime <= futureTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test TLS handshake (TCP) with near future time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from storage, move backward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Create a TCP socket.                                                       | PAL_SUCCESS |
* | 4 | Set the server port.                                                     | PAL_SUCCESS |
* | 5 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 6 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 7 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 8 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 9 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 10 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 11 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 12 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 13 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 14 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 15 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 16 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 17 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 18 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 19 | Free X509 Handle.                                                   | PAL_SUCCESS |
* | 20 | Verify that the time was NOT updated during the handshake.                | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureTrustedServer_NoTimeUpdate)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t currentTime = 0;
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;
    struct server_address server;

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    // Get valid time
    do_handshake(PAL_TLS_MODE, false);

    /*#1*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(0 != currentTime);

    status = pal_osSetTime(currentTime - (PAL_SECONDS_PER_DAY / 2));//going back half day to simulate future server by half day (in order to prevent time update)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#5*/
    status = pal_x509Initiate(&trustedServerCA);
    TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(trustedServerCA, (const unsigned char *)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#6*/
    status = pal_x509CertGetAttribute(trustedServerCA, PAL_X509_CERT_ID_ATTR, g_trustedServerID, sizeof(g_trustedServerID), &g_actualServerIDSize);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#7*/
    status = storage_rbp_write(STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME, (uint8_t*)g_trustedServerID, g_actualServerIDSize, false);
    if (PAL_SUCCESS != status)
    {
        status = pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#8*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }

    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#9*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#10*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#11*/
    setCredentials(palTLSConf);

    /*#12*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#13*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#14*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
    }

    /*#15*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#16*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#17*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#18*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#19*/
    status = pal_x509Free(&trustedServerCA);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#20*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX(currentTime, updatedTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif


}

/**
* @brief Test TLS handshake (TCP) with near past time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from storage, move forward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Create a TCP socket.                                                       | PAL_SUCCESS |
* | 4 | Set the server port.                                                     | PAL_SUCCESS |
* | 5 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 6 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 7 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 8 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 9 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 10 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 11 | Set the certificate and keys.                                              | PAL_SUCCESS |
* | 12 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 13 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 14 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 15 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 16 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 17 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 18 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 19 | Free X509 handle.                                                     | PAL_SUCCESS |
* | 20 | Verify that the time was NOT updated during the handshake.                | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_NearPastTrustedServer_NoTimeUpdate)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t currentTime = 0;
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    //Get valid time since the storage was cleared during TEST_SETUP
    do_handshake(PAL_TLS_MODE, false);

    /*#1*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(0 != currentTime);

    status = pal_osSetTime(currentTime + (PAL_SECONDS_PER_DAY / 2));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#5*/
    status = pal_x509Initiate(&trustedServerCA);
    TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(trustedServerCA, (const unsigned char *)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#6*/
    status = pal_x509CertGetAttribute(trustedServerCA, PAL_X509_CERT_ID_ATTR, g_trustedServerID, sizeof(g_trustedServerID), &g_actualServerIDSize);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#7*/
    status = storage_rbp_write(STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME, (uint8_t*)g_trustedServerID, g_actualServerIDSize, false);
    if (PAL_SUCCESS != status)
    {
        status = pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#8*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }

    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#9*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#10*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#11*/
    setCredentials(palTLSConf);

    /*#12*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#13*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#14*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
    }

    /*#15*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }


    /*#16*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);

    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#17*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#18*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#19*/
    status = pal_x509Free(&trustedServerCA);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#20*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX(currentTime, updatedTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

static void do_handshake(palTLSTransportMode_t mode, bool enable_session_storing)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = mode;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    #if (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);

    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    if (mode == PAL_TLS_MODE)
    {
        status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    }
    else
    {
        status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_DGRAM, true, 0, socketCallback1, &g_socket);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    if (mode == PAL_TLS_MODE)
    {
        do {
            status = pal_connect(g_socket, &socketAddr, addressLength);
            pal_osSemaphoreWait(s_semaphoreID, 100, &temp);
        } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

        if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
            status = PAL_SUCCESS;
        }
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);

    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if (PAL_USE_SSL_SESSION_RESUME == 1)
    pal_enableSslSessionStoring(palTLSConf, enable_session_storing);
#endif

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        setCredentials(palTLSConf);
    #elif (PAL_ENABLE_PSK == 1)
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif

    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while ((PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status));

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

// Introduce helper functions to be used in TCPHandshakeWhileCertVerify_threads test.
// The test is only ran if PAL_USE_SECURE_TIME and PAL_ENABLE_X509 are set so helper
// functions can also be under those checks
#if ((PAL_USE_SECURE_TIME == 1) && (PAL_ENABLE_X509 == 1))
static palStatus_t ThreadHandshakeTCP()
{
    palStatus_t status = PAL_SUCCESS;
    palStatus_t tmpStatus = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    palSocket_t socketTCP = 0;
    palTLSSocket_t tlsSocket = { socketTCP, &socketAddr, 0, transportationMode };
    palTLSTest_t *testTLSCtx = NULL;
    palStatus_t mutexStatus = PAL_SUCCESS;
    bool mutexWait = false;
    int32_t verifyResult = 0;
    struct server_address server;

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    mutexWait = true;

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &socketTCP);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = socketTCP;

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#4*/
    do {
        status = pal_connect(socketTCP, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }

    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);

    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#7*/
    setCredentials(palTLSConf);

    /*#8*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#9*/
    testTLSCtx = (palTLSTest_t*)palTLSHandle; //This casting is done to sign that we are in retry situation.
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status); // More than current epoch time -> success
    do
    {
        if (testTLSCtx->retryHandShake && !g_retryHandshake)
        {
            g_retryHandshake = true;
            if (mutexWait)
            {
                mutexStatus = pal_osMutexRelease(g_mutexHandShake1);
                TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
                mutexWait = false;
                pal_osDelay(600);
            }
        }
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        pal_osDelay(1000);
    }
    while ( (PAL_ERR_TLS_WANT_READ == status) || (PAL_ERR_TLS_WANT_WRITE == status));

    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#10*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#11*/
    do
    {
        status = pal_sslWrite(palTLSHandle, palTLSConf, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_TLS_WANT_WRITE);

    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#12*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

finish:
    if (mutexWait)
    {
        mutexStatus = pal_osMutexRelease(g_mutexHandShake1);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
    }

    /*#13*/
    tmpStatus = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG_ERR("Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }

    /*#14*/
    tmpStatus = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG_ERR("Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }

    /*#15*/
    tmpStatus = pal_close(&socketTCP);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG_ERR("Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }
    if (PAL_SUCCESS == status)
    {
        status = tmpStatus;
    }
    return status;

}

void pal_TCPHandshakeFunc3(void const *argument)
{
    palStatus_t mutexStatus = PAL_SUCCESS;
    palStatus_t* arg = (palStatus_t*)argument;

    mutexStatus = pal_osMutexWait(g_mutexHandShake1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    mutexStatus = pal_osMutexWait(g_mutex1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    *arg = ThreadHandshakeTCP();

    mutexStatus = pal_osMutexRelease(g_mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
}

void pal_CertVerify(void const *argument)
{
    palStatus_t status = PAL_SUCCESS;
    palStatus_t mutexStatus = PAL_SUCCESS;
    palStatus_t* arg = (palStatus_t*)argument;
    palX509Handle_t certHandle = NULLPTR;
    int32_t verifyResult = 0;

    mutexStatus = pal_osMutexWait(g_mutexHandShake1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    status = pal_osMutexWait(g_mutex2, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509Initiate(&certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(certHandle, (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    PAL_LOG_INFO("Calling Cert Verify..");
    *arg = pal_x509CertVerifyExtended(certHandle, certHandle, &verifyResult);
    TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_FUTURE & verifyResult);

    pal_x509Free(&certHandle);

    mutexStatus = pal_osMutexRelease(g_mutexHandShake1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    mutexStatus = pal_osMutexRelease(g_mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
}

static void runTLSThreadTest(palThreadFuncPtr func1, palThreadFuncPtr func2, palStatus_t test1Result, palStatus_t test2Result)
{
    palStatus_t status = PAL_SUCCESS;
    palThreadID_t threadID1 = NULLPTR;
    palThreadID_t threadID2 = NULLPTR;
    palStatus_t tlsArgs1 = PAL_SUCCESS;
    palStatus_t tlsArgs2 = PAL_SUCCESS;

    status = pal_osMutexCreate(&g_mutexHandShake1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexCreate(&g_mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexCreate(&g_mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexWait(g_mutexHandShake1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osThreadCreateWithAlloc(func1, &tlsArgs1, PAL_osPriorityHigh, 5*PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexRelease(g_mutexHandShake1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    pal_osDelay(100);

    status = pal_osThreadCreateWithAlloc(func2, &tlsArgs2, PAL_osPriorityAboveNormal, 5*PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexWait(g_mutex1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexWait(g_mutex2, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osThreadTerminate(&threadID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osThreadTerminate(&threadID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexRelease(g_mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexRelease(g_mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexDelete(&g_mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexDelete(&g_mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osMutexDelete(&g_mutexHandShake1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    TEST_ASSERT_EQUAL_HEX(test1Result, tlsArgs1);
    TEST_ASSERT_EQUAL_HEX(test2Result, tlsArgs2);
}
#endif


/**
* @brief Test try to process certificate verification with future certificate validation time while processing handshake
*        in another thread to update the device time, we need to check that certificate verification is done against the
*        broken device time (0) and after handshake is done, we need to re-verify against the fixed time according to the
*        server time sent by the server during handshake.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create Thread1 to process DTLS handshake                | PAL_SUCCESS |
* | 1 | Create Thread2 to process TLS handshake                 | PAL_ERR_X509_CERT_VERIFY_FAILED |
*/
TEST(pal_tls, TCPHandshakeWhileCertVerify_threads)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_ENABLE_X509 == 1))
    palStatus_t status = PAL_SUCCESS;
    palX509Handle_t certHandle = NULLPTR;
    uint64_t systemTime = 0;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);

    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osSetTime(0);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    runTLSThreadTest(pal_TCPHandshakeFunc3, pal_CertVerify, PAL_SUCCESS, PAL_ERR_X509_CERT_VERIFY_FAILED);

    systemTime = pal_osGetTime();
    TEST_ASSERT_TRUE(0 < systemTime);

    status = pal_x509Initiate(&certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(certHandle, (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertVerify(certHandle, certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509Free(&certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_ENABLE_X509 not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test SSL Session Resume (TCP)
*/
TEST(pal_tls, tlsHandshake_SessionResume)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    if (MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI == NULL || MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY == NULL ||
            MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE == NULL || MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE  == NULL) {
        TEST_IGNORE_MESSAGE("Ignored, no credentials from mbed_cloud_dev_credentials.c");
    }

#if (PAL_USE_SSL_SESSION_RESUME == 1)

    // Check that session is not stored into file system since feature is disabled by default.
    do_handshake(PAL_DTLS_MODE, false);
    TEST_ASSERT(!isSslSessionAvailable());

    // Handshake again, session should be now stored into file system.
    do_handshake(PAL_DTLS_MODE, true);
    pal_store_cid();
    TEST_ASSERT(isSslSessionAvailable());

    // This time handshake will use the saved session.
    // Currently can be verified only through mbedtls logs.
    do_handshake(PAL_DTLS_MODE, true);
    TEST_ASSERT(isSslSessionAvailable());

    // Remove CID
    pal_remove_cid();

    // TLS tests, clear old session first
    removeSslSession();
    TEST_ASSERT(!isSslSessionAvailable());
    do_handshake(PAL_TLS_MODE, true);
    TEST_ASSERT(isSslSessionAvailable());

    // This time handshake will use the saved session.
    // Currently can be verified only through mbedtls logs.
    do_handshake(PAL_TLS_MODE, true);
    TEST_ASSERT(isSslSessionAvailable());

#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SSL_SESSION_RESUME not set");
#endif // PAL_USE_SSL_SESSION_RESUME

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

/**
* @brief Test TLS handshake (TCP) to make sure client handles multiple error messages from certificate verification.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 2 | Create a TCP socket.                                                       | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 5 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 6 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 7 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 8 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 9 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 10 | Set the certificate and keys. set CA cert so that it will not be valid.   | PAL_SUCCESS |
* | 11 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 12 | Set system time to be far in the future `pal_osSetTime`.                   | PAL_SUCCESS |
* | 13 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_ERR_X509_CERT_VERIFY_FAILED |
* | 14 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 15 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 16 | Free X509 handle.                                                   | PAL_SUCCESS |
*/
// this is copy-paste of palTLSService_t from pal_TLS.c. It's not meant to be used outside PAL but
// since this test needs to mimic malicious server returning a certificate which is wrong in two
// ways and also returning non-valid 'secure time' in the ServerHello message we need to modify
// it during the test.
typedef struct tls_ctx
{
    bool retryHandShake;
    uint64_t serverTime;
    uintptr_t platTlsHandle;
}tls_ctx_t;

TEST(pal_tls, tlsHandshakeTCP_ExpiredServerCert_UnTrusted)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#if (PAL_USE_INTERNAL_FLASH)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    struct server_address server;

    int32_t temp;
    status = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, status);

    /*#1*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS);
    status = doDnsQuery(server.hostname, &socketAddr, &addressLength);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("DNS query error for %s", PAL_TLS_TEST_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_asynchronousSocket(socketAddr.addressType, PAL_SOCK_STREAM, true, 0, socketCallback1, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#4*/
    status = pal_x509Initiate(&trustedServerCA);
    TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(trustedServerCA, (const unsigned char *)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#5*/
    status = pal_x509CertGetAttribute(trustedServerCA, PAL_X509_CERT_ID_ATTR, g_trustedServerID, sizeof(g_trustedServerID), &g_actualServerIDSize);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#6*/
    status = storage_rbp_write(STORAGE_RBP_TRUSTED_TIME_SRV_ID_NAME, (uint8_t*)g_trustedServerID, g_actualServerIDSize, false);
    if (PAL_SUCCESS != status)
    {
        status = pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#7*/
    do {
        status = pal_connect(g_socket, &socketAddr, addressLength);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    } while (status == PAL_ERR_SOCKET_IN_PROGRES || status == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        status = PAL_SUCCESS;
    }

    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#8*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#9*/
    status = pal_initTLS(palTLSConf, &palTLSHandle, false);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#10*/
    setCredentialsWrongCA(palTLSConf);

    /*#11*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#12*/
    status = pal_osSetStrongTime(futureTime);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#13*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf, false);
        tls_ctx_t* tls_ctx = (tls_ctx_t*)palTLSHandle;
        if (tls_ctx->retryHandShake) {
            // server should really fail before logic goes to renegotiation...
            // ..but this hack ensures we get server's cert to appear from future
            // if it happens to still continue there
            tls_ctx->serverTime = 50;
        }
        pal_osSemaphoreWait(s_semaphoreID, 1000, &temp);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    if (PAL_ERR_X509_CERT_VERIFY_FAILED != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_CERT_VERIFY_FAILED, status);
    }

    /*#14*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#15*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != status)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#16*/
    status = pal_x509Free(&trustedServerCA);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(updatedTime <= futureTime);

    status = storage_rbp_read(STORAGE_RBP_LAST_TIME_BACK_NAME, (uint8_t*)&updatedTime, sizeof(updatedTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(updatedTime <= futureTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_INTERNAL_FLASH not set");
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is defined");
#endif

}

static void setCredentials(palTLSConfHandle_t handle)
{
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };

    palStatus_t status;
    palPrivateKey_t prvKey;
    status = pal_initPrivateKey((const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_setOwnCertChain(handle, &pubKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_setOwnPrivateKey(handle, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_setCAChain(handle, &caCert, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

static void setCredentialsWrongCA(palTLSConfHandle_t handle)
{
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE };

    palStatus_t status;
    palPrivateKey_t prvKey;
    status = pal_initPrivateKey((const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_setOwnCertChain(handle, &pubKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_setOwnPrivateKey(handle, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_setCAChain(handle, &caCert, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

#if (PAL_USE_SSL_SESSION_RESUME == 1)
static bool isSslSessionAvailable()
{
    size_t act_size = 0;
    kcm_status_e kcm_status = kcm_init();
    if (kcm_status != KCM_STATUS_SUCCESS)
    {
        return false;
    }

    kcm_status = kcm_item_get_data_size((uint8_t *)ssl_session_item_name,
                                   strlen(ssl_session_item_name),
                                   KCM_CONFIG_ITEM, &act_size);

    if (kcm_status == KCM_STATUS_SUCCESS)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static void removeSslSession()
{
    kcm_status_e kcm_status = kcm_init();
    if (kcm_status != KCM_STATUS_SUCCESS)
    {
        return;
    }
    else
    {
        kcm_item_delete((uint8_t *)ssl_session_item_name,
                        strlen(ssl_session_item_name),
                        KCM_CONFIG_ITEM);
    }
}
#endif //PAL_USE_SSL_SESSION_RESUME

