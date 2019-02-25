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
#include "pal_tls_utils.h"
#include "pal_network.h"
#include "storage.h"
#include "test_runners.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal_sst.h"
#else
#include "sotp.h"
#endif

#include <stdlib.h>

#define TRACE_GROUP "PAL"
#define PAL_TEST_PSK_IDENTITY "Client_identity"

#define PAL_TEST_PSK {0x12,0x34,0x45,0x67,0x89,0x10}
#define PAL_WAIT_TIME	3

#define HOSTNAME_STR_MAX_LEN 256

PAL_PRIVATE palSocket_t g_socket = 0;
extern void * g_palTestTLSInterfaceCTX; // this is set by the palTestMain funciton
PAL_PRIVATE uint32_t g_interfaceCTXIndex = 0;

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    PAL_PRIVATE uint8_t g_trustedServerID[PAL_CERT_ID_SIZE] __attribute__((aligned(4))) = { 0 };
    PAL_PRIVATE size_t g_actualServerIDSize = 0;
#endif 

PAL_PRIVATE palMutexID_t g_mutex1 = NULLPTR;
#if (PAL_ENABLE_X509 == 1)
	PAL_PRIVATE palMutexID_t g_mutex2 = NULLPTR;
#endif
PAL_PRIVATE palMutexID_t g_mutexHandShake1 = NULLPTR;
PAL_PRIVATE bool g_retryHandshake = false;

#define PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(a, b) \
    if (a != b) \
    {\
        PAL_LOG_ERR("Expected: %" PRId32 " , Actual: %" PRId32 " , Line: %d\n", (int32_t)a, (int32_t)b, __LINE__);\
        goto finish;\
    }


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
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    // Reset storage before pal_initTime since there might be CMAC lefovers
    // in internal flash which might fail storage access in pal_initTime
    pal_SSTReset();
#else 
    sotp_reset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    // Initialize the time module, as this test uses time functionality
    status = pal_initTime();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // Initialize the time module
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

}

TEST_TEAR_DOWN(pal_tls)
{
    palStatus_t status = PAL_SUCCESS;
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
    palTLSTransportMode_t transportationMode =     PAL_TLS_MODE;
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

static void handshakeUDP(bool socketNonBlocking)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_DTLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    #if (PAL_ENABLE_X509 == 1)
        palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE,MAX_CERTIFICATE_SIZE};
        palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY,MAX_CERTIFICATE_SIZE};
        palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA,MAX_CERTIFICATE_SIZE};
    #elif (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = {g_socket, &socketAddr, 0, transportationMode};
    int32_t verifyResult = 0;
    struct server_address server;

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_DGRAM, socketNonBlocking, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_UDP);

    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
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
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        /*#6*/
        status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#7*/
        status = pal_setCAChain(palTLSConf, &caCert, NULL);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #elif (PAL_ENABLE_PSK == 1)
        /*#6 + #7*/
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif
    /*#8*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#9*/

	status = pal_setHandShakeTimeOut(palTLSConf, 30000);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#10*/

    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#11*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#12*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_UDP_REQUEST_MESSAGE, sizeof(PAL_TLS_UDP_REQUEST_MESSAGE), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
    }while (PAL_ERR_TLS_WANT_READ == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#15*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#16*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#17*/
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}


static void handshakeTCP(bool socketNonBlocking)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    #if (PAL_ENABLE_X509 == 1)
        palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
        palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
        palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    #elif (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };    
    uint64_t curTimeInSec, timePassedInSec;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds
    int32_t verifyResult = 0;
    struct server_address server;

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, socketNonBlocking, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);

    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);

    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_connect(g_socket, &socketAddr, addressLength);
    if (PAL_ERR_SOCKET_IN_PROGRES == status)
    {
        pal_osDelay(400);
    }
    else
    {
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);
    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        /*#7*/    
        status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#8*/
        status = pal_setCAChain(palTLSConf, &caCert, NULL);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #elif (PAL_ENABLE_PSK == 1)
        /*#7 + 8*/
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif
    /*#9*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#10*/
    if (true == socketNonBlocking)
    {
        status = pal_osSetTime(minSecSinceEpoch);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); // More than current epoch time -> success
        do
        {
            curTimeInSec = pal_osGetTime();
            TEST_ASSERT_TRUE(curTimeInSec >= minSecSinceEpoch);        
            timePassedInSec = curTimeInSec - minSecSinceEpoch;
            status = pal_handShake(palTLSHandle, palTLSConf);
        }
        while ( (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status) &&
                (timePassedInSec < PAL_SECONDS_PER_MIN)); //2 minutes to wait for handshake
    }
    else //blocking
    {
        status = pal_handShake(palTLSHandle, palTLSConf);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#11*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#12*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#ifdef PAL_TLS_RESPONSE_MESSAGE
    TEST_ASSERT_EQUAL(PAL_TLS_RESPONSE_SIZE, actualLen);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(PAL_TLS_RESPONSE_MESSAGE, serverResponse, PAL_TLS_RESPONSE_SIZE);
#endif

    /*#15*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#16*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#17*/
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

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
    status = pal_initTLS(palTLSConf, &palTLSHandle);
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
* | 2 | Add keys to the configuration using `pal_setOwnCertAndPrivateKey`.           | PAL_SUCCESS |
* | 3 | Initialize TLS context using `pal_initTLS`.                          | PAL_SUCCESS |
* | 4 | Uninitialize TLS context using `pal_freeTLS`.                        | PAL_SUCCESS |
* | 5 | Uninitialize TLS configuration using `pal_tlsConfigurationFree`.     | PAL_SUCCESS |
*/
TEST(pal_tls, tlsPrivateAndPublicKeys)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};

    /*#1*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
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
    status = pal_initTLS(palTLSConf, &palTLSHandle);
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
* @brief Test TLS handshake (TCP blocking).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 8 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 9 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShaket`.           | PAL_SUCCESS |
* | 11 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 12 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 13 | Wait for the response.                                                  | PAL_SUCCESS |
* | 14 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 15 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 16 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 17 | Close the TCP socket.                                                   | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
    handshakeTCP(false);
}

/**
* @brief Test TLS handshake (TCP non-blocking).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a TCP (non-blocking) socket.                                    | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 8 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 9 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShaket` in a loop. | PAL_SUCCESS |
* | 11 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 12 | Write data over the open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 13 | Wait for the response.                                                  | PAL_SUCCESS |
* | 14 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 15 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 16 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 17 | Close the TCP socket.                                                   | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_nonBlocking)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
    handshakeTCP(true);
}

/**
* @brief Test (D)TLS handshake (UDP -blocking).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a UDP (blocking) socket.                                        | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 5 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 6 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 7 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 8 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 9 | Set the timeout for the handshake using `pal_setHandShakeTimeOut`.         | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShaket` in a loop. | PAL_SUCCESS |
* | 11 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 12 | Write data over the open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 13 | Wait for the response.                                                  | PAL_SUCCESS |
* | 14 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 15 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 16 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 17 | Close the UDP socket.                                                   | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeUDP)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
    handshakeUDP(false);
}

/**
* @brief Test (D)TLS handshake (UDP -NonBlocking).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a UDP (blocking) socket.                                        | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 5 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 6 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 7 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 8 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 9 | Set the timeout for the handshake using `pal_setHandShakeTimeOut`.         | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShaket` in a loop. | PAL_SUCCESS |
* | 11 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 12 | Write data over the open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 13 | Wait for the response.                                                  | PAL_SUCCESS |
* | 14 | Read data from the open TLS connection using `pal_sslRead`.               | PAL_SUCCESS |
* | 15 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 16 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 17 | Close the UDP socket.                                                   | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeUDP_NonBlocking)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
    handshakeUDP(true);
}

/**
* @brief Test (D)TLS handshake (UDP non-blocking) with a very short timeout to see if you get a timeout.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a UDP (blocking) socket.                                        | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on server adderss.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 5 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 6 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 7 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 8 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 9 | Set a short timeout for the handshake using `pal_setHandShakeTimeOut`.   | PAL_SUCCESS |
* | 10 | Perform a TLS handshake with the server using `pal_handShaket` in a loop. | PAL_ERR_TIMEOUT_EXPIRED |
* | 11 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 12 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeUDPTimeOut)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_DTLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    #if (PAL_ENABLE_X509 == 1)
        palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
        palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
        palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    #elif (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif 
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    struct server_address server;
    
    uint64_t curTimeInSec;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds      
    
    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_DGRAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_UDP);
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
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
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #if (PAL_ENABLE_X509 == 1)
        /*#6*/
        status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#7*/
        status = pal_setCAChain(palTLSConf, &caCert, NULL);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #elif (PAL_ENABLE_PSK == 1)
        /*#6 + #7*/
        status = pal_setPSK(palTLSConf, (const unsigned char*)identity, strlen(identity), (const unsigned char*)psk, sizeof(psk));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif
    /*#8*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#9*/
    status = pal_setHandShakeTimeOut(palTLSConf, 100);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osSetTime(minSecSinceEpoch);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); // More than current epoch time -> success    
    /*#10*/
    do
    {
        status = pal_handShake(palTLSHandle, palTLSConf);
    }
    while (PAL_ERR_TLS_WANT_READ == status || PAL_ERR_TLS_WANT_WRITE == status);

    curTimeInSec = pal_osGetTime();
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_TIMEOUT_EXPIRED, status);
    TEST_ASSERT_TRUE(curTimeInSec - minSecSinceEpoch <= PAL_WAIT_TIME); //less than PAL_WAIT_TIME seconds
    /*#11*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#12*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

/**
* @brief Test TLS handshake (TCP blocking).
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a TCP (blocking) socket.                                          | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                              | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 8 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 9 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 10 | Set device time to be in future.                                          | PAL_SUCCESS |
* | 11 | Perform a TLS handshake with the server using `pal_handShaket`.           | PAL_SUCCESS |
* | 12 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 13 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 14 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 15 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 16 | Close the TCP socket.                                                   | PAL_SUCCESS |
* | 17 | Check that time is updated.                                               | PAL_SUCCESS |
* | 18 | Verify that the storage time value was updated.                          | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureLWM2M)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    uint32_t written = 0;
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    
    char serverResponse[PAL_TLS_RESPONSE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint64_t deviceTime = pal_osGetTime(); //get device time to update it in case of failure
	uint64_t currentTime = 0;
    size_t actualSavedTimeSize = 0;
    uint64_t initialTime = 0;
    int32_t verifyResult = 0;
    struct server_address server;

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_connect(g_socket, &socketAddr, addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#7*/
    status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#8*/
    status = pal_setCAChain(palTLSConf, &caCert, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); 
    /*#9*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#10*/

    status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&initialTime, (uint16_t)sizeof(initialTime), false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_osSetTime(0);//back in the past to set time to the future during handhsake
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#11*/
    status = pal_handShake(palTLSHandle, palTLSConf);
    if (PAL_SUCCESS != status)
    {
        pal_osSetTime(deviceTime);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#12*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
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
}

/**
* @brief Test TLS handshake (TCP blocking) with near future time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from storage, move backward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Update `STORAGE_RBP_SAVED_TIME_NAME` directly in storage to the new time from #1  | PAL_SUCCESS |
* | 3 | Create a TCP (blocking) socket.                                         | PAL_SUCCESS |
* | 4 | Perform a DNS lookup on the server address.                             | PAL_SUCCESS |
* | 5 | Set the server port.                                                    | PAL_SUCCESS |
* | 6 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 7 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 8 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 9 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 10 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 11 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 12 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 13 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 14 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 15 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 16 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 17 | Verify that the time was NOT updated during the handshake.                        | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureLWM2M_NoTimeUpdate)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
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
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t currentTime = 0;
    uint64_t tmpTime = 0;
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    int32_t verifyResult = 0;
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);

    //save valid time since the storage was cleared during TEST_SETUP
    uint64_t valid_time = PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100;
    status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&valid_time, sizeof(uint64_t), false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    
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
	status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	tlsSocket.addressLength = addressLength;
	tlsSocket.socket = g_socket;
    
	/*#6*/
	status = pal_connect(g_socket, &socketAddr, addressLength);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#7*/
	status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#8*/
	status = pal_initTLS(palTLSConf, &palTLSHandle);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

	/*#9*/
	status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#10*/
	status = pal_setCAChain(palTLSConf, &caCert, NULL);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#11*/
	status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#12*/
	status = pal_handShake(palTLSHandle, palTLSConf);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#13*/
	status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
	}
    /*#14*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
    if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

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
}


/**
* @brief Test TLS handshake (TCP blocking) with future time to make handshake to fail due to bad cert time from server.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 5 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 6 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 7 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 8 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 9 | Set the socket chain to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 10 | Setsystem time to be far in the future `pal_osSetTime`.                   | PAL_SUCCESS |
* | 11 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_ERR_X509_CERT_VERIFY_FAILED |
* | 12 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_ERR_X509_BADCERT_EXPIRED |
* | 13 | Set tme back to the original time before the test.                        | PAL_SUCCESS |
* | 14 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 15 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 16 | Verify that the storage time value was not changed.                          | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_ExpiredLWM2MCert)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t currentTime = 0;
    size_t actualSavedTimeSize = 0;
    int32_t verifyResult = 0;
    struct server_address server;

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);

    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_connect(g_socket, &socketAddr, addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    
    /*#7*/
    status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#8*/
    status = pal_setCAChain(palTLSConf, &caCert, NULL);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#9*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#10*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_osSetTime(futureTime);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#11*/
    status = pal_handShake(palTLSHandle, palTLSConf);
    if (PAL_ERR_X509_CERT_VERIFY_FAILED != status)
    {
        pal_osSetTime(currentTime);
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_CERT_VERIFY_FAILED, status);
    }
    /*#12*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    if ((PAL_ERR_X509_CERT_VERIFY_FAILED != status) || (0 == (PAL_ERR_X509_BADCERT_EXPIRED & verifyResult)))
    {
        pal_osSetTime(currentTime);
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
    }
    /*#13*/
    status = pal_osSetTime(currentTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#14*/
    status = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_tlsConfigurationFree(&palTLSConf);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#15*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#16*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	TEST_ASSERT_TRUE(futureTime <= currentTime);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_USE_SECURE_TIME or PAL_USE_INTERNAL_FLASH not set");
#endif
}

/**
* @brief Test TLS handshake (TCP blocking) with future time to make handshake update the device time according to the server time.
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 2 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 3 | Set the server port.                                                     | PAL_SUCCESS |
* | 4 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 5 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 6 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 7 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 8 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 9 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 10 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 11 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 12 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 13 | Set system time to be far in the future `pal_osSetTime`.                   | PAL_SUCCESS |
* | 14 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 15 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 16 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 17 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 18 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 19 | Free X509 handle.                                                   | PAL_SUCCESS |
* | 20 | Verify that the time updated during the handshake.                        | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_ExpiredServerCert_Trusted)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
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
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
	palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
	uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
	palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;
    struct server_address server;

	/*#1*/
	status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
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
	status = pal_connect(g_socket, &socketAddr, addressLength);
	if (PAL_SUCCESS != status)
	{
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#8*/
	status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#9*/
	status = pal_initTLS(palTLSConf, &palTLSHandle);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

	/*#10*/
	status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#11*/
	status = pal_setCAChain(palTLSConf, &caCert, NULL);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
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
	status = pal_osSetStrongTime(futureTime);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#14*/
	status = pal_handShake(palTLSHandle, palTLSConf);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#15*/
	status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
	}
    /*#16*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_BADCERT_EXPIRED, status);
	}

    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
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
}

/**
* @brief Test TLS handshake (TCP blocking) with near future time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from storage, move backward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 3 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 4 | Set the server port.                                                     | PAL_SUCCESS |
* | 5 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 6 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 7 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 8 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 9 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 10 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 11 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 12 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 13 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 14 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 15 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 16 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 17 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 18 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 19 | Free X509 Handle.                                                   | PAL_SUCCESS |
* | 20 | Verify that the time was NOT updated during the handshake.                | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureTrustedServer_NoTimeUpdate)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
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
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
	palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
	uint64_t currentTime = 0;
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;
    struct server_address server;

    //save valid time since the storage was cleared during TEST_SETUP
    uint64_t valid_time = PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100;
    status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&valid_time, sizeof(uint64_t), false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);


    /*#1*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(0 != currentTime);

    status = pal_osSetTime(currentTime - (PAL_SECONDS_PER_DAY / 2));//going back half day to simulate future server by half day (in order to prevent time update)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#2*/
	status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
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
	status = pal_connect(g_socket, &socketAddr, addressLength);
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
	status = pal_initTLS(palTLSConf, &palTLSHandle);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

	/*#11*/
	status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#12*/
	status = pal_setCAChain(palTLSConf, &caCert, NULL);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#13*/
	status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#14*/
	status = pal_handShake(palTLSHandle, palTLSConf);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#15*/
	status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
	}
    /*#16*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
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
}

/**
* @brief Test TLS handshake (TCP blocking) with near past time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from storage, move forward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 3 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 4 | Set the server port.                                                     | PAL_SUCCESS |
* | 5 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 6 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 7 | Set the CA cert ID into the storage.                                            | PAL_SUCCESS |
* | 8 | Connect the TCP socket to the server.                                        | PAL_SUCCESS |
* | 9 | Initialize the TLS configuration using `pal_initTLSConfiguration`.         | PAL_SUCCESS |
* | 10 | Initialize the TLS context using `pal_initTLS`.                            | PAL_SUCCESS |
* | 11 | Set the certificate and keys to the configuration using `pal_setOwnCertAndPrivateKey`.| PAL_SUCCESS |
* | 12 | Set the certificate chain to the configuration using `pal_setCAChain`.        | PAL_SUCCESS |
* | 13 | Set the socket to the configuration using `pal_tlsSetSocket`.           | PAL_SUCCESS |
* | 14 | Perform a TLS handshake with the server using `pal_handShake`.           | PAL_SUCCESS |
* | 15 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 16 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 17 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 18 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 19 | Free X509 handle.                                                     | PAL_SUCCESS |
* | 20 | Verify that the time was NOT updated during the handshake.                | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_NearPastTrustedServer_NoTimeUpdate)
{
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
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
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    uint64_t currentTime = 0;
    uint64_t updatedTime = 0;
    size_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);

    //save valid time since the storage was cleared during TEST_SETUP
    uint64_t valid_time = PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100;
    status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&valid_time, sizeof(uint64_t), false);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#1*/
    status = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t*)&currentTime, sizeof(currentTime), &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(0 != currentTime);

    status = pal_osSetTime(currentTime + (PAL_SECONDS_PER_DAY / 2));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        status = pal_close(&g_socket);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        return;
    }
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
    status = pal_connect(g_socket, &socketAddr, addressLength);
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
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    /*#11*/
    status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#12*/
    status = pal_setCAChain(palTLSConf, &caCert, NULL);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#13*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#14*/
    status = pal_handShake(palTLSHandle, palTLSConf);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	/*#15*/
	status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
		TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_EXPIRED & verifyResult);
	}
    /*#16*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
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
}

// Introduce helper functions to be used in TCPHandshakeWhileCertVerify_threads test.
// The test is only ran if PAL_USE_SECURE_TIME and PAL_ENABLE_X509 are set so helper
// functions can also be under those checks
#if ((PAL_USE_SECURE_TIME == 1) && (PAL_ENABLE_X509 == 1))
static palStatus_t ThreadHandshakeTCP(bool socketNonBlocking)
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
    palX509_t pubKey = {(const void*)PAL_TLS_TEST_DEVICE_CERTIFICATE, MAX_CERTIFICATE_SIZE};
    palPrivateKey_t prvKey = {(const void*)PAL_TLS_TEST_DEVICE_PRIVATE_KEY, MAX_CERTIFICATE_SIZE};
    palX509_t caCert = { (const void*)PAL_TLS_TEST_SERVER_CA, MAX_CERTIFICATE_SIZE };
    palTLSSocket_t tlsSocket = { socketTCP, &socketAddr, 0, transportationMode };
    palTLSTest_t *testTLSCtx = NULL;
    palStatus_t mutexStatus = PAL_SUCCESS;
    bool mutexWait = false;
    int32_t verifyResult = 0;
    struct server_address server;

	mutexWait = true;
    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, socketNonBlocking, 0, &socketTCP);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#2*/
    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);
    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = socketTCP;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, server.port);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#4*/
    status = pal_connect(socketTCP, &socketAddr, addressLength);
    if (PAL_ERR_SOCKET_IN_PROGRES == status)
    {
        pal_osDelay(500);
    }
    else
    {
        PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    }
    /*#5*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(palTLSConf, NULLPTR);
    /*#6*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslSetDebugging(palTLSConf, true);
    //TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#7*/
    status = pal_setOwnCertAndPrivateKey(palTLSConf, &pubKey, &prvKey);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#8*/
    status = pal_setCAChain(palTLSConf, &caCert, NULL);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#9*/
    status = pal_tlsSetSocket(palTLSConf, &tlsSocket);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#10*/
    testTLSCtx = (palTLSTest_t*)palTLSHandle; //This casting is done to sign that we are in retry situation.
    if (true == socketNonBlocking)
    {
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
            status = pal_handShake(palTLSHandle, palTLSConf);
        }
        while ( (PAL_ERR_TLS_WANT_READ == status) || (PAL_ERR_TLS_WANT_WRITE == status));
    }
    else //blocking
    {
        status = pal_handShake(palTLSHandle, palTLSConf);
    }
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    /*#11*/
    status = pal_sslGetVerifyResultExtended(palTLSHandle, &verifyResult);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#12*/
    status = pal_sslWrite(palTLSHandle, PAL_TLS_REQUEST_MESSAGE, sizeof(PAL_TLS_REQUEST_MESSAGE), &written);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#13*/
    pal_osDelay(PAL_TLS_RESPONSE_WAIT_MS);

    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_RESPONSE_SIZE, &actualLen);
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
    /*#15*/
    tmpStatus = pal_freeTLS(&palTLSHandle);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG_ERR("Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }
    /*#16*/
    tmpStatus = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG_ERR("Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }
    /*#17*/
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

    *arg = ThreadHandshakeTCP(true);

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
    TEST_IGNORE_MESSAGE("Ignored, Linux PAL tests don't get credentials from mbed_cloud_dev_credentials.c");
#if ((PAL_USE_SECURE_TIME == 1) && (PAL_ENABLE_X509 == 1))
    palStatus_t status = PAL_SUCCESS;
    palX509Handle_t certHandle = NULLPTR;
    uint64_t systemTime = 0;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    struct server_address server;

    parseServerAddress(&server, PAL_TLS_TEST_SERVER_ADDRESS_TCP);

    status = pal_getAddressInfo(server.hostname, &socketAddr, &addressLength);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration or error)");
        return;
    }

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
}








