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
#include "stdlib.h"
#include "sotp.h"
#include "test_runners.h"

#define TRACE_GROUP "TLS_TESTS"
#define PAL_TEST_PSK_IDENTITY "Client_identity"

#define PAL_TEST_PSK {0x12,0x34,0x45,0x67,0x89,0x10}


PAL_PRIVATE palSocket_t g_socket = 0;
extern void * g_palTestTLSInterfaceCTX; // this is set by the palTestMain funciton
PAL_PRIVATE uint32_t g_interfaceCTXIndex = 0;

#if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    PAL_PRIVATE uint8_t g_trustedServerID[PAL_CERT_ID_SIZE] __attribute__((aligned(4))) = { 0 };
    PAL_PRIVATE size_t g_actualServerIDSize = 0;
#endif 

PAL_PRIVATE palMutexID_t g_mutex1 = NULLPTR;
PAL_PRIVATE palMutexID_t g_mutex2 = NULLPTR;
PAL_PRIVATE palMutexID_t g_mutexHandShake1 = NULLPTR;
PAL_PRIVATE bool g_retryHandshake = false;
PAL_PRIVATE const uint8_t g_coapHelloWorldRequest[16] = { 0x50,0x01,0x57,0x3e,0xff,0x2f,0x68,0x65,0x6c,0x6c,0x6f,0x57,0x6f,0x72,0x6c,0x64 };

#define PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(a, b) \
    if (a != b) \
    {\
        PAL_LOG(ERR,"Expected: %" PRId32 " , Actual: %" PRId32 " , Line: %d\n", (int32_t)a, (int32_t)b, __LINE__);\
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
    uint64_t currentTime = 1504893346; //GMT: Friday, September 8, 2017 5:55:46 PM

    pal_init();

    if (g_palTestTLSInterfaceCTX == NULL)
    {
        PAL_LOG(ERR, "error: net interface not configutred correctly");
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
    sotp_result_e sotpRes = SOTP_SUCCESS;
    if (0 != g_socket)
    {
        pal_close(&g_socket);
    }

	sotpRes = sotp_delete(SOTP_TYPE_TRUSTED_TIME_SRV_ID);
	TEST_ASSERT_TRUE((SOTP_SUCCESS == sotpRes) || (SOTP_NOT_FOUND == sotpRes));
    
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

static void handshakeUDP(bool socketNonBlocking)
{
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_DTLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    #if (PAL_ENABLE_X509 == 1)
        palX509_t pubKey = {(const void*)g_pubKey,sizeof(g_pubKey)};
        palPrivateKey_t prvKey = {(const void*)g_prvKey,sizeof(g_prvKey)};
        palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    #elif (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = {g_socket, &socketAddr, 0, transportationMode};
    int32_t verifyResult = 0;

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_DGRAM, socketNonBlocking, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, DTLS_SERVER_PORT);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // This code commented out to prevent massive prints from mbedTLS, if you want to see logs from client side, just uncomment them.
    //status = pal_sslDebugging(true);
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
	status = pal_sslWrite(palTLSHandle, g_coapHelloWorldRequest, sizeof(g_coapHelloWorldRequest), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    pal_osDelay(5000);
    /*#14*/
    do
    {
        status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
    }while (PAL_ERR_TLS_WANT_READ == status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

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
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    #if (PAL_ENABLE_X509 == 1)
        palX509_t pubKey = {(const void*)g_pubKey,sizeof(g_pubKey)};
        palPrivateKey_t prvKey = {(const void*)g_prvKey,sizeof(g_prvKey)};
        palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    #elif (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };    
    uint64_t curTimeInSec, timePassedInSec;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds
    int32_t verifyResult = 0;
    

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, socketNonBlocking, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    if (true == socketNonBlocking)
    {
        status = pal_setSockAddrPort(&socketAddr, TLS_SERVER_PORT_NB);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    else //blocking
    {
        status = pal_setSockAddrPort(&socketAddr, TLS_SERVER_PORT);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

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
    //status = pal_sslDebugging(true);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    pal_osDelay(5000);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

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
    palX509_t pubKey = { (const void*)g_pubKey,sizeof(g_pubKey) };
    palPrivateKey_t prvKey = { (const void*)g_prvKey,sizeof(g_prvKey) };

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
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_DTLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    #if (PAL_ENABLE_X509 == 1)
        palX509_t pubKey = { (const void*)g_pubKey,sizeof(g_pubKey) };
        palPrivateKey_t prvKey = { (const void*)g_prvKey,sizeof(g_prvKey) };
        palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    #elif (PAL_ENABLE_PSK == 1)
        const char* identity = PAL_TEST_PSK_IDENTITY;
        const char psk[]= PAL_TEST_PSK;
    #endif 
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    
    uint64_t curTimeInSec;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds      
    
    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_DGRAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
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
    //status = pal_sslDebugging(true);
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
    TEST_ASSERT_TRUE(curTimeInSec - minSecSinceEpoch <= 1); //less than one second             
    /*#11*/
    status = pal_freeTLS(&palTLSHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#12*/
    status = pal_tlsConfigurationFree(&palTLSConf);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_close(&g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

#if PAL_USE_INTERNAL_FLASH
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
* | 10 | Set device time to be in future.                                          | PAL_SUCCESS |
* | 11 | Perform a TLS handshake with the server using `pal_handShaket`.           | PAL_SUCCESS |
* | 12 | Verify the handshake result using `pal_sslGetVerifyResult`.               | PAL_SUCCESS |
* | 13 | Write data over open TLS connection using `pal_sslWrite`.            | PAL_SUCCESS |
* | 14 | Uninitialize the TLS context using `pal_freeTLS`.                         | PAL_SUCCESS |
* | 15 | Uninitialize the TLS configuration using `pal_tlsConfigurationFree`.      | PAL_SUCCESS |
* | 16 | Close the TCP socket.                                                   | PAL_SUCCESS |
* | 17 | Check that time is updated.                                               | PAL_SUCCESS |
* | 18 | Verify that the SOTP time value was updated.                          | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_FutureLWM2M)
{
    #if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode =     PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    uint32_t written = 0;
    palX509_t pubKey = {(const void*)g_pubKey,sizeof(g_pubKey)};
    palPrivateKey_t prvKey = {(const void*)g_prvKey,sizeof(g_prvKey)};
    palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint64_t deviceTime = pal_osGetTime(); //get device time to update it in case of failure
	uint64_t currentTime = 0;
    uint16_t actualSavedTimeSize = 0;
    uint64_t initialSOTPTime = 0;
    sotp_result_e sotpRes = SOTP_SUCCESS;
    int32_t verifyResult = 0;

    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, TLS_RENEGOTIATE_SERVER_PORT);
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

    sotpRes = sotp_set(SOTP_TYPE_SAVED_TIME, (uint16_t)sizeof(initialSOTPTime), (uint32_t*)&initialSOTPTime);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    pal_osDelay(5000);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
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
    TEST_ASSERT_TRUE(0 != deviceTime);
    /*#18*/
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(currentTime), (uint32_t*)&currentTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_TRUE(0 != currentTime);
    #endif 
}

/**
* @brief Test TLS handshake (TCP blocking) with near future time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from SOTP, move backward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Update `SOTP_TYPE_SAVED_TIME` directly in SOTP to the new time from #1  | PAL_SUCCESS |
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
    #if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    uint32_t written = 0;
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    palX509_t pubKey = { (const void*)g_pubKey,sizeof(g_pubKey) };
    palPrivateKey_t prvKey = { (const void*)g_prvKey,sizeof(g_prvKey) };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    sotp_result_e sotpRes = SOTP_SUCCESS;
    uint64_t currentTime = 0;
    uint64_t tmpTime = 0;
    uint64_t updatedTime = 0;
    uint16_t actualSavedTimeSize = 0;
    int32_t verifyResult = 0;

    /*#1*/
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(tmpTime), (uint32_t*)&tmpTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);

    currentTime = tmpTime - (PAL_SECONDS_PER_DAY / 2); //going back half day to simulate future server by half day (in order to prevent time update)
    status = pal_osSetTime(currentTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    sotpRes = sotp_set(SOTP_TYPE_SAVED_TIME, (uint16_t)sizeof(currentTime), (uint32_t*)&currentTime);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);

	/*#3*/
	status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#4*/
	status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_setSockAddrPort(&socketAddr, TLS_RENEGOTIATE_SERVER_PORT);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

    pal_osDelay(5000);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
    if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

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
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(updatedTime), (uint32_t*)&updatedTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_EQUAL_HEX(currentTime, updatedTime);
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
* | 16 | Verify that the SOTP time value was not changed.                          | PAL_SUCCESS |
*/
TEST(pal_tls, tlsHandshakeTCP_ExpiredLWM2MCert)
{
    #if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    palX509_t pubKey = {(const void*)g_pubKey,sizeof(g_pubKey)};
    palPrivateKey_t prvKey = {(const void*)g_prvKey,sizeof(g_prvKey)};
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t currentTime = 0;
    uint64_t currentSOTPTime = 0;
    uint16_t actualSavedTimeSize = 0;
	sotp_result_e sotpRes = SOTP_SUCCESS;
    int32_t verifyResult = 0;


    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, TLS_RENEGOTIATE_SERVER_PORT);
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
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(currentTime), (uint32_t*)&currentTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
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
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(currentSOTPTime), (uint32_t*)&currentSOTPTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
	TEST_ASSERT_TRUE(futureTime <= currentSOTPTime);
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
* | 6 | Set the CA cert ID into the SOTP.                                            | PAL_SUCCESS |
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
    #if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
	palStatus_t status = PAL_SUCCESS;
	palTLSConfHandle_t palTLSConf = NULLPTR;
	palTLSHandle_t palTLSHandle = NULLPTR;
	palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
	palSocketAddress_t socketAddr = { 0 };
	palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
	palX509_t pubKey = { (const void*)g_pubKey,sizeof(g_pubKey) };
	palPrivateKey_t prvKey = { (const void*)g_prvKey,sizeof(g_prvKey) };
	palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
	palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
	uint64_t futureTime = 2145542642; //Wed, 27 Dec 2037 16:04:02 GMT
    uint64_t updatedTime = 0;
    uint16_t actualSavedTimeSize = 0;
	palX509Handle_t trustedServerCA = NULLPTR;
    sotp_result_e sotpRes = SOTP_SUCCESS;
    int32_t verifyResult = 0;

	/*#1*/
	status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#2*/
	status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_setSockAddrPort(&socketAddr, TLS_RENEGOTIATE_SERVER_PORT);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    
	tlsSocket.addressLength = addressLength;
	tlsSocket.socket = g_socket;
    /*#4*/
	status = pal_x509Initiate(&trustedServerCA);
	TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_x509CertParse(trustedServerCA, (const unsigned char *)pal_test_cas, sizeof(pal_test_cas));
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
    sotpRes = sotp_set(SOTP_TYPE_TRUSTED_TIME_SRV_ID, g_actualServerIDSize, (uint32_t*)g_trustedServerID);
    if (SOTP_SUCCESS != sotpRes)
	{
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_BADCERT_EXPIRED, status);
	}

    pal_osDelay(5000);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_ERR_X509_BADCERT_EXPIRED, status);
	}

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
    
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(updatedTime), (uint32_t*)&updatedTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_TRUE(updatedTime <= futureTime);

    sotpRes = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(updatedTime), (uint32_t*)&updatedTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_TRUE(updatedTime <= futureTime);
    #endif 
}

/**
* @brief Test TLS handshake (TCP blocking) with near future time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from SOTP, move backward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 3 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 4 | Set the server port.                                                     | PAL_SUCCESS |
* | 5 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 6 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 7 | Set the CA cert ID into the SOTP.                                            | PAL_SUCCESS |
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
    #if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
	palStatus_t status = PAL_SUCCESS;
	palTLSConfHandle_t palTLSConf = NULLPTR;
	palTLSHandle_t palTLSHandle = NULLPTR;
	palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
	palSocketAddress_t socketAddr = { 0 };
	palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
	palX509_t pubKey = { (const void*)g_pubKey,sizeof(g_pubKey) };
	palPrivateKey_t prvKey = { (const void*)g_prvKey,sizeof(g_prvKey) };
	palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
	palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    sotp_result_e sotpRes = SOTP_SUCCESS;
	uint64_t currentTime = 0;
    uint64_t updatedTime = 0;
    uint16_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;

    /*#1*/
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(currentTime), (uint32_t*)&currentTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_TRUE(0 != currentTime);

    status = pal_osSetTime(currentTime - (PAL_SECONDS_PER_DAY / 2));//going back half day to simulate future server by half day (in order to prevent time update)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#2*/
	status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	/*#3*/
	status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_setSockAddrPort(&socketAddr, TLS_RENEGOTIATE_SERVER_PORT);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	tlsSocket.addressLength = addressLength;
	tlsSocket.socket = g_socket;
    
    /*#5*/
	status = pal_x509Initiate(&trustedServerCA);
	TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_x509CertParse(trustedServerCA, (const unsigned char *)pal_test_cas, sizeof(pal_test_cas));
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
    sotpRes = sotp_set(SOTP_TYPE_TRUSTED_TIME_SRV_ID, g_actualServerIDSize, (uint32_t*)g_trustedServerID);
    if (SOTP_SUCCESS != sotpRes)
	{
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

    pal_osDelay(5000);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
	if (PAL_SUCCESS != status)
	{
		pal_freeTLS(&palTLSHandle);
		pal_tlsConfigurationFree(&palTLSConf);
		pal_x509Free(&trustedServerCA);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}

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
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(updatedTime), (uint32_t*)&updatedTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_EQUAL_HEX(currentTime, updatedTime);
    #endif 

}

/**
* @brief Test TLS handshake (TCP blocking) with near past time and validate that the handshake didn't update the device time (due to set time rules)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get saved time from SOTP, move forward half day and set time to RAM    | PAL_SUCCESS |
* | 2 | Create a TCP (blocking) socket.                                        | PAL_SUCCESS |
* | 3 | Perform a DNS lookup on the server address.                                | PAL_SUCCESS |
* | 4 | Set the server port.                                                     | PAL_SUCCESS |
* | 5 | Parse the CA cert.                                                     | PAL_SUCCESS |
* | 6 | Get the CA cert ID.                                                     | PAL_SUCCESS |
* | 7 | Set the CA cert ID into the SOTP.                                            | PAL_SUCCESS |
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
    #if ((PAL_USE_SECURE_TIME == 1) && (PAL_USE_INTERNAL_FLASH == 1))
    palStatus_t status = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = { 0 };
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    palX509_t pubKey = { (const void*)g_pubKey,sizeof(g_pubKey) };
    palPrivateKey_t prvKey = { (const void*)g_prvKey,sizeof(g_prvKey) };
    palTLSSocket_t tlsSocket = { g_socket, &socketAddr, 0, transportationMode };
    palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    sotp_result_e sotpRes = SOTP_SUCCESS;
    uint64_t currentTime = 0;
    uint64_t updatedTime = 0;
    uint16_t actualSavedTimeSize = 0;
    palX509Handle_t trustedServerCA = NULLPTR;
    int32_t verifyResult = 0;

    /*#1*/
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(currentTime), (uint32_t*)&currentTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_TRUE(0 != currentTime);

    status = pal_osSetTime(currentTime + (PAL_SECONDS_PER_DAY / 2));//going back half day to simulate future server by half day (in order to prevent time update)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, false, 0, &g_socket);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_setSockAddrPort(&socketAddr, TLS_RENEGOTIATE_SERVER_PORT);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = g_socket;

    /*#5*/
    status = pal_x509Initiate(&trustedServerCA);
    TEST_ASSERT_NOT_EQUAL(trustedServerCA, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(trustedServerCA, (const unsigned char *)pal_test_cas, sizeof(pal_test_cas));
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
    sotpRes = sotp_set(SOTP_TYPE_TRUSTED_TIME_SRV_ID, g_actualServerIDSize, (uint32_t*)g_trustedServerID);
    if (SOTP_SUCCESS != sotpRes)
    {
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    pal_osDelay(5000);
    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
    if (PAL_SUCCESS != status)
    {
        pal_freeTLS(&palTLSHandle);
        pal_tlsConfigurationFree(&palTLSConf);
        pal_x509Free(&trustedServerCA);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

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
    sotpRes = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(updatedTime), (uint32_t*)&updatedTime, &actualSavedTimeSize);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpRes);
    TEST_ASSERT_EQUAL_HEX(currentTime, updatedTime);
    #endif
}

#endif //PAL_USE_INTERNAL_FLASH

static palStatus_t ThreadHandshakeTCPResource()
{

    palStatus_t status = PAL_SUCCESS;
    palStatus_t mutexStatus = PAL_SUCCESS;
    palStatus_t tmpStatus = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;

    mutexStatus = pal_osMutexWait(g_mutexHandShake1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    /*#1*/
    status = pal_initTLSConfiguration(&palTLSConf, transportationMode);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_initTLS(palTLSConf, &palTLSHandle);

    mutexStatus = pal_osMutexRelease(g_mutexHandShake1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    pal_osDelay(800);
    if(PAL_SUCCESS == status)
    {
    	tmpStatus = pal_freeTLS(&palTLSHandle);
    	if (PAL_SUCCESS != tmpStatus)
    	{
    		PAL_LOG(ERR,"Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    	}
    }

	/*#16*/
	tmpStatus = pal_tlsConfigurationFree(&palTLSConf);
	if (PAL_SUCCESS != tmpStatus)
	{
		PAL_LOG(ERR,"Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
	}

    return status;
}

static palStatus_t ThreadHandshakeTCP(bool socketNonBlocking)
{
    palStatus_t status = PAL_SUCCESS;
    palStatus_t tmpStatus = PAL_SUCCESS;
    palTLSConfHandle_t palTLSConf = NULLPTR;
    palTLSHandle_t palTLSHandle = NULLPTR;
    palTLSTransportMode_t transportationMode = PAL_TLS_MODE;
    palSocketAddress_t socketAddr = {0};
    palSocketLength_t addressLength = 0;
    char serverResponse[PAL_TLS_MESSAGE_SIZE] = {0};
    uint32_t actualLen = 0;
    uint32_t written = 0;
    palSocket_t socketTCP = 0;
    palX509_t pubKey = {(const void*)g_pubKey,sizeof(g_pubKey)};
    palPrivateKey_t prvKey = {(const void*)g_prvKey,sizeof(g_prvKey)};
    palTLSSocket_t tlsSocket = { socketTCP, &socketAddr, 0, transportationMode };
    palX509_t caCert = { (const void*)pal_test_cas,sizeof(pal_test_cas) };
    palTLSTest_t *testTLSCtx = NULL;
    palStatus_t mutexStatus = PAL_SUCCESS;
    bool mutexWait = false;
    int32_t verifyResult = 0;


    mutexStatus = pal_osMutexWait(g_mutexHandShake1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
	mutexWait = true;
    /*#1*/
    status = pal_socket(PAL_AF_INET, PAL_SOCK_STREAM, socketNonBlocking, 0, &socketTCP);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#2*/
    status = pal_getAddressInfo(PAL_TLS_TEST_SERVER_ADDRESS, &socketAddr, &addressLength);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

    tlsSocket.addressLength = addressLength;
    tlsSocket.socket = socketTCP;
    /*#3*/
    if (true == socketNonBlocking)
    {
        status = pal_setSockAddrPort(&socketAddr, TLS_SERVER_PORT_NB);
        PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    }
    else //blocking
    {
        status = pal_setSockAddrPort(&socketAddr, TLS_SERVER_PORT);
        PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    }

    /*#4*/
    status = pal_connect(socketTCP, &socketAddr, addressLength);
    if (PAL_ERR_SOCKET_IN_PROGRES == status)
    {
        pal_osDelay(400);
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
    //status = pal_sslDebugging(true);
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
					pal_osDelay(100);
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
    status = pal_sslWrite(palTLSHandle, TLS_GET_REQUEST, sizeof(TLS_GET_REQUEST), &written);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);
    /*#13*/
    pal_osDelay(5000);

    /*#14*/
    status = pal_sslRead(palTLSHandle, serverResponse, PAL_TLS_MESSAGE_SIZE, &actualLen);
    PAL_TLS_INT32_CHECK_NOT_EQUAL_GOTO_FINISH(PAL_SUCCESS, status);

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
        PAL_LOG(ERR,"Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }
    /*#16*/
    tmpStatus = pal_tlsConfigurationFree(&palTLSConf);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG(ERR,"Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }
    /*#17*/
    tmpStatus = pal_close(&socketTCP);
    if (PAL_SUCCESS != tmpStatus)
    {
        PAL_LOG(ERR,"Expected: %d , Actual: %d , Line: %d\n", (int)PAL_SUCCESS, (int)tmpStatus, __LINE__);
    }
    if (PAL_SUCCESS == status)
    {
        status = tmpStatus;
    }
    return status;

}

void pal_TCPHandshakeFunc1(void const *argument)
{
    palStatus_t mutexStatus = PAL_SUCCESS;
    palStatus_t* arg = (palStatus_t*)argument;
    mutexStatus = pal_osMutexWait(g_mutex1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    *arg = ThreadHandshakeTCPResource();

    mutexStatus = pal_osMutexRelease(g_mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
}

void pal_TCPHandshakeFunc2(void const *argument)
{
    palStatus_t mutexStatus = PAL_SUCCESS;
    palStatus_t* arg = (palStatus_t*)argument;
    mutexStatus = pal_osMutexWait(g_mutex2, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    *arg = ThreadHandshakeTCPResource();

    mutexStatus = pal_osMutexRelease(g_mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
}


void pal_TCPHandshakeFunc3(void const *argument)
{
    palStatus_t mutexStatus = PAL_SUCCESS;
    palStatus_t* arg = (palStatus_t*)argument;
    mutexStatus = pal_osMutexWait(g_mutex1, PAL_RTOS_WAIT_FOREVER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
    *arg = ThreadHandshakeTCP(true);

    mutexStatus = pal_osMutexRelease(g_mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
}

void pal_CertVerify(void const *argument)
{
#if (PAL_ENABLE_X509 == 1)
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

    status = pal_x509CertParse(certHandle, (const void*)pal_test_cas, sizeof(pal_test_cas));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    PAL_LOG(INFO,"Calling Cert Verify..");
    *arg = pal_x509CertVerifyExtended(certHandle, certHandle, &verifyResult);
    TEST_ASSERT_TRUE(PAL_ERR_X509_BADCERT_FUTURE & verifyResult);
    
    pal_x509Free(&certHandle);

    mutexStatus = pal_osMutexRelease(g_mutexHandShake1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);

    mutexStatus = pal_osMutexRelease(g_mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, mutexStatus);
#endif
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

	status = pal_osThreadCreateWithAlloc(func1, &tlsArgs1, PAL_osPriorityHigh, 5*PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID1);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

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


/**
* @brief Test try to process multiple handshake in the same time over different threads (second handhsake MUST fail)
*
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create Thread1 to process DTLS handshake                | PAL_SUCCESS |
* | 1 | Create Thread2 to process TLS handshake                 | PAL_ERR_TLS_RESOURCE |
*/
TEST(pal_tls, parallelTCPHandshakes_threads)
{
    runTLSThreadTest(pal_TCPHandshakeFunc1, pal_TCPHandshakeFunc2, PAL_SUCCESS, PAL_ERR_TLS_RESOURCE);
}

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
    #if (PAL_USE_SECURE_TIME == 1)
    palStatus_t status = PAL_SUCCESS;
    palX509Handle_t certHandle = NULLPTR;
    uint64_t systemTime = 0;

    status = pal_osSetTime(0);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    runTLSThreadTest(pal_TCPHandshakeFunc3, pal_CertVerify, PAL_SUCCESS, PAL_ERR_X509_CERT_VERIFY_FAILED);

    systemTime = pal_osGetTime();
    TEST_ASSERT_TRUE(0 < systemTime);

    status = pal_x509Initiate(&certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertParse(certHandle, (const void*)pal_test_cas, sizeof(pal_test_cas));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509CertVerify(certHandle, certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509Free(&certHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    #endif
}








