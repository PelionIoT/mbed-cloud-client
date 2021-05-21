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
#include "cs_pal_crypto.h"
#include "unity.h"
#include "unity_fixture.h"
#include "test_runners.h"
#include "mcc_common_setup.h"
#include <string.h>
// config file for keepalive server
#include "pal_socket_test_address.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "crypto.h"
#endif

#ifdef __linux__
#include <netdb.h>
#endif

TEST_GROUP(pal_socket);

#define TRACE_GROUP "PAL"

//Sometimes you may want to get local data in a module,
//for example if you need to pass a reference.
//However, you should usually avoid this.


#define PAL_NET_SUPPORT_LWIP 1
#define PAL_NET_TEST_SERVER_NAME   "www.arm.com"
#define PAL_NET_TEST_SERVER_NAME_UDP   "8.8.8.8"


#define PAL_NET_TEST_SERVER_HTTP_PORT 80

#define PAL_NET_TEST_SERVER_UDP_PORT 53
#define PAL_NET_TEST_INCOMING_PORT 8002
#define PAL_NET_TEST_INCOMING_PORT2 8989

#define PAL_NET_TEST_LOCAL_LOOPBACK_IF_INDEX 0
extern void * g_palTestNetworkInterface; // this is set by the palTestMain function
PAL_PRIVATE uint32_t g_interfaceCTXIndex = 0;
PAL_PRIVATE uint32_t s_callbackcounter = 0;

#define PAL_NET_TEST_SOCKETS 4
PAL_PRIVATE palSocket_t g_testSockets[PAL_NET_TEST_SOCKETS] = {0,0,0,0};

#define PAL_NET_TEST_GOOGLE_CDN_HOST "ajax.googleapis.com" /*! CDN host server */
#define PAL_NET_TEST_GOOGLE_CDN_HOST_PORT 80 /*! CDN host port */
#define PAL_NET_TEST_GOOGLE_CDN_REQUEST "GET /ajax/libs/jquery/3.2.1/jquery.js HTTP/1.0\r\nHost:" PAL_NET_TEST_GOOGLE_CDN_HOST "\r\n\r\n" /*! HTTP get request */
#define PAL_NET_TEST_BUFFERED_BUF_SIZE_SMALL 64
#define PAL_NET_TEST_BUFFERED_BUF_SIZE_LARGE 1024
#define PAL_NET_TEST_BUFFERED_UDP_PORT 2606
#define PAL_NET_TEST_BUFFERED_UDP_MESSAGE_SIZE (1024 * 256)
PAL_PRIVATE uint8_t *g_testRecvBuffer = NULLPTR;
PAL_PRIVATE uint8_t *g_testSendBuffer = NULLPTR;
#ifdef TARGET_LIKE_MBED
PAL_PRIVATE bool g_interfaceConnected = false;
#endif
#define PAL_NET_TEST_ECHO_TEST_SERVER_ADDRESS "echo.mbedcloudtesting.com"

// the tests expect to have guaranteed forward progress, even if they fail. So the semaphore
// wait time is set to some arbitrary time, which is likely "long enough" to work even on system high load.
// But if one tries to debug the code under test, the test code will timeout too soon. So if a
// runtime debugger is used, just set this define to PAL_RTOS_WAIT_FOREVER
#define TEST_SEMAPHORE_WAIT 10000


#if defined(__SXOS__)
// SX OS Does not support PAL_SO_RCVTIMEO or PAL_SO_SNDTIMEO
    #define PAL_SO_RCVTIMEO_EXPECTED_RESULT     PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED
    #define PAL_SO_SNDTIMEO_EXPECTED_RESULT     PAL_ERR_SOCKET_OPTION_NOT_SUPPORTED
#else
    #define PAL_SO_RCVTIMEO_EXPECTED_RESULT     PAL_SUCCESS
    #define PAL_SO_SNDTIMEO_EXPECTED_RESULT     PAL_SUCCESS
#endif


typedef struct pal_udp_test_data /*! structure used to hold state in UDP buffered tests */
{
    const size_t messageSize;
    const size_t bufferSize;
    const uint8_t startValue;
    palNetInterfaceInfo_t interfaceInfo;
    uint8_t currentValue;
    size_t totalSize;
    size_t chunkSize;
} pal_udp_test_data_t;

TEST_SETUP(pal_socket)
{
    uint32_t i = 0;
    palStatus_t status;
    //This is run before *each test*
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    if ( NULL == g_palTestNetworkInterface )
    {
        PAL_LOG_ERR("error: net interface not configured correctly");
    }
    else
    {
        status = pal_registerNetworkInterface(g_palTestNetworkInterface, &g_interfaceCTXIndex);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    for (i = 0; i < PAL_NET_TEST_SOCKETS; i++)
    {
        g_testSockets[i] = 0;
    }
}

TEST_TEAR_DOWN(pal_socket)
{
    uint32_t i = 0;
    for (i = 0; i < PAL_NET_TEST_SOCKETS; i++)
    {
        if (g_testSockets[i] != 0)
        {
            pal_close(&(g_testSockets[i]));
        }
    }

    if (g_testRecvBuffer != NULLPTR)
    {
        free(g_testRecvBuffer);
        g_testRecvBuffer = NULLPTR;
    }
    if (g_testSendBuffer != NULLPTR)
    {
        free(g_testSendBuffer);
        g_testSendBuffer = NULLPTR;
    }

    pal_destroy();
}

#define PAL_TEST_BUFFER_SIZE 50
PAL_PRIVATE void socketCallback1( void * arg)
{
    s_callbackcounter++;
}

static palSemaphoreID_t s_semaphoreID = NULLPTR;
static palSemaphoreID_t s_semaphoreID3 = NULLPTR;

#if (PAL_DNS_API_VERSION == 2) || (PAL_DNS_API_VERSION == 3)

static palSemaphoreID_t s_asyncDnsSemaphore = NULLPTR;

// flag marking if the pal_getAddressInfoAsync callback has been invoked
PAL_PRIVATE bool g_getAddressInfoAsyncCallbackInvoked = false;

#if (PAL_DNS_API_VERSION == 3)
static palAddressInfo_t *global_addrInfo = NULLPTR;
static palDNSQuery_t dns_query_t = 0;
// callback invoked from the call to pal_getAddressInfoAsync
PAL_PRIVATE void getAddressInfoAsyncCallback(const char* url, palAddressInfo_t *addrInfo, palStatus_t status, void* callbackArgument)
{
    global_addrInfo = addrInfo;
#else
// callback invoked from the call to pal_getAddressInfoAsync
PAL_PRIVATE void getAddressInfoAsyncCallback(const char* url, palSocketAddress_t* address, palStatus_t status, void* callbackArgument)
{
#endif
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    g_getAddressInfoAsyncCallbackInvoked = true;
    pal_osSemaphoreRelease(s_asyncDnsSemaphore);
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

PAL_PRIVATE void socketCallback2(void * arg)
{
    palStatus_t result;
    if(s_callbackcounter == 0)
    {
        result = pal_osSemaphoreRelease(s_semaphoreID);
        TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    }
    s_callbackcounter++;

}

PAL_PRIVATE void socketCallback3(void * arg)
{
    palStatus_t result;
    result = pal_osSemaphoreRelease(s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
}
/*! \brief Test socket creation, destruction and modification, as well as getting address infromation and checking the blocking status of sockets.
*
** \test
* | # |    Step                                                                                 |   Expected  |
* |---|-----------------------------------------------------------------------------------      |-------------|
* | 1 | Register a net interface using `pal_registerNetworkInterface`.                          | PAL_SUCCESS |
* | 2 | Register a net interface using `pal_registerNetworkInterface`,                          | PAL_SUCCESS |
*       and check that the ID is the same as the previous step.
* | 3 | Unregister a net interface using `pal_unregisterNetworkInterface`.                      | PAL_SUCCESS |
* | 4 | Get the interface address using `pal_getNetInterfaceInfo`.                              | PAL_SUCCESS |
* | 5 | Create a blocking asynchronous UDP socket with `socketCallback1` as callback.           | PAL_ERR_INVALID_ARGUMENT |
* | 6 | Create a non blocking asynchronous UDP socket with `socketCallback1` as callback.       | PAL_SUCCESS |
* | 7 | Check the number of net interfaces registered using `pal_getNetInterfaceInfo`.          | PAL_SUCCESS |
* | 8 | Set the socket receive timeout using `pal_setSocketOptions`.                            | PAL_SUCCESS |
* | 9 | Check that the sockets return the correct blocking status using `pal_isNonBlocking`.    | PAL_SUCCESS |
* | 10 | Test DNS resolving with valid params                                                   | PAL_SUCCESS |
* | 11 | Close all sockets.                                                                     | PAL_SUCCESS |
*/
TEST(pal_socket, socketUDPCreationOptionsTest)
{
    palStatus_t result = PAL_SUCCESS;
    uint32_t numInterface = 0;
    palNetInterfaceInfo_t interfaceInfo;
    uint32_t interfaceIndex = 0;
    uint32_t interfaceIndex2 = 0;
    uint32_t sockOptVal = 5000;
    uint32_t sockOptLen = sizeof(sockOptVal);
    palSocketAddress_t address = { 0 };
    palSocketLength_t addrlen = 0;
    bool isNonBlocking = false;

    memset(&interfaceInfo,0,sizeof(interfaceInfo));

    /*#1*/
    result = pal_registerNetworkInterface(g_palTestNetworkInterface, &interfaceIndex);
    TEST_ASSERT_EQUAL( PAL_SUCCESS, result);

    const char *var[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8"};
    for (int i = 0; i < PAL_MAX_SUPORTED_NET_INTERFACES - 1; i++) {
        result = pal_registerNetworkInterface((void*)var[i], &interfaceIndex);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        result = pal_getNumberOfNetInterfaces(&numInterface);
        TEST_ASSERT_EQUAL(numInterface, i + 2);
    }

    // Array full
    result = pal_registerNetworkInterface((void*)"10", &interfaceIndex);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SOCKET_MAX_NUMBER_OF_INTERFACES_REACHED, result);

    // Check that re-adding the network interface returns the same index,
    // which in this case is the first item in the list
    /*#2*/
    result = pal_registerNetworkInterface(g_palTestNetworkInterface, &interfaceIndex2);
    TEST_ASSERT_EQUAL_HEX(0, interfaceIndex2);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    // Remove interfaces from the list, keep the first item since it required in other tests
    /*#3*/
    for (int i = 1; i < PAL_MAX_SUPORTED_NET_INTERFACES; i++) {
        pal_unregisterNetworkInterface(i);
        pal_getNumberOfNetInterfaces(&numInterface);
        TEST_ASSERT_EQUAL(numInterface, PAL_MAX_SUPORTED_NET_INTERFACES - i);
    }
    // Try to remove interface again
    result = pal_unregisterNetworkInterface(1);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, result);

// PAL validate macros are only available in debug builds
#ifdef DEBUG
    // Interface index out of range
    pal_unregisterNetworkInterface(11);
#endif
    // Set index back to default one
    interfaceIndex = 0;

#if PAL_SUPPORT_IP_V4
    /*#4*/
    result = pal_getNetInterfaceInfo(interfaceIndex, &interfaceInfo);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    PAL_PRINTF("Default interface address: %u %u %u %u \r\n",
        (unsigned char)interfaceInfo.address.addressData[2],
        (unsigned char)interfaceInfo.address.addressData[3],
        (unsigned char)interfaceInfo.address.addressData[4],
        (unsigned char)interfaceInfo.address.addressData[5]);;
#endif

#ifdef DEBUG
    /*#5*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_DGRAM, false, interfaceIndex, socketCallback1, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, result);
#endif
    /*#6*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_DGRAM, true, interfaceIndex, socketCallback1, &g_testSockets[1]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    result = pal_getNumberOfNetInterfaces(&numInterface);
    TEST_ASSERT_EQUAL(numInterface, 1);

    /*#8*/
    result = pal_setSocketOptions(g_testSockets[1], PAL_SO_RCVTIMEO, &sockOptVal, sockOptLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);

    /*#9*/
    result = pal_isNonBlocking(g_testSockets[1], &isNonBlocking);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(isNonBlocking, true);

    /*#10*/
    result = doDnsQuery("0.0.0.0", &address, &addrlen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#11*/
    result = pal_close(&g_testSockets[2]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    result = pal_close(&g_testSockets[1]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    result = pal_close(&g_testSockets[1]); //double close - should succeed
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
}


/*! \brief Test TCP socket creation, connection, send and receive with a test server.
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a blocking async TCP socket using `pal_asynchronousSocket`.                             | PAL_SUCCESS |
* | 2 | Look up the IP address of the test server using `pal_getAddressInfo`.                          | PAL_SUCCESS |
* | 3 | Set the port to a test port in the address structure using `pal_setSockAddrPort` and set timeout. | PAL_SUCCESS |
* | 4 | Connect the socket to the test server using `pal_connect`.                                     | PAL_SUCCESS |
* | 5 | Send a test message (short HTTP request) to the test server using `pal_send`.                  | PAL_SUCCESS |
* | 6 | Receive (blocking) the server's response using `pal_recv` and check it is HTTP.          | PAL_SUCCESS |
* | 7 | Close the socket.                                                                        | PAL_SUCCESS |
*/
TEST(pal_socket, basicTCPclientSendRecieve)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    const char message[] = "GET / HTTP/1.0\r\n\r\n";
    size_t sent = 0;
    char buffer[100] = { 0 };
    size_t read = 0;
    palSocketLength_t addrlen = 0;
    int timeout = PAL_MILLI_PER_SECOND;

    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#1*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#2*/
    result = doDnsQuery(PAL_NET_TEST_SERVER_NAME, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        goto end;
    }
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_NET_TEST_SERVER_HTTP_PORT);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_SNDTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_SNDTIMEO_EXPECTED_RESULT, result);
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_RCVTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);

    /*#4*/
    do {
        result = pal_connect(g_testSockets[0], &address, 16);
        pal_osSemaphoreWait(s_semaphoreID3, 100, &temp);
    } while (result != PAL_SUCCESS);

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#5*/
    result = pal_send(g_testSockets[0], message, sizeof(message) - 1, &sent);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#6*/
    do {
        result = pal_recv(g_testSockets[0], buffer, 99, &read);
        pal_osSemaphoreWait(s_semaphoreID3, 100, &temp);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    TEST_ASSERT(read >= 4);
    TEST_ASSERT(buffer[0] == 'H' && buffer[1] == 'T'&& buffer[2] == 'T' && buffer[3] == 'P');

    pal_osSemaphoreRelease(s_semaphoreID3);
    pal_osSemaphoreDelete(&s_semaphoreID3);
end: //unified cleanup
    /*#7*/
    pal_close(&g_testSockets[0]);

}

/*! \brief Test UDP socket creation, connection, send and recieve with a test server.
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a async UDP socket using `pal_asynchronousSocket`.                         | PAL_SUCCESS |
* | 2 | Look up the IP address of the test server using `pal_getAddressInfo`.                      | PAL_SUCCESS |
* | 3 | Set the port to a test port in the address structure using `pal_setSockAddrPort`.            | PAL_SUCCESS |
* | 4 | Connect the socket to the test server using `pal_connect`.                                 | PAL_SUCCESS |
* | 5 | Send a test message (short DNS request) to the test server using `pal_send`.                | PAL_SUCCESS |
* | 6 | Receive the server's response using `pal_recv`.                           | PAL_SUCCESS |
* | 7 | Close the socket.                                                                    | PAL_SUCCESS |
*/
TEST(pal_socket, basicUDPclientSendRecieve)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    palSocketAddress_t address2 = { 0 };
    uint8_t buffer[33] = { 0x8e, 0xde, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x61, 0x72, 0x73, 0x74, 0x65, 0x63, 0x68, 0x6e, 0x69, 0x63, 0x61, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };
    uint8_t buffer_in[10];
    size_t sent = 0;
    size_t read = 0;
    size_t socket_timeout_ms = 5000;
    palSocketLength_t addrlen = 0;

    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#1*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_DGRAM, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#2*/
    result = doDnsQuery(PAL_NET_TEST_SERVER_NAME_UDP, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration can't continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        goto end;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_NET_TEST_SERVER_UDP_PORT);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#4*/
    //We set a timeout for receiving so we won't get stuck in the test
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_RCVTIMEO, &socket_timeout_ms, sizeof(socket_timeout_ms));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);

    /*#5*/
    result = pal_sendTo(g_testSockets[0], buffer, sizeof(buffer), &address, 16, &sent);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL(sent, sizeof(buffer));

    /*#6*/
    do {
        result = pal_receiveFrom(g_testSockets[0], buffer_in, 10, &address2, &addrlen, &read);
        pal_osSemaphoreWait(s_semaphoreID3, 100, &temp);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);

    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL(read, 10);
    pal_osSemaphoreRelease(s_semaphoreID3);
    pal_osSemaphoreDelete(&s_semaphoreID3);
end:
    /*#7*/
    pal_close(&g_testSockets[0]);
}

// This is an example showing how to check for a socket that has been closed remotely.
#if 0
PAL_PRIVATE void basicSocketScenario3Callback(void * arg)
{
    char buffer[400];
    size_t read = 0;
    palStatus_t result;


    s_callbackcounter++;
    result = pal_recv(g_testSockets[0], buffer, 999, &read);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    // If 0 bytes are read it means that the peer has performed an orderly shutdown so we must close the socket
    // to avoid ppoll from checking it. Checking a socket whose other end has been shut down causes ppoll to immediately return
    // with events == 0x1.
    if(read == 0)
    {
        pal_close(&g_testSockets[0]);
    }
    else
    {
        buffer[read] = '\0';
        if(s_callbackcounter == 0)
        {
            TEST_ASSERT(read >= 4);
            TEST_ASSERT(buffer[0] == 'H' && buffer[1] == 'T'&& buffer[2] == 'T' && buffer[3] == 'P');
        }
    }

}
#endif

static int s_secondCallbackCounter = 0;
PAL_PRIVATE void socketCallbackErr(void * arg)
{
    s_secondCallbackCounter++;
}

/*! \brief Test asynchronous socket callbacks.
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Look up the IP address of the test server using `pal_getAddressInfo`.                      | PAL_SUCCESS |
* | 2 | Create a asynchronous TCP socket with `socketCallback3` as callback.        | PAL_SUCCESS |
* | 3 | Set port to a test port in the address structure using `pal_setSockAddrPort`.            | PAL_SUCCESS |
* | 4 | Connect the socket to the test server using `pal_connect`.                                 | PAL_SUCCESS |
* | 5 | Send a test message (short HTTP request) to the test server using `pal_send`.               | PAL_SUCCESS |
* | 6 | Wait for a callback to release the semaphore when the response arrives.                    | PAL_SUCCESS |
* | 7 | Receive the server's response using `pal_recv` and check that the response is HTTP.| PAL_SUCCESS |
* | 8 | Close the socket.                                                                    | PAL_SUCCESS |
*/
TEST(pal_socket, basicSocketScenario3)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    const char* message = "GET / HTTP/1.0\r\nHost:10.45.48.68:8000\r\n\r\n";
    size_t sent = 0;
    char buffer[100] = { 0 };
    size_t read = 0;
    s_callbackcounter = 0;
    palSocketLength_t addrlen = 0;
    int32_t countersAvailable;

    result = pal_osSemaphoreCreate(1, &s_semaphoreID);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    result = pal_osSemaphoreWait(s_semaphoreID, 40000, &countersAvailable);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#1*/
    result = doDnsQuery(PAL_NET_TEST_SERVER_NAME, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        return;
    }
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#2*/
    result = pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, socketCallback2, "socketCallback2Arg", &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    s_secondCallbackCounter = 0;
    result = pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, socketCallbackErr, "socketCallback2Arg", &g_testSockets[1]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    TEST_ASSERT_EQUAL_HEX(0, s_secondCallbackCounter);
    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_NET_TEST_SERVER_HTTP_PORT);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#4*/
    do {
        result = pal_connect(g_testSockets[0], &address, 16);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &countersAvailable);
    } while (result == PAL_ERR_SOCKET_IN_PROGRES || result == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (result == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        result = PAL_SUCCESS;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    TEST_ASSERT_EQUAL_HEX(0, s_secondCallbackCounter);

    /*#5*/
    result = pal_send(g_testSockets[0], message, strlen(message), &sent);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    TEST_ASSERT_EQUAL_HEX(0, s_secondCallbackCounter);

    /*#7*/
    do {
        result = pal_recv(g_testSockets[0], buffer, 99, &read);
        pal_osSemaphoreWait(s_semaphoreID, 1000, &countersAvailable);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);

    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    TEST_ASSERT(read >= 4);
    TEST_ASSERT(buffer[0] == 'H' && buffer[1] == 'T'&& buffer[2] == 'T' && buffer[3] == 'P');
    TEST_ASSERT(s_callbackcounter > 0);

    TEST_ASSERT_EQUAL_HEX(0, s_secondCallbackCounter);
    /*#8*/
    pal_close(&g_testSockets[0]);
}


#if PAL_NET_SERVER_SOCKET_API

typedef struct palNetTestThreadData{
    palSemaphoreID_t sem1;
    palSemaphoreID_t sem2;
    uint16_t port;
} palNetTestThreadData_t;

char s_rcv_buffer[20] = {0};
char s_rcv_buffer2[50]  = {0};

void palNetClientFunc(void const *argument)
{
    palStatus_t result = PAL_SUCCESS;
    int32_t tmp = 0;
    size_t sent = 0;
    size_t read = 0;

    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    palNetTestThreadData_t* dualSem = (palNetTestThreadData_t*)argument;
    TEST_ASSERT_NOT_NULL(dualSem);

    palSocketLength_t addrlen = 16;
    //palSocketAddress_t address = { 0 };
    palNetInterfaceInfo_t interfaceInfo;
    const char* message = "GET / HTTP/1.0\r\n\r\n";

    /*#C1*/
    result = pal_osSemaphoreWait(dualSem->sem1, TEST_SEMAPHORE_WAIT, &tmp);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C2*/
    result = pal_getNetInterfaceInfo(PAL_NET_TEST_LOCAL_LOOPBACK_IF_INDEX, &interfaceInfo);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C3*/
    uint16_t incoming_port = dualSem->port;
    PAL_PRINTF("client port = %u", incoming_port);
    result = pal_setSockAddrPort(&(interfaceInfo.address), incoming_port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C4*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, socketCallback3, &g_testSockets[2]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C5*/
    do {
        result = pal_connect(g_testSockets[2], &(interfaceInfo.address), addrlen);
        pal_osSemaphoreWait(s_semaphoreID3, 1000, &temp);
    } while (result == PAL_ERR_SOCKET_IN_PROGRES || result == PAL_ERR_SOCKET_WOULD_BLOCK);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C6*/
    result = pal_send(g_testSockets[2], message, 18, &sent);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C7*/
    do {
        result = pal_recv(g_testSockets[2], s_rcv_buffer, 15, &read);
        pal_osSemaphoreWait(s_semaphoreID3, 1000, &temp);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#C8*/
    pal_close(&g_testSockets[2]);

    result = pal_osSemaphoreRelease(dualSem->sem2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    pal_osSemaphoreRelease(s_semaphoreID3);
    pal_osSemaphoreDelete(&s_semaphoreID3);
}

#endif // PAL_NET_SERVER_SOCKET_API

palSemaphoreID_t g_acceptedSocketEventSem = NULLPTR;
PAL_PRIVATE int32_t g_clientSocketEventCounter = 0;

void acceptedSocketCb(void *arg)
{
    int32_t counter;

    // Increment event counter
    counter = pal_osAtomicIncrement(&g_clientSocketEventCounter, 1);

    // Make sure arg got through successfully
    TEST_ASSERT_EQUAL(&g_testSockets[1], arg);

    // Make sure that even even multiple events are triggered, we do not release a released semaphore
    // which may result in undefined behavior, depending on implementation
    if (1 == counter)
    {
        pal_osSemaphoreRelease(g_acceptedSocketEventSem);
    }
}

/*! \brief /b ServerSocketScenario tests a TCP client-server scenario using device loopback.
*
* \note In mbed-os lwip loopback feature must be enabled to make test working.
* This can be done by enabling LWIP_NETIF_LOOPBACK flag.
* The sequence below is an approximation of the actual order of execution.
* \note The test steps are divided into those in the server main thread (S1..S13) and those in the client thread (C1..C8).
* The sequence below is an approximation of the actual order of execution.
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | S1 | Look up the IP address of loopback using `pal_getAddressInfo`.                           | PAL_SUCCESS |
* | S2 | Create a blocking async TCP server socket using `pal_asynchronousSocket`.                | PAL_SUCCESS |
* | S3 | Set the port to test port in address structure using `pal_setSockAddrPort`.              | PAL_SUCCESS |
* | S4 | Bind the server socket to the port and address using `pal_bind`.                         | PAL_SUCCESS |
* | S5 | Create synchronization sepmaphores and set count to 0.                                   | PAL_SUCCESS |
* | S6 | Create a client thread with `BelowNormal` priority running `palNetClientFunc`.           | PAL_SUCCESS |
* | C1 | Client thread blocks on client sepmaphore s1.                                            | PAL_SUCCESS |
* | S7 | Listen to the server port using `pal_listen`.                                            | PAL_SUCCESS |
* | S8 | Release the client sepmahore s1.                                                         | PAL_SUCCESS |
* | S9 | Call `accept` (blocking) to accept a new connection (retry in case of failure).          | PAL_SUCCESS |
* | C2 | Look up the IP address of the loopback using `pal_getAddressInfo`.                       | PAL_SUCCESS |
* | C3 | Set the port to test port in the address structure using `pal_setSockAddrPort`.          | PAL_SUCCESS |
* | C4 | Create a blocking async TCP socket using `pal_asynchronousSocket`.                       | PAL_SUCCESS |
* | C5 | Connect to the server using `pal_connect`.                                               | PAL_SUCCESS |
* | C6 | Send data to server.                                                                     | PAL_SUCCESS |
* | S10 | Receive data from the client.                                                           | PAL_SUCCESS |
* | S11 | Send data to the client.                                                                | PAL_SUCCESS |
* | C7 | Receive data from the server.                                                            | PAL_SUCCESS |
* | C8 | Client thread cleanup - close the socket and release the semaphore.                      | PAL_SUCCESS |
* | S12 | Cleanup: close sockets and delete semaphores.                                           | PAL_SUCCESS |
*/
TEST(pal_socket, ServerSocketScenario)
{
#if PAL_NET_SERVER_SOCKET_API
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address2 = { 0 };
    const char* messageOut = "HTTP/1.0 200 OK";
    size_t sent = 0;
    size_t read = 0;
    g_clientSocketEventCounter = 0;
    // Note: unlike the pal_connect(), the pal accept() still verifies the given address length.
    palSocketLength_t addrlen = sizeof(palSocketAddress_t);

    palSemaphoreID_t semaphoreID = NULLPTR;
    palSemaphoreID_t semaphoreID2 = NULLPTR;
    palNetTestThreadData_t dualSem = {0};
    palThreadID_t threadID1 = NULLPTR;
    int32_t tmp = 0;
    palNetInterfaceInfo_t interfaceInfo;
    memset(&interfaceInfo,0,sizeof(interfaceInfo));

    /*#S1*/
    result = pal_getNetInterfaceInfo(PAL_NET_TEST_LOCAL_LOOPBACK_IF_INDEX, &interfaceInfo);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S2*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_STREAM_SERVER, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S3*/
    uint32_t rand_number = 0;
    uint16_t incoming_port;

#if !PAL_USE_HW_TRNG
    palStatus_t status = PAL_SUCCESS;
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
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    pal_osRandomBuffer((uint8_t*)&rand_number, sizeof(rand_number));
    incoming_port = (uint16_t)(35400 + (rand_number % (40000 - 35400)));
    PAL_PRINTF("server port = %u", incoming_port);

    result = pal_setSockAddrPort(&(interfaceInfo.address), incoming_port);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S4*/
    result = pal_bind(g_testSockets[0], &(interfaceInfo.address), interfaceInfo.addressSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S5*/
    // start client thread to connect to the server.
    result = pal_osSemaphoreCreate(0 ,&semaphoreID);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    result = pal_osSemaphoreCreate(0 ,&semaphoreID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    result = pal_osSemaphoreCreate(0 ,&g_acceptedSocketEventSem);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    dualSem.sem1 = semaphoreID;
    dualSem.sem2 = semaphoreID2;
    dualSem.port = incoming_port;

    /*#S6*/
    result = pal_osThreadCreateWithAlloc(palNetClientFunc, &dualSem , PAL_osPriorityBelowNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S7*/
    result = pal_listen(g_testSockets[0], 10);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S8*/
    result = pal_osSemaphoreRelease(dualSem.sem1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);


    PAL_PRINTF("waiting for connection:\r\n");
    /*#S9*/
    do {
        result = pal_accept(g_testSockets[0], &address2, &addrlen, &g_testSockets[1], acceptedSocketCb, &g_testSockets[1]);
        pal_osSemaphoreWait(g_acceptedSocketEventSem, 100, NULL);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S10*/
    do {
        result = pal_recv(g_testSockets[1], s_rcv_buffer2, 49, &read);
        pal_osSemaphoreWait(s_semaphoreID3, 1000, NULL);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#S11*/
    result = pal_send(g_testSockets[1], messageOut, 15, &sent);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    //cleanup
    /*#S12*/
    pal_close(&g_testSockets[1]);
    pal_close(&g_testSockets[0]);


    result = pal_osSemaphoreWait(semaphoreID2, TEST_SEMAPHORE_WAIT, &tmp);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    pal_osDelay(2000);
    pal_osThreadTerminate(&threadID1);
    result = pal_osSemaphoreDelete(&semaphoreID);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(NULLPTR, semaphoreID);

    result = pal_osSemaphoreDelete(&semaphoreID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(NULLPTR, semaphoreID2);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_NET_SERVER_SOCKET_API not defined");
#endif // PAL_NET_SERVER_SOCKET_API
}



PAL_PRIVATE volatile uint32_t s_callbackCounterNonBlock = 0;

PAL_PRIVATE void nonBlockCallback(void * arg)
{
    s_callbackCounterNonBlock++;
}

#define PAL_NET_TEST_HTTP_HEADER_LEN 5

/*! \brief /b nonBlockingAsyncTest checks the asynchronous- nonblocking socket scenario.
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Look up the IP address of the test server using `pal_getAddressInfo`.                        | PAL_SUCCESS |
* | 2 | Create an asynchronous non-blocking TCP socket with `nonBlockCallback` as callback.     | PAL_SUCCESS |
* | 3 | Set the port to test port in the address structure using `pal_setSockAddrPort`.              | PAL_SUCCESS |
* | 4 | Connect the socket.                                                                    | PAL_SUCCESS or PAL_ERR_SOCKET_IN_PROGRES |
* | 5 | Send a test message to the test server using `pal_send` (repeat until success).           | PAL_SUCCESS or PAL_ERR_SOCKET_IN_PROGRES |
* | 6 | Wait for the callback and receive server response using `pal_recv` (repeat until success). | PAL_SUCCESS or PAL_ERR_SOCKET_WOULD_BLOCK|
* | 7 | Close the socket.                                                                      | PAL_SUCCESS |
*/
TEST(pal_socket, nonBlockingAsyncTest)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    const char* message = "GET / HTTP/1.0\r\nHost:10.45.48.68:8000\r\n\r\n";
    size_t sent = 0;
    char buffer[100] = { 0 };
    size_t read = 0;
    s_callbackcounter = 0;
    palSocketLength_t addrlen = 0;
    int32_t waitIterations = 0;

    /*#1*/
    result = doDnsQuery(PAL_NET_TEST_SERVER_NAME, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, nonBlockCallback, "non-blockSocketCallbackArg", &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_NET_TEST_SERVER_HTTP_PORT);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#4*/
    result = pal_connect(g_testSockets[0], &address, 16);
    if (PAL_ERR_SOCKET_IN_PROGRES == result)
    {
        result = pal_connect(g_testSockets[0], &address, 16);
        if ((result != PAL_SUCCESS) && (result != PAL_ERR_SOCKET_ALREADY_CONNECTED) && (result != PAL_ERR_SOCKET_IN_PROGRES) && (result != PAL_ERR_SOCKET_WOULD_BLOCK)) // check expected result codes.(connection should either be in progress or connected already)
        {
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
        pal_osDelay(400);
    }
    else
    {
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }
    s_callbackCounterNonBlock = 0;

    /*#5*/
    result = pal_send(g_testSockets[0], message, strlen(message), &sent);

    while (PAL_ERR_SOCKET_IN_PROGRES == result)
    {
        pal_osDelay(100);
        result = pal_send(g_testSockets[0], message, strlen(message), &sent);
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_recv(g_testSockets[0], buffer, PAL_NET_TEST_HTTP_HEADER_LEN, &read); // may block
    while ((PAL_ERR_SOCKET_WOULD_BLOCK == result) && (10 > waitIterations ))
    {
        s_callbackCounterNonBlock = 0;
        while (s_callbackCounterNonBlock == 0)
        {
            waitIterations++;
            pal_osDelay(100);
        }
        result = pal_recv(g_testSockets[0], buffer, PAL_NET_TEST_HTTP_HEADER_LEN, &read); // shouldnt block
    }

    /*#7*/
    pal_close(&g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT(read >= 4);
    TEST_ASSERT(buffer[0] == 'H' && buffer[1] == 'T'&& buffer[2] == 'T' && buffer[3] == 'P');
    TEST_ASSERT(s_callbackCounterNonBlock > 0);
}

/*! \brief /b tProvUDPTest tests UDP socket send/receive and checks that we get the correct error for receive timeout.
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a async UDP socket using `pal_asynchronousSocket`.                           | PAL_SUCCESS |
* | 2 | Look up the IP address of the test server using `pal_getAddressInfo`.                        | PAL_SUCCESS |
* | 3 | Set the port to test port in the address structure using `pal_setSockAddrPort`.              | PAL_SUCCESS |
* | 4 | Set socket timeouts using `pal_setSocketOptions`.                                            | PAL_SUCCESS |
* | 5 | Send a test message (short HTTP request) to test the server using `pal_send`.                | PAL_SUCCESS |
* | 6 | Receive the server response using `pal_recv`.                                     | PAL_SUCCESS |
* | 7 | Receive the server response again using `pal_recv` and fail.                     | PAL_ERR_SOCKET_WOULD_BLOCK |
* | 8 | Close the socket.                                                                            | PAL_SUCCESS |
*/
TEST(pal_socket, tProvUDPTest)
{
#if defined(__SXOS__)
    TEST_IGNORE_MESSAGE("Ignored, SX OS does not support PAL_SO_RCVTIMEO");
#else
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0,{0} };
    uint8_t buffer[100] = { 0 };
    uint8_t buffer_dns[33] = { 0x8e, 0xde, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x61, 0x72, 0x73, 0x74, 0x65, 0x63, 0x68, 0x6e, 0x69, 0x63, 0x61, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 };
    size_t sent = 0;
    size_t read = 0;
    palSocketLength_t addrlen = 16;
    int timeout = PAL_MILLI_PER_SECOND;

    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#1*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_DGRAM, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#2*/
    result = doDnsQuery(PAL_NET_TEST_SERVER_NAME_UDP, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        goto end;
    }
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_NET_TEST_SERVER_UDP_PORT);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#4*/
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_SNDTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_SNDTIMEO_EXPECTED_RESULT, result);

    timeout = 1000;
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_RCVTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);

    /*#5*/
    result = pal_sendTo(g_testSockets[0], buffer_dns, sizeof(buffer_dns), &address, addrlen, &sent);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(sent, sizeof(buffer_dns));

    /*#6*/
    do {
        result = pal_receiveFrom(g_testSockets[0], buffer, 16, NULL, NULL, &read);
        pal_osSemaphoreWait(s_semaphoreID3, 100, &temp);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL(read, 16);

    /*#7*/
    result = pal_receiveFrom(g_testSockets[0], buffer, 100, NULL, NULL, &read); //  should get timeout
    TEST_ASSERT_EQUAL_HEX(result, PAL_ERR_SOCKET_WOULD_BLOCK);

end:
    /*#8*/
    pal_close(&g_testSockets[0]);
#endif
}


PAL_PRIVATE void fillUDPTestBuffer(pal_udp_test_data_t *data, uint8_t* buffer)
{
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT_NOT_NULL(buffer);

    memset(buffer, 0, data->bufferSize);
    data->chunkSize = (data->messageSize - data->totalSize > data->bufferSize) ? data->bufferSize : (data->messageSize - data->totalSize);
    memset(buffer, ++(data->currentValue), data->chunkSize);
    data->totalSize += data->chunkSize;
}

// UDP test sender thread function.
PAL_PRIVATE void socketUDPBufferedTestSender(const void *arg)
{
    palStatus_t result = PAL_SUCCESS;
    pal_udp_test_data_t *data = (pal_udp_test_data_t*)arg; // cast from const to non-const
    size_t sent = 0, totalSent = 0;

    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT_NOT_EQUAL(0, data->bufferSize);
    TEST_ASSERT_NOT_EQUAL(0, data->chunkSize);

    g_testSendBuffer = (uint8_t*)malloc(sizeof(uint8_t) * data->bufferSize);
    TEST_ASSERT_NOT_NULL(g_testSendBuffer);

    data->totalSize = 0;
    data->chunkSize = 0;
    data->currentValue = data->startValue;
    while (totalSent != data->messageSize)
    {
        fillUDPTestBuffer(data, g_testSendBuffer);
        result = pal_sendTo(g_testSockets[0], g_testSendBuffer, data->chunkSize, &(data->interfaceInfo.address), data->interfaceInfo.addressSize, &sent);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        totalSent += sent;
        pal_osDelay(5); // allow some time for the RX bits to be set
    };

    free(g_testSendBuffer);
    g_testSendBuffer = NULLPTR;
}

/*! \brief Test UDP socket read in chunks
*
* \note The test generates data and calculates its hash, then this data is re-generated from a dedicated thread and
* received on the current thread which calculates the received data hash and compares it to the original hash
*
* @param[in]    bufSize - the read buffer size
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the MD context.                                                           | PAL_SUCCESS |
* | 2 | Allocate buffer.                                                                     | PAL_SUCCESS |
* | 3 | Generate data incrementally and update the MD context.                               | PAL_SUCCESS |
* | 4 | Get the hash output size and validate it.                                            | PAL_SUCCESS |
* | 5 | Get the calculated hash.                                                             | PAL_SUCCESS |
* | 6 | Free the MD context resources.                                                       | PAL_SUCCESS |
* | 7 | Get the interface address.                                                           | PAL_SUCCESS |
* | 8 | Create a async UDP socket.                                                          | PAL_SUCCESS |
* | 9 | Set the socket port and set send/receive timeouts.                                   | PAL_SUCCESS |
* | 10 | Bind the socket.                                                                    | PAL_SUCCESS |
* | 11 | Initialize the MD context.                                                          | PAL_SUCCESS |
* | 12 | Launch the data sender thread.                                                      | PAL_SUCCESS |
* | 13 | Read data from the socket until there's no more data or all data has been received. | PAL_SUCCESS |
* | 14 | Update the MD context.                                                              | PAL_SUCCESS |
* | 15 | Terminate the sending thread.                                                       | PAL_SUCCESS |
* | 16 | Close the socket.                                                                   | PAL_SUCCESS |
* | 17 | Get the hash output size and validate it.                                           | PAL_SUCCESS |
* | 18 | Get the calculated hash and compare it.                                             | PAL_SUCCESS |
* | 19 | Free the MD context resources.                                                      | PAL_SUCCESS |
* | 20 | Free allocated buffer.                                                              | PAL_SUCCESS |
*/
PAL_PRIVATE void socketUDPBuffered(size_t bufSize)
{
    palStatus_t result = PAL_SUCCESS;
    pal_udp_test_data_t data = { PAL_NET_TEST_BUFFERED_UDP_MESSAGE_SIZE, bufSize, 0 };
    uint8_t expectedHash[PAL_SHA256_SIZE] = { 0 }, actualHash[PAL_SHA256_SIZE] = { 0 };
    size_t read = 0, totalRead = 0, hashlen = 0;
    int timeout = PAL_MILLI_PER_SECOND;
    palMDHandle_t handle = NULLPTR;
    palThreadID_t thread = NULLPTR;

    /*#1*/
    result = pal_mdInit(&handle, PAL_SHA256);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_NOT_EQUAL(NULLPTR, handle);

    /*#2*/
    g_testRecvBuffer = (uint8_t*)malloc(sizeof(uint8_t) * bufSize);
    TEST_ASSERT_NOT_EQUAL(NULLPTR, g_testRecvBuffer);

    /*#3*/
    data.totalSize = data.chunkSize = 0;
    data.currentValue = data.startValue;
    while (data.totalSize != data.messageSize)
    {
        fillUDPTestBuffer(&data, g_testRecvBuffer);
        result = pal_mdUpdate(handle, g_testRecvBuffer, data.chunkSize);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    };

    /*#4*/
    result = pal_mdGetOutputSize(handle, &hashlen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(PAL_SHA256_SIZE, hashlen);

    /*#5*/
    result = pal_mdFinal(handle, expectedHash);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_mdFree(&handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    memset(&(data.interfaceInfo), 0, sizeof(data.interfaceInfo));
    result = pal_getNetInterfaceInfo(0, &(data.interfaceInfo));
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        goto end;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#8*/
    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_DGRAM, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#9*/
    result = pal_setSockAddrPort(&(data.interfaceInfo.address), PAL_NET_TEST_BUFFERED_UDP_PORT);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_RCVTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_SNDTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_SNDTIMEO_EXPECTED_RESULT, result);

    /*#10*/
    result = pal_bind(g_testSockets[0], &(data.interfaceInfo.address), data.interfaceInfo.addressSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#11*/
    handle = NULLPTR;
    result = pal_mdInit(&handle, PAL_SHA256);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_NOT_EQUAL(NULLPTR, handle);

    /*#12*/
    result = pal_osThreadCreateWithAlloc(socketUDPBufferedTestSender, &data, PAL_osPriorityNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &thread);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_NOT_EQUAL(NULLPTR, thread);

    /*#13*/
    do
    {
        read = 0;
        memset(g_testRecvBuffer, 0, data.bufferSize);
        result = pal_receiveFrom(g_testSockets[0], g_testRecvBuffer, data.bufferSize, &(data.interfaceInfo.address), &(data.interfaceInfo.addressSize), &read);

        /*#14*/
        if (result == PAL_SUCCESS) {
            totalRead += read;
            pal_mdUpdate(handle, g_testRecvBuffer, read);
        }

        pal_osSemaphoreWait(s_semaphoreID3, 100, &temp);

    } while (totalRead < data.messageSize);


    /*#15*/
    result = pal_osThreadTerminate(&thread);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#16*/
    result = pal_close(&g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#17*/
    hashlen = 0;
    result = pal_mdGetOutputSize(handle, &hashlen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(PAL_SHA256_SIZE, hashlen);

    /*#18*/
    result = pal_mdFinal(handle, actualHash);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_MEMORY(expectedHash, actualHash, PAL_SHA256_SIZE);

    /*#19*/
    result = pal_mdFree(&handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    pal_osSemaphoreRelease(s_semaphoreID3);
    pal_osSemaphoreDelete(&s_semaphoreID3);

    /*#20*/
end:
    free(g_testRecvBuffer);
    g_testRecvBuffer = NULLPTR;
}

/*! \brief Test function UDP socket read in small chunks
*
** \test
*/
TEST(pal_socket, socketUDPBufferedSmall)
{
    socketUDPBuffered(PAL_NET_TEST_BUFFERED_BUF_SIZE_SMALL);
}

/*! \brief Test function UDP socket read in large chunks
*
** \test
*/
TEST(pal_socket, socketUDPBufferedLarge)
{
    socketUDPBuffered(PAL_NET_TEST_BUFFERED_BUF_SIZE_LARGE);
}


/*! \brief Test TCP socket read in chunks
*
* \note The test attempts to perform an HTTP get request to a google (jquery) CDN, read the file in chunks (ignoring HTTP headers) and compare its hash to a pre-known hash using SHA256.
*
* @param[in]    bufSize - the read buffer size
*
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a async TCP socket.                                                               | PAL_SUCCESS |
* | 2 | Look up the IP address of the CDN server.                                                           | PAL_SUCCESS |
* | 3 | Set the port to the CDN server's HTTP port and set send/receive timeouts.                           | PAL_SUCCESS |
* | 4 | Connect the socket to the CDN server.                                                               | PAL_SUCCESS |
* | 5 | Send an HTTP get request to the CDN server.                                                         | PAL_SUCCESS |
* | 6 | Initialize the MD context.                                                                          | PAL_SUCCESS |
* | 7 | Allocate HTTP response buffer.                                                                      | PAL_SUCCESS |
* | 8 | Read the server's response until there's no more data to read.                                      | PAL_SUCCESS |
* | 9 | If we're done dealing with the HTTP headers then update the MD context.                             | PAL_SUCCESS |
* | 10 | Locate the end of the HTTP headers in the server's response (HTTP headers end with a double CRLF). | PAL_SUCCESS |
* | 11 | Update the MD context.                                                                             | PAL_SUCCESS |
* | 12 | Close the socket.                                                                                  | PAL_SUCCESS |
* | 13 | Get the hash output size and validate it.                                                          | PAL_SUCCESS |
* | 14 | Get the calculated hash and compare it to the pre-known hash.                                      | PAL_SUCCESS |
* | 15 | Free the MD context resources.                                                                     | PAL_SUCCESS |
* | 16 | Free HTTP response buffer.                                                                         | PAL_SUCCESS |
*/
PAL_PRIVATE void socketTCPBuffered(size_t bufSize)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    palSocketLength_t addrlen = 0;
    int timeout = 5000;
    size_t read = 0, sent = 0, hashlen = 0;
    bool body = false;
    palMDHandle_t handle = NULLPTR;
    uint8_t actualHash[PAL_SHA256_SIZE] = { 0 };
    const uint8_t expectedHash[] = // pre-calculated jquery.js 3.2.1 SHA256
    {
        0x0d, 0x90, 0x27, 0x28, 0x9f, 0xfa, 0x5d, 0x9f, 0x6c, 0x8b, 0x4e, 0x07, 0x82, 0xbb, 0x31, 0xbb,
        0xff, 0x2c, 0xef, 0x5e, 0xe3, 0x70, 0x8c, 0xcb, 0xcb, 0x7a, 0x22, 0xdf, 0x91, 0x28, 0xbb, 0x21
    };

    /*#2*/
    result = doDnsQuery(PAL_NET_TEST_GOOGLE_CDN_HOST, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#1*/
    result = pal_asynchronousSocket(address.addressType, PAL_SOCK_STREAM, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_NET_TEST_GOOGLE_CDN_HOST_PORT);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_SNDTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_SNDTIMEO_EXPECTED_RESULT, result);
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_RCVTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);

    /*#4*/
    do {
        result = pal_connect(g_testSockets[0], &address, addrlen);
        pal_osSemaphoreWait(s_semaphoreID3, 10000, &temp);
    } while (result == PAL_ERR_SOCKET_IN_PROGRES || result == PAL_ERR_SOCKET_WOULD_BLOCK);

    if (result == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
        result = PAL_SUCCESS;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#5*/
    result = pal_send(g_testSockets[0], PAL_NET_TEST_GOOGLE_CDN_REQUEST, sizeof(PAL_NET_TEST_GOOGLE_CDN_REQUEST) - 1, &sent);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_mdInit(&handle, PAL_SHA256);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_NOT_EQUAL(NULLPTR, handle);

    /*#7*/
    g_testRecvBuffer = (uint8_t*)malloc(sizeof(uint8_t) * bufSize + 1);
    TEST_ASSERT_NOT_EQUAL(NULLPTR, g_testRecvBuffer);

    /*#8*/
    palStatus_t md_result = PAL_SUCCESS;
    do
    {
        read = 0;
        memset(g_testRecvBuffer, 0, bufSize + 1);
        result = pal_recv(g_testSockets[0], g_testRecvBuffer, bufSize, &read);

        /*#9*/
        if (body && result == PAL_SUCCESS)
        {
            md_result = pal_mdUpdate(handle, g_testRecvBuffer, read);
            continue;
        }

        /*#10*/
        // HTTP header ends with double CRLF
        const char *body_start = strstr((char*)g_testRecvBuffer, "\r\n\r\n");
        if (body_start) {
            body = true;
            md_result = pal_mdUpdate(handle, (const unsigned char *)(body_start + 4), strlen(body_start + 4));
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, md_result);
        }
    } while (read > 0 || result == PAL_ERR_SOCKET_WOULD_BLOCK);

    /*#12*/
    result = pal_close(&g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#13*/
    result = pal_mdGetOutputSize(handle, &hashlen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(PAL_SHA256_SIZE, hashlen);

    /*#14*/
    result = pal_mdFinal(handle, actualHash);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_MEMORY(expectedHash, actualHash, PAL_SHA256_SIZE);

    /*#15*/
    result = pal_mdFree(&handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    pal_osSemaphoreRelease(s_semaphoreID3);
    pal_osSemaphoreDelete(&s_semaphoreID3);

    /*#16*/
    free(g_testRecvBuffer);
    g_testRecvBuffer = NULLPTR;

}

/*! \brief Test function TCP socket read in small chunks
*
** \test
*/
TEST(pal_socket, socketTCPBufferedSmall)
{
    socketTCPBuffered(PAL_NET_TEST_BUFFERED_BUF_SIZE_SMALL);
}

/*! \brief Test function TCP socket read in large chunks
*
** \test
*/
TEST(pal_socket, socketTCPBufferedLarge)
{
    socketTCPBuffered(PAL_NET_TEST_BUFFERED_BUF_SIZE_LARGE);
}

#if (PAL_DNS_API_VERSION == 1)

// flag marking if the pal_getAddressInfoAsync callback has been invoked
PAL_PRIVATE bool g_getAddressInfoAsyncCallbackInvoked = false;

// callback invoked from the call to pal_getAddressInfoAsync
PAL_PRIVATE void getAddressInfoAsyncCallback(const char* hostname, palSocketAddress_t* address, palSocketLength_t* addressLength, palStatus_t status, void* arg)
{
    palStatus_t* statusArg = (palStatus_t*)arg;
    *statusArg = status;
    g_getAddressInfoAsyncCallbackInvoked = true;
}
#endif

/*! \brief Test get address info asynchronously
** \test
* | # |    Step                                                                                               |  Expected   |
* |---|-------------------------------------------------------------------------------------------------------|-------------|
* | 1 | Invoke an asynchronous get address info.                                                              | PAL_SUCCESS |
* | 2 | Check that callback is called.                                          | PAL_SUCCESS |
*/
TEST(pal_socket, getAddressInfoAsync)
{
#if (PAL_DNS_API_VERSION == 2)
    palSocketAddress_t addressAsync = { 0 };
    palSocketLength_t addrlenAsync = 0;
    palStatus_t status;

    /*#1*/
    status = doDnsQuery(PAL_NET_TEST_SERVER_NAME, &addressAsync, &addrlenAsync);
    if ((PAL_ERR_SOCKET_DNS_ERROR == status) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == status))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        return;
    }
    TEST_ASSERT_TRUE_MESSAGE((PAL_SUCCESS == status), "Asynchronous call to pal_getAddressInfo failed");

    /*#2*/
    TEST_ASSERT_TRUE_MESSAGE(g_getAddressInfoAsyncCallbackInvoked, "getAddressInfoAsyncCallback was not invoked");
    g_getAddressInfoAsyncCallbackInvoked = false;

#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_DNS_API_VERSION not 2");
#endif // (PAL_DNS_API_VERSION == 2)
}


/*! \brief Test pal socket APIs input parameter validations
** \test
*/
TEST(pal_socket, socketApiInputParamValidation)
{
#ifdef DEBUG
    palStatus_t status;
    palSocketAddress_t addr;
    addr.addressType = PAL_AF_UNSPEC;
    uint16_t port = 0;

    status = pal_registerNetworkInterface(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_setSockAddrPort(NULL, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_setSockAddrPort(&addr, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY, status);
#if PAL_SUPPORT_IP_V4
    status = pal_setSockAddrIPV4Addr(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getSockAddrIPV4Addr(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getSockAddrIPV4Addr(&addr, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY, status);
#endif
#if PAL_SUPPORT_IP_V6
    status = pal_setSockAddrIPV6Addr(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getSockAddrIPV6Addr(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getSockAddrIPV6Addr(&addr, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY, status);
#endif
    status = pal_getSockAddrPort(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getSockAddrPort(&addr, &port);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY, status);
    status = pal_setSocketOptions(NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_isNonBlocking(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_bind(NULL, NULL, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_receiveFrom(NULL, NULL, 0, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_sendTo(NULL, NULL, 0, NULL, 0, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_close(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getNumberOfNetInterfaces(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_getNetInterfaceInfo(0, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#if PAL_NET_TCP_AND_TLS_SUPPORT

#if PAL_NET_SERVER_SOCKET_API
    status = pal_accept(NULL, NULL, NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif // PAL_NET_SERVER_SOCKET_API

    status = pal_connect(NULL, NULL, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_recv(NULL, NULL, 0, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_send(NULL, NULL, 0, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif // PAL_NET_TCP_AND_TLS_SUPPORT
    status = pal_asynchronousSocketWithArgument(PAL_AF_UNSPEC, PAL_SOCK_DGRAM, true, 0, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#if PAL_NET_DNS_SUPPORT && ((PAL_DNS_API_VERSION == 0) || (PAL_DNS_API_VERSION == 1))
    status = pal_getAddressInfo(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#if (PAL_DNS_API_VERSION == 2)
    status = pal_getAddressInfoAsync(NULL, NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif
#endif // PAL_NET_DNS_SUPPORT
#else
    TEST_IGNORE_MESSAGE("Ignored, DEBUG not defined");
#endif //DEBUG
}

#ifdef PAL_TEST_KEEPALIVE
PAL_PRIVATE void keepAliveFunc(bool keepalive)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    char buffer[100] = { 0 };
    size_t read = 0;
    palSocketLength_t addrlen = 0;
    int timeout = PAL_MILLI_PER_SECOND;
    int KeepAliveOn = 0, KeepAliveIntvl = 0, KeepAliveIdle = 0;
    int keepaliveNumber=0;

    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    if (keepalive)
    {
        KeepAliveOn=1;
        KeepAliveIntvl=1;
        KeepAliveIdle =1;
    }

    /*#1*/
    result = pal_asynchronousSocket(PAL_AF_INET, PAL_SOCK_STREAM, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#2*/
    result = doDnsQuery(PAL_TEST_KEEPALIVE_SERVER_ADDRESS, &addressSync, &addrlenSync);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        goto end;
    }
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, PAL_TEST_SERVER_KEEPALIVE_PORT);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_SNDTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_SNDTIMEO_EXPECTED_RESULT, result);
    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_RCVTIMEO, &timeout, sizeof(timeout));
    TEST_ASSERT_EQUAL_HEX(PAL_SO_RCVTIMEO_EXPECTED_RESULT, result);

    result = pal_setSocketOptions(g_testSockets[0], PAL_SO_KEEPALIVE, &KeepAliveOn, sizeof(KeepAliveOn));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    if (keepalive) {
        result = pal_setSocketOptions(g_testSockets[0], PAL_SO_KEEPIDLE, &KeepAliveIdle, sizeof(KeepAliveIdle));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        result = pal_setSocketOptions(g_testSockets[0], PAL_SO_KEEPINTVL, &KeepAliveIntvl, sizeof(KeepAliveIntvl));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }

    /*#4*/
    do {
        result = pal_connect(g_testSockets[0], &address, sizeof(palSocketAddress_t));
        pal_osSemaphoreWait(s_semaphoreID3, 10000, &temp);
    } while (result == PAL_ERR_SOCKET_INTERRUPTED);

    if (result != PAL_SUCCESS)
    {
        PAL_LOG_ERR("Unable to connect to %s", PAL_TEST_KEEPALIVE_SERVER_ADDRESS);
    }
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    /*#6*/
    while (result != PAL_ERR_SOCKET_CONNECTION_CLOSED)
    {
        result = pal_recv(g_testSockets[0], buffer, sizeof(buffer)-1 , &read);
        if (result != PAL_ERR_SOCKET_CONNECTION_CLOSED)
        {
            if((read != 0) && (buffer[0]!=0))
            {
                keepaliveNumber=atoi(buffer);
                if (keepalive){
                    TEST_ASSERT_TRUE(keepaliveNumber > PAL_TEST_KEEPALIVE_NUM_OF_ACK);
                }
                else{
                    TEST_ASSERT_TRUE(keepaliveNumber < PAL_TEST_KEEPALIVE_NUM_OF_ACK);
                }
                break;
            }
        }

    }
end:
    result = pal_close(&g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);
}
#endif // #ifdef PAL_TEST_KEEPALIVE
/*! \brief Test keepAlive On/Off
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a blocking async TCP socket using `pal_asynchronousSocket`.                        			| PAL_SUCCESS |
* | 2 | Look up the IP address of the test server using `pal_getAddressInfo`.                          		| PAL_SUCCESS |
* | 3 | Set the port to a test port in the address structure using `pal_setSockAddrPort` and set timeout. 	| PAL_SUCCESS |
* | 4 | Set keepalive socket options : if keepalive is on set keepalibe idel and intvl  . 					| PAL_SUCCESS |
* | 5 | Connect the socket to the test server using `pal_connect`.                                    	 	| PAL_SUCCESS |
* | 6 | Receive (blocking) the server's response using `pal_recv` and check it keepalive packates sent. 	| PAL_SUCCESS |
* | 7 | Close the socket.                                                                        			| PAL_SUCCESS |
*/

TEST(pal_socket, keepaliveOn)
{
#ifdef PAL_TEST_KEEPALIVE
    keepAliveFunc(true);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_TEST_KEEPALIVE not defined");
#endif
}

TEST(pal_socket, keepaliveOff)
{
#ifdef PAL_TEST_KEEPALIVE
    keepAliveFunc(false);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_TEST_KEEPALIVE not defined");
#endif
}

/*! \brief /b tcp_echo checks the asynchronous- nonblocking socket scenario using tcp.
** \test
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Look up the IP address of the test server using `pal_getAddressInfo`.                        | PAL_SUCCESS |
* | 2 | Create an asynchronous non-blocking TCP socket with `nonBlockCallback` as callback.     | PAL_SUCCESS |
* | 3 | Set the port to test port in the address structure using `pal_setSockAddrPort`.              | PAL_SUCCESS |
* | 4 | Connect the socket.                                                                    | PAL_SUCCESS or PAL_ERR_SOCKET_IN_PROGRES |
* | 5 | Send a test message to the test server using `pal_send` (repeat until success).           | PAL_SUCCESS or PAL_ERR_SOCKET_IN_PROGRES |
* | 6 | Wait for the callback and receive server response using `pal_recv` (repeat until success). | PAL_SUCCESS or PAL_ERR_SOCKET_WOULD_BLOCK|
* | 7 | Close the socket.                                                                      | PAL_SUCCESS |
*/
PAL_PRIVATE void echo_test(bool tcp)
{
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    const char* message = "Test string to be sent to echo server, and expected to be returned by the echo server.";
    size_t sent = 0;
    char buffer[100] = { 0 };
    size_t read = 0;
    size_t tot_read = 0;
    palSocketLength_t addrlen = 0;
    palSocketType_t sockType;

    TEST_ASSERT_MESSAGE(sizeof(buffer) / sizeof(char) > strlen(message), "buffer too small to contain test message");

    if (tcp)
    {
        sockType = PAL_SOCK_STREAM;
    }
    else
    {
        sockType = PAL_SOCK_DGRAM;
    }

    /*#1*/
    result = doDnsQuery(PAL_NET_TEST_ECHO_TEST_SERVER_ADDRESS, &address, &addrlen);
    if ((PAL_ERR_SOCKET_DNS_ERROR == result) || (PAL_ERR_SOCKET_INVALID_ADDRESS_FAMILY == result))
    {
        PAL_LOG_ERR("error: address lookup returned an address not supported by current configuration cant continue test ( IPv6 add for IPv4 only configuration or IPv4 for IPv6 only configuration)");
        return;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    int32_t temp;
    result = pal_osSemaphoreCreate(1, &s_semaphoreID3);
    TEST_ASSERT_EQUAL_HEX( PAL_SUCCESS, result);

    result = pal_asynchronousSocket(address.addressType, sockType, true, 0, socketCallback3, &g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_setSockAddrPort(&address, 7);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#4*/
    if (sockType == PAL_SOCK_STREAM)
    {
        do {
            result = pal_connect(g_testSockets[0], &address, addrlen);
            pal_osSemaphoreWait(s_semaphoreID3, 10000, &temp);
        } while (result == PAL_ERR_SOCKET_IN_PROGRES || result == PAL_ERR_SOCKET_WOULD_BLOCK);

        if (result == PAL_ERR_SOCKET_ALREADY_CONNECTED) {
            result = PAL_SUCCESS;
        }
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }

    /*#5*/
    do {
        if (sockType == PAL_SOCK_STREAM)
        {
            result = pal_send(g_testSockets[0], message, strlen(message), &sent);
        }
        else
        {
            result = pal_sendTo(g_testSockets[0], message, strlen(message), &address, addrlen, &sent);
        }
        pal_osSemaphoreWait(s_semaphoreID3, 1000, &temp);
    } while (PAL_ERR_SOCKET_WOULD_BLOCK == result);

    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    do {
        read = 0;
        if (sockType == PAL_SOCK_STREAM)
        {
            result = pal_recv(g_testSockets[0], buffer + tot_read, 100, &read);
        }
        else
        {
            result = pal_receiveFrom(g_testSockets[0], buffer + tot_read, 100, &address, &addrlen, &read);
        }

        if (result == PAL_SUCCESS)
        {
            tot_read += read;
        }
        pal_osSemaphoreWait(s_semaphoreID3, 1000, &temp);
    } while (result == PAL_ERR_SOCKET_WOULD_BLOCK);

    /*#7*/
    pal_close(&g_testSockets[0]);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL(strlen(message), tot_read);
    TEST_ASSERT_EQUAL_STRING(message, buffer);

    pal_osSemaphoreRelease(s_semaphoreID3);
    pal_osSemaphoreDelete(&s_semaphoreID3);
}

TEST(pal_socket, tcp_echo)
{
    echo_test(true);
}

TEST(pal_socket, udp_echo)
{
    echo_test(false);
}

#ifdef TARGET_LIKE_MBED
void network_status_event_cb(palNetworkStatus_t status, void *client_arg)
{
    if (status == PAL_NETWORK_STATUS_CONNECTED) {
        PAL_PRINTF("Interface connected!");
        g_interfaceConnected = true;
    } else {
        PAL_PRINTF("Interface disconnected!");
        g_interfaceConnected = false;
    }
}
#endif

TEST(pal_socket, interfaceStatusListener)
{
#ifdef TARGET_LIKE_MBED
    palStatus_t result = PAL_SUCCESS;

    result = pal_registerNetworkInterface(g_palTestNetworkInterface, &g_interfaceCTXIndex);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    result = pal_setConnectionStatusCallback(g_interfaceCTXIndex, &network_status_event_cb, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    g_interfaceConnected = true;
    mcc_platform_close_connection();
    TEST_ASSERT_EQUAL(g_interfaceConnected, false);

    mcc_platform_init_connection();
    TEST_ASSERT_EQUAL(g_interfaceConnected, true);
#else
    TEST_IGNORE_MESSAGE("Currently only supported on mbed-os!");
#endif
}
