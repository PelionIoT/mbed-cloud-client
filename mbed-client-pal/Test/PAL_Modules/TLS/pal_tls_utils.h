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

#ifndef TEST_TLS_PAL_TEST_UTILS_H_
#define TEST_TLS_PAL_TEST_UTILS_H_

#define DTLS_SERVER_PORT_TIMEOUT 9 //Discard protocol

/* Workaround for Linux and Freertos builds. Cloud credentials must be defined in build
 * before running tests. Now just defined as NULL to make build work.
*/
#if defined (__LINUX__) ||  defined(__FREERTOS__)

#if defined (__CC_ARM)          /* ARM compiler. */
    #warning("You must define mbed cloud credentials before running TLS tests")
#else
    #pragma message ("You must define mbed cloud credentials before running TLS tests")
#endif

/* Defined as NULL */
#define MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI NULL
#define MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY NULL
#define MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE NULL
#define MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE NULL

#else

extern const char MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI[];
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY[];
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE[];
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE[];

#endif /* defined (__LINUX__) ||  defined(__FREERTOS__) */

#define PAL_TLS_TEST_SERVER_ADDRESS_UDP MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI
#define PAL_TLS_TEST_SERVER_ADDRESS_TCP MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI
#define PAL_TLS_TEST_DEVICE_PRIVATE_KEY MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY
#define PAL_TLS_TEST_SERVER_CA MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE
#define PAL_TLS_TEST_DEVICE_CERTIFICATE MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE

// Bootstrap server responds to 'coap ping'

// confirmable empty message with id 0
const unsigned char coap_ping_message[] = {
    0x40, 0x00, 0x00, 0x00
};

// reset empty with message id 0
const unsigned char coap_ping_response[] = {
    0x70, 0x00, 0x00, 0x00
};

#define PAL_TLS_REQUEST_MESSAGE coap_ping_message
#define PAL_TLS_UDP_REQUEST_MESSAGE coap_ping_message
#define PAL_TLS_RESPONSE_MESSAGE coap_ping_response
#define PAL_TLS_RESPONSE_SIZE sizeof(coap_ping_response)

const uint16_t MAX_CERTIFICATE_SIZE = 1024;

#if (PAL_ENABLE_PSK == 1)
const unsigned char g_psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const unsigned char g_psk_id[] = "Client_identity";
#endif /* (PAL_ENABLE_PSK == 1) */
#endif /* TEST_TLS_PAL_TEST_UTILS_H_ */
