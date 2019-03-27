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

#include "pal.h"
#include "unity.h"
#include "unity_fixture.h"
#include "pal_plat_rot.h"
#include "pal_sst.h"
#include <string.h>
#include <stdlib.h>
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal_sst.h"
#else
#include "sotp.h"
#endif
#if (PAL_USE_HW_ROT == 1)
#ifdef __SXOS__
#include "hal_sys.h"
#ifndef ROT_MEM_ADDR
#define ROT_MEM_ADDR  0x00001000
#endif
bool rot_key_set = false;
#endif
#endif

#define TRACE_GROUP "PAL"
TEST_GROUP(pal_rot);

uint8_t setRoTKey[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }; //16 bytes=128bit

TEST_SETUP(pal_rot)
{
    palStatus_t status = PAL_SUCCESS;

    //init pal
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
// reset storage before each tests to avoid possible RoT leftovers
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    pal_SSTReset();
#if !PAL_USE_HW_TRNG
    // If no hardware trng - entropy must be injected for random to work
    uint8_t entropy_buf[48] = { 0 };
    status = pal_osEntropyInject(entropy_buf, sizeof(entropy_buf));
    TEST_ASSERT(status == PAL_SUCCESS || status == PAL_ERR_ENTROPY_EXISTS);
#endif

#else
    sotp_reset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#if (PAL_USE_HW_ROT == 1)
#ifdef __SXOS__
    // SXOS sets ROT to secure section of chip
    if (rot_key_set == false) {
        uint32_t csStatus = hal_SysEnterCriticalSection();
        memd_Flash_security_REG_Write(ROT_MEM_ADDR, sizeof(setRoTKey), 0, setRoTKey);
        hal_SysExitCriticalSection(csStatus);
        rot_key_set = true;
    }
#endif
#endif
}

TEST_TEAR_DOWN(pal_rot)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    pal_SSTReset();
#else
    sotp_reset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    pal_destroy();
}

/*! \brief Check derivation of keys from the platform's Root of Trust using the KDF algorithm.
 *
 * 
 *
* | # |    Step                                                                        |   Expected  |
* |---|--------------------------------------------------------------------------------|-------------|
* | 1 | Start a loop to perform the following steps.                                   |             |
* | 2 | Derive a device key for encryption using `pal_osGetDeviceKey`.                 | PAL_SUCCESS |
* | 3 | Derive a device key for signing using `pal_osGetDeviceKey`.                    | PAL_SUCCESS |
* | 4 | Call `pal_osGetDeviceKey` with invalid arguments.                              | PAL_FAILURE |
* | 5 | Call `pal_osGetDeviceKey` with invalid arguments.                              | PAL_FAILURE |
* | 6 | Check that the derived signing and encryption keys are different.              | PAL_SUCCESS |
* | 7 | Check that all integrations of each type of derivation return the same value.  | PAL_SUCCESS |
 */
TEST(pal_rot, GetDeviceKeyTest_CMAC)
{

#ifndef  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    size_t keyLenBytes = 16;
    uint8_t timesToDerive = 4;
    unsigned char encKeyDerive[timesToDerive][keyLenBytes]; //16 bytes=128bit
    unsigned char signKeyDerive[timesToDerive][keyLenBytes]; //16 bytes=128bit
    /*#1*/
    for (int i=0; i < timesToDerive; i++)
    {
        /*#2*/
        status = pal_osGetDeviceKey(palOsStorageEncryptionKey128Bit, encKeyDerive[i], keyLenBytes);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#3*/
        status = pal_osGetDeviceKey(palOsStorageSignatureKey128Bit,  signKeyDerive[i], keyLenBytes);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#4*/
        status = pal_osGetDeviceKey(palOsStorageSignatureKey128Bit,  signKeyDerive[i], keyLenBytes-1);
        TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, status);
        /*#5*/
        status = pal_osGetDeviceKey(palOsStorageSignatureKey128Bit,  NULL, keyLenBytes);
        TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, status);
        /*#6*/
        status = memcmp(encKeyDerive[i], signKeyDerive[i], keyLenBytes);
        TEST_ASSERT_NOT_EQUAL(status,0); //The keys MUST be different!
        /*#7*/
        if (i > 0) //Make sure key derivation is persistent every time
        {
            TEST_ASSERT_EQUAL_MEMORY(encKeyDerive[i-1], encKeyDerive[i], keyLenBytes);
            TEST_ASSERT_EQUAL_MEMORY(signKeyDerive[i-1], signKeyDerive[i], keyLenBytes);

        } //if

    } //for

#else // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is set ");
#endif

}

/*! \brief Check derivation of keys from the platform's Root of Trust using the KDF algorithm.
 *
 * 
 *
* | # |    Step                                                                        | Expected            |
* |---|--------------------------------------------------------------------------------|---------------------|
* | 1 | Start a loop to perform the following steps.                                   |                     |
* | 2 | Derive a device key for encryption using `pal_osGetDeviceKey`.                 | PAL_SUCCESS         |
* | 3 | Call `pal_osGetDeviceKey` with invalid arguments.                              | PAL_FAILURE         |
* | 4 | Call `pal_osGetDeviceKey` with invalid arguments.                              | PAL_FAILURE         |
* | 5 | Check that all integrations of each type of derivation return the same value.  | PAL_SUCCESS         |
* | 6 | Call `pal_osGetDeviceKey` with invalid palDevKeyType_t.                        | PAL_ERR_INVALID_ARGUMENT |
 */

TEST(pal_rot, GetDeviceKeyTest_HMAC_SHA256)
{

#ifndef  MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    size_t keyLenBytes = 32;
    uint8_t timesToDerive = 4;
    unsigned char encKeyDerive[timesToDerive][keyLenBytes]; //32 bytes=256bit
    /*#1*/
    for (int i = 0; i < timesToDerive; i++)
    {
        /*#2*/
        status = pal_osGetDeviceKey(palOsStorageHmacSha256, encKeyDerive[i], keyLenBytes);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#ifdef DEBUG
        /*#3*/
        status = pal_osGetDeviceKey(palOsStorageHmacSha256,  encKeyDerive[i], keyLenBytes-1);

        TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, status);
        /*#4*/
        status = pal_osGetDeviceKey(palOsStorageHmacSha256,  NULL, keyLenBytes);
        TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, status);
#endif
        /*#5*/
        if (i > 0) //Make sure key derivation is persistent every time
        {
            TEST_ASSERT_EQUAL_MEMORY(encKeyDerive[i-1], encKeyDerive[i], keyLenBytes);
        } //if

    } //for

#ifdef DEBUG
      /*#6*/
    status = pal_osGetDeviceKey((palDevKeyType_t)999, encKeyDerive[0], keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif

#else // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is set ");
#endif
}


/*! \brief Check rot key from the platform's Root of Trust.
*
*
*
* | # |    Step                                                                        | Expected            |
* |---|--------------------------------------------------------------------------------|---------------------|
* | 1 | Start a loop to perform the following steps.                                   |                     |
* | 2 | Get ROT  key  using `pal_plat_osGetRoT`.                                       | PAL_SUCCESS |
* | 3 | Get ROT  key  using `pal_plat_osGetRoT`.                                       | PAL_SUCCESS |
* | 4 | Get ROT  key  using `pal_plat_osGetRoT` with wrong size.                       | PAL_FAILURE |
* | 5 | Get ROT  key  using `pal_plat_osGetRoT` with null pointer buffer.              | PAL_FAILURE |
* | 6 | Check that both buffers from 2 and 3 are the same                              | PAL_SUCCESS |
* | 7 | Check that all integrations return the same value.                             | PAL_SUCCESS |
*/
TEST(pal_rot, GetRoTKeyTest)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    size_t keyLenBytes = 16;
    uint8_t timesToDerive = 4;
    unsigned char encKeyDerive[timesToDerive][keyLenBytes]; //16 bytes=128bit
    unsigned char signKeyDerive[timesToDerive][keyLenBytes]; //16 bytes=128bit
    char *data_vector = "data_vector";

    //Set data with confidentiality flag, this operation will initiate generation of RoT on platforms that support TRNG.
    status =   pal_SSTSet("test_data", data_vector, strlen(data_vector), PAL_SST_CONFIDENTIALITY_FLAG);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
                                                             /*#1*/
    for (int i = 0; i < timesToDerive; i++)
    {

        /*#2*/
        status = pal_plat_osGetRoT(encKeyDerive[i], keyLenBytes);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#3*/
        status = pal_plat_osGetRoT(signKeyDerive[i], keyLenBytes);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        /*#4*/
        status = pal_plat_osGetRoT(signKeyDerive[i], keyLenBytes - 1);
        TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, status);
        /*#5*/
        status = pal_plat_osGetRoT(NULL, keyLenBytes);
        TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, status);
        /*#6*/
        status = memcmp(encKeyDerive[i], signKeyDerive[i], keyLenBytes);
        TEST_ASSERT_EQUAL(status, 0); //The ROT must be the same 
        /*#7*/
        if (i > 0) //Make sure key is persistent every time
        {
            TEST_ASSERT_EQUAL_MEMORY(encKeyDerive[i - 1], encKeyDerive[i], keyLenBytes);
            TEST_ASSERT_EQUAL_MEMORY(signKeyDerive[i - 1], signKeyDerive[i], keyLenBytes);
        } //if
    } //for


#else // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is not set ");
#endif

}


/*! \brief Check set rot key.
*
*
*
* | # |    Step                                                                        | Expected            |
* |---|--------------------------------------------------------------------------------|---------------------|
* | 1 | Read ROT  key  using `pal_plat_osGetRoT`                                       | PAL_ERR_ITEM_NOT_EXIST  |
* | 2 | Set ROT  key  using `pal_osSetRoT`.                                            | PAL_SUCCESS |
* | 3 | Read ROT  key  using `pal_plat_osGetRoT`                                       | PAL_SUCCESS |
* | 4 | Compare read rot buffer with set rot buffer`                                   | PAL_SUCCESS |
* | 5 | Set ROT  key  using `pal_osSetRoT`.                                            | PAL_ERR_ITEM_EXIST |
* | 6 | Read ROT  key  using `pal_plat_osGetRoT`                                       | PAL_SUCCESS |
* | 7 | Compare read rot buffer with set rot buffer`                                   | PAL_SUCCESS |
*/

TEST(pal_rot, SeTRoTKeyTest)
{
    palStatus_t status = PAL_SUCCESS;
    size_t keyLenBytes = 16;
    uint8_t readRoTKey[keyLenBytes]; //16 bytes=128bit

#if (PAL_USE_HW_ROT == 0)
    /*#1*/
    status = pal_plat_osGetRoT(readRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_ITEM_NOT_EXIST, status);
    /*#2*/
    status = pal_osSetRoT(setRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_plat_osGetRoT(readRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = memcmp(readRoTKey, setRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL(status, 0); //The ROT must be the same 
    /*#5*/
    status = pal_osSetRoT(setRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_ITEM_EXIST, status);
    /*#6*/
    status = pal_plat_osGetRoT(readRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#7*/
    status = memcmp(readRoTKey, setRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL(status, 0); //The ROT must be the same 
#else // PAL_USE_HW_ROT =1
#ifdef __SXOS__
    status = pal_plat_osGetRoT(readRoTKey, keyLenBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(setRoTKey, readRoTKey, keyLenBytes);
#else
    TEST_IGNORE_MESSAGE("Ignored, for configuration  PAL_USE_HW_ROT=1, set pal_osSetRoT is not implemented ");
#endif
#endif
}
