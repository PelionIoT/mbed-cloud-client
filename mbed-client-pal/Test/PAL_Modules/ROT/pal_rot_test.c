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
#include "unity.h"
#include "unity_fixture.h"

#include "pal_plat_rot.h"


#include <string.h>
#include <stdlib.h>

#define TRACE_GROUP "PAL"

TEST_GROUP(pal_rot);


TEST_SETUP(pal_rot)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

}

TEST_TEAR_DOWN(pal_rot)
{
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
    palStatus_t status = PAL_SUCCESS;
    size_t keyLenBytes = 32;
    uint8_t timesToDerive = 4;
    unsigned char encKeyDerive[timesToDerive][keyLenBytes]; //32 bytes=256bit
    /*#1*/
    for (int i=0; i < timesToDerive; i++)
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
}

