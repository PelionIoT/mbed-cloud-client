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
#include "test_runners.h"

#include <string.h>
#include <stdlib.h>
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "psa/crypto.h"
#endif

#define TRACE_GROUP "PAL"

TEST_GROUP(pal_drbg);

#define PAL_RANDOM_TEST_LOOP 100000
#define PAL_RANDOM_ARRAY_TEST_SIZE 100
#define PAL_RANDOM_BUFFER_ARRAY_TEST_SIZE 60

#define PAL_RUNNING_TEST_TIME   5  //estimation on length of test in seconds
#define PAL_TEST_HIGH_RES_TIMER 100
#define PAL_TEST_HIGH_RES_TIMER2 10
#define PAL_TEST_PERCENTAGE_LOW 95
#define PAL_TEST_PERCENTAGE_HIGH 105
#define PAL_TEST_PERCENTAGE_HUNDRED  100


TEST_SETUP(pal_drbg)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if !PAL_USE_HW_TRNG
    // If no hardware trng - entropy must be injected for random to work
    uint8_t entropy_buf[48] = { 0 };
    status = pal_osEntropyInject(entropy_buf, sizeof(entropy_buf));
    TEST_ASSERT(status == PAL_SUCCESS || status == PAL_ERR_ENTROPY_EXISTS);
#endif

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    // After entropy is injected, it is safe to initialize PSA
    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);
#endif


}

TEST_TEAR_DOWN(pal_drbg)
{
    pal_destroy();
}


struct randBuf
{
    uint8_t rand[6];
};

/*! \brief Check the random APIs. For each API, the test calls the random API in a loop
* and stores the result. When the loop finishes, we verify that the count of the
* duplication in the stored values is less than the defined random margin value for each API.
*
* | #  |    Step                                                                     |   Expected               |
* |--- |-----------------------------------------------------------------------------|--------------------------|
* | 1  | Fill array with random 32bit values using `pal_osRandom32bit` in a loop.    | PAL_SUCCESS              |
* | 2  | Check array for matching values and make sure there are not too many.       | PAL_SUCCESS              |
* | 3  | Fill array with random values using `pal_osRandomUniform` in a loop.        | PAL_SUCCESS              |
* | 4  | Check array for matching values and make sure there are not too many.       | PAL_SUCCESS              |
* | 5  | Fill array with random byte sequences using `pal_osRandomBuffer` in a loop. | PAL_SUCCESS              |
* | 6  | Check array for matching values and make sure there are not too many.       | PAL_SUCCESS              |
* | 7  | Call pal_osRandom32bit with NULL output parameter.                          | PAL_ERR_INVALID_ARGUMENT |
* | 8  | Call pal_osRandomBuffer with NULL output parameter.                         | PAL_ERR_INVALID_ARGUMENT |
* | 9  | Call pal_osRandomUniform with NULL output parameter.                        | PAL_ERR_INVALID_ARGUMENT |
* | 10 | Call pal_osRandomBuffer while pal is not initialized.                       | PAL_ERR_NOT_INITIALIZED  |
*/
TEST(pal_drbg, RandomUnityTest)
{
    palStatus_t status = PAL_SUCCESS;
    uint32_t randomArray[PAL_RANDOM_ARRAY_TEST_SIZE];
    struct randBuf randomBufArray[PAL_RANDOM_BUFFER_ARRAY_TEST_SIZE];
    uint32_t randomMargin = 0;

    memset(randomArray, 0x0, sizeof(randomArray));
    memset(randomBufArray, 0x0, sizeof(randomBufArray));
    /*#1*/
    for(int i = 0; i < PAL_RANDOM_ARRAY_TEST_SIZE ; ++i)
    {
        status = pal_osRandom32bit(&randomArray[i]);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#2*/
    for(int k = 0; k < PAL_RANDOM_ARRAY_TEST_SIZE ; ++k)
    {
        for (int j = k+1 ; j < PAL_RANDOM_ARRAY_TEST_SIZE ; ++j)
        {
            if (randomArray[k] == randomArray[j])
            {
                ++randomMargin;
            }
        }
        randomArray[k] = 0;
    }
    TEST_ASSERT_TRUE(20 >= randomMargin);
    randomMargin = 0;
    /*#5*/
    for (int i = 0; i < PAL_RANDOM_BUFFER_ARRAY_TEST_SIZE ; ++i)
    {
        status = pal_osRandomBuffer(randomBufArray[i].rand, sizeof(randomBufArray[i].rand));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#6*/
    for(int k = 0; k < PAL_RANDOM_BUFFER_ARRAY_TEST_SIZE ; ++k)
    {
        for (int j = k+1 ; j < PAL_RANDOM_BUFFER_ARRAY_TEST_SIZE ; ++j)
        {
            if(0 == memcmp(randomBufArray[k].rand, randomBufArray[j].rand, sizeof(uint8_t)*6))
            {
                ++randomMargin;
            }
        }
    }

    TEST_ASSERT_TRUE(10 >= randomMargin);

#ifdef DEBUG
    /*#7*/
    status = pal_osRandom32bit(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);

    /*#8*/
    status = pal_osRandomBuffer(NULL, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);


#endif

#if (PAL_INITIALIZED_BEFORE_TESTS == 0)
    /*#10*/
    pal_destroy();

    status = pal_osRandomBuffer(randomBufArray[0].rand, sizeof(randomBufArray[0].rand));
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_NOT_INITIALIZED, status);
#endif
}


/*! \brief call the random API in a PAL_RANDOM_TEST_LOOP loop.
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Call `pal_osRandomBuffer` in a PAL_RANDOM_TEST_LOOP loop .         PAL_SUCCESS |
*/
TEST(pal_drbg, loopRandomBigNumber)
{
	palStatus_t status = PAL_SUCCESS;
	uint8_t loopRandomArray[PAL_RANDOM_ARRAY_TEST_SIZE];

	for (int i = 0; i < PAL_RANDOM_TEST_LOOP; ++i)
	{
		status = pal_osRandomBuffer(loopRandomArray, sizeof(loopRandomArray));
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
}

// the following functions are not part of PAL's external API hence extern
extern palStatus_t pal_plat_noiseWriteValue(const int32_t* data, uint8_t startBit, uint8_t lenBits, uint8_t* bitsWritten);
extern palStatus_t pal_plat_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten);
extern palStatus_t pal_plat_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead);

/*! \brief This test verifies the functionality of noise collection
*
* | # |    Step                                                                                    |   Expected  |
* |---|--------------------------------------------------------------------------------------------|-------------|
* | 1 | Reset the noise buffer by reading whatever is available                                     | PAL_SUCCESS |
* | 2 | Write an entire int32_t (all bits) and verify writes and that full read not possible       | PAL_SUCCESS |
* | 3 | Write only some bits of the int32_t and verify writes and that full read not possible      | PAL_SUCCESS |
* | 4 | Write only some bits of the int32_t, implicitly causing splitting the value into 2 indexes | PAL_SUCCESS |
* | 5 | Read whatever was collected thus far (partial read) and verify output                      | PAL_SUCCESS |
* | 6 | Try to read again and verify buffer is empty                                               | PAL_SUCCESS |
* | 7 | Write a buffer excluding the last 7 bits of the last index and verify results              | PAL_SUCCESS |
* | 8 | Fill the buffer and try to write some more data into it                                    | PAL_SUCCESS |
*/
TEST(pal_drbg, pal_noise)
{
    palStatus_t status;
    int32_t outBuffer[PAL_NOISE_BUFFER_LEN] = { 0 };
    int32_t inBuffer[] = { 0xB76EC265, 0xD16ACE6E, 0xF56AAD6A };
    uint16_t bitsWritten = 0;
    uint16_t bitsRead = 0;
    int32_t writeValue;
    uint8_t i;

    /*#1*/
    pal_plat_noiseRead(outBuffer, true, &bitsRead);
    memset(outBuffer, 0, PAL_NOISE_SIZE_BYTES);

    /*#2*/
    writeValue = 0xCB76102A;
    status = pal_plat_noiseWriteValue(&writeValue, 0, 32, (uint8_t*)&bitsWritten); // write all bits
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(32, bitsWritten);
    status = pal_plat_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#3*/
    status = pal_plat_noiseWriteValue(&writeValue, 3, 20, (uint8_t*)&bitsWritten); // write some of the bits, starting at bit index 3
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(20, bitsWritten);
    status = pal_plat_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#4*/
    status = pal_plat_noiseWriteValue(&writeValue, 16, 16, (uint8_t*)&bitsWritten); // write some of the bits, starting at bit index 16, this functionality tests splitting the bits into 2 different indexes
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(16, bitsWritten);
    status = pal_plat_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#5*/
    status = pal_plat_noiseRead(outBuffer, true, &bitsRead); // read whatever collected (resets buffer)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(64, bitsRead); // even though we wrote 68 bits by now, output should be 64 since the last byte is not full so we should not receive it back
    TEST_ASSERT_EQUAL_HEX(0xCB76102A, outBuffer[0]);
    TEST_ASSERT_EQUAL_HEX(0xB76EC205, outBuffer[1]);
    TEST_ASSERT_EQUAL_HEX(0, outBuffer[2]);
    memset(outBuffer, 0, PAL_NOISE_SIZE_BYTES);

    /*#6*/
    status = pal_plat_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_EMPTY, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#7*/
    status = pal_plat_noiseWriteBuffer(inBuffer, ((sizeof(inBuffer) * CHAR_BIT) - 7), &bitsWritten); // write all except for the last 7 bits of index 2
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(((sizeof(inBuffer) * CHAR_BIT) - 7), bitsWritten);
    status = pal_plat_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);
    status = pal_plat_noiseRead(outBuffer, true, &bitsRead); // read whatever collected (resets buffer)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, bitsRead);
    TEST_ASSERT_EQUAL_HEX(inBuffer[0], outBuffer[0]);
    TEST_ASSERT_EQUAL_HEX(inBuffer[1], outBuffer[1]);
    TEST_ASSERT_EQUAL_HEX(0x6AAD6A, outBuffer[2]);

    /*#8*/
    for (i = 0; i <= (sizeof(inBuffer) / sizeof(int32_t)); ++i)
    {
        status = pal_plat_noiseWriteBuffer(inBuffer, (sizeof(inBuffer) * CHAR_BIT), &bitsWritten);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        TEST_ASSERT_EQUAL_HEX((sizeof(inBuffer) * CHAR_BIT), bitsWritten);
    }
    status = pal_plat_noiseWriteBuffer(inBuffer, (sizeof(inBuffer) * CHAR_BIT), &bitsWritten);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_FULL, status);
    TEST_ASSERT_EQUAL_HEX(0, bitsWritten);
}
