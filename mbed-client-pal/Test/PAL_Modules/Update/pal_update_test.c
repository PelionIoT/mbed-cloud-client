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
#include "mbed_trace.h"

#include <string.h>

#define TRACE_GROUP "PAL"

#define KILOBYTE 1024

#define FIRST_IMAGE_INDEX        0

TEST_GROUP(pal_update);


palBuffer_t g_writeBuffer = {0};
palBuffer_t g_readBuffer = {0};
palImageHeaderDeails_t g_imageHeader = {0};
uint8_t g_isTestDone;


uint8_t numberofBlocks = 0;

/*! \brief Sanity test the update test are running.
*/
TEST_SETUP(pal_update)
{
    PAL_LOG_INFO("running new test\r\n");

}

typedef enum _updateTestState
{
    test_init = 1,
    test_write,
    test_commit,
    test_read
}updateTestState;

PAL_PRIVATE void stateAdvance(palImageEvents_t state)
{
    PAL_PRINTF("Finished event %d\r\n",state);
    state++;
    PAL_PRINTF("Starting event %d\r\n",state);
    int rc = PAL_SUCCESS;
    PAL_PRINTF("Write ptr = (%p - %p) read ptr = (%p - %p)\r\n",
            g_writeBuffer.buffer,g_writeBuffer.buffer + g_writeBuffer.maxBufferLength,
            g_readBuffer.buffer, g_readBuffer.buffer + g_readBuffer.maxBufferLength);
    switch (state)
    {
    case PAL_IMAGE_EVENT_PREPARE:
          rc = pal_imagePrepare(FIRST_IMAGE_INDEX, &g_imageHeader);
          PAL_PRINTF("pal_imagePrepare returned %d \r\n",rc);
          TEST_ASSERT_EQUAL(0, rc);
          break;
    case PAL_IMAGE_EVENT_WRITE:
          rc = pal_imageWrite(FIRST_IMAGE_INDEX, 0, (palConstBuffer_t*)&g_writeBuffer);
          PAL_PRINTF("pal_imageWrite returned %d \r\n",rc);
          TEST_ASSERT_TRUE(rc >= 0);
          break;
    case PAL_IMAGE_EVENT_FINALIZE:
          rc = pal_imageFinalize(FIRST_IMAGE_INDEX);
          PAL_PRINTF("pal_imageFinalize returned %d \r\n",rc);
          TEST_ASSERT_TRUE(rc >= 0);
          break;
    case PAL_IMAGE_EVENT_READTOBUFFER:
          rc = pal_imageReadToBuffer(FIRST_IMAGE_INDEX,0,&g_readBuffer);
          TEST_ASSERT_TRUE(rc >= 0);
          PAL_PRINTF("pal_imageReadToBuffer  with offset %d return %d \r\n",0,rc);
          break;
    case PAL_IMAGE_EVENT_ACTIVATE:
          PAL_PRINTF("Checking the output\r\n");
          PAL_PRINTF("\r\ng_readBuffer bufferLength=%" PRIu32 "\r\n",g_readBuffer.maxBufferLength);


          TEST_ASSERT_EQUAL_MEMORY(g_writeBuffer.buffer,g_readBuffer.buffer,g_readBuffer.maxBufferLength);
          PAL_PRINTF("write ptr = %p read ptr = %p\r\n",g_writeBuffer.buffer,g_readBuffer.buffer);

          free(g_readBuffer.buffer);
          free(g_writeBuffer.buffer);
          pal_imageDeInit();
          g_isTestDone = 1;
          break;
    default:
        PAL_PRINTF("Error - this should not happen\r\n");
        PAL_PRINTF("Write ptr = %p read ptr = %p\r\n",g_writeBuffer.buffer,g_readBuffer.buffer);
        free(g_readBuffer.buffer);
        free(g_writeBuffer.buffer);
        pal_imageDeInit();
        g_isTestDone = 1;
    }
}






void printBuffer(uint8_t* buffer, size_t bufSize)
{
    size_t i = 0;
    PAL_PRINTF("0x");
    for (i=0;i < bufSize;i++)
    {
        PAL_PRINTF("%x",buffer[i]);
    }
    PAL_PRINTF("\r\n");
}


PAL_PRIVATE void fillBuffer(uint8_t* buffer, size_t bufSize)
{
    size_t  i = 0;
    uint8_t value = 0;
    int8_t step = -1;
    PAL_PRINTF("Filling buffer size %zu\r\n",bufSize);
    for(i=0; i < bufSize ; i++)
    {
        buffer[i] = value;
        if ((0 == value) || (255 == value))
        {
            step*=-1;
        }
        value+=step;
    }
    PAL_PRINTF("Buffer is full\r\n");

}


TEST_TEAR_DOWN(pal_update)
{
}



void pal_update_xK(int sizeInK)
{

  palStatus_t rc = PAL_SUCCESS;
  if (!(sizeInK % KILOBYTE))
  {
      PAL_PRINTF("\n-====== PAL_UPDATE_%dKb ======- \n",sizeInK / KILOBYTE);
  }
  else
  {
      PAL_PRINTF("\n-====== PAL_UPDATE_%db ======- \n",sizeInK);
  }
  uint8_t *writeData = (uint8_t*)malloc(sizeInK);
  uint8_t *readData  = (uint8_t*)malloc(sizeInK);

  TEST_ASSERT_TRUE(writeData != NULL);
  TEST_ASSERT_TRUE(readData != NULL);

  uint64_t version = 11111111;

  // XXX: the pal_imagePrepare() has hardcoded requirement of hash being SHA256, so it must be given here too
  uint8_t hash[SIZEOF_SHA256] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                                  0x0c, 0x1c, 0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x7c,
                                  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
                                  };

  g_isTestDone = 0;

  g_imageHeader.version = version;

  g_imageHeader.hash.buffer =(uint8_t*)&hash;
  g_imageHeader.hash.bufferLength = sizeof(hash);
  g_imageHeader.hash.maxBufferLength = sizeof(hash);

  g_imageHeader.imageSize = sizeInK;

  g_writeBuffer.buffer = writeData;
  g_writeBuffer.bufferLength = sizeInK;
  g_writeBuffer.maxBufferLength = sizeInK;

  PAL_PRINTF("write buffer length %" PRIu32 " max length %" PRIu32 "\r\n",g_writeBuffer.bufferLength,g_writeBuffer.maxBufferLength);
  fillBuffer(g_writeBuffer.buffer,g_writeBuffer.bufferLength);

  g_readBuffer.buffer = readData;
  g_readBuffer.maxBufferLength = sizeInK;


  rc =pal_imageInitAPI(stateAdvance);
  PAL_PRINTF("pal_imageInitAPI returned %" PRIu32 " \r\n",rc);
  TEST_ASSERT_TRUE(rc >= 0);

  /*Wait until the async test finishes*/
  while (!g_isTestDone)
      pal_osDelay(5); //Make the OS switch context

}

/*! \brief Writing a 1Kb image and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading a 1Kb image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                      | Success |
* | 2 | `pal_imagePrepare`                               | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                                 | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                              | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                          | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.            | memcmp == 0 |
*/

TEST(pal_update, pal_update_1k)
{
    pal_update_xK(1*KILOBYTE);
}


/*! \brief Writing a 2Kb image and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading a 2Kb image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                      | Success |
* | 2 | `pal_imagePrepare`                               | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                                 | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                              | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                          | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.            | memcmp == 0 |
*/

TEST(pal_update, pal_update_2k)
{
    pal_update_xK(2*KILOBYTE);
}

/*! \brief Writing a 4Kb image and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading a 4Kb image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                     | Success |
* | 2 | `pal_imagePrepare`                               | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                                 | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                              | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                          | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.            | memcmp == 0 |
*/

TEST(pal_update, pal_update_4k)
{
    pal_update_xK(4*KILOBYTE);
}

/*! \brief Writing an 8Kb image and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading an 8Kb image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                              | Success |
* | 2 | `pal_imagePrepare`                      | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                        | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                     | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                 | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.   | memcmp == 0 |
*/

TEST(pal_update, pal_update_8k)
{
    pal_update_xK(8*KILOBYTE);
}

/*! \brief Writing a 16Kb image and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading a 16Kb image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                 | Success |
* | 2 | `pal_imagePrepare`                           | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                             | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                          | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                      | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.        | memcmp == 0 |
*/

TEST(pal_update, pal_update_16k)
{
    pal_update_xK(16*KILOBYTE);
}


/*! \brief Writing a small image (5b) and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading a 5b image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                             | Success |
* | 2 | `pal_imagePrepare`                       | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                         | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                      | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                  | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.    | memcmp == 0 |
*/


TEST(pal_update,pal_update_writeSmallChunk_5b)
{
    pal_update_xK(5);
}


/*! \brief Writing an unaligned image of 1001b and verifying its value.
 * \test
*  This test simulates a state machine for writing and reading a 51001b image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                   | Success |
* | 2 | `pal_imagePrepare`                            | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                              | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                           | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                       | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.         | memcmp == 0 |
*/


TEST(pal_update,pal_update_writeUnaligned_1001b)
{
    //1039 is a prime number so probably never aligned.
    pal_update_xK(1039);
}




PAL_PRIVATE void multiWriteMultiRead(palImageEvents_t state)
{
    int rc = PAL_SUCCESS;
    static uint8_t counter = 0;
    static uint8_t *writeBase = NULL;
    static uint8_t *readBase = NULL;
    if (NULL == writeBase)
    {
        writeBase = g_writeBuffer.buffer;
        g_writeBuffer.maxBufferLength = g_writeBuffer.maxBufferLength/numberofBlocks;
        g_writeBuffer.bufferLength = g_writeBuffer.bufferLength/numberofBlocks;

        readBase = g_readBuffer.buffer;
        g_readBuffer.maxBufferLength = g_readBuffer.maxBufferLength/numberofBlocks;
    }
    PAL_PRINTF("Finished event %d\r\n",state);
    if (PAL_IMAGE_EVENT_WRITE == state) // Just wrote data
    {
        counter++;
        if (numberofBlocks == counter) // Wrote all needed blocks
        {
            state++; // Advance to next state
            counter = 0; //Initialize counter
        }
    }
    else if (PAL_IMAGE_EVENT_READTOBUFFER == state) // Just read data
    {
        counter++ ;
        if (numberofBlocks == counter) // Read all needed blocks
        {
            state++; // Advance to next state
            counter = 0;
        }
    }
    else
    {
        state++; // Advance to next state
    }

    PAL_PRINTF("Starting event %d\r\n",state);

    switch (state)
    {
    case PAL_IMAGE_EVENT_PREPARE:
          rc = pal_imagePrepare(FIRST_IMAGE_INDEX, &g_imageHeader);
          PAL_PRINTF("pal_imagePrepare returned %d \r\n",rc);
          TEST_ASSERT_EQUAL(0, rc);
          break;
    case PAL_IMAGE_EVENT_WRITE:
          PAL_PRINTF("Write KILOBYTE * %d = %d\r\n",counter,KILOBYTE*(counter));
          g_writeBuffer.buffer = &writeBase[KILOBYTE*(counter)];// Writing 1k every time
          rc = pal_imageWrite(FIRST_IMAGE_INDEX, KILOBYTE*(counter),(palConstBuffer_t*)&g_writeBuffer);
          PAL_PRINTF("pal_imageWrite returned %d \r\n",rc);
          TEST_ASSERT_TRUE(rc >= 0);
          break;
    case PAL_IMAGE_EVENT_FINALIZE:
          rc = pal_imageFinalize(FIRST_IMAGE_INDEX);
          PAL_PRINTF("pal_imageFinalize returned %d \r\n",rc);
          TEST_ASSERT_TRUE(rc >= 0);
          break;
    case PAL_IMAGE_EVENT_READTOBUFFER:
          PAL_PRINTF("Read KILOBYTE * %d = %d\r\n",counter, KILOBYTE*(counter));
          g_readBuffer.buffer = &readBase[KILOBYTE*(counter)];// Writing 1k every time
          g_readBuffer.bufferLength = 0;
          rc = pal_imageReadToBuffer(FIRST_IMAGE_INDEX, KILOBYTE*(counter),&g_readBuffer);
          PAL_PRINTF("pal_imageReadToBuffer  with offset %d return %d \r\n",0,rc);
          break;
    case PAL_IMAGE_EVENT_ACTIVATE:

          PAL_PRINTF("Checking the output\r\n");

          TEST_ASSERT_TRUE(rc >= 0);
          TEST_ASSERT_TRUE(!memcmp(readBase,writeBase,numberofBlocks*KILOBYTE));
          free(writeBase);
          free(readBase);
          pal_imageDeInit();
          g_isTestDone = 1;
          break;
    default:
        PAL_PRINTF("Error\r\n");
        free(writeBase);
        free(readBase);
        pal_imageDeInit();
        g_isTestDone = 1;
        break;
    }
}


/*! \brief Writing a 4Kb image and reading it with a 1Kb buffer.
 * \test
*  This test simulates a state machine for writing and reading a 4Kb image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                             | Success |
* | 2 | `pal_imagePrepare`                                     | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                                       | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                                    | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                                | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.                  | memcmp == 0 |
*/

TEST(pal_update, pal_update_4k_write_1k_4_times)
{
  palStatus_t rc = PAL_SUCCESS;

  uint8_t *writeData = (uint8_t*)malloc(4*KILOBYTE);
  uint8_t *readData  = (uint8_t*)malloc(4*KILOBYTE);


  TEST_ASSERT_TRUE(writeData != NULL);
  TEST_ASSERT_TRUE(readData != NULL);

  uint64_t version = 11111111;
  // XXX: the pal_imagePrepare() has hardcoded requirement of hash being SHA256, so it must be given here too
  uint8_t hash[SIZEOF_SHA256] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                                  0x0c, 0x1c, 0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x7c,
                                  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
                                  };
  g_isTestDone = 0;

  g_imageHeader.version = version;

  g_imageHeader.hash.buffer =(uint8_t*)&hash;
  g_imageHeader.hash.bufferLength = sizeof(hash);
  g_imageHeader.hash.maxBufferLength = sizeof(hash);

  g_imageHeader.imageSize = 4*KILOBYTE;

  fillBuffer(writeData,4*KILOBYTE);

  g_writeBuffer.buffer = writeData;
  g_writeBuffer.bufferLength = 4*KILOBYTE;
  g_writeBuffer.maxBufferLength = 4*KILOBYTE;
  PAL_PRINTF("pal_update_4k");
  PAL_PRINTF("Write buffer length %" PRIu32 " max length %" PRIu32 "\r\n",g_writeBuffer.bufferLength,g_writeBuffer.maxBufferLength);
  fillBuffer(g_writeBuffer.buffer,g_writeBuffer.bufferLength);

  g_readBuffer.buffer = readData;
  g_readBuffer.maxBufferLength =  4*KILOBYTE;

  numberofBlocks = 4;

  rc = pal_imageInitAPI(multiWriteMultiRead);
  PAL_PRINTF("pal_imageInitAPI returned %" PRIu32 " \r\n",rc);
  TEST_ASSERT_TRUE(rc >= 0);
  /*Wait until the async test finishes*/
  while (!g_isTestDone)
      pal_osDelay(5); // Make the OS switch context

}

/*! \brief Writing a different image with incrementing size.
 * \test
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                           | Success |
* | 2 | `1kb_image`                          | Success |
* | 3 | `2kb_image`                          | Success |
* | 4 | `4kb_image`                          | Success |
* | 5 | `8kb_image`                          | Success |
* | 6 | `16kb_image`                         | Success |
* | 7 | `32kb_image`                         | Success |
*/
TEST(pal_update, pal_update_stressTest)
{
    uint8_t it,j;
    PAL_PRINTF("****************************************************\r\n");
    PAL_PRINTF("******* Testing multiple writes sequentially *******\r\n");
    PAL_PRINTF("****************************************************\r\n");
    for (j=0; j < 5; j++)
    {
        PAL_PRINTF("1\r\n");
        for (it = 1; it < 32; it*=2)
        {
            pal_update_xK(it*KILOBYTE);

        }
    }
}






PAL_PRIVATE void readStateMachine(palImageEvents_t state)
{
    static uint8_t *readData = NULL ;
    static uint32_t bytesWasRead = 0;
    int rc = PAL_SUCCESS;
    PAL_PRINTF("Finished event %d\r\n",state);
    /*If just finished reading*/
    if (PAL_IMAGE_EVENT_READTOBUFFER == state)
    {
        PAL_PRINTF("g_readBuffer.bufferLength %" PRIu32 "\r\n",g_readBuffer.bufferLength);
        if (0 < g_readBuffer.bufferLength)
        {
            PAL_PRINTF("Writing %" PRIu32 " bytes to readData[%" PRIu32 "]\r\n",g_readBuffer.bufferLength,bytesWasRead);
            memcpy(&readData[bytesWasRead],g_readBuffer.buffer,g_readBuffer.bufferLength);
            bytesWasRead+=g_readBuffer.bufferLength;
        }
        else
        {
            state++;
        }
    }
    else
    {
        state++;
    }
    PAL_PRINTF("Starting event %d\r\n",state);
    switch (state)
    {
    case PAL_IMAGE_EVENT_PREPARE:
          bytesWasRead = 0;
          PAL_PRINTF("Allocating %" PRIu32 " byes for test \r\n",g_writeBuffer.maxBufferLength);
          readData = (uint8_t*)malloc(g_writeBuffer.maxBufferLength);
          TEST_ASSERT_TRUE(readData != NULL);
          rc = pal_imagePrepare(FIRST_IMAGE_INDEX,&g_imageHeader);
          PAL_PRINTF("pal_imagePrepare returned %d \r\n",rc);
          TEST_ASSERT_EQUAL(0, rc);
          break;
    case PAL_IMAGE_EVENT_WRITE:
          rc = pal_imageWrite(FIRST_IMAGE_INDEX,0,(palConstBuffer_t*)&g_writeBuffer);
          PAL_PRINTF("pal_imageWrite returned %d \r\n",rc);
          TEST_ASSERT_TRUE(rc >= 0);
          break;
    case PAL_IMAGE_EVENT_FINALIZE:
          rc = pal_imageFinalize(FIRST_IMAGE_INDEX);
          PAL_PRINTF("pal_imageFinalize returned %d \r\n",rc);
          TEST_ASSERT_TRUE(rc >= 0);
          break;
    case PAL_IMAGE_EVENT_READTOBUFFER:
          g_readBuffer.bufferLength = 0;
          memset(g_readBuffer.buffer,0,g_readBuffer.maxBufferLength);
          rc = pal_imageReadToBuffer(FIRST_IMAGE_INDEX,bytesWasRead,&g_readBuffer);
          PAL_PRINTF("pal_imageReadToBuffer  with offset %" PRIu32 " return %d \r\n",bytesWasRead,rc);
          //TEST_ASSERT_TRUE((rc >= 0) || (rc != -10));
          break;
    case PAL_IMAGE_EVENT_ACTIVATE:
          PAL_PRINTF("Checking the output\r\n");
          PAL_PRINTF("\r\ng_readBuffer bufferLength=%" PRIu32 "\r\n",g_readBuffer.maxBufferLength);
          TEST_ASSERT_TRUE(!memcmp(readData,g_writeBuffer.buffer,g_writeBuffer.bufferLength));
          PAL_PRINTF("write ptr = %p read ptr = %p\r\n",g_writeBuffer.buffer,g_readBuffer.buffer);
          free(g_readBuffer.buffer);
          free(g_writeBuffer.buffer);
          free(readData);
          pal_imageDeInit();
          g_isTestDone = 1;
          break;
    default:
        PAL_PRINTF("Error - this should not happen\r\n");
        PAL_PRINTF("write ptr = %p read ptr = %p\r\n",g_writeBuffer.buffer,g_readBuffer.buffer);
        free(g_readBuffer.buffer);
        free(g_writeBuffer.buffer);
        free(readData);
        pal_imageDeInit();
        g_isTestDone = 1;
        TEST_ASSERT_TRUE(rc >= 0);
    }
}



/*! \brief Writing an image and verifying its value by multiple reads.
 * \test
*  This test simulates a state machine for writing and reading an image.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize the test.                                        | Success |
* | 2 | `pal_imagePrepare`                                 | PAL_SUCCESS |
* | 3 | `pal_imageWrite`                                   | PAL_SUCCESS |
* | 4 | `pal_imageFinalize`                                | PAL_SUCCESS |
* | 5 | `pal_imageReadToBuffer`                            | PAL_SUCCESS |
* | 6 | Compare the written image with the read image.              | memcmp == 0 |
*/

TEST(pal_update, pal_update_Read)
{
      uint32_t sizeIn=1500;
      palStatus_t rc = PAL_SUCCESS;
      PAL_PRINTF("\n-====== PAL_UPDATE_READ TEST %" PRIu32 " b ======- \n",sizeIn);
      uint8_t *writeData = (uint8_t*)malloc(sizeIn);
      uint8_t *readData  = (uint8_t*)malloc(sizeIn/5);

      TEST_ASSERT_TRUE(writeData != NULL);
      TEST_ASSERT_TRUE(readData != NULL);

      uint64_t version = 11111111;
      // XXX: the pal_imagePrepare() has hardcoded requirement of hash being SHA256, so it must be given here too
      uint8_t hash[SIZEOF_SHA256] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                                      0x0c, 0x1c, 0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x7c,
                                      0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7
                                      };
      g_isTestDone = 0;

      g_imageHeader.version = version;

      g_imageHeader.hash.buffer = (uint8_t*)&hash;
      g_imageHeader.hash.bufferLength = sizeof(hash);
      g_imageHeader.hash.maxBufferLength = sizeof(hash);

      g_imageHeader.imageSize = sizeIn;

      g_writeBuffer.buffer = writeData;
      g_writeBuffer.bufferLength = sizeIn;
      g_writeBuffer.maxBufferLength = sizeIn;

      PAL_PRINTF("write buffer length %" PRIu32 " max length %" PRIu32 "\r\n",g_writeBuffer.bufferLength,g_writeBuffer.maxBufferLength);
      fillBuffer(g_writeBuffer.buffer,g_writeBuffer.bufferLength);

      g_readBuffer.buffer = readData;
      g_readBuffer.maxBufferLength = sizeIn/5;
      g_readBuffer.bufferLength = 0;

      rc =pal_imageInitAPI(readStateMachine);
      PAL_PRINTF("pal_imageInitAPI returned %" PRIu32 " \r\n",rc);
      TEST_ASSERT_TRUE(rc >= 0);

      /*Wait until the async test finishes*/
      while (!g_isTestDone)
          pal_osDelay(5); // Make the OS switch context

}
