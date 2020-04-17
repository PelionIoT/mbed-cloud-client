// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#include "unity.h"
#include "unity_fixture.h"
#include "test_runners.h"
#include "pal.h"

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#include "kvstore_global_api.h"

#define TEST_PAL_SST_MAX_ITEM_NAME_SIZE           15
#define TEST_PAL_SST_MAX_INPUT_DATA_SIZE          8

#define TRACE_GROUP "PAL"



/** test vector **/
typedef struct pal_SSTItemsTestVector {
    char item_name[TEST_PAL_SST_MAX_ITEM_NAME_SIZE + 1];    /* item name */
    uint8_t input_data[TEST_PAL_SST_MAX_INPUT_DATA_SIZE]; /* item input data */
    size_t input_data_size; /* input data size */
    uint32_t input_flags; /* input flags. currently supported:
                             PAL_SST_WRITE_ONCE_FLAG
                             PAL_SST_CONFIDENTIALITY_FLAG
                             PAL_SST_REPLAY_PROTECTION_FLAG */
    uint8_t output_data[TEST_PAL_SST_MAX_INPUT_DATA_SIZE]; /* buffer for output data */
    size_t output_data_size;  /* output data actual size */
    palSSTItemInfo_t output_item_info; /*output item info.
                                       Includes: stored item size and item flags */
}pal_SSTItemsTestVector_t;

#ifdef DEBUG
static void print_test_data(const pal_SSTItemsTestVector_t* data_array, size_t data_array_size)
{
    size_t i, j, index;
    char data_char[100];

    PAL_LOG_DBG("--------------------------------------------");
    for (i = 0; i < data_array_size; i++) {
        PAL_LOG_DBG("-------------------------");
        PAL_LOG_DBG("item name: %s", data_array[i].item_name);
        index = 0;
        for (j = 0; j < data_array[i].input_data_size; j++) {
            index += sprintf(&data_char[index], " 0x%"PRIx8"", data_array[i].input_data[j]);
        }
        data_char[index] = '\0';
        PAL_LOG_DBG("item input data: %s", data_char);
        PAL_LOG_DBG("input data flags: 0x%" PRIx32 "", data_array[i].input_flags);
        index = 0;
        for (j = 0; j < data_array[i].output_data_size; j++) {
            index += sprintf(&data_char[index], " 0x%"PRIx8"", data_array[i].output_data[j]);
        }
        data_char[index] = '\0';
        PAL_LOG_DBG("item output data: %s", data_char);
        PAL_LOG_DBG("output data flags: 0x%" PRIx32 "", data_array[i].output_item_info.SSTFlagsBitmap);
    }
    PAL_LOG_DBG("--------------------------------------------");
}
#endif //ifdef DEBUG

#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

TEST_GROUP(pal_sst);

TEST_SETUP(pal_sst)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    palStatus_t pal_status;

    pal_status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, pal_status);

    //reset SST
    pal_status = pal_SSTReset();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, pal_status);

#if !PAL_USE_HW_TRNG
    // If no hardware trng - entropy must be injected for random to work
    uint8_t entropy_buf[48] = { 0 };
    pal_status = pal_osEntropyInject(entropy_buf, sizeof(entropy_buf));
    TEST_ASSERT(pal_status == PAL_SUCCESS || pal_status == PAL_ERR_ENTROPY_EXISTS);
#endif

#endif

}

TEST_TEAR_DOWN(pal_sst)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    palStatus_t pal_status;

    //reset SST
    pal_status = pal_SSTReset();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, pal_status);
#endif

}


/*! \brief Check basic usage of the following APIs: `pal_SSTSet()`, pal_SSTGetInfo, `pal_SSTGet()` and `pal_SSTRemove`.
 *
 * | # |    Step                                                                                       |  Expected   |
 * |---|--------------------------------|----------------------------------------------------------------------------|
 * | 1 | Set valid item using pal_SSTSet()                                                             | PAL_SUCCESS |
 * | 2 | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3 | compare the input data size with received data size using pal_SSTGetInfo()                    | PAL_SUCCESS |
 * | 4 | Get item using pal_SSTGet()                                                                   | PAL_SUCCESS |
 * | 5 | Check the the data fetched with pal_SSTGet() is equal to data set with pal_SSTSet()           | PAL_SUCCESS |
 * | 6 | Remove data using pal_SSTRemove                                                               | PAL_SUCCESS |
 */
TEST(pal_sst, pal_sst_test_basic)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    /**test data set for the current test**/
    static pal_SSTItemsTestVector_t pal_sst_items_data[] =
    {
        /*  item name         input data                        input data size input flags      out data    outdatasize   outiteminfo
            ---------         ---------                         ---------       -----------      ----------- -----------   ----------- */

            {{"qwqwqw"},      {1,2,3,4,5},                      5,              0x0,             {0},        0,            {0}},
            {{"131"},         {0xa,0xb,0xc,0xd,0xe},            6,              0x0,             {0},        0,            {0}},
            {{"a"},           {10,20,30,40},                    11,             0x0,             {0},        0,            {0}},
            {{"sds-.23k"},   {0x11,0x22,0x33},                  3,              0x0,             {0},        0,            {0}},
            {{"__123dkf"},   {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},   7,              0x0,             {0},        0,            {0}},
    };


    size_t pal_sst_items_data_size = (sizeof(pal_sst_items_data) / sizeof(pal_sst_items_data[0]));
    palStatus_t status = PAL_SUCCESS;
    size_t i;

#ifdef DEBUG
    PAL_LOG_DBG("\nbefore test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif

    for (i = 0; i < pal_sst_items_data_size; i++) {

        PAL_LOG_DBG("iteration %d\n", i);

        /*#1*/
        status = pal_SSTSet(pal_sst_items_data[i].item_name, pal_sst_items_data[i].input_data,
                            pal_sst_items_data[i].input_data_size, pal_sst_items_data[i].input_flags);
        TEST_ASSERT_EQUAL(PAL_SUCCESS, status);

        /*#2*/
        status = pal_SSTGetInfo(pal_sst_items_data[i].item_name, &(pal_sst_items_data[i].output_item_info));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

        /*#3*/
        TEST_ASSERT_EQUAL(pal_sst_items_data[i].input_data_size, pal_sst_items_data[i].output_item_info.itemSize);

        /*#4*/
        status = pal_SSTGet(pal_sst_items_data[i].item_name, pal_sst_items_data[i].output_data, TEST_PAL_SST_MAX_INPUT_DATA_SIZE, &(pal_sst_items_data[i].output_data_size));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

        /*#5*/
        TEST_ASSERT_EQUAL_MEMORY(pal_sst_items_data[i].input_data, pal_sst_items_data[i].output_data, pal_sst_items_data[i].output_data_size);

        /*#6*/
        status = pal_SSTRemove(pal_sst_items_data[i].item_name);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    }

#ifdef DEBUG
    PAL_LOG_DBG("\nafter test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif 

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is not defined");
#endif

}


/*! \brief: Check basic iterator behavior.
 * Tested APIs: `pal_SSTIteratorOpen()`, `pal_SSTIteratorNext()` and `pal_SSTIteratorClose()`.
 *
 * | # |    Step                                                                                       |  Expected   |
 * |---|--------------------------------|----------------------------------------------------------------------------|
 * | 1 | Set valid items using pal_SSTSet()                                                            | PAL_SUCCESS |
 * | 2 | Open iterator using  pal_SSTIteratorOpen() with test prefix                                   | PAL_SUCCESS |
 * | 3 | Get next item for the test prefix defined in step (2). Should success since item exists       | PAL_SUCCESS |
 * | 4 | Get next item for the test prefix defined in step (2). Should success since item exists       | PAL_SUCCESS |
 * | 5 | Get next item for the test prefix defined in step (2). Should FAIL since item not exists      | PAL_ERR_SST_ITEM_NOT_FOUND |
 * | 6 | Close iterator using  pal_SSTIteratorClose()                                                  | PAL_SUCCESS |
 */
TEST(pal_sst, pal_sst_test_iterator)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    size_t i;
    palSSTIterator_t pal_iterator;
    char output_item_name[TEST_PAL_SST_MAX_ITEM_NAME_SIZE];

    /**test data set for the current test**/
    static const pal_SSTItemsTestVector_t pal_sst_items_data[] =
    {
        /*  item name         input data                        input data size input flags      out data    outdatasize   outiteminfo
            ---------         ---------                         ---------       -----------      ----------- -----------   ----------- */
            {{"test_item_1"}, {1,2,3,4,5},                      5,              0x0,             {0},        0,            {0}},
            {{"dummy123"},    {0xa,0xb,0xc,0xd,0xe},            6,              0x0,             {0},        0,            {0}},
            {{"test_item_2"}, {6,7,8,9,10,11,12},               10,             0x0,             {0},        0,            {0}},
            {{"temp_item_1"}, {10,20,30,40},                    11,             0x0,             {0},        0,            {0}},
            {{"dummy456"},    {0x11,0x22,0x33},                 3,              0x0,             {0},        0,            {0}},
            {{"temp_item_2"}, {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF},  7,              0x0,             {0},        0,            {0}},
    };

    /**test prefixes for test data**/
    const char* test_prefix[2] = { "dummy", "temp_" };

    size_t pal_sst_items_data_size = (sizeof(pal_sst_items_data) / sizeof(pal_sst_items_data[0]));


#ifdef DEBUG
    PAL_LOG_DBG("\nbefore test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif


    /*#1*/
    for (i = 0; i < pal_sst_items_data_size; i++) {

        PAL_LOG_DBG("iteration\n %d", i);

        status = pal_SSTSet(pal_sst_items_data[i].item_name, pal_sst_items_data[i].input_data,
                            pal_sst_items_data[i].input_data_size, pal_sst_items_data[i].input_flags);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

    for (i = 0; i < 2; i++) {
        /*#2*/
        status = pal_SSTIteratorOpen(&pal_iterator, test_prefix[i]);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

        /*#3*/
        status = pal_SSTIteratorNext(pal_iterator, output_item_name, TEST_PAL_SST_MAX_ITEM_NAME_SIZE);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

        /*#4*/
        status = pal_SSTIteratorNext(pal_iterator, output_item_name, TEST_PAL_SST_MAX_ITEM_NAME_SIZE);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

        /*#5*/
        status = pal_SSTIteratorNext(pal_iterator, output_item_name, TEST_PAL_SST_MAX_ITEM_NAME_SIZE);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_ITEM_NOT_FOUND, status);

        /*#6*/
        status = pal_SSTIteratorClose(pal_iterator);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }

#ifdef DEBUG
    PAL_LOG_DBG("\nafter test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
        TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is not defined");
#endif

}


/*! \brief Check functionality of the input flags:
 *  PAL_SST_WRITE_ONCE_FLAG, PAL_SST_ENCRYPT_FLAG, PAL_SST_ENCRYPT_FLAG, PAL_SST_ROLLBACK_PROTECT_FLAG
 *
 * | #  |    Step                                                                                       |  Expected   |
 * |--- |--------------------------------|----------------------------------------------------------------------------|
   |item 0|
 * | 1  | Set item with PAL_SST_WRITE_ONCE_FLAG using pal_SSTSet()                                      | PAL_SUCCESS |
 * | 2  | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3  | compare the PAL_SST_WRITE_ONCE_FLAG set with pal_SSTSet() with received flags using pal_SSTGetInfo() | EQUAL|
 * | 4  | Set item again using pal_SSTSet(). Should fail, because of WRITE_ONCE flag                    | PAL_ERR_SST_WRITE_PROTECTED |
 * | 5  | Remove data using pal_SSTRemove. Should fail, because of WRITE_ONCE flag                      | PAL_ERR_SST_WRITE_PROTECTED |
 * |item 1|
 * | 1  | Set item with PAL_SST_REPLAY_PROTECTION_FLAG using pal_SSTSet()                               | PAL_SUCCESS |
 * | 2  | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3  | Set item again using pal_SSTSet(). Should success                                             | PAL_SUCCESS |
 * | 4  | Remove data using pal_SSTRemove.                                                              | PAL_SUCCESS |
 * |item 2|
 * | 1  | Set (item 1) with no flags using pal_SSTSet(). Should fail since no PAL_SST_REPLAY_PROTECTION_FLAG was set | PAL_SUCCESS |
 * | 2  | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3  | Remove data using pal_SSTRemove.                                                              | PAL_SUCCESS |
 * |item 3|
 * | 1  | Set item with PAL_SST_CONFIDENTIALITY_FLAG using pal_SSTSet()                                 | PAL_SUCCESS |
 * | 2  | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3  | Set item again using pal_SSTSet().                                                            | PAL_SUCCESS |
 * | 4  | Remove data using pal_SSTRemove.                                                              | PAL_SUCCESS |
 * |item 4|
 * | 1  | Set item with PAL_SST_WRITE_ONCE_FLAG and PAL_SST_REPLAY_PROTECTION_FLAG using pal_SSTSet()   | PAL_SUCCESS |
 * | 2  | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3  | compare the PAL_SST_WRITE_ONCE_FLAG set with pal_SSTSet() with received flag using pal_SSTGetInfo() |EQUAL |
 * | 4  | Set item again using pal_SSTSet(). Should fail, because PAL_SST_WRITE_ONCE_FLAG set           | PAL_ERR_SST_WRITE_PROTECTED |
 * | 5  | Remove data using pal_SSTRemove. Should fail, because PAL_SST_WRITE_ONCE_FLAG set             | PAL_ERR_SST_WRITE_PROTECTED |
 * |item 5|
 * | 1  | Set item (item 1) with PAL_SST_REPLAY_PROTECTION_FLAG using pal_SSTSet(). Should success since data is different | PAL_SUCCESS |
 * | 2  | Get item info using pal_SSTGetInfo()                                                          | PAL_SUCCESS |
 * | 3  | Remove data using pal_SSTRemove.                                                              | PAL_SUCCESS |
 */
TEST(pal_sst, pal_sst_test_flags)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;

    /**test data set for the current test**/
    static pal_SSTItemsTestVector_t pal_sst_items_data[] =
    {
        /*  item name         input data             input data size input flags                                              out data    outdatasize   outiteminfo
            ---------         ---------              ------------    -----------                                              ----------- -----------   ----------- */
        /*0*/  {{"a"},        {1,2,3,4,5},               5,             PAL_SST_WRITE_ONCE_FLAG,                                  {0},        0,           {0}},
        /*1*/  {{"bbcd"},     {0xa,0xb,0xc,0xd,0xe},     5,             PAL_SST_REPLAY_PROTECTION_FLAG,                           {0},        0,           {0}},
        /*2*/  {{"bbcd"},     {10,20,30},                3,             0x0,                                                      {0},        0,           {0}},
        /*3*/  {{"1_23_4"},   {0x1,0x3,0x5,0x7,0x9},     6,             PAL_SST_CONFIDENTIALITY_FLAG,                             {0},        0,           {0}},
        /*4*/  {{"_a_K34s"},  {0x1,0x3,0x5,0x7,0x9},     6,             PAL_SST_WRITE_ONCE_FLAG | PAL_SST_REPLAY_PROTECTION_FLAG, {0},        0,           {0}},
        /*5*/  {{"bbcd"},     {0xa,0xb,0xc,0xd,0xf},     5,             PAL_SST_REPLAY_PROTECTION_FLAG,                           {0},        0,           {0}},
    };


#ifdef DEBUG
    size_t pal_sst_items_data_size = (sizeof(pal_sst_items_data) / sizeof(pal_sst_items_data[0]));
    PAL_LOG_DBG("\nbefore test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif


    /****** item 0 ********/
    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[0].item_name, pal_sst_items_data[0].input_data,
                        pal_sst_items_data[0].input_data_size, pal_sst_items_data[0].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGetInfo(pal_sst_items_data[0].item_name, &(pal_sst_items_data[0].output_item_info));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    TEST_ASSERT_EQUAL(pal_sst_items_data[0].input_flags & PAL_SST_WRITE_ONCE_FLAG, 
                    pal_sst_items_data[0].output_item_info.SSTFlagsBitmap & PAL_SST_WRITE_ONCE_FLAG);

    /*#4*/
    status = pal_SSTSet(pal_sst_items_data[0].item_name, pal_sst_items_data[0].input_data,
                        pal_sst_items_data[0].input_data_size, pal_sst_items_data[0].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_WRITE_PROTECTED, status);

    /*#5*/
    status = pal_SSTRemove(pal_sst_items_data[0].item_name);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_WRITE_PROTECTED, status);
    /****** item 0 ********/

    /****** item 1 ********/
    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[1].item_name, pal_sst_items_data[1].input_data,
                        pal_sst_items_data[1].input_data_size, pal_sst_items_data[1].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGetInfo(pal_sst_items_data[1].item_name, &(pal_sst_items_data[1].output_item_info));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_SSTSet(pal_sst_items_data[1].item_name, pal_sst_items_data[1].input_data,
                        pal_sst_items_data[1].input_data_size, pal_sst_items_data[1].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_SSTRemove(pal_sst_items_data[1].item_name);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /****** item 1 ********/

    /****** item 2 ********/
    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[2].item_name, pal_sst_items_data[2].input_data,
                        pal_sst_items_data[2].input_data_size, pal_sst_items_data[2].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGetInfo(pal_sst_items_data[2].item_name, &(pal_sst_items_data[2].output_item_info));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_SSTRemove(pal_sst_items_data[2].item_name);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /****** item 2 ********/

    /****** item 3 ********/
    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[3].item_name, pal_sst_items_data[3].input_data,
                        pal_sst_items_data[3].input_data_size, pal_sst_items_data[3].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGetInfo(pal_sst_items_data[3].item_name, &(pal_sst_items_data[3].output_item_info));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_SSTSet(pal_sst_items_data[3].item_name, pal_sst_items_data[3].input_data,
                        pal_sst_items_data[3].input_data_size, pal_sst_items_data[3].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_SSTRemove(pal_sst_items_data[3].item_name);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /****** item 3 ********/

    /****** item 4 ********/
    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[4].item_name, pal_sst_items_data[4].input_data,
                        pal_sst_items_data[4].input_data_size, pal_sst_items_data[4].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGetInfo(pal_sst_items_data[4].item_name, &(pal_sst_items_data[4].output_item_info));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    TEST_ASSERT_EQUAL(pal_sst_items_data[4].input_flags & PAL_SST_WRITE_ONCE_FLAG, pal_sst_items_data[4].output_item_info.SSTFlagsBitmap & PAL_SST_WRITE_ONCE_FLAG);

    /*#4*/
    status = pal_SSTSet(pal_sst_items_data[4].item_name, pal_sst_items_data[4].input_data,
                        pal_sst_items_data[4].input_data_size, pal_sst_items_data[4].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_WRITE_PROTECTED, status);

    /*#5*/
    status = pal_SSTRemove(pal_sst_items_data[4].item_name);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_WRITE_PROTECTED, status);
    /****** item 4 ********/

    /****** item 5 ********/
    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[5].item_name, pal_sst_items_data[5].input_data,
                        pal_sst_items_data[5].input_data_size, pal_sst_items_data[5].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGetInfo(pal_sst_items_data[5].item_name, &(pal_sst_items_data[5].output_item_info));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_SSTRemove(pal_sst_items_data[5].item_name);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /****** item 5********/

#ifdef DEBUG
    PAL_LOG_DBG("\nafter test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif 

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is not defined");
#endif

}


/*! \brief Check few non standard scenarios listed below:
 *
 * | # |    Step                                                                                       |  Expected   |
 * |---|--------------------------------|----------------------------------------------------------------------------|
 * | 1 | Set item with pointer to NULL buffer and zero data size using pal_SSTSet()                    | PAL_SUCCESS |
 * | 2 | Get item using with NULL buffer and zero buffer size using pal_SSTGet()                       | PAL_SUCCESS |
 * | 3 | Get a non existing item using  pal_SSTGet()                                                   | PAL_ERR_SST_ITEM_NOT_FOUND |
 * | 4 | Set valid item of 120 chars using pal_SSTSet()                                                | PAL_SUCCESS |
 * | 5 | Reset storage using pal_SSTReset()                                                            | PAL_SUCCESS |
 * | 6 | Get a non existing item using  pal_SSTGet() since called after pal_SSTReset                   | PAL_ERR_SST_ITEM_NOT_FOUND |
 */
TEST(pal_sst, pal_sst_test_special_cases)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;

    static pal_SSTItemsTestVector_t pal_sst_items_data[] =
    {
        /*  item name        input data    input data size                     input flags      out data    outdatasize   outiteminfo
            ---------        ---------     ---------                           -----------      ----------- -----------   ----------- */
            {{"dede"},       {0},           0,                                     0x0,           {0},         0,           {0}   },
            {{"qzqzqzqzq"},  {1,2,3,10,5},  TEST_PAL_SST_MAX_INPUT_DATA_SIZE + 1,  0x0,           {0},         0,           {0}   },
    };

#ifdef DEBUG
    size_t pal_sst_items_data_size = (sizeof(pal_sst_items_data) / sizeof(pal_sst_items_data[0]));
    PAL_LOG_DBG("\nbefore test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif

    /*#1*/
    status = pal_SSTSet(pal_sst_items_data[0].item_name, NULL, 0, pal_sst_items_data[0].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_SSTGet(pal_sst_items_data[0].item_name, NULL, pal_sst_items_data[0].input_data_size, &pal_sst_items_data[0].output_data_size);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_SSTGet(pal_sst_items_data[1].item_name, NULL, 0, &pal_sst_items_data[1].output_data_size);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_ITEM_NOT_FOUND, status);

    /*#4*/
    memset(pal_sst_items_data[1].item_name, 'a', TEST_PAL_SST_MAX_ITEM_NAME_SIZE);
    status = pal_SSTSet(pal_sst_items_data[1].item_name, pal_sst_items_data[1].input_data, pal_sst_items_data[1].input_data_size,
                        pal_sst_items_data[0].input_flags);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_SSTReset();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#6*/
    status = pal_SSTGet(pal_sst_items_data[1].item_name, pal_sst_items_data[1].input_data, pal_sst_items_data[1].input_data_size,
                        &pal_sst_items_data[1].output_data_size);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_SST_ITEM_NOT_FOUND, status);

#ifdef DEBUG
    PAL_LOG_DBG("\nafter test");
    print_test_data(pal_sst_items_data, pal_sst_items_data_size);
#endif

#else //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
   TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is not defined");
#endif


}

