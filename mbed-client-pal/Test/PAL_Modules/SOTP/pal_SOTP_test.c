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
#include "cs_pal_crypto.h"
#include "unity.h"
#include "unity_fixture.h"
#include "test_runners.h"

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#include "sotp.h"


#define SOTP_DIR "/sotp"
#define ROT_KEY_SIZE 16

//add 5 years to minimum time
#define PAL_TEST_START_TIME (PAL_MIN_SEC_FROM_EPOCH + ((PAL_SECONDS_PER_DAY * PAL_DAYS_IN_A_YEAR) * 5))
#define ACCEPTABLE_DELAY_IN_SEC (10)
#define PAL_SOTP_TEST_DELAY_IN_SEC (5 * 1000)

#define TRACE_GROUP "PAL"

extern palTestsStatusData_t palTestStatus;

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT


TEST_GROUP(pal_SOTP);

    
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#if (PAL_USE_HW_RTC)
    static uint64_t systemRealRTC = 0;
    static uint64_t systemStartTickCount = 0;
#endif

PAL_PRIVATE palCtrDrbgCtxHandle_t g_drbgCtx = NULLPTR;

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

TEST_SETUP(pal_SOTP)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_initTime();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if (PAL_USE_HW_RTC == 1)
    uint64_t sysTicks = 0;    
    status = pal_plat_osGetRtcTime(&systemRealRTC);
    if (systemRealRTC < (uint64_t)PAL_MIN_RTC_SET_TIME)
    {
        systemRealRTC = PAL_MIN_RTC_SET_TIME;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    systemStartTickCount = pal_osKernelSysTick();
#endif

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

}



TEST_TEAR_DOWN(pal_SOTP)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status = PAL_SUCCESS;
#if (PAL_USE_HW_RTC == 1)
    uint64_t sysTicks = 0;
    uint64_t endTickCount = 0;
    uint64_t timeToAddInSec = 0;
    uint64_t timeToAddInMiliSec = 0;
    endTickCount = pal_osKernelSysTick();
    timeToAddInMiliSec = pal_osKernelSysMilliSecTick(endTickCount - systemStartTickCount); //switch from mili to seconds
    timeToAddInSec = PAL_MILISEC_TO_SEC(timeToAddInMiliSec);

    // XXX: This code expected the pal_init() having been called, even though it is not on all branches!
    status = pal_plat_rtcInit();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_plat_osSetRtcTime(systemRealRTC + timeToAddInSec);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif
    if (g_drbgCtx)
    {
        pal_CtrDRBGFree(&g_drbgCtx);
    }
    status = pal_destroy();

#if (PAL_INITIALIZED_BEFORE_TESTS == 0)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

}


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

static palStatus_t writeDataInFS(uint8_t* data, size_t dataSize, char* dataName)
{
    palStatus_t status = PAL_SUCCESS, status2 = PAL_SUCCESS;
    char filePath[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palFileDescriptor_t fd = 0;
    size_t dataSizeWritten = 0;

    status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, filePath);
    strncat(filePath,SOTP_DIR,PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
    if (PAL_SUCCESS == status) 
    {
         status = pal_fsMkDir(filePath);
         if ((PAL_SUCCESS == status) || (PAL_ERR_FS_NAME_ALREADY_EXIST == status)) 
         {
             strncat(filePath,"/",PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
             strncat(filePath,dataName,PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
             status = pal_fsFopen(filePath,PAL_FS_FLAG_READWRITETRUNC,&fd);
             if (PAL_SUCCESS == status)
             {
                 status =  pal_fsFwrite(&fd, (void *)data, dataSize, &dataSizeWritten);
                 status2 = pal_fsFclose(&fd);
                 if (PAL_SUCCESS != status2) 
                 {
                     PAL_LOG_ERR("Failed to close data file of sotp pal testing after write");
                 }
             }
         }

    }
    return status;
}

static palStatus_t readDataFromFS(uint8_t* data, size_t dataSize, char* dataName)
{
    palStatus_t status= PAL_SUCCESS, status2 = PAL_SUCCESS;
    char filePath[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palFileDescriptor_t fd = 0;
    size_t dataSizeWritten = 0;

    status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, filePath);
    strncat(filePath,SOTP_DIR,PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
    if (PAL_SUCCESS == status) 
    {
         strncat(filePath,"/",PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
         strncat(filePath,dataName,PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
         status = pal_fsFopen(filePath, PAL_FS_FLAG_READONLY, &fd);
         if (PAL_SUCCESS == status)
         {
             status =  pal_fsFread(&fd, (void *)data, dataSize, &dataSizeWritten);
             status2 = pal_fsFclose(&fd);
             if (PAL_SUCCESS != status2) 
             {
                 PAL_LOG_ERR("Failed to close data file of sotp pal testing after read");
             }
             status2 = pal_fsUnlink(filePath);
             if (PAL_SUCCESS != status2) 
             {
                 PAL_LOG_ERR("Failed to delete data file of sotp pal testing after read");
             }
         }

    }
    return status;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT


TEST(pal_SOTP, SW_HW_RoT)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

        uint32_t rotLength = ROT_KEY_SIZE;
        palDevKeyType_t ketType = palOsStorageEncryptionKey128Bit;
        uint8_t rotA[ROT_KEY_SIZE] = {0};
        uint8_t rotB[ROT_KEY_SIZE] = {0};
        sotp_result_e sotpStatus = SOTP_SUCCESS;
        palStatus_t status = PAL_SUCCESS;
        (void)sotpStatus;
        if (palTestStatus.inner == -1) {
            status = pal_osGetDeviceKey(ketType, rotA, rotLength);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        #if(PAL_USE_HW_ROT == 0) // test SW RoT
            status = pal_osGetDeviceKey(ketType, rotB, rotLength);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            TEST_ASSERT_TRUE(0 == memcmp(rotA,rotB,rotLength))

            sotpStatus = sotp_delete(SOTP_TYPE_ROT);
            TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

            memset(rotA,0,sizeof(rotA));

            status = pal_osGetDeviceKey(ketType, rotA, rotLength);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            /** 
             * if there is no HW RoT, The Rot is generated from random. 
             * So, if deleted and re generated there is no chance that the 
             * ols RoT and the New will bw the same
             **/ 
            TEST_ASSERT_TRUE(0 != memcmp(rotA,rotB,rotLength))
         #endif
            status = writeDataInFS(rotA, rotLength,"RoT");
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            status = palTestReboot(PAL_TEST_MODULE_SOTP, PAL_TEST_SOTP_TEST_SW_HW_ROT);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        }//start here after the reboot
        else 
        {
		updatePalTestStatusAfterReboot();

            memset(rotA,0,sizeof(rotA));
            memset(rotB,0,sizeof(rotB));

            status = pal_osGetDeviceKey(ketType, rotA, rotLength);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            status = readDataFromFS(rotB, rotLength, "RoT");
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            TEST_ASSERT_TRUE(0 == memcmp(rotA,rotB,rotLength))
        }

#else
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is defined");
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
        
}

TEST(pal_SOTP, timeInit)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    // call pal destroy as this test need to start before pal_init()
    
    palStatus_t status = PAL_SUCCESS;

    status = pal_destroy();
#if (PAL_INITIALIZED_BEFORE_TESTS == 0)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif

    /** 
     this is is splited to 2 different parts because of the ifdefs
     if the end of this if is inside the #if (PAL_USE_HW_RTC == 1) 
     in any other case, if this was a single if this had casue  
     compilation error 
     **/ 

    
    if (palTestStatus.inner == -1) 
    {
        #if ((PAL_USE_HW_RTC == 1) && (PAL_USE_INTERNAL_FLASH == 1) && (PAL_INT_FLASH_NUM_SECTION ==2))
         {
            uint64_t currentTime = 0;
            sotpStatus = sotp_delete(SOTP_TYPE_SAVED_TIME);
            TEST_ASSERT_TRUE((SOTP_SUCCESS == sotpStatus) || (SOTP_NOT_FOUND == sotpStatus))
            status = pal_plat_osSetRtcTime((uint64_t)PAL_TEST_START_TIME);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            status = pal_init();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = pal_osGetTime();
            TEST_ASSERT_TRUE((currentTime - ACCEPTABLE_DELAY_IN_SEC) <= PAL_TEST_START_TIME);
            status = pal_destroy();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            status = pal_plat_osSetRtcTime((uint64_t)0);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            status = pal_init();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            status = pal_osDelay(PAL_SOTP_TEST_DELAY_IN_SEC);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = pal_osGetTime();
            TEST_ASSERT_EQUAL_HEX(0, currentTime);
            status = pal_destroy();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = PAL_TEST_START_TIME;
            sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&currentTime);
            TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, status);
            currentTime -= (PAL_SECONDS_PER_DAY * PAL_DAYS_IN_A_YEAR); // remove an year
            status = pal_plat_osSetRtcTime(currentTime);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            status = pal_init();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = pal_osGetTime();
            TEST_ASSERT_TRUE((PAL_TEST_START_TIME - ACCEPTABLE_DELAY_IN_SEC) <= currentTime);
            status = pal_destroy();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = PAL_TEST_START_TIME;
            status = pal_plat_osSetRtcTime(currentTime);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime -= (PAL_SECONDS_PER_DAY * PAL_DAYS_IN_A_YEAR); // remove an year
            sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&currentTime);
            TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, status);
            status = pal_init();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = pal_osGetTime();
            TEST_ASSERT_TRUE((currentTime - ACCEPTABLE_DELAY_IN_SEC) <= PAL_TEST_START_TIME);
        #endif


        #if ((PAL_USE_HW_RTC == 0) && (PAL_USE_INTERNAL_FLASH == 1) && (PAL_INT_FLASH_NUM_SECTION ==2))
        {
            uint64_t currentTime = 0;
            currentTime = PAL_TEST_START_TIME; // remove an year
            sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&currentTime);
            TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, status);
            status = pal_init();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
            currentTime = pal_osGetTime();
            TEST_ASSERT_TRUE((PAL_TEST_START_TIME - ACCEPTABLE_DELAY_IN_SEC) <= currentTime);
            status = pal_destroy();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); 
        }
        #endif
    }
    #if (PAL_USE_HW_RTC == 1)
    {
        uint64_t currentTime = 0;
        if (palTestStatus.inner == -1) 
        {

            // XXX: This code expected the pal_init() having been called, even though it is not on all branches!
            status = pal_plat_rtcInit();
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            currentTime = PAL_TEST_START_TIME; // remove an year
            status = pal_plat_osSetRtcTime(currentTime);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            status = palTestReboot(PAL_TEST_MODULE_SOTP, PAL_TEST_SOTP_TEST_TIME_INIT);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
         }//start here after reboot
         else
         {
        	updatePalTestStatusAfterReboot();
            status = pal_plat_osGetRtcTime(&currentTime);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

            TEST_ASSERT_TRUE((currentTime - ACCEPTABLE_DELAY_IN_SEC) <= PAL_TEST_START_TIME);
         }
    }
    #endif

#else
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is defined");
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

}

// the following function is not part of PAL's external API hence extern
extern palStatus_t pal_plat_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead);

/*! \brief Test random buffer generation with sotp
*
* | # |    Step                                                        |  Expected   |
* |---|----------------------------------------------------------------|-------------|
* | 1 | Save a fixed seed to sotp or read current value is exists.     | PAL_SUCCESS |
* | 2 | Generate short & long term seed.                               | PAL_SUCCESS |
* | 3 | Generate expected random.                                      | PAL_SUCCESS |
* | 4 | Call pal_osRandomBuffer and compare expected to actual random. | PAL_SUCCESS |
* | 5 | Validate counter and next (boot) long term seed.               | PAL_SUCCESS |
*/
TEST(pal_SOTP, random)
{

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    palStatus_t status;
    sotp_result_e res;
    uint16_t bytesRead = 0;
    uint32_t counter = 0;
    uint32_t counterCopy = 0;
    uint8_t buf[(PAL_INITIAL_RANDOM_SIZE * 2 + sizeof(counter))] PAL_PTR_ADDR_ALIGN_UINT8_TO_UINT32 = { 0 };
    bool sotpRandomExists = false;

#if !PAL_USE_HW_TRNG
    uint16_t bitsRead = 0;
    int32_t noiseBuffer[PAL_NOISE_BUFFER_LEN] = { 0 };
    pal_plat_noiseRead(noiseBuffer, true, &bitsRead);
#endif // !PAL_USE_HW_TRNG

    /*#1*/
    res = sotp_get(SOTP_TYPE_RANDOM_SEED, (PAL_INITIAL_RANDOM_SIZE + sizeof(counter)), (uint32_t*)buf, &bytesRead); // read 48 drbg bytes + 4 counter bytes
    TEST_ASSERT_TRUE(SOTP_SUCCESS == res || SOTP_NOT_FOUND == res);
    if (SOTP_SUCCESS == res)
    {
        memcpy((void*)&counter, (void*)&buf[PAL_INITIAL_RANDOM_SIZE], sizeof(counter));
        sotpRandomExists = true;
    }
    else if (SOTP_NOT_FOUND == res)
    {
        memset((void*)buf, 7, PAL_INITIAL_RANDOM_SIZE); // fixed dummy seed
        res = sotp_set(SOTP_TYPE_RANDOM_SEED, PAL_INITIAL_RANDOM_SIZE, (uint32_t*)buf);
        TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, res);
    }

    /*#2*/
    status = pal_CtrDRBGInit(&g_drbgCtx, (void*)buf, PAL_INITIAL_RANDOM_SIZE);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    memset((void*)buf, 0, sizeof(buf));
    status = pal_CtrDRBGGenerate(g_drbgCtx, (unsigned char*)buf, PAL_INITIAL_RANDOM_SIZE * 2); // generate 48 bytes long term & 48 bytes short term seed
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_CtrDRBGFree(&g_drbgCtx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    g_drbgCtx = NULLPTR;

    /*#3*/
    status = pal_CtrDRBGInit(&g_drbgCtx, (void*)buf, PAL_INITIAL_RANDOM_SIZE);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    memset((void*)buf, 0, PAL_INITIAL_RANDOM_SIZE);
    status = pal_CtrDRBGGenerate(g_drbgCtx, (unsigned char*)buf, PAL_INITIAL_RANDOM_SIZE); // generate expected random buffer
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_CtrDRBGFree(&g_drbgCtx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    g_drbgCtx = NULLPTR;

    /*#4*/
    uint8_t random[PAL_INITIAL_RANDOM_SIZE] = { 0 };
    status = pal_osRandomBuffer(random, PAL_INITIAL_RANDOM_SIZE); // get the actual random buffer
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#if !PAL_USE_HW_TRNG
    TEST_ASSERT_EQUAL_MEMORY(buf, random, PAL_INITIAL_RANDOM_SIZE);
#endif // !PAL_USE_HW_TRNG

    /*#5*/
    memmove(&buf[(PAL_INITIAL_RANDOM_SIZE + sizeof(counter))], &buf[PAL_INITIAL_RANDOM_SIZE], PAL_INITIAL_RANDOM_SIZE); // make space for the counter while preserving next seed bytes
    memset((void*)buf, 0, (PAL_INITIAL_RANDOM_SIZE + sizeof(counter)));
    counterCopy = counter;
    res = sotp_get(SOTP_TYPE_RANDOM_SEED, (PAL_INITIAL_RANDOM_SIZE + sizeof(counter)), (uint32_t*)buf, &bytesRead);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, res);
    TEST_ASSERT_EQUAL((PAL_INITIAL_RANDOM_SIZE + sizeof(counter)), bytesRead);
    memcpy((void*)&counter, (void*)&buf[PAL_INITIAL_RANDOM_SIZE], sizeof(counter)); // read the counter from sotp data
    TEST_ASSERT_EQUAL(counterCopy + 1, counter);
#if !PAL_USE_HW_TRNG
    TEST_ASSERT_EQUAL_MEMORY(&buf[(PAL_INITIAL_RANDOM_SIZE + sizeof(counter))], buf, PAL_INITIAL_RANDOM_SIZE);
#endif // !PAL_USE_HW_TRNG

    if (false == sotpRandomExists)
    {
        res = sotp_delete(SOTP_TYPE_RANDOM_SEED);
        TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, res);
    }

#else
    TEST_IGNORE_MESSAGE("Ignored, MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT is defined");
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

}

