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
#include "sotp.h"
#include "test_runners.h"

#include <string.h>
#include <stdlib.h>

#define TRACE_GROUP "PAL"

TEST_GROUP(pal_time);

TEST_SETUP(pal_time)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

}

TEST_TEAR_DOWN(pal_time)
{
    pal_destroy();
}

/*! \brief Check the APIs `pal_osSetTime()` and `pal_osGetTime()` with different scenarios
* for valid and non-valid scenarios and epoch values.
* The test also checks that the time increases.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Start a loop for the following steps.                                                | PAL_SUCCESS |
* | 2 | Set time to invalid value using `pal_osSetTime`.                                 | PAL_ERR_INVALID_TIME |
* | 3 | Get time using `pal_osGetTime`.                                                  | PAL_SUCCESS |
* | 4 | Set time to valid value using `pal_osSetTime`.                                   | PAL_SUCCESS |
* | 5 | Sleep.                                                                         | PAL_SUCCESS |
* | 6 | Get time using `pal_osGetTime` and check that it equals set time + sleep time.   | PAL_SUCCESS |
*/
TEST(pal_time, RealTimeClockTest1)
{
    palStatus_t status;
    uint64_t curTime = 0;
    uint64_t lastTimeSeen = 0;
    const uint64_t minSecSinceEpoch = PAL_MIN_SEC_FROM_EPOCH + 1; //At least 47 years passed from 1.1.1970 in seconds

    /*#1*/
    for (int i=0; i < 2; i++)
    {
    /*#2*/
        status = pal_osSetTime(3);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_TIME, status); // Less than current epoch time -> error

    /*#3*/
        curTime = pal_osGetTime();
        TEST_ASSERT_TRUE(lastTimeSeen <= curTime); //Time was not previously set; 0 is acceptable
    /*#4*/
        status = pal_osSetTime(minSecSinceEpoch);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); // More than current epoch time -> success
    /*#5*/
        int milliDelay = 1500;
        pal_osDelay(milliDelay); //500 milliseconds
    /*#6*/
        curTime = pal_osGetTime();
        TEST_ASSERT_TRUE(curTime > minSecSinceEpoch);
        TEST_ASSERT_TRUE(curTime <= minSecSinceEpoch+(int)ceil((float)milliDelay/1000));
        lastTimeSeen = curTime;
    }
}


/*! \brief Check Weak Set Time - Forword flow.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | checking RTC and SOTP flow - not set SOTP SAVED TIME  + LAST TIME BACK + RTC to new time          		      | PAL_SUCCESS |
* | 2 | checking RTC and SOTP flow - not set SOTP SAVED TIME  + LAST TIME BACK to new time but set RTC to new time    | PAL_SUCCESS |
* | 3 | checking RTC and SOTP flow - set SOTP SAVED TIME  + LAST TIME BACK + RTC to new time          		          | PAL_SUCCESS |
*/
TEST(pal_time, OsWeakSetTime_Forword)
{
    palStatus_t status;
    sotp_result_e sotpStatus = SOTP_SUCCESS;
    uint64_t setTimeInSeconds = 0;
    uint64_t curentTimeInSeconds=0;
    uint64_t pal_Time = 0;
    uint64_t sotpGetTime = 0;
    uint16_t actualLenBytes = 0;

#if (PAL_USE_HW_RTC)
    //This code is to preserve system time
    uint64_t testStartTime = 0;
    status = pal_plat_osGetRtcTime(&testStartTime);
#endif


    /*#1*/
#if (PAL_USE_HW_RTC)
    pal_plat_osSetRtcTime(PAL_MIN_RTC_SET_TIME);
#endif
    pal_osSetTime(PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100);
    curentTimeInSeconds = pal_osGetTime();

    sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&curentTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    sotpStatus = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&curentTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

#if (PAL_USE_HW_RTC)
    uint64_t rtcTime = 0;
    status = pal_plat_osSetRtcTime(curentTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif//PAL_USE_HW_RTC

    setTimeInSeconds = curentTimeInSeconds + (50 * PAL_ONE_SEC);
    status = pal_osSetWeakTime(setTimeInSeconds);

    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5)
    {
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);

    sotpStatus = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);
#endif 

#if (PAL_USE_HW_RTC)
    status = pal_plat_osGetRtcTime(&rtcTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(rtcTime, setTimeInSeconds);
#endif//PAL_USE_HW_RTC

    /*#2*/
    curentTimeInSeconds = pal_osGetTime();
#if (PAL_USE_HW_RTC)
    pal_plat_osSetRtcTime(curentTimeInSeconds);
#endif//PAL_USE_HW_RTC
    
    setTimeInSeconds = curentTimeInSeconds+(200 * PAL_ONE_SEC);

    status = pal_osSetWeakTime(setTimeInSeconds);
    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5)
    {
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
	TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
	TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);

    sotpStatus = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
	TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
	TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);
#endif

#if (PAL_USE_HW_RTC)
    status = pal_plat_osGetRtcTime(&rtcTime);
    TEST_ASSERT_EQUAL_UINT64(rtcTime, setTimeInSeconds);
#endif//PAL_USE_HW_RTC

    /*#3*/
    curentTimeInSeconds = pal_osGetTime();
    sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&curentTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    sotpStatus = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&curentTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

#if (PAL_USE_HW_RTC)
    status = pal_plat_osSetRtcTime(curentTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif//PAL_USE_HW_RTC

    setTimeInSeconds = curentTimeInSeconds + PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC + (100 * PAL_ONE_SEC);
    status = pal_osSetWeakTime(setTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
	TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
	TEST_ASSERT_EQUAL_UINT64(sotpGetTime, setTimeInSeconds);
#endif

#if (PAL_USE_HW_RTC)
    status = pal_plat_osGetRtcTime(&rtcTime);
    TEST_ASSERT_EQUAL_UINT64(rtcTime, setTimeInSeconds);
#endif//PAL_USE_HW_RTC

#if (PAL_USE_HW_RTC)
    //restore System time
    pal_plat_osSetRtcTime(testStartTime + PAL_RUNNING_TEST_TIME);
#endif
}

/*! \brief Check Weak Set Time - Backword flow.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | checking SOTP flow - set SOTP SAVED TIME and LAST TIME BACK to new time	        | PAL_SUCCESS |
* | 2 | checking SOTP flow - not set SOTP SAVED TIME and LAST TIME BACK to new time	    | PAL_SUCCESS |
*/
TEST(pal_time, OsWeakSetTime_Backword)
{
    uint64_t setTimeInSeconds = 0;
    uint64_t curentTimeInSeconds = 0;
    palStatus_t status;
    sotp_result_e sotpStatus = SOTP_SUCCESS;
    uint64_t getTimeValueBackword = 0;
    uint64_t pal_Time = 0;
#if (PAL_USE_HW_RTC)
    //This code is to preserve system time
    uint64_t testStartTime = 0;
    status = pal_plat_osGetRtcTime(&testStartTime);
#endif

    /*#1*/
#if (PAL_USE_HW_RTC)
    pal_plat_osSetRtcTime(PAL_MIN_RTC_SET_TIME);
    pal_osSetTime(PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100);
#endif
    curentTimeInSeconds = pal_osGetTime();

    getTimeValueBackword = curentTimeInSeconds - (3 * PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC);
    sotpStatus = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&getTimeValueBackword);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);


    setTimeInSeconds = curentTimeInSeconds - (6 * PAL_SECONDS_PER_MIN);
    status = pal_osSetWeakTime(setTimeInSeconds);

    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5)
    {
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    uint64_t sotpGetTime = 0;
    uint16_t actualLenBytes = 0;

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_EQUAL_UINT64(sotpGetTime, setTimeInSeconds);

    sotpStatus = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_EQUAL_UINT64(sotpGetTime, setTimeInSeconds);
#endif

    /*#2*/
    curentTimeInSeconds = pal_osGetTime();
    getTimeValueBackword = curentTimeInSeconds - (3 * PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC);
    sotpStatus = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&getTimeValueBackword);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&getTimeValueBackword);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    setTimeInSeconds = curentTimeInSeconds - (12 * PAL_SECONDS_PER_MIN);

    status = pal_osSetWeakTime(setTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);
    sotpStatus = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);
#endif

#if (PAL_USE_HW_RTC)
    //restore System time
    pal_plat_osSetRtcTime(testStartTime + PAL_RUNNING_TEST_TIME);
#endif
}

/*! \brief Weak Strong Set Time- minimalStoredLag flow.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | checking SOTP flow- set SOTP SAVED TIME to new time	                		| PAL_SUCCESS |
* | 2 | checking SOTP flow- not set SOTP SAVED TIME	to new time                     | PAL_SUCCESS |
*/
TEST(pal_time, OsWeakSetTime_minimalStoredLag)
{
    palStatus_t status;
    sotp_result_e sotpStatus = SOTP_SUCCESS;
    uint64_t setTimeInSeconds = 0;
    uint64_t curentTimeInSeconds = 0;
    uint64_t sotpGetTime = 0;
    uint16_t actualLenBytes = 0;
    uint64_t setSotpTimeValue = 0;
    
#if (PAL_USE_HW_RTC)
    //This code is to preserve system time
    uint64_t testStartTime = 0;
    status = pal_plat_osGetRtcTime(&testStartTime);
#endif

    /*#1*/
#if (PAL_USE_HW_RTC)
    pal_plat_osSetRtcTime(PAL_MIN_RTC_SET_TIME);
#endif
    pal_osSetTime(PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100);
    curentTimeInSeconds = pal_osGetTime();
    setTimeInSeconds = curentTimeInSeconds;

    setSotpTimeValue = curentTimeInSeconds - (PAL_MINIMUM_STORAGE_LATENCY_SEC + 50);
    sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setSotpTimeValue);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    status = pal_osSetWeakTime(setTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_EQUAL_UINT64(sotpGetTime, setTimeInSeconds);
#endif

    /*#2*/
    curentTimeInSeconds = pal_osGetTime();
    setTimeInSeconds = curentTimeInSeconds - 50;

    setSotpTimeValue = curentTimeInSeconds;
    sotpStatus = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&setSotpTimeValue);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    status = pal_osSetWeakTime(setTimeInSeconds);
 	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	
#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);
#endif

#if (PAL_USE_HW_RTC)
    //restore System time
    pal_plat_osSetRtcTime(testStartTime + PAL_RUNNING_TEST_TIME);
#endif
}

/*! \brief Check Strong Set Time.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | checking RTC flow - set new RTC time					                		| PAL_SUCCESS |
* | 2 | checking RTC flow - not set RTC new time				                		| PAL_SUCCESS |
* | 3 | checking SOTP flow - set SOTP SAVED TIME and LAST TIME BACK to new time	        | PAL_SUCCESS |
* | 4 | checking SOTP flow - not set SOTP SAVED TIME and LAST TIME BACK to new time       | PAL_SUCCESS |
*/
TEST(pal_time, OsStrongSetTime)
{
    palStatus_t status;
    sotp_result_e sotpStatus = SOTP_SUCCESS;
    uint64_t setTimeInSeconds = 0;
    uint64_t curentTimeInSeconds = 0;
    uint64_t pal_Time = 0;
    uint64_t sotpGetTime = 0;
    uint16_t actualLenBytes = 0;
    uint64_t setSotpTimeValue = 0;

#if (PAL_USE_HW_RTC)
    //This code is to preserve system time
    uint64_t testStartTime = 0;
    status = pal_plat_osGetRtcTime(&testStartTime);
#endif

    /*#1*/
#if (PAL_USE_HW_RTC)
    pal_plat_osSetRtcTime(PAL_MIN_RTC_SET_TIME);
#endif
    pal_osSetTime(PAL_MIN_SEC_FROM_EPOCH + PAL_SECONDS_PER_DAY * 100);
    curentTimeInSeconds = pal_osGetTime();
    setTimeInSeconds = curentTimeInSeconds;

#if (PAL_USE_HW_RTC)
    uint64_t rtcTime = 0;
    rtcTime = curentTimeInSeconds - (50 + PAL_MINIMUM_RTC_LATENCY_SEC);
    status = pal_plat_osSetRtcTime(rtcTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif//PAL_USE_HW_RTC

    status = pal_osSetStrongTime(setTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if (PAL_USE_HW_RTC)
    status = pal_plat_osGetRtcTime(&rtcTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL_UINT64(rtcTime, setTimeInSeconds);
#endif//PAL_USE_HW_RTC

    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5)
    {
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    curentTimeInSeconds = pal_osGetTime();
    setTimeInSeconds = curentTimeInSeconds;

#if (PAL_USE_HW_RTC)
    rtcTime = curentTimeInSeconds;
    status = pal_plat_osSetRtcTime(rtcTime - 50);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif//PAL_USE_HW_RTC

    status = pal_osSetStrongTime(setTimeInSeconds);

#if (PAL_USE_HW_RTC)
    status = pal_plat_osGetRtcTime(&rtcTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(rtcTime, setTimeInSeconds);
#endif//PAL_USE_HW_RTC

    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5){
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    curentTimeInSeconds = pal_osGetTime();
    setTimeInSeconds = curentTimeInSeconds;
    setSotpTimeValue = curentTimeInSeconds - (PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC + 1*PAL_ONE_SEC);
    sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setSotpTimeValue);
	TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    status = pal_osSetStrongTime(setTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_EQUAL_UINT64(sotpGetTime, setTimeInSeconds);

    sotpStatus = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_EQUAL_UINT64(sotpGetTime, setTimeInSeconds);
#endif

    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5)
    {
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    curentTimeInSeconds = pal_osGetTime();
    setTimeInSeconds = curentTimeInSeconds;

    setSotpTimeValue = curentTimeInSeconds - 5;
    sotpStatus = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setSotpTimeValue);
	TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    sotpStatus = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&setSotpTimeValue);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);

    status = pal_osSetStrongTime(setTimeInSeconds);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if PAL_USE_INTERNAL_FLASH
    sotpStatus = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);

    sotpStatus = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    TEST_ASSERT_EQUAL_HEX(SOTP_SUCCESS, sotpStatus);
    TEST_ASSERT_NOT_EQUAL(sotpGetTime, setTimeInSeconds);
#endif

    pal_Time = pal_osGetTime();
    if (pal_Time - setTimeInSeconds > 5)
    {
    	status = PAL_ERR_GENERAL_BASE;
    }
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

#if (PAL_USE_HW_RTC)
    //restore System time
    pal_plat_osSetRtcTime(testStartTime + PAL_RUNNING_TEST_TIME);
#endif
}
