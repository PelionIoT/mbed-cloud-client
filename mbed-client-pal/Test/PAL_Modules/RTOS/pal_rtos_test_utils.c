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
#include "pal_rtos_test_utils.h"

#include "test_runners.h"
#include "unity_fixture.h"

#include <stdio.h>

#define TRACE_GROUP "PAL"

extern threadsArgument_t g_threadsArg;
timerArgument_t timerArgs;

void palThreadFunc1(void const *argument)
{
    volatile palThreadID_t threadID;
	threadsArgument_t *tmp = (threadsArgument_t*)argument;
#ifdef MUTEX_UNITY_TEST
    palStatus_t status = PAL_SUCCESS;
    PAL_PRINTF("palThreadFunc1::before mutex\n");
    status = pal_osMutexWait(mutex1, 100);
    PAL_PRINTF("palThreadFunc1::after mutex: 0x%08x\n", status);
    PAL_PRINTF("palThreadFunc1::after mutex (expected): 0x%08x\n", PAL_ERR_RTOS_TIMEOUT);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_TIMEOUT, status);
    return; // for Mutex scenario, this should end here
#endif //MUTEX_UNITY_TEST

	tmp->arg1 = 10;
    threadID = pal_osThreadGetId();
    TEST_ASSERT_NOT_EQUAL(threadID, NULLPTR);    
    PAL_PRINTF("palThreadFunc1::Thread ID is %"PRIuPTR " \n", threadID);    
#ifdef MUTEX_UNITY_TEST
	status = pal_osMutexRelease(mutex1);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MUTEX_UNITY_TEST
    PAL_PRINTF("palThreadFunc1::STAAAAM\n");
}

void palThreadFunc2(void const *argument)
{
    volatile palThreadID_t threadID;
	threadsArgument_t *tmp = (threadsArgument_t*)argument;
#ifdef MUTEX_UNITY_TEST
    palStatus_t status = PAL_SUCCESS;
    PAL_PRINTF("palThreadFunc2::before mutex\n");
    status = pal_osMutexWait(mutex2, 300);
    PAL_PRINTF("palThreadFunc2::after mutex: 0x%08x\n", status);
    PAL_PRINTF("palThreadFunc2::after mutex (expected): 0x%08x\n", PAL_SUCCESS);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MUTEX_UNITY_TEST

	tmp->arg2 = 20;
    threadID = pal_osThreadGetId();
    TEST_ASSERT_NOT_EQUAL(threadID, NULLPTR);    
    PAL_PRINTF("palThreadFunc2::Thread ID is %"PRIuPTR "\n", threadID);
#ifdef MUTEX_UNITY_TEST
	status = pal_osMutexRelease(mutex2);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MUTEX_UNITY_TEST
    PAL_PRINTF("palThreadFunc2::STAAAAM\n");
}

void palThreadFunc3(void const *argument)
{
    volatile palThreadID_t threadID;
	threadsArgument_t *tmp = (threadsArgument_t*)argument;

#ifdef SEMAPHORE_UNITY_TEST
    palStatus_t status = PAL_SUCCESS;
    uint32_t semaphoresAvailable = 10;
    status = pal_osSemaphoreWait(semaphore1, 200, &semaphoresAvailable);
    
    if (PAL_SUCCESS == status)
    {
        PAL_PRINTF("palThreadFunc3::semaphoresAvailable: %d\n", semaphoresAvailable);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    else if(PAL_ERR_RTOS_TIMEOUT == status)
    {
        PAL_PRINTF("palThreadFunc3::semaphoresAvailable: %d\n", semaphoresAvailable);
        PAL_PRINTF("palThreadFunc3::status: 0x%08x\n", status);
        PAL_PRINTF("palThreadFunc3::failed to get Semaphore as expected\n", status);
        TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_TIMEOUT, status);
        return;
    }
    pal_osDelay(6000);
#endif //SEMAPHORE_UNITY_TEST
    tmp->arg3 = 30;
    threadID = pal_osThreadGetId();
    TEST_ASSERT_NOT_EQUAL(threadID, NULLPTR);    
    PAL_PRINTF("palThreadFunc3::Thread ID is %"PRIuPTR "\n", threadID);

#ifdef SEMAPHORE_UNITY_TEST
    status = pal_osSemaphoreRelease(semaphore1);
    PAL_PRINTF("palThreadFunc3::pal_osSemaphoreRelease res: 0x%08x\n", status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //SEMAPHORE_UNITY_TEST
    PAL_PRINTF("palThreadFunc3::STAAAAM\n");
}

void palThreadFunc4(void const *argument)
{
    volatile palThreadID_t threadID;
	threadsArgument_t *tmp = (threadsArgument_t*)argument;
#ifdef MUTEX_UNITY_TEST
    palStatus_t status = PAL_SUCCESS;
    PAL_PRINTF("palThreadFunc4::before mutex\n");
    status = pal_osMutexWait(mutex1, 200);
    PAL_PRINTF("palThreadFunc4::after mutex: 0x%08x\n", status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    pal_osDelay(3500);  //wait 3.5 seconds to make sure that the next thread arrive to this point
#endif //MUTEX_UNITY_TEST

	tmp->arg4 = 40;
    threadID = pal_osThreadGetId();
    TEST_ASSERT_NOT_EQUAL(threadID, NULLPTR);    
    PAL_PRINTF("Thread ID is %"PRIuPTR "\n", threadID);

#ifdef MUTEX_UNITY_TEST
    status = pal_osMutexRelease(mutex1);
    PAL_PRINTF("palThreadFunc4::after release mutex: 0x%08x\n", status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MUTEX_UNITY_TEST
    PAL_PRINTF("palThreadFunc4::STAAAAM\n");
}

void palThreadFunc5(void const *argument)
{
    volatile palThreadID_t threadID;
	threadsArgument_t *tmp = (threadsArgument_t*)argument;
#ifdef MUTEX_UNITY_TEST
    palStatus_t status = PAL_SUCCESS;
    PAL_PRINTF("palThreadFunc5::before mutex\n");
    status = pal_osMutexWait(mutex1, 4500);
    PAL_PRINTF("palThreadFunc5::after mutex: 0x%08x\n", status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MUTEX_UNITY_TEST
	tmp->arg5 = 50;
    threadID = pal_osThreadGetId();
    TEST_ASSERT_NOT_EQUAL(threadID, NULLPTR);    
    PAL_PRINTF("Thread ID is %"PRIuPTR "\n", threadID);
#ifdef MUTEX_UNITY_TEST
    status = pal_osMutexRelease(mutex1);
    PAL_PRINTF("palThreadFunc5::after release mutex: 0x%08x\n", status);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MUTEX_UNITY_TEST
    PAL_PRINTF("palThreadFunc5::STAAAAM\n");
}

void palThreadFunc6(void const *argument)
{
	volatile palThreadID_t threadID;
	threadsArgument_t *tmp = (threadsArgument_t*)argument;
#ifdef SEMAPHORE_UNITY_TEST
    palStatus_t status = PAL_SUCCESS;
    uint32_t semaphoresAvailable = 10;
    status = pal_osSemaphoreWait(123456, 200, &semaphoresAvailable);  //MUST fail, since there is no semaphore with ID=3
    PAL_PRINTF("palThreadFunc6::semaphoresAvailable: %d\n", semaphoresAvailable);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_PARAMETER, status);
    return;
#endif //SEMAPHORE_UNITY_TEST
	tmp->arg6 = 60;
    threadID = pal_osThreadGetId();
    TEST_ASSERT_NOT_EQUAL(threadID, NULLPTR);
    PAL_PRINTF("Thread ID is %"PRIuPTR "\n", threadID);
#ifdef SEMAPHORE_UNITY_TEST
    status = pal_osSemaphoreRelease(123456);
    PAL_PRINTF("palThreadFunc6::pal_osSemaphoreRelease res: 0x%08x\n", status);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_PARAMETER, status);
#endif //SEMAPHORE_UNITY_TEST
    PAL_PRINTF("palThreadFunc6::STAAAAM\n");
}


void palTimerFunc1(void const *argument)
{
    g_timerArgs.ticksInFunc1 = pal_osKernelSysTick();
    PAL_PRINTF("ticks in palTimerFunc1: 0 - %" PRIu32 "\n", g_timerArgs.ticksInFunc1);
    PAL_PRINTF("Once Timer function was called\n");
}

void palTimerFunc2(void const *argument)
{
    g_timerArgs.ticksInFunc2 = pal_osKernelSysTick();
    PAL_PRINTF("ticks in palTimerFunc2: 0 - %" PRIu32 "\n", g_timerArgs.ticksInFunc2);
    PAL_PRINTF("Periodic Timer function was called\n");
}

void palTimerFunc3(void const *argument)
{
    static int counter =0;
    counter++;
}

void palTimerFunc4(void const *argument)
{ 
    static int counter =0;
    counter++;
	g_timerArgs.ticksInFunc1 = counter;
}

void palTimerFunc5(void const *argument) // function to count calls + wait alternatin short and long periods for timer drift test
{
    static int counter = 0;
    counter++;
    g_timerArgs.ticksInFunc1 = counter;

#ifdef __SXOS__
    // The sleep API really should not be used from timer interrupt, as it
    // a) will panic on OS side
    // b) harm the system as it is documented that callback should not spend more than 10ms in it
#else
    if (counter % 2 == 0)
    {
        pal_osDelay(PAL_TIMER_TEST_TIME_TO_WAIT_MS_LONG);
    }
    else
    {
        pal_osDelay(PAL_TIMER_TEST_TIME_TO_WAIT_MS_SHORT);
    }
#endif
}

void palTimerFunc6(void const *argument)
{
    palTimerID_t *timerID = (palTimerID_t*)argument;

    pal_osTimerStop(*timerID);
    g_timerArgs.ticksInFunc1++;
}

void palTimerFunc7(void const *argument)
{
    palTimerID_t *timerID = (palTimerID_t*)argument;
    g_timerArgs.ticksInFunc1++;

    if (g_timerArgs.ticksInFunc1 >= 10) {
        pal_osTimerStop(*timerID);
        g_timerArgs.ticksInFunc2 = pal_osKernelSysTick();
    }
}

void palThreadFuncWaitForEverTest(void const *argument)
{
	pal_osDelay(PAL_TIME_TO_WAIT_MS/2);
	pal_osSemaphoreRelease(*((palSemaphoreID_t*)(argument)));
}

void palRunThreads()
{
	palStatus_t status = PAL_SUCCESS;
	palThreadID_t threadID1 = NULLPTR;
	palThreadID_t threadID2 = NULLPTR;
	palThreadID_t threadID3 = NULLPTR;
	palThreadID_t threadID4 = NULLPTR;
	palThreadID_t threadID5 = NULLPTR;
	palThreadID_t threadID6 = NULLPTR;

	status = pal_osThreadCreateWithAlloc(palThreadFunc1, &g_threadsArg, PAL_osPriorityIdle, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID1);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadCreateWithAlloc(palThreadFunc2, &g_threadsArg, PAL_osPriorityLow, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID2);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadCreateWithAlloc(palThreadFunc3, &g_threadsArg, PAL_osPriorityNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID3);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadCreateWithAlloc(palThreadFunc4, &g_threadsArg, PAL_osPriorityBelowNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID4);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osDelay(PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC * 2); // dealy to work around mbedOS timer issue (starting more than 6 timers at once will cause a hang)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadCreateWithAlloc(palThreadFunc5, &g_threadsArg, PAL_osPriorityAboveNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID5);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadCreateWithAlloc(palThreadFunc6, &g_threadsArg, PAL_osPriorityHigh, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID6);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	pal_osDelay(PAL_TIME_TO_WAIT_MS/5);

	status = pal_osThreadTerminate(&threadID1);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadTerminate(&threadID2);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadTerminate(&threadID3);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadTerminate(&threadID4);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadTerminate(&threadID5);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	status = pal_osThreadTerminate(&threadID6);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

void RecursiveLockThread(void const *param)
{
	size_t i = 0;
	palStatus_t status;
	palRecursiveMutexParam_t *actualParams = (palRecursiveMutexParam_t*)param;
    size_t countbeforeStart = 0;
    volatile palThreadID_t threadID = 10;
	
    status = pal_osSemaphoreWait(actualParams->sem, PAL_RTOS_WAIT_FOREVER, NULL);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    for (i = 0; i < 100; ++i)
	{
		status = pal_osMutexWait(actualParams->mtx, PAL_RTOS_WAIT_FOREVER);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        if (i == 0)
        {
            countbeforeStart = actualParams->count;
            TEST_ASSERT_EQUAL_HEX(NULLPTR, actualParams->activeThread);
            actualParams->activeThread = pal_osThreadGetId();
        }
        actualParams->count++;
        threadID = pal_osThreadGetId();
        TEST_ASSERT_NOT_EQUAL(NULLPTR, threadID);
        TEST_ASSERT_EQUAL(actualParams->activeThread, threadID);
        pal_osDelay(1);
	}

    threadID = 10;
    pal_osDelay(50);
    TEST_ASSERT_EQUAL(100, actualParams->count - countbeforeStart);
	for (i = 0; i < 100; ++i)
	{
        threadID = pal_osThreadGetId();
        TEST_ASSERT_NOT_EQUAL(NULLPTR, threadID);
        TEST_ASSERT_EQUAL(actualParams->activeThread, threadID);
		actualParams->count++;
		if (i == 99)
        {
            TEST_ASSERT_EQUAL(200, actualParams->count - countbeforeStart);
            actualParams->activeThread = NULLPTR;
        }

        status = pal_osMutexRelease(actualParams->mtx);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        pal_osDelay(1);
	}
  
    status = pal_osSemaphoreRelease(actualParams->sem);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

