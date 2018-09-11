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
#include "pal_rtos_test_utils.h"
#include <string.h>
#include <stdlib.h>
#include "sotp.h"
#include "pal_plat_rtos.h"

#define TRACE_GROUP "PAL"

TEST_GROUP(pal_rtos);

//Sometimes you may want to get local data in a module,
//for example if you need to pass a reference.
//However, you should usually avoid this.
//extern int Counter;
threadsArgument_t g_threadsArg = {0};
timerArgument_t g_timerArgs = {0};
palMutexID_t mutex1 = NULLPTR;
palMutexID_t mutex2 = NULLPTR;
palSemaphoreID_t semaphore1 = NULLPTR;
palRecursiveMutexParam_t* recursiveMutexData = NULL;
#define PAL_RUNNING_TEST_TIME   5  //estimation on length of test in seconds
#define PAL_TEST_HIGH_RES_TIMER 100
#define PAL_TEST_HIGH_RES_TIMER2 10
#define PAL_TEST_PERCENTAGE_LOW 95
#define PAL_TEST_PERCENTAGE_HIGH 105
#define PAL_TEST_PERCENTAGE_HUNDRED  100

//Forward declarations
void palRunThreads(void);


TEST_SETUP(pal_rtos)
{
    palStatus_t status = PAL_SUCCESS;
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

}

TEST_TEAR_DOWN(pal_rtos)
{
    if (NULL != recursiveMutexData)
    {
        if (recursiveMutexData->higherPriorityThread != NULLPTR)
        {
            pal_osThreadTerminate(&(recursiveMutexData->higherPriorityThread));
        }
        if (recursiveMutexData->lowerPriorityThread != NULLPTR)
        {
            pal_osThreadTerminate(&(recursiveMutexData->lowerPriorityThread));
        }
        if (recursiveMutexData->mtx != NULLPTR)
        {
            pal_osMutexDelete(&(recursiveMutexData->mtx));
        }
        if (recursiveMutexData->sem != NULLPTR)
        {
            pal_osSemaphoreDelete(&recursiveMutexData->sem);
        }
        free(recursiveMutexData);
        recursiveMutexData = NULL;
    }
    pal_destroy();
}

/*! \brief Sanity check of the kernel system tick API.
 * Fails if system tic value is zero (**note:** this can sometimes happen on wrap-around).
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Get current tick count using `pal_osKernelSysTick` and check that it is not 0.  | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_osKernelSysTick_Unity)
{
    uint32_t tick1 = 0, tick2 = 0;
    /*#1*/
    tick1 = pal_osKernelSysTick();
    PAL_PRINTF("%" PRIu32 " %" PRIu32 "\n", tick1, tick2);

    TEST_ASSERT_TRUE(tick2 != tick1);
}

/*! \brief Sanity check of the kernel system tick API.
 * Fails if two calls return the same `sysTick` value.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Get current tick count using `pal_osKernelSysTick`.       | PAL_SUCCESS |
 * | 2 | Get current tick count using `pal_osKernelSysTick`.       | PAL_SUCCESS |
 * | 3 | Check that the two tick count values are not the same. | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_osKernelSysTick64_Unity)
{
    uint64_t tick1 = 0, tick2 = 0;
    /*#1*/
    tick1 = pal_osKernelSysTick();
    /*#2*/
    tick2 = pal_osKernelSysTick();
    /*#3*/
    TEST_ASSERT_TRUE(tick2 >= tick1);
}

/*! \brief Check the conversion from a non-zero `sysTick` value to microseconds.
 * Verify that the result is not 0.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Convert a nubmer in `sysTicks` to microseconds using `pal_osKernelSysTickMicroSec` and check it is not 0. | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_osKernelSysTickMicroSec_Unity)
{
    uint64_t tick = 0;
    uint64_t microSec = 2000 * 1000;
    /*#1*/
    tick = pal_osKernelSysTickMicroSec(microSec);
    TEST_ASSERT_TRUE(0 != tick);
}

/*! \brief Sanity check of non-zero values conversion between microseconds to ticks to milliseconds.
 * Verify that the result is correct when converting the input (microseconds) to the test output (milliseconds).
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Convert a nubmer in `sysTicks` to mircorseconds using `pal_osKernelSysTickMicroSec` and check it is not 0. | PAL_SUCCESS |
 * | 2 | Convert a nubmer in `sysTicks` to milliseconds using `pal_osKernelSysMilliSecTick` and check the returned value. | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_osKernelSysMilliSecTick_Unity)
{
    uint64_t tick = 0;
    uint64_t microSec = 200 * 1000;
    uint64_t milliseconds = 0;
    /*#1*/
    tick = pal_osKernelSysTickMicroSec(microSec);
    TEST_ASSERT_TRUE(0 != tick);
    /*#2*/
    milliseconds = pal_osKernelSysMilliSecTick(tick);
    TEST_ASSERT_EQUAL(microSec/1000, milliseconds);
   
}

/*! \brief Verify that the tick frequency function returns a non-zero value.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Get the kernel `sysTick` frequency and check that it is positive.     | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_osKernelSysTickFrequency_Unity)
{
    uint64_t frequency = 0;
    /*#1*/
    frequency = pal_osKernelSysTickFrequency();

    TEST_ASSERT_TRUE(frequency > 0);
}

/*! \brief Sanity check for the Delay API, verifying that `sysTick` increments after delay.
 * The test reads two system tick values. Between the two calls, it calls the delay function and
 * verifies that the tick values are different.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Get the kernel `sysTick` value.                           | PAL_SUCCESS |
 * | 2 | Sleep for a short period .                              | PAL_SUCCESS |
 * | 3 | Get the kernel `sysTick` value.                          | PAL_SUCCESS |
 * | 4 | Check that second tick value is greater than the first. | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_osDelay_Unity)
{
    palStatus_t status = PAL_SUCCESS;
    uint32_t tick1 , tick2;
    /*#1*/
    tick1 = pal_osKernelSysTick();
    /*#2*/
    status = pal_osDelay(200);
    /*#3*/
    tick2 = pal_osKernelSysTick();
    /*#4*/
    TEST_ASSERT_TRUE(tick2 > tick1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

/*! \brief Test for basic timing scenarios based on calls for the ticks and delay
* functionality while verifying that results meet the defined deltas.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Get the kernel `sysTick` value.                                      | PAL_SUCCESS |
* | 2 | Sleep for a very short period.                                     | PAL_SUCCESS |
* | 3 | Get the kernel `sysTick` value.                                      | PAL_SUCCESS |
* | 4 | Check that second tick value is greater than the first.            | PAL_SUCCESS |
* | 5 | Get the kernel `sysTick` value.                                      | PAL_SUCCESS |
* | 6 | Sleep for a longer period.                                         | PAL_SUCCESS |
* | 7 | Get the kernel `sysTick` value.                                      | PAL_SUCCESS |
* | 8 | Check that second tick value is greated than the first.           | PAL_SUCCESS |
* | 9 | Calculate the difference between the ticks.                                | PAL_SUCCESS |
* | 10 | Convert last sleep period to ticks.                              | PAL_SUCCESS |
* | 11 | Check that the tick period is correct (same as sleep period +/-delta). | PAL_SUCCESS |
*/
TEST(pal_rtos, BasicTimeScenario)
{
    palStatus_t status = PAL_SUCCESS;
    uint64_t tick, tick1 , tick2 , tickDiff, tickDelta;

    /*#1*/
    tick1 = pal_osKernelSysTick();
    /*#2*/
    status = pal_osDelay(1);
    /*#3*/
    tick2 = pal_osKernelSysTick();

    /*#4*/
    TEST_ASSERT_TRUE(tick1 != tick2);
    TEST_ASSERT_TRUE(tick2 > tick1);  // To check that the tick counts are incremental - be aware of wrap-arounds
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /****************************************/
    /*#5*/
    tick1 = pal_osKernelSysTick();
    /*#6*/
    status = pal_osDelay(2000);
    /*#7*/
    tick2 = pal_osKernelSysTick();

    /*#8*/
    TEST_ASSERT_TRUE(tick1 != tick2);
    TEST_ASSERT_TRUE(tick2 > tick1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#9*/
    tickDiff = tick2 - tick1;
    /*#10*/
    tick = pal_osKernelSysTickMicroSec(2000 * 1000);
    // 10 milliseconds delta
    /*#11*/
    tickDelta = pal_osKernelSysTickMicroSec(10 * 1000);
    TEST_ASSERT_TRUE((tick - tickDelta < tickDiff) && (tickDiff < tick + tickDelta));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

/*! \brief Create two timers: periodic and one-shot. Starts both timers,
* then causes a delay to allow output from the timer functions to be printed on the console.
*
* | # |    Step                                                                                          |   Expected                     |
* |---|--------------------------------------------------------------------------------------------------|--------------------------------|
* | 1 | Create a one-shot timer, which calls `palTimerFunc1` when triggered, using `pal_osTimerCreate`.  | PAL_SUCCESS                    |
* | 2 | Create a periodic timer, which calls `palTimerFunc2` when triggered, using `pal_osTimerCreate`.  | PAL_SUCCESS                    |
* | 3 | Get the kernel `sysTick` value.                                                                  | PAL_SUCCESS                    |
* | 4 | Start the first timer using `pal_osTimerStart`.                                                  | PAL_SUCCESS                    |
* | 5 | Get the kernel `sysTick` value.                                                                  | PAL_SUCCESS                    |
* | 6 | Start the first timer using `pal_osTimerStart`.                                                  | PAL_SUCCESS                    |
* | 7 | Sleep for a period.                                                                              | PAL_SUCCESS                    |
* | 8 | Stop the second timer using `pal_osTimerStop`.                                                   | PAL_SUCCESS                    |
* | 9 | Delete the first timer using `pal_osTimerDelete`.                                                | PAL_SUCCESS                    |
* | 10 | Delete the second timer using `pal_osTimerDelete`.                                              | PAL_SUCCESS                    |
* | 11 | Create a periodic timer, which calls `palTimerFunc3` when triggered, using `pal_osTimerCreate`. | PAL_SUCCESS                    |
* | 12 | Create a periodic timer, which calls `palTimerFunc4` when triggered, using `pal_osTimerCreate`. | PAL_ERR_NO_HIGH_RES_TIMER_LEFT |
* | 13 | Start the first timer using `pal_osTimerStart` as high res timer.                               | PAL_SUCCESS                    |
* | 14 | Start the second timer using `pal_osTimerStart` as high res timer.                              | PAL_ERR_NO_HIGH_RES_TIMER_LEFT |
* | 15 | Sleep for a period.                                                                             | PAL_SUCCESS                    |
* | 16 | Stop the second timer using `pal_osTimerStop`.                                                  | PAL_SUCCESS                    |
* | 17 | Start the second timer using `pal_osTimerStart` as high res timer                               | PAL_SUCCESS                    |
* | 18 | Sleep for a period.                                                                             | PAL_SUCCESS                    |
* | 19 | Delete the first timer using `pal_osTimerDelete`.                                               | PAL_SUCCESS                    |
* | 20 | Delete the second timer using `pal_osTimerDelete`.                                              | PAL_SUCCESS                    |
* | 21 | Create a periodic timer, which calls `palTimerFunc5` when triggered, using `pal_osTimerCreate`. | PAL_SUCCESS                    |
* | 22 | Sleep for a period.                                                                             | PAL_SUCCESS                    |
* | 23 | Delete the first timer using `pal_osTimerDelete`.                                               | PAL_SUCCESS                    |
* | 24 | Stop the timer using `pal_osTimerStop`.  and check the number of callbacks is correct           | PAL_SUCCESS                    |
* | 25 | Delete the timer using `pal_osTimerDelete`.                                                     | PAL_SUCCESS                    |
* | 26 | Start the timer with zero millisec.                                                             | PAL_ERR_RTOS_VALUE             |
* | 27 | Delete the timer using `pal_osTimerDelete`.                                                     | PAL_SUCCESS                    |
*/
TEST(pal_rtos, TimerUnityTest)
{
    palStatus_t status = PAL_SUCCESS;
    palTimerID_t timerID1 = NULLPTR;
    palTimerID_t timerID2 = NULLPTR;
    /*#1*/
    status = pal_osTimerCreate(palTimerFunc1, NULL, palOsTimerOnce, &timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_osTimerCreate(palTimerFunc2, NULL, palOsTimerPeriodic, &timerID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    g_timerArgs.ticksBeforeTimer = pal_osKernelSysTick();
    /*#4*/
    status = pal_osTimerStart(timerID1, 1000);
    PAL_PRINTF("ticks before Timer: 0 - %" PRIu32 "\n", g_timerArgs.ticksBeforeTimer);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    g_timerArgs.ticksBeforeTimer = pal_osKernelSysTick();
    /*#6*/
    status = pal_osTimerStart(timerID2, 1000);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#7*/
    status = pal_osDelay(1500);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#8*/
    status = pal_osTimerStop(timerID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#9*/
    status = pal_osTimerDelete(&timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, timerID1);
    /*#10*/
    status = pal_osTimerDelete(&timerID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, timerID2);

	g_timerArgs.ticksBeforeTimer = 0;
    g_timerArgs.ticksInFunc1 = 0;
    g_timerArgs.ticksInFunc2 = 0;
	
    /*#11*/
    status = pal_osTimerCreate(palTimerFunc3, NULL, palOsTimerPeriodic, &timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    
    /*#12*/
    status = pal_osTimerCreate(palTimerFunc4, NULL, palOsTimerPeriodic, &timerID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#13*/
    status = pal_osTimerStart(timerID1, PAL_TEST_HIGH_RES_TIMER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#14*/
    status = pal_osTimerStart(timerID2, PAL_TEST_HIGH_RES_TIMER);
    if (PAL_SUCCESS == status) // behavior is slightly different for Linux due to high res timer limitation there (only one at a time supported there)
	{
		status = pal_osTimerStop(timerID2);
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
	else  
	{
		TEST_ASSERT_EQUAL_HEX(PAL_ERR_NO_HIGH_RES_TIMER_LEFT, status);
	}
    /*#15*/
    status = pal_osDelay(500);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#16*/
    status = pal_osTimerStop(timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#17*/
    status = pal_osTimerStart(timerID2, PAL_TEST_HIGH_RES_TIMER2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#18*/
    status = pal_osDelay(PAL_TIME_TO_WAIT_SHORT_MS);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osTimerStop(timerID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

	TEST_ASSERT_TRUE(g_timerArgs.ticksInFunc1 >= ((PAL_TIME_TO_WAIT_SHORT_MS / PAL_TEST_HIGH_RES_TIMER2)*PAL_TEST_PERCENTAGE_LOW)/ PAL_TEST_PERCENTAGE_HUNDRED); // check there is at least more than 95% of expected timer callbacks.
	
    /*#19*/
    status = pal_osTimerDelete(&timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, timerID1);
    
    /*#20*/
    status = pal_osTimerDelete(&timerID2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, timerID2);

    /*#21*/
    g_timerArgs.ticksBeforeTimer = 0;
    g_timerArgs.ticksInFunc1 = 0;
    g_timerArgs.ticksInFunc2 = 0;

    status = pal_osTimerCreate(palTimerFunc5, NULL, palOsTimerPeriodic, &timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#22*/
    status = pal_osTimerStart(timerID1, PAL_TEST_HIGH_RES_TIMER);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    
    /*#23*/
    status = pal_osDelay(PAL_TIME_TO_WAIT_MS);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#24*/
    status = pal_osTimerStop(timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    TEST_ASSERT_TRUE(g_timerArgs.ticksInFunc1 >= ((PAL_TIME_TO_WAIT_MS / PAL_TEST_HIGH_RES_TIMER) * PAL_TEST_PERCENTAGE_LOW) / PAL_TEST_PERCENTAGE_HUNDRED); // check there is at least more than 95% of expected timer callbacks.
    TEST_ASSERT_TRUE(g_timerArgs.ticksInFunc1 <= ((PAL_TIME_TO_WAIT_MS / PAL_TEST_HIGH_RES_TIMER) * PAL_TEST_PERCENTAGE_HIGH) / PAL_TEST_PERCENTAGE_HUNDRED); // check there is at most less than 105% of expected timer callbacks.

    /*#25*/
    status = pal_osTimerDelete(&timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, timerID1);

    /*#26*/
    status = pal_osTimerCreate(palTimerFunc5, NULL, palOsTimerPeriodic, &timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_osTimerStart(timerID1, 0);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_VALUE, status);

    /*#27*/
    status = pal_osTimerDelete(&timerID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

/*! \brief Creates mutexes and semaphores and uses them to communicate between
* the different threads it creates (as defined in `pal_rtos_test_utils.c`).
* In this test, we check that thread communication is working as expected between the threads and in the designed order.
* In one case, we expect the thread to fail to lock a mutex – (thread1).
* Threads are created with different priorities (PAL enforces this attribute).
* For each case, the thread function prints the expected result. The test code verifies this result as well.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a mutex using `pal_osMutexCreate`.                           | PAL_SUCCESS |
* | 2 | Create a mutex using `pal_osMutexCreate`.                           | PAL_SUCCESS |
* | 3 | Create a semaphore with count 1.                                  | PAL_SUCCESS |
* | 4 | Run the PAL test threads using the `palRunThreads` test function.  | PAL_SUCCESS |
* | 5 | Delete the semaphore using `pal_osSemaphoreDelete`.                     | PAL_SUCCESS |
* | 6 | Delete the first mutex using `pal_osMutexDelete`.                       | PAL_SUCCESS |
* | 7 | Delete the second mutex using `pal_osMutexDelete`.                       | PAL_SUCCESS |
*/
TEST(pal_rtos, PrimitivesUnityTest1)
{
    palStatus_t status = PAL_SUCCESS;
    /*#1*/
    status = pal_osMutexCreate(&mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_osMutexCreate(&mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_osSemaphoreCreate(1 ,&semaphore1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    palRunThreads();
    /*#5*/
    status = pal_osSemaphoreDelete(&semaphore1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, semaphore1);
    /*#6*/
    status = pal_osMutexDelete(&mutex1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, mutex1);
    /*#7*/
    status = pal_osMutexDelete(&mutex2);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(NULLPTR, mutex2);

}

/*! \brief Verifies that several RTOS primitives APIs can handle invalid
* arguments. The test calls each API with invalid arguments and verifies the result.
* It also verifies that the semaphore wait API can accept NULL as the third parameter.
*
* | # |    Step                                                                      |   Expected               |
* |---|------------------------------------------------------------------------------|--------------------------|
* | 1 | Test thread creation with invalid arguments (`pal_osThreadCreateWithAlloc`). | PAL_ERR_INVALID_ARGUMENT |
* | 2 | Test thread creation with invalid arguments (`pal_osThreadCreateWithAlloc`). | PAL_ERR_INVALID_ARGUMENT |
* | 3 | Test thread creation with invalid arguments (`pal_osThreadCreateWithAlloc`). | PAL_ERR_INVALID_ARGUMENT |
* | 4 | Test semaphore creation with invalid arguments (`pal_osSemaphoreCreate`).    | PAL_ERR_INVALID_ARGUMENT |
* | 5 | Test semaphore creation with invalid arguments (`pal_osSemaphoreCreate`).    | PAL_ERR_INVALID_ARGUMENT |
* | 6 | Test semaphore creation with invalid arguments (`pal_osSemaphoreCreate`).    | PAL_ERR_INVALID_ARGUMENT |
* | 7 | Test semaphore creation with invalid arguments (`pal_osSemaphoreCreate`).    | PAL_ERR_INVALID_ARGUMENT |
* | 8 | Test legacy thread create api (pal_osThreadCreate).                          | PAL_SUCCESS              |
* | 9 | Call pal_osThreadTerminate with NULL invalid parameter.                      | PAL_ERR_INVALID_ARGUMENT |
*/
TEST(pal_rtos, PrimitivesUnityTest2)
{
#ifdef DEBUG
	palStatus_t status = PAL_SUCCESS;
	palThreadID_t threadID = NULLPTR;
    int32_t tmp = 0;
    /*#1*/
    //Check thread parameter validation
    status = pal_osThreadCreateWithAlloc(palThreadFunc1, NULL, PAL_osPriorityError, 1024, NULL, &threadID);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#2*/
    status = pal_osThreadCreateWithAlloc(palThreadFunc1, NULL, PAL_osPriorityIdle, 0, NULL, &threadID);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#3*/
    status = pal_osThreadCreateWithAlloc(palThreadFunc1, NULL, PAL_osPriorityIdle, 1024, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);

    /*#4*/
    //Check semaphore parameter validation
    status = pal_osSemaphoreCreate(1 ,NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#5*/
    status = pal_osSemaphoreDelete(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#6*/
    status = pal_osSemaphoreWait(NULLPTR, 1000, &tmp);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#7*/
    status = pal_osSemaphoreRelease(NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#9*/
    status = pal_osThreadTerminate(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif
}

/*! \brief Creates a semaphore with count=1 and a thread to
* test that it waits forever (the test waits 5 seconds). Then deletes the semaphore
* and terminates the thread.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a semaphore with count = 1 using `pal_osSemaphoreCreate`.                          | PAL_SUCCESS |
* | 2 | Wait for the semaphore using `pal_osSemaphoreWait` (should not block).                    | PAL_SUCCESS |
* | 3 | Create a thread running `palThreadFuncWaitForEverTestusing` and `pal_osThreadCreateWithAlloc`. | PAL_SUCCESS |
* | 4 | Set time using `pal_osSetTime`.                                                           | PAL_SUCCESS |
* | 5 | Wait for the semaphore using `pal_osSemaphoreWait` (should block; released by thread).        | PAL_SUCCESS |
* | 6 | Delete the semaphore using `pal_osSemaphoreDelete`.                                           | PAL_SUCCESS |
* | 7 | Terminate the thread using `pal_osThreadTerminate`.                                           | PAL_SUCCESS |
*/
TEST(pal_rtos, SemaphoreWaitForever)
{
    int32_t count = 0;
    uint64_t timeElapsed = PAL_MIN_SEC_FROM_EPOCH;
    uint64_t timePassedInSec;
    palStatus_t status = PAL_SUCCESS;
    palThreadID_t threadID1 = PAL_INVALID_THREAD;

    /*#1*/
    status = pal_osSemaphoreCreate(1 ,&semaphore1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_osSemaphoreWait(semaphore1, PAL_RTOS_WAIT_FOREVER, &count);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_osSetTime(timeElapsed);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status); // More than current epoch time -> success    
    status = pal_osThreadCreateWithAlloc(palThreadFuncWaitForEverTest, (void *)&semaphore1, PAL_osPriorityAboveNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &threadID1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
    status = pal_osSemaphoreWait(semaphore1, PAL_RTOS_WAIT_FOREVER, &count);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    timePassedInSec = pal_osGetTime();
    TEST_ASSERT_EQUAL_HEX(0, (timePassedInSec - timeElapsed) >= PAL_TIME_TO_WAIT_MS/2);
    /*#6*/
    status = pal_osSemaphoreDelete(&semaphore1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, semaphore1);
    /*#7*/
    status = pal_osThreadTerminate(&threadID1);
    TEST_ASSERT_EQUAL(PAL_SUCCESS, status);
}

/*! \brief Creates a semaphore and waits on it to verify the
* available count for it. Also verifies that the semaphore release API works correctly.
* In addition, it checks the semaphore parameter validation scenarios.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a semaphore with count = 2 using `pal_osSemaphoreCreate`.                          | PAL_SUCCESS |
* | 2 | Wait for the semaphore using `pal_osSemaphoreWait` (should not block), and check count.   | PAL_SUCCESS |
* | 3 | Increase semaphore count by ten using `pal_osSemaphoreRelease` in a loop.             | PAL_SUCCESS |
* | 4 | Delete semaphore using `pal_osSemaphoreDelete`.                                           | PAL_SUCCESS |
* | 5 | Test semaphore creation with invalid arguments (`pal_osSemaphoreCreate`).                 | PAL_ERR_INVALID_ARGUMENT |
* | 6 | Test semaphore deletion with invalid arguments (`pal_osSemaphoreDelete`).                 | PAL_ERR_INVALID_ARGUMENT |
* | 7 | Test semaphore waiting with invalid arguments (`pal_osSemaphoreWait`).                    | PAL_ERR_INVALID_ARGUMENT |
* | 8 | Test semaphore release with invalid arguments (`pal_osSemaphoreRelease`).                 | PAL_ERR_INVALID_ARGUMENT |
*/
TEST(pal_rtos, SemaphoreBasicTest)
{

    palStatus_t status = PAL_SUCCESS;
    int counter = 0;
    /*#1*/
    status = pal_osSemaphoreCreate(2 ,&semaphore1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    int32_t count = -1;
    status = pal_osSemaphoreWait(semaphore1, 1000, &count);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(1, count);

    /*#3*/
    for(counter = 0; counter < 10; counter++)
    {
        status=pal_osSemaphoreRelease(semaphore1);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    }
    /*#4*/
    status=pal_osSemaphoreDelete(&semaphore1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, semaphore1);

    
#ifdef DEBUG
    //Check semaphore parameter validation
    int32_t tmp;
    /*#5*/
    status = pal_osSemaphoreCreate(1 ,NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#6*/
    status = pal_osSemaphoreDelete(NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#7*/
    status = pal_osSemaphoreWait(NULLPTR, 1000, &tmp);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    /*#8*/
    status = pal_osSemaphoreRelease(NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif
}



/*! \brief Performs a single atomic increment call
* to an integer value and verifies that the result is as expected.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Call atomic increment using `pal_osAtomicIncrement` and check that the value was incremented. | PAL_SUCCESS |
*/
TEST(pal_rtos, AtomicIncrementUnityTest)
{
    int32_t num1 = 0;
    int32_t increment = 10;
    int32_t tmp = 0;
    int32_t original = num1;
    /*#1*/
    tmp = pal_osAtomicIncrement(&num1, increment);


    TEST_ASSERT_EQUAL(original + increment, tmp);

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
TEST(pal_rtos, RandomUnityTest)
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

    /*#10*/
    pal_destroy();
    status = pal_osRandomBuffer(randomBufArray[0].rand, sizeof(randomBufArray[0].rand));
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_NOT_INITIALIZED, status);
}


/*! \brief call the random API in a PAL_RANDOM_TEST_LOOP loop.
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Call `pal_osRandomBuffer` in a PAL_RANDOM_TEST_LOOP loop .         PAL_SUCCESS |
*/
TEST(pal_rtos, loopRandomBigNumber)
{
	palStatus_t status = PAL_SUCCESS;
	uint8_t loopRandomArray[PAL_RANDOM_ARRAY_TEST_SIZE];

	for (int i = 0; i < PAL_RANDOM_TEST_LOOP; ++i)
	{
		status = pal_osRandomBuffer(loopRandomArray, sizeof(loopRandomArray));
		TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
	}
}

/*! \brief Verify that PAL can handle multiple calls for `pal_init()` and `pal_destroy()`.
*
* | # |    Step                                              |   Expected  |
* |---|------------------------------------------------------|-------------|
* | 1 | Call `pal_init`.                                     | PAL_SUCCESS |
* | 2 | Call `pal_init`.                                     | PAL_SUCCESS |
* | 3 | Call `pal_init`.                                     | PAL_SUCCESS |
* | 4 | Call `pal_destroy` in a loop untill init count == 0. | PAL_SUCCESS |
* | 5 | Call `pal_init`.                                     | PAL_SUCCESS |
* | 6 | Call `pal_RTOSInitialize`.                           | PAL_SUCCESS |
* | 7 | Call `pal_destroy`.                                  | PAL_SUCCESS |
*/
TEST(pal_rtos, pal_init_test)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t initCounter = 0;
    /*#1*/
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    do
    {
        initCounter = pal_destroy();
        //TEST_ASSERT_EQUAL_HEX(0, initCounter);

    }while(initCounter != 0);

    /*#5*/
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_RTOSInitialize(NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#7*/
    initCounter = pal_destroy();
    TEST_ASSERT_EQUAL_HEX(0, initCounter);
}

/*! \brief Check derivation of keys from the platform's Root of Trust using the KDF algorithm.
 *
 * 
 *
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Start a loop to perform the following steps.                                               |  |
* | 2 | Derive a device key for encryption using `pal_osGetDeviceKey`.                   | PAL_SUCCESS |
* | 3 | Derive a device key for signing using `pal_osGetDeviceKey`.                      | PAL_SUCCESS |
* | 4 | Call `pal_osGetDeviceKey` with invalid arguments.                              | PAL_FAILURE |
* | 5 | Call `pal_osGetDeviceKey` with invalid arguments.                              | PAL_FAILURE |
* | 6 | Check that the derived signing and encryption keys are different.                     | PAL_SUCCESS |
* | 7 | Check that all integrations of each type of derivation return the same value.       | PAL_SUCCESS |
 */
TEST(pal_rtos, GetDeviceKeyTest_CMAC)
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
* | 6 | Call `pal_osGetDeviceKey` with invalid palDevKeyType_t.                        | PAL_ERR_GET_DEV_KEY |
 */
TEST(pal_rtos, GetDeviceKeyTest_HMAC_SHA256)
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
TEST(pal_rtos, RealTimeClockTest1)
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


/*! \brief Check recursive mutex behavior.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Create a mutex using `pal_osMutexCreate`.                                             | PAL_SUCCESS |
* | 2 | Create a semaphore using `pal_osSemaphoreCreate`.                                     | PAL_SUCCESS |
* | 3 | Create a thread running `RecursiveLockThread` using `pal_osThreadCreateWithAlloc`.       | PAL_SUCCESS |
* | 4 | Create a thread running `RecursiveLockThread` using `pal_osThreadCreateWithAlloc`.       | PAL_SUCCESS |
* | 5 | Release the semaphore using `pal_osSemaphoreRelease`.                                    | PAL_SUCCESS |
* | 6 | Release the semaphore using `pal_osSemaphoreRelease`.                                    | PAL_SUCCESS |
* | 7 | Sleep for a short interval.                                                          | PAL_SUCCESS |
* | 8 | Wait for the semaphore using `pal_osSemaphoreWait`.                                      | PAL_SUCCESS |
* | 9 | Wait for the semaphore using `pal_osSemaphoreWait`.                                      | PAL_SUCCESS |
* | 10 | Terminate the first thread using `pal_osThreadTerminate`.                               | PAL_SUCCESS |
* | 11 | Terminate the second thread using `pal_osThreadTerminate`.                              | PAL_SUCCESS |
* | 12 | Delete the mutex using `pal_osMutexDelete`.                                           | PAL_SUCCESS |
* | 13 | Delete the semaphore using `pal_osSemaphoreDelete`.                                   | PAL_SUCCESS |
*/
TEST(pal_rtos, Recursive_Mutex_Test)
{
    palStatus_t status;
    int32_t val = 0;

    recursiveMutexData = malloc(sizeof(palRecursiveMutexParam_t));
    TEST_ASSERT_NOT_NULL(recursiveMutexData);
    memset(recursiveMutexData, 0, sizeof(palRecursiveMutexParam_t));
    /*#1*/
    status = pal_osMutexCreate(&(recursiveMutexData->mtx));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#2*/
    status = pal_osSemaphoreCreate(0, &(recursiveMutexData->sem));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#3*/
    status = pal_osThreadCreateWithAlloc(RecursiveLockThread, (void*)recursiveMutexData, PAL_osPriorityHigh, PAL_TEST_THREAD_STACK_SIZE, NULL, &(recursiveMutexData->higherPriorityThread));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#4*/
     status = pal_osThreadCreateWithAlloc(RecursiveLockThread, (void*)recursiveMutexData, PAL_osPriorityAboveNormal, PAL_TEST_THREAD_STACK_SIZE, NULL, &(recursiveMutexData->lowerPriorityThread));
     TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#5*/
    status = pal_osSemaphoreRelease(recursiveMutexData->sem);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#6*/
    status = pal_osSemaphoreRelease(recursiveMutexData->sem);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#7*/
    pal_osDelay(1000);
    /*#8*/
    status = pal_osSemaphoreWait(recursiveMutexData->sem, PAL_RTOS_WAIT_FOREVER, &val);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#9*/
    status = pal_osSemaphoreWait(recursiveMutexData->sem, PAL_RTOS_WAIT_FOREVER, &val);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, val);
    TEST_ASSERT_EQUAL_HEX(NULLPTR, recursiveMutexData->activeThread);
    /*#10*/
    status = pal_osThreadTerminate(&(recursiveMutexData->higherPriorityThread));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#11*/
    status = pal_osThreadTerminate(&(recursiveMutexData->lowerPriorityThread));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#12*/
    status = pal_osMutexDelete(&(recursiveMutexData->mtx));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    /*#13*/
    status = pal_osSemaphoreDelete(&recursiveMutexData->sem);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    TEST_ASSERT_EQUAL(400, recursiveMutexData->count);

    free(recursiveMutexData);
    recursiveMutexData = NULL;
}



/*! \brief Check Weak Set Time - Forword flow.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | checking RTC and SOTP flow - not set SOTP SAVED TIME  + LAST TIME BACK + RTC to new time          		      | PAL_SUCCESS |
* | 2 | checking RTC and SOTP flow - not set SOTP SAVED TIME  + LAST TIME BACK to new time but set RTC to new time    | PAL_SUCCESS |
* | 3 | checking RTC and SOTP flow - set SOTP SAVED TIME  + LAST TIME BACK + RTC to new time          		          | PAL_SUCCESS |
*/
TEST(pal_rtos, OsWeakSetTime_Forword)
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
TEST(pal_rtos, OsWeakSetTime_Backword)
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
TEST(pal_rtos, OsWeakSetTime_minimalStoredLag)
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
TEST(pal_rtos, OsStrongSetTime)
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


/*! \brief This test verify the functionality of the RTC
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Get system RTC                           | PAL_SUCCESS |
 * | 2 | set new RTC                              | PAL_SUCCESS |
 * | 3 | delay for 2 seconds                      | PAL_SUCCESS |
 * | 4 | get RTC & compare to RTC from (2)        | PAL_SUCCESS |
 * | 5 | restore system time from (1)             | PAL_SUCCESS |
 */
TEST(pal_rtos, pal_rtc)
{
#if (PAL_USE_HW_RTC)
    palStatus_t status = PAL_SUCCESS;
    uint64_t time1 = 0, sysTime = 0;

    /*#1*/
    status = pal_plat_osGetRtcTime(&sysTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_plat_osSetRtcTime(PAL_MIN_RTC_SET_TIME);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
    status = pal_osDelay(2000);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#4*/
    status = pal_plat_osGetRtcTime(&time1);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_TRUE(time1 - PAL_MIN_RTC_SET_TIME >=  1 * PAL_ONE_SEC);

    /*#5*/
    pal_plat_osSetRtcTime(sysTime + time1 - PAL_MIN_RTC_SET_TIME  + 1); //add lost time from delay


#endif
}

// the following functions are not part of PAL's external API hence extern
extern palStatus_t pal_noiseWriteValue(const int32_t* data, uint8_t startBit, uint8_t lenBits, uint8_t* bitsWritten);
extern palStatus_t pal_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten);
extern palStatus_t pal_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead);

/*! \brief This test verifies the functionality of noise collection
*
* | # |    Step                                                                                    |   Expected  |
* |---|--------------------------------------------------------------------------------------------|-------------|
* | 1 | Reset the noise buffer by reading watever is available                                     | PAL_SUCCESS |
* | 2 | Write an entire int32_t (all bits) and verify writes and that full read not possible       | PAL_SUCCESS |
* | 3 | Write only some bits of the int32_t and verify writes and that full read not possible      | PAL_SUCCESS |
* | 4 | Write only some bits of the int32_t, implicitly causing splitting the value into 2 indexes | PAL_SUCCESS |
* | 5 | Read whatever was collected thus far (partial read) and verify output                      | PAL_SUCCESS |
* | 6 | Try to read again and verify buffer is empty                                               | PAL_SUCCESS |
* | 7 | Write a buffer excluding the last 7 bits of the last index and verify results              | PAL_SUCCESS |
* | 8 | Fill the buffer and try to write some more data into it                                    | PAL_SUCCESS |
*/
TEST(pal_rtos, pal_noise)
{
    palStatus_t status;
    int32_t outBuffer[PAL_NOISE_BUFFER_LEN] = { 0 };
    int32_t inBuffer[] = { 0xB76EC265, 0xD16ACE6E, 0xF56AAD6A };
    uint16_t bitsWritten = 0;
    uint16_t bitsRead = 0;
    int32_t writeValue;
    uint8_t i;

    /*#1*/
    pal_noiseRead(outBuffer, true, &bitsRead);
    memset(outBuffer, 0, PAL_NOISE_SIZE_BYTES);

    /*#2*/
    writeValue = 0xCB76102A;
    status = pal_noiseWriteValue(&writeValue, 0, 32, (uint8_t*)&bitsWritten); // write all bits
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(32, bitsWritten);
    status = pal_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#3*/
    status = pal_noiseWriteValue(&writeValue, 3, 20, (uint8_t*)&bitsWritten); // write some of the bits, starting at bit index 3
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(20, bitsWritten);
    status = pal_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#4*/
    status = pal_noiseWriteValue(&writeValue, 16, 16, (uint8_t*)&bitsWritten); // write some of the bits, starting at bit index 16, this functionality tests splitting the bits into 2 different indexes
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(16, bitsWritten);
    status = pal_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#5*/
    status = pal_noiseRead(outBuffer, true, &bitsRead); // read whatever collected (resets buffer)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(64, bitsRead); // even though we wrote 68 bits by now, output should be 64 since the last byte is not full so we should not receive it back
    TEST_ASSERT_EQUAL_HEX(0xCB76102A, outBuffer[0]);
    TEST_ASSERT_EQUAL_HEX(0xB76EC205, outBuffer[1]);
    TEST_ASSERT_EQUAL_HEX(0, outBuffer[2]);
    memset(outBuffer, 0, PAL_NOISE_SIZE_BYTES);

    /*#6*/
    status = pal_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_EMPTY, status);
    TEST_ASSERT_EQUAL(0, bitsRead);

    /*#7*/
    status = pal_noiseWriteBuffer(inBuffer, ((sizeof(inBuffer) * CHAR_BIT) - 7), &bitsWritten); // write all except for the last 7 bits of index 2
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL(((sizeof(inBuffer) * CHAR_BIT) - 7), bitsWritten);
    status = pal_noiseRead(outBuffer, false, &bitsRead);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL, status);
    TEST_ASSERT_EQUAL(0, bitsRead);
    status = pal_noiseRead(outBuffer, true, &bitsRead); // read whatever collected (resets buffer)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, bitsRead);
    TEST_ASSERT_EQUAL_HEX(inBuffer[0], outBuffer[0]);
    TEST_ASSERT_EQUAL_HEX(inBuffer[1], outBuffer[1]);
    TEST_ASSERT_EQUAL_HEX(0x6AAD6A, outBuffer[2]);

    /*#8*/
    for (i = 0; i <= (sizeof(inBuffer) / sizeof(int32_t)); ++i)
    {
        status = pal_noiseWriteBuffer(inBuffer, (sizeof(inBuffer) * CHAR_BIT), &bitsWritten);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
        TEST_ASSERT_EQUAL_HEX((sizeof(inBuffer) * CHAR_BIT), bitsWritten);
    }
    status = pal_noiseWriteBuffer(inBuffer, (sizeof(inBuffer) * CHAR_BIT), &bitsWritten);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_RTOS_NOISE_BUFFER_FULL, status);
    TEST_ASSERT_EQUAL_HEX(0, bitsWritten);
}
