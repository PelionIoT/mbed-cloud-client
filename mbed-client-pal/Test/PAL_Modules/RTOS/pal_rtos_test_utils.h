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

#ifndef _PAL_RTOS_TEST_UTILS_H
#define _PAL_RTOS_TEST_UTILS_H

#include "pal.h"

// XXX: remove this block completely once all the tests pass again
#if 0    //MUST MOVE TO PLATFORM SPECIFIC HEADER
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"

#include "pin_mux.h"
#include "clock_config.h"


#define MUTEX_UNITY_TEST 1
#define SEMAPHORE_UNITY_TEST 1
#endif   // MUST MOVE TO PLATFORM SPECIFIC HEADER
#define PAL_TIME_TO_WAIT_MS	5000 //in [ms]
#define PAL_TIME_TO_WAIT_SHORT_MS	300 //in [ms]
#define PAL_TIMER_TEST_TIME_TO_WAIT_MS_SHORT 40 //in [ms]
#define PAL_TIMER_TEST_TIME_TO_WAIT_MS_LONG 130 //in [ms]

typedef struct threadsArgument{
    uint32_t arg1;
    uint32_t arg2;
    uint32_t arg3;
    uint32_t arg4;
    uint32_t arg5;
    uint32_t arg6;
    uint32_t arg7;
    uint8_t threadCounter;
}threadsArgument_t;


extern threadsArgument_t g_threadsArg;

void palThreadFunc1(void const *argument);
void palThreadFunc2(void const *argument);
void palThreadFunc3(void const *argument);
void palThreadFunc4(void const *argument);
void palThreadFunc5(void const *argument);
void palThreadFunc6(void const *argument);


typedef struct timerArgument{
    uint32_t ticksBeforeTimer;
    uint32_t ticksInFunc1;
    uint32_t ticksInFunc2;
}timerArgument_t;

extern volatile timerArgument_t g_timerArgs;

void palTimerFunc1(void const *argument);
void palTimerFunc2(void const *argument);
void palTimerFunc3(void const *argument);
void palTimerFunc4(void const *argument);
void palTimerFunc5(void const *argument);
void palTimerFunc6(void const *argument);
void palTimerFunc7(void const *argument);
void palTimerFunc8(void const *argument);


void palThreadFuncWaitForEverTest(void const *argument);

void RecursiveLockThread(void const *param);
typedef struct palRecursiveMutexParam{
    palMutexID_t mtx;
    palSemaphoreID_t sem;
    size_t count;
    palThreadID_t higherPriorityThread;
    palThreadID_t lowerPriorityThread;
    palThreadID_t activeThread;
} palRecursiveMutexParam_t;

#define MEMORY_POOL1_BLOCK_SIZE 32
#define MEMORY_POOL1_BLOCK_COUNT 5
#define MEMORY_POOL2_BLOCK_SIZE 12
#define MEMORY_POOL2_BLOCK_COUNT 4

extern palMutexID_t mutex1;
extern palMutexID_t mutex2;

extern palSemaphoreID_t semaphore1;

#endif //_PAL_RTOS_TEST_UTILS_H
