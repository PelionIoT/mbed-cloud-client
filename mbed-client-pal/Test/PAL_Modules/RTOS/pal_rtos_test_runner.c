/*******************************************************************************
 * Copyright 2016-2018 ARM Ltd.
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

#include "unity.h"
#include "unity_fixture.h"
#include "pal.h"

TEST_GROUP_RUNNER(pal_rtos)
{
	RUN_TEST_CASE(pal_rtos, SemaphoreWaitForever);
	RUN_TEST_CASE(pal_rtos, pal_osKernelSysTick_Unity);
	RUN_TEST_CASE(pal_rtos, pal_osKernelSysTick64_Unity);
	RUN_TEST_CASE(pal_rtos, pal_osKernelSysTickMicroSec_Unity);
	RUN_TEST_CASE(pal_rtos, pal_osKernelSysMilliSecTick_Unity);
	RUN_TEST_CASE(pal_rtos, pal_osKernelSysTickFrequency_Unity);
	RUN_TEST_CASE(pal_rtos, pal_osDelay_Unity);
	RUN_TEST_CASE(pal_rtos, BasicTimeScenario);
	RUN_TEST_CASE(pal_rtos, TimerUnityTest);
	RUN_TEST_CASE(pal_rtos, AtomicIncrementUnityTest);
	RUN_TEST_CASE(pal_rtos, PrimitivesUnityTest1);
	RUN_TEST_CASE(pal_rtos, PrimitivesUnityTest2);
	RUN_TEST_CASE(pal_rtos, SemaphoreBasicTest);
	RUN_TEST_CASE(pal_rtos, pal_init_test);
	RUN_TEST_CASE(pal_rtos, Recursive_Mutex_Test);
	RUN_TEST_CASE(pal_rtos, pal_rtc);
}

