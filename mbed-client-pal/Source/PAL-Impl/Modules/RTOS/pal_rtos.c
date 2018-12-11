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

#include "pal.h"
#include "pal_plat_rtos.h"

#include <stdlib.h>

#define TRACE_GROUP "PAL"

PAL_PRIVATE bool palRTOSInitialized = false;

#if (PAL_SIMULATE_RTOS_REBOOT == 1)
    #include <unistd.h>
    extern char *program_invocation_name;
#endif


palStatus_t pal_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status = PAL_SUCCESS;
    if (palRTOSInitialized)
    {
        return status;
    }

    status = pal_plat_RTOSInitialize(opaqueContext);
    if (PAL_SUCCESS == status)
    {
        palRTOSInitialized = true;
    }
    else
    {
        PAL_LOG_ERR("pal_RTOSInitialize: pal_plat_RTOSInitialize failed, status=%" PRIx32 "\n", status);
    }
    return status;
}

palStatus_t pal_RTOSDestroy(void)
{
    palStatus_t status = PAL_ERR_NOT_INITIALIZED;
    if (!palRTOSInitialized)
    {
        return status;
    }

    status = pal_plat_RTOSDestroy();
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("pal_RTOSDestroy: pal_plat_RTOSDestroy failed, status=%" PRIx32 "\n", status);
    }
    palRTOSInitialized = false;
    return status;
}

void pal_osReboot(void)
{
    PAL_LOG_INFO( "pal_osReboot\r\n");
#if (PAL_USE_APPLICATION_REBOOT)
    pal_plat_osApplicationReboot();
#else
    //Simulator is currently for Linux only
    #if (PAL_SIMULATE_RTOS_REBOOT == 1)
        const char *argv[] = {"0" , 0};
        char *const envp[] = { 0 };
        argv[0] = program_invocation_name;

        PAL_LOG_INFO( "pal_osReboot -> simulated reboot with execve(%s).\r\n", argv[0]);
  
        if (-1 == execve(argv[0], (char **)argv , envp))
        {
            PAL_LOG_ERR("child process execve failed [%s]",argv[0]);
        }
    #else
        PAL_LOG_INFO( "Rebooting the system\r\n");
        pal_plat_osReboot();
    #endif
#endif
}

uint64_t pal_osKernelSysTick(void)
{
    static uint64_t lastValue = 0;
    static uint64_t wraparoundsDetected = 0;
    const uint64_t one = 1;
    uint64_t tics = pal_plat_osKernelSysTick();
    uint64_t tmp = tics + (wraparoundsDetected << 32);

    if (tmp < lastValue) //erez's "wraparound algorithm" if we detect a wrap around add 1 to the higher 32 bits
    {
        tmp = tmp + (one << 32);
        wraparoundsDetected++;
    }
    lastValue = tmp;
    return (uint64_t)tmp;
}

uint64_t pal_osKernelSysTickMicroSec(uint64_t microseconds)
{
    uint64_t result;
    result = pal_plat_osKernelSysTickMicroSec(microseconds);
    return result;
}

uint64_t pal_osKernelSysMilliSecTick(uint64_t sysTicks)
{
    uint64_t result = 0;
    uint64_t osTickFreq = pal_plat_osKernelSysTickFrequency();
    if ((sysTicks) && (osTickFreq)) // > 0
    {
        result = (uint64_t)((sysTicks) * PAL_TICK_TO_MILLI_FACTOR / osTickFreq); //convert ticks per second to milliseconds
    }

    return result;
}

uint64_t pal_osKernelSysTickFrequency(void)
{
    uint64_t result;
    result = pal_plat_osKernelSysTickFrequency();
    return result;
}

palStatus_t pal_osThreadCreateWithAlloc(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadLocalStore_t* store, palThreadID_t* threadID)
{
    PAL_VALIDATE_ARGUMENTS((NULL == function) || (PAL_osPrioritylast < priority) || (PAL_osPriorityError == priority) || (0 == stackSize) || (NULL == threadID));
    if (store)
    {
        PAL_LOG_ERR("thread storage in not supported\n");
        return PAL_ERR_NOT_SUPPORTED;
    }
    palStatus_t status = pal_plat_osThreadCreate(function, funcArgument, priority, stackSize, threadID);
    return status;
}

palStatus_t pal_osThreadTerminate(palThreadID_t* threadID)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == threadID) || (PAL_INVALID_THREAD == *threadID));
    palStatus_t status = pal_plat_osThreadTerminate(threadID);
    return status;
}

palThreadID_t pal_osThreadGetId(void)
{
    palThreadID_t threadID = pal_plat_osThreadGetId();
    return threadID;
}

palStatus_t pal_osDelay(uint32_t milliseconds)
{
    palStatus_t status;
    status = pal_plat_osDelay(milliseconds);
    return status;
}

palStatus_t pal_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == timerID || NULL == function);
    palStatus_t status;
    status = pal_plat_osTimerCreate(function, funcArgument, timerType, timerID);
    return status;
}

palStatus_t pal_osTimerStart(palTimerID_t timerID, uint32_t millisec)
{
    PAL_VALIDATE_ARGUMENTS (NULLPTR == timerID);
    palStatus_t status;
    if (0 == millisec)
    {
        return PAL_ERR_RTOS_VALUE;
    }
    status = pal_plat_osTimerStart(timerID, millisec);
    return status;
}

palStatus_t pal_osTimerStop(palTimerID_t timerID)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == timerID);
    palStatus_t status;
    status = pal_plat_osTimerStop(timerID);
    return status;
}

palStatus_t pal_osTimerDelete(palTimerID_t* timerID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == timerID || NULLPTR == *timerID);
    palStatus_t status;
    status = pal_plat_osTimerDelete(timerID);
    return status;
}

palStatus_t pal_osMutexCreate(palMutexID_t* mutexID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == mutexID);
    palStatus_t status;
    status = pal_plat_osMutexCreate(mutexID);
    return status;
}

palStatus_t pal_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == mutexID));
    palStatus_t status;
    status = pal_plat_osMutexWait(mutexID, millisec);
    return status;
}

palStatus_t pal_osMutexRelease(palMutexID_t mutexID)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == mutexID);
    palStatus_t status;
    status = pal_plat_osMutexRelease(mutexID);
    return status;
}

palStatus_t pal_osMutexDelete(palMutexID_t* mutexID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == mutexID || NULLPTR == *mutexID);
    palStatus_t status;
    status = pal_plat_osMutexDelete(mutexID);
    return status;
}

palStatus_t pal_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreCreate(count, semaphoreID);
    return status;
}

palStatus_t pal_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec,  int32_t* countersAvailable)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreWait(semaphoreID, millisec, countersAvailable);
    return status;
}

palStatus_t pal_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreRelease(semaphoreID);
    return status;
}

palStatus_t pal_osSemaphoreDelete(palSemaphoreID_t* semaphoreID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == semaphoreID || NULLPTR == *semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreDelete(semaphoreID);
    return status;
}


int32_t pal_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
    PAL_VALIDATE_ARGUMENTS(NULL == valuePtr);
    int32_t result;
    result = pal_plat_osAtomicIncrement(valuePtr, increment);
    return result;
}

