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
#include <stdlib.h>
#include <string.h>

#include "pal_plat_rtos.h"
#include "mbed.h"

#include "entropy_poll.h"


/*
    mbedOS latest version RTOS support
*/
#if defined(osRtxVersionAPI) && (osRtxVersionAPI >= 20000000)

#include "cmsis_os2.h" // Revision:    V2.1
#include <time.h>

#define PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(cmsisCode)\
    ((int32_t)((int32_t)cmsisCode + PAL_ERR_RTOS_ERROR_BASE))

typedef struct threadPortData 
{
    osThreadId_t osThreadID;
    osThreadAttr_t osThread;
    mbed_rtos_storage_thread_t osThreadStorage;
} threadPortData_t;

//! Timer structure
typedef struct palTimer{
    palTimerID_t              timerID;
    osTimerAttr_t             osTimer;
    mbed_rtos_storage_timer_t osTimerStorage;
} palTimer_t;

//! Mutex structure
typedef struct palMutex{
    palMutexID_t              mutexID;
    osMutexAttr_t             osMutex;
    mbed_rtos_storage_mutex_t osMutexStorage;
}palMutex_t;

//! Semaphore structure
typedef struct palSemaphore{
    palSemaphoreID_t              semaphoreID;
    osSemaphoreAttr_t             osSemaphore;
    mbed_rtos_storage_semaphore_t osSemaphoreStorage;
}palSemaphore_t;


typedef struct palThreadCleanupData
{
    palTimerID_t timerID;
    threadPortData_t* portData;
} palThreadCleanupData_t;

PAL_PRIVATE int16_t g_threadPriorityMap[PAL_NUMBER_OF_THREAD_PRIORITIES] = 
{ 
    (int16_t)osPriorityIdle,         // PAL_osPriorityIdle
    (int16_t)osPriorityLow,          // PAL_osPriorityLow
    (int16_t)osPriorityLow1,         // PAL_osPriorityReservedTRNG
    (int16_t)osPriorityBelowNormal,  // PAL_osPriorityBelowNormal
    (int16_t)osPriorityNormal,       // PAL_osPriorityNormal
    (int16_t)osPriorityAboveNormal,  // PAL_osPriorityAboveNormal
    (int16_t)osPriorityAboveNormal1, // PAL_osPriorityReservedDNS,
    (int16_t)osPriorityAboveNormal2, // PAL_osPriorityReservedSockets
    (int16_t)osPriorityHigh,         // PAL_osPriorityHigh
    (int16_t)osPriorityRealtime,     // PAL_osPriorityReservedHighResTimer
    (int16_t)osPriorityRealtime1     // PAL_osPriorityRealtime
};

PAL_PRIVATE void threadCleanupTimer(const void* arg)
{
    palStatus_t status;
    osThreadState_t threadState;
    palThreadCleanupData_t* threadCleanupData = (palThreadCleanupData_t*)arg;
    palTimerID_t timerID = threadCleanupData->timerID;

    threadState = osThreadGetState(threadCleanupData->portData->osThreadID);
    if ((osThreadTerminated == threadState) || (osThreadInactive == threadState)) // thread has ended
    {
        free(threadCleanupData->portData->osThread.stack_mem);
        free(threadCleanupData->portData);
        free(threadCleanupData);
        status = pal_osTimerDelete(&timerID);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG(ERR, "threadCleanupTimer: pal_osTimerDelete failed\n");
        }
    }
    else // thread has not ended so wait another PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC
    {
        if (osThreadError == threadState)
        {
            PAL_LOG(ERR, "threadCleanupTimer: threadState = osThreadError\n");
        }
        else
        {
            status = pal_osTimerStart(timerID, PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC);
            if (PAL_SUCCESS != status)
            {
                PAL_LOG(ERR, "threadCleanupTimer: pal_osTimerStart failed\n");
            }
        }
    }
}

PAL_PRIVATE void threadFunction(void* arg)
{
    palThreadServiceBridge_t* bridge = (palThreadServiceBridge_t*)arg;
    bridge->function(bridge->threadData);
}

void pal_plat_osReboot()
{
    NVIC_SystemReset();
}

palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
    return PAL_SUCCESS;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
    palStatus_t status;
    osStatus_t platStatus = osDelay(milliseconds);
    if (osOK == platStatus)
    {
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus); //TODO(nirson01): error propagation MACRO??
    }
    return status;
}

uint64_t pal_plat_osKernelSysTick(void)
{
    uint64_t result;
    result = osKernelGetTickCount();
    return result;
}

uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{
    uint64_t result;
    result =  (((uint64_t)microseconds * (osKernelGetTickFreq())) / 1000000);

    return result;
}

uint64_t pal_plat_osKernelSysTickFrequency()
{
    return osKernelGetTickFreq();
}

int16_t pal_plat_osThreadTranslatePriority(palThreadPriority_t priority)
{
    return g_threadPriorityMap[priority];
}

palStatus_t pal_plat_osThreadDataInitialize(palThreadPortData* portData, int16_t priority, uint32_t stackSize)
{
    palStatus_t status = PAL_SUCCESS;
    threadPortData_t* data = (threadPortData_t*)calloc(1, sizeof(threadPortData_t));
    uint32_t* stack = (uint32_t*)malloc(stackSize);
    if ((NULL == data) || (NULL == stack))
    {
        free(data);
        free(stack);
        status = PAL_ERR_RTOS_RESOURCE;
    }
    else
    {
        data->osThread.priority = (osPriority_t)priority;
        data->osThread.stack_size = stackSize;
        data->osThread.stack_mem = stack;
        data->osThread.cb_mem = &(data->osThreadStorage);
        data->osThread.cb_size = sizeof(data->osThreadStorage);
        memset(&(data->osThreadStorage), 0, sizeof(data->osThreadStorage));
        *portData = (palThreadPortData)data;
    }
    return status;
}

palStatus_t pal_plat_osThreadRun(palThreadServiceBridge_t* bridge, palThreadID_t* osThreadID)
{
    palStatus_t status = PAL_SUCCESS;
    threadPortData_t* portData = (threadPortData_t*)(bridge->threadData->portData);
    osThreadId_t threadID = osThreadNew(threadFunction, bridge, &(portData->osThread));
    if (NULL == threadID)
    {
        free(portData->osThread.stack_mem);
        free(portData);
        status = PAL_ERR_GENERIC_FAILURE;
    }
    else
    {
        portData->osThreadID = threadID;
        *osThreadID = (palThreadID_t)threadID;
    }
    return status;
}

palStatus_t pal_plat_osThreadDataCleanup(palThreadData_t* threadData)
{
    palStatus_t status = PAL_SUCCESS;
    threadPortData_t* portData = (threadPortData_t*)(threadData->portData);
    palTimerID_t timerID = NULLPTR;
    palThreadCleanupData_t* threadCleanupData = (palThreadCleanupData_t*)malloc(sizeof(palThreadCleanupData_t));
    if (NULL == threadCleanupData)
    {
        status = PAL_ERR_RTOS_RESOURCE;
    }
    else
    {
        // mbedOS threads do not clean up on their own & also cannot clean up from self (thread), therefore we clean up using a timer
        status = pal_osTimerCreate(threadCleanupTimer, threadCleanupData, palOsTimerOnce, &timerID);
        if (PAL_SUCCESS == status)
        {
            threadCleanupData->timerID = timerID;
            threadCleanupData->portData = portData;
            if (NULL == portData->osThreadID)
            {
                portData->osThreadID = (osThreadId_t)threadData->osThreadID;
            }
            status = pal_osTimerStart(timerID, PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC);
        }
    }    
    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    palThreadID_t osThreadID = (palThreadID_t)osThreadGetId();
    return osThreadID;
}

palStatus_t pal_plat_osThreadTerminate(palThreadData_t* threadData)
{
    palStatus_t status = PAL_ERR_RTOS_TASK;
    osStatus_t osStatus = osOK;
    osThreadState_t threadState = osThreadError;
    threadPortData_t* portData = NULL;
    osThreadId_t threadID = (osThreadId_t)(threadData->osThreadID);
    if (osThreadGetId() != threadID) // terminate only if not trying to terminate from self
    {
        threadState = osThreadGetState(threadID);
        if ((osThreadTerminated != threadState) && (osThreadError != threadState) && (osThreadInactive != threadState))
        {
            osStatus = osThreadTerminate(threadID);
        }

        if (osErrorISR == osStatus)
        {
            status = PAL_ERR_RTOS_ISR;
        }
        else
        {
            portData = (threadPortData_t*)(threadData->portData);
            free(portData->osThread.stack_mem);
            free(portData);
            status = PAL_SUCCESS;
        }
    }
    return status;
}

palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID)
{
    palStatus_t status = PAL_SUCCESS;
    palTimer_t* timer = NULL;
   
    timer = (palTimer_t*)malloc(sizeof(palTimer_t));
    if (NULL == timer)
    {
        status = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == status)
    {
        timer->osTimer.name = NULL;
        timer->osTimer.attr_bits = 0;
        timer->osTimer.cb_mem = &timer->osTimerStorage;
        timer->osTimer.cb_size = sizeof(timer->osTimerStorage);
        memset(&timer->osTimerStorage, 0, sizeof(timer->osTimerStorage));
    
        timer->timerID = (uintptr_t)osTimerNew((osTimerFunc_t)function, (osTimerType_t)timerType, funcArgument, &timer->osTimer);
        if (NULLPTR == timer->timerID)
        {
            free(timer);
            timer = NULL;
            status = PAL_ERR_GENERIC_FAILURE;
        }
        else
        {
            *timerID = (palTimerID_t)timer;
        }
    }
    return status;
}

palStatus_t pal_plat_osTimerStart(palTimerID_t timerID, uint32_t millisec)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palTimer_t* timer = NULL;
    
    timer = (palTimer_t*)timerID;
    platStatus = osTimerStart((osTimerId_t)timer->timerID, millisec);
    if (osOK == (osStatus_t)platStatus)
    {
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;
}

palStatus_t pal_plat_osTimerStop(palTimerID_t timerID)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palTimer_t* timer = NULL;
    
    timer = (palTimer_t*)timerID;
    platStatus = osTimerStop((osTimerId_t)timer->timerID);
    if (osOK == platStatus)
    {
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;  
}

palStatus_t pal_plat_osTimerDelete(palTimerID_t* timerID)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palTimer_t* timer = NULL;
    
    timer = (palTimer_t*)*timerID;
    platStatus = osTimerDelete((osTimerId_t)timer->timerID);
    if (osOK == platStatus)
    {
        free(timer);
        *timerID = NULLPTR;
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;
}


palStatus_t pal_plat_osMutexCreate(palMutexID_t* mutexID)
{
    palStatus_t status = PAL_SUCCESS;
    palMutex_t* mutex = NULL;

    mutex = (palMutex_t*)malloc(sizeof(palMutex_t));
    if (NULL == mutex)
    {
        status = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == status)
    {
        mutex->osMutex.name = NULL;
        mutex->osMutex.attr_bits = osMutexRecursive | osMutexRobust;
        mutex->osMutex.cb_mem = &mutex->osMutexStorage;
        mutex->osMutex.cb_size = sizeof(mutex->osMutexStorage);
        memset(&mutex->osMutexStorage, 0, sizeof(mutex->osMutexStorage));

        mutex->mutexID = (uintptr_t)osMutexNew(&mutex->osMutex);
        if (NULLPTR == mutex->mutexID)
        {
            free(mutex);
            mutex = NULL;
            status = PAL_ERR_GENERIC_FAILURE;
        }
        else
        {
            *mutexID = (palMutexID_t)mutex;
        }
    }
    return status;
}


palStatus_t pal_plat_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palMutex_t* mutex = NULL;
    
    mutex = (palMutex_t*)mutexID;
    platStatus = osMutexAcquire((osMutexId_t)mutex->mutexID, millisec);
    if (osOK == platStatus)
    {
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;
}


palStatus_t pal_plat_osMutexRelease(palMutexID_t mutexID)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palMutex_t* mutex = NULL;
    
    mutex = (palMutex_t*)mutexID;
    platStatus = osMutexRelease((osMutexId_t)mutex->mutexID);
    if (osOK == platStatus)
    {
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;
}

palStatus_t pal_plat_osMutexDelete(palMutexID_t* mutexID)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palMutex_t* mutex = NULL;
    
    mutex = (palMutex_t*)*mutexID;
    platStatus = osMutexDelete((osMutexId_t)mutex->mutexID);
    if (osOK == platStatus)
    {
        free(mutex);
        *mutexID = NULLPTR;
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;
}

palStatus_t pal_plat_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID)
{
    palStatus_t status = PAL_SUCCESS;
    palSemaphore_t* semaphore = NULL;
    
    semaphore = (palSemaphore_t*)malloc(sizeof(palSemaphore_t));
    if (NULL == semaphore)
    {
        status = PAL_ERR_NO_MEMORY;
    }

    if(PAL_SUCCESS == status)
    {
        semaphore->osSemaphore.cb_mem = &semaphore->osSemaphoreStorage;
        semaphore->osSemaphore.cb_size = sizeof(semaphore->osSemaphoreStorage);
        memset(&semaphore->osSemaphoreStorage, 0, sizeof(semaphore->osSemaphoreStorage));

        semaphore->semaphoreID = (uintptr_t)osSemaphoreNew(PAL_MAX_SEMAPHORE_COUNT, count, &semaphore->osSemaphore);
        if (NULLPTR == semaphore->semaphoreID)
        {
            free(semaphore);
            semaphore = NULL;
            status = PAL_ERR_GENERIC_FAILURE;
        }
        else
        {
            *semaphoreID = (palSemaphoreID_t)semaphore;
        }
    }
    return status;  
}

palStatus_t pal_plat_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec, int32_t* countersAvailable)
{
    palStatus_t status = PAL_SUCCESS;
    palSemaphore_t* semaphore = NULL;
    osStatus_t platStatus;
    
    semaphore = (palSemaphore_t*)semaphoreID;
    platStatus = osSemaphoreAcquire((osSemaphoreId_t)semaphore->semaphoreID, millisec);

    if (osErrorTimeout == platStatus)
    {
        status = PAL_ERR_RTOS_TIMEOUT;
    }
    else if (platStatus != osOK)
    {
        status = PAL_ERR_RTOS_PARAMETER;
    }

    if (NULL != countersAvailable)
    {
        *countersAvailable = osSemaphoreGetCount((osSemaphoreId_t)semaphore->semaphoreID);
    }
    return status;
}

palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palSemaphore_t* semaphore = NULL;

    semaphore = (palSemaphore_t*)semaphoreID;
    platStatus = osSemaphoreRelease((osSemaphoreId_t)semaphore->semaphoreID);
    if (osOK == platStatus)
    {
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;
}

palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t* semaphoreID)
{
    palStatus_t status = PAL_SUCCESS;
    osStatus_t platStatus = osOK;
    palSemaphore_t* semaphore = NULL;
    
    semaphore = (palSemaphore_t*)*semaphoreID;
    platStatus = osSemaphoreDelete((osSemaphoreId_t)semaphore->semaphoreID);
    if (osOK == platStatus)
    {
        free(semaphore);
        *semaphoreID = NULLPTR;
        status = PAL_SUCCESS;
    }
    else
    {
        status = PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(platStatus);
    }

    return status;  
}

int32_t pal_plat_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
    if (increment >= 0)
    {
        return core_util_atomic_incr_u32((uint32_t*)valuePtr, increment);
    }
    else
    {
        return core_util_atomic_decr_u32((uint32_t*)valuePtr, 0 - increment);
    }
}


 void *pal_plat_malloc(size_t len)
{
	return malloc(len);
}


 void pal_plat_free(void * buffer)
{
	return free(buffer);
}

palStatus_t pal_plat_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = 0;
    size_t actualOutputLen = 0;
    platStatus = mbedtls_hardware_poll(NULL /*Not used by the function*/, randomBuf, bufSizeBytes, &actualOutputLen);
    if ((0 != platStatus) || (0 == actualOutputLen))
    {
        status = PAL_ERR_RTOS_TRNG_FAILED;
    }
    else if (actualOutputLen != bufSizeBytes)
    {
        status = PAL_ERR_RTOS_TRNG_PARTIAL_DATA;
    }

    if (NULL != actualRandomSizeBytes)
    {
        *actualRandomSizeBytes = actualOutputLen;
    }
    return status;
}

#if (PAL_USE_HW_RTC)
palStatus_t pal_plat_osGetRtcTime(uint64_t *rtcGetTime)
{
    palStatus_t ret = PAL_SUCCESS;
    if(rtcGetTime != NULL)
    {
        *rtcGetTime = (uint64_t)time(NULL);
    }
    else
    {
        ret = PAL_ERR_NULL_POINTER;
    }
    return ret;
}

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
    palStatus_t status = PAL_SUCCESS;
    if (rtcSetTime < (uint64_t)PAL_MIN_RTC_SET_TIME)
    {
        status = PAL_ERR_INVALID_TIME;
    }
    else
    {
        set_time(rtcSetTime);
    }

    return status;
}

palStatus_t pal_plat_rtcInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    return ret;
}

palStatus_t pal_plat_rtcDeInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    return ret;
}
#endif //#if (PAL_USE_HW_RTC)


#endif
