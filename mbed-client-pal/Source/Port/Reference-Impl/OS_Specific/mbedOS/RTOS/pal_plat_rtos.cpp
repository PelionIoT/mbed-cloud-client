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

#define TRACE_GROUP "PAL"

/*
    mbedOS latest version RTOS support
*/
#if defined(osRtxVersionAPI) && (osRtxVersionAPI >= 20000000)

#include "cmsis_os2.h" // Revision:    V2.1
#include <time.h>

#define PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(cmsisCode)\
    ((int32_t)((int32_t)cmsisCode + PAL_ERR_RTOS_ERROR_BASE))

#define PAL_THREAD_NAME_MAX_LEN 20 // max len for thread name which holds the pointer (as string) to dynamically allocated thread data
#define PAL_THREAD_STACK_ALIGN(x) ((x % sizeof(uint64_t)) ? (x + ((sizeof(uint64_t)) - (x % sizeof(uint64_t)))) : x)

typedef struct palThreadData 
{
    osThreadId_t threadID;
    osThreadAttr_t threadAttr;
    mbed_rtos_storage_thread_t threadStore;
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;
} palThreadData_t;

typedef struct palThreadCleanupData
{
    palTimerID_t timerID;
    palThreadData_t* threadData;
} palThreadCleanupData_t;

PAL_PRIVATE palMutexID_t g_threadsMutex = NULLPTR;

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

void pal_plat_osReboot()
{
    NVIC_SystemReset();
}

palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status = pal_osMutexCreate(&g_threadsMutex);
    return status;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
    palStatus_t status = PAL_SUCCESS; 
    if (NULLPTR != g_threadsMutex)
    {
        status = pal_osMutexDelete(&g_threadsMutex);
        g_threadsMutex = NULLPTR;
    }
    return status;
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

PAL_PRIVATE void timerFunctionThreadCleanup(const void* arg)
{
    palStatus_t status;
    palThreadCleanupData_t* cleanupData = (palThreadCleanupData_t*)arg;
    palTimerID_t timerID = cleanupData->timerID;
    osThreadState_t threadState = osThreadGetState(cleanupData->threadData->threadID);
    if ((osThreadTerminated == threadState) || (osThreadInactive == threadState)) // thread has transitioned into its final state so clean up
    {
        free(cleanupData->threadData->threadAttr.stack_mem);
        free((void*)cleanupData->threadData->threadAttr.name);
        free(cleanupData->threadData);
        free(cleanupData);
        status = pal_osTimerDelete(&timerID);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_ERR("timerFunctionThreadCleanup timer delete failed\n");
        }
        goto end;
    }

    if (osThreadError == threadState)
    {
        PAL_LOG_ERR("timerFunctionThreadCleanup threadState is osThreadError\n");
        goto end;
    }

    status = pal_osTimerStart(timerID, PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC); // thread has not transitioned into its final so start the timer again
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("timerFunctionThreadCleanup timer start failed\n");
    }
end:
    return;
}

PAL_PRIVATE void threadFunction(void* arg)
{
    palThreadData_t* threadData;
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;
    palThreadCleanupData_t* cleanupData;
    palTimerID_t timerID;
    bool isMutexTaken = false;
    palStatus_t status = pal_osMutexWait(g_threadsMutex, PAL_RTOS_WAIT_FOREVER); // avoid race condition with thread terminate
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("threadFunction mutex wait failed (pre)\n");
        goto end;
    }

    isMutexTaken = true;
    threadData = (palThreadData_t*)arg;
    userFunction = threadData->userFunction;
    userFunctionArgument = threadData->userFunctionArgument;
    status = pal_osMutexRelease(g_threadsMutex);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("threadFunction mutex release failed (pre)\n");
        goto end;
    }

    isMutexTaken = false;
    userFunction(userFunctionArgument); // invoke user function with user argument (use local vars)
    status = pal_osMutexWait(g_threadsMutex, PAL_RTOS_WAIT_FOREVER); // avoid race condition with thread terminate
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("threadFunction mutex wait failed (post)\n");
        goto end;
    }

    isMutexTaken = true;
    cleanupData = (palThreadCleanupData_t*)malloc(sizeof(palThreadCleanupData_t));
    if (NULL == cleanupData)
    {
        PAL_LOG_ERR("threadFunction malloc palThreadCleanupData_t failed\n");
        goto end;
    }

    status = pal_osTimerCreate(timerFunctionThreadCleanup, cleanupData, palOsTimerOnce, &timerID);
    if (PAL_SUCCESS != status)
    {
        free(cleanupData);
        PAL_LOG_ERR("threadFunction create timer failed\n");
        goto end;
    }

    memset((void*)threadData->threadAttr.name, 0, PAL_THREAD_NAME_MAX_LEN); // clear the thread name which holds the address (as string) of the dynamically allocated palThreadData_t (rechecked in thread terminate)
    threadData->threadID = osThreadGetId();
    cleanupData->timerID = timerID;
    cleanupData->threadData = threadData;
    status = pal_osTimerStart(timerID, PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC);
    if (PAL_SUCCESS != status)
    {
        free(cleanupData); // timer failed to start so cleanup dynamically allocated palThreadCleanupData_t
        PAL_LOG_ERR("threadFunction timer start failed\n");
        status = pal_osTimerDelete(&timerID);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_ERR("threadFunction timer delete failed\n");
        }
    }
end:
    if (isMutexTaken)
    {
        status = pal_osMutexRelease(g_threadsMutex);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_ERR("threadFunction mutex release failed (post)\n");
        }
    }
}

PAL_PRIVATE osPriority_t translatePriority(palThreadPriority_t priority)
{
    osPriority_t translatedPriority;
    switch (priority)
    {
        case PAL_osPriorityIdle:
            translatedPriority = osPriorityIdle;
            break;
        case PAL_osPriorityLow:
            translatedPriority = osPriorityLow;
            break;
        case PAL_osPriorityReservedTRNG:
            translatedPriority = osPriorityLow1;
            break;
        case PAL_osPriorityBelowNormal:
            translatedPriority = osPriorityBelowNormal;
            break;
        case PAL_osPriorityNormal:
            translatedPriority = osPriorityNormal;
            break;
        case PAL_osPriorityAboveNormal:
            translatedPriority = osPriorityAboveNormal;
            break;
        case PAL_osPriorityReservedDNS:
            translatedPriority = osPriorityAboveNormal1;
            break;
        case PAL_osPriorityReservedSockets:
            translatedPriority = osPriorityAboveNormal2;
            break;
        case PAL_osPriorityHigh:
            translatedPriority = osPriorityHigh;
            break;
        case PAL_osPriorityReservedHighResTimer:
            translatedPriority = osPriorityRealtime;
            break;
        case PAL_osPriorityRealtime:
            translatedPriority = osPriorityRealtime1;
            break;
        case PAL_osPriorityError:
        default:
            translatedPriority = osPriorityError;
            break;
    }
    return translatedPriority;
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;
    void* threadStack = NULL;
    char* threadName = NULL;
    palThreadData_t* threadData = NULL;
    int bytesWritten;
    osThreadId_t sysThreadID;
    osPriority_t threadPriority = translatePriority(priority);
    if (osPriorityError == threadPriority)
    {
        status = PAL_ERR_RTOS_PRIORITY;
        goto end;
    }

    stackSize = PAL_THREAD_STACK_ALIGN(stackSize);
    threadStack = malloc(stackSize);
    threadName = (char*)calloc((PAL_THREAD_NAME_MAX_LEN + 1), sizeof(char)); // name will hold the address of the dynamically allocated palThreadData_t (as string)
    threadData = (palThreadData_t*)malloc(sizeof(palThreadData_t));
    if ((NULL == threadData) || (NULL == threadStack) || (NULL == threadName))
    {
        status = PAL_ERR_RTOS_RESOURCE;
        goto clean;
    }

    bytesWritten = snprintf(threadName, (PAL_THREAD_NAME_MAX_LEN + 1), "%p", threadData);
    if ((bytesWritten <= 0) || ((PAL_THREAD_NAME_MAX_LEN + 1) <= bytesWritten))
    {
        status = PAL_ERR_RTOS_RESOURCE;
        goto clean;
    }

    memset(&(threadData->threadStore), 0, sizeof(threadData->threadStore));
    threadData->threadAttr.priority = threadPriority;
    threadData->threadAttr.stack_size = stackSize;
    threadData->threadAttr.stack_mem = threadStack;
    threadData->threadAttr.name = threadName;
    threadData->threadAttr.cb_mem= &(threadData->threadStore);
    threadData->threadAttr.cb_size = sizeof(threadData->threadStore);
    threadData->userFunction = function;
    threadData->userFunctionArgument = funcArgument;

    sysThreadID = osThreadNew(threadFunction, threadData, &(threadData->threadAttr));
    if (NULL == sysThreadID)
    {
        status = PAL_ERR_GENERIC_FAILURE;
        goto clean;
    }

    *threadID = (palThreadID_t)sysThreadID;
    goto end;
clean:
    free(threadStack);
    free(threadName);
    free(threadData);
end:
    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    palThreadID_t threadID = (palThreadID_t)osThreadGetId();
    return threadID;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t* threadID)
{
    palStatus_t status;
    palThreadData_t* threadData = NULL;
    osThreadId_t sysThreadID = (osThreadId_t)*threadID;
    osStatus_t sysStatus;
    osThreadState_t threadState;
    const char* threadName;
    bool isMutexTaken = false;
    if (osThreadGetId() == sysThreadID) // self termination not allowed
    {
        status = PAL_ERR_RTOS_TASK;
        goto end;   
    }

    status = pal_osMutexWait(g_threadsMutex, PAL_RTOS_WAIT_FOREVER); // avoid race condition with thread function
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("thread terminate mutex wait failed\n");
        goto end;
    }

    isMutexTaken = true;
    threadState = osThreadGetState(sysThreadID);
    if ((osThreadTerminated == threadState) || (osThreadInactive == threadState) || (osThreadError == threadState)) // thread has already transitioned into its final state
    {
        goto end;
    }

    threadName = osThreadGetName(sysThreadID);
    if ((NULL == threadName) || (1 != sscanf(threadName, "%p", &threadData))) // this may happen if the thread has not tranistioned into its final state yet (altered in thread function)
    {
        goto end;
    }

    sysStatus = osThreadTerminate(sysThreadID);
    if (osErrorISR == sysStatus)
    {
        status = PAL_ERR_RTOS_ISR;
        goto end;
    }

    free(threadData->threadAttr.stack_mem);
    free((void*)threadData->threadAttr.name);
    free(threadData);
end:
    if (isMutexTaken)
    {
        if (PAL_SUCCESS != pal_osMutexRelease(g_threadsMutex))
        {
            PAL_LOG_ERR("thread terminate mutex release failed\n");
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

#if PAL_USE_HW_TRNG
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
#endif

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
