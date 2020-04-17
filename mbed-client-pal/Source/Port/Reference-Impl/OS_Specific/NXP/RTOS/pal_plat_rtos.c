/*******************************************************************************
 * Copyright 2020 ARM Ltd.
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

/* PAL-RTOS porting for FreeRTOS-8.1.2
*  This is porting code for PAL RTOS APIS for 
*  FreeRTOS-8.1.2 version.
*/

#include "board.h"
#include "FreeRTOS.h"
#include "event_groups.h"
#include "semphr.h"
#include "task.h"


#include "pal.h"
#include "pal_plat_rtos.h"
#include <stdlib.h>

#define TRACE_GROUP "PAL"

#define PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(cmsisCode)\
    ((int32_t)(cmsisCode + PAL_ERR_RTOS_ERROR_BASE))

#define PAL_TICK_TO_MILLI_FACTOR 1000

extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes);

/////////////////////////STATIC FUNCTION///////////////////////////
/*! Get IPSR Register
*
* @param[in] Void
* \returns uint32 - the content of the IPSR Register.
*
*/
PAL_PRIVATE PAL_INLINE uint32_t pal_plat_GetIPSR(void);
/////////////////////////END STATIC FUNCTION///////////////////////////

//! Timer structure
typedef struct palTimer{
	palTimerID_t            timerID;
	//    uint32_t                internalTimerData[PAL_TIMER_DATA_SIZE];  ///< pointer to internal data
	TimerCallbackFunction_t function;
	void*                   functionArgs;
	uint32_t                timerType;
} palTimer_t;

//! Mutex structure
typedef struct palMutex{
	palMutexID_t            mutexID;
}palMutex_t;

//! Semaphore structure
typedef struct palSemaphore{
	palSemaphoreID_t        semaphoreID;
	uint32_t                maxCount;
}palSemaphore_t;

typedef struct palThreadData
{
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;
    TaskHandle_t sysThreadID;
} palThreadData_t;

#define PAL_MAX_CONCURRENT_THREADS 20

PAL_PRIVATE palMutexID_t g_threadsMutex = NULLPTR;
PAL_PRIVATE palThreadData_t* g_threadsArray[PAL_MAX_CONCURRENT_THREADS] = { 0 };

#define PAL_THREADS_MUTEX_LOCK(status) \
    { \
        status = pal_osMutexWait(g_threadsMutex, PAL_RTOS_WAIT_FOREVER); \
        if (PAL_SUCCESS != status)\
        { \
            PAL_LOG_ERR("%s mutex wait failed\n", __FUNCTION__); \
        } \
    }

#define PAL_THREADS_MUTEX_UNLOCK(status) \
    { \
        status = pal_osMutexRelease(g_threadsMutex); \
        if (PAL_SUCCESS != status)\
        { \
            PAL_LOG_ERR("%s mutex release failed\n", __FUNCTION__); \
        } \
    }

PAL_PRIVATE void threadFree(palThreadData_t** threadData);

PAL_PRIVATE PAL_INLINE uint32_t pal_plat_GetIPSR(void)
{
	uint32_t result;

#if defined (__CC_ARM)
	__asm volatile
	{
		MRS result, ipsr
	}
#elif defined (__GNUC__)
	__asm volatile ("MRS %0, ipsr" : "=r" (result) );
#endif

	return(result);
}

palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status = pal_osMutexCreate(&g_threadsMutex);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }

    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    for (int i = 0; i < PAL_MAX_CONCURRENT_THREADS; i++)
    {
        if (g_threadsArray[i])
        {
            threadFree(&g_threadsArray[i]);
        }
    }
    PAL_THREADS_MUTEX_UNLOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
#if (PAL_USE_HW_RTC)
    if (PAL_SUCCESS == status)
    {
        status = pal_plat_rtcInit();        
    }
#endif
end:
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
#if (PAL_USE_HW_RTC)
    if (PAL_SUCCESS == status)
    {
        status = pal_plat_rtcDeInit();
    }
#endif
	return status;
}

palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
	vTaskDelay(milliseconds / portTICK_PERIOD_MS);
	return PAL_SUCCESS;
}


uint64_t pal_plat_osKernelSysTick()
{

	uint64_t result;
	if (pal_plat_GetIPSR() != 0)
	{
		result = xTaskGetTickCountFromISR();
	}
	else
	{
		result = xTaskGetTickCount();
	}
	return result;
}

uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{
	uint64_t sysTicks = microseconds * configTICK_RATE_HZ / (PAL_TICK_TO_MILLI_FACTOR * PAL_TICK_TO_MILLI_FACTOR);
	return sysTicks;
}

uint64_t pal_plat_osKernelSysTickFrequency()
{
	return configTICK_RATE_HZ;
}

PAL_PRIVATE PAL_INLINE palThreadData_t** threadAllocate(void)
{
    palThreadData_t** threadData = NULL;
    for (int i = 0; i < PAL_MAX_CONCURRENT_THREADS; i++)
    {
        if (!g_threadsArray[i])
        {
            g_threadsArray[i] = (palThreadData_t*)calloc(1, sizeof(palThreadData_t));
            if (g_threadsArray[i])
            {
                threadData = &g_threadsArray[i];
            }
            break;
        }
    }
    return threadData;
}

PAL_PRIVATE void threadFree(palThreadData_t** threadData)
{
    (*threadData)->userFunction = NULL;
    (*threadData)->userFunctionArgument = NULL;
    (*threadData)->sysThreadID = NULL;
    free(*threadData);
    *threadData = NULL;
}

PAL_PRIVATE palThreadData_t** threadFind(const TaskHandle_t sysThreadID)
{
    palThreadData_t** threadData = NULL;
    for (int i = 0; i < PAL_MAX_CONCURRENT_THREADS; i++)
    {
        if (sysThreadID == g_threadsArray[i]->sysThreadID)
        {
            threadData = &g_threadsArray[i];
            break;
        }
    }
    return threadData;
}

PAL_PRIVATE void threadFunction(void* arg)
{
    palStatus_t status = PAL_SUCCESS;
    palThreadData_t** threadData;
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;
    
    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    threadData = (palThreadData_t**)arg;
    userFunction = (*threadData)->userFunction;
    userFunctionArgument = (*threadData)->userFunctionArgument;
    if (NULL == (*threadData)->sysThreadID) // maybe null if this thread has a higher priority than the thread which created this thread
    {
        (*threadData)->sysThreadID = xTaskGetCurrentTaskHandle(); // set the thread id
    }    
    PAL_THREADS_MUTEX_UNLOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    
    userFunction(userFunctionArgument); // invoke user function with user argument (use local vars) - note we're not under mutex lock anymore
    
    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    threadFree(threadData); // clean up
    PAL_THREADS_MUTEX_UNLOCK(status)
end:
    vTaskDelete(NULL);
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;
    palThreadData_t** threadData;
    TaskHandle_t sysThreadID = NULLPTR;    

    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    threadData = threadAllocate(); // allocate thread data from the global array
    PAL_THREADS_MUTEX_UNLOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }

    if (NULL == threadData) // allocation failed or all array slots are occupied
    {
        status = PAL_ERR_RTOS_RESOURCE;
        goto end;
    }

    (*threadData)->userFunction = function; // note that threadData is safe here (eventhough it's not mutex locked), no other thread will attempt to change it until the thread is either finished or terminated
    (*threadData)->userFunctionArgument = funcArgument;
    
    //Note: the stack in this API is handled as an array of "StackType_t" which can be of different sizes for different ports.
    //      in this specific port of (8.1.2) the "StackType_t" is defined to 4-bytes this is why we divide the "stackSize" parameter by "sizeof(uint32_t)".
    //      inside freeRTOS code, the stack size is calculated according to the following formula: "((size_t)usStackDepth) * sizeof(StackType_t)"
    //       where "usStackDepth" is equal to "stackSize / sizeof(uint32_t)"
    BaseType_t result = xTaskCreate((TaskFunction_t)threadFunction,
        "palTask",
        (stackSize / sizeof(uint32_t)),
        threadData,
        (int16_t)priority,
        &sysThreadID);

    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    if (pdPASS == result)
    {        
        if ((NULL != *threadData) && (NULL == (*threadData)->sysThreadID)) // *threadData maybe null in case the thread has already finished and cleaned up, sysThreadID maybe null if the created thread is lower priority than the creating thread
        {
            (*threadData)->sysThreadID = sysThreadID; // set the thread id
        }
        *threadID = (palThreadID_t)sysThreadID;
    }   
    else
    {
        threadFree(threadData); // thread creation failed so clean up dynamic allocations etc.
        status = PAL_ERR_GENERIC_FAILURE;
    }
    PAL_THREADS_MUTEX_UNLOCK(status);
end:
    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    palThreadID_t threadID = (palThreadID_t)xTaskGetCurrentTaskHandle();
    return threadID;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t* threadID)
{
    palStatus_t status = PAL_ERR_RTOS_TASK;
    TaskHandle_t sysThreadID = (TaskHandle_t)*threadID;
    palThreadData_t** threadData;
    if (xTaskGetCurrentTaskHandle() != sysThreadID) // self termination not allowed
    {
        PAL_THREADS_MUTEX_LOCK(status);
        if (PAL_SUCCESS != status)
        {
            goto end;
        }
        threadData = threadFind(sysThreadID);
        if (threadData) // thread may have ended or terminated already
        {
            vTaskDelete(sysThreadID);
            threadFree(threadData);
        }
        PAL_THREADS_MUTEX_UNLOCK(status);        
    }
end:
    return status;
}

PAL_PRIVATE palTimer_t* s_timerArrays[PAL_MAX_NUM_OF_TIMERS] = {0};

PAL_PRIVATE void pal_plat_osTimerWarpperFunction( TimerHandle_t xTimer )
{
	int i;
	palTimer_t* timer = NULL;
	for(i=0 ; i< PAL_MAX_NUM_OF_TIMERS ; i++)
	{
		if (s_timerArrays[i]->timerID == (palTimerID_t)xTimer)
		{
			timer = s_timerArrays[i];
			timer->function(timer->functionArgs);

		}
	}
}

palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID)
{
	palStatus_t status = PAL_SUCCESS;
	palTimer_t* timer = NULL;
	int i;
	if(NULL == timerID || NULL == function)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	timer = (palTimer_t*)malloc(sizeof(palTimer_t));

	if (NULL == timer)
	{
		status = PAL_ERR_NO_MEMORY;
	}
	else
	{
		memset(timer,0,sizeof(palTimer_t));
	}

	if (PAL_SUCCESS == status)
	{
		for (i=0; i< PAL_MAX_NUM_OF_TIMERS; i++)
		{
			if (s_timerArrays[i] == NULL)
			{
				s_timerArrays[i] = timer;
				break;
			}
		}
		if (PAL_MAX_NUM_OF_TIMERS == i)
		{
			status = PAL_ERR_NO_MEMORY;
		}
		if (PAL_SUCCESS == status)
		{
			timer->function = (TimerCallbackFunction_t)function;
			timer->functionArgs = funcArgument;
			timer->timerType = timerType;

			timer->timerID = (palTimerID_t)xTimerCreate(
					"timer",
					1, // xTimerPeriod - cannot be '0'
					(const TickType_t)timerType, // 0 = osTimerOnce, 1 = osTimerPeriodic
					NULL,
					(TimerCallbackFunction_t)pal_plat_osTimerWarpperFunction
			);
		}
		if (NULLPTR == timer->timerID)
		{
			free(timer);
			timer = NULLPTR;
            PAL_LOG_ERR("Rtos timer create failure");
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
	palTimer_t* timer = NULL;

	if (NULLPTR == timerID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	timer = (palTimer_t*)timerID;

	if (pal_plat_GetIPSR() != 0)
	{
		BaseType_t pxHigherPriorityTaskWoken;
		status = xTimerChangePeriodFromISR(
				(TimerHandle_t)(timer->timerID),
				(millisec / portTICK_PERIOD_MS),
				&pxHigherPriorityTaskWoken
		);
	}
	else
	{
		status =  xTimerChangePeriod((TimerHandle_t)(timer->timerID), (millisec / portTICK_PERIOD_MS), 0);
	}

	if (pdPASS != status)
	{
		status =  PAL_ERR_RTOS_PARAMETER;
	}
	if (pdPASS == status)
	{
		if (pal_plat_GetIPSR() != 0)
		{
			BaseType_t pxHigherPriorityTaskWoken;
			status = xTimerStartFromISR((TimerHandle_t)(timer->timerID), &pxHigherPriorityTaskWoken);
		}
		else
		{
			status = xTimerStart((TimerHandle_t)(timer->timerID), 0);
		}

		if (pdPASS != status)
		{
			status =  PAL_ERR_RTOS_PARAMETER;
		}
		else
		{
			status = PAL_SUCCESS;
		}
	}
	return status;
}

palStatus_t pal_plat_osTimerStop(palTimerID_t timerID)
{
	palStatus_t status = PAL_SUCCESS;
	palTimer_t* timer = NULL;

	if(NULLPTR == timerID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	timer = (palTimer_t*)timerID;

	if (pal_plat_GetIPSR() != 0)
	{
		BaseType_t pxHigherPriorityTaskWoken;
		status = xTimerStopFromISR((TimerHandle_t)(timer->timerID), &pxHigherPriorityTaskWoken);
	}
	else
	{
		status = xTimerStop((TimerHandle_t)(timer->timerID), 0);
	}


	if (pdPASS != status)
	{
		status = PAL_ERR_RTOS_PARAMETER;
	}
	else
	{
		status = PAL_SUCCESS;
	}
	return status;
}

palStatus_t pal_plat_osTimerDelete(palTimerID_t* timerID)
{
	palStatus_t status = PAL_ERR_RTOS_PARAMETER;
	palTimer_t* timer = NULL;
	int i;

	if(NULL == timerID || NULLPTR == *timerID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	timer = (palTimer_t*)*timerID;

	if (timer->timerID)
	{
		for(i=0 ; i< PAL_MAX_NUM_OF_TIMERS ; i++)
		{
			if (s_timerArrays[i] == timer)
			{
				status = xTimerDelete((TimerHandle_t)(timer->timerID), 0);
				free(timer);
				s_timerArrays[i] = NULL;
				*timerID = NULLPTR;
				break;
			}
		}

		if (pdPASS == status)
		{
			status = PAL_SUCCESS;
		}
		else
		{
			status = PAL_ERR_RTOS_PARAMETER;
		}
	}
	else
	{
		status = PAL_ERR_RTOS_PARAMETER;
	}

	return status;
}


palStatus_t pal_plat_osMutexCreate(palMutexID_t* mutexID)
{

	palStatus_t status = PAL_SUCCESS;
	palMutex_t* mutex = NULL;
	if(NULL == mutexID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	mutex = (palMutex_t*)malloc(sizeof(palMutex_t));
	if (NULL == mutex)
	{
		status = PAL_ERR_NO_MEMORY;
	}

	if (PAL_SUCCESS == status)
	{

		mutex->mutexID = (uintptr_t) xSemaphoreCreateRecursiveMutex();
		if (NULLPTR == mutex->mutexID)
		{
			free(mutex);
			mutex = NULL;
            PAL_LOG_ERR("Rtos mutex create failure");
			status = PAL_ERR_GENERIC_FAILURE;
		}
		*mutexID = (palMutexID_t)mutex;
	}
	return status;
}


palStatus_t pal_plat_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{

	palStatus_t status = PAL_SUCCESS;
	palMutex_t* mutex = NULL;
	BaseType_t res = pdTRUE;

	if(NULLPTR == mutexID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	mutex = (palMutex_t*)mutexID;
	if (pal_plat_GetIPSR() != 0)
	{
		BaseType_t pxHigherPriorityTaskWoken;
		res = xSemaphoreTakeFromISR(mutex->mutexID, &pxHigherPriorityTaskWoken);
	}
	else
	{
		res = xSemaphoreTakeRecursive((QueueHandle_t)(mutex->mutexID), (millisec / portTICK_PERIOD_MS) );
	}

	if (pdTRUE == res)
	{
		status = PAL_SUCCESS;
	}
	else
	{
		status = PAL_ERR_RTOS_TIMEOUT;
	}

	return status;
}


palStatus_t pal_plat_osMutexRelease(palMutexID_t mutexID)
{
	palStatus_t status = PAL_SUCCESS;
	palMutex_t* mutex = NULL;
	BaseType_t res = pdTRUE;

	if(NULLPTR == mutexID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	mutex = (palMutex_t*)mutexID;
	if (pal_plat_GetIPSR() != 0)
	{
		BaseType_t pxHigherPriorityTaskWoken;
		res = xSemaphoreGiveFromISR(mutex->mutexID, &pxHigherPriorityTaskWoken);
	}
	else
	{
		res = xSemaphoreGiveRecursive((QueueHandle_t)(mutex->mutexID));
	}

	if (pdTRUE == res)
	{
		status = PAL_SUCCESS;
	}
	else
	{
        PAL_LOG_ERR("Rtos mutex release failure %ld", res);
		status = PAL_ERR_GENERIC_FAILURE;
	}
	return status;
}

palStatus_t pal_plat_osMutexDelete(palMutexID_t* mutexID)
{
	palStatus_t status = PAL_SUCCESS;
	palMutex_t* mutex = NULL;

	if(NULL == mutexID || NULLPTR == *mutexID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	mutex = (palMutex_t*)*mutexID;
	if (NULLPTR != mutex->mutexID)
	{
		vSemaphoreDelete(mutex->mutexID);
		free(mutex);
		*mutexID = NULLPTR;
		status = PAL_SUCCESS;
	}
	else
	{
        PAL_LOG_ERR("Rtos mutex delete failure");
		status = PAL_ERR_GENERIC_FAILURE;
	}
	return status;
}

palStatus_t pal_plat_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID)
{
	palStatus_t status = PAL_SUCCESS;
	palSemaphore_t* semaphore = NULL;

	if(NULL == semaphoreID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	semaphore = (palSemaphore_t*)malloc(sizeof(palSemaphore_t));
	if (NULL == semaphore)
	{
		status = PAL_ERR_NO_MEMORY;
	}

	if(PAL_SUCCESS == status)
	{
		semaphore->semaphoreID = (uintptr_t)xSemaphoreCreateCounting(PAL_SEMAPHORE_MAX_COUNT, count);
		semaphore->maxCount = PAL_SEMAPHORE_MAX_COUNT;
		if (NULLPTR == semaphore->semaphoreID)
		{
			free(semaphore);
			semaphore = NULLPTR;
            PAL_LOG_ERR("Rtos semaphore create error");
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
	int32_t tmpCounters = 0;
	BaseType_t res = pdTRUE;

	if(NULLPTR == semaphoreID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	semaphore = (palSemaphore_t*)semaphoreID;
	if (pal_plat_GetIPSR() != 0)
	{
		BaseType_t pxHigherPriorityTaskWoken;
		res = xSemaphoreTakeFromISR(semaphore->semaphoreID, &pxHigherPriorityTaskWoken);
	}
	else
	{
		if (millisec == PAL_RTOS_WAIT_FOREVER)
		{
			res = xSemaphoreTake(semaphore->semaphoreID, portMAX_DELAY);
		}
		else
		{
			res = xSemaphoreTake(semaphore->semaphoreID, millisec / portTICK_PERIOD_MS);
		}
	}

	if (pdTRUE == res)
	{
		
		tmpCounters = uxQueueMessagesWaiting((QueueHandle_t)(semaphore->semaphoreID));
	}
	else
	{
		tmpCounters = 0;
		status = PAL_ERR_RTOS_TIMEOUT;
	}

	if (NULL != countersAvailable)
	{
		//because mbedOS returns the number available BEFORE the current take, we have to add 1 here.
		*countersAvailable = tmpCounters;
	}
	return status;
}

palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
	palStatus_t status = PAL_SUCCESS;
	palSemaphore_t* semaphore = NULL;
	BaseType_t res = pdTRUE;
	int32_t tmpCounters = 0;

	if(NULLPTR == semaphoreID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	semaphore = (palSemaphore_t*)semaphoreID;

	tmpCounters = uxQueueMessagesWaiting((QueueHandle_t)(semaphore->semaphoreID));

	if(tmpCounters < semaphore->maxCount)
	{
		if (pal_plat_GetIPSR() != 0)
		{
			BaseType_t pxHigherPriorityTaskWoken;
			res = xSemaphoreGiveFromISR(semaphore->semaphoreID, &pxHigherPriorityTaskWoken);
		}
		else
		{
			res = xSemaphoreGive(semaphore->semaphoreID);
		}

		if (pdTRUE != res)
		{	
			status = PAL_ERR_RTOS_PARAMETER;
		}
	}
	else 
	{
		status = PAL_ERR_RTOS_RESOURCE;
	}
	
	return status;
}

palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t* semaphoreID)
{
	palStatus_t status = PAL_SUCCESS;
	palSemaphore_t* semaphore = NULL;

	if(NULL == semaphoreID || NULLPTR == *semaphoreID)
	{
		return PAL_ERR_INVALID_ARGUMENT;
	}

	semaphore = (palSemaphore_t*)*semaphoreID;
	if (NULLPTR != semaphore->semaphoreID)
	{
		vSemaphoreDelete(semaphore->semaphoreID);
		free(semaphore);
		*semaphoreID = NULLPTR;
		status = PAL_SUCCESS;
	}
	else
	{
        PAL_LOG_ERR("Rtos semaphore destroy error");
		status = PAL_ERR_GENERIC_FAILURE;
	}
	return status;
}


void *pal_plat_malloc(size_t len)
{
	return malloc(len);
}


void pal_plat_free(void * buffer)
{
	free(buffer);
}


palStatus_t pal_plat_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes)
{
    palStatus_t status = PAL_SUCCESS;

	status = pal_plat_getRandomBufferFromHW(randomBuf, bufSizeBytes, actualRandomSizeBytes);
    return status;
}


