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


#define PAL_RTOS_TRANSLATE_CMSIS_ERROR_CODE(cmsisCode)\
    ((int32_t)(cmsisCode + PAL_ERR_RTOS_ERROR_BASE))

#define PAL_TICK_TO_MILLI_FACTOR 1000

PAL_PRIVATE int16_t g_threadPriorityMap[PAL_NUMBER_OF_THREAD_PRIORITIES] = 
{ 
    0, // PAL_osPriorityIdle
    1, // PAL_osPriorityLow
    2, // PAL_osPriorityReservedTRNG
    3, // PAL_osPriorityBelowNormal
    4, // PAL_osPriorityNormal
    5, // PAL_osPriorityAboveNormal
    6, // PAL_osPriorityReservedDNS
    7, // PAL_osPriorityReservedSockets
    8, // PAL_osPriorityHigh
    9, // PAL_osPriorityReservedHighResTimer
    10 // PAL_osPriorityRealtime
};

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

PAL_PRIVATE void threadFunction(void const* arg)
{
    palThreadServiceBridge_t* bridge = (palThreadServiceBridge_t*)arg;
    bridge->function(bridge->threadData);
    vTaskDelete(NULL);
}

palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
	palStatus_t status = PAL_SUCCESS;	
#if (PAL_USE_HW_RTC)
    status = pal_plat_rtcInit();
#endif
    return status;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
	palStatus_t status = PAL_SUCCESS;
#if (PAL_USE_HW_RTC)
	status = pal_plat_rtcDeInit();
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

int16_t pal_plat_osThreadTranslatePriority(palThreadPriority_t priority)
{
    return g_threadPriorityMap[priority];
}

palStatus_t pal_plat_osThreadDataInitialize(palThreadPortData* portData, int16_t priority, uint32_t stackSize)
{
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osThreadRun(palThreadServiceBridge_t* bridge, palThreadID_t* osThreadID)
{
    palStatus_t status = PAL_SUCCESS;
    TaskHandle_t threadID = NULLPTR;

    //Note: the stack in this API is handled as an array of "StackType_t" which can be of different sizes for different ports.
    //      in this specific port of (8.1.2) the "StackType_t" is defined to 4-bytes this is why we divide the "stackSize" parameter by "sizeof(uint32_t)".
    //      inside freeRTOS code, the stack size is calculated according to the following formula: "((size_t)usStackDepth) * sizeof(StackType_t)"
    //       where "usStackDepth" is equal to "stackSize / sizeof(uint32_t)"
    BaseType_t result = xTaskGenericCreate((TaskFunction_t)threadFunction, 
        "palTask",
        (bridge->threadData->stackSize / sizeof(uint32_t)),
        bridge,
        bridge->threadData->osPriority,
        &threadID,
        NULL, //if stack pointer is NULL then allocate the stack according to stack size
        NULL);

    if (pdPASS == result)
    {
        *osThreadID = (palThreadID_t)threadID;
    }   
    else
    {
        status = PAL_ERR_GENERIC_FAILURE;
    }
    return status;
}

palStatus_t pal_plat_osThreadDataCleanup(palThreadData_t* threadData)
{
    return PAL_SUCCESS;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    palThreadID_t osThreadID = (palThreadID_t)xTaskGetCurrentTaskHandle();
    return osThreadID;
}

palStatus_t pal_plat_osThreadTerminate(palThreadData_t* threadData)
{
    palStatus_t status = PAL_ERR_RTOS_TASK;
    TaskHandle_t threadID = (TaskHandle_t)(threadData->osThreadID);
    if (xTaskGetCurrentTaskHandle() != threadID) // terminate only if not trying to terminate from self
    {
        vTaskDelete(threadID);
        status = PAL_SUCCESS;
    }
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
			PAL_LOG(ERR, "Rtos timer create failure");
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
			PAL_LOG(ERR, "Rtos mutex create failure");
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
		PAL_LOG(ERR, "Rtos mutex release failure %ld", res);
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
		PAL_LOG(ERR, "Rtos mutex delete failure");
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
			PAL_LOG(ERR, "Rtos semaphore create error");
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
		PAL_LOG(ERR, "Rtos semaphore destroy error");
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


