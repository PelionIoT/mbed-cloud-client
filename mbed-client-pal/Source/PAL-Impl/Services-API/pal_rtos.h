// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef _PAL_RTOS_H
#define _PAL_RTOS_H

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

#include <stdint.h>
#include <string.h> //memcpy


#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h" //added for PAL_INITIAL_RANDOM_SIZE value

/*! \file pal_rtos.h
 *  \brief PAL RTOS.
 *  This file contains the real-time OS APIs and is a part of the PAL service API.
 *
*   Random API is also provided.  
 *   as well as random API and ROT (root of trust).
 */


//! Wait forever define. Used for semaphores and mutexes.
#define PAL_TICK_TO_MILLI_FACTOR 1000

//! Primitive ID type declarations.
typedef uintptr_t palThreadID_t;
typedef uintptr_t palTimerID_t;
typedef uintptr_t palMutexID_t;
typedef uintptr_t palSemaphoreID_t;
typedef uintptr_t palMemoryPoolID_t;
typedef uintptr_t palMessageQID_t;

//! Timer types supported in PAL.
typedef enum  palTimerType {
    palOsTimerOnce = 0, /*!< One-shot timer. */
	palOsTimerPeriodic = 1 /*!< Periodic (repeating) timer. */
} palTimerType_t;


//! PAL timer function prototype.
typedef void(*palTimerFuncPtr)(void const *funcArgument);

//! PAL thread function prototype.
typedef void(*palThreadFuncPtr)(void const *funcArgument);

//! \enum pal_osPriority Available priorities in PAL implementation, each priority can appear only once.
typedef enum pal_osPriority {
    PAL_osPriorityFirst = 0,
    PAL_osPriorityIdle = PAL_osPriorityFirst,
    PAL_osPriorityLow = 1,
    PAL_osPriorityReservedTRNG = 2,
    PAL_osPriorityBelowNormal = 3,
    PAL_osPriorityNormal = 4,
    PAL_osPriorityAboveNormal = 5,
    PAL_osPriorityReservedDNS = 6, /*!< Reserved for PAL's internal use */
    PAL_osPriorityReservedSockets = 7, /*!< Reserved for PAL's internal use */
    PAL_osPriorityHigh = 8,
    PAL_osPriorityReservedHighResTimer = 9, /*!< Reserved for PAL's internal use */
    PAL_osPriorityRealtime = 10,
    PAL_osPrioritylast = PAL_osPriorityRealtime,
    PAL_osPriorityError = 0x84
} palThreadPriority_t; /*!< \brief Thread priority levels for PAL threads - each thread must have a different priority. */

//! \brief Thread local store struct.
//!
//! Can be used to hold, for example, state and configurations inside the thread.
typedef struct pal_threadLocalStore{
    void* storeData;
} palThreadLocalStore_t;

typedef struct pal_timeVal{
    int32_t    pal_tv_sec;      /*!< \brief Seconds. */
    int32_t    pal_tv_usec;     /*!< \brief Microseconds. */
} pal_timeVal_t;


//------- system general functions
/*! \brief Initiates a system reboot.
*
* Applications can provide their own implementation by defining PAL_USE_APPLICATION_REBOOT and
* providing the implementation for \c pal_plat_osApplicationReboot() function.
*/
void pal_osReboot(void);

//------- system tick functions
/*! \brief Get the RTOS kernel system timer counter.
* \note The system needs to supply a 64-bit tick counter. If only a 32-bit counter is supported,
*       the counter wraps around very often (for example, once every 42 sec for 100Mhz).
* \return The RTOS kernel system timer counter.
*/
uint64_t pal_osKernelSysTick(void);


/*! \brief Converts a value from microseconds to kernel system ticks.
*
* @param[in] microseconds The number of microseconds to convert into system ticks.
*
* \return Converted value in system ticks.
*/
uint64_t pal_osKernelSysTickMicroSec(uint64_t microseconds);

/*! \brief Converts kernel system ticks to milliseconds.
*
* @param[in] sysTicks The number of kernel system ticks to convert into milliseconds.
*
* \return Converted value in milliseconds.
*/
uint64_t pal_osKernelSysMilliSecTick(uint64_t sysTicks);

/*! \brief Get the system tick frequency.
* \return The system tick frequency.
*
* \note The system tick frequency MUST be more than 1KHz. In other words, there must be at least one tick per millisecond.
*/
uint64_t pal_osKernelSysTickFrequency(void);

/*! \brief Allocates memory for the thread stack, creates and starts the thread function inside the PAL platform wrapper function.
*
* @param[in] function A function pointer to the thread callback function.
* @param[in] funcArgument An argument for the thread function.
* @param[in] priority The priority of the thread.
* @param[in] stackSize The stack size of the thread, can NOT be 0.
* @param[in] store \b MUST be `NULL` - this functionality is not supported.
* @param[out] threadID: The created thread ID handle. In case of error, this value is `NULL`.
*
* \return PAL_SUCCESS when the thread was created successfully.
*
* \note When the priority of the created thread function is higher than the current running thread, the
*       created thread function starts instantly and becomes the new running thread.
* \note Calling \c pal_osThreadTerminate() releases the thread stack.
*/
palStatus_t pal_osThreadCreateWithAlloc(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadLocalStore_t* store, palThreadID_t* threadID);

/*! \brief Terminate the thread and free the data allocated for it.
*
* @param[in] threadID The thread ID to stop and terminate.
*
* \return PAL_SUCCESS(0) in case of success, and a negative value indicating a specific error code in case of failure.
*
* \note  \c pal_osThreadTerminate is a non-blocking operation. It sends a cancellation request to the thread,
*        and usually the thread exits immediately, but the system does not always guarantee this.
*/
palStatus_t pal_osThreadTerminate(palThreadID_t* threadID);

/*! \brief Get the ID of the current thread.
* \return The ID of the current thread.
* \return PAL_MAX_UINT32 in case of error.
*/
palThreadID_t pal_osThreadGetId(void);

/*! \brief Wait for a specified time period in milliseconds.
*
* @param[in] milliseconds The number of milliseconds to wait before proceeding.
*
* \return PAL_SUCCESS(0) in case of success, and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osDelay(uint32_t milliseconds);

/*! \brief Create a timer.
*
* @param[in] function A function pointer to the timer callback function.
* @param[in] funcArgument An argument for the timer callback function.
* @param[in] timerType The timer type to be created, either periodic or one-shot.
* @param[out] timerID The ID handle for the created timer. In case of error, this value is `NULL`.
*
* \return PAL_SUCCESS when the timer was created successfully.
* \return PAL_ERR_NO_MEMORY when there is no memory resource available to create a timer object.
*
* \note The timer function runs according to the platform resources of stack-size and priority.
*/
palStatus_t pal_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID);

/*! \brief Start or restart a timer.
*
* @param[in] timerID The ID handle for the timer to start or restart.
* @param[in] millisec The length of time in milliseconds to set the timer to. MUST be larger than 0.
*
* \return PAL_ERR_RTOS_VALUE In case the value of \c millisec was \c 0 .
* \return PAL_SUCCESS(0) in case of success, and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osTimerStart(palTimerID_t timerID, uint32_t millisec);

/*! \brief Stop a timer.
* @param[in] timerID The ID handle for the timer to stop.
* \return PAL_SUCCESS(0) in case of success, and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osTimerStop(palTimerID_t timerID);

/*! \brief Delete a timer object.
*
* @param[in,out] timerID The ID handle for the timer to delete. On success, `*timerID` is changed to `NULL`.
*
* \return PAL_SUCCESS when timer was deleted successfully.
* \return PAL_ERR_RTOS_PARAMETER when the `timerID` is incorrect.
*/
palStatus_t pal_osTimerDelete(palTimerID_t* timerID);

/*! \brief Create and initialize a mutex object.
*
* @param[out] mutexID The created mutex ID handle. In case of error, this value is `NULL`.
*
* \return PAL_SUCCESS when the mutex was created successfully.
* \return PAL_ERR_NO_MEMORY when there is no memory resource available to create a mutex object.
*/
palStatus_t pal_osMutexCreate(palMutexID_t* mutexID);

/*! \brief Wait until a mutex becomes available.
*
* @param[in] mutexID The handle for the mutex.
* @param[in] millisec The timeout for waiting for the mutex to be available. PAL_RTOS_WAIT_FOREVER can be used as a parameter.
*
* \return PAL_SUCCESS(0) in case of success.
* \return PAL_ERR_RTOS_RESOURCE Failure - mutex was not availabe but no timeout was set.
* \return PAL_ERR_RTOS_TIMEOUT Failure - mutex was not available before timeout.
* \return PAL_ERR_RTOS_PARAMETER Failure - mutex ID is invalid.
* \return PAL_ERR_RTOS_ISR Failure - cannot be called from the interrupt service routines.
*/
palStatus_t pal_osMutexWait(palMutexID_t mutexID, uint32_t millisec);

/*! \brief Release a mutex that was obtained by `osMutexWait`.
*
* @param[in] mutexID The handle for the mutex.
* \return PAL_SUCCESS(0) in case of success, or another negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osMutexRelease(palMutexID_t mutexID);

/*! \brief Delete a mutex object.
*
* @param[in,out] mutexID The mutex handle to delete. On success, `*mutexID` is changed to `NULL`.
*
* \return PAL_SUCCESS when the mutex was deleted successfully.
* \return PAL_ERR_RTOS_RESOURCE Failure - mutex is already released.
* \return PAL_ERR_RTOS_PARAMETER Failure - mutex ID is invalid.
* \return PAL_ERR_RTOS_ISR Failure - cannot be called from the interrupt service routines.
* \note After this call, the `mutexID` is no longer valid and cannot be used.
*/
palStatus_t pal_osMutexDelete(palMutexID_t* mutexID);

/*! \brief Create and initialize a semaphore object.
*
* @param[in] count The number of available resources.
* @param[out] semaphoreID The created semaphore ID handle. In case of error, this value is `NULL`.
*
* \return PAL_SUCCESS when the semaphore was created successfully.
* \return PAL_ERR_NO_MEMORY when there is no memory resource available to create a semaphore object.
*/
palStatus_t pal_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID);

/*! \brief Wait until a semaphore token becomes available.
*
* @param[in] semaphoreID The handle for the semaphore.
* @param[in] millisec The timeout for the waiting operation. If the timeout
                       expires before the semaphore is released, an error is
                       returned from the function. PAL_RTOS_WAIT_FOREVER can be used.
* @param[out] countersAvailable The number of semaphores available at the call if a
                                  semaphore is available. If the semaphore is not available due to timeout or error, `0` is returned. This parameter can be NULL
* \return PAL_SUCCESS(0) in case of success.
* \return PAL_ERR_RTOS_TIMEOUT Failure - the semaphore was not available until timeout.
* \return PAL_ERR_RTOS_PARAMETER Failure - the semaphore ID is invalid.
*/
palStatus_t pal_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec, int32_t* countersAvailable);

/*! \brief Release a semaphore token.
*
* @param[in] semaphoreID The handle for the semaphore
*
* \return PAL_SUCCESS(0) in case of success, or a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osSemaphoreRelease(palSemaphoreID_t semaphoreID);

/*! \brief Delete a semaphore object.
*
* @param[in,out] semaphoreID The semaphore handle to delete. On success, `*semaphoreID` is changed to `NULL`.
*
* \return PAL_SUCCESS when the semaphore was deleted successfully.
* \return PAL_ERR_RTOS_RESOURCE Failure - the semaphore was already released. \n
* \return PAL_ERR_RTOS_PARAMETER Failure - the semaphore ID is invalid.
* \note After this call, the `semaphoreID` is no longer valid and cannot be used.
*/
palStatus_t pal_osSemaphoreDelete(palSemaphoreID_t* semaphoreID);

/*! \brief Perform an atomic increment for a signed 32-bit value.
*
* @param[in,out] valuePtr The address of the value to increment.
* @param[in] increment The number by which to increment.
*
* \return The value of `valuePtr` after the increment operation.
*/
int32_t pal_osAtomicIncrement(int32_t* valuePtr, int32_t increment);

/*! Initialize the RTOS module for PAL.
 * This function can be called only once before running the system.
 * To remove PAL from the system, call `pal_RTOSDestroy`.
 * After calling `pal_RTOSDestroy`, you can call `pal_RTOSInitialize` again.
*
* @param[in] opaqueContext: context to be passed to the platform if needed.
*
* \return PAL_SUCCESS upon success.
*/
palStatus_t pal_RTOSInitialize(void* opaqueContext);


/*! This function removes PAL from the system and can be called after `pal_RTOSInitialize`.
**
* \return PAL_SUCCESS upon success. \n
* 		  PAL_ERR_NOT_INITIALIZED - if the user did not call `pal_RTOSInitialize()` first.
*/
palStatus_t pal_RTOSDestroy(void);



#ifdef __cplusplus
}
#endif
#endif //_PAL_RTOS_H
