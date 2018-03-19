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
*   This file contains the real-time OS APIs and is a part of the PAL service API.
*   It provides thread, timers, semaphores, mutexes and memory pool management APIs.
*   Random API and ROT (root of trust) are also provided.  
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
    palOsTimerOnce = 0, /*! One shot timer. */
	palOsTimerPeriodic = 1 /*! Periodic (repeating) timer. */
} palTimerType_t;



//! Device key types supported in PAL.
typedef enum  palDeviceKeyType {
    palOsStorageEncryptionKey128Bit = 0, /*! 128bit storage encryption key derived from RoT. */
    palOsStorageSignatureKey128Bit = 1, /*! 128bit storage signature key derived from RoT. */
    palOsStorageHmacSha256 = 2
} palDevKeyType_t;

//! PAL timer function prototype.
typedef void(*palTimerFuncPtr)(void const *funcArgument);

//! PAL thread function prototype.
typedef void(*palThreadFuncPtr)(void const *funcArgument); 

//! Available priorities in PAL implementation, each priority can appear only once.
typedef enum pal_osPriority {
    PAL_osPriorityFirst = 0,
    PAL_osPriorityIdle = PAL_osPriorityFirst,
    PAL_osPriorityLow = 1,
    PAL_osPriorityReservedTRNG = 2,
    PAL_osPriorityBelowNormal = 3,
    PAL_osPriorityNormal = 4,
    PAL_osPriorityAboveNormal = 5,
    PAL_osPriorityReservedDNS = 6, /*! Reserved for PAL's internal use */
    PAL_osPriorityReservedSockets = 7, /*! Reserved for PAL's internal use */
    PAL_osPriorityHigh = 8,
    PAL_osPriorityReservedHighResTimer = 9, /*! Reserved for PAL's internal use */
    PAL_osPriorityRealtime = 10,
    PAL_osPrioritylast = PAL_osPriorityRealtime,
    PAL_osPriorityError = 0x84
} palThreadPriority_t; /*! Thread priority levels for PAL threads - each thread must have a different priority. */

//! Thread local store struct.
//! Can be used to hold for example state and configurations inside the thread.
typedef struct pal_threadLocalStore{
    void* storeData;
} palThreadLocalStore_t;

typedef struct pal_timeVal{
    int32_t    pal_tv_sec;      /*! Seconds. */
    int32_t    pal_tv_usec;     /*! Microseconds. */
} pal_timeVal_t;


//------- system general functions
/*! Initiates a system reboot.
*/
void pal_osReboot(void);

//------- system tick functions
/*! Get the RTOS kernel system timer counter.
* \note The system needs to supply a 64-bit tick counter. If only a 32-bit counter is supported,
* \note the counter wraps around very often (for example, once every 42 sec for 100Mhz).
* \return The RTOS kernel system timer counter.
*/
uint64_t pal_osKernelSysTick(void);


/*! Converts a value from microseconds to kernel system ticks.
*
* @param[in] microseconds The number of microseconds to convert into system ticks.
*
* \return Converted value in system ticks.
*/
uint64_t pal_osKernelSysTickMicroSec(uint64_t microseconds);

/*! Converts value from kernel system ticks to milliseconds.
*
* @param[in] sysTicks The number of kernel system ticks to convert into milliseconds.
*
* \return Converted value in system milliseconds.
*/
uint64_t pal_osKernelSysMilliSecTick(uint64_t sysTicks);

/*! Get the system tick frequency.
* \return The system tick frequency.
*
* \note The system tick frequency MUST be more than 1KHz (at least one tick per millisecond).
*/
uint64_t pal_osKernelSysTickFrequency(void);


/*! Get the system time.
* \return The system 64-bit counter indicating the current system time in seconds on success.
*         Zero value when the time is not set in the system.
* \note If the delta between secure time value previously set in the system and current system time is greater than PAL_LAST_SAVED_TIME_LATENCY_SEC
* then secure time value will be overridden with current system time
*/
uint64_t pal_osGetTime(void);

/*! \brief Set the current system time by accepting seconds since January 1st 1970 UTC+0.
*
* @param[in] seconds Seconds from January 1st 1970 UTC+0.
*
* \return PAL_SUCCESS when the time was set successfully. \n
*         PAL_ERR_INVALID_TIME when there is a failure setting the system time.
*/
palStatus_t pal_osSetTime(uint64_t seconds);

/*! \brief  Initialization the time module
*   After boot, the time in RAM will be initialized with the max value between RTC and SOTP SAVED_TIME. If no RTC is present, RTC time is zero.
*   After initialization the time module will start counting ticks.
*   The answer to get_time should be calculated by the sum of the initial value (RTC or SOTP) + the number of ticks converted into seconds.
*
* \return PAL_SUCCESS when initialization succeed. \n
*
* \note
*/
palStatus_t pal_initTime(void);

/*! \brief save weak time according to design
*   Time Forward (a)
*   set the time (in RAM) unconditionally. Save the new time in SOTP if the change (between new time and current time in RAM) is greater than 24 hours.
*   Set the time to RTC if the change is greater than 100 seconds. This limitation is to avoid multiple writes to the SOTP and RTC and not related to security.
*   Time Forward (b)
*   If (a) did not happen, save the time into SOTP if new time is greater from SAVED_TIME by a week (604800 seconds).
*   Time Backwards
*   set the device time on the device (RAM) and save the time in SOTP only if the change
*   (between new time and current time in RAM) is smaller than 3 minutes for each day lapsed from the last change
*   done via pal_osWeakSetTime. RTC is never set backwards by pal_osWeakSetTime().
*
* @param[in] uint64_t setTimeInSeconds  Seconds from January 1st 1970 UTC+0.
*
* \return PAL_SUCCESS when set weak  succeed. \n
*
* \note To implement this, when the new time is saved in SOTP by the function pal_osWeakSetTime two records with different types must be saved in SOTP:
* \note 1.- The new time (the same record as in factory setup)
* \note 2.- The time this action was performed, in order to enforce the 24 hours limitation. Record LAST_TIME_BACK.
*/
palStatus_t pal_osSetWeakTime(uint64_t setTimeInSeconds);

/*! \brief save strong time according to design
*   Set the time (in RAM) unconditionally. Save in SOTP or/and RTC the new time under the following conditions:
•	Time forward – if time difference between current time in SOTP (not device time) and new time is greater than a day
•	Time backward – if time difference between current time and new time is greater than one minute.
*   If the time is saved in SOTP (forward or backwards), the record LAST_TIME_BACK must be saved.
*
** @param[in] uint64_t setTimeInSeconds - Seconds from January 1st 1970 UTC+0.
**
* \return PAL_SUCCESS when set strong succeed. \n
*
* \note   The limitations are aimed to reduce the number of write operations to the SOTP and not related to security.
*   This function will be called when receiving time from a server that is completely trusted.
*/
palStatus_t pal_osSetStrongTime(uint64_t setTimeInSeconds);

/*! \brief Allocates memory for the thread stack, creates and starts the thread function (inside the PAL platform wrapper function).
*
* @param[in] function A function pointer to the thread callback function.
* @param[in] funcArgument An argument for the thread function.
* @param[in] priority The priority of the thread.
* @param[in] stackSize The stack size of the thread, can NOT be 0.
* @param[in] store A pointer to thread's local store, can be NULL.
* @param[out] threadID: The created thread ID handle. In case of error, this value is NULL.
*
* \return PAL_SUCCESS when the thread was created successfully. \n
*         PAL_ERR_RTOS_PRIORITY when the given priority is already used in the system.
*
* \note Each thread MUST have a unique priority.
* \note When the priority of the created thread function is higher than the current running thread, the
*       created thread function starts instantly and becomes the new running thread.
* \note Calling \c pal_osThreadTerminate() releases the thread stack.
*/
palStatus_t pal_osThreadCreateWithAlloc(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadLocalStore_t* store, palThreadID_t* threadID);

/*! Terminate and free allocated data for the thread.
*
* @param[in] threadID The thread ID to stop and terminate.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure. \n
*         PAL_ERR_RTOS_RESOURCE if the thread ID is not correct.
* \note  pal_osThreadTerminate is a non blocking operation, pal_osThreadTerminate sends cancellation request to the thread, 
*        usually the thread exits immediately, but the system does not always guarantee this
*/
palStatus_t pal_osThreadTerminate(palThreadID_t* threadID);

/*! Get the ID of the current thread.
* \return The ID of the current thread. In case of error, return PAL_MAX_UINT32.
* \note For a thread with real time priority, the function always returns PAL_MAX_UINT32.
*/
palThreadID_t pal_osThreadGetId(void);

/*! Get the storage of the current thread.
* \return The storage of the current thread.
*/
palThreadLocalStore_t* pal_osThreadGetLocalStore(void);

/*! Wait for a specified time period in milliseconds.
*
* @param[in] milliseconds The number of milliseconds to wait before proceeding.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osDelay(uint32_t milliseconds);

/*! Create a timer.
*
* @param[in] function A function pointer to the timer callback function.
* @param[in] funcArgument An argument for the timer callback function.
* @param[in] timerType The timer type to be created, periodic or oneShot.
* @param[out] timerID The created timer ID handle. In case of error, this value is NULL.
*
* \return PAL_SUCCESS when the timer was created successfully. \n
*         PAL_ERR_NO_MEMORY when there is no memory resource available to create a timer object.
*
* \note The timer function runs according to the platform resources of stack-size and priority.
*/
palStatus_t pal_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID);

/*! Start or restart a timer.
*
* @param[in] timerID The handle for the timer to start.
* @param[in] millisec The amount of time in milliseconds to set the timer to. MUST be larger than 0.
*                      In case of 0 value, the error PAL_ERR_RTOS_VALUE is returned.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osTimerStart(palTimerID_t timerID, uint32_t millisec);

/*! Stop a timer.
* @param[in] timerID The handle for the timer to stop.
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osTimerStop(palTimerID_t timerID);

/*! Delete the timer object.
*
* @param[inout] timerID The handle for the timer to delete. In success, `*timerID` = NULL.
*
* \return PAL_SUCCESS when timer was deleted successfully. \n
*         PAL_ERR_RTOS_PARAMETER when the `timerID` is incorrect.
*/
palStatus_t pal_osTimerDelete(palTimerID_t* timerID);

/*! Create and initialize a mutex object.
*
* @param[out] mutexID The created mutex ID handle. In case of error, this value is NULL.
*
* \return PAL_SUCCESS when the mutex was created successfully. \n
*         PAL_ERR_NO_MEMORY when there is no memory resource available to create a mutex object.
*/
palStatus_t pal_osMutexCreate(palMutexID_t* mutexID);

/*! Wait until a mutex becomes available.
*
* @param[in] mutexID The handle for the mutex.
* @param[in] millisec The timeout for waiting to the mutex to be available. PAL_RTOS_WAIT_FOREVER can be used as a parameter.
*
* \return PAL_SUCCESS(0) in case of success or one of the following error codes in case of failure: \n
*         PAL_ERR_RTOS_RESOURCE - mutex was not availabe but no timeout was set. \n
*         PAL_ERR_RTOS_TIMEOUT - mutex was not available until the timeout. \n
*         PAL_ERR_RTOS_PARAMETER - mutex ID is invalid. \n
*         PAL_ERR_RTOS_ISR - cannot be called from the interrupt service routines.
*/
palStatus_t pal_osMutexWait(palMutexID_t mutexID, uint32_t millisec);

/*! Release a mutex that was obtained by `osMutexWait`.
*
* @param[in] mutexID The handle for the mutex.
* \return PAL_SUCCESS(0) in case of success and another negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osMutexRelease(palMutexID_t mutexID);

/*!Delete a mutex object.
*
* @param[inout] mutexID The mutex handle to delete. In success, `*mutexID` = NULL.
*
* \return PAL_SUCCESS when the mutex was deleted successfully. \n
*         PAL_ERR_RTOS_RESOURCE - mutex is already released. \n
*         PAL_ERR_RTOS_PARAMETER - mutex ID is invalid. \n
*         PAL_ERR_RTOS_ISR - cannot be called from the interrupt service routines. \n
* \note After this call, the `mutex_id` is no longer valid and cannot be used.
*/
palStatus_t pal_osMutexDelete(palMutexID_t* mutexID);

/*! Create and initialize a semaphore object.
*
* @param[in] count The number of available resources.
* @param[out] semaphoreID The created semaphore ID handle. In case of error, this value is NULL.
*
* \return PAL_SUCCESS when the semaphore was created successfully. \n
*         PAL_ERR_NO_MEMORY when there is no memory resource available to create a semaphore object.
*/
palStatus_t pal_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID);

/*! Wait until a semaphore token becomes available.
*
* @param[in] semaphoreID The handle for the semaphore.
* @param[in] millisec The timeout for the waiting operation if the timeout 
                       expires before the semaphore is released and error is 
                       returned from the function. PAL_RTOS_WAIT_FOREVER can be used.
* @param[out] countersAvailable The number of semaphores available at the call if a
                                  semaphore is available. If the semaphore is not available (timeout/error) zero is returned. This parameter can be NULL 
* \return PAL_SUCCESS(0) in case of success and one of the following error codes in case of failure: \n
*       PAL_ERR_RTOS_TIMEOUT - the semaphore was not available until timeout. \n
*       PAL_ERR_RTOS_PARAMETER - the semaphore ID is invalid.
*/
palStatus_t pal_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec, int32_t* countersAvailable);

/*! Release a semaphore token.
*
* @param[in] semaphoreID The handle for the semaphore
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osSemaphoreRelease(palSemaphoreID_t semaphoreID);

/*! Delete a semaphore object.
*
* @param[inout] semaphoreID The semaphore handle to delete. In success, `*semaphoreID` = NULL.
*
* \return PAL_SUCCESS when the semaphore was deleted successfully. \n
*         PAL_ERR_RTOS_RESOURCE - the semaphore was already released. \n
*         PAL_ERR_RTOS_PARAMETER - the semaphore ID is invalid.
* \note After this call, the `semaphore_id` is no longer valid and cannot be used.
*/
palStatus_t pal_osSemaphoreDelete(palSemaphoreID_t* semaphoreID);

/*! Perform an atomic increment for a signed 32-bit value.
*
* @param[in,out] valuePtr The address of the value to increment.
* @param[in] increment The number by which to increment.
*
* \return The value of `valuePtr` after the increment operation.
*/
int32_t pal_osAtomicIncrement(int32_t* valuePtr, int32_t increment);


/*! Generate random number into given buffer with given size in bytes.
*
* @param[out] randomBuf A buffer to hold the generated number.
* @param[in] bufSizeBytes The size of the buffer and the size of the required random number to generate.
*
\note `pal_init()` MUST be called before this function
\return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes);


/*! Return a device unique key derived from the root of trust.
*
* @param[in] keyType The type of key to derive.
* @param[in,out] key A 128-bit OR 256-bit buffer to hold the derived key, size is defined according to the `keyType`.
* @param[in] keyLenBytes The size of buffer to hold the 128-bit OR 256-bit key.
* \return PAL_SUCCESS in case of success and one of the following error codes in case of failure: \n
* PAL_ERR_GET_DEV_KEY - an error in key derivation.
*/
palStatus_t pal_osGetDeviceKey(palDevKeyType_t keyType, uint8_t *key, size_t keyLenBytes);


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

/*! Generate a 32-bit random number.
*
* @param[out] random A 32-bit buffer to hold the generated number.
*
\note `pal_init()` MUST be called before this function.
\return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osRandom32bit(uint32_t *random);


#ifdef __cplusplus
}
#endif
#endif //_PAL_RTOS_H
