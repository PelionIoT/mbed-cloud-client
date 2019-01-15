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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <stdatomic.h>
#include "semaphore.h"

#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>
 
#include <proto/exec.h>
#include <proto/dos.h>

#include "pal.h"
#include "pal_plat_rtos.h"

#define TRACE_GROUP "PAL"

extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes);

/*! Initiate a system reboot.
 */
void pal_plat_osReboot(void)
{

}

/*! Initialize all data structures (semaphores, mutexs, memory pools, message queues) at system initialization.
*	In case of a failure in any of the initializations, the function returns with an error and stops the rest of the initializations.
* @param[in] opaqueContext The context passed to the initialization (not required for generic CMSIS, pass NULL in this case).
* \return PAL_SUCCESS(0) in case of success, PAL_ERR_CREATION_FAILED in case of failure.
*/
palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status = PAL_SUCCESS;

    return status;
}

/*! De-Initialize thread objects.
 */
palStatus_t pal_plat_RTOSDestroy(void)
{
    palStatus_t ret = PAL_SUCCESS;

    return ret;
}

/*return The RTOS kernel system timer counter, in microseconds
 */

uint64_t pal_plat_osKernelSysTick(void) // optional API - not part of original CMSIS API.
{    
    uint64_t ticks; 
    return ticks;
}

/* Convert the value from microseconds to kernel sys ticks.
 * This is the same as CMSIS macro osKernelSysTickMicroSec.
 * since we return microsecods as ticks, just return the value
 */
uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{
    return 1;
}

/*! Get the system tick frequency.
 * \return The system tick frequency.
 */
inline uint64_t pal_plat_osKernelSysTickFrequency(void)
{
    return 1;
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;

    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    return 0;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;
    
    return status;
}

/*! Wait for a specified period of time in milliseconds.
 *
 * @param[in] milliseconds The number of milliseconds to wait before proceeding.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
    palStatus_t status = PAL_SUCCESS;

    return status;
}

/*! Create a timer.
 *
 * @param[in] function A function pointer to the timer callback function.
 * @param[in] funcArgument An argument for the timer callback function.
 * @param[in] timerType The timer type to be created, periodic or oneShot.
 * @param[out] timerID The ID of the created timer, zero value indicates an error.
 *
 * \return PAL_SUCCESS when the timer was created successfully. A specific error in case of failure.
 */
palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function, void* funcArgument,
        palTimerType_t timerType, palTimerID_t* timerID)
{
    palStatus_t status = PAL_SUCCESS;
 
    return status;
}

/*! Start or restart a timer.
 *
 * @param[in] timerID The handle for the timer to start.
 * @param[in] millisec The time in milliseconds to set the timer to.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osTimerStart(palTimerID_t timerID, uint32_t millisec)
{
    palStatus_t status = PAL_SUCCESS;    

    return status;
}

/*! Stop a timer.
 *
 * @param[in] timerID The handle for the timer to stop.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osTimerStop(palTimerID_t timerID)
{
    palStatus_t status = PAL_SUCCESS;    

    return status;
}

/*! Delete the timer object
 *
 * @param[inout] timerID The handle for the timer to delete. In success, *timerID = NULL.
 *
 * \return PAL_SUCCESS when the timer was deleted successfully, PAL_ERR_RTOS_PARAMETER when the timerID is incorrect.
 */
palStatus_t pal_plat_osTimerDelete(palTimerID_t* timerID)
{
    palStatus_t status = PAL_SUCCESS;    

    return status;
}

/*! Create and initialize a mutex object.
 *
 * @param[out] mutexID The created mutex ID handle, zero value indicates an error.
 *
 * \return PAL_SUCCESS when the mutex was created successfully, a specific error in case of failure.
 */
palStatus_t pal_plat_osMutexCreate(palMutexID_t* mutexID)
{
    palStatus_t status = PAL_SUCCESS;

    /* We'll use semaphores for mutexes in here */
    struct SignalSemaphore *mutex;
    {
        //int ret;
        if (NULL == mutexID)
        {
            return PAL_ERR_INVALID_ARGUMENT;
        }

        mutex = malloc(sizeof(struct SignalSemaphore));
        if (NULL == mutex)
        {
            status = PAL_ERR_NO_MEMORY;
            goto finish;
        }

        //pthread_mutexattr_t mutexAttr;
        //pthread_mutexattr_init(&mutexAttr);
        //pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
        //ret = pthread_mutex_init(mutex, &mutexAttr);
        InitSemaphore(mutex);
        // if (0 != ret)
        // {
        //     if (ENOMEM == ret)
        //     {
        //         status = PAL_ERR_NO_MEMORY;
        //     }
        //     else
        //     {
        //         PAL_LOG_ERR("Rtos mutex create status %d", ret);
        //         status = PAL_ERR_GENERIC_FAILURE;
        //     }
        //     goto finish;
        // }
        *mutexID = (palMutexID_t) mutex;
    }
    finish: if (PAL_SUCCESS != status)
    {
        if (NULL != mutex)
        {
            free(mutex);
        }
    }
    return status;
}

/* Wait until a mutex becomes available.
 *
 * @param[in] mutexID The handle for the mutex.
 * @param[in] millisec The timeout for the waiting operation if the timeout expires before the semaphore is released and an error is returned from the function.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, one of the following error codes in case of failure:
 * 		  PAL_ERR_RTOS_RESOURCE - Mutex not available but no timeout set.
 * 		  PAL_ERR_RTOS_TIMEOUT - Mutex was not available until timeout expired.
 * 		  PAL_ERR_RTOS_PARAMETER - Mutex ID is invalid.
 * 		  PAL_ERR_RTOS_ISR - Cannot be called from interrupt service routines.
 */
palStatus_t pal_plat_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    palStatus_t status = PAL_SUCCESS;    

    return status;
}

/* Release a mutex that was obtained by osMutexWait.
 *
 * @param[in] mutexID The handle for the mutex.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osMutexRelease(palMutexID_t mutexID)
{
    palStatus_t status = PAL_SUCCESS;
    
    return status;
}

/*Delete a mutex object.
 *
 * @param[inout] mutexID The ID of the mutex to delete. In success, *mutexID = NULL.
 *
 * \return PAL_SUCCESS when the mutex was deleted successfully, one of the following error codes in case of failure:
 * 		  PAL_ERR_RTOS_RESOURCE - Mutex already released.
 * 		  PAL_ERR_RTOS_PARAMETER - Mutex ID is invalid.
 * 		  PAL_ERR_RTOS_ISR - Cannot be called from interrupt service routines.
 * \note After this call, mutex_id is no longer valid and cannot be used.
 */
palStatus_t pal_plat_osMutexDelete(palMutexID_t* mutexID)
{
    palStatus_t status = PAL_SUCCESS;
    //uint32_t ret;
    if (NULL == mutexID) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    struct SignalSemaphore *mutex = (struct SignalSemaphore *)*mutexID;
    //pthread_mutex_t* mutex = (pthread_mutex_t*) *mutexID;

    if (NULL == mutex) {
        status = PAL_ERR_RTOS_RESOURCE;
    }
    else {
        // ret = pthread_mutex_destroy(mutex);
        // if ((PAL_SUCCESS == status) && (0 != ret))
        // {
        // PAL_LOG_ERR("pal_plat_osMutexDelete 0x%x",ret);
        //     status = PAL_ERR_RTOS_RESOURCE;
        // }
        free(mutex);
        *mutexID = (palMutexID_t) NULL;
    }
    return status;
}

/* Create and initialize a semaphore object.
 *
 * Semaphore is shared between threads, but not process.
 *
 * @param[in] count The number of available resources.
 * @param[out] semaphoreID The ID of the created semaphore, zero value indicates an error.
 *
 * \return PAL_SUCCESS when the semaphore was created successfully, a specific error in case of failure.
 */
palStatus_t pal_plat_osSemaphoreCreate(uint32_t count,
        palSemaphoreID_t* semaphoreID)
{
    palStatus_t status = PAL_SUCCESS;
    sem_t* semaphore = NULL;

    {
        if (NULL == semaphoreID)
        {
            return PAL_ERR_INVALID_ARGUMENT;
        }
        semaphore = malloc(sizeof(sem_t));
        if (NULL == semaphore)
        {
            status = PAL_ERR_NO_MEMORY;
            goto finish;
        }
        /* create the semaphore as shared between threads */
        int ret = sem_init(semaphore, 0, count);
        if (-1 == ret)
        {
            if (EINVAL == errno)
            {
                /* count is too big */
                status = PAL_ERR_INVALID_ARGUMENT;
            }
            else
            {
                PAL_LOG_ERR("Rtos semaphore init error %d", ret);
                status = PAL_ERR_GENERIC_FAILURE;
            }
            goto finish;
        }

        *semaphoreID = (palSemaphoreID_t) semaphore;
    }
    finish: if (PAL_SUCCESS != status)
    {
        if (NULL != semaphore)
        {
            free(semaphore);
        }
        *semaphoreID = (palSemaphoreID_t) NULL;
    }
    return status;
}

/* Wait until a semaphore token becomes available.
 *
 * @param[in] semaphoreID The handle for the semaphore.
 * @param[in] millisec The timeout for the waiting operation if the timeout expires before the semaphore is released and an error is returned from the function.
 * @param[out] countersAvailable The number of semaphores available (before the wait), if semaphores are not available (timeout/error) zero is returned.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, one of the following error codes in case of failure:
 * 		PAL_ERR_RTOS_TIMEOUT - Semaphore was not available until timeout expired.
 *	    PAL_ERR_RTOS_PARAMETER - Semaphore ID is invalid.
 *	    PAL_ERR_INVALID_ARGUMENT - countersAvailable is NULL
 *
 *	    NOTES: 1. counterAvailable returns 0 in case there are no semaphores available or there are other threads waiting on it.
 *	              Value is not thread safe - it might be changed by the time it is read/returned.
 *	           2. timed wait is using absolute time.
 */
palStatus_t pal_plat_osSemaphoreWait(palSemaphoreID_t semaphoreID,
        uint32_t millisec, int32_t* countersAvailable)
{
    palStatus_t status = PAL_SUCCESS;
    int tmpCounters = 0;
    {
        int err;
        sem_t* sem = (sem_t*) semaphoreID;
        if ((NULL == sem))
        {
            return PAL_ERR_INVALID_ARGUMENT;
        }

        if (PAL_RTOS_WAIT_FOREVER != millisec)
        {
            /* calculate the wait absolute time */
            /* accuracy is quite poor this way. However the libsem seems to implement only 1s accuracy. This can be improved upon */
            struct timespec ts;
            ts.tv_sec = time(NULL);
            // clock_gettime(CLOCK_REALTIME, &ts);
            // ts.tv_sec += millisec / PAL_MILLI_PER_SECOND;
            // ts.tv_nsec += PAL_MILLI_TO_NANO(millisec);
            // ts.tv_sec += ts.tv_nsec / PAL_NANO_PER_SECOND; // in case there is overflow in the nanoseconds.
            // ts.tv_nsec = ts.tv_nsec % PAL_NANO_PER_SECOND;

            while ((err = sem_timedwait(sem, &ts)) == -1 && errno == EINTR)
                continue; /* Restart if interrupted by handler */
        }
        else
        { // wait for ever
            do
            {
                err = sem_wait(sem);

                /* loop again if the wait was interrupted by a signal */
            } while ((err == -1) && (errno == EINTR));
        }

        if (-1 == err)
        {
            tmpCounters = 0;
            if (errno == ETIMEDOUT)
            {
                status = PAL_ERR_RTOS_TIMEOUT;
            }
            else
            { /* seems this is not a valid semaphore */
                status = PAL_ERR_RTOS_PARAMETER;
            }
            goto finish;
        }
        /* get the counter number, shouldn't fail, as we already know this is valid semaphore */
        sem_getvalue(sem, &tmpCounters);
    }
    finish:
    if (NULL != countersAvailable)
    {
        *countersAvailable = tmpCounters;
    }
    return status;
}

/*! Release a semaphore token.
 *
 * @param[in] semaphoreID The handle for the semaphore.
 *
 * \return The status in the form of palStatus_t; PAL_SUCCESS(0) in case of success, a negative value indicating a specific error code in case of failure.
 */
palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
    palStatus_t status = PAL_SUCCESS;
    sem_t* sem = (sem_t*) semaphoreID;

    if (NULL == sem)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    if (-1 == sem_post(sem))
    {
        if (EINVAL == errno)
        {
            status = PAL_ERR_RTOS_PARAMETER;
        }
        else
        { /* max value of semaphore exeeded */
            PAL_LOG_ERR("Rtos semaphore release error %d", errno);
            status = PAL_ERR_GENERIC_FAILURE;
        }
    }

    return status;
}

/*! Delete a semaphore object.
 *
 * @param[inout] semaphoreID: The ID of the semaphore to delete. In success, *semaphoreID = NULL.
 *
 * \return PAL_SUCCESS when the semaphore was deleted successfully, one of the following error codes in case of failure:
 * 		  PAL_ERR_RTOS_RESOURCE - Semaphore already released.
 * 		  PAL_ERR_RTOS_PARAMETER - Semaphore ID is invalid.
 * \note After this call, the semaphore_id is no longer valid and cannot be used.
 */
palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t* semaphoreID)
{
    palStatus_t status = PAL_SUCCESS;
    {
        if (NULL == semaphoreID)
        {
            return PAL_ERR_INVALID_ARGUMENT;
        }

        sem_t* sem = (sem_t*) (*semaphoreID);
        if (NULL == sem)
        {
            status = PAL_ERR_RTOS_RESOURCE;
            goto finish;
        }
        if (-1 == sem_destroy(sem))
        {
            status = PAL_ERR_RTOS_PARAMETER;
            goto finish;
        }

        if (NULL != sem)
        {
            free(sem);
        }
        *semaphoreID = (palSemaphoreID_t) NULL;
    }
    finish: return status;
}

/*! Perform an atomic increment for a signed32 bit value.
 *
 * @param[in,out] valuePtr The address of the value to increment.
 * @param[in] increment The number by which to increment.
 *
 * \returns The value of the valuePtr after the increment operation.
 */
int32_t pal_plat_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
    //int32_t res = __sync_add_and_fetch(valuePtr, increment);
    _Atomic int32_t res = __atomic_add_fetch(valuePtr, increment,__ATOMIC_SEQ_CST);    
    return res;    
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
	status = pal_plat_getRandomBufferFromHW(randomBuf, bufSizeBytes, actualRandomSizeBytes);
    return status;
}

#if (PAL_USE_HW_RTC)
palStatus_t pal_plat_osGetRtcTime(uint64_t *rtcGetTime)
{
	palStatus_t ret = PAL_SUCCESS;

    return ret;
}

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
    palStatus_t ret = PAL_SUCCESS;

    return ret;
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

