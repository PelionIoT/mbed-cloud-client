/*******************************************************************************
 * Copyright 2018 ARM Ltd.
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

/* PAL-RTOS porting for SXOS SDK
*  This is porting code for PAL RTOS APIS for
*  SXOS SDK / RSX RTOS.
*/


#include "pal.h"
#include "pal_plat_rtos.h"

#include <cos.h>
#include <tm.h>
#include <dm.h>

#include <stdlib.h>
#include <stdio.h> // snprintf

#define TRACE_GROUP "PAL"
#define PAL_THREAD_PRIORITY_TRANSLATE(x) ((COS_MMI_TASKS_PRIORITY_BASE + (uint8_t)PAL_osPrioritylast) - x)

extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes);

PAL_PRIVATE void pal_plat_osTimerHelperThreadFunction(const void* param);

//! Internal timer structure
typedef struct palTimer {
    palTimerFuncPtr function;
    void*           functionArgs;
    palTimerType_t  timerType;
    uint32_t        periodMs;
} palTimer_t;

//! Internal mutex structure
typedef struct palMutex {
    COS_MUTEX   osMutex;
} palMutex_t;

//! Internal semaphore structure
typedef struct palSemaphore {
    COS_SEMA    osSemaphore;
} palSemaphore_t;

//! Internal semaphore structure
typedef struct palThread
{
    palThreadFuncPtr    userFunction;
    void*               userFunctionArgument;
    char*               name;
    HANDLE              osThread;
} palThread_t;


// XXX: this just has to have space for pal_0xffffffff\0
#define PAL_THREAD_NAME_MAX_LEN 16 // max len for thread name which holds the pointer (as string) to dynamically allocated thread data

// Max attempts to try setting RTC time
#define PAL_MAX_RTC_SET_ATTEMPTS 5

// This define controls if the timer uses the IRQ based timer or task one. In practice
// this affects on the context where the timer callback is called on. Unless the ns-hal-pal and PAL
// sides can implement a recursive critical section without mutexes, the code needs a thread
// context. Note: the mutex code can not be called from IRQ.
#ifndef PAL_SXOS_USE_TIMER_HELPER_THREAD
#define PAL_SXOS_USE_TIMER_HELPER_THREAD 1
#endif

#if PAL_SXOS_USE_TIMER_HELPER_THREAD

// The timer callback thread is having this much stack, which should be plenty as on other OS' even 1KB is
// enough for the client code. But of course the OS itself affects also on the needed stack space
#ifndef PAL_TIMER_THREAD_STACK_SIZE
#define PAL_TIMER_THREAD_STACK_SIZE (4*1024)
#endif

PAL_PRIVATE palThreadID_t g_timer_helper_thread;
#endif

palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status;

#if PAL_SXOS_USE_TIMER_HELPER_THREAD
    status = pal_plat_osThreadCreate(pal_plat_osTimerHelperThreadFunction,
                                    NULL,
                                    PAL_osPriorityReservedHighResTimer,
                                    PAL_TIMER_THREAD_STACK_SIZE,
                                    &g_timer_helper_thread);
#else
    status = PAL_SUCCESS;
#endif

#if (PAL_USE_HW_RTC)
    if (status == PAL_SUCCESS)
    {
        status = pal_plat_rtcInit();
    }
#endif

    return status;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
    palStatus_t status;

#if PAL_SXOS_USE_TIMER_HELPER_THREAD
    status = pal_plat_osThreadTerminate(&g_timer_helper_thread);
#else
    status = PAL_SUCCESS;
#endif

#if (PAL_USE_HW_RTC)
    if (status == PAL_SUCCESS)
    {
        status = pal_plat_rtcDeInit();
    }
#endif

    return status;
}

palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
    palStatus_t status = PAL_SUCCESS;

    if (COS_Sleep(milliseconds) == false) {
        // according to source, the COS_Sleep() returns unconditionally TRUE, but
        // let's be super cautious and pass the error to caller. OTOH, nobody checks
        // the return value anyway..
        status = PAL_ERR_RTOS_OS;
    }
    return status;
}


uint64_t pal_plat_osKernelSysTick()
{

    static uint32_t prevCountLo = 0;
    static uint64_t prevCount = 0;

    uint32_t osCount = (uint32_t)COS_GetTickCount();

    if (osCount < prevCountLo) {
        prevCount = (1LL << 32) + osCount;
    } else {
        prevCount = osCount;
    }
    prevCountLo = osCount;

    return prevCount;
}

uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{
    uint64_t ticks = (uint64_t)COS_Msec2Tick(microseconds / 1000);
    return ticks;
}

uint64_t pal_plat_osKernelSysTickFrequency()
{
    uint64_t ticksPerSecond = COS_Sec2Tick(1);
    return ticksPerSecond;
}

PAL_PRIVATE void pal_plat_osThreadWarpperFunction(void* param)
{
    palThread_t* thread = param;

    thread->userFunction(thread->userFunctionArgument);

    // COS does not seem to support thread function to return (problems in deleting the thread).
    // Therefore if userFunction returns, we stay here waiting for task to be deleted.
    HANDLE task = COS_GetCurrentTaskHandle();
    COS_EVENT event;
    for (;;) {
        COS_WaitEvent(task, &event, COS_WAIT_FOREVER);
    }
}


palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;

    int bytesWritten;
    palThread_t* thread = malloc(sizeof(palThread_t));
    char* threadName = malloc((PAL_THREAD_NAME_MAX_LEN + 1)); // name will hold the address of the dynamically allocated palThread_t (as string)
    thread = malloc(sizeof(palThread_t));
    if ((NULL == thread) || (NULL == threadName))
    {
        status = PAL_ERR_RTOS_RESOURCE;
        goto clean;
    }

    // XXX: the thread name really needs to come from the client side, as then we could use meaningful names
    bytesWritten = snprintf(threadName, (PAL_THREAD_NAME_MAX_LEN + 1), "pal_%p", thread);
    if ((bytesWritten <= 0) || ((PAL_THREAD_NAME_MAX_LEN + 1) <= bytesWritten))
    {
        status = PAL_ERR_RTOS_RESOURCE;
        goto clean;
    }

    // Note: COS_CreateTask() has a pStackAddr -parameter but it actually does not use it and
    // it allocates the stack internally.
    thread->name = threadName;
    thread->userFunction = function;
    thread->userFunctionArgument = funcArgument;

    // 0xDC - 0xFA is reserved for MMI task, 0xDC is default
    // (0 is highest, 0xff lowest priority)

    uint8_t taskPriority = PAL_THREAD_PRIORITY_TRANSLATE(priority);

    // Create and start a task. As the thread cleanup seems to require a COS_StopTask(),
    // we use a wrapper to call the user provided function and eventually do the cleanup.
    HANDLE threadOs = COS_CreateTask((PTASK_ENTRY)pal_plat_osThreadWarpperFunction,
                                    thread,
                                    NULL,
                                    stackSize,
                                    taskPriority,
                                    COS_CREATE_DEFAULT,
                                    0,
                                    threadName);

    if (threadOs == NULL)
    {
        status = PAL_ERR_NO_MEMORY;
        goto clean;
    }
    else
    {
        thread->osThread = threadOs;
        *threadID = (palThreadID_t)thread;
    }

    return status;

clean:
    free(thread);
    free(threadName);

    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    // XXX: the current thread ID is not really a useful value for anything but separating
    // threads in debug traces. The given value is NOT the same as returned by pal_osThreadCreate().
    HANDLE currTask = COS_GetCurrentTaskHandle();

    return (palThreadID_t)currTask;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;

    palThread_t* thread = (palThread_t*)*threadID;

    if (COS_GetCurrentTaskHandle() == thread->osThread) // self termination not allowed
    {
        status = PAL_ERR_RTOS_TASK;
        goto end;
    }

    // deleting a running task is not supported by COS, so it needs to be stopped first.
    COS_StopTask((TASK_HANDLE *)thread->osThread);

    // this has a hardcoded "return FALSE", which may or may not be a bug, so pass the return check here
    COS_DeleteTask(thread->osThread);

    free(thread->name);
    free(thread);

end:

    return status;
}

// This thread function will be used to serve the timer requests. It will not do
// anything itself but call the COS_WaitEvent(), which internally will handle calling
// the timer callbacks.
PAL_PRIVATE void pal_plat_osTimerHelperThreadFunction(const void* param)
{
    HANDLE current_task = COS_GetCurrentTaskHandle();

    while (true)
    {
        COS_EVENT event;
        COS_WaitEvent(current_task, &event, COS_WAIT_FOREVER);
    }
}

PAL_PRIVATE void pal_plat_osTimerWarpperFunction(void* param)
{
    palTimer_t* timer = param;

    if (timer->timerType == palOsTimerPeriodic)
    {
        // XXX: by re-starting the periodic timer here we get relatively constant
        // interval. But of course this requires the callback to return before the
        // timeout or behavior gets bad. But this whole IRQ based timer code really
        // expects the timer callback to just behave.
        // Having the timer starting here is also convenient for the caller site also,
        // as it can stop the timer from callback and this wrapper will not overwrite
        // that will.
#if PAL_SXOS_USE_TIMER_HELPER_THREAD
        const palThread_t* timer_thread = (palThread_t*)g_timer_helper_thread;

        HANDLE timer_thread_handle = timer_thread->osThread;

        COS_StartCallbackTimer(timer_thread_handle, timer->periodMs, pal_plat_osTimerWarpperFunction, param);
#else
        COS_StartFunctionTimer(timer->periodMs, pal_plat_osTimerWarpperFunction, param);
#endif
    }

    timer->function(timer->functionArgs);
}

palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID)
{
    palStatus_t status = PAL_SUCCESS;

    // the COS identifies the timer by callback+param tuple. As we pass the PAL timer callback
    // and its own timer struct as parameter to COS timer, the uniqueness is guaranteed and there is no
    // need to maintain a local timer ID scheme.

    palTimer_t* timer = malloc(sizeof(palTimer_t));

    if (NULL == timer)
    {
        status = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == status)
    {
        timer->function = function;
        timer->functionArgs = funcArgument;
        timer->timerType = timerType;

        *timerID = (palTimerID_t)timer;
    }

    return status;
}

palStatus_t pal_plat_osTimerStart(palTimerID_t timerID, uint32_t millisec)
{
    palStatus_t status = PAL_SUCCESS;

    palTimer_t* timer = (palTimer_t*)timerID;

    // There is no periodic timer on COS as far as I know, so we need to emulate it
    // by storing the period to timer and re-issue the timer from the callback itself.
    timer->periodMs = millisec;

#if PAL_SXOS_USE_TIMER_HELPER_THREAD
    const palThread_t* timer_thread = (palThread_t*)g_timer_helper_thread;

    HANDLE timer_thread_handle = timer_thread->osThread;

    COS_StartCallbackTimer(timer_thread_handle, millisec, pal_plat_osTimerWarpperFunction, timer);
#else
    // XXX: there is a COS_StartFunctionTimerForcedly(), which will actually
    // do less-forced restart of timer than COS_StartFunctionTimer(), which will
    // stop existing timer and start another.
    COS_StartFunctionTimer(millisec, pal_plat_osTimerWarpperFunction, timer);
#endif

    return status;
}

palStatus_t pal_plat_osTimerStop(palTimerID_t timerID)
{
    palStatus_t status = PAL_SUCCESS;

    palTimer_t* timer = (palTimer_t*)timerID;

#if PAL_SXOS_USE_TIMER_HELPER_THREAD
    const palThread_t* timer_thread = (palThread_t*)g_timer_helper_thread;

    HANDLE timer_thread_handle = timer_thread->osThread;

    COS_StopCallbackTimer(timer_thread_handle, (COS_CALLBACK_FUNC_T)pal_plat_osTimerWarpperFunction, timer);
#else
    COS_StopFunctionTimer((COS_CALLBACK_FUNC_T)pal_plat_osTimerWarpperFunction, timer);
#endif

    return status;
}

palStatus_t pal_plat_osTimerDelete(palTimerID_t* timerID)
{
    palStatus_t status = PAL_SUCCESS;

    palTimer_t* timer = (palTimer_t*)*timerID;

    free(timer);

    *timerID = 0;

    return status;
}


palStatus_t pal_plat_osMutexCreate(palMutexID_t* mutexID)
{
    // There is a COS_CreateMutex() & COS_DeleteMutex()using HANDLE's, but it is
    // marked as deprecated.
    // Let's then use the other API, COS_Mutex*, which takes in a COS_MUTEX

    palStatus_t status = PAL_SUCCESS;
    palMutex_t* mutex;

    // the COS_MutexInit() expects a zeroed struct, hence calloc()
    mutex = (palMutex_t*)calloc(1, sizeof(palMutex_t));
    if (NULL == mutex)
    {
        status = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == status)
    {
        // init can not fail
        COS_MutexInit(&mutex->osMutex);

        // Note: the PAL does not touch the given pointer unless success.
        *mutexID = (palMutexID_t)mutex;
    }

    return status;
}


palStatus_t pal_plat_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    palStatus_t status = PAL_SUCCESS;

    palMutex_t* mutex = (palMutex_t*)mutexID;

    if (millisec == PAL_RTOS_WAIT_FOREVER) {

        COS_MutexLock(&mutex->osMutex);
    }
    else
    {
        if (COS_MutexTryLock(&mutex->osMutex, millisec) == false) {

            status = PAL_ERR_RTOS_TIMEOUT;
        }
    }

    return status;
}


palStatus_t pal_plat_osMutexRelease(palMutexID_t mutexID)
{
    palMutex_t* mutex = (palMutex_t*)mutexID;

    COS_MutexUnlock(&mutex->osMutex);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osMutexDelete(palMutexID_t* mutexID)
{
    palMutex_t* mutex = (palMutex_t*)*mutexID;
    COS_MutexDestroy(&mutex->osMutex);

    free(mutex);

    *mutexID = NULL;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID)
{
    // There is a COS_CreateSemaphore() & COS_DeleteSemaphore()using HANDLE's, but it is
    // marked as deprecated.
    // Let's then use the other API, COS_Sema*, which takes in a COS_SEMA

    palStatus_t status = PAL_SUCCESS;
    palSemaphore_t* semaphore;

    // the COS_SemaInit() expects a zeroed struct, hence calloc()
    semaphore = (palSemaphore_t*)calloc(1, sizeof(palSemaphore_t));
    if (NULL == semaphore)
    {
        status = PAL_ERR_NO_MEMORY;
    }

    if (PAL_SUCCESS == status)
    {
        // init can not fail
        COS_SemaInit(&semaphore->osSemaphore, count);

        // Note: the PAL does not touch the given pointer unless success.
        *semaphoreID = (palSemaphoreID_t)semaphore;
    }

    return status;
}

palStatus_t pal_plat_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec, int32_t* countersAvailable)
{
    palStatus_t status = PAL_SUCCESS;

    palSemaphore_t* semaphore = (palSemaphore_t*)semaphoreID;

    if (millisec == PAL_RTOS_WAIT_FOREVER)
    {
        COS_SemaTake(&semaphore->osSemaphore);
    }
    else
    {
        if (COS_SemaTryTake(&semaphore->osSemaphore, millisec) == false)
        {
            status = PAL_ERR_RTOS_TIMEOUT;
        }
    }

    if ((NULL != countersAvailable) && (PAL_SUCCESS == status))
    {
        // XXX: this is pointless, only the test code uses the counters value and
        // the whole countersAvailable needs to be removed from API. On other OS there are even
        // silly hacks to support this misfeature.
        *countersAvailable = semaphore->osSemaphore.count;
    }

    return status;
}

palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
    palSemaphore_t* semaphore = (palSemaphore_t*)semaphoreID;

    COS_SemaRelease(&semaphore->osSemaphore);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t* semaphoreID)
{
    palSemaphore_t* semaphore = (palSemaphore_t*)*semaphoreID;

    COS_SemaDestroy(&semaphore->osSemaphore);

    free(semaphore);

    *semaphoreID = NULL;

    return PAL_SUCCESS;
}


void *pal_plat_malloc(size_t len)
{
    return malloc(len);
}


void pal_plat_free(void * buffer)
{
    free(buffer);
}

int32_t pal_plat_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
    int32_t res;

    HANDLE section = COS_EnterCriticalSection();

    res = *valuePtr + increment;
    *valuePtr = res;

    COS_ExitCriticalSection(section);

    return res;
}

palStatus_t pal_plat_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes)
{
    // XXX: this needs to return success until properly implemented to get the client side into network
    //palStatus_t status = PAL_ERR_NOT_IMPLEMENTED;

    palStatus_t status = PAL_SUCCESS;
    return status;
}

void pal_plat_osReboot(void)
{
    DM_DeviceSwithOff(true);
    while (1)
    {
        COS_Sleep(1000); // Wait until reset
    }
}

#if defined(PAL_USE_HW_RTC)

PAL_PRIVATE palMutexID_t rtcMutex = NULLPTR;

/*
 * Unisoc TM_FILENAME's DateTime is not seconds since 1.1.1970 but
 * seconds since 1.1.2000
 */
#define EPOCH_TIME_1_1_2000  (946684800)

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
    palStatus_t ret = PAL_SUCCESS;
    if (rtcSetTime < (uint64_t)PAL_MIN_RTC_SET_TIME)
    {
        ret = PAL_ERR_INVALID_TIME;
    }
    else
    {
        ret = pal_osMutexWait(rtcMutex, 5 * PAL_MILLI_PER_SECOND * PAL_ONE_SEC);
        if (ret == PAL_SUCCESS)
        {
            TM_FILETIME tm_filetime;
            TM_SYSTEMTIME tm_systemtime;

            tm_filetime.DateTime = (UINT32)rtcSetTime - EPOCH_TIME_1_1_2000;
            if (!TM_FileTimeToSystemTime(tm_filetime, &tm_systemtime))
            {
                ret = PAL_ERR_TIME_TRANSLATE;
            }

            if (ret == PAL_SUCCESS)
            {
                // TM_SetSystemTime returns false if platform RTC handler is busy.
                // Therefore try couple of times.
                bool ret_rtc = false;
                for (int attempt = PAL_MAX_RTC_SET_ATTEMPTS; attempt > 0 && !ret_rtc; attempt--)
                {
                    ret_rtc = TM_SetSystemTime(&tm_systemtime);

                    // Wait a moment before trying again
                    if (!ret_rtc)
                    {
                        COS_Sleep(1);
                    }
                }

                if (!ret_rtc)
                {
                    ret = PAL_ERR_RTOS_RTC_SET_TIME_ERROR;
                }
            }

            pal_osMutexRelease(rtcMutex);
        }
    }

    return ret;
}

palStatus_t pal_plat_osGetRtcTime(uint64_t *rtcGetTime)
{
    palStatus_t ret = PAL_SUCCESS;
    if (rtcGetTime != NULL)
    {
        TM_FILETIME tm_filetime;
        TM_SYSTEMTIME tm_systemtime;

        if (!TM_GetSystemTime(&tm_systemtime))
        {
            ret = PAL_ERR_RTOS_RTC_GET_TIME_ERROR;
        }

        if (ret == PAL_SUCCESS && !TM_SystemTimeToFileTime(&tm_systemtime, &tm_filetime))
        {
            ret = PAL_ERR_TIME_TRANSLATE;
        }
        *rtcGetTime = (uint64_t)tm_filetime.DateTime + EPOCH_TIME_1_1_2000;
    }
    else
    {
        ret = PAL_ERR_NULL_POINTER;
    }

    return ret;
}

palStatus_t pal_plat_rtcDeInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    if (NULLPTR != rtcMutex)
    {
        ret = pal_osMutexDelete(&rtcMutex);
        rtcMutex = NULLPTR;
    }
    return ret;
}

palStatus_t pal_plat_rtcInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    if (NULLPTR == rtcMutex)
    {
        ret = pal_osMutexCreate(&rtcMutex);
    }
    return ret;
}
#endif
