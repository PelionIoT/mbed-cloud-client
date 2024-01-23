/*******************************************************************************
 * Copyright 2016-2019 ARM Ltd.
 * Copyright 2024 Izuma Networks
 *
 * SPDX-License-Identifier: Apache-2.0
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
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <mqueue.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include "pal.h"
#include "pal_plat_rtos.h"

#define TRACE_GROUP "PAL"

 /*
 * The realtime clock is in nano seconds resolution. This is too much for us, so we use "longer" ticks.
 * Below are relevant defines.
 * make sure they all coherent. Can use one at the other, but will add some unneeded calculations.
 */
#define NANOS_PER_TICK 100
#define TICKS_PER_MICRO  10L
#define TICKS_PER_MILLI  TICKS_PER_MICRO * 1000
#define TICKS_PER_SECOND TICKS_PER_MILLI * 1000

// priorities must be positive, so shift all by this margin. we might want to do smarter convert.
#define LINUX_THREAD_PRIORITY_BASE 10

#ifndef CLOCK_MONOTONIC_RAW //a workaround for the operWRT port that missing this include
#define CLOCK_MONOTONIC_RAW 4 //http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/time.h
#endif

#ifndef PAL_REBOOT_RETRY_COUNT
#define PAL_REBOOT_RETRY_COUNT 3
#endif

#define PAL_THREAD_PRIORITY_TRANSLATE(x) ((int16_t)(x + 7))

typedef struct palThreadData
{
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;
} palThreadData_t;

/*
 * Internal struct to handle timers.
 */
struct palTimerInfo
{
    struct palTimerInfo *next;
    timer_t handle;
    palTimerFuncPtr function;
    void *funcArgs;
    palTimerType_t timerType;
};

// Mutex to prevent simultaneus modification of the linked list of the timers in g_timerList.
PAL_PRIVATE palMutexID_t g_timerListMutex = 0;

#if (PAL_SIMULATE_RTOS_REBOOT == 1)
    extern char *program_invocation_name;
#endif


// A singly linked list of the timers, access may be done only if holding the g_timerListMutex.
// The list is needed as the timers use async signals and when the signal is finally delivered, the
// palTimerInfo timer struct may be already deleted. The signals themselves carry pointer to timer,
// so whenever a signal is received, the thread will look if the palTimerInfo is still on the list,
// and if it is, uses the struct to find the callback pointer and arguments.
PAL_PRIVATE volatile struct palTimerInfo *g_timerList = NULL;

extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes);

PAL_PRIVATE palStatus_t startTimerThread();
PAL_PRIVATE palStatus_t stopTimerThread();
PAL_PRIVATE void palTimerThread(void const *args);

/*! Initiate a system reboot.
 */
void pal_plat_osReboot(void)
{
//Simulator is currently for Linux only
#if (PAL_SIMULATE_RTOS_REBOOT == 1)
    const char *argv[] = {"0" , 0};
    char *const envp[] = { 0 };
    argv[0] = program_invocation_name;

    PAL_LOG_INFO("pal_plat_osReboot -> simulated reboot with execve(%s).\r\n", argv[0]);

    if (-1 == execve(argv[0], (char **)argv , envp))
    {
        PAL_LOG_ERR("child process execve failed [%s]\r\n", argv[0]);
    }
#else
    PAL_LOG_INFO("Rebooting the system\r\n");
    int status;
    int retries = 0;

    // Syncronize cached files to persistant storage.
    while (retries < PAL_REBOOT_RETRY_COUNT) {
        // Prefer using the command line command, as they perform
        // more things than the plain C API.
        status = system("sync");
        if (status == 127) {
            PAL_LOG_ERR("sync command not available, using C API instead.\r\n");
            // Since glibc 2.2.2 sync is void sync(void); - no return value.
            // Ref: https://man7.org/linux/man-pages/man2/sync.2.html
            // That function cannot fail, so status is zero.
            sync();
            status = 0;
        }
        if (status == 0)
        {
            PAL_LOG_INFO("sync succesfully done.\r\n");
            break;
        }
        else {
            PAL_LOG_ERR("sync command failed %d, retry...\r\n", status);
            retries++;
            sleep(1);
        }
    }
    // Reboot the device
    retries = 0;
    while (retries < PAL_REBOOT_RETRY_COUNT) {
        // Prefer using the command line command, as they perform
        // more things than the plain C API.
        status = system("reboot");
        if (status == 127) {
            PAL_LOG_ERR("reboot command not available, using C API instead.\r\n");
            status = reboot(RB_AUTOBOOT);
        }
        if (status != 0) {
            PAL_LOG_ERROR("Reboot failed with status %d\r\n", status);
            // Print the processes that are uninterruptile
            // and might be blocking the reboot
            system("ps -aux | grep D");
            retries++;
            sleep(1);
        }
    }
#endif
}

/*! Initialize all data structures (semaphores, mutexs, memory pools, message queues) at system initialization.
*	In case of a failure in any of the initializations, the function returns with an error and stops the rest of the initializations.
* @param[in] opaqueContext The context passed to the initialization (not required for generic CMSIS, pass NULL in this case).
* \return PAL_SUCCESS(0) in case of success, PAL_ERR_CREATION_FAILED in case of failure.
*/
palStatus_t pal_plat_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status = PAL_SUCCESS;
    (void)opaqueContext;
#if (PAL_USE_HW_RTC)
    status = pal_plat_rtcInit();
#endif

    // Setup the signal handler thread which will be shared with all the timers

    status = pal_osMutexCreate(&g_timerListMutex);

    if (status == PAL_SUCCESS) {

        sigset_t blocked;

        sigemptyset(&blocked);
        sigaddset(&blocked, PAL_TIMER_SIGNAL);

        // Make PAL_TIMER_SIGNAL blocked from this thread and the others
        // created onwards. Note: there is no handler for that on purpose, as
        // the signal is handled by the timer thread itself by sigwaitinfo().
        int err = pthread_sigmask(SIG_BLOCK, &blocked, NULL);

        if (err != 0) {

            status = PAL_ERR_SYSCALL_FAILED;
        }
    }

    if (status == PAL_SUCCESS) {

        status = startTimerThread();
    }

    return status;
}

/*! De-Initialize thread objects.
 */
palStatus_t pal_plat_RTOSDestroy(void)
{
    palStatus_t ret = PAL_SUCCESS;

#if PAL_USE_HW_RTC
    ret = pal_plat_rtcDeInit();
#endif

    // Is there really a point to check these, as if the shutdown fails, what can we do?
    // Nobody is going to call the shutdown again.
    if (ret == PAL_SUCCESS) {
        ret = stopTimerThread();
    }

    if (ret == PAL_SUCCESS) {
        ret = pal_osMutexDelete(&g_timerListMutex);
    }

    return ret;
}

/*return The RTOS kernel system timer counter, in microseconds
 */

uint64_t pal_plat_osKernelSysTick(void) // optional API - not part of original CMSIS API.
{
    /*Using clock_gettime is more accurate, but then we have to convert it to ticks. we are using a tick every 100 nanoseconds*/
    struct timespec ts;
    uint64_t ticks;
    //TODO: error handling
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

    ticks = (uint64_t) (ts.tv_sec * (uint64_t)TICKS_PER_SECOND
            + (ts.tv_nsec / NANOS_PER_TICK));
    return ticks;
}

/* Convert the value from microseconds to kernel sys ticks.
 * This is the same as CMSIS macro osKernelSysTickMicroSec.
 * since we return microsecods as ticks, just return the value
 */
uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{

    //convert to nanoseconds
    return microseconds * TICKS_PER_MICRO;
}

/*! Get the system tick frequency.
 * \return The system tick frequency.
 */
inline uint64_t pal_plat_osKernelSysTickFrequency(void)
{
    /* since we use clock_gettime, with resolution of 100 nanosecond per tick*/
    return TICKS_PER_SECOND;
}

PAL_PRIVATE void threadCleanupHandler(void* arg)
{
    free(arg);
}

PAL_PRIVATE void* threadFunction(void* arg)
{
    /*
    * note: even if a thread is only scheduled but has not started running, it will be cancelled only once it starts running and once it reaches a cancellation point, 
    *       hence the clean up handler will always be executed thus avoiding a memory leak.
    *       see section 2.9.5 @ http://pubs.opengroup.org/onlinepubs/009695399/functions/xsh_chap02_09.html
    */
    pthread_cleanup_push(threadCleanupHandler, arg); // register a cleanup handler to be executed once the thread is finished/terminated (threads can terminate only when reaching a cancellation point)
    palThreadData_t* threadData = (palThreadData_t*)arg;
    threadData->userFunction(threadData->userFunctionArgument);
    pthread_cleanup_pop(1); // in case the thread has not terminated execute the cleanup handler (passing a non zero value to pthread_cleanup_pop)
    return NULL;
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t* threadID)
{
    (void)priority;
    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    pthread_t sysThreadID = (pthread_t)NULL;
    pthread_attr_t attr;
    pthread_attr_t* ptrAttr = NULL;
    palThreadData_t* threadData;
    int err = pthread_attr_init(&attr);
    if (0 != err)
    {
        goto finish;
    }
    ptrAttr = &attr;

    if (stackSize < PTHREAD_STACK_MIN)
    {        
        PAL_LOG_WARN("Stack size is less than PTHREAD_STACK_MIN (%#x), change the stack size to 2*PTHREAD_STACK_MIN\r\n", PTHREAD_STACK_MIN);
        stackSize = 2*PTHREAD_STACK_MIN;
    }

    err = pthread_attr_setstacksize(ptrAttr, stackSize);
    if (0 != err)
    {
        goto finish;
    }

    err = pthread_attr_setdetachstate(ptrAttr, PTHREAD_CREATE_DETACHED);
    if (0 != err)
    {
        goto finish;
    }

    threadData = (palThreadData_t*)malloc(sizeof(palThreadData_t));
    if (NULL == threadData)
    {
        status = PAL_ERR_RTOS_RESOURCE;
        goto finish;
    }
    threadData->userFunction = function;
    threadData->userFunctionArgument = funcArgument;

    err = pthread_create(&sysThreadID, ptrAttr, threadFunction, (void*)threadData);
    if (0 != err)
    {        
        free(threadData);
        status = (EPERM == err) ? PAL_ERR_RTOS_PRIORITY : PAL_ERR_RTOS_RESOURCE;
        goto finish;
    }

    *threadID = (palThreadID_t)sysThreadID;
    status = PAL_SUCCESS;

finish:
    if (NULL != ptrAttr)
    {
        err = pthread_attr_destroy(ptrAttr);
        if (0 != err)
        {
            PAL_LOG_ERR("pal_plat_osThreadCreate failed to destroy pthread_attr_t\n");
        }
    }
    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    palThreadID_t threadID = (palThreadID_t)pthread_self();
    return threadID;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t* threadID)
{
    palStatus_t status = PAL_ERR_RTOS_TASK;
    int err;
    pthread_t sysThreadID = (pthread_t)*threadID;
    if (!pthread_equal(pthread_self(), sysThreadID)) // self termination not allowed
    {
        err = pthread_cancel(sysThreadID);
        if ((0 == err) || (ESRCH == err))
        {
            status = PAL_SUCCESS;
        }
        else
        {
            status = PAL_ERR_RTOS_RESOURCE;
        }
    }
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
    struct timespec sTime;
    struct timespec rTime; // this will return how much sleep time still left in case of interrupted sleep
    int stat;
    //init rTime, as we will copy it over to stime inside the do-while loop.
    rTime.tv_sec = milliseconds / 1000;
    rTime.tv_nsec = PAL_MILLI_TO_NANO(milliseconds);

    do
    {
        sTime.tv_sec = rTime.tv_sec;
        sTime.tv_nsec = rTime.tv_nsec;
        stat = nanosleep(&sTime, &rTime);
    } while ((-1 == stat) && (EINTR ==errno)) ;
    return (stat == 0) ? PAL_SUCCESS : PAL_ERR_GENERIC_FAILURE;
}


/*
* Internal struct to handle timers.
*/

typedef struct palTimerThreadContext
{
    // semaphore used for signaling both the thread startup and thread closure
    palSemaphoreID_t startStopSemaphore;

    // If set, the timer thread will stop its loop, signal the startStopSemaphore
    // and run out of thread function. This is set and accessed while holding the
    // g_timerListMutex.
    volatile bool threadStopRequested;

} palTimerThreadContext_t;


static palThreadID_t s_palHighResTimerThreadID = NULLPTR;
static palTimerThreadContext_t s_palTimerThreadContext = {0};

/*
* Thread for handling the signals from all timers by calling the attached callback
*/

PAL_PRIVATE void palTimerThread(void const *args)
{
    palTimerThreadContext_t* context = (palTimerThreadContext_t*)args;

    int err = 0;

    sigset_t signal_set_to_wait;

    sigemptyset(&signal_set_to_wait);
    sigaddset(&signal_set_to_wait, PAL_TIMER_SIGNAL);

    // signal the caller that thread has started
    if (pal_osSemaphoreRelease(context->startStopSemaphore) != PAL_SUCCESS) {
        PAL_LOG_ERR("pal_osSemaphoreRelease(context->startStopSemaphore) failed!");
    }

    // loop until signaled with threadStopRequested
    while (1) {

        siginfo_t info;

        // wait for signal from a timer
        err = sigwaitinfo(&signal_set_to_wait, &info);

        // A positive return value is the signal number, negative value is a sign of some
        // signal handler interrupting the OS call and errno should be then EINTR.
        // The other two documented errors, EAGAIN or EINVAL should not happen as we're
        // not using the timeout, but have them logged just in case.
        if (err <= 0) {
            if (errno != EINTR) {
                PAL_LOG_ERR("palTimerThread: sigwaitinfo failed with %d\n", errno);
            }
        } else {

            // before using the timer list or threadStopRequested flag, we need to claim the mutex
            pal_osMutexWait(g_timerListMutex, PAL_RTOS_WAIT_FOREVER);

            if (context->threadStopRequested) {

                // release mutex and bail out
                // Coverity fix - Unchecked return value. Function pal_osMutexRelease already contains error trace.
                (void)pal_osMutexRelease(g_timerListMutex);
                break;

            } else {

                // the sival_ptr contains the pointer of timer which caused it
                struct palTimerInfo* signal_timer = (struct palTimerInfo*)info.si_value.sival_ptr;

                struct palTimerInfo *temp_timer = (struct palTimerInfo*)g_timerList;

                palTimerFuncPtr found_function = NULL;
                void *found_funcArgs;

                // Check, if the timer still is on the list. It may have been deleted, if the
                // signal delivery / client callback has taken some time.
                while (temp_timer != NULL) {

                    if (temp_timer == signal_timer) {

                        // Ok, found the timer from list, backup the parameters as we release
                        // the mutex after this loop, before calling the callback and the
                        // temp_timer may very well get deleted just after the mutex is released.

                        found_function = temp_timer->function;
                        found_funcArgs = temp_timer->funcArgs;

                        break;
                    } else {
                        temp_timer = temp_timer->next;
                    }
                }

                // Release the list mutex before callback to avoid callback deadlocking other threads
                // if they try to create a timer.
                // Coverity fix - 243862 Unchecked return value
                (void)pal_osMutexRelease(g_timerListMutex);

                // the function may be NULL here if the timer was already freed
                if (found_function) {
                    // finally call the callback function
                    found_function(found_funcArgs);
                }
            }
        }
    }

    // signal the caller that thread is now stopping and it can continue the pal_destroy()
    // Coverity fix - 243860 Unchecked return value. There is not much doable if fail.
    (void)pal_osSemaphoreRelease(context->startStopSemaphore);
}

PAL_PRIVATE palStatus_t startTimerThread()
{
    palStatus_t status;

    status = pal_osSemaphoreCreate(0, &s_palTimerThreadContext.startStopSemaphore);

    if (status == PAL_SUCCESS) {

        s_palTimerThreadContext.threadStopRequested = false;

        status = pal_osThreadCreateWithAlloc(palTimerThread, &s_palTimerThreadContext, PAL_osPriorityReservedHighResTimer,
                                                PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE, NULL, &s_palHighResTimerThreadID);

        if (status == PAL_SUCCESS) {

            // the timer thread will signal on semaphore when it has started
            pal_osSemaphoreWait(s_palTimerThreadContext.startStopSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);

        } else {
            // cleanup the semaphore
            pal_osSemaphoreDelete(&s_palTimerThreadContext.startStopSemaphore);
        }
    }

    return status;
}

PAL_PRIVATE palStatus_t stopTimerThread()
{
    palStatus_t status;

    status = pal_osMutexWait(g_timerListMutex, PAL_RTOS_WAIT_FOREVER);

    if (status == PAL_SUCCESS) {

        // set the flag to end the thread
        s_palTimerThreadContext.threadStopRequested = true;

        // ping the timer thread that it should start shutdown
        pthread_t sysThreadID = (pthread_t)s_palHighResTimerThreadID;
        int err;

        do {

            // Send the signal to wake up helper thread. A cleaner way would
            // use pthread_sigqueue() as it allows sending the sival, but that
            // does not really matter as the threadStopRequested flag is
            // always checked before accessing the sival. pthread_sigqueue() is also
            // missing from eg. musl library.
            err = pthread_kill(sysThreadID, PAL_TIMER_SIGNAL);

        } while (err == EAGAIN); // retry (spin, yuck!) if the signal queue is full

        // Coverity fix - 243859 Unchecked return value. There is not much doable if fail. StopTimerThread is part of shutdown step.
        (void)pal_osMutexRelease(g_timerListMutex);

        // pthread_sigqueue() failed, which is a sign of thread being dead, so a wait
        // on semaphore would cause a deadlock.
        if (err == 0) {

            // wait for for acknowledgement that timer thread is going down
            pal_osSemaphoreWait(s_palTimerThreadContext.startStopSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);
        }

        pal_osSemaphoreDelete(&s_palTimerThreadContext.startStopSemaphore);

        // and clean up the thread
        status = pal_osThreadTerminate(&s_palHighResTimerThreadID);
    }
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
    struct palTimerInfo* timerInfo = NULL;
    {
        struct sigevent sig;
        timer_t localTimer;

        if ((NULL == timerID) || (NULL == (void*) function))
        {
            return PAL_ERR_INVALID_ARGUMENT;
        }

        timerInfo = (struct palTimerInfo*) malloc(sizeof(struct palTimerInfo));
        if (NULL == timerInfo)
        {
            status = PAL_ERR_NO_MEMORY;
            goto finish;
        }

        timerInfo->function = function;
        timerInfo->funcArgs = funcArgument;
        timerInfo->timerType = timerType;

        memset(&sig, 0, sizeof(sig));

        sig.sigev_notify = SIGEV_SIGNAL;
        sig.sigev_signo = PAL_TIMER_SIGNAL;

        // the signal handler uses this to find the correct timer context
        sig.sigev_value.sival_ptr = timerInfo;

        int ret = timer_create(CLOCK_MONOTONIC, &sig, &localTimer);
        if (-1 == ret)
        {
            if (EINVAL == errno)
            {
                status = PAL_ERR_INVALID_ARGUMENT;
                goto finish;
            }
            if (ENOMEM == errno)
            {
                status = PAL_ERR_NO_MEMORY;
                goto finish;
            }
            PAL_LOG_ERR("Rtos timer create error %d", ret);
            status = PAL_ERR_GENERIC_FAILURE;
            goto finish;
        }

        // managed to create the timer - finish up
        timerInfo->handle = localTimer;
        *timerID = (palTimerID_t) timerInfo;

        pal_osMutexWait(g_timerListMutex, PAL_RTOS_WAIT_FOREVER);

        // add the new timer to head of the singly linked list
        timerInfo->next = (struct palTimerInfo *)g_timerList;

        g_timerList = timerInfo;

        // 243861 Unchecked return value
        (void)pal_osMutexRelease(g_timerListMutex);
    }
    finish: if (PAL_SUCCESS != status)
    {
        if (NULL != timerInfo)
        {
            free(timerInfo);
            *timerID = (palTimerID_t) NULL;
        }
    }
    return status;
}

/* Convert milliseconds into seconds and nanoseconds inside a timespec struct
 */
PAL_PRIVATE void convertMilli2Timespec(uint32_t millisec, struct timespec* ts)
{
    ts->tv_sec = millisec / 1000;
    ts->tv_nsec = PAL_MILLI_TO_NANO(millisec);
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
    if (NULL == (struct palTimerInfo *) timerID)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct palTimerInfo* timerInfo = (struct palTimerInfo *) timerID;
    struct itimerspec its;

    convertMilli2Timespec(millisec, &(its.it_value));

    if (palOsTimerPeriodic == timerInfo->timerType)
    {
        convertMilli2Timespec(millisec, &(its.it_interval));
    }
    else
    {  // one time timer
        convertMilli2Timespec(0, &(its.it_interval));
    }

    if (-1 == timer_settime(timerInfo->handle, 0, &its, NULL))
    {
        status = PAL_ERR_INVALID_ARGUMENT;
    }

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
    if (NULL == (struct palTimerInfo *) timerID)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct palTimerInfo* timerInfo = (struct palTimerInfo *) timerID;
    struct itimerspec its;

    // set timer to 0 to disarm it.
    convertMilli2Timespec(0, &(its.it_value));

    convertMilli2Timespec(0, &(its.it_interval));

    if (-1 == timer_settime(timerInfo->handle, 0, &its, NULL))
    {
        status = PAL_ERR_INVALID_ARGUMENT;
    }

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
    if ((NULL == timerID) || ((struct palTimerInfo *)*timerID == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    struct palTimerInfo* timerInfo = (struct palTimerInfo *) *timerID;

    // the list of timers is protected by a mutex to avoid concurrency issues
    pal_osMutexWait(g_timerListMutex, PAL_RTOS_WAIT_FOREVER);

    // remove the timer from the list before freeing it
    struct palTimerInfo *prev_timer = NULL;
    struct palTimerInfo *temp_timer = (struct palTimerInfo *)g_timerList;

    while (temp_timer) {

        if (temp_timer == timerInfo) {
            // found the timer from list, now it needs to be removed from there

            if (prev_timer) {
                // there was a previous item, so update its next to this objects next
                prev_timer->next = temp_timer->next;
            } else {
                // the item was the first/only one, so update the list head instead
                g_timerList = temp_timer->next;
            }
            // all done now
            break;

        } else {
            prev_timer = temp_timer;
            temp_timer = temp_timer->next;
        }
    }

    timer_t lt = timerInfo->handle;
    if (-1 == timer_delete(lt)) {
        status = PAL_ERR_RTOS_RESOURCE;
    }

    // 243863 Unchecked return value
    (void)pal_osMutexRelease(g_timerListMutex);

    free(timerInfo);
    *timerID = (palTimerID_t) NULL;

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
    pthread_mutex_t* mutex = NULL;
    {
        int ret;
        if (NULL == mutexID)
        {
            return PAL_ERR_INVALID_ARGUMENT;
        }

        mutex = malloc(sizeof(pthread_mutex_t));
        if (NULL == mutex)
        {
            status = PAL_ERR_NO_MEMORY;
            goto finish;
        }

        pthread_mutexattr_t mutexAttr;
        pthread_mutexattr_init(&mutexAttr);
        pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
        ret = pthread_mutex_init(mutex, &mutexAttr);

        if (0 != ret)
        {
            if (ENOMEM == ret)
            {
                status = PAL_ERR_NO_MEMORY;
            }
            else
            {
                PAL_LOG_ERR("Rtos mutex create status %d", ret);
                status = PAL_ERR_GENERIC_FAILURE;
            }
            goto finish;
        }
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
    int err;
    if (NULL == ((pthread_mutex_t*) mutexID))
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    pthread_mutex_t* mutex = (pthread_mutex_t*) mutexID;

    if (PAL_RTOS_WAIT_FOREVER != millisec)
    {
        /* calculate the wait absolute time */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        ts.tv_sec += (millisec / PAL_MILLI_PER_SECOND);
        ts.tv_nsec += PAL_MILLI_TO_NANO(millisec);
        ts.tv_sec += ts.tv_nsec / PAL_NANO_PER_SECOND; // if there is some overflow in the addition of nanoseconds.
        ts.tv_nsec = ts.tv_nsec % PAL_NANO_PER_SECOND;

        while ((err = pthread_mutex_timedlock(mutex, &ts)) != 0 && err == EINTR)
        {
            continue; /* Restart if interrupted by handler */
        }
    }
    else
    { // wait for ever
        err = pthread_mutex_lock(mutex);
    }

    if (0 != err)
    {
        if (err == ETIMEDOUT)
        {
            status = PAL_ERR_RTOS_TIMEOUT;
        }
        else
        {
            PAL_LOG_ERR("Rtos mutex wait status %d", err);
            status = PAL_ERR_GENERIC_FAILURE;
        }
    }

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
    int result = 0;

    pthread_mutex_t* mutex = (pthread_mutex_t*) mutexID;
    if (NULL == mutex)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    result = pthread_mutex_unlock(mutex);
    if (0 != result)
    {
        // only reason this might fail - process don't have permission for mutex.
        PAL_LOG_ERR("Rtos mutex release failure - %d",result);
        status = PAL_ERR_GENERIC_FAILURE;
    }
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
    uint32_t ret;
    if (NULL == mutexID) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    pthread_mutex_t* mutex = (pthread_mutex_t*) *mutexID;

    if (NULL == mutex) {
        status = PAL_ERR_RTOS_RESOURCE;
    }
    else {
        ret = pthread_mutex_destroy(mutex);
        if ((PAL_SUCCESS == status) && (0 != ret))
        {
        PAL_LOG_ERR("pal_plat_osMutexDelete 0x%x",ret);
            status = PAL_ERR_RTOS_RESOURCE;
        }
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
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += millisec / PAL_MILLI_PER_SECOND;
            ts.tv_nsec += PAL_MILLI_TO_NANO(millisec);
            ts.tv_sec += ts.tv_nsec / PAL_NANO_PER_SECOND; // in case there is overflow in the nanoseconds.
            ts.tv_nsec = ts.tv_nsec % PAL_NANO_PER_SECOND;

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
    int32_t res = __sync_add_and_fetch(valuePtr, increment);
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
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <time.h>
palMutexID_t rtcMutex = NULLPTR;

#if RTC_PRIVILEGE
static const char default_rtc[] = "/dev/rtc0";

PAL_PRIVATE  uint64_t pal_convertTimeStructToSeconds(const struct rtc_time *dateTime)
{
    /* Number of days from begin of the non Leap-year*/
    uint64_t monthDays[] = {0, 31U, 59U, 90U, 120U, 151U, 181U, 212U, 243U, 273U, 304U, 334U};
    uint64_t seconds, daysCount = 0;
    /* Compute number of days from 1970 till given year*/
    daysCount = (dateTime->tm_year + 1900 - 1970) * PAL_DAYS_IN_A_YEAR;
    /* Add leap year days */
    daysCount += (((dateTime->tm_year + 1900) / 4) - (1970U / 4));
    /* Add number of days till given month*/
    daysCount += monthDays[dateTime->tm_mon];
    /* Add days in given month minus one */
    daysCount += (dateTime->tm_mday - 1);
    if (!(((dateTime->tm_year + 1900) & 3U)) && (dateTime->tm_mon <= 2U))
    {
    	daysCount--;
    }

    seconds = (daysCount * PAL_SECONDS_PER_DAY) + (dateTime->tm_hour * PAL_SECONDS_PER_HOUR) +
              (dateTime->tm_min * PAL_SECONDS_PER_MIN) + dateTime->tm_sec;

    return seconds;
}
#endif

palStatus_t pal_plat_osGetRtcTime(uint64_t *rtcGetTime)
{
	palStatus_t ret = PAL_SUCCESS;
#if RTC_PRIVILEGE
    struct rtc_time GetTime ={0};
    if(rtcGetTime != NULL)
    {
        int fd, retval = 0;
        fd = open(default_rtc, O_RDONLY);
        if (fd == -1)
        {
            ret = PAL_ERR_RTOS_RTC_OPEN_DEVICE_ERROR;
        }
        else
        {
            retval = ioctl(fd, RTC_RD_TIME , &GetTime);
            if (retval == -1)
            {
                ret = PAL_ERR_RTOS_RTC_OPEN_IOCTL_ERROR;
            }
            else
            {
                *rtcGetTime = pal_convertTimeStructToSeconds(&GetTime);
            }
            close(fd);
        }
    }
    else
    {
        ret = PAL_ERR_NULL_POINTER;
    }
#else
    *rtcGetTime = time(NULL);
#endif
    return ret;
}

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
	palStatus_t ret = 0;
	int retval = 0;
#if RTC_PRIVILEGE
    int fd = 0;
    int retval = 0;
    struct tm * convertedTime = gmtime((time_t*)&rtcSetTime);

    fd = open (default_rtc, O_RDONLY);
    retval = ioctl(fd, RTC_SET_TIME, (struct rtc_time*)convertedTime);
    if (retval == -1)
    {
        ret = PAL_ERR_RTOS_RTC_OPEN_IOCTL_ERROR;
    }
    close(fd);
#else
    ret = pal_osMutexWait(rtcMutex, 5 * PAL_MILLI_PER_SECOND * PAL_ONE_SEC);
    if(ret == PAL_SUCCESS)
    {
        retval = stime((time_t*)&rtcSetTime);
        if (retval == -1)
        {
            ret = PAL_ERR_RTOS_NO_PRIVILEGED; //need to give privilege mode "sudo setcap -v cap_sys_time=+epi [filename]"
        }
        pal_osMutexRelease(rtcMutex);
    }
#endif
    return ret;
}

palStatus_t pal_plat_rtcInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    if(NULLPTR == rtcMutex)
    {
        ret = pal_osMutexCreate(&rtcMutex);
    }
    return ret;
}

palStatus_t pal_plat_rtcDeInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    if(NULLPTR != rtcMutex)
    {
        ret = pal_osMutexDelete(&rtcMutex);
        rtcMutex = NULLPTR;
    }
    return ret;
}

#endif //#if (PAL_USE_HW_RTC)

