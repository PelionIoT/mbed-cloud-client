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

#include <exec/types.h>
#include <exec/memory.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>
 
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/battclock.h>
#include <resources/battclock.h>
#include <clib/timer_protos.h>

#include "semaphore.h"

#include "pal.h"
#include "pal_plat_rtos.h"

#define TRACE_GROUP "PAL"

extern palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes);

/*
 * Internal struct to handle timers.
 */
struct palTimerInfo
{
    struct palTimerInfo *next;
    struct timerequest *TimerIO;
    palTimerFuncPtr function;
    void *funcArgs;
    palTimerType_t timerType;
    bool aborted;
};

// Message port via timers signal their completion
PAL_PRIVATE struct MsgPort * g_timerMsgPort = 0;

// Mutex to prevent simultaneus modification of the linked list of the timers in g_timerList.
PAL_PRIVATE palMutexID_t g_timerListMutex = 0;

// A singly linked list of the timers, access may be done only if holding the g_timerListMutex.
// The list is needed as the timers use async signals and when the signal is finally delivered, the
// palTimerInfo timer struct may be already deleted. The signals themselves carry pointer to timer,
// so whenever a signal is received, the thread will look if the palTimerInfo is still on the list,
// and if it is, uses the struct to find the callback pointer and arguments.
PAL_PRIVATE volatile struct palTimerInfo *g_timerList = NULL;

PAL_PRIVATE struct timerequest *g_TimerIO = NULL;
struct Library *TimerBase = NULL;
PAL_PRIVATE unsigned long g_tickFreq = 0;

typedef struct palThreadData
{
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;
    struct Process *thread;
    char threadID;
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

PAL_PRIVATE palStatus_t startTimerThread();
PAL_PRIVATE palStatus_t stopTimerThread();
PAL_PRIVATE void palTimerThread(void const *args);

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
    struct EClockVal tmp; 
    (void)opaqueContext;        

    status = pal_osMutexCreate(&g_threadsMutex);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }

    // Setup the signal handler thread which will be shared with all the timers
    status = pal_osMutexCreate(&g_timerListMutex);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    
    {
        g_TimerIO  = (struct timerequest *)malloc(sizeof(struct timerequest ));
        if(NULL == g_TimerIO)
        {
            status = PAL_ERR_NO_MEMORY;
            goto end;
        }

        if (OpenDevice(TIMERNAME,UNIT_ECLOCK,
                    (struct IORequest *)g_TimerIO,0L))
        {
            free(g_TimerIO);
            status = PAL_ERR_CREATION_FAILED;
            goto end;
        }
        
        TimerBase = (struct Library *)g_TimerIO->tr_node.io_Device;

        unsigned long eClockFreq = ReadEClock(&tmp);
        // Roundup the frequency to minimize error
        g_tickFreq = (unsigned long)(((float)eClockFreq / 1000.0)+0.5);
    }
    
    #if (PAL_USE_HW_RTC)
    status = pal_plat_rtcInit();
    #endif

    if (status == PAL_SUCCESS) {

        status = startTimerThread();
    }
end:
    if(PAL_SUCCESS != status)
    {
        //TODO free those resources that got created
    }
    return status;
}

/*! De-Initialize thread objects.
 */
palStatus_t pal_plat_RTOSDestroy(void)
{

    stopTimerThread();

    if (NULLPTR != g_threadsMutex)
    {
        pal_osMutexDelete(&g_threadsMutex);
        g_threadsMutex = NULLPTR;
    }

    if (NULLPTR != g_timerListMutex) {
        pal_osMutexDelete(&g_timerListMutex);
    }

    if(NULL != g_TimerIO)
    {
        CloseDevice( (struct IORequest *) g_TimerIO );
        free(g_TimerIO);
    }

    #if PAL_USE_HW_RTC
    pal_plat_rtcDeInit();
    #endif

    return PAL_SUCCESS;
}

/*return The RTOS kernel system timer counter, in microseconds
 */

uint64_t pal_plat_osKernelSysTick(void) // optional API - not part of original CMSIS API.
{   
    struct EClockVal ticks_now;
    ReadEClock(&ticks_now);

    return ((uint64_t)ticks_now.ev_hi << 32) + ((uint64_t)ticks_now.ev_lo);
}

/* Convert the value from microseconds to kernel sys ticks.
 * This is the same as CMSIS macro osKernelSysTickMicroSec.
 * since we return microsecods as ticks, just return the value
 */
uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{    
    uint64_t ticksIn = (microseconds * g_tickFreq) / 1000;
    return ticksIn;
}

/*! Get the system tick frequency.
 * \return The system tick frequency.
 */
inline uint64_t pal_plat_osKernelSysTickFrequency(void)
{    
    return g_tickFreq * 1000;
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
                (*threadData)->threadID = i;
            }
            break;
        }
    }
    return threadData;
}

PAL_PRIVATE void threadFree(palThreadData_t** threadData)
{
    //printf("threadFree\n");
    (*threadData)->userFunction = NULL;
    (*threadData)->userFunctionArgument = NULL;
    (*threadData)->thread = NULL;
    (*threadData)->threadID = -1;
    free(*threadData);
    *threadData = NULL;
}

PAL_PRIVATE int32_t threadFunction(void)
{
    palStatus_t status = PAL_SUCCESS;
    palThreadData_t** threadData = NULL;
    palThreadFuncPtr userFunction;
    void* userFunctionArgument;

    struct Process *thisProcess = (struct Process *)FindTask(NULL);
    if(NULL == thisProcess || NULL == thisProcess->pr_Task.tc_Node.ln_Name)
    {
        goto end;
    }
    
    char thisThreadID = atoi(thisProcess->pr_Task.tc_Node.ln_Name);
    //printf("Thread id: %d\n", thisThreadID);    
    if(-1 == thisThreadID )
    {
        goto end;
    }    
     
    //This feels a bit stupid, but lets keep it like this until other issues get rooted out
    for (int i = 0; i < PAL_MAX_CONCURRENT_THREADS; i++)
    {                    
        if (g_threadsArray[i] && g_threadsArray[i]->threadID == thisThreadID)
        {                     
            threadData = &g_threadsArray[i];
            break;            
        }        
    }

    if(NULL == threadData)
    {
        //printf("does not compute\n");
        goto end;
    }

    //threadData = (palThreadData_t**)g_threadsArray[(unsigned char)thisThreadID];
    //printf("got id: %d\n", (*threadData)->threadID);
    userFunction = (*threadData)->userFunction;
    userFunctionArgument = (*threadData)->userFunctionArgument;
    if (NULL == (*threadData)->thread) // maybe null if this thread has a higher priority than the thread which created this thread
    {   
        PAL_THREADS_MUTEX_LOCK(status);
        if (PAL_SUCCESS != status)
        {
            goto end;
        }
        (*threadData)->thread = thisProcess; // set the thread id
        PAL_THREADS_MUTEX_UNLOCK(status);
        if (PAL_SUCCESS != status)
        {
            goto end;
        }
    }        
    
    if(NULL != userFunction) {
        //printf("calling userfunction\n");
        userFunction(userFunctionArgument); // invoke user function with user argument (use local vars) - note we're not under mutex lock anymore
    }

    
    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    //printf("free thread\n");
    threadFree(threadData); // clean up
    PAL_THREADS_MUTEX_UNLOCK(status)
end:    
    return 0;
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t* threadID)
{
    palStatus_t status = PAL_SUCCESS;
    palThreadData_t** threadData;
    struct Process * sysThreadID = NULLPTR;    
    char childprocessname[5];
    BPTR output;    

    /* Open the console for the child process. */
    if (output = Open("CONSOLE:", MODE_OLDFILE));

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
    sprintf(childprocessname, "%d", (*threadData)->threadID);

    sysThreadID = CreateNewProcTags(
                    NP_Entry,       threadFunction,  /* The child process  */
                    NP_Name,        childprocessname,
                    NP_Output,      output,
                    NP_StackSize,   stackSize,
                    NP_Priority,    priority,
                    NP_FreeSeglist, FALSE,
                    NP_CloseOutput, TRUE,                    
                    TAG_END);  

    PAL_THREADS_MUTEX_LOCK(status);
    if (PAL_SUCCESS != status)
    {
        goto end;
    }
    if (NULL != sysThreadID)
    { 
        //printf("Thread creation great success!\n");
        
        if ((NULL != *threadData) && (NULL == (*threadData)->thread)) // *threadData maybe null in case the thread has already finished and cleaned up, sysThreadID maybe null if the created thread is lower priority than the creating thread
        {
            (*threadData)->thread = sysThreadID; // set the thread id
        }
        *threadID = (palThreadID_t)sysThreadID;
    }   
    else
    {
        //printf("Thread creation failed!\n");
        threadFree(threadData); // thread creation failed so clean up dynamic allocations etc.
        status = PAL_ERR_GENERIC_FAILURE;
    }
    PAL_THREADS_MUTEX_UNLOCK(status);
end:
    return status;
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    struct Process *thisProcess = (struct Process *)FindTask(NULL);
    return (palThreadID_t)thisProcess;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t* threadID)
{
    palStatus_t status = PAL_ERR_RTOS_TASK;
    struct Process *sysThreadID = (struct Process *)*threadID;    
    palThreadData_t** threadData = NULL;

    char thisThreadID = atoi(sysThreadID->pr_Task.tc_Node.ln_Name);
    //printf("terminate Thread id: %d\n", thisThreadID);    

    if ((struct Process *)FindTask(NULL) != sysThreadID) // self termination not allowed
    {
        PAL_THREADS_MUTEX_LOCK(status);
        if (PAL_SUCCESS != status)
        {
            goto end;
        }
        
        for (int i = 0; i < PAL_MAX_CONCURRENT_THREADS; i++)
        {
            if (g_threadsArray[i] && g_threadsArray[i]->threadID == thisThreadID)
            {         
                threadData = &g_threadsArray[i];
                break;
            }
        }

        if (threadData) // thread may have ended or terminated already
        {         
            //TODO
            //there might be a way to stop / terminate process in AmigaOS, need some digging to do
            //fow now, lets just free this data structure
            threadFree(threadData);
        }
        PAL_THREADS_MUTEX_UNLOCK(status);        
    }
end:
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
    #if 1
    uint32_t millisecondsInTick = (1000/CLOCKS_PER_SEC);
    uint32_t ticks = (milliseconds + (millisecondsInTick / 2)) / millisecondsInTick;
    if(ticks == 0) {
        Delay(1);
    } else {
        Delay(ticks);
    }
    #else
    // usleep is implemented in clib2 and it (most likely) uses UNIT_VBLANK
    // -> the same accuracy as the previous implementation (50Hz).
    // probably not too difficult to change to use ECLOCK in CLIB2
    usleep(1000*milliseconds);
    #endif
    return PAL_SUCCESS;
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

    //printf("in palTimerThread\n");

    //Create message port for timers
    g_timerMsgPort = CreateMsgPort();

    if(NULL != g_timerMsgPort)
    {
        
    
        //int err = 0;

        //sigset_t signal_set_to_wait;

        //sigemptyset(&signal_set_to_wait);
        //sigaddset(&signal_set_to_wait, PAL_TIMER_SIGNAL);    

        // signal the caller that thread has started
        if (pal_osSemaphoreRelease(context->startStopSemaphore) != PAL_SUCCESS) {
            PAL_LOG_ERR("pal_osSemaphoreRelease(context->startStopSemaphore) failed!");
        }

        // loop until signaled with threadStopRequested
        while (1) {

            //siginfo_t info;

            // wait for signal from a timer        
            //err = sigwaitinfo(&signal_set_to_wait, &info);

            //printf("waitPort\n");

            WaitPort(g_timerMsgPort);
            //Wait(SIGBREAKF_CTRL_F);
            //uint32_t signals = Wait(0xffffffff);
            //printf("got signals: %u\n", signals);

            struct Message *TimerMSG =  (struct Message *)GetMsg(g_timerMsgPort);
            if(NULL != TimerMSG)
            {

                //printf("gotMsg\n");

            // A positive return value is the signal number, negative value is a sign of some
            // signal handler interrupting the OS call and errno should be then EINTR.
            // The other two documented errors, EAGAIN or EINVAL should not happen as we're
            // not using the timeout, but have them logged just in case.
            // if (err <= 0) {
            //     if (errno != EINTR) {
            //         PAL_LOG_ERR("palTimerThread: sigwaitinfo failed with %d\n", errno);
            //     }
            // } else         
                // before using the timer list or threadStopRequested flag, we need to claim the mutex
                pal_osMutexWait(g_timerListMutex, PAL_RTOS_WAIT_FOREVER);

                if (context->threadStopRequested) {

                    // release mutex and bail out
                    // Coverity fix - Unchecked return value. Function pal_osMutexRelease already contains error trace.
                    (void)pal_osMutexRelease(g_timerListMutex);
                    break;

                } else {

                    struct palTimerInfo *temp_timer = (struct palTimerInfo*)g_timerList;

                    palTimerFuncPtr found_function = NULL;
                    void *found_funcArgs;

                    // Check, if the timer still is on the list. It may have been deleted, if the
                    // signal delivery / client callback has taken some time.
                    while (temp_timer != NULL) {

                        if ((struct Message *)temp_timer->TimerIO == TimerMSG) {

                            // Ok, found the timer from list, backup the parameters as we release
                            // the mutex after this loop, before calling the callback and the
                            // temp_timer may very well get deleted just after the mutex is released.
                            if(!temp_timer->aborted)
                            {
                                found_function = temp_timer->function;
                                found_funcArgs = temp_timer->funcArgs;
                            }

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
                        // if periodic, re-schedule
                        if(palOsTimerPeriodic == temp_timer->timerType)
                        {
                            SendIO((struct IORequest *)temp_timer->TimerIO);
                        }
                    }
                }
            }
        }
        DeleteMsgPort(g_timerMsgPort);
    }

    // signal the caller that thread is now stopping and it can continue the pal_destroy()
    // Coverity fix - 243860 Unchecked return value. There is not much doable if fail.
    (void)pal_osSemaphoreRelease(context->startStopSemaphore);
}

PAL_PRIVATE palStatus_t startTimerThread()
{
    palStatus_t status;
    //printf("startTimerThread\n");
    status = pal_osSemaphoreCreate(0, &s_palTimerThreadContext.startStopSemaphore);

    if (status == PAL_SUCCESS) {

        s_palTimerThreadContext.threadStopRequested = false;

        status = pal_osThreadCreateWithAlloc(palTimerThread, &s_palTimerThreadContext, PAL_osPriorityReservedHighResTimer,
                                                PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE, NULL, &s_palHighResTimerThreadID);

        if (status == PAL_SUCCESS) {

            // the timer thread will signal on semaphore when it has started
            pal_osSemaphoreWait(s_palTimerThreadContext.startStopSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);
            //printf("start OK\n");

        } else {
            // cleanup the semaphore
            pal_osSemaphoreDelete(&s_palTimerThreadContext.startStopSemaphore);
            //printf("start fail\n");
        }
    }

    return status;
}

PAL_PRIVATE palStatus_t stopTimerThread()
{
    palStatus_t status;
    struct Message wakeupMsg;

    //printf("stopTimerThread\n");
    status = pal_osMutexWait(g_timerListMutex, PAL_RTOS_WAIT_FOREVER);
    //printf("got mutex\n");

    if (status == PAL_SUCCESS) {

        // set the flag to end the thread
        s_palTimerThreadContext.threadStopRequested = true;

        // send message to global message port to wake the thread
        // for some reason this fails to wakeup the thread, so we send the message AND signal
        PutMsg(g_timerMsgPort, &wakeupMsg);

        //Signal((struct Task *)s_palHighResTimerThreadID, SIGBREAKF_CTRL_F);

        // ping the timer thread that it should start shutdown
        // pthread_t sysThreadID = (pthread_t)s_palHighResTimerThreadID;
        // int err;

        // do {

        //     // Send the signal to wake up helper thread. A cleaner way would
        //     // use pthread_sigqueue() as it allows sending the sival, but that
        //     // does not really matter as the threadStopRequested flag is
        //     // always checked before accessing the sival. pthread_sigqueue() is also
        //     // missing from eg. musl library.
        //     err = pthread_kill(sysThreadID, PAL_TIMER_SIGNAL);

        // } while (err == EAGAIN); // retry (spin, yuck!) if the signal queue is full

        // Coverity fix - 243859 Unchecked return value. There is not much doable if fail. StopTimerThread is part of shutdown step.
        (void)pal_osMutexRelease(g_timerListMutex);

        //printf("yield mutex\n");

        // pthread_sigqueue() failed, which is a sign of thread being dead, so a wait
        // on semaphore would cause a deadlock.
        //if (err == 0) 
        {

            // wait for for acknowledgement that timer thread is going down
            pal_osSemaphoreWait(s_palTimerThreadContext.startStopSemaphore, PAL_RTOS_WAIT_FOREVER, NULL);
        }

        pal_osSemaphoreDelete(&s_palTimerThreadContext.startStopSemaphore);

        // and clean up the thread
        status = pal_osThreadTerminate(&s_palHighResTimerThreadID);
        //printf("stop OK\n");        
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
        //struct sigevent sig;
        //timer_t localTimer;        

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

        //Allocate timer structure
        //timerInfo->TimerIO = malloc(sizeof(struct timerequest));
        timerInfo->TimerIO = (struct timerequest*)CreateIORequest(g_timerMsgPort, sizeof(struct timerequest));
        //printf("sigbit: %u\n", 1 << g_timerMsgPort->mp_SigBit);

        if (NULL == timerInfo->TimerIO)
        {
            status = PAL_ERR_NO_MEMORY;
        }

        //Allocate message port for timer
        //(timerInfo->TimerIO)->tr_node.io_Message.mn_ReplyPort = g_timerMsgPort;        

        timerInfo->function = function;
        timerInfo->funcArgs = funcArgument;
        timerInfo->timerType = timerType;
        timerInfo->aborted = false;    


        // memset(&sig, 0, sizeof(sig));

        // sig.sigev_notify = SIGEV_SIGNAL;
        // sig.sigev_signo = PAL_TIMER_SIGNAL;

        // // the signal handler uses this to find the correct timer context
        // sig.sigev_value.sival_ptr = timerInfo;

        if (OpenDevice( TIMERNAME, UNIT_VBLANK, (struct IORequest *) timerInfo->TimerIO, 0L))
		{
            status = PAL_ERR_NO_MEMORY;            
            goto finish;
        }    

        // int ret = timer_create(CLOCK_MONOTONIC, &sig, &localTimer);
        // if (-1 == ret)
        // {
        //     if (EINVAL == errno)
        //     {
        //         status = PAL_ERR_INVALID_ARGUMENT;
        //         goto finish;
        //     }
        //     if (ENOMEM == errno)
        //     {
        //         status = PAL_ERR_NO_MEMORY;
        //         goto finish;
        //     }
        //     PAL_LOG_ERR("Rtos timer create error %d", ret);
        //     status = PAL_ERR_GENERIC_FAILURE;
        //     goto finish;
        // }

        // managed to create the timer - finish up
        //timerInfo->handle = localTimer;
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
        // a retarded resource release decision tree
        if (NULL != timerInfo)
        {
            if(NULL != timerInfo->TimerIO)
            {                
                //free(timerInfo->TimerIO);
                DeleteIORequest(timerInfo->TimerIO);
            }
            free(timerInfo);
            *timerID = (palTimerID_t) NULL;
        }
    }

    return status;
}


/* Convert milliseconds into seconds and microseconds inside a timeval struct
 */
PAL_PRIVATE void convertMilli2Timeval(uint32_t millisec, struct timeval* ts)
{
    ts->tv_secs = millisec / 1000;
    ts->tv_micro = (millisec % PAL_MILLI_PER_SECOND) * 1000;
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

    timerInfo->TimerIO->tr_node.io_Command = TR_ADDREQUEST;
    convertMilli2Timeval(millisec, &(timerInfo->TimerIO->tr_time));    

    SendIO((struct IORequest *)timerInfo->TimerIO);
    //TODO if repeating, do SendIO in callback/wrapper/thread?
    
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
    timerInfo->aborted = true;
    AbortIO((struct IORequest *)timerInfo->TimerIO);    

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

    
    if(NULL != timerInfo->TimerIO)
    {        
        free(timerInfo->TimerIO);
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
    //int err;
    if (NULL == ((struct SignalSemaphore*) mutexID))
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    struct SignalSemaphore* mutex = (struct SignalSemaphore*) mutexID;

    if (PAL_RTOS_WAIT_FOREVER != millisec)
    {
        //TODO fix this

        // /* calculate the wait absolute time */
        // struct timespec ts;
        // clock_gettime(CLOCK_REALTIME, &ts);

        // ts.tv_sec += (millisec / PAL_MILLI_PER_SECOND);
        // ts.tv_nsec += PAL_MILLI_TO_NANO(millisec);
        // ts.tv_sec += ts.tv_nsec / PAL_NANO_PER_SECOND; // if there is some overflow in the addition of nanoseconds.
        // ts.tv_nsec = ts.tv_nsec % PAL_NANO_PER_SECOND;

        // while ((err = pthread_mutex_timedlock(mutex, &ts)) != 0 && err == EINTR)
        // {
        //     continue; /* Restart if interrupted by handler */
        // }
    }
    else
    { // wait for ever
        //err = pthread_mutex_lock(mutex);
        ObtainSemaphore(mutex);
    }

    // if (0 != err)
    // {
    //     if (err == ETIMEDOUT)
    //     {
    //         status = PAL_ERR_RTOS_TIMEOUT;
    //     }
    //     else
    //     {
    //         PAL_LOG_ERR("Rtos mutex wait status %d", err);
    //         status = PAL_ERR_GENERIC_FAILURE;
    //     }
    // }

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
    //int result = 0;

    struct SignalSemaphore* mutex = (struct SignalSemaphore*) mutexID;
    if (NULL == mutex)
    {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    ReleaseSemaphore(mutex);
    // result = pthread_mutex_unlock(mutex);
    // if (0 != result)
    // {
    //     // only reason this might fail - process don't have permission for mutex.
    //     PAL_LOG_ERR("Rtos mutex release failure - %d",result);
    //     status = PAL_ERR_GENERIC_FAILURE;
    // }
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
            /* accuracy is 20ms this way. However the libsem seems to implement only 1s accuracy. This can be improved upon */
            struct timespec ts;
            clock_t ticks = clock();
            ts.tv_sec  = (ticks / CLOCKS_PER_SEC) + (millisec / PAL_MILLI_PER_SECOND);
            ts.tv_nsec = PAL_MILLI_TO_NANO(((((ticks % CLOCKS_PER_SEC) * 1000) / CLOCKS_PER_SEC))  + millisec);
            // clock_gettime(CLOCK_REALTIME, &ts);
            // ts.tv_sec += millisec / PAL_MILLI_PER_SECOND;
            // ts.tv_nsec += PAL_MILLI_TO_NANO(millisec);
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
    struct Library * BattClockBase = OpenResource(BATTCLOCKNAME);
    *rtcGetTime = (uint64_t)ReadBattClock();

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
    struct Library * BattClockBase = OpenResource(BATTCLOCKNAME);
    WriteBattClock(rtcSetTime);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_rtcInit(void)
{       
    return PAL_SUCCESS;
}

palStatus_t pal_plat_rtcDeInit(void)
{      
    return PAL_SUCCESS;
}

#endif //#if (PAL_USE_HW_RTC)

