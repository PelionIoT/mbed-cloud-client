/* Copyright (c) 2021 Pelion
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
 */

#include <zephyr.h>
#include <zephyr/types.h>
#include <logging/log.h>
#include <power/reboot.h>
#include <posix/time.h>

#include "pal_plat_rtos.h"

#ifndef CONFIG_PELION_PAL_PLAT_RTOS_LOG_LEVEL
#define CONFIG_PELION_PAL_PLAT_RTOS_LOG_LEVEL 2 /* Warning */
#endif
LOG_MODULE_REGISTER(pal_plat_rtos, CONFIG_PELION_PAL_PLAT_RTOS_LOG_LEVEL);

typedef struct {
    bool available;
    struct k_thread thread;
} pal_thread_t;

static pal_thread_t pal_threads[PAL_THREADS_MAX_COUNT] = { 0 };
static K_THREAD_STACK_ARRAY_DEFINE(pal_stacks, PAL_THREADS_MAX_COUNT, PAL_STACKS_MAX_SIZE);

static k_timeout_t get_timeout(uint32_t timeout)
{
    if (timeout == PAL_RTOS_WAIT_FOREVER) {
        return K_FOREVER;
    }
    return K_MSEC(timeout);
}

void pal_plat_osReboot(void)
{
    sys_reboot(SYS_REBOOT_COLD);
}

palStatus_t pal_plat_RTOSInitialize(void *opaqueContext)
{
    /* initialize pre-allocated thread structure */
    for (size_t index = 0; index < PAL_THREADS_MAX_COUNT; index++) {
        pal_threads[index].available = true;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

uint64_t pal_plat_osKernelSysTick(void)
{
    return k_uptime_ticks();
}

uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{
    return k_us_to_ticks_ceil64(microseconds);
}

uint64_t pal_plat_osKernelSysTickFrequency(void)
{
    return CONFIG_SYS_CLOCK_TICKS_PER_SEC;
}

static void thread_fn(void *func, void *arg, void *unused)
{
    (void)unused;

    LOG_INF("Thread %p run - func:%p arg:%p", k_current_get(), func, arg);
    ((palThreadFuncPtr)func)(arg);
    LOG_INF("Thread %p closing", k_current_get());
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void *funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadID_t *threadID)
{
    if (threadID == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    /* find unused memory block from pool */
    size_t index = 0;

    for ( ; index < PAL_THREADS_MAX_COUNT; index++) {
        if (pal_threads[index].available) {
            break;
        }
    }

    /* create new thread with memory from pool */
    if ((stackSize <= PAL_STACKS_MAX_SIZE) && (index < PAL_THREADS_MAX_COUNT)) {

        /* mark thread as in-use */
        pal_threads[index].available = false;

        /* Adjust priority - let pelion threads execute as preemptive threads. */
        BUILD_ASSERT(CONFIG_NUM_PREEMPT_PRIORITIES > PAL_osPrioritylast - PAL_osPriorityFirst,
                 "Not enough priorities of preemptive threads");
        int prio_adj = PAL_osPrioritylast - priority;

        k_tid_t tid = k_thread_create(&(pal_threads[index].thread),
                                      pal_stacks[index],
                                      K_THREAD_STACK_SIZEOF(pal_stacks[index]),
                                      (void*)thread_fn,
                                      function, funcArgument, NULL,
                                      prio_adj,
                                      0,
                                      K_NO_WAIT);

        LOG_INF("Thread %p created - prio:%d (%d) stack_size:%d", tid, priority, prio_adj, stackSize);
        *threadID = (palThreadID_t) tid;

        return PAL_SUCCESS;
    } else {
        LOG_ERR("Failed to create thread: no memory");
        *threadID = 0;
    }

    return PAL_ERR_NO_MEMORY;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t *threadID)
{
    struct k_thread* thread = (struct k_thread*) *threadID;

    if (!thread) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    LOG_WRN("Killing thread not available - waiting for thread to stop");
    while (true) {
        int err = k_thread_join(thread, K_FOREVER);
        if (!err) {
            /* return thread data structure to pool and clear it */
            pal_thread_t* container = CONTAINER_OF(thread, pal_thread_t, thread);
            memset(&(container->thread), 0, sizeof(struct k_thread));
            container->available = true;
            return PAL_SUCCESS;
        } else if ((err == -EBUSY) || (err == -EAGAIN)) {
            continue;
        } else {
            return PAL_ERR_RTOS_TASK;
        }
    }
}

palThreadID_t pal_plat_osThreadGetId(void)
{
    return (palThreadID_t) k_current_get();
}


palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
    while (true) {
        int err = k_sleep(K_MSEC(milliseconds));

        if (!err) {
            return PAL_SUCCESS;
        } else if (err < 0) {
            return PAL_ERR_GENERIC_FAILURE;
        } else {
            milliseconds = err;
            continue;
        }
    }
}

struct timer_data {
    struct k_work_delayable dwork;
    struct k_work_sync work_sync;
    palTimerFuncPtr callback;
    void *arg;
    struct k_mutex lock;
    uint64_t timeout;
    uint64_t period;
};

static void work_fn(struct k_work *work)
{
    struct k_work_delayable *dwork = CONTAINER_OF(work, struct k_work_delayable, work);
    struct timer_data *timer_data = CONTAINER_OF(dwork, struct timer_data, dwork);

    uint64_t uptime = k_uptime_get();
    int ret = 0;

    k_mutex_lock(&timer_data->lock, K_FOREVER);

    uint64_t timeout = timer_data->timeout;

    if (timer_data->timeout == UINT64_MAX) {
        /* Timer was stopped. */
    } else if (uptime >= timer_data->timeout) {
        palTimerFuncPtr callback = timer_data->callback;
        void *arg = timer_data->arg;

        k_mutex_unlock(&timer_data->lock);
        callback(arg);
        k_mutex_lock(&timer_data->lock, K_FOREVER);

        if (timer_data->period && (timer_data->period != UINT64_MAX)) {
            /* Calculate next timeout for periodic timers. */
            if (timeout == timer_data->timeout) {
                timer_data->timeout = timeout + timer_data->period;
            } else {
                /* Timer was restarted - timeout was updated. */
            }

            ret = k_work_reschedule(&timer_data->dwork, K_TIMEOUT_ABS_MS(timer_data->timeout));
            __ASSERT_NO_MSG(ret > 0);
        }
    } else {
        /* Theoretically impossible but could be handled, reschedule remaining time. */
        ret = k_work_reschedule(&timer_data->dwork, K_MSEC(timer_data->timeout - uptime));
        __ASSERT_NO_MSG(ret > 0);
    }

    /* Release the timer. */
    k_mutex_unlock(&timer_data->lock);
}

palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function,
                   void *funcArgument,
                   palTimerType_t timerType,
                   palTimerID_t *timerID)
{
    if ((timerID == NULL) || ((void*)function == NULL)) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct timer_data *timer_data = malloc(sizeof(*timer_data));

    if (timer_data) {
        timer_data->arg = funcArgument;
        timer_data->callback = function;

        /* Non-zero period marks periodic timer. */
        timer_data->period = (timerType == palOsTimerPeriodic) ? UINT64_MAX : 0;
        timer_data->timeout = 0;

        k_mutex_init(&timer_data->lock);
        k_work_init_delayable(&timer_data->dwork, work_fn);

        *timerID = (palTimerID_t)timer_data;
        return PAL_SUCCESS;
    }

    timerID = 0;
    return PAL_ERR_NO_MEMORY;
}

palStatus_t pal_plat_osTimerStart(palTimerID_t timerID, uint32_t millisec)
{
    struct timer_data *timer_data = (void*)timerID;
    if (!timer_data) {
        return PAL_ERR_RTOS_PARAMETER;
    } else if ((millisec == 0) || (millisec == PAL_RTOS_WAIT_FOREVER)) {
        return PAL_ERR_RTOS_VALUE;
    }

    uint64_t uptime = k_uptime_get();

    k_mutex_lock(&timer_data->lock, K_FOREVER);

    timer_data->timeout = (uptime + millisec);
    if (timer_data->period) {
        timer_data->period = millisec;
    }

    int ret = k_work_reschedule(&timer_data->dwork, K_TIMEOUT_ABS_MS(timer_data->timeout));
    __ASSERT_NO_MSG(ret > 0);
    k_mutex_unlock(&timer_data->lock);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osTimerStop(palTimerID_t timerID)
{
    struct timer_data *timer_data = (void*)timerID;
    if (!timer_data) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    k_mutex_lock(&timer_data->lock, K_FOREVER);

    /* Mark timeout as stopped. */
    timer_data->timeout = UINT64_MAX;
    if (timer_data->period) {
        timer_data->period = UINT64_MAX;
    }

    /* Return code is not relevant.
     * If Stop was called from timer callback it cannot be stopped.
     * Let in-callback code handle the stop.
     */
    (void)k_work_cancel_delayable(&timer_data->dwork);
    k_mutex_unlock(&timer_data->lock);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osTimerDelete(palTimerID_t *timerID)
{
    if (timerID == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct timer_data *timer_data = (void*)*timerID;
    if (!timer_data) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    /* Callbacks are executed form sys_workq thread.
     * Deletion from its own callback will lead to deadlock.
     */
    __ASSERT_NO_MSG(k_current_get() != &k_sys_work_q.thread);

    palStatus_t ret = pal_plat_osTimerStop(*timerID);
    __ASSERT_NO_MSG(ret == PAL_SUCCESS);

    (void)k_work_cancel_delayable_sync(&timer_data->dwork, &timer_data->work_sync);

    /* Nothing is using the resources - delete the timer. */
    free(timer_data);
    *timerID = (palTimerID_t)NULL;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osMutexCreate(palMutexID_t *mutexID)
{
    if (NULL == mutexID) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct k_mutex *mutex = malloc(sizeof(*mutex));
    if (mutex) {
        int err = k_mutex_init(mutex);
        if (err) {
            free(mutex);
            mutexID = 0;
            return PAL_ERR_CREATION_FAILED;
        }

        *mutexID = (palMutexID_t)mutex;
        return PAL_SUCCESS;
    }

    *mutexID = 0;
    return PAL_ERR_NO_MEMORY;
}

palStatus_t pal_plat_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    struct k_mutex *mutex = (void*)mutexID;
    if (!mutex) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    int ret = k_mutex_lock(mutex, get_timeout(millisec));

    if (ret == -EAGAIN) {
        return PAL_ERR_RTOS_TIMEOUT;
    } else if (ret) {
        return PAL_ERR_GENERIC_FAILURE;

    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osMutexRelease(palMutexID_t mutexID)
{
    struct k_mutex *mutex = (void*)mutexID;
    if (!mutex) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    int ret = k_mutex_unlock(mutex);

    if (ret) {
        return PAL_ERR_GENERIC_FAILURE;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osMutexDelete(palMutexID_t *mutexID)
{
    if (mutexID == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct k_mutex *mutex = (void*)mutexID;
    if (!mutex) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    free(mutex);

    *mutexID = (palMutexID_t)NULL;
    return PAL_SUCCESS;
}


palStatus_t pal_plat_osSemaphoreCreate(uint32_t count, palSemaphoreID_t *semaphoreID)
{
    if (NULL == semaphoreID) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct k_sem *sem = malloc(sizeof(*sem));
    if (sem) {
        int err = k_sem_init(sem, count, PAL_SEMAPHORE_MAX_COUNT);
        if (err) {
            LOG_ERR("Failed to initialize semaphore (err:%d)", err);
            free(sem);
            semaphoreID = 0;
            return PAL_ERR_CREATION_FAILED;
        }

        *semaphoreID = (palSemaphoreID_t)sem;
        return PAL_SUCCESS;
    } else {
        LOG_ERR("Failed to create semaphore: no memory");
    }

    *semaphoreID = 0;
    return PAL_ERR_NO_MEMORY;
}

palStatus_t pal_plat_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec, int32_t *countersAvailable)
{
    struct k_sem *sem = (void*)semaphoreID;
    if (!sem) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    int ret = k_sem_take(sem, get_timeout(millisec));

    if (ret == -EAGAIN) {
        return PAL_ERR_RTOS_TIMEOUT;
    } else if (ret) {
        return PAL_ERR_GENERIC_FAILURE;

    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
    struct k_sem *sem = (void*)semaphoreID;
    if (!sem) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    k_sem_give(sem);

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t *semaphoreID)
{
    if (semaphoreID == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct k_sem *sem = (void*)semaphoreID;
    if (!sem) {
        return PAL_ERR_RTOS_PARAMETER;
    }

    free(sem);

    *semaphoreID = (palSemaphoreID_t)NULL;
    return PAL_SUCCESS;
}


int32_t pal_plat_osAtomicIncrement(int32_t *valuePtr, int32_t increment)
{
    /* Assert type as atomic_add operates on ints. */
    BUILD_ASSERT((sizeof(*valuePtr) == sizeof(int)) &&
                 (INT_MAX == INT32_MAX));
    int res = atomic_add(valuePtr, increment);
    return res + increment;
}


void *pal_plat_malloc(size_t len)
{
    return malloc(len);
}
void pal_plat_free(void *buffer)
{
    free(buffer);
}

palStatus_t pal_plat_osGetRoTFromHW(uint8_t *keyBuf, size_t keyLenBytes)
{
    __ASSERT(false, "No HW RoT support provided. Correct configuration");
    return PAL_ERR_NOT_SUPPORTED;
}

palStatus_t pal_plat_osGetRtcTime(uint64_t *rtcGetTime)
{
    if (NULL == rtcGetTime) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    struct timespec ts;

    int ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (ret < 0) {
        return PAL_ERR_GENERIC_FAILURE;
    }

    (*rtcGetTime) = ts.tv_sec;

    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
    struct timespec ts = {
        .tv_sec = rtcSetTime,
        .tv_nsec = 0,
    };

    int ret = clock_settime(CLOCK_REALTIME, &ts);
    if (ret < 0) {
        return PAL_ERR_GENERIC_FAILURE;
    }

    return PAL_SUCCESS;
}

palStatus_t pal_plat_rtcDeInit(void)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_rtcInit(void)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}

palStatus_t pal_plat_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes, size_t *actualRandomSizeBytes)
{
    return PAL_ERR_NOT_IMPLEMENTED;
}
