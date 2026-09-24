/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include "pal_plat_rtos.h"

typedef struct win_thread {
    struct win_thread *next;
    HANDLE thread;
    HANDLE cancel;
    unsigned id;
    palThreadFuncPtr function;
    void *argument;
} win_thread;

typedef struct win_timer {
    HANDLE thread;
    HANDLE stop;
    HANDLE timer;
    unsigned thread_id;
    volatile LONG references;
    CRITICAL_SECTION lock;
    bool active;
    bool closing;
    uint64_t deadline;
    uint32_t period;
    palTimerType_t type;
    palTimerFuncPtr function;
    void *argument;
} win_timer;

typedef struct win_semaphore {
    HANDLE handle;
    SRWLOCK lock;
    LONG count;
} win_semaphore;

static SRWLOCK threads_lock = SRWLOCK_INIT;
static win_thread *threads;
static __declspec(thread) win_thread *current_thread;
static volatile LONG timer_count;

static void thread_cleanup(win_thread *thread)
{
    win_thread **entry;
    AcquireSRWLockExclusive(&threads_lock);
    for (entry = &threads; *entry && *entry != thread; entry = &(*entry)->next) {}
    if (*entry) *entry = thread->next;
    ReleaseSRWLockExclusive(&threads_lock);
    CloseHandle(thread->thread);
    CloseHandle(thread->cancel);
    current_thread = NULL;
    free(thread);
}

static void cancellation_point(void)
{
    if (current_thread && WaitForSingleObject(current_thread->cancel, 0) == WAIT_OBJECT_0) {
        thread_cleanup(current_thread);
        _endthreadex(0);
    }
}

/* Cancellation is deferred to PAL waits, like a pthread cancellation point.
 * Never use TerminateThread: it can strand CRT and application locks. */
static DWORD wait_handle(HANDLE object, DWORD milliseconds)
{
    if (current_thread) {
        HANDLE objects[2] = {current_thread->cancel, object};
        DWORD result = WaitForMultipleObjects(2, objects, FALSE, milliseconds);
        if (result == WAIT_OBJECT_0) cancellation_point();
        if (result == WAIT_OBJECT_0 + 1) return WAIT_OBJECT_0;
        if (result == WAIT_ABANDONED_0 + 1) return WAIT_ABANDONED;
        return result;
    }
    return WaitForSingleObject(object, milliseconds);
}

static unsigned __stdcall thread_main(void *argument)
{
    win_thread *thread = argument;
    current_thread = thread;
    cancellation_point();
    thread->function(thread->argument);
    thread_cleanup(thread);
    return 0;
}

palStatus_t pal_plat_RTOSInitialize(void *context)
{
    (void)context;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
    bool busy;
    AcquireSRWLockShared(&threads_lock);
    busy = threads != NULL;
    ReleaseSRWLockShared(&threads_lock);
    return (busy || InterlockedCompareExchange(&timer_count, 0, 0)) ? PAL_ERR_RTOS_RESOURCE : PAL_SUCCESS;
}

void pal_plat_osReboot(void)
{
    /* Application restart only. A privileged updater and explicit policy must
     * implement any future permission to reboot the Windows host. */
    ExitProcess(EXIT_FAILURE);
}

uint64_t pal_plat_osKernelSysTick(void) { return GetTickCount64(); }
uint64_t pal_plat_osKernelSysTickFrequency(void) { return 1000; }
uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds)
{
    return microseconds / 1000 + (microseconds % 1000 != 0);
}

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void *argument,
    palThreadPriority_t priority, uint32_t stack_size, palThreadID_t *id)
{
    win_thread *thread;
    if (!id || !function || !stack_size) return PAL_ERR_RTOS_PARAMETER;
    *id = 0;
    if (priority < PAL_osPriorityFirst || priority > PAL_osPrioritylast) return PAL_ERR_RTOS_PRIORITY;
    thread = calloc(1, sizeof(*thread));
    if (!thread) return PAL_ERR_NO_MEMORY;
    thread->function = function;
    thread->argument = argument;
    thread->cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!thread->cancel) { free(thread); return PAL_ERR_RTOS_RESOURCE; }
    /* Honor at least the executable's normal native stack reserve. Tiny
     * embedded PAL stack sizes are insufficient for Windows CRT callbacks. */
    if (stack_size < 128 * 1024) stack_size = 128 * 1024;
    thread->thread = (HANDLE)_beginthreadex(NULL, stack_size, thread_main, thread,
        CREATE_SUSPENDED, &thread->id);
    if (!thread->thread) {
        CloseHandle(thread->cancel);
        free(thread);
        return PAL_ERR_RTOS_RESOURCE;
    }
    /* Use normal OS scheduling for PAL's reserved priorities, matching the
     * Linux port's treatment of these logical priorities. */
    AcquireSRWLockExclusive(&threads_lock);
    thread->next = threads;
    threads = thread;
    *id = thread->id;
    ReleaseSRWLockExclusive(&threads_lock);
    ResumeThread(thread->thread);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t *id)
{
    win_thread *thread;
    if (!id || !*id || *id == PAL_INVALID_THREAD) return PAL_ERR_RTOS_PARAMETER;
    AcquireSRWLockShared(&threads_lock);
    for (thread = threads; thread && thread->id != *id; thread = thread->next) {}
    if (thread) SetEvent(thread->cancel);
    ReleaseSRWLockShared(&threads_lock);
    *id = 0;
    cancellation_point();
    return PAL_SUCCESS;
}

palThreadID_t pal_plat_osThreadGetId(void) { return GetCurrentThreadId(); }

palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
    if (current_thread) {
        DWORD result = WaitForSingleObject(current_thread->cancel, milliseconds);
        if (result == WAIT_FAILED) return PAL_ERR_RTOS_OS;
        cancellation_point();
    } else {
        Sleep(milliseconds);
    }
    return PAL_SUCCESS;
}

static void timer_release(win_timer *timer)
{
    if (InterlockedDecrement(&timer->references) == 0) {
        CloseHandle(timer->timer);
        CloseHandle(timer->stop);
        CloseHandle(timer->thread);
        DeleteCriticalSection(&timer->lock);
        InterlockedDecrement(&timer_count);
        free(timer);
    }
}

static unsigned __stdcall timer_main(void *argument)
{
    win_timer *timer = argument;
    HANDLE objects[2] = {timer->stop, timer->timer};
    while (WaitForMultipleObjects(2, objects, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
        bool invoke = false;
        EnterCriticalSection(&timer->lock);
        if (timer->active && !timer->closing) {
            uint64_t now = GetTickCount64();
            if (now >= timer->deadline) {
                if (timer->type == palOsTimerOnce) timer->active = false;
                else timer->deadline = now + timer->period;
                invoke = true;
            } else {
                LARGE_INTEGER remaining;
                /* Tick readings are coarse, and a restart can leave an old
                 * wake already dispatched. Re-arm for the remaining interval
                 * instead of consuming the only wake of a one-shot timer. */
                remaining.QuadPart = -(LONGLONG)(timer->deadline - now) * 10000;
                SetWaitableTimer(timer->timer, &remaining,
                    timer->type == palOsTimerPeriodic ? (LONG)timer->period : 0,
                    NULL, NULL, FALSE);
            }
        }
        LeaveCriticalSection(&timer->lock);
        /* Never hold our lock while application code may acquire the event
         * loop lock. Stop cancels future firings; delete drains this worker. */
        if (invoke) timer->function(timer->argument);
    }
    timer_release(timer);
    return 0;
}

palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function, void *argument,
    palTimerType_t type, palTimerID_t *id)
{
    win_timer *timer;
    if (!function || !id || (type != palOsTimerOnce && type != palOsTimerPeriodic)) return PAL_ERR_RTOS_PARAMETER;
    *id = 0;
    timer = calloc(1, sizeof(*timer));
    if (!timer) return PAL_ERR_NO_MEMORY;
    timer->function = function;
    timer->argument = argument;
    timer->type = type;
    timer->references = 2; /* Caller and worker each own a reference. */
    InitializeCriticalSection(&timer->lock);
    timer->timer = CreateWaitableTimerW(NULL, FALSE, NULL);
    timer->stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (timer->timer && timer->stop) {
        timer->thread = (HANDLE)_beginthreadex(NULL, 0, timer_main, timer,
            CREATE_SUSPENDED, &timer->thread_id);
    }
    if (!timer->thread) {
        if (timer->timer) CloseHandle(timer->timer);
        if (timer->stop) CloseHandle(timer->stop);
        DeleteCriticalSection(&timer->lock);
        free(timer);
        return PAL_ERR_RTOS_RESOURCE;
    }
    InterlockedIncrement(&timer_count);
    *id = (palTimerID_t)timer;
    ResumeThread(timer->thread);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osTimerStart(palTimerID_t id, uint32_t milliseconds)
{
    win_timer *timer = (win_timer *)id;
    LARGE_INTEGER due;
    BOOL result;
    if (!timer) return PAL_ERR_RTOS_PARAMETER;
    if (!milliseconds || (timer->type == palOsTimerPeriodic && milliseconds > LONG_MAX)) return PAL_ERR_RTOS_VALUE;
    due.QuadPart = -(LONGLONG)milliseconds * 10000;
    EnterCriticalSection(&timer->lock);
    result = !timer->closing && SetWaitableTimer(timer->timer, &due,
        timer->type == palOsTimerPeriodic ? (LONG)milliseconds : 0, NULL, NULL, FALSE);
    if (result) {
        timer->active = true;
        timer->deadline = GetTickCount64() + milliseconds;
        timer->period = milliseconds;
    }
    LeaveCriticalSection(&timer->lock);
    return result ? PAL_SUCCESS : PAL_ERR_RTOS_RESOURCE;
}

palStatus_t pal_plat_osTimerStop(palTimerID_t id)
{
    win_timer *timer = (win_timer *)id;
    BOOL result;
    if (!timer) return PAL_ERR_RTOS_PARAMETER;
    EnterCriticalSection(&timer->lock);
    timer->active = false;
    result = CancelWaitableTimer(timer->timer);
    LeaveCriticalSection(&timer->lock);
    return result ? PAL_SUCCESS : PAL_ERR_RTOS_RESOURCE;
}

palStatus_t pal_plat_osTimerDelete(palTimerID_t *id)
{
    win_timer *timer;
    if (!id || !*id) return PAL_ERR_RTOS_PARAMETER;
    timer = (win_timer *)*id;
    EnterCriticalSection(&timer->lock);
    timer->closing = true;
    timer->active = false;
    CancelWaitableTimer(timer->timer);
    SetEvent(timer->stop);
    LeaveCriticalSection(&timer->lock);
    *id = 0;
    if (GetCurrentThreadId() != timer->thread_id) WaitForSingleObject(timer->thread, INFINITE);
    timer_release(timer);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osMutexCreate(palMutexID_t *id)
{
    if (!id) return PAL_ERR_RTOS_PARAMETER;
    *id = (palMutexID_t)CreateMutexW(NULL, FALSE, NULL);
    return *id ? PAL_SUCCESS : PAL_ERR_RTOS_RESOURCE;
}

palStatus_t pal_plat_osMutexWait(palMutexID_t id, uint32_t milliseconds)
{
    DWORD result;
    if (!id) return PAL_ERR_RTOS_PARAMETER;
    result = wait_handle((HANDLE)id, milliseconds);
    if (result == WAIT_OBJECT_0) return PAL_SUCCESS;
    if (result == WAIT_TIMEOUT) return milliseconds ? PAL_ERR_RTOS_TIMEOUT : PAL_ERR_RTOS_RESOURCE;
    if (result == WAIT_ABANDONED) {
        ReleaseMutex((HANDLE)id);
        return PAL_ERR_RTOS_RESOURCE;
    }
    return PAL_ERR_RTOS_PARAMETER;
}

palStatus_t pal_plat_osMutexRelease(palMutexID_t id)
{
    return id && ReleaseMutex((HANDLE)id) ? PAL_SUCCESS : PAL_ERR_RTOS_PARAMETER;
}

palStatus_t pal_plat_osMutexDelete(palMutexID_t *id)
{
    if (!id || !*id || !CloseHandle((HANDLE)*id)) return PAL_ERR_RTOS_PARAMETER;
    *id = 0;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreCreate(uint32_t count, palSemaphoreID_t *id)
{
    win_semaphore *semaphore;
    if (!id || count > LONG_MAX) return PAL_ERR_RTOS_PARAMETER;
    *id = 0;
    semaphore = calloc(1, sizeof(*semaphore));
    if (!semaphore) return PAL_ERR_NO_MEMORY;
    InitializeSRWLock(&semaphore->lock);
    semaphore->count = (LONG)count;
    semaphore->handle = CreateSemaphoreW(NULL, (LONG)count, LONG_MAX, NULL);
    if (!semaphore->handle) { free(semaphore); return PAL_ERR_RTOS_RESOURCE; }
    *id = (palSemaphoreID_t)semaphore;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreWait(palSemaphoreID_t id, uint32_t milliseconds, int32_t *available)
{
    win_semaphore *semaphore = (win_semaphore *)id;
    DWORD result;
    if (available) *available = 0;
    if (!semaphore) return PAL_ERR_RTOS_PARAMETER;
    result = wait_handle(semaphore->handle, milliseconds);
    if (result == WAIT_TIMEOUT) return PAL_ERR_RTOS_TIMEOUT;
    if (result != WAIT_OBJECT_0) return PAL_ERR_RTOS_PARAMETER;
    AcquireSRWLockExclusive(&semaphore->lock);
    --semaphore->count;
    if (available) *available = semaphore->count;
    ReleaseSRWLockExclusive(&semaphore->lock);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t id)
{
    win_semaphore *semaphore = (win_semaphore *)id;
    BOOL result;
    if (!semaphore) return PAL_ERR_RTOS_PARAMETER;
    AcquireSRWLockExclusive(&semaphore->lock);
    result = ReleaseSemaphore(semaphore->handle, 1, NULL);
    if (result) ++semaphore->count;
    ReleaseSRWLockExclusive(&semaphore->lock);
    return result ? PAL_SUCCESS : PAL_ERR_RTOS_RESOURCE;
}

palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t *id)
{
    win_semaphore *semaphore;
    if (!id || !*id) return PAL_ERR_RTOS_PARAMETER;
    semaphore = (win_semaphore *)*id;
    if (!CloseHandle(semaphore->handle)) return PAL_ERR_RTOS_RESOURCE;
    free(semaphore);
    *id = 0;
    return PAL_SUCCESS;
}

int32_t pal_plat_osAtomicIncrement(int32_t *value, int32_t increment)
{
    LONG old = InterlockedExchangeAdd((volatile LONG *)value, increment);
    return (int32_t)((uint32_t)old + (uint32_t)increment);
}
void *pal_plat_malloc(size_t size) { return malloc(size); }
void pal_plat_free(void *buffer) { free(buffer); }
palStatus_t pal_plat_osGetRoTFromHW(uint8_t *buffer, size_t size)
{
    (void)buffer; (void)size;
    return PAL_ERR_NOT_SUPPORTED;
}
palStatus_t pal_plat_osSetRtcTime(uint64_t time)
{
    (void)time;
    return PAL_ERR_RTOS_NO_PRIVILEGED;
}
palStatus_t pal_plat_osGetRtcTime(uint64_t *time)
{
    FILETIME ft;
    ULARGE_INTEGER value;
    if (!time) return PAL_ERR_RTOS_PARAMETER;
    GetSystemTimeAsFileTime(&ft);
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    *time = (value.QuadPart - UINT64_C(116444736000000000)) / UINT64_C(10000000);
    return PAL_SUCCESS;
}
palStatus_t pal_plat_rtcInit(void) { return PAL_SUCCESS; }
palStatus_t pal_plat_rtcDeInit(void) { return PAL_SUCCESS; }
