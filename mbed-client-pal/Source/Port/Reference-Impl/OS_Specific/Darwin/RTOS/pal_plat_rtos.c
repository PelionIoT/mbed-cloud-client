/* SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "pal_plat_rtos.h"

typedef struct darwin_thread {
    struct darwin_thread *next;
    pthread_t thread;
    palThreadFuncPtr function;
    void *argument;
} darwin_thread;

typedef struct darwin_wait {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned waiters;
    pthread_t owner;
    uint32_t depth;
    int32_t count;
} darwin_wait;

typedef struct darwin_timer {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    pthread_t thread;
    bool active;
    bool closing;
    bool delete_on_exit;
    uint64_t deadline;
    uint32_t period;
    palTimerType_t type;
    palTimerFuncPtr function;
    void *argument;
} darwin_timer;

static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static darwin_thread *threads;
static unsigned timer_count;

static uint64_t monotonic_us(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) abort();
    return (uint64_t)now.tv_sec * UINT64_C(1000000) + (uint64_t)now.tv_nsec / 1000;
}

/* Darwin's relative condition wait uses a monotonic interval. Recompute it
 * against one deadline after every wake, including spurious wakes. */
static int wait_until(pthread_cond_t *condition, pthread_mutex_t *lock, uint64_t deadline)
{
    uint64_t now = monotonic_us();
    if (now >= deadline) return ETIMEDOUT;
    uint64_t remaining = deadline - now;
    struct timespec interval = {(time_t)(remaining / 1000000), (long)(remaining % 1000000) * 1000};
    return pthread_cond_timedwait_relative_np(condition, lock, &interval);
}

static void thread_cleanup(void *argument)
{
    darwin_thread *thread = argument;
    pthread_mutex_lock(&runtime_lock);
    darwin_thread **entry = &threads;
    while (*entry && *entry != thread) entry = &(*entry)->next;
    if (*entry) *entry = thread->next;
    pthread_mutex_unlock(&runtime_lock);
    free(thread);
}

static void *thread_main(void *argument)
{
    darwin_thread *thread = argument;
    pthread_cleanup_push(thread_cleanup, thread);
    /* Creation publishes the handle and registry entry before user code runs. */
    pthread_mutex_lock(&runtime_lock);
    pthread_mutex_unlock(&runtime_lock);
    pthread_testcancel();
    thread->function(thread->argument);
    pthread_cleanup_pop(1);
    return NULL;
}

palStatus_t pal_plat_RTOSInitialize(void *context)
{
    (void)context;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_RTOSDestroy(void)
{
    pthread_mutex_lock(&runtime_lock);
    bool busy = threads != NULL || timer_count != 0;
    pthread_mutex_unlock(&runtime_lock);
    return busy ? PAL_ERR_RTOS_RESOURCE : PAL_SUCCESS;
}

void pal_plat_osReboot(void)
{
    /* The service supervisor may restart Core; do not reboot the host. */
    _Exit(EXIT_FAILURE);
}

uint64_t pal_plat_osKernelSysTick(void) { return monotonic_us(); }
uint64_t pal_plat_osKernelSysTickFrequency(void) { return UINT64_C(1000000); }
uint64_t pal_plat_osKernelSysTickMicroSec(uint64_t microseconds) { return microseconds; }

palStatus_t pal_plat_osThreadCreate(palThreadFuncPtr function, void *argument,
    palThreadPriority_t priority, uint32_t stack_size, palThreadID_t *id)
{
    if (!id || !function || !stack_size) return PAL_ERR_RTOS_PARAMETER;
    *id = 0;
    if (priority < PAL_osPriorityFirst || priority > PAL_osPrioritylast) return PAL_ERR_RTOS_PRIORITY;
    darwin_thread *thread = calloc(1, sizeof(*thread));
    if (!thread) return PAL_ERR_NO_MEMORY;
    thread->function = function;
    thread->argument = argument;
    pthread_attr_t attributes;
    if (pthread_attr_init(&attributes) != 0) { free(thread); return PAL_ERR_RTOS_RESOURCE; }
    size_t native_stack = stack_size < 128 * 1024 ? 128 * 1024 : stack_size;
    size_t page = (size_t)getpagesize();
    native_stack = (native_stack + page - 1) / page * page;
    int error = pthread_attr_setstacksize(&attributes, native_stack);
    if (!error) error = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    /* PAL's logical priorities use normal OS scheduling, as on Linux. */
    pthread_mutex_lock(&runtime_lock);
    if (!error) error = pthread_create(&thread->thread, &attributes, thread_main, thread);
    if (!error) {
        thread->next = threads;
        threads = thread;
        *id = (palThreadID_t)thread->thread;
    }
    pthread_mutex_unlock(&runtime_lock);
    pthread_attr_destroy(&attributes);
    if (error) { free(thread); return PAL_ERR_RTOS_RESOURCE; }
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osThreadTerminate(palThreadID_t *id)
{
    if (!id || !*id || *id == PAL_INVALID_THREAD) return PAL_ERR_RTOS_PARAMETER;
    int error = 0;
    pthread_mutex_lock(&runtime_lock);
    for (darwin_thread *thread = threads; thread; thread = thread->next) {
        if ((palThreadID_t)thread->thread == *id) {
            error = pthread_cancel(thread->thread);
            break;
        }
    }
    pthread_mutex_unlock(&runtime_lock);
    if (error) return PAL_ERR_RTOS_RESOURCE;
    *id = 0;
    pthread_testcancel();
    return PAL_SUCCESS;
}

palThreadID_t pal_plat_osThreadGetId(void) { return (palThreadID_t)pthread_self(); }

palStatus_t pal_plat_osDelay(uint32_t milliseconds)
{
    struct timespec delay = {milliseconds / 1000, (long)(milliseconds % 1000) * 1000000};
    pthread_testcancel();
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) return PAL_ERR_RTOS_OS;
    }
    return PAL_SUCCESS;
}

static void timer_free(darwin_timer *timer)
{
    pthread_cond_destroy(&timer->changed);
    pthread_mutex_destroy(&timer->lock);
    free(timer);
    pthread_mutex_lock(&runtime_lock);
    --timer_count;
    pthread_mutex_unlock(&runtime_lock);
}

static void *timer_main(void *argument)
{
    darwin_timer *timer = argument;
    pthread_mutex_lock(&timer->lock);
    while (!timer->closing) {
        if (!timer->active) {
            pthread_cond_wait(&timer->changed, &timer->lock);
            continue;
        }
        if (monotonic_us() < timer->deadline) {
            wait_until(&timer->changed, &timer->lock, timer->deadline);
            continue;
        }
        if (timer->type == palOsTimerOnce) timer->active = false;
        else timer->deadline = monotonic_us() + (uint64_t)timer->period * 1000;
        /* Application callbacks may stop, restart or delete their own timer. */
        pthread_mutex_unlock(&timer->lock);
        timer->function(timer->argument);
        pthread_mutex_lock(&timer->lock);
    }
    bool delete_on_exit = timer->delete_on_exit;
    pthread_mutex_unlock(&timer->lock);
    if (delete_on_exit) timer_free(timer);
    return NULL;
}

palStatus_t pal_plat_osTimerCreate(palTimerFuncPtr function, void *argument,
    palTimerType_t type, palTimerID_t *id)
{
    if (!function || !id || (type != palOsTimerOnce && type != palOsTimerPeriodic)) return PAL_ERR_RTOS_PARAMETER;
    *id = 0;
    darwin_timer *timer = calloc(1, sizeof(*timer));
    if (!timer) return PAL_ERR_NO_MEMORY;
    if (pthread_mutex_init(&timer->lock, NULL) != 0) { free(timer); return PAL_ERR_RTOS_RESOURCE; }
    if (pthread_cond_init(&timer->changed, NULL) != 0) {
        pthread_mutex_destroy(&timer->lock);
        free(timer);
        return PAL_ERR_RTOS_RESOURCE;
    }
    timer->function = function;
    timer->argument = argument;
    timer->type = type;
    pthread_mutex_lock(&runtime_lock);
    ++timer_count;
    pthread_mutex_unlock(&runtime_lock);
    if (pthread_create(&timer->thread, NULL, timer_main, timer) != 0) {
        timer_free(timer);
        return PAL_ERR_RTOS_RESOURCE;
    }
    *id = (palTimerID_t)timer;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osTimerStart(palTimerID_t id, uint32_t milliseconds)
{
    darwin_timer *timer = (darwin_timer *)id;
    if (!timer) return PAL_ERR_RTOS_PARAMETER;
    if (!milliseconds) return PAL_ERR_RTOS_VALUE;
    pthread_mutex_lock(&timer->lock);
    bool closing = timer->closing;
    if (!closing) {
        timer->period = milliseconds;
        timer->deadline = monotonic_us() + (uint64_t)milliseconds * 1000;
        timer->active = true;
        pthread_cond_signal(&timer->changed);
    }
    pthread_mutex_unlock(&timer->lock);
    return closing ? PAL_ERR_RTOS_RESOURCE : PAL_SUCCESS;
}

palStatus_t pal_plat_osTimerStop(palTimerID_t id)
{
    darwin_timer *timer = (darwin_timer *)id;
    if (!timer) return PAL_ERR_RTOS_PARAMETER;
    pthread_mutex_lock(&timer->lock);
    timer->active = false;
    pthread_cond_signal(&timer->changed);
    pthread_mutex_unlock(&timer->lock);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osTimerDelete(palTimerID_t *id)
{
    if (!id || !*id) return PAL_ERR_RTOS_PARAMETER;
    darwin_timer *timer = (darwin_timer *)*id;
    int previous_cancel_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state);
    pthread_mutex_lock(&timer->lock);
    bool self = pthread_equal(pthread_self(), timer->thread);
    timer->closing = true;
    timer->active = false;
    timer->delete_on_exit = self;
    pthread_cond_signal(&timer->changed);
    pthread_mutex_unlock(&timer->lock);
    *id = 0;
    if (self) pthread_detach(timer->thread);
    else {
        pthread_join(timer->thread, NULL);
        timer_free(timer);
    }
    pthread_setcancelstate(previous_cancel_state, NULL);
    return PAL_SUCCESS;
}

static palStatus_t wait_create(uint32_t count, darwin_wait **output)
{
    *output = NULL;
    darwin_wait *object = calloc(1, sizeof(*object));
    if (!object) return PAL_ERR_NO_MEMORY;
    if (pthread_mutex_init(&object->lock, NULL) != 0) { free(object); return PAL_ERR_RTOS_RESOURCE; }
    if (pthread_cond_init(&object->changed, NULL) != 0) {
        pthread_mutex_destroy(&object->lock);
        free(object);
        return PAL_ERR_RTOS_RESOURCE;
    }
    object->count = (int32_t)count;
    *output = object;
    return PAL_SUCCESS;
}

static void wait_cancel(void *argument)
{
    darwin_wait *object = argument;
    --object->waiters;
    pthread_cond_broadcast(&object->changed);
    pthread_mutex_unlock(&object->lock);
}

static palStatus_t wait_acquire(darwin_wait *object, bool mutex, uint32_t milliseconds, int32_t *available)
{
    if (available) *available = 0;
    if (!object) return PAL_ERR_RTOS_PARAMETER;
    uint64_t deadline = monotonic_us() + (uint64_t)milliseconds * 1000;
    palStatus_t status = PAL_SUCCESS;
    pthread_mutex_lock(&object->lock);
    ++object->waiters;
    pthread_cleanup_push(wait_cancel, object);
    while (mutex ? (object->depth && !pthread_equal(object->owner, pthread_self())) : !object->count) {
        if (!milliseconds) {
            status = mutex ? PAL_ERR_RTOS_RESOURCE : PAL_ERR_RTOS_TIMEOUT;
            break;
        }
        int error = milliseconds == PAL_RTOS_WAIT_FOREVER
            ? pthread_cond_wait(&object->changed, &object->lock)
            : wait_until(&object->changed, &object->lock, deadline);
        if (error) {
            status = error == ETIMEDOUT ? PAL_ERR_RTOS_TIMEOUT : PAL_ERR_RTOS_OS;
            break;
        }
    }
    if (status == PAL_SUCCESS) {
        if (mutex) {
            if (object->depth == UINT32_MAX) status = PAL_ERR_RTOS_RESOURCE;
            else { object->owner = pthread_self(); ++object->depth; }
        } else {
            --object->count;
            if (available) *available = object->count;
        }
    }
    pthread_cleanup_pop(0);
    --object->waiters;
    pthread_mutex_unlock(&object->lock);
    return status;
}

static palStatus_t wait_delete(darwin_wait *object)
{
    pthread_mutex_lock(&object->lock);
    bool busy = object->waiters != 0 || object->depth != 0;
    pthread_mutex_unlock(&object->lock);
    if (busy) return PAL_ERR_RTOS_RESOURCE;
    pthread_cond_destroy(&object->changed);
    pthread_mutex_destroy(&object->lock);
    free(object);
    return PAL_SUCCESS;
}

palStatus_t pal_plat_osMutexCreate(palMutexID_t *id)
{
    if (!id) return PAL_ERR_RTOS_PARAMETER;
    darwin_wait *object;
    palStatus_t status = wait_create(0, &object);
    *id = (palMutexID_t)object;
    return status;
}

palStatus_t pal_plat_osMutexWait(palMutexID_t id, uint32_t milliseconds)
{
    return wait_acquire((darwin_wait *)id, true, milliseconds, NULL);
}

palStatus_t pal_plat_osMutexRelease(palMutexID_t id)
{
    darwin_wait *object = (darwin_wait *)id;
    if (!object) return PAL_ERR_RTOS_PARAMETER;
    pthread_mutex_lock(&object->lock);
    palStatus_t status = PAL_ERR_RTOS_PARAMETER;
    if (object->depth && pthread_equal(object->owner, pthread_self())) {
        if (!--object->depth) pthread_cond_signal(&object->changed);
        status = PAL_SUCCESS;
    }
    pthread_mutex_unlock(&object->lock);
    return status;
}

palStatus_t pal_plat_osMutexDelete(palMutexID_t *id)
{
    if (!id || !*id) return PAL_ERR_RTOS_PARAMETER;
    palStatus_t status = wait_delete((darwin_wait *)*id);
    if (status == PAL_SUCCESS) *id = 0;
    return status;
}

palStatus_t pal_plat_osSemaphoreCreate(uint32_t count, palSemaphoreID_t *id)
{
    if (!id || count > INT32_MAX) return PAL_ERR_RTOS_PARAMETER;
    darwin_wait *object;
    palStatus_t status = wait_create(count, &object);
    *id = (palSemaphoreID_t)object;
    return status;
}

palStatus_t pal_plat_osSemaphoreWait(palSemaphoreID_t id, uint32_t milliseconds, int32_t *available)
{
    return wait_acquire((darwin_wait *)id, false, milliseconds, available);
}

palStatus_t pal_plat_osSemaphoreRelease(palSemaphoreID_t id)
{
    darwin_wait *object = (darwin_wait *)id;
    if (!object) return PAL_ERR_RTOS_PARAMETER;
    pthread_mutex_lock(&object->lock);
    palStatus_t status = PAL_ERR_RTOS_RESOURCE;
    if (object->count < INT32_MAX) {
        ++object->count;
        pthread_cond_signal(&object->changed);
        status = PAL_SUCCESS;
    }
    pthread_mutex_unlock(&object->lock);
    return status;
}

palStatus_t pal_plat_osSemaphoreDelete(palSemaphoreID_t *id)
{
    if (!id || !*id) return PAL_ERR_RTOS_PARAMETER;
    palStatus_t status = wait_delete((darwin_wait *)*id);
    if (status == PAL_SUCCESS) *id = 0;
    return status;
}

int32_t pal_plat_osAtomicIncrement(int32_t *value, int32_t increment)
{
    return __atomic_add_fetch(value, increment, __ATOMIC_SEQ_CST);
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
palStatus_t pal_plat_osGetRtcTime(uint64_t *output)
{
    if (!output) return PAL_ERR_RTOS_PARAMETER;
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return PAL_ERR_RTOS_OS;
    *output = (uint64_t)now.tv_sec;
    return PAL_SUCCESS;
}
palStatus_t pal_plat_rtcInit(void) { return PAL_SUCCESS; }
palStatus_t pal_plat_rtcDeInit(void) { return PAL_SUCCESS; }
