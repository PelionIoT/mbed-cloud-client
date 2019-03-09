#include <proto/exec.h>
#include <proto/dos.h>
#include <errno.h>
#include "semaphore.h"

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    if (sem == NULL || value > (unsigned int)SEM_VALUE_MAX)
    {
        errno = EINVAL;
        return -1;
    }

    sem->value = value;
    InitSemaphore(&sem->gate);
    InitSemaphore(&sem->mutex);

    if(sem->value == 0)
    {
        ObtainSemaphore(&sem->gate);
    }

    return 0;
}

int sem_destroy(sem_t *sem)
{
    if (sem == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    if (!AttemptSemaphore(&sem->gate))
    {
        errno = EBUSY;
        return -1;
    }

    ObtainSemaphore(&sem->mutex);
    sem->value = 0;
    ReleaseSemaphore(&sem->mutex);
    ReleaseSemaphore(&sem->gate);

    return 0;
}

int sem_trywait(sem_t *sem)
{
    if (sem == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    if(!AttemptSemaphore(&sem->gate)) {
        return EAGAIN;
    }

    if(!AttemptSemaphore(&sem->mutex)) {
        ReleaseSemaphore(&sem->gate);
        return EAGAIN;
    }

    sem->value--;

    if(sem->value > 0) {
        ReleaseSemaphore(&sem->gate);
    }

    ReleaseSemaphore(&sem->mutex);

    return 0;
}

int sem_timedwait(sem_t *sem, const struct timespec *abstime)
{
    #if 0
    int result = 0;

    if (sem == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&sem->lock);

    sem->waiters_count++;

    while (sem->value == 0 && result == 0)
        result = pthread_cond_timedwait(&sem->count_nonzero, &sem->lock, abstime);

    sem->waiters_count--;

    if (result != 0)
    {
        pthread_mutex_unlock(&sem->lock);
        errno = result;
        return -1;
    }

    sem->value--;

    pthread_mutex_unlock(&sem->lock);

    return 0;
    #else
    return sem_wait(sem);
    #endif
}

int sem_wait(sem_t *sem)
{
    //return sem_timedwait(sem, NULL);

    if (sem == NULL)
    {
        errno = EINVAL;
        return -1;
    }
obtain:
    ObtainSemaphore(&sem->gate);
    //check if we started nesting here, and if so, apply some remedy
    if(sem->gate.ss_NestCount == 2) {
        //we should not have got here, but because the semaphore is recursive we did.
        //revert the situation and try again after count is bigger than zero
        while(1) {
            ObtainSemaphore(&sem->mutex);
            if(sem->value > 0) {
                //Finally release our hold of gate
                ReleaseSemaphore(&sem->gate);
                //Done with this loop, get on with it
                ReleaseSemaphore(&sem->mutex);
                goto obtain;
            }
            ReleaseSemaphore(&sem->mutex);
            //delay here until stuff happens
            Delay(1);
        }
    }
    ObtainSemaphore(&sem->mutex);
    sem->value--;

    if(sem->value > 0) {
        ReleaseSemaphore(&sem->gate);
    }

    ReleaseSemaphore(&sem->mutex);

    return 0;
}

int sem_post(sem_t *sem)
{
    if (sem == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    ObtainSemaphore(&sem->mutex);

    if (sem->value >= SEM_VALUE_MAX)
    {
        ReleaseSemaphore(&sem->mutex);
        errno = EOVERFLOW;
        return -1;
    }

    sem->value++;

     if(sem->value == 1) {
         ReleaseSemaphore(&sem->gate);
     }

    //if (sem->waiters_count > 0)
    //    pthread_cond_signal(&sem->count_nonzero);

    ReleaseSemaphore(&sem->mutex);

    return 0;
}

int sem_getvalue(sem_t *sem, int *sval)
{
    if (sem == NULL || sval == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    if (AttemptSemaphore(&sem->mutex))
    {
        *sval = sem->value;
        ReleaseSemaphore(&sem->mutex);
    }
    else
    {
        // if one or more threads are waiting to lock the semaphore,
        // then return the negative of the waiters
        *sval = -sem->gate.ss_QueueCount;
    }

    return 0;
}
