#ifndef SEMAPHORE_H
#define SEMAPHORE_H

#include <proto/exec.h>
#include <limits.h>

#undef SEM_VALUE_MAX
#define SEM_VALUE_MAX INT_MAX

struct sema
{
    int value;
    struct SignalSemaphore gate;
    struct SignalSemaphore mutex;
};

typedef struct sema sem_t;

#ifdef  __cplusplus
extern "C" {
#endif

int sem_init(sem_t *sem, int pshared, unsigned int value);
int sem_destroy(sem_t *sem);
int sem_trywait(sem_t *sem);
int sem_wait(sem_t *sem);
int sem_timedwait(sem_t *sem, const struct timespec *abstime);
int sem_post(sem_t *sem);
int sem_getvalue(sem_t *sem, int *sval);

#ifdef  __cplusplus
}
#endif

#endif
