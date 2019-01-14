
/**
 * POSIX Semaphores Emulation for AmigaOS
 * Copyright (C)2009 Diego Casorran
 * 
 * Public Domain as long this copyright notice is left unchanged.
 * 
 * Implementation conforms to POSIX.1-2008 where possible.
 */

#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H	1

#ifndef AMIGA
# error this header is designed for AmigaOS or compatible systems
#endif /* !AMIGA */

#include <sys/types.h>
#include <sys/time.h>

/* Value returned if `sem_open' failed.  */
#define SEM_FAILED      ((sem_t *) 0L)
#define SEM_VALUE_MAX	(~0U)

#define __SIZEOF_SEM_T	130

#if defined(__SIZEOF_SEM_T_PAD)
# if __SIZEOF_SEM_T_PAD == 0
#  undef __SIZEOF_SEM_T_PAD
#  define __SIZEOF_SEM_T_PAD __SIZEOF_SEM_T
# elif __SIZEOF_SEM_T_PAD < __SIZEOF_SEM_T
#  undef __SIZEOF_SEM_T_PAD
# endif
#endif
#ifndef __SIZEOF_SEM_T_PAD
# define __SIZEOF_SEM_T_PAD 256
#endif

typedef union {
	
	char __size[__SIZEOF_SEM_T];
	char __pad[__SIZEOF_SEM_T_PAD];
} sem_t;


#ifdef __cplusplus
extern "C" {
#endif

/* Initialize semaphore object SEM to VALUE.  If PSHARED then share it
   with other processes.  */
extern int sem_init (sem_t *__sem, int __pshared, unsigned int __value);

/* Free resources associated with semaphore object SEM.  */
extern int sem_destroy (sem_t *__sem);

/* Open a named semaphore NAME with open flags OFLAG.  */
extern sem_t *sem_open (const char *__name, int __oflag, ...);

/* Close descriptor for named semaphore SEM.  */
extern int sem_close (sem_t *__sem);

/* Remove named semaphore NAME.  */
extern int sem_unlink (const char *__name);

/* Wait for SEM being posted. */
extern int sem_wait (sem_t *__sem);

/* Similar to `sem_wait' but wait only until ABSTIME. */
extern int sem_timedwait (sem_t *__sem, const struct timespec *__abstime);

/* Test whether SEM is posted.  */
extern int sem_trywait (sem_t *__sem);

/* Post SEM.  */
extern int sem_post (sem_t *__sem) ;

/* Get current value of SEM and store it in *SVAL.  */
extern int sem_getvalue (sem_t *__sem, int *__sval);

#ifdef __cplusplus
}
#endif

#endif	/* semaphore.h */
