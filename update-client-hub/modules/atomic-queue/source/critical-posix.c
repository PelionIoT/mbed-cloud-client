// ----------------------------------------------------------------------------
// Copyright 2015-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#if defined(TARGET_LIKE_POSIX) && !defined(ATOMIC_QUEUE_USE_PAL)

// It's probably a better idea to define _POSIX_SOURCE in the target description
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

// Module include
#include "aq_critical.h"

static pthread_mutex_t *get_mutex()
{
    static int initialized = 0;
    static pthread_mutex_t Mutex;
    if (!initialized) {
        pthread_mutexattr_t Attr;
        pthread_mutexattr_init(&Attr);
        pthread_mutexattr_settype(&Attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&Mutex, &Attr);
        initialized = 1;
    }
    return &Mutex;
}

static volatile unsigned irq_nesting_depth = 0;
static sigset_t old_sig_set;

void aq_critical_section_enter()
{
    pthread_mutex_lock(get_mutex());
    if (++irq_nesting_depth == 1) {
        int rc;
        sigset_t full_set;
        rc = sigfillset(&full_set);
        assert(rc == 0);
        rc = sigprocmask(SIG_BLOCK, &full_set, &old_sig_set);
        assert(rc == 0);
        (void) rc;
    }
}

void aq_critical_section_exit(void)
{
    if (--irq_nesting_depth == 0) {
        int rc = sigprocmask(SIG_SETMASK, &old_sig_set, NULL);
        assert(rc == 0);
        (void) rc;
    }
    pthread_mutex_unlock(get_mutex());
}
#endif // defined(TARGET_LIKE_POSIX)
