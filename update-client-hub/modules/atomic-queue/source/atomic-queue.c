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

#include "atomic-queue/atomic-queue.h"
#include "atomic.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CORE_UTIL_ASSERT_MSG(test, msg)


int aq_element_take(struct atomic_queue_element *e, void *ctx)
{
    if (!e) { return ATOMIC_QUEUE_NULL_ELEMENT;}
    if (!ctx) { return ATOMIC_QUEUE_INVALID_CONTEXT;}
    // Duplicate element check using lock
    uintptr_t lock; // This is initialized in the do/while loop.
    // Check/obtain a lock on the element.
    do {
        lock = e->lock;
        if (lock) {
            return ATOMIC_QUEUE_DUPLICATE_ELEMENT;
        }
    } while (!aq_atomic_cas_uintptr(&e->lock, lock, (uintptr_t)ctx));
    return ATOMIC_QUEUE_SUCCESS;
}

int aq_element_release(struct atomic_queue_element *e, void **ctx)
{
    if (!e) { return ATOMIC_QUEUE_NULL_ELEMENT;}
    if (!ctx) { return ATOMIC_QUEUE_INVALID_CONTEXT;}
    *ctx = (void *) e->lock;
    e->lock = 0;
    return ATOMIC_QUEUE_SUCCESS;
}

int aq_push_tail(struct atomic_queue *q, struct atomic_queue_element *e)
{
    CORE_UTIL_ASSERT_MSG(q != NULL, "null queue used");
    if (!e) { return ATOMIC_QUEUE_NULL_ELEMENT;}
    if (q == NULL) {
        return ATOMIC_QUEUE_NULL_QUEUE;
    }

    do {
        e->next = q->tail;
    } while (!aq_atomic_cas_uintptr((uintptr_t *)&q->tail, (uintptr_t)e->next, (uintptr_t)e));

    return ATOMIC_QUEUE_SUCCESS;
}

struct atomic_queue_element *aq_pop_head(struct atomic_queue *q)
{
    CORE_UTIL_ASSERT_MSG(q != NULL, "null queue used");
    if (q == NULL) {
        return NULL;
    }
    struct atomic_queue_element *current;
    int fail = AQ_ATOMIC_CAS_DEREF_VALUE;
    while (fail != AQ_ATOMIC_CAS_DEREF_SUCCESS) {
        // Set the element reference pointer to the tail pointer
        struct atomic_queue_element *volatile *px = &q->tail;
        if (*px == NULL) {
            return NULL;
        }
        fail = AQ_ATOMIC_CAS_DEREF_VALUE;
        while (fail == AQ_ATOMIC_CAS_DEREF_VALUE) {
            fail = aq_atomic_cas_deref_uintptr((uintptr_t *volatile *)px,
                                               (uintptr_t **)&current,
                                               (uintptr_t) NULL,
                                               NULL,
                                               offsetof(struct atomic_queue_element, next));
            if (fail == AQ_ATOMIC_CAS_DEREF_VALUE) {
                // Detect a loop to the tail of the queue
                if (current->next == q->tail) {
                    return NULL;
                }
                px = &current->next;
            }
        }
    }

    return current;
}


int aq_empty(struct atomic_queue *q)
{
    return q->tail == NULL;
}

unsigned aq_count(struct atomic_queue *q)
{
    unsigned x;
    struct atomic_queue_element *volatile e;
    if (aq_empty(q)) {
        return 0;
    }
    e = q->tail;
    for (x = 1; e->next != NULL; x++, e = e->next) {
        if (e->next == q->tail) {
            return (unsigned) - 1;
        }
    }
    return x;
}

void aq_initialize_element(struct atomic_queue_element *e)
{
    if (!e) { return;}
    e->lock = 0;
    e->next = NULL;
}
