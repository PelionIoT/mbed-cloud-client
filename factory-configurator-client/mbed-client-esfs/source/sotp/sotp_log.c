/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ----------------------------------------------------------- Includes -----------------------------------------------------------


#include "pal.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "sotp_log.h"

#if SOTP_LOG

#define LINE_SIZE 1024
typedef struct {
    uint64_t start_time;
    uint64_t end_time;
    uint32_t action_id;
    uint32_t dummy;
    char line[LINE_SIZE];
} sotp_log_entry_t;

#define MAX_ENTRIES 64
typedef struct {
    uint32_t num_entries;
    uint32_t curr_entry_ind;
    uint32_t ind_stack_ptr;
    uint32_t ind_stack[4];
    sotp_log_entry_t entries[MAX_ENTRIES];
} sotp_thr_log_t;

// Must be aligned to the size of native integer, otherwise atomic add may not work
static uint32_t action_id_ctr  __attribute__((aligned(8)));
#define MAX_NUMBER_OF_THREADS 9
static sotp_thr_log_t thr_logs[MAX_NUMBER_OF_THREADS];

// Initialize SOTP logs.
// Parameters :
// Return   : None.
void sotp_log_init(void)
{
    action_id_ctr = 0;
    memset(thr_logs, 0, sizeof(thr_logs));
}

// Create an SOTP log entry.
// Parameters :
// args     - [IN]   format (as in printf).
// args     - [IN]   arg list (as in printf) to log.
// Return   : None.
void sotp_log_create(char *fmt, ...)
{
    int thr = 0;
    sotp_thr_log_t *thr_log = &thr_logs[thr];
    sotp_log_entry_t *entry;
    uint32_t entry_ind;
    va_list args;
    uint32_t action_id;

    action_id = pal_osAtomicIncrement((int32_t *) &action_id_ctr, 1);

    if (thr_log->num_entries < MAX_ENTRIES) {
        thr_log->num_entries++;
    }

    entry_ind = thr_log->curr_entry_ind;
    thr_logs->ind_stack[thr_logs->ind_stack_ptr++] = entry_ind;
    thr_log->curr_entry_ind = (thr_log->curr_entry_ind + 1) % MAX_ENTRIES;
    entry = &thr_log->entries[entry_ind];
    entry->start_time = pal_osKernelSysTick();
    entry->action_id = action_id;

    va_start(args, fmt);
    vsnprintf(entry->line, LINE_SIZE, fmt, args);
    va_end(args);
}

// Append to an SOTP log entry.
// Parameters :
// args     - [IN]   format (as in printf).
// args     - [IN]   arg list (as in printf) to log.
// Return   : None.
void sotp_log_append(char *fmt, ...)
{
    int thr = 0;
    sotp_thr_log_t *thr_log = &thr_logs[thr];
    sotp_log_entry_t *entry;
    uint32_t entry_ind;
    va_list args;

    if (!thr_logs->ind_stack_ptr) {
        return;
    }

    entry_ind = thr_logs->ind_stack[thr_logs->ind_stack_ptr-1];
    entry = &thr_log->entries[entry_ind];
    va_start(args, fmt);
    vsnprintf(entry->line + strlen(entry->line), LINE_SIZE-strlen(entry->line), fmt, args);
    va_end(args);

}

// Finalize an SOTP log entry.
// Parameters :
// Return   : None.
void sotp_log_finalize(void)
{
    int thr = 0;
    sotp_thr_log_t *thr_log = &thr_logs[thr];
    sotp_log_entry_t *entry;
    uint32_t entry_ind;

    if (!thr_logs->ind_stack_ptr) {
        return;
    }
    entry_ind = thr_logs->ind_stack[--thr_logs->ind_stack_ptr];
    entry = &thr_log->entries[entry_ind];
    entry->end_time = pal_osKernelSysTick();
}

// Print SOTP log (sorted by start time).
// Parameters :
// Return   : None.
void sotp_log_print_log(void)
{
    int pending_logs;
    int log_inds[MAX_NUMBER_OF_THREADS];
    int i, thr;
    uint64_t earliest;
    sotp_log_entry_t *curr_entry, *entry_to_print;
    uint64_t ref_time;

    pending_logs = 0;
    ref_time = (uint64_t) -1;
    for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
        if (!thr_logs[i].num_entries) {
            log_inds[i] = -1;
            continue;
        }
        pending_logs++;
        if (thr_logs[i].num_entries < MAX_ENTRIES)
            log_inds[i] = 0;
        else
            log_inds[i] = thr_logs[i].curr_entry_ind;
        curr_entry = &thr_logs[i].entries[log_inds[i]];
        if (curr_entry->start_time && (curr_entry->start_time < ref_time)) {
            ref_time = curr_entry->start_time;
        }
    }

    while (pending_logs) {
        earliest = (uint64_t) -1;
        for (i = 0; i < MAX_NUMBER_OF_THREADS; i++) {
            if (log_inds[i] < 0)
                continue;
            curr_entry = &thr_logs[i].entries[log_inds[i]];
            if (curr_entry->start_time < earliest) {
                entry_to_print = curr_entry;
                earliest = curr_entry->start_time;
                thr = i;
            }
        }
        printf("%d (+%9ld-%9ld) #%9d %s\n",
                thr,
                entry_to_print->start_time - ref_time,
                entry_to_print->end_time?(entry_to_print->end_time - entry_to_print->start_time) : 0,
                entry_to_print->action_id,
                entry_to_print->line);
        ref_time = entry_to_print->start_time;
        log_inds[thr] = (log_inds[thr] + 1) % MAX_ENTRIES;
        if (log_inds[thr] == thr_logs[thr].curr_entry_ind) {
            log_inds[thr] = -1;
            pending_logs--;
        }
    }
}

#endif
