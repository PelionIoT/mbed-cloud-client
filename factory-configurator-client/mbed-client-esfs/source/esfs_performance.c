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

#include <stdio.h>
#include <string.h>
#include "esfs_performance.h"

#ifdef  ESFS_PERFOMANCE_TEST // Allow disabling calls to performance

#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP         "esfs"  // Maximum 4 characters
#define TICKS_PER_MICROSEC  120 // FIXME Replace with pal_osKernelSysMilliSecTick when it will work

static performance_record_t performance_array[PERFORMANCE_ARRAY_SIZE]={{{0}, 0}};
static unsigned long performance_index = 0;

void print_performance()
{
unsigned long i;
char type_title[10];
    for (i=0;i<performance_index;i++)
    {
        if (performance_array[i].type == ESFS_PERFORMANCE_END)
        {
            strcpy(type_title,"end  ");
            tr_cmdline("\nPerformance %s %s %lu %lu",
                performance_array[i].title,
                type_title,
                performance_array[i].mark,
                performance_array[i].total);
        }
        else
        {
            strcpy(type_title,"start  ");
            tr_cmdline("\nPerformance %s %s %lu",
                performance_array[i].title,
                type_title,
                performance_array[i].total);
        }
    }
    performance_index = 0;
    tr_cmdline("\nIndex=%lu",performance_index);

}
void add_performance_mark(const char * title, esfs_performance_type_e type)
{
    unsigned long mark  = (unsigned long)(pal_osKernelSysTick()/TICKS_PER_MICROSEC);
    performance_array[performance_index].mark = mark;
    strncpy(performance_array[performance_index].title, title, TITLE_MAX);
    performance_array[performance_index].total=0;
    performance_array[performance_index].type=type;
    if (type == ESFS_PERFORMANCE_END)
    {
        // find the start mark
        for (unsigned long j=performance_index-1;j>=0;j--)
        {
            if (!strncmp(performance_array[j].title,title,TITLE_MAX))
            {
                performance_array[performance_index].total = mark - performance_array[j].mark;
                break;
            }
        }
    }

    if (performance_index++ >= (PERFORMANCE_ARRAY_SIZE-1))
    {
        print_performance();
    }
}


#endif  // ESFS_PERFOMANCE_TEST


