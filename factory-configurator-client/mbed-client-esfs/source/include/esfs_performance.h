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

#ifndef ESFS_SOURCE_INCLUDE_ESFS_PERFORMANCE_H_
#define ESFS_SOURCE_INCLUDE_ESFS_PERFORMANCE_H_

#include <stdint.h>

//#define ESFS_PERFOMANCE_TEST   // Allow enabling and disabling calls to performance. Define it on compilation

#define TITLE_MAX   30
#define PERFORMANCE_ARRAY_SIZE  100
typedef enum esfs_performance_type
{
        ESFS_PERFORMANCE_START,
        ESFS_PERFORMANCE_END
}esfs_performance_type_e;

typedef struct performance_record
{
    char title[TITLE_MAX+1];
    unsigned long mark;
    unsigned long total;
    esfs_performance_type_e type;
}performance_record_t;


#ifdef  ESFS_PERFOMANCE_TEST  // If not defined ESFS_PERFOMANCE_TEST functions will be removed

void print_performance();
void add_performance_mark(const char * title, esfs_performance_type_e type);



#else

#define print_performance()
#define add_performance_mark(title, type)

#endif

#endif /* ESFS_SOURCE_INCLUDE_ESFS_PERFORMANCE_H_ */

