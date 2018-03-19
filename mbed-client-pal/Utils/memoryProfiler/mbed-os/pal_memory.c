/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
/*
 * pal_memory.c
 *
 *  Created on: Jun 26, 2017
 *      Author: pal
 */
#ifdef PAL_MEMORY_STATISTICS

#include "stdio.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed_stats.h"

#define TRACE_GROUP "PALM"
void printMemoryStats(void)
{
	mbed_stats_heap_t heap_stats;
	mbed_stats_heap_get(&heap_stats);

	mbed_stats_stack_t stack_stats;
	mbed_stats_stack_get(&stack_stats);
	tr_info("--- heap stats ---\n");

	tr_info("heap max size: %ld\n", heap_stats.max_size);
	tr_info("heap reserved size: %ld\n", heap_stats.reserved_size);
	tr_info("heap alloc cnt: %ld\n", heap_stats.alloc_cnt);
	tr_info("heap alloc fail cnt: %ld\n", heap_stats.alloc_fail_cnt);

	tr_info("--- stack stats ---\n");
	tr_info("stack max size: %ld\n", stack_stats.max_size);
	tr_info("stack reserved size: %ld\n", stack_stats.reserved_size);
	tr_info("stack stack cnt: %ld\n", stack_stats.stack_cnt);

}
#endif
