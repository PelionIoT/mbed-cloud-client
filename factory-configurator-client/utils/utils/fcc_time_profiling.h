// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifndef __FCC_TIME_PROFILING_H__
#define __FCC_TIME_PROFILING_H__

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include "mbed-trace/mbed_trace.h"
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifdef FCC_TIME_PROFILING

extern uint64_t fcc_gen_timer;
extern uint64_t fcc_bundle_timer;
extern uint64_t fcc_key_timer;
extern uint64_t fcc_certificate_timer;
extern uint64_t fcc_config_param_timer;
extern uint64_t fcc_certificate_chain_timer;
extern uint64_t fcc_generate_csr_timer;

void calculate_time(const char *label, size_t size, uint64_t ticks);


#define TRACE_GROUP     "fcc"

/**
* Init timer
*
* Note: when used for the first time, a delay of 1 sec added for ticks calculation. This delay should be subtracted
* from the time calculation
*/
#define FCC_INIT_TIMER(ticks) calculate_time("",0,pal_osKernelSysTick() - ticks)
/**
* Start timer
*/
#define FCC_SET_START_TIMER(ticks) ticks=pal_osKernelSysTick();

/**
* End timer, print label and the calculated result.
* If the label is string "size" should be 0, and if the label is buffer - "size" should be the size of buffer to print.
*
* Note: when used for the first time, a delay of 1 sec added for ticks calculation. This delay should be subtracted
* from the time calculation
*/
#define FCC_END_TIMER(label,size, ticks) calculate_time(label,size,pal_osKernelSysTick() - ticks)
/**
*  The function calculates time from started timer, prints the label as string or as buffer with size and the calulated time.
**/

#else 
#define FCC_INIT_TIMER(ticks)  do {} while (0)
#define FCC_SET_START_TIMER(ticks) do {} while (0)
#define FCC_END_TIMER(label, size, ticks) do {} while (0)
#endif
#ifdef __cplusplus
}
#endif

#endif  // __PV_MACROS_H__

