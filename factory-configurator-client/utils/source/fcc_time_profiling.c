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


#include "fcc_time_profiling.h"

#ifdef FCC_TIME_PROFILING

uint64_t fcc_gen_timer = 0;
uint64_t fcc_bundle_timer = 0;
uint64_t fcc_key_timer = 0;
uint64_t fcc_certificate_timer = 0;
uint64_t fcc_config_param_timer = 0;
uint64_t fcc_certificate_chain_timer = 0;
uint64_t fcc_generate_csr_timer = 0;


/**
*  The function calculates time from started timer, prints the label as string or as buffer with size and the calulated time.
**/

void calculate_time(const char *label, size_t size, uint64_t ticks)
{
    static double ticks_persecond = 0.0;
    static double ticks_permillisecond = 0.0;
    static double ticks_permicrosecond = 0.0;

    // Since the tick conversion to time functions on some of the reference platforms give incorrect results,
    // we use pal_osDelay() to estimate how many ticks per second. We do this once and then base all
    // subsequent calculations on the values that we store in static variables.
    // For new platforms the accuracy of pal_osDelay() should be verified before accepting the time results.
    if (ticks_persecond == 0.0)
    {
        // Calculate how many ticks per second
        uint64_t tick1 = pal_osKernelSysTick();
        // One second delay
        pal_osDelay(1000);
        uint64_t tick2 = pal_osKernelSysTick();
        ticks_persecond = tick2 - tick1;
        ticks_permillisecond = ticks_persecond / 1000.0;
        ticks_permicrosecond = ticks_persecond / 1000000.0;
    }
    if (size == 0) {
        //Print string
        mbed_tracef(TRACE_LEVEL_ERROR, TRACE_GROUP, "%s: %20lu ticks, %10.2lf milli, %10.2lf micro\n", (char*)label, (long unsigned int)ticks, (double)(ticks / ticks_permillisecond), (double)(ticks / ticks_permicrosecond));
    }  else {
        //Print buffer with size "size"
        mbed_tracef(TRACE_LEVEL_ERROR, TRACE_GROUP, "%.*s: %20lu ticks, %10.2lf milli, %10.2lf micro\n",size, label, (long unsigned int)ticks, (double)(ticks / ticks_permillisecond), (double)(ticks / ticks_permicrosecond));
    }

}


#endif

