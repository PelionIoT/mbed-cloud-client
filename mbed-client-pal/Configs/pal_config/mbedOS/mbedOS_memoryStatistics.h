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
#ifndef PAL_MBEDOS_MEMORY_STATISTICS_H_

#include "mbedOS_default.h"

#ifndef MBED_HEAP_STATS_ENABLED
    #define MBED_HEAP_STATS_ENABLED 1
#endif 

#ifndef MBED_STACK_STATS_ENABLED
    #define MBED_STACK_STATS_ENABLED 1
#endif 

#ifndef PAL_MEMORY_STATISTICS
    #define PAL_MEMORY_STATISTICS 1
#endif 

#endif //PAL_MBEDOS_MEMORY_STATISTICS_H_