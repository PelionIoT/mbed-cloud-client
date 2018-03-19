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
/* Logging macros */

#ifndef __MBED_TRACE_HELPER_H__
#define __MBED_TRACE_HELPER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
/**
* Function used in mbed-trace to set trace print
*/
void mbed_trace_helper_print(const char* format);
/**
* Function used in mbed-trace to set wait mutex function
*/
void mbed_trace_helper_mutex_wait( void );
/**
* Function used in mbed-trace to set release mutex function
*/
void mbed_trace_helper_mutex_release( void );
/**
* This function creates mutex
*/
bool mbed_trace_helper_create_mutex( void );
/**
* Deletes mutex
*/
void mbed_trace_helper_delete_mutex(void);
/**
* Check activated trace level according to MBED_TRACE_MAX_LEVEL and used level in mbed_trace_config_set.
* In case the activated level is higher then MBED_TRACE_MAX_LEVEL, the function prints warning.
*/
uint8_t mbed_trace_helper_check_activated_trace_level( void );
/**
* The function calls to configuration functions of mbed_trace_helper according to passed parameters and initializes mbed-trace
*/
bool mbed_trace_helper_init(uint8_t config, bool is_mutex_used);
/**
* The function terminats thred and mbed-trace
*/
void mbed_trace_helper_finish( void );
#ifdef __cplusplus
}
#endif
#endif /*__TRACE_HELPER_H__*/

