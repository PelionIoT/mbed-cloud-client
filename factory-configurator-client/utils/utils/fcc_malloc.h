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

#ifndef __FCC_MALLOC_H__
#define __FCC_MALLOC_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

   
/**
* Allocate the requested amount of bytes and log heap statistics.
* - It is assumed FCC running in a single thread (no thread safety)
* - This function does not allows re-entrance
*
* @param size The amount of bytes to allocate on the heap memory
*
* @returns
*     If allocation succeeded - a valid pointer to the beginning of the allocated heap memory
*     If allocation failed - a NULL pointer will be returned
*/
void *fcc_malloc(size_t size);

/**
* Free the heap bytes followed by the given pointer and log heap statistics.
* - It is assumed FCC running in a single thread (no thread safety)
* - This function does not allows re-entrance
*
* @param ptr A pointer to the beginning of bytes allocated on the heap memory
*/
void fcc_free(void *ptr);

#ifndef FCC_MEM_STATS_ENABLED
#define fcc_malloc(size) malloc( (size) )
#define fcc_free(ptr) free( (ptr) )
#endif

#ifdef __cplusplus
}
#endif

#endif
