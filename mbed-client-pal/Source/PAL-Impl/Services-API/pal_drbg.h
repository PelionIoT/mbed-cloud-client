/*******************************************************************************
 * Copyright 2016-2018 ARM Ltd.
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


#ifndef _PAL_DRBG_H
#define _PAL_DRBG_H

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "pal.h" //added for PAL_INITIAL_RANDOM_SIZE value

/*! \file pal_dbrg.h
*  \brief PAL DBRG.
*   This file contains the real-time OS APIs and is a part of the PAL service API.
*   It provides thread, timers, semaphores, mutexes and memory pool management APIs.
*   Random API is also provided.  
*/


/*! Generate random number into given buffer with given size in bytes.
*
* @param[out] randomBuf A buffer to hold the generated number.
* @param[in] bufSizeBytes The size of the buffer and the size of the required random number to generate.
*
\note `pal_init()` MUST be called before this function
\return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes);

/*! Generate a 32-bit random number.
*
* @param[out] random A 32-bit buffer to hold the generated number.
*
\note `pal_init()` MUST be called before this function.
\return PAL_SUCCESS on success, a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_osRandom32bit(uint32_t *randomInt);


#ifdef __cplusplus
}
#endif
#endif //_PAL_DRBG_H
