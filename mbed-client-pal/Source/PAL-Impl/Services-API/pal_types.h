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


#ifndef _PAL_TYPES_H
#define _PAL_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#if defined __cplusplus && !defined __STDC_FORMAT_MACROS
    #define UNDEF__STDC_FORMAT_MACROS
    #define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#ifdef UNDEF__STDC_FORMAT_MACROS
    #undef UNDEF__STDC_FORMAT_MACROS
    #undef __STDC_FORMAT_MACROS
#endif
#include <stdlib.h>

/*! \file pal_types.h
*  \brief PAL types.
*   This file contains PAL generic types.
*/


#define NULLPTR 0

#define PAL_INVALID_THREAD	0xFFFFFFFF

typedef int32_t palStatus_t;

typedef struct _palBuffer_t
{
    uint32_t  maxBufferLength;
    uint32_t  bufferLength;
    uint8_t *buffer;
} palBuffer_t;

typedef struct _palConstBuffer_t
{
    const uint32_t  maxBufferLength;
    const uint32_t  bufferLength;
    const uint8_t *buffer;
} palConstBuffer_t;

typedef struct sotpAreaData
{
	uint32_t address;   /*\brief  the address of the starting sector for the given area*/
	size_t	 size;		/*\brief  the size of the area*/
}palSotpAreaData_t;


#ifdef __cplusplus
}
#endif
#endif //_PAL_TYPES_H
