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


#ifndef _PAL_MACROS_H
#define _PAL_MACROS_H

#ifdef __cplusplus
extern "C" {
#endif

//for PAL_LOG prints
#include "pal.h"
#include "mbed-trace/mbed_trace.h"
#include "assert.h"
#include <limits.h>
/*! \file pal_macros.h
*  \brief PAL macros.
*   This file contains macros defined by PAL for constant values and network purposes.
*/

// Maximum integer types.
#define PAL_MAX_UINT8       0xFFU
#define PAL_MAX_UINT16      0xFFFFU
#define PAL_MAX_UINT32      0xFFFFFFFFUL
#define PAL_MAX_INT32       0x7FFFFFFFL
#define PAL_MIN_INT32       0x80000000L
#define PAL_MAX_UINT64      0xFFFFFFFFFFFFFFFFULL
#define PAL_MAX_INT64       0x7FFFFFFFFFFFFFFFLL

// Useful macros.



#if defined(__arm__) || defined(__IAR_SYSTEMS_ICC__) // Compile with ARMCC, GCC_ARM or IAR compilers.
    #define PAL_TARGET_POINTER_SIZE __sizeof_ptr
    #ifdef __BIG_ENDIAN
        #define PAL_COMPILATION_ENDIANITY 1 // Define PAL compilation endian (0 is little endian, 1 is big endian).
    #else
        #define PAL_COMPILATION_ENDIANITY 0 // Define PAL compilation endian (0 is little endian, 1 is big endian).
    #endif
#elif defined(__GNUC__) // Compiling with GCC.
    #define PAL_TARGET_POINTER_SIZE __SIZEOF_POINTER__
    #ifdef __BYTE_ORDER
        #if __BYTE_ORDER == __BIG_ENDIAN // If both are not defined it is TRUE!
            #define PAL_COMPILATION_ENDIANITY 1 // Define PAL compilation endian (0 is little endian, 1 is big endian).
        #elif __BYTE_ORDER == __LITTLE_ENDIAN
            #define PAL_COMPILATION_ENDIANITY 0// Define PAL compilation endian (0 is little endian, 1 is big endian).
        #else
            #error missing endiantiy defintion for GCC
        #endif
    #endif
#else
    #error neither ARM target compilers nor GCC used for compilation - not supported
#endif




#define PAL_MAX(a,b)            ((a) > (b) ? (a) : (b))

#define PAL_MIN(a,b)            ((a) < (b) ? (a) : (b))

#define PAL_DIVIDE_ROUND_UP(num, divider)           (((num) + (divider) - 1) / (divider))

#if PAL_COMPILATION_ENDIANITY == 1
#define BIG__ENDIAN 1
#elif PAL_COMPILATION_ENDIANITY == 0
#define LITTLE__ENDIAN 1
#else 
#error neither BIG__ENDIAN nor LITTLE__ENDIAN defined, cannot compile
#endif


// Endianity macros.
#ifdef LITTLE__ENDIAN

#define PAL_HTONS(x) (((((unsigned short)(x)) >> 8) & 0xff) | \
            ((((unsigned short)(x)) & 0xff) << 8))
#define PAL_NTOHS(x) (((((unsigned short)(x)) >> 8) & 0xff) | \
            ((((unsigned short)(x)) & 0xff) << 8) )
#define PAL_HTONL(x) ((((x)>>24) & 0xffL) | (((x)>>8) & 0xff00L) | \
            (((x)<<8) & 0xff0000L) | (((x)<<24) & 0xff000000L))
#define PAL_NTOHL(x) ((((x)>>24) & 0xffL) | (((x)>>8) & 0xff00L) | \
            (((x)<<8) & 0xff0000L) | (((x)<<24) & 0xff000000L))

#elif defined(BIG__ENDIAN)

#define PAL_HTONS(x) (x)
#define PAL_NTOHS(x) (x)
#define PAL_HTONL(x) (x)
#define PAL_NTOHL(x) (x)
#else
#error neither BIG__ENDIAN nor LITTLE__ENDIAN defined, cannot compile
#endif


#define PAL_GET_LOWER_8BITS(x) (x & 0xFF)
#define PAL_GET_THREAD_INDEX(x) (PAL_GET_LOWER_8BITS(x))

#define PAL_INVERSE_UINT16_BYTES( val ) \
    ( ((val) << 8) | (((val) & 0x0000FF00) >> 8))

#define PAL_INVERSE_UINT32_BYTES( val ) \
   ( ((val) >> 24) | (((val) & 0x00FF0000) >> 8) | (((val) & 0x0000FF00) << 8) | (((val) & 0x000000FF) << 24) )

#define PAL_INVERSE_UINT64_BYTES( val ) \
    ((PAL_INVERSE_UINT32_BYTES( ((val >> 16) >> 16)) &0xffffffff)  | ((((uint64_t)PAL_INVERSE_UINT32_BYTES(val & 0xffffffff))<<16)<<16)) 

/* Set of Macros similar to the HTONS/L, NTOHS/L ones but converting to/from little endian instead of big endian. */
#ifdef LITTLE__ENDIAN 
#define PAL_LITTLE_ENDIAN_TO_HOST_16BIT(x) (x)
#define PAL_LITTLE_ENDIAN_TO_HOST_32BIT(x) (x)
#define PAL_LITTLE_ENDIAN_TO_HOST_64BIT(x) (x)
#define PAL_HOST_TO_LITTLE_ENDIAN_16BIT(x) (x)
#define PAL_HOST_TO_LITTLE_ENDIAN_32BIT(x) (x)
#define PAL_HOST_TO_LITTLE_ENDIAN_64BIT(x) (x)




#elif defined(BIG__ENDIAN)
#define PAL_LITTLE_ENDIAN_TO_HOST_16BIT(x) (PAL_INVERSE_UINT16_BYTES(((uint16_t)x)))
#define PAL_LITTLE_ENDIAN_TO_HOST_32BIT(x) (PAL_INVERSE_UINT32_BYTES(((uint32_t)x)))
#define PAL_LITTLE_ENDIAN_TO_HOST_64BIT(x) (PAL_INVERSE_UINT64_BYTES(((uint64_t)x)))
#define PAL_HOST_TO_LITTLE_ENDIAN_16BIT(x) (PAL_INVERSE_UINT16_BYTES(((uint16_t)x)))
#define PAL_HOST_TO_LITTLE_ENDIAN_32BIT(x) (PAL_INVERSE_UINT32_BYTES(((uint32_t)x)))
#define PAL_HOST_TO_LITTLE_ENDIAN_64BIT(x) (PAL_INVERSE_UINT64_BYTES(((uint64_t)x)))

#else
#error neither BIG__ENDIAN nor LITTLE__ENDIAN defined, cannot compile
#endif


#define PAL_MODULE_INIT(INIT) INIT= 1
#define PAL_MODULE_DEINIT(INIT) INIT= 0

//!< Time utility values
#define PAL_MILISEC_TO_SEC(milisec) (milisec/1000)
#define PAL_ONE_SEC                   1
#define PAL_SECONDS_PER_MIN           60
#define PAL_MINUTES_PER_HOUR          60
#define PAL_HOURS_PER_DAY              24
#define PAL_SECONDS_PER_HOUR          PAL_MINUTES_PER_HOUR * PAL_SECONDS_PER_MIN
#define PAL_SECONDS_PER_DAY           PAL_HOURS_PER_DAY * PAL_SECONDS_PER_HOUR
#define PAL_DAYS_IN_A_YEAR            (365U)
#define PAL_RATIO_SECONDS_PER_DAY     480
#define PAL_MINIMUM_RTC_LATENCY_SEC       100
#define PAL_MINIMUM_STORAGE_LATENCY_SEC   500000
#define PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC      100000
#define PAL_MINIMUM_SOTP_BACKWARD_LATENCY_SEC      100
#define PAL_FEB_MONTH 2
#define PAL_MILLI_PER_SECOND 1000
#define PAL_NANO_PER_MILLI 1000000L
#define PAL_NANO_PER_SECOND 1000000000L
#define PAL_MILLI_TO_NANO(x) (((x) % PAL_MILLI_PER_SECOND) * PAL_NANO_PER_MILLI)
#define PAL_MILISEC_TO_SEC(milisec) (milisec/1000)
#define PAL_MIN_SEC_FROM_EPOCH   1487015542 ////at least 47 years passed from 1.1.1970 in seconds
#define PAL_MIN_RTC_SET_TIME    PAL_MIN_SEC_FROM_EPOCH
#define PAL_LAST_SAVED_TIME_LATENCY_SEC     2500000

//!< Define static function and inline function.
#if defined (__CC_ARM)          /* ARM compiler. */
	#define PAL_INLINE  __inline
#elif defined (__GNUC__)        /* GNU compiler. */
	#define PAL_INLINE  __attribute__((always_inline)) __inline
#else
	#define PAL_INLINE	//!< User should provide the compiler inline function command.
#endif

#define PAL_PRIVATE static

#if defined (__CC_ARM)          /* ARM compiler. */
#define PAL_PRAGMA(x)
#define PAL_DEPRECATED(x)
#else
#define PAL_PRAGMA(x) _Pragma (#x)
#define PAL_DEPRECATED(x) PAL_PRAGMA(message ("!!! PAL DEPRECATED CODE- " #x))
#endif

#ifdef DEBUG

#define PAL_MODULE_IS_INIT(INIT) if(!INIT) return PAL_ERR_NOT_INITIALIZED;


#else
#define PAL_MODULE_IS_INIT(INIT) (void)INIT

#endif //DEBUG

// Compile time assert.
#define PAL_ASSERT_STATIC(e) \
   do { \
      enum { assert_static__ = 1/(e) }; \
      } while (0)

#define PAL_UNUSED_ARG(x) (void)(x)





//for non recoverable errors
#define PAL_LOG_ASSERT( ARGS...) \
{ \
    tr_err(ARGS); \
	assert(0);\
}



#define PAL_LOG_ERR_FUNC  tr_err
#define PAL_LOG_WARN_FUNC tr_warn
#define PAL_LOG_INFO_FUNC tr_info
#define PAL_LOG_DBG_FUNC  tr_debug

// Little trick with mbed-trace error level is equal to function name handling the same level of log output
#define PAL_LOG_LEVEL_ERR  TRACE_LEVEL_ERROR
#define PAL_LOG_LEVEL_WARN TRACE_LEVEL_WARN
#define PAL_LOG_LEVEL_INFO TRACE_LEVEL_INFO
#define PAL_LOG_LEVEL_DBG  TRACE_LEVEL_DEBUG

#define PAL_LOG_ERR( ARGS...)   PAL_LOG_ERR_FUNC(ARGS);
#define PAL_LOG_WARN( ARGS...)  PAL_LOG_WARN_FUNC(ARGS);
#define PAL_LOG_INFO( ARGS...)  PAL_LOG_INFO_FUNC(ARGS);
#define PAL_LOG_DBG( ARGS...)   PAL_LOG_DBG_FUNC(ARGS);


#define PAL_LOG(LOG_LEVEL, ARGS...)  tracef(PAL_LOG_LEVEL_##LOG_LEVEL, "PAL" , ARGS);


#ifdef DEBUG
#ifdef VERBOSE
#define PAL_PRINTF( ARGS...) \
        #define PAL_PRINTF(fmt, ...) PAL_LOG(DBG, "%s:%d: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__);
#else
#define PAL_PRINTF( ARGS...) \
		PAL_LOG(DBG, ARGS);
#endif
#else
	#define PAL_PRINTF( ARGS...)
#endif

#define DEBUG_PRINT(ARGS...) PAL_PRINTF(ARGS)

#define PAL_PTR_ADDR_ALIGN_UINT8_TO_UINT32 __attribute__((aligned(4)))

#define PAL_INT32_BITS (sizeof(int32_t) * CHAR_BIT)

#ifdef DEBUG


#define PAL_VALIDATE_CONDITION_WITH_ERROR(condition, error) \
    {\
        if ((condition)) \
        { \
            PAL_LOG(ERR,"(%s,%d): Parameters  values is illegal\r\n",__FUNCTION__,__LINE__); \
            return error; \
        } \
    }
#define PAL_VALIDATE_ARGUMENTS(condition) PAL_VALIDATE_CONDITION_WITH_ERROR(condition,PAL_ERR_INVALID_ARGUMENT)

#else
#define PAL_VALIDATE_ARGUMENTS(condition) PAL_VALIDATE_ARG_RLZ(condition,PAL_ERR_INVALID_ARGUMENT)
#define PAL_VALIDATE_CONDITION_WITH_ERROR(condition, error) PAL_VALIDATE_ARG_RLZ(condition, error)
#endif


#define PAL_VALIDATE_ARG_RLZ(condition, error) \
{\
	if ((condition)) \
	{ \
		return error; \
	} \
}



#ifdef __cplusplus
}
#endif
#endif //_PAL_MACROS_H
