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

#ifndef __PV_MACROS_H__
#define __PV_MACROS_H__

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ignore a pointer parameter */
#define PV_IGNORE_PARAM_PTR NULL

/* Ignore parameter value */
#define PV_IGNORE_PARAM_VAL 0

/* This parameter is temporarily muted or unused for good resons */
#define PV_UNUSED_PARAM(param) \
    (void)(param)

/* Variable used only for DEBUG targets (like prints or macros
*  which are effective only in debug mode) */
#define PV_DEBUG_USE(var) \
    PV_UNUSED_PARAM(var)


/* Compile time assertion (we do not have static_assert support). */
#define PV_ASSERT_CONCAT_(a, b) a##b
#define PV_ASSERT_CONCAT(a, b) PV_ASSERT_CONCAT_(a, b)
#define PV_CASSERT(cond, message) \
    enum { PV_ASSERT_CONCAT(assert_line_, __LINE__) = 1 / (int)(!!(cond)) }

/* Returns the amount of elements in an array. */
#define PV_ARRAY_LENGTH(array) (sizeof(array)/sizeof((array)[0]))

/*Returns number in range between max and min */
#define PV_NUMBER_LIMIT(number, max, min ) ((number % (max - min + 1)) + min)


/**
 * Returns the size of a member in a struct.
 */
#define PV_SIZEOF_MEMBER(struct_type, member_name) sizeof(((struct_type *)0)->member_name)

/**
 *  Checks alignment of val to uint32_t
*/
#ifndef SA_PV_PLAT_PC
#define PV_IS_ALIGNED(val) 		\
    ((val & ((sizeof(uint32_t) - 1))) ==  0)
#else
#define PV_IS_ALIGNED(val) 	 \
    ((sizeof(uint32_t) & ((sizeof(uint32_t) - 1))) ==  0)
#endif


/** Reads a uint32_t from a potentially unaligned uint8_t pointer.
 *   As we cannot know if unaligned access is allowed, using this approach is the
 *   only way to guarantee correct behavior.
 *
 *    @param buf	
 *
 *    @returns
 *	    32 bit number
 */
static inline uint32_t pv_read_uint32(const uint8_t *buf)
{
    uint32_t number;
    memcpy(&number, buf, sizeof(number));
    return number;
}



/** Reads a uint64_t from a potentially unaligned uint8_t pointer.
*     As we cannot know if unaligned access is allowed, using this approach is the
*     only way to guarantee correct behavior.
*
*    @param buf    
*
*    @returns
*        64 bit number
*/
static inline uint64_t pv_read_uint64(const uint8_t *buf)
{
    uint64_t number;
    memcpy(&number, buf, sizeof(number));
    return number;
}


/** Writes a uint32_t to a potentially unaligned uint8_t pointer.
 *    As we cannot know if unaligned access is allowed, using this approach is the
 *    only way to guarantee correct behavior.
 *
 *    @param buf
 *    @param number
 *
 */
static inline void pv_write_uint32(uint8_t *buf, uint32_t number)
{
    memcpy(buf, &number, sizeof(number));
}


/** Calculates the length of a string.
 * 
 *    @param str [in] - A pointer to an input string. If NULL, 0  will be returned.
 *                                                  
 *    @returns
 *        the number of characters in a string without counting the null termination character.
 *        There is no strnlen in libC. It's posix extension that also exists in mbed-os, but may not exist in other OS
 */
static inline uint32_t pv_str_n_len(const char* str, uint32_t max_size)
{
    uint32_t i = 0;
    if (str == NULL) {
        return 0;
    }

    while (i < max_size && str[i] != '\0') {
        i++;
    }

    return i;
}


/** Compares strings (source with target)
 * 
 *    @param str1 [in]  - First string to compare
 *    @param str2 [in]  - Second string to compare
 *    @param a_max_size [in]	- Max number of characters to compare
 *
 *    @returns
 *        true - if strings are identical.
 *        false -if strings are not identical
 */
static inline bool pv_str_equals(const char* str1, const char* str2, uint32_t a_max_size)
{
    uint32_t str_size = pv_str_n_len(str1, a_max_size);

    if (str_size == a_max_size) {
        return false;
    }
    if (str_size != pv_str_n_len(str2, a_max_size)) {
        return false;
    }

    if (strncmp(str1, str2, a_max_size) != 0) {
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif

#endif  // __PV_MACROS_H__

