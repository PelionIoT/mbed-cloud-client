// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef ARM_UPDATE_COMMON_UTILITIES_H
#define ARM_UPDATE_COMMON_UTILITIES_H

#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_error.h"
#include <string.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARM_UC_util_min(A,B)\
    ((A) < (B) ? (A) : (B))

/* lookup table for printing hexadecimal characters. */
extern const uint8_t arm_uc_hex_table[16];

/**
 * @brief Parse a uri string to populate a arm_uc_uri_t struct
 * @detail Format of uri scheme:[//]host[:port]/path
 *         [] means optional, path will always start with a '/'
 *
 * @param str Pointer to string containing URI.
 * @param size String length.
 * @param uri The arm_uc_uri_t struct to be populated
 */
arm_uc_error_t arm_uc_str2uri(const uint8_t *str, uint32_t size, arm_uc_uri_t *uri);

/**
 * @brief Find substring inside string.
 * @details The size of both string and substring is explicitly passed so no
 *          assumptions are made about NULL termination.
 *
 * @param big_buffer Pointer to the string to be searched.
 * @param big_length Length of the string to be searched.
 * @param little_buffer Pointer to the substring being searched for.
 * @param little_length Length of the substring being searched for.
 * @return Index to where the substring was found inside the string. If the
 *         string doesn't contain the subtring, UINT32_MAX is returned.
 */
uint32_t arm_uc_strnstrn(const uint8_t *big_buffer,
                         uint32_t big_length,
                         const uint8_t *little_buffer,
                         uint32_t little_length);

/**
 * @brief Find string length.
 * @details Custom implementation of strnlen which is a GNU extension.
 *          Returns either the string length or max_length.
 *
 * @param buffer Pointer to string.
 * @param max_length Maximum buffer length.
 *
 * @return String length or max_length.
 */
uint32_t arm_uc_strnlen(const uint8_t *buffer, uint32_t max_length);

/**
 * @brief Convert string to unsigned 32 bit integer.
 * @details Function tries to parse string as an unsigned 32 bit integer
 *          and return the value. The function will set the third parameter
 *          to true if the parsing was successful.
 *
 * @param buffer Pointer to string.
 * @param max_length Maximum buffer length.
 * @param success Pointer to boolean indicating whether the parsing was successful.
 * @return Parsed value. Only valid if success it true.
 */
uint32_t arm_uc_str2uint32(const uint8_t *buffer,
                           uint32_t max_length,
                           bool *success);

/**
 * @brief Calculate CRC 32
 *
 * @param buffer Input array.
 * @param length Length of array in bytes.
 *
 * @return 32 bit CRC.
 */
uint32_t arm_uc_crc32(const uint8_t *buffer, uint32_t length);

/**
 * @brief Parse 4 byte array into uint32_t
 *
 * @param input 4 byte array.
 * @return uint32_t
 */
uint32_t arm_uc_parse_uint32(const uint8_t *input);

/**
 * @brief Parse 8 byte array into uint64_t
 *
 * @param input 8 byte array.
 * @return uint64_t
 */
uint64_t arm_uc_parse_uint64(const uint8_t *input);

/**
 * @brief Write uint32_t to array.
 *
 * @param buffer Pointer to buffer.
 * @param value Value to be written.
 */
void arm_uc_write_uint32(uint8_t *buffer, uint32_t value);

/**
 * @brief Write uint64_t to array.
 *
 * @param buffer Pointer to buffer.
 * @param value Value to be written.
 */
void arm_uc_write_uint64(uint8_t *buffer, uint64_t value);

/**
 * @brief Do a shallow copy of a buffer.
 * @details Copies each field of a buffer from `src` to `dest`. This creates another reference to the buffer that
 *          backs `src` and drops any reference to a buffer that backs `dest`.
 *
 * @param[out] dest Pointer to a buffer structure that will receive a reference to the buffer that backs `src`
 * @param[in] src Pointer to a buffer to copy into dest
 */
static inline void ARM_UC_buffer_shallow_copy(arm_uc_buffer_t *dest, arm_uc_buffer_t *src)
{
    dest->size_max = src->size_max;
    dest->size     = src->size;
    dest->ptr      = src->ptr;
}

/**
 * @brief Do a deep copy of a buffer.
 * @details Copies the content of `src->ptr` to `dest->ptr`
 * If the space used in the source memory, referenced by the source buffer, is less than the maximum space available in
 * the destination memory, referenced by the destination buffer, copies the source into the destination.
 *
 * @param[out] dest Pointer to a buffer structure that references destination memory
 * @param[in] src Pointer to a buffer that references the data to copy into the destination memory
 * @retval MFST_ERR_SIZE when the source size is larger than the destination's maximum size
 * @retval MFST_ERR_NULL_PTR when any expected pointer is NULL
 * @retval MFST_ERR_NONE on success
 */
static inline arm_uc_error_t ARM_UC_buffer_deep_copy(arm_uc_buffer_t *dest, arm_uc_buffer_t *src)
{
    ARM_UC_INIT_ERROR(retval, MFST_ERR_NULL_PTR);

    /* NULL pointer check */
    if (dest &&
            dest->ptr &&
            src &&
            src->ptr) {
        /* destination buffer is large enough */
        if (src->size <= dest->size_max) {
            /* copy content and set new size */
            memcpy(dest->ptr, src->ptr, src->size);
            dest->size = src->size;

            ARM_UC_CLEAR_ERROR(retval);
        } else {
            ARM_UC_SET_ERROR(retval, MFST_ERR_SIZE);
        }
    } else {
        ARM_UC_SET_ERROR(retval, MFST_ERR_NULL_PTR);
    }

    return retval;
}

uint32_t ARM_UC_BinCompareCT(const arm_uc_buffer_t *a, const arm_uc_buffer_t *b);
uint8_t *ARM_UC_Base64Enc(uint8_t *buf, const uint32_t size, const arm_uc_buffer_t *bin);
void ARM_UC_Base64Dec(arm_uc_buffer_t *bin, const uint32_t size, const uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif // ARM_UPDATE_COMMON_UTILITIES_H
