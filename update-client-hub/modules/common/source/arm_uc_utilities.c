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

#include "update-client-common/arm_uc_utilities.h"
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* lookup table for printing hexadecimal values */
const uint8_t arm_uc_hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
                                     };

/**
 * @brief Parse a uri string to populate a arm_uc_uri_t struct
 * @detail Format of uri scheme:[//]host[:port]/path
 *         [] means optional, path will always start with a '/'
 *
 * @param str Pointer to string containing URI.
 * @param size String length.
 * @param uri The arm_uc_uri_t struct to be populated
 * @return Error code.
 */
arm_uc_error_t arm_uc_str2uri(const uint8_t *buffer,
                              uint32_t buffer_size,
                              arm_uc_uri_t *uri)
{
    arm_uc_error_t result = (arm_uc_error_t) { ERR_INVALID_PARAMETER };

    if (buffer &&
            uri &&
            uri->ptr &&
            (buffer_size < uri->size_max)) {
        const uint8_t *str = buffer;
        uint8_t *colon = NULL;
        uint8_t *slash = NULL;
        uint32_t len = 0;
        uint8_t slash_count = 0;

        /* find scheme by searching for first colon */
        colon = memchr(str, ':', buffer_size);
        len = colon - str;

        if (len < uri->size_max) {
            /* copy scheme to temporary uri buffer and convert to lower case.
            */
            for (uint32_t index = 0; index < len; index++) {
                /* lower case characters have higher ASCII value */
                if (str[index] < 'a') {
                    uri->ptr[index] = str[index] + ('a' - 'A');
                } else {
                    uri->ptr[index] = str[index];
                }
            }

            /* copy ':' */
            uri->ptr[len] = str[len];

            /* convert scheme string to scheme type */
            if (memcmp(uri->ptr, "http:", 5) == 0) {
                uri->scheme = URI_SCHEME_HTTP;

                /* set default port based on scheme - can be overwritten */
                uri->port   = 80;
            } else if (memcmp(uri->ptr, "coaps:", 6) == 0) {
                uri->scheme = URI_SCHEME_COAPS;
                uri->port = 5683;
            } else if (memcmp(uri->ptr, "file:", 5) == 0) {
                uri->scheme = URI_SCHEME_FILE;
            } else {
                uri->scheme = URI_SCHEME_NONE;
            }

            /* only continue if scheme is supported */
            if (uri->scheme != URI_SCHEME_NONE) {
                /* strip leading '/', but at most two of them, since 'file://' URIs
                   might have a third '/' when specifying absolute paths */
                str = colon + 1;
                for (str += 1;
                        (str[0] == '/') && (str < (buffer + buffer_size) && (slash_count < 1));
                        ++str, ++slash_count);

                /* File URIs only have the 'path' component, so they need to
                   be handled separately */
                if (uri->scheme == URI_SCHEME_FILE) {
                    /* host part will be empty */
                    uri->ptr[0] = '\0';
                    uri->host = (char *)uri->ptr;

                    /* path is the whole data after "file://" */
                    len = buffer_size - (str - buffer);
                    memcpy(uri->ptr + 1, str, len);
                    uri->ptr[len + 1] = '\0';
                    uri->path = (char *)uri->ptr + 1;
                    uri->size = len + 2;

                    result = (arm_uc_error_t) { ERR_NONE };
                } else {
                    /* find separation between host and path */
                    slash = memchr(str, '/', buffer_size - (str - buffer));

                    if (slash != NULL) {
                        bool parsed = true;

                        /* find optional port */
                        colon = memchr(str, ':', buffer_size - (slash - buffer));

                        if (colon != NULL) {
                            uri->port = arm_uc_str2uint32(colon + 1,
                                                          buffer_size - (colon - buffer),
                                                          &parsed);
                            len = colon - str;
                        } else {
                            len = slash - str;
                        }

                        /* check */
                        if ((parsed == 1) && (len < uri->size_max)) {
                            /* copy host name to URI buffer */
                            memcpy(uri->ptr, str, len);

                            /* \0 terminate string */
                            uri->ptr[len] = '\0';

                            /* update length */
                            uri->size = len + 1;

                            /* set host pointer */
                            uri->host = (char *) uri->ptr;

                            /* find remaining path length */
                            str = slash;
                            len = arm_uc_strnlen(str, buffer_size - (str - buffer));

                            /* check */
                            if ((len > 0) && (len < (uri->size_max - uri->size))) {
                                /* copy path to URI buffer */
                                memcpy(&uri->ptr[uri->size], str, len);

                                /* set path pointer */
                                uri->path = (char *) &uri->ptr[uri->size];

                                /* \0 terminate string */
                                uri->ptr[uri->size + len] = '\0';

                                /* update length after path pointer is set */
                                uri->size += len + 1;

                                /* parsing passed all checks */
                                result = (arm_uc_error_t) { ERR_NONE };
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}

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
                         uint32_t little_length)
{
    uint32_t result = UINT32_MAX;

    /* Sanity check. Pointers are not NULL. The little buffer is smaller than
       the big buffer. The little buffer is not empty.
    */
    if (big_buffer &&
            little_buffer &&
            (big_length >= little_length) &&
            (little_length > 0)) {
        uint8_t little_hash = 0;
        uint8_t big_hash = 0;
        uint32_t little_length_m1 = little_length - 1;

        /* Prepare hashes. The last byte for the big hash is added in the
           comparison loop.
        */
        for (uint32_t index = 0; index < little_length_m1; index++) {
            little_hash ^= little_buffer[index];
            big_hash ^= big_buffer[index];
        }

        /* Add the last byte for the little hash. */
        little_hash ^= little_buffer[little_length_m1];

        /* Comparison loop. In each loop the big hash is updated and compared
           to the little hash. If the hash matches, a more thorough byte-wise
           comparison is performed. The complexity of the hash determines how
           often a collision occures and how often a full comparison is done.
        */
        for (uint32_t index = 0;
                index < (big_length - (little_length_m1));
                index++) {
            /* update hash */
            big_hash ^= big_buffer[index + (little_length_m1)];

            /* cursory check */
            if (little_hash == big_hash) {
                /* hash checks out do comprehensive check */
                uint32_t checks = 0;

                for (; checks < little_length; checks++) {
                    /* stop counting if bytes differ */
                    if (big_buffer[index + checks] != little_buffer[checks]) {
                        break;
                    }
                }

                /* check if all bytes matched */
                if (checks == little_length) {
                    /* save pointer and break loop */
                    result = index;
                    break;
                }
            }

            /* update hash - remove tail */
            big_hash ^= big_buffer[index];
        }
    }

    return result;
}

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
uint32_t arm_uc_strnlen(const uint8_t *buffer, uint32_t max_length)
{
    uint32_t length = 0;

    for (; length < max_length; length++) {
        if (buffer[length] == '\0') {
            break;
        }
    }

    return length;
}

/**
 * @brief Convert string to unsigned 32 bit integer.
 * @details Function tries to parse string as an unsigned 32 bit integer
 *          and return the value. The function expects the first byte to be an
 *          integer and will continue until:
 *           1. the buffer is empty
 *           2. the intermediate result is larger then UINT32_MAX
 *           3. the next byte is not a number
 *
 *          If a valid 32 bit unsigned integer is found the third parameter is
 *          set to true and the return value holds the parsed number. Otherwise,
 *          the third parameter will be false and the return value will be 0.
 *
 * @param buffer Pointer to string.
 * @param max_length Maximum buffer length.
 * @param success Pointer to boolean indicating whether the parsing was successful.
 * @return Parsed value. Only valid if success it true.
 */
uint32_t arm_uc_str2uint32(const uint8_t *buffer,
                           uint32_t max_length,
                           bool *success)
{
    uint64_t result = 0;
    bool found = false;

    /* default output and return status is 0 and false */
    uint32_t output = 0;

    if (success) {
        *success = false;
    }

    /* null pointer and length check */
    if (buffer && (max_length > 0)) {
        /* loop through string */
        for (uint32_t index = 0; index < max_length; index++) {
            /* check if character is a number */
            if (('0' <= buffer[index]) &&
                    (buffer[index] <= '9') &&
                    (result < UINT64_MAX)) {
                /* shift one decimal position and append next digit */
                result *= 10;
                result += buffer[index] - '0';

                /* found at least one integer, mark as found */
                found = true;
            } else {
                /* character is not a number, stop loop */
                break;
            }
        }

        /* set output and return value only if a valid number was found */
        if (found && (result <= UINT64_MAX)) {
            output = result;

            if (success) {
                *success = true;
            }
        }
    }

    return output;
}

static const uint8_t base64EncodeArray[65] = {MBED_CLOUD_UPDATE_BASE64_CHARSET};

uint8_t *ARM_UC_Base64Enc(uint8_t *buf, const uint32_t size, const arm_uc_buffer_t *bin)
{
    uint32_t partial = 0;
    const uint8_t *lastPos = buf + size;
    uint32_t i;
    uint32_t pad2 = (bin->size - bin->size % 3);
    uint32_t pad1 = (bin->size - bin->size % 3) + 1;
    for (i = 0; i < bin->size && buf <= lastPos - 4; i += 3) {
        partial = (bin->ptr[i] << 16);
        if (i < pad1) {
            partial = partial | (bin->ptr[i + 1] << 8);
        }
        if (i < pad2) {
            partial = partial | (bin->ptr[i + 2] << 0);
        }
        buf[0] = base64EncodeArray[(partial >> 18) & 0x3f];
        buf[1] = base64EncodeArray[(partial >> 12) & 0x3f];
        buf[2] = (i < pad1) ? base64EncodeArray[(partial >>  6) & 0x3f] : base64EncodeArray[64];
        buf[3] = (i < pad2) ? base64EncodeArray[(partial >>  0) & 0x3f] : base64EncodeArray[64];
        buf += 4;
    }
    buf[0] = 0;
    return buf;
}

uint32_t ARM_UC_Base64DecodeChar(uint8_t c)
{
    if (c == MBED_CLOUD_UPDATE_BASE64_CHARSET[64] || c == MBED_CLOUD_UPDATE_BASE64_CHARSET[0]) {
        return 0;
    }
    uint32_t idx = 0;
    int32_t i;
    for (i = 5; i >= 0; i--) {
        uint32_t tmpidx = idx | 1 << i;
        uint8_t ct = MBED_CLOUD_UPDATE_BASE64_CHARSET[tmpidx];
        if (c == ct) {
            return tmpidx;
        } else if (c > ct) {
            idx = tmpidx;
        }
    }
    return (uint32_t) -1;
}

void ARM_UC_Base64Dec(arm_uc_buffer_t *bin, const uint32_t size, const uint8_t *buf)
{
    uintptr_t optr = (uintptr_t)bin->ptr;
    const uint8_t  *iptr = buf;
    while ((uintptr_t)iptr + 4 < (uintptr_t) buf + size && optr + 1 < (uintptr_t)bin->ptr + bin->size_max) {
        uint8_t partial[3];
        uint8_t a = (ARM_UC_Base64DecodeChar(iptr[0]));
        uint8_t b = (ARM_UC_Base64DecodeChar(iptr[1]));
        uint8_t c = (ARM_UC_Base64DecodeChar(iptr[2]));
        uint8_t d = (ARM_UC_Base64DecodeChar(iptr[3]));
        uint8_t l = 3;
        if (d == MBED_CLOUD_UPDATE_BASE64_CHARSET[64]) {
            l--;
        }
        if (c == MBED_CLOUD_UPDATE_BASE64_CHARSET[64]) {
            l--;
        }
        partial[0] = ((a << 2) & 0xfc) | ((b >> 4) & 0x3);
        partial[1] = ((b << 4) & 0xf0) | ((c >> 2) & 0xf);
        partial[2] = ((c << 6) & 0xc0) | ((d >> 0) & 0x3f);
        memcpy((void *)optr, partial, l);
        iptr += 4;
        optr += l;
        if (d == MBED_CLOUD_UPDATE_BASE64_CHARSET[64]) {
            break;
        }
    }
    bin->size = optr - (uintptr_t)bin->ptr;
}

size_t arm_uc_calculate_full_uri_length(const arm_uc_uri_t *uri)
{

    size_t scheme_length = 0;

    if (uri->scheme == URI_SCHEME_COAPS) {
        scheme_length = strlen(UC_COAPS_STRING) + 1;
    } else if (uri->scheme == URI_SCHEME_HTTP) {
        scheme_length = strlen(UC_HTTP_STRING) + 1;
    } else if (uri->scheme == URI_SCHEME_FILE) {
        scheme_length = strlen(UC_FILE_STRING) + 1;
    } else {
        return 0; // Not supported scheme
    }

    return (uri->size +
            strlen(uri->path) +
            scheme_length);
}
