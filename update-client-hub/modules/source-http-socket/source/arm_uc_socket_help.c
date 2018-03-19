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

#include "arm_uc_socket_help.h"

#include <string.h>

/**
 * @brief Helper function for picking out values from an HTTP header.
 * @details The buffer is searched for the tag provided tag and if found the
 *          remainder of that line is MOVED to the front of the buffer and the
 *          size is shrunk to only include the detected value.
 *
 * @param buffer Pointer to an arm_uc_buffer_t.
 * @param tag_buffer Pointer to tag (a string).
 * @param tag_size Length of the tag.
 * @return True if tag was found. False otherwise.
 */
bool arm_uc_socket_trim_value(arm_uc_buffer_t* buffer,
                              const char* tag_buffer,
                              uint32_t tag_size)
{
    /* default return value */
    bool result = false;

    /* check for NULL pointers */
    if (buffer && buffer->ptr && tag_buffer)
    {
        /* search for the tag */
        uint32_t start = arm_uc_strnstrn(buffer->ptr,
                                         buffer->size,
                                         (const uint8_t*) tag_buffer,
                                         tag_size);

        /* check if index is within bounds */
        if (start < buffer->size)
        {
            /* remove tag */
            start += tag_size;

            /* remove ": " between tag and value */
            start += 2;

            /* search for the end of the line */
            uint32_t length = arm_uc_strnstrn(&(buffer->ptr[start]),
                                              buffer->size - start,
                                              (const uint8_t*) "\r",
                                              1);

            /* move value to front of buffer if all indices are within bounds */
            if ((start + length) < buffer->size)
            {
                /* memmove handles overlapping regions */
                memmove(buffer->ptr, &(buffer->ptr[start]), length);

                /* resize buffer */
                buffer->size = length;

                /* set return value to success */
                result = true;
            }
        }
    }

    return result;
}
