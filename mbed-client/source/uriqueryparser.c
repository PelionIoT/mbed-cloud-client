/*
 * Copyright (c) 2018 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include "assert.h"
#include "mbed-client/uriqueryparser.h"

// Use int return value instead of ssize_t since we don't have it for all platforms
int parse_query_parameter_value_from_uri(const char *uri, const char *parameter_name, const char **parameter_value)
{
    assert(uri);
    assert(parameter_name);
    assert(parameter_value);

    *parameter_value = NULL;

    char *value_ptr = strchr(uri, '?');
    if (value_ptr == NULL) {
        return -1;
    }

    // Skip '?'
    value_ptr++;

    return parse_query_parameter_value_from_query(value_ptr, parameter_name, parameter_value);
}

// Use int return value instead of ssize_t since we don't have it for all platforms
int parse_query_parameter_value_from_query(const char *query, const char *parameter_name, const char **parameter_value)
{
    assert(query);
    assert(parameter_name);
    assert(parameter_value);

    *parameter_value = NULL;
    const int param_name_len = strlen(parameter_name);
    const int query_len = strlen(query);

    if (param_name_len == 0 || query_len == 0) {
        return -1;
    }

    const char *value_ptr = query;

    do {
        value_ptr = strstr(value_ptr, parameter_name);

        // No match at all, then break
        if (!value_ptr) {
            break;
        }

        // Check that match was at the beginning or there is a & before the match
        if (!(value_ptr == query || *(value_ptr - 1) == '&')) {
            // Offset value_ptr past the match to find next one
            value_ptr += param_name_len;
            continue;
        }

        // Offset to after parameter name
        value_ptr += param_name_len;

        // Check that parameter was not at the end
        if (value_ptr >= query + query_len) {
            break;
        }

        // CHeck that there is an '=' after parameter name, continue if not as there might be
        // another parameter left
        if (*value_ptr != '=') {
            continue;
        }

        *parameter_value = ++value_ptr;
        break;

    } while (value_ptr);

    // If parameter found, calculate length of value either ending at an '&' or the end
    if (*parameter_value != NULL) {
        value_ptr = strchr(*parameter_value, '&');
        if (value_ptr) {
            return value_ptr - *parameter_value;
        }
        return strlen(*parameter_value);
    }
    return -1;
}
