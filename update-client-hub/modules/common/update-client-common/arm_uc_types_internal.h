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

#ifndef ARM_UPDATE_COMMON_TYPES_INTERNAL_H
#define ARM_UPDATE_COMMON_TYPES_INTERNAL_H

#include "arm_uc_types.h"
#include <stdint.h>

typedef enum {
    URI_SCHEME_NONE,
    URI_SCHEME_HTTP,
    URI_SCHEME_COAPS,
    URI_SCHEME_FILE
} arm_uc_uri_scheme_t;

typedef struct {
    uint32_t            size_max; // maximum size of the buffer
    uint32_t            size;     // index of the first empty byte in the buffer
    uint8_t            *ptr;      // pointer to buffer's memory
    arm_uc_uri_scheme_t scheme;     // URI type
    uint16_t            port;     // connection port
    char               *host;     // \0 terminated string with host name
    char               *path;     // \0 terminated string with resource path
} arm_uc_uri_t;

#define UC_COAPS_STRING  "coaps://"
#define UC_HTTP_STRING   "http://"
#define UC_FILE_STRING   "file://"

#endif // ARM_UPDATE_COMMON_TYPES_INTERNAL_H
