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

#ifndef __ARM_UC_SOCKET_HELP_H__
#define __ARM_UC_SOCKET_HELP_H__

#include "update-client-common/arm_uc_common.h"

#include <stdbool.h>
#include <stdint.h>

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
bool arm_uc_http_socket_trim_value(arm_uc_buffer_t *buffer,
                                   const char *tag_buffer,
                                   uint32_t tag_size);

#endif // __ARM_UC_SOCKET_HELP_H__
