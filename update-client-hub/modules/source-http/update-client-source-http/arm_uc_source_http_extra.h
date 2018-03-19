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

#ifndef __UPDATE_CLIENT_SOURCE_HTTP_EXTRA_H__
#define __UPDATE_CLIENT_SOURCE_HTTP_EXTRA_H__

#include "update-client-common/arm_uc_common.h"

#include <stdint.h>

/**
 * @brief Set URI location for the default manifest.
 * @details The default manifest is polled regularly and generates a
 *          notification upon change. The URI struct and the content pointer to
 *          must be valid throughout the lifetime of the application.
 *
 * @param uri URI struct with manifest location.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_SetDefaultManifestURL(arm_uc_uri_t* uri);

/**
 * @brief Set polling interval for notification generation.
 * @details The default manifest location is polled with this interval.
 *
 * @param seconds Seconds between each poll.
 * @return Error code.
 */
arm_uc_error_t ARM_UCS_SetPollingInterval(uint32_t seconds);

/**
 * @brief Main function for the Source.
 * @details This function will query the default manifest location and generate
 *          a notification if it has changed since the last time it was checked.
 *          The number of queries generated is bound by the polling interval.
 *
 *          This function should be used on systems with timed callbacks.
 *
 * @param buffer arm_uc_buffer_t for storing HTTP header during hash check.
 * @return Seconds until the next polling interval.
 */
uint32_t ARM_UCS_CallMultipleTimes(arm_uc_buffer_t* buffer);


typedef struct _ARM_UCS_HTTPLinuxExtra_t
{
    arm_uc_error_t (*SetDefaultManifestURL)(arm_uc_uri_t* uri);
    arm_uc_error_t (*SetPollingInterval)(uint32_t seconds);
    uint32_t (*CallMultipleTimes)(arm_uc_buffer_t* buffer);
} ARM_UCS_HTTPSourceExtra_t;

extern ARM_UCS_HTTPSourceExtra_t ARM_UCS_HTTPSourceExtra;

#endif // __UPDATE_CLIENT_SOURCE_HTTP_EXTRA_H__
