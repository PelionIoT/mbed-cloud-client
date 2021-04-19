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

#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_PROFILE_MBED_CLIENT_LITE) && (ARM_UC_PROFILE_MBED_CLIENT_LITE == 1)

#include "update-client-common/arm_uc_hw_plat.h"
#include "update-client-common/arm_uc_utilities.h"
#include "update-client-common/arm_uc_error.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __linux__
#include <sys/reboot.h>
#endif

#if defined(TARGET_LIKE_MBED)
#define RESET_MASK_FOR_CORTEX_M_SERIES  0x5fa0004
volatile unsigned int *AIRCR_REG = (volatile unsigned int *)(
                                       0xE000ED0C);   //This register address is true for the Cortex M family
#endif

/**
 * @brief Issue a platform-specific Hard-reboot
 *
 */
void arm_uc_plat_reboot(void)
{
#if defined(TARGET_LIKE_MBED)
    *AIRCR_REG = RESET_MASK_FOR_CORTEX_M_SERIES;
    while (1); /* wait until reset */
#elif __linux__
    // Reboot the device
    reboot(RB_AUTOBOOT);
    while (1); /* wait until reset */
#endif
}

#endif
