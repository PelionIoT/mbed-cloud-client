// ----------------------------------------------------------------------------
// Copyright 2015-2017 ARM Ltd.
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

#include <assert.h>
#include "ns_types.h"
#include "platform/arm_hal_random.h"
#include "pal.h"

void arm_random_module_init(void)
{
    palStatus_t status = pal_init();
    assert(status == PAL_SUCCESS);
}

uint32_t arm_random_seed_get(void)
{
    uint32_t result = 0;
    palStatus_t status = pal_osRandom32bit(&result);
    assert(status == PAL_SUCCESS);
    return result;
}
