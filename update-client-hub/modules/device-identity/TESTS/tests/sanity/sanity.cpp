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

#include <greentea-client/test_env.h>
#include <utest/utest.h>
#include <unity/unity.h>

#include "pal4life-device-identity/pal_device_identity.h"

using namespace utest::v1;

void print_guid(const arm_uc_guid_t* guid)
{
    for (size_t index = 0; index  < sizeof(arm_uc_guid_t); index++)
    {
        printf("%02X", ((uint8_t*)guid)[index]);
    }
    printf("\r\n");
}

void test_unit()
{
    arm_uc_guid_t guid = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    print_guid(&guid);
}

Case cases[] = {
    Case("test_init", test_unit)
};

Specification specification(cases, verbose_continue_handlers);

#if defined(TARGET_LIKE_MBED)
int main()
#elif defined(TARGET_LIKE_POSIX)
void app_start(int argc __unused, char** argv __unused)
#endif
{
    // Run the test specification
    Harness::run(specification);
}