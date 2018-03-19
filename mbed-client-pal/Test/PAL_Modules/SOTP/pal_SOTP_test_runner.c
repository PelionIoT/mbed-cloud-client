/*******************************************************************************
 * Copyright 2016, 2017 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

#include "unity.h"
#include "unity_fixture.h"
#include "test_runners.h"

extern palTestsStatusData_t palTestStatus;

TEST_GROUP_RUNNER(pal_SOTP)
{
    switch (palTestStatus.test) 
    {
    case -1:
    case PAL_TEST_SOTP_TEST_SW_HW_ROT:
        RUN_TEST_CASE(pal_SOTP, SW_HW_RoT);
    case PAL_TEST_SOTP_TEST_TIME_INIT:
        RUN_TEST_CASE(pal_SOTP, timeInit);
    case PAL_TEST_SOTP_TEST_RANDOM:
        RUN_TEST_CASE(pal_SOTP, random);
        break;
    default:
        PAL_PRINTF("This should not happen\r\n");
    }
}
