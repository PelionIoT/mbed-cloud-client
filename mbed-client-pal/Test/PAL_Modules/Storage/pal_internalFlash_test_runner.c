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


TEST_GROUP_RUNNER(pal_internalFlash)
{
#ifndef PAL_SKIP_TEST_MODULE_INTERNALFLASH
    RUN_TEST_CASE(pal_internalFlash, BasicTest);
    RUN_TEST_CASE(pal_internalFlash, NegativeTest);
#endif
}
