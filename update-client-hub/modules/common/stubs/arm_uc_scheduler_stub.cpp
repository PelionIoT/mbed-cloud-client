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

#include "update-client-common/arm_uc_common.h"
#include "utest/utest.h"
#include "utest/utest_shim.h"
#include "equeue/equeue.h"


using namespace utest::v1;
extern equeue_t evq;


volatile uint32_t _postCallback_event = 0;
bool POSTCALLBACK_DONE = false;

void post_callback(void *)
{
    printf("post_callback\n");
    POSTCALLBACK_DONE = true;

    Harness::validate_callback();

}

bool ARM_UC_PostCallback(arm_uc_callback_t *_storage,
                         void (*_callback)(uint32_t),
                         uint32_t _parameter)
{
    printf("STUBBED ARM_UC_PostCallback parameter:; %d\n", _parameter);
    bool success = true;

    _postCallback_event = _parameter;


    return success;
}

