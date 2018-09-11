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

#ifndef ARM_UC_HUB_ERROR_HANDLER_H
#define ARM_UC_HUB_ERROR_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "update_client_hub_state_machine.h"

#include "update-client-common/arm_uc_common.h"

void ARM_UC_HUB_AddErrorCallbackInternal(void (*callback)(int32_t error));

extern void ARM_UC_HUB_ErrorHandler(int32_t error, arm_uc_hub_state_t state);

#ifdef __cplusplus
}
#endif

#endif // ARM_UC_HUB_ERROR_HANDLER_H
