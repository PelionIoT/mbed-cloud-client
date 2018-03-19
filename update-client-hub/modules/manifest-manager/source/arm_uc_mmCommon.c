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

#include "update-client-manifest-manager/update-client-manifest-manager-context.h"

#include "arm_uc_mmCommon.h"
#include "arm_uc_mmConfig.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"

#include <string.h>

arm_uc_mmPersistentContext_t arm_uc_mmPersistentContext = { 0 };
const size_t arm_uc_mmDynamicContextSize = sizeof(arm_uc_mmContext_t);

#if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
volatile uint8_t arm_uc_mm_gDebugLevel = 10;
#else
volatile uint8_t arm_uc_mm_gDebugLevel = 0;
#endif
