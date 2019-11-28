// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#if defined(ARM_UC_ENABLE) && (ARM_UC_ENABLE == 1)

#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "arm_uc_mmCommon.h"
#include "arm_uc_mmConfig.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"

#include <string.h>

// Initialisation with an enum silences a compiler warning for ARM ("188-D: enumerated type mixed with another type").
arm_uc_mmPersistentContext_t arm_uc_mmPersistentContext = { ARM_UC_MM_STATE_INVALID };
const size_t arm_uc_mmDynamicContextSize = sizeof(arm_uc_mmContext_t);

#endif
