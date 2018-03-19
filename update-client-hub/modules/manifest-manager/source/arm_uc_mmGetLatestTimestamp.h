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

#ifndef ARM_UC_MM_GET_LATEST_TIMESTAMP_H
#define ARM_UC_MM_GET_LATEST_TIMESTAMP_H

#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"

arm_uc_error_t getLatestManifestTimestamp(uint64_t *ts, arm_uc_buffer_t* key);
arm_uc_error_t getLatestManifestTimestampFSM(uint32_t event);

#endif // ARM_UC_MM_GET_LATEST_TIMESTAMP_H
