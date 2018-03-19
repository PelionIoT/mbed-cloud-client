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

#ifndef MANIFEST_MANAGER_FETCH_FIRMWARE_INFO_H
#define MANIFEST_MANAGER_FETCH_FIRMWARE_INFO_H


#include "arm_uc_mmConfig.h"
#include "update-client-common/arm_uc_common.h"

arm_uc_error_t ARM_UC_mmFetchFirmwareInfoFSM(uint32_t event);

#endif // MANIFEST_MANAGER_FETCH_FIRMWARE_INFO_H
