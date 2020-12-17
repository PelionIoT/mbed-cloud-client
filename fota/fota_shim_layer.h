// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#ifndef __FOTA_SHIM_LAYER_H_
#define __FOTA_SHIM_LAYER_H_

#include "fota/fota_base.h"

#ifdef FOTA_SHIM_LAYER

#define ARM_UCCC_REQUEST_INVALID                      117
#define ARM_UCCC_REQUEST_DOWNLOAD                     118
#define ARM_UCCC_REQUEST_INSTALL                      119

#define ARM_UCCC_REJECT_REASON_UNAUTHORIZED           120
#define ARM_UCCC_REJECT_REASON_UNAVAILABLE            121

#define ARM_UC_HUB_Uninitialize()


typedef void (*auth_handler_t)(int32_t request);
typedef void (*priority_auth_handler_t)(int32_t request, uint64_t priority);
typedef void (*progress_handler_t)(uint32_t progress, uint32_t total);

void fota_shim_set_auth_handler(auth_handler_t handler);
void fota_shim_set_auth_handler(priority_auth_handler_t handler);
void fota_shim_set_progress_handler(progress_handler_t handler);

#endif  // FOTA_SHIM_LAYER

#endif  // __FOTA_SHIM_LAYER_H_
