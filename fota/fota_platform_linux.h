// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef __FOTA_PLATFORM_LINUX_H_
#define __FOTA_PLATFORM_LINUX_H_

#include "fota/fota_base.h"

#if MBED_CLOUD_CLIENT_FOTA_ENABLE

#ifdef __cplusplus
extern "C" {
#endif

#include "fota_candidate.h"

int fota_linux_candidate_iterate(fota_candidate_iterate_callback_info *info);
int fota_linux_init();

#ifdef __cplusplus
}
#endif
#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
#endif // __FOTA_PLATFORM_LINUX_H_
