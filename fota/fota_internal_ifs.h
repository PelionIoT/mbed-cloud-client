// ----------------------------------------------------------------------------
// Copyright 2021 Pelion Ltd.
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

#ifndef __FOTA_INTERNAL_IFS_H_
#define __FOTA_INTERNAL_IFS_H_

#include "fota/fota_config.h"
#include "fota/fota_internal.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Resume Pelion FOTA update - internal
 *
 * If the update process is interrupted, the interal flow can call this function to resume the process.
  */
void fota_internal_resume(fota_resume_reason_e resume_reason);


#ifdef __cplusplus
}
#endif

#endif // (MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif //  __FOTA_INTERNAL_IFS_H_
