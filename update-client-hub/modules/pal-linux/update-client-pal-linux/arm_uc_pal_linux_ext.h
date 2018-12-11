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

#ifndef ARM_UC_PAL_LINUX_EXT_H
#define ARM_UC_PAL_LINUX_EXT_H

#include "update-client-paal/arm_uc_paal_update_api.h"

/**
 * @brief Write a manifest to a file.
 * @param location Storage location ID.
 * @param buffer Buffer that contains the manifest.
 * @return Returns ERR_NONE if the manifest was written.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
arm_uc_error_t ARM_UC_PAL_Linux_WriteManifest(uint32_t location,
                                              const arm_uc_buffer_t *manifest);

#endif // ARM_UC_PAL_LINUX_H
