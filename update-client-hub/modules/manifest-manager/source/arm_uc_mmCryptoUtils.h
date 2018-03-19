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

#ifndef MANIFEST_MANAGER_CRYPTO_FSM_H
#define MANIFEST_MANAGER_CRYPTO_FSM_H

#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"


arm_uc_error_t ARM_UC_mmValidateManifestHash(arm_uc_buffer_t* buffer);
arm_uc_error_t ARM_UC_mmValidateSignature(arm_uc_mm_validate_signature_context_t* ctx,
                                          void (*applicationEventHandler)(uint32_t),
                                          arm_uc_buffer_t* buffer,
                                          arm_uc_buffer_t* certBuffer,
                                          uint32_t sigIndex);
arm_uc_error_t ARM_UC_mmGetManifestHashFromBin(arm_uc_buffer_t* buffer, arm_uc_buffer_t* hash);
void ARM_UC_mmGetFirmwareHashFromBin(arm_uc_buffer_t* manifest, arm_uc_buffer_t* hash);


struct cryptsize {
    uint32_t hashlen;
    uint32_t aeslen;
};

struct cryptsize getCryptInfo(arm_uc_buffer_t* buffer);
/**
 * NOTE: This function does no validation. cryptomode must already have been validated by validateCryptoMode
 *
 * */
arm_uc_mm_crypto_flags_t ARM_UC_mmGetCryptoFlags(uint32_t cryptoMode);


#endif // MANIFEST_MANAGER_CRYPTO_FSM_H
