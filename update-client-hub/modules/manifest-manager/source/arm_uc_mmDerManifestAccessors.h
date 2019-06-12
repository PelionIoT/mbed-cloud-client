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

#ifndef ARM_UPDATE_CLIENT_MANIFEST_MANAGER_ACCESSORS_H
#define ARM_UPDATE_CLIENT_MANIFEST_MANAGER_ACCESSORS_H
// WARNING: THIS IS A MACHINE-GENERATED FILE. DO NOT MODIFY.
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_common.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"
#define MFST_MAGIC 1414743629
enum {
    ARM_UC_MFST_CRYPTOMODE_UNINIT = 0,
    ARM_UC_MFST_CRYPTOMODE_SHA256,
    ARM_UC_MFST_CRYPTOMODE_SHA256_HMAC,
    ARM_UC_MFST_CRYPTOMODE_SHA256_HMAC_AES128,
    ARM_UC_MFST_CRYPTOMODE_SHA256_ECC,
    ARM_UC_MFST_CRYPTOMODE_SHA256_ECC_AES128,
    ARM_UC_MFST_CRYPTOMODE_MAX,
};

uint32_t ARM_UC_mmGetUint32_t(arm_uc_buffer_t *buffer, uint32_t offset);
arm_uc_error_t ARM_UC_mmGetMagic(arm_uc_buffer_t *buffer, uint32_t *val);
arm_uc_error_t ARM_UC_mmGetVersion(arm_uc_buffer_t *buffer, uint32_t *val);
arm_uc_error_t ARM_UC_mmGetCryptoMode(arm_uc_buffer_t *buffer, uint32_t *val);
arm_uc_error_t ARM_UC_mmGetNonce(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetVendorGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid);
arm_uc_error_t ARM_UC_mmGetClassGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid);
arm_uc_error_t ARM_UC_mmGetDeviceGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid);
arm_uc_error_t ARM_UC_mmGetPrecursorDigest(arm_uc_buffer_t* buffer, arm_uc_buffer_t* val);
arm_uc_error_t ARM_UC_mmGetTimestamp(arm_uc_buffer_t *buffer, uint64_t *val);
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1) && (!defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) || (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 0))
arm_uc_error_t ARM_UC_mmGetVendorInfo(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
#endif
arm_uc_error_t ARM_UC_mmGetValidFrom(arm_uc_buffer_t *buffer, uint64_t *val);
arm_uc_error_t ARM_UC_mmGetValidTo(arm_uc_buffer_t *buffer, uint64_t *val);
arm_uc_error_t ARM_UC_mmGetCertificateId(arm_uc_buffer_t *buffer, uint32_t sigIdx, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetPriority(arm_uc_buffer_t* buffer, uint64_t* val);
arm_uc_error_t ARM_UC_mmGetFwFormat(arm_uc_buffer_t *buffer, uint32_t *val);
arm_uc_error_t ARM_UC_mmGetFwInitVector(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetFwUri(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetFwSize(arm_uc_buffer_t *buffer, uint32_t *val);
arm_uc_error_t ARM_UC_mmGetFwHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetInstalledSize(arm_uc_buffer_t* buffer, arm_uc_image_size_t* val);
arm_uc_error_t ARM_UC_mmGetInstalledDigest(arm_uc_buffer_t* buffer, arm_uc_buffer_t* val);
arm_uc_error_t ARM_UC_mmGetFwSymmKey(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetFwCertId(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetDescription(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetManifestLinksUri(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetManifestLinksHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);
arm_uc_error_t ARM_UC_mmGetManifestLinksElementCount(arm_uc_buffer_t *buffer, uint32_t *val);
uint32_t ARM_UC_mmGetManifestLinksElementSize(arm_uc_buffer_t *buffer, uint32_t baseOffset);
arm_uc_error_t ARM_UC_mmGetManifestLinksElement(arm_uc_buffer_t *buffer, uint32_t index, arm_uc_buffer_t *element);
arm_uc_error_t ARM_UC_mmGetManifestHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val);

arm_uc_error_t ARM_UC_mmDERSignedResourceGetSingleValue(arm_uc_buffer_t *buffer, const int32_t fieldID,
                                                        arm_uc_buffer_t *val);

#endif // ARM_UPDATE_CLIENT_MANIFEST_MANAGER_ACCESSORS_H
