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

#include "update-client-manifest-manager/update-client-manifest-types.h"
#include "arm_uc_mmDerManifestAccessors.h"
#include "arm_uc_mmDerManifestParser.h"
#include <string.h>


arm_uc_error_t ARM_UC_wrapMbedTLSError(int32_t mt_err)
{
    return (arm_uc_error_t) {.error = -mt_err, .module = MBED_TLS_ERROR_PREFIX};
}

arm_uc_error_t ARM_UC_mmDERSignedResourceGetSingleValue(arm_uc_buffer_t *buffer, const int32_t fieldID,
                                                        arm_uc_buffer_t *val)
{
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    arm_uc_error_t err = {ARM_UC_DP_ERR_UNKNOWN};
    if (rc < 0) {
        err = ARM_UC_wrapMbedTLSError(rc);
    } else if (rc == 0) {
        err.code = ERR_NONE;
    } else { //if (rc > 0)
        err.code = ARM_UC_DP_ERR_NOT_FOUND;
    }
    return err;
}

arm_uc_error_t ARM_UC_mmDERGetSingleValue(
    const struct arm_uc_mmDerElement *desc,
    arm_uc_buffer_t *buffer,
    const int32_t valueID,
    arm_uc_buffer_t *val)
{
    int32_t rc = ARM_UC_mmDERParseTree(desc, buffer, 1U, &valueID, val);
    arm_uc_error_t err = {ARM_UC_DP_ERR_UNKNOWN};
    if (rc < 0) {
        err = ARM_UC_wrapMbedTLSError(rc);
    } else if (rc == 0) {
        err.code = ERR_NONE;
    } else { //if (rc > 0)
        err.code = ARM_UC_DP_ERR_NOT_FOUND;
    }
    return err;
}

uint32_t ARM_UC_mmGetCryptoModeInline(arm_uc_buffer_t *buffer)
{
    uint32_t val = 1U; // default to SHA256 and ECC
    ARM_UC_mmGetCryptoMode(buffer, &val);
    return val;
}
arm_uc_error_t ARM_UC_mmGetVersion(arm_uc_buffer_t *buffer, uint32_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_VERSION;
    arm_uc_buffer_t field = { 0UL };
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetCryptoMode(arm_uc_buffer_t *buffer, uint32_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_ENC_ENUM;
    arm_uc_buffer_t field = { 0UL };
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetTimestamp(arm_uc_buffer_t *buffer, uint64_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_TIMESTAMP;
    arm_uc_buffer_t field = { 0UL };
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint64(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1) && (!defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) || (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 0))
arm_uc_error_t ARM_UC_mmGetVendorInfo(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val) {
    const int32_t fieldID = ARM_UC_MM_DER_MFST_VENDOR_INFO;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
#endif
arm_uc_error_t ARM_UC_mmGetValidFrom(arm_uc_buffer_t *buffer, uint64_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_VALID_FROM;
    arm_uc_buffer_t field = { 0UL };
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc < 0 || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    if (rc > 0) return (arm_uc_error_t) {MFST_ERR_EMPTY_FIELD};
    *val = ARM_UC_mmDerBuf2Uint64(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetValidTo(arm_uc_buffer_t *buffer, uint64_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_VALID_TO;
    arm_uc_buffer_t field = { 0UL };
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc < 0 || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    if (rc > 0) return (arm_uc_error_t) {MFST_ERR_EMPTY_FIELD};
    *val = ARM_UC_mmDerBuf2Uint64(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetVendorGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_VENDOR_UUID;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, guid);
    if (rc || guid->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetClassGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_CLASS_UUID;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, guid);
    if (rc || guid->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetDeviceGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_DEVICE_UUID;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, guid);
    if (rc || guid->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
arm_uc_error_t ARM_UC_mmGetPrecursorDigest(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_PRECUSOR_DIGEST;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, guid);
    if (rc || guid->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetPriority(arm_uc_buffer_t *buffer, uint64_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_PRIORITY;
    arm_uc_buffer_t field = { 0UL };
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint64(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetFwFormat(arm_uc_buffer_t *buffer, uint32_t *val)
{
    arm_uc_buffer_t field = { 0UL };
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_FMT_ENUM;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
#endif
arm_uc_error_t ARM_UC_mmGetFwInitVector(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_CRYPT_IV;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetFwUri(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetFwSize(arm_uc_buffer_t *buffer, uint32_t *val)
{
    arm_uc_buffer_t field = { 0UL };
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetFwHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
arm_uc_error_t ARM_UC_mmGetInstalledSize(arm_uc_buffer_t *buffer, arm_uc_image_size_t *val)
{
    arm_uc_buffer_t field = { 0UL };
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_INSTALLEDSIZE;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &field);
    if (rc || field.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    *val = ARM_UC_mmDerBuf2Uint64(&field);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetInstalledDigest(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_INSTALLEDDIGEST;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
#endif
arm_uc_error_t ARM_UC_mmGetFwSymmKey(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    return (arm_uc_error_t) {MFST_ERR_VERSION};
}
arm_uc_error_t ARM_UC_mmGetFwCertId(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_FW_CRYPT_ID_LOCAL;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetDescription(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_DESC;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetManifestLinksUri(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_DEP_REF_URL;
    int32_t rc = ARM_UC_mmDERParseTree(arm_uc_mmManifestDependencies, buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetManifestLinksHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    const int32_t fieldID = ARM_UC_MM_DER_MFST_DEP_REF_HASH;
    int32_t rc = ARM_UC_mmDERParseTree(arm_uc_mmManifestDependencies, buffer, 1U, &fieldID, val);
    if (rc || val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetManifestLinksElement(arm_uc_buffer_t *buffer, uint32_t index, arm_uc_buffer_t *element)
{
    arm_uc_buffer_t elements = { 0UL };
    const int32_t fieldID = ARM_UC_MM_DER_MFST_DEPS;
    int32_t rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, &elements);
    if (rc || elements.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    element->ptr = NULL;
    rc = ARM_UC_mmDERGetSequenceElement(&elements, index, element);
    if (rc) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetManifestHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    return ARM_UC_mmDERSignedResourceGetSingleValue(buffer, ARM_UC_MM_DER_SIG_HASH, val);
}
arm_uc_error_t ARM_UC_mmGetSignatureBlock(arm_uc_buffer_t *buffer, uint32_t idx, arm_uc_buffer_t *block)
{
    arm_uc_buffer_t signatures = { 0UL };
    arm_uc_error_t err = ARM_UC_mmDERSignedResourceGetSingleValue(buffer, ARM_UC_MM_DER_SIG_SIGNATURES, &signatures);
    if (err.error) { return err; }
    if (signatures.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};

    int32_t rc = ARM_UC_mmDERGetSequenceElement(&signatures, idx, block);
    if (rc) { return ARM_UC_wrapMbedTLSError(rc); }
    if (block->ptr == NULL) return (arm_uc_error_t) {ARM_UC_DP_ERR_NO_MORE_ELEMENTS};

    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetSignature(arm_uc_buffer_t *buffer, uint32_t idx, arm_uc_buffer_t *val)
{
    arm_uc_buffer_t signatureBlock = { 0UL };
    arm_uc_error_t err = ARM_UC_mmGetSignatureBlock(buffer, idx, &signatureBlock);
    if (err.error) { return err; }
    if (signatureBlock.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};

    err = ARM_UC_mmDERGetSingleValue(arm_uc_mmSignatures, &signatureBlock, ARM_UC_MM_DER_SIG_SIGNATURE, val);
    if (err.error) { return err; }
    if (val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetCertificateId(arm_uc_buffer_t *buffer, uint32_t sigIdx, arm_uc_buffer_t *val)
{
    arm_uc_buffer_t signatureBlock = { 0UL };
    arm_uc_error_t err = ARM_UC_mmGetSignatureBlock(buffer, sigIdx, &signatureBlock);
    if (err.error) { return err; }
    if (signatureBlock.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};

    arm_uc_buffer_t seq = { 0UL };
    err = ARM_UC_mmDERGetSingleValue(arm_uc_mmSignatures, &signatureBlock, ARM_UC_MM_DER_SIG_CERTS, &seq);
    if (err.error) { return err; }
    if (seq.ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};

    arm_uc_buffer_t element = { 0UL };
    element.ptr = NULL;
    int32_t rc = ARM_UC_mmDERGetSequenceElement(&seq, 0, &element);
    if (rc) { return ARM_UC_wrapMbedTLSError(rc); }
    if (element.ptr == NULL) return (arm_uc_error_t) {ARM_UC_DP_ERR_NO_MORE_ELEMENTS};

    err = ARM_UC_mmDERGetSingleValue(arm_uc_mmSignatureCertificateReferences, &element, ARM_UC_MM_DER_SIG_CERT_FINGERPRINT,
                                     val);
    if (err.error) { return err; }
    if (val->ptr == NULL) return (arm_uc_error_t) {MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t) {ERR_NONE};
}
