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

#include "arm_uc_mmCryptoUtils.h"
#include "arm_uc_mmCommon.h"
#include "arm_uc_mmConfig.h"
#include "arm_uc_mmStateSelector.h"
#include "arm_uc_mmDerManifestAccessors.h"
#include "arm_uc_mmDerManifestParser.h"
#include "arm_uc_mmGetLatestTimestamp.h"
#include "arm_uc_mmFSMHelper.h"
#include "arm_uc_mmInsertManifest.h"
#include "update-client-common/arm_uc_scheduler.h"
#include "update-client-common/arm_uc_config.h"

#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "update-client-manifest-manager/update-client-manifest-manager.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"

#include "pal4life-device-identity/pal_device_identity.h"

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/**
 * @file arm_uc_mmInsertManifest.c
 * @brief Inserts a manifest into a slot specified by the manifest.
 * @details This API is used by the manifest manager to validate and store a manifest.
 *
 * The workflow for inserting a manifest is:
 * 1. Check the version of the manifest
 * 2. Validate the cryptographic mode
 * 3. Verify the hash of the manifest.
 * 4. Verify each signature of the manifest.
 * 5. Validate the applicability of the manifest (GUID matching)
 * 6. Validate the storage identifier
 * TBD: Store the manifest in the KCM
 *
 * NOTE: There is a security vs. energy tradeoff in this code.
 * To optimize for energy, the cheapest fields should be checked first, that means checking applicability before
 * hash or signature. However, to optimize for security, we must prioritize safety over energy. Since parsers are
 * notorious sources of bugs, we must make every effort to protect the parser from insecure content. This means
 * accessing the absolute minimum of fields prior to verifyinng the signature.
 *
 * The current version of this code optimizes for security. Once the parser has been more thoroughly validated, we can
 * consider exposing it to more unvalidated data as an energy saving measure.
 *
 * @dot
 * digraph {
 *     Idle
 *     Idle -> Begin [label="[event == BEGIN]"]
 *     Begin
 *     Begin -> VerifyBasicParameters
 *     VerifyBasicParameters
 *     // Validate the manifest size             (This is a precursor to security validation)
 *     // Validate the manifest version          (This is required in order to know how to parse the manifest)
 *     // Validate the manifest encryption mode  (This is required in order to know how to validate the signature)
 *     VerifyBasicParameters -> VerifyHash
 *     VerifyBasicParameters -> VerifyFail [label="[Basic Parameters invalid]"]
 *     VerifyHash
 *     VerifyHash -> VerifySignatureLoopStart
 *     VerifyHash -> VerifyFail [label="[Hash invalid]"]
 *     VerifySignatureLoopStart
 *     VerifySignatureLoopStart -> VerifySignatureStart
 *     VerifySignatureStart
 *     VerifySignatureStart -> VerifySignature
 *     VerifySignatureStart -> VerifyParameters [label="[No More Signatures]"]
 *     VerifySignature
 *     VerifySignature -> VerifyParameters [label="[Last Signature]"]
 *     VerifySignature -> VerifyFail [label="[Signature invalid]"]
 *     // Validate the applicability of the manifest (GUID matching)
 *     // Validate the storage identifier
 *     VerifyParameters
 *     VerifyParameters -> VerifyTimestamp
 *     VerifyParameters -> VerifyFail [label="[Parameters invalid]"]
 *     VerifyTimestampStart
 *     VerifyTimestampStart -> VerifyTimestamp
 *     VerifyTimestamp
 *     VerifyTimestamp -> VerifyApplication
 *     VerifyTimestamp -> VerifyFail [label="[Timestamp too old]"]
 *     VerifyApplication
 *     VerifyApplication -> VerifyDone
 *     VerifyApplication -> VerifyFail [label="[App denied]"]
 *     VerifyFail
 *     VerifyFail -> Idle
 *     VerifyDone
 *     VerifyDone -> AlertHub
 *     AlertHub
 *     AlertHub -> Idle
 * }
 * @enddot
 */

#if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
static const char *ARM_UC_mmInsertState2Str(uint32_t state)
{
    switch (state) {
#define ENUM_AUTO(name) case name: return #name;
#define ENUM_FIXED(name, val) ENUM_AUTO(name)
            ARM_UC_MM_INS_STATE_LIST
#undef ENUM_AUTO
#undef ENUM_FIXED
        default:
            return "Unknown State";
    }
}
#endif

#define max(A,B) ((A)>(B)?(A):(B))

/** @brief Validate that the resource contained in this signed container is a manifest.
 */
static arm_uc_error_t validateResourceType(arm_uc_buffer_t *buffer)
{
    arm_uc_error_t err = {ERR_NONE};
    arm_uc_buffer_t type = { 0 };
    // Read the resource type field.
    err = ARM_UC_mmDERSignedResourceGetSingleValue(buffer,
                                                   ARM_UC_MM_DER_RESOURCE_TYPE, &type);
    if (type.ptr == NULL) {
        err.code = MFST_ERR_DER_FORMAT;
    } else if (err.error == ERR_NONE) {
        // The resource type must be a manifest.
        if (ARM_UC_mmDerBuf2Uint(&type) != 0) {
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_DER_FORMAT);
        }
    }
    return err;
}
/** @brief Validate that this manifest is a supported version
 */
static arm_uc_error_t validateManifestVersion(arm_uc_buffer_t *buffer)
{
    uint32_t val = 0;
    // Read the manifest version
    arm_uc_error_t err = ARM_UC_mmGetVersion(buffer, &val);
    if (err.code == ERR_NONE) {
        // Verify the manifest version
        if (val < MANIFEST_SUPPORTED_VERSION || val > MANIFEST_SUPPORTED_VERSION_EXT) {
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_VERSION);
        }
    }
    return err;
}

/** @brief Validate the manifest size
 */
static arm_uc_error_t validateManifestSize(arm_uc_buffer_t *buffer)
{
    arm_uc_error_t err = {ERR_NONE};
    arm_uc_buffer_t val = {0};

    // Get the manifest inner part
    err = ARM_UC_mmDERSignedResourceGetSingleValue(buffer, ARM_UC_MM_DER_MFST, &val);
    if (err.error == ERR_NONE) {
        // Make sure that the manifest does not overrun.
        uintptr_t bufend = (uintptr_t)buffer->ptr + buffer->size;
        uintptr_t valend = (uintptr_t)val.ptr + val.size;
        if (bufend < valend) {
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_SIZE);
        }
        // TODO: There should be a minimum size for the manifest too.
    }
    return err;
}

/** @brief Validate the crypto mode
 *  @details The manifest must contain a cryptographic mode identifier. Only a small number of modes are supported. If
 *           the manifest is to be processed, then one of these modes must be supported.
 *
 *           While the manifest format supports OID cryptographic mode identifiers, these are not currently supported in
 *           the update client.
 */
static arm_uc_error_t validateCryptoMode(arm_uc_buffer_t *buffer, arm_uc_mm_crypto_flags_t *flags)
{
    uint32_t cryptoMode = 1U; // default SHA256 and ECC
    arm_uc_error_t err = ARM_UC_mmGetCryptoMode(buffer, &cryptoMode);
    if (err.error == ERR_NONE) {
        if (cryptoMode <= MFST_CRYPT_UNINIT || MFST_CRYPT_MAX <= cryptoMode) {
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_CRYPTO_MODE);
        } else {
            *flags = ARM_UC_mmGetCryptoFlags(cryptoMode);
        }
    }
    return err;
}

// Validate that the manifest applies to this device
static arm_uc_error_t validateFirmwareApplicability(arm_uc_buffer_t *buffer)
{
    arm_uc_buffer_t vendor_guid = {0};
    arm_uc_buffer_t class_guid  = {0};

    arm_uc_error_t err = {ERR_NONE};
    if (err.code == ERR_NONE) {
        err = ARM_UC_mmGetVendorGuid(buffer, &vendor_guid);
    }
    if (err.code == ERR_NONE) {
        err = ARM_UC_mmGetClassGuid(buffer, &class_guid);
    }
    if (err.code == ERR_NONE) {
        err = pal_deviceIdentityCheck(
                  (vendor_guid.size != 0UL ? &vendor_guid : NULL),
                  (class_guid.size != 0UL ? &class_guid : NULL)
              );
    }

#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
    if (err.code == ERR_NONE) {
        uint32_t version;
        err = ARM_UC_mmGetVersion(buffer, &version);
        if (err.code == ERR_NONE && version != 1) {
            ARM_UC_SET_ERROR(err, MFST_ERR_VERSION);
        }
    }
#endif
    return err;
}
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
arm_uc_error_t validateDeltaParameters(arm_uc_buffer_t *buffer)
{
    const int keyIDs[] = {
        ARM_UC_MM_DER_MFST_PRECUSOR_DIGEST,
        ARM_UC_MM_DER_MFST_FW_INSTALLEDSIZE,
        ARM_UC_MM_DER_MFST_FW_INSTALLEDDIGEST,
    };
    uint32_t format;
    arm_uc_error_t err = ARM_UC_mmGetFwFormat(buffer, &format);
    if (ARM_UC_IS_ERROR(err)) {
        return err;
    }

    if (format == 1) {
        ARM_UC_SET_ERROR(err, ERR_NONE);
    } else if (format == 5) {
        arm_uc_buffer_t buffers[ARRAY_SIZE(keyIDs)];

        int rc = ARM_UC_mmDERGetSignedResourceValues(
            buffer,
            ARRAY_SIZE(keyIDs),
            keyIDs,
            buffers);
        if (rc) {
            ARM_UC_SET_ERROR(err, MFST_ERR_DER_FORMAT);
        }

    } else {
        ARM_UC_SET_ERROR(err, MFST_ERR_FORMAT);
    }
    return err;
}
#endif
/*
 * DOT Setup
 * DOT: digraph {
 */

/* @brief Idle state
 * @details The idle state generates no events and causes no state transitions. It only moves to a new state when the
 *          `ARM_UC_MM_EVENT_BEGIN` event is received.
 * DOT States:
 * DOT:    Idle
 * DOT:    Idle -> Begin [label="[event == BEGIN]"]
 */
static arm_uc_error_t state_idle(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    if (*event == ARM_UC_MM_EVENT_BEGIN) {
        ctx->state = ARM_UC_MM_INS_STATE_BEGIN;
    }
    return err;
}
/* @brief Begin state
 * @details This is an empty placeholder state that is used as a state transition target for Idle. This allows
 *          modifications to the FSM flow without modifying Idle.
 * DOT States:
 * DOT:    Begin
 * DOT:    Begin -> VerifyBasicParameters
 */
static arm_uc_error_t state_begin(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    ctx->state = ARM_UC_MM_INS_STATE_VERIFY_BASIC_PARAMS;
    return err;
}
/* @brief Verify critical pre-security parameters
 * @details Some parameters must be verified before security validation. These parameters are critical to either finding
 *          or validating the security parameters themselves. The parameters validated are:
 *
 * * The resource size             (This is a precursor to security validation)
 * * The resource is a manifest    (A non-manifest will not be accepted)
 * * The manifest version          (This is required in order to know how to parse the manifest)
 * * The manifest encryption mode  (This is required in order to know how to validate the signature)
 *
 * DOT States:
 * DOT:    VerifyBasicParameters
 * DOT:    VerifyBasicParameters -> VerifyHash
 * DOT:    VerifyBasicParameters -> VerifyFail [label="[Basic Parameters invalid]"]
 */
static arm_uc_error_t state_verifyBasicParameters(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};

    if (err.error == ERR_NONE) {
        err = validateResourceType(&ctx->manifest);
    }
    if (err.error == ERR_NONE) {
        err = validateManifestSize(&ctx->manifest);
    }
    if (err.error == ERR_NONE) {
        err = validateManifestVersion(&ctx->manifest);
    }
    if (err.error == ERR_NONE) {
        err = validateCryptoMode(&ctx->manifest, &ctx->cryptoMode);
    }
    // Set the state based on error condition
    if (err.error == ERR_NONE) {
        ctx->state = ARM_UC_MM_INS_STATE_HASH_VERIFY;
    } else {
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_FAIL;
    }
    return err;
}
/** @brief   Verify the manifest hash
 *  @details Manifest hash verification happens in a single state. This is because hash verification is currently
 *           considered to be a blocking operation. If an asynchronous hash accelerator is used, this will need to be
 *           modified to use two states to handle hash initiation and waiting for completion.
 *
 * DOT States:
 * DOT:     VerifyHash
 * DOT:     VerifyHash -> VerifySignatureLoopStart
 * DOT:     VerifyHash -> VerifyFail [label="[Hash invalid]"]
 */
static arm_uc_error_t state_verifyHash(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = ARM_UC_mmValidateManifestHash(&ctx->manifest);
    if (err.error == ERR_NONE) {
        // If the cryptoMode specifies either ecc or rsa, then we can validate that.
        if (ctx->cryptoMode.ecc || ctx->cryptoMode.rsa || ctx->cryptoMode.psk) {
            ctx->state = ARM_UC_MM_INS_STATE_VERIFY_SIG_LOOP;
        } else {
            // Unsigned manifests are not supported at this time, so they count as a failure.
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_FORMAT);
            ctx->state = ARM_UC_MM_INS_STATE_VERIFY_FAIL;
        }
    } else {
        ARM_UC_MFST_SET_ERROR(err, MFST_ERR_HASH);
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_FAIL;
    }
    return err;
}
/** @brief Start the signature verification loop.
 *  @details This state provides initialization for the signature verification loop.
 *           The outer loop is tracked by `loopCounters[0]` and represents the signature index.
 *
 * DOT States:
 * DOT:     VerifySignatureLoopStart
 * DOT:     VerifySignatureLoopStart -> VerifySignatureStart
 */
static arm_uc_error_t state_verifySignatureLoopStart(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    // Set the exterior loop counter
    ctx->loopCounters[0] = 0;
    ctx->state = ARM_UC_MM_INS_STATE_VERIFY_SIG_START;
    return err;
}
/** @brief   Begin verifying the signature.
 *  @details This calls the ARM_UC_mmValidateSignature setup function, but does not start the signature verification
 *           state machine. `ARM_UC_mmValidateSignature` attempts to read a signature at the index specified by the
 *           outer loop counter (`loopCounters[0]`). If it fails, it assumes that all signatures have been processed.
 *           If at least one signature has been processed, then continue with validation, but a minimum of one signature
 *           is required for validation.
 *
 * DOT States:
 * DOT:     VerifySignatureStart
 * DOT:     VerifySignatureStart -> VerifySignature
 * DOT:     VerifySignatureStart -> VerifyParameters [label="[No More Signatures]"]
 */
static arm_uc_error_t state_verifySignatureStart(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    // start the signature verification
    arm_uc_error_t err = {ERR_NONE};
    uint32_t cryptoMode;
    err = ARM_UC_mmGetCryptoMode(&ctx->manifest, &cryptoMode);
    if (err.error == ERR_NONE) {
        switch (cryptoMode) {
#if defined(ARM_UC_FEATURE_MANIFEST_PUBKEY) && (ARM_UC_FEATURE_MANIFEST_PUBKEY == 1)
            case MFST_CRYPT_SHA256_ECC_AES128_PSK:
            case MFST_CRYPT_SHA256_ECC:
                err = ARM_UC_mmValidateSignature(&ctx->signatureContext,
                                                 ARM_UC_mmCallbackFSMEntry,
                                                 &ctx->manifest,
                                                 &ctx->certificateStorage,
                                                 ctx->loopCounters[0]);
                break;
#endif /* ARM_UC_FEATURE_MANIFEST_PUBKEY */
#if defined(ARM_UC_FEATURE_MANIFEST_PSK) && (ARM_UC_FEATURE_MANIFEST_PSK == 1)
            case MFST_CRYPT_PSK_AES128CCM_SHA256:
            case MFST_CRYPT_NONE_PSK_AES128CCM_SHA256:
                err = ARM_UC_mmVerifySignaturePSK(&ctx->signatureContext,
                                                  ARM_UC_mmCallbackFSMEntry,
                                                  &ctx->manifest,
                                                  ctx->loopCounters[0]);
                break;
#endif /* ARM_UC_FEATURE_MANIFEST_PSK */
        }
    }
    if (err.error == ERR_NONE) {
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_SIG_WAIT;
        *event = ARM_UC_MM_RC_NONE;
        ARM_UC_MFST_SET_ERROR(err, MFST_ERR_PENDING);
    }
    // If there are no more signatures and at least one signature was validated
    if (err.code == ARM_UC_DP_ERR_NO_MORE_ELEMENTS) {
        if (ctx->loopCounters[0] >= 1) {
            // Signature validation done. Move on to parameter validation.
            ctx->state = ARM_UC_MM_INS_STATE_VERIFY_PARAMS;
            ARM_UC_MFST_SET_ERROR(err, ERR_NONE);
        } else {
            // WARNING: If the fingerprint is empty, MFST_ERR_FORMAT is returned.
            // At least one signature is required.
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_FORMAT);
            ctx->state = ARM_UC_MM_INS_STATE_VERIFY_FAIL;
        }
    }
    return err;
}
/** @brief   Wait for signature validation to complete.
 *  @details Calls the `ARM_UC_mmValidateSignature` state machine and collects exit status. When signature validation is
 *           complete, the return value will be `ERR_NONE`.
 *
 * DOT States:
 * DOT:     VerifySignature
 * DOT:     VerifySignature -> VerifyFail [label="[Signature invalid]"]
 * DOT:     VerifySignature -> VerifySignatureStart
 */
static arm_uc_error_t state_verifySignature(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    // Wait for the signature verification to end.
    // If the signature validation ended
    if (*event == ARM_UC_MM_RC_DONE) {
        // Increment the loop counter
        ctx->loopCounters[0] += 1;
        // Return to the beginning of the loop.
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_SIG_START;
    } else if (*event == ARM_UC_MM_RC_ERROR) {
        err = ctx->signatureContext.storedError;
    } else {
        ARM_UC_MFST_SET_ERROR(err,  MFST_ERR_BAD_EVENT);
    }
    return err;
}
/** @brief   Validates remaining parsable parameters
 *  @details This currently means only the firmware applicability, as identified by UUID. Several additiional parameters
 *           could be validated:
 *
 *           * Storage identifier
 *           * Payload type identifier
 *           * URI validation in payload reference
 *           * Valid size of payload hash
 *           * nonce size, non-zero
 *           * Valid From, Valid To
 *           * timestamp
 *           * Encryption info
 *
 *
 * DOT States:
 * DOT:     VerifyParameters
 * DOT:     VerifyParameters -> VerifyApplication
 * DOT:     VerifyParameters -> VerifyFail [label="[Parameters invalid]"]
 */
static arm_uc_error_t state_verifyParameters(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = validateFirmwareApplicability(&ctx->manifest);
#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
    if (err.error == ERR_NONE) {
        err = validateDeltaParameters(&ctx->manifest);
        if (ARM_UC_IS_ERROR(err)) {
            UC_MMGR_ERR_MSG("validateDeltaParameters failed with error %s", ARM_UC_err2Str(err));
        }
    }
#endif
    if (err.error == ERR_NONE) {
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_TS_START;
    }
    return err;
}
/** @brief   Initiate timestamp verification.
 *  @details This starts the process of loading the active timestamp. This may be a non-blocking operation.
 *
 * DOT States:
 * DOT:     VerifyTimestampStart
 * DOT:     VerifyTimestampStart -> VerifyTimestamp
 */
static arm_uc_error_t state_verifyTimestampStart(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    // Since this is a root manifest, extract maximum stored timestamp
    arm_uc_error_t err = getLatestManifestTimestamp(&ctx->max_ts, NULL);
    if (err.error == ERR_NONE) {
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_TS;
        *event = ARM_UC_MM_EVENT_BEGIN;
    }
    return err;
}
/** @brief   Waits for the active timestamp to be loaded.
 *  @details Once the active timestamp has been loaded, this validates the inserted manifest timestamp.
 *
 * DOT States:
 * DOT:    VerifyTimestamp
 * DOT:    VerifyTimestamp -> VerifyApplication
 * DOT:    VerifyTimestamp -> VerifyFail [label="[Timestamp too old]"]
 */
static arm_uc_error_t state_verifyTimestamp(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = getLatestManifestTimestampFSM(*event);
    if (err.error == ERR_NONE) {
        err = ARM_UC_mmGetTimestamp(&ctx->manifest, &ctx->current_ts);
    }
    if (err.error == ERR_NONE) {
#if MANIFEST_ROLLBACK_PROTECTION
        // Validate the timestamp for rollback protection.
        if (ctx->max_ts >= ctx->current_ts) {
            ARM_UC_MFST_SET_ERROR(err, MFST_ERR_ROLLBACK);
        } else
#endif
        {
            ARM_UC_MFST_SET_ERROR(err, ERR_NONE);
            ctx->state = ARM_UC_MM_INS_STATE_VERIFY_APP;
        }
    }
    return err;
}

/** @brief   Calls out to a handler provided by the application.
 *  @details Currently unimplemented.
 *
 * DOT States:
 * DOT:     VerifyApplication
 * DOT:     VerifyApplication -> VerifyDone
 * DOT:     VerifyApplication -> VerifyFail [label="[App denied]"]
 */
static arm_uc_error_t state_verifyApplication(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    if (err.error == ERR_NONE) {
        ctx->state = ARM_UC_MM_INS_STATE_VERIFY_DONE;
    }
    return err;
}
/** @brief   Verification has failed.
 *  @details This state will never be entered. This is for documentation purposes only. The state machine exits when an
 *           error is detected, so this state cannot be entered. The hub will be notified via the state machine's error
 *           handler.
 *
 * DOT States:
 * DOT:     VerifyFail
 * DOT:     VerifyFail -> Idle
 */


/** @brief   Verification has completed successfully.
 *  @details This is a placeholder state that may be useful if more operations must be performed after verification,
 *           for example, storage of the manifest.
 *
 * DOT States:
 * DOT:     VerifyDone
 * DOT:     VerifyDone -> AlertHub
 */
static arm_uc_error_t state_verifyDone(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    if (err.error == ERR_NONE) {
        ctx->state = ARM_UC_MM_INS_STATE_ALERT;
    }
    return err;
}
/** @brief   Alert the hub that insert has finished processing the manifest.
 *  @details Queues a callback to the hub, that reports completion.
 *
 * DOT States:
 * DOT:     AlertHub
 * DOT:     AlertHub -> Idle
 */
static arm_uc_error_t state_alertHub(struct arm_uc_mmInsertContext_t *ctx, uint32_t *event)
{
    arm_uc_error_t err = {ERR_NONE};
    return err;
}
/**
 * DOT Teardown
 * DOT: }
 */

arm_uc_error_t ARM_UC_mmInsertFSM(uint32_t event)
{
    arm_uc_error_t err = {ERR_NONE};
    struct arm_uc_mmInsertContext_t *ctx;
    if (arm_uc_mmPersistentContext.ctx == NULL || *arm_uc_mmPersistentContext.ctx == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }
    ctx = &(*arm_uc_mmPersistentContext.ctx)->insert;

    uint32_t oldState;
#if ARM_UC_MM_ENABLE_INSERT_TEST_VECTORS
    uint32_t oldEvent;
#endif
    UC_MMGR_TRACE("> %s (%u)\n", __PRETTY_FUNCTION__, (unsigned)event);
    do {
        // Preserve the old state to check for state transitions
        oldState = ctx->state;

#if ARM_UC_MM_ENABLE_INSERT_TEST_VECTORS
        // Preserve the old event for testing
        oldEvent = event;
#endif
        // Reset error logging
        arm_uc_mmPersistentContext.errorFile = NULL;
        arm_uc_mmPersistentContext.errorLine = 0;

        UC_MMGR_TRACE("+ %s state: %s(%u)\n", __PRETTY_FUNCTION__,
                            ARM_UC_mmInsertState2Str(ctx->state), (unsigned)ctx->state);
        switch (ctx->state) {
            case ARM_UC_MM_INS_STATE_IDLE:
                err = state_idle(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_BEGIN:
                err = state_begin(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_BASIC_PARAMS:
                err = state_verifyBasicParameters(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_HASH_VERIFY:
                err = state_verifyHash(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_SIG_LOOP:
                err = state_verifySignatureLoopStart(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_SIG_START:
                err =  state_verifySignatureStart(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_SIG_WAIT:
                err = state_verifySignature(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_PARAMS:
                err = state_verifyParameters(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_TS_START:
                err = state_verifyTimestampStart(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_TS:
                err = state_verifyTimestamp(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_APP:
                err = state_verifyApplication(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_VERIFY_DONE:
                err = state_verifyDone(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_ALERT:
                err = state_alertHub(ctx, &event);
                break;
            case ARM_UC_MM_INS_STATE_INVALID:
            default:
                err = (arm_uc_error_t) {MFST_ERR_INVALID_STATE};
                break;
        }
#if ARM_UC_MM_ENABLE_INSERT_TEST_VECTORS
        if (arm_uc_mmPersistentContext.testHook) {
            arm_uc_mmPersistentContext.testHook("insert", *arm_uc_mmPersistentContext.ctx, oldState, oldEvent, err);
        }
#endif
    } while (err.code == ERR_NONE && oldState != ctx->state);
    UC_MMGR_TRACE("< %s %c%c:%hu (%s)\n", __PRETTY_FUNCTION__,
                        CC_ASCII(err.modulecc[0]), CC_ASCII(err.modulecc[1]),
                        err.error, ARM_UC_err2Str(err));
    return err;
}

#endif
