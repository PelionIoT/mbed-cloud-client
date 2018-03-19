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

#include "arm_uc_mmCryptoUtils.h"
#include "arm_uc_mmCommon.h"
#include "arm_uc_mmConfig.h"
#include "arm_uc_mmDerManifestParser.h"
#include "update-client-common/arm_uc_crypto.h"

#include "update-client-control-center/arm_uc_certificate.h"

#include "arm_uc_mmDerManifestAccessors.h"
#include "update-client-manifest-manager/update-client-manifest-manager.h"

#include <string.h>

void ARM_UC_mmVerifySignatureEntry(uint32_t event);
/**
 * @file Cryptographic utilities
 * This file provides two primary APIs:
 * * Verifying manifest hashes
 * * Verifying manifest signatures
 *
 * Some utility functions used by other files in this module are also provided.
 *
 * Algorithm support:
 * ECC is currently supported, but RSA is not.
 * Currently, only ECC secp256r1 (prime256v1) is supported.
 * Currently, only SHA256 is supported.
 * HMAC is not yet supported.
 */

/**
 * @brief Returns the sizes of the cryptographic primitives used by the supplied manifest.
 * @details Extracts the cryptomode field from a manifest and returns a struct that describes the size of cryptographic
 *          primitives used in the manifest. The supplied manifest must have been validated. No validation is performed
 *          by this function.
 *
 * @param[in]  buffer A buffer that contains a validated manifest.
 * @return            A struct cryptsize, which contains the AES primitive sizes and SHA primitive size, both in bytes.
 *                    An invalid cryptographic mode specifier will cause primitive sizes of `0` to be returned.
 */
struct cryptsize getCryptInfo(arm_uc_buffer_t* buffer)
{
    struct cryptsize cs = {0};
    uint32_t cryptoMode = 1U; // default SHA256 and ECC
    ARM_UC_mmGetCryptoMode(buffer, &cryptoMode);

    switch(cryptoMode)
    {
        case MFST_CRYPT_SHA256_ECC_AES128_PSK:
        // case MFST_CRYPT_SHA256_HMAC_AES128_PSK:
            cs.aeslen = 128/CHAR_BIT;
        // case MFST_CRYPT_SHA256_HMAC:
        case MFST_CRYPT_SHA256:
            cs.hashlen = 256/CHAR_BIT;
            break;
        case MFST_CRYPT_SHA256_ECC:
            cs.hashlen = 256/CHAR_BIT;
        default:
            break;
    }
    return cs;
}

/**
 * @brief Converts a cryptographic mode enum to a structure with mode identifiers
 * @details In order to simplify many tests, the cryptographic mode identifier is converted into a structure of mode
 *          identifiers, one for each cryptographic primitive. This allows other parts of the code to examine the mode
 *          of one particular primitive without testing against many enums. This function performs no validation. The
 *          calling function should have performed validation in advance. If the cryptoMode is unrecognized, then a
 *          return will be populated with 0 for every flag.
 *
 *          HMAC modes are not currently supported.
 * TODO: Convert flags to enums
 * @param[in]  cryptoMode The cryptographic mode enum that specifies the settings for each primitive
 * @return                A structure of flags that indicate the mode of:
 *                        * Hash algorithm
 *                        * MAC
 *                        * Symmetric Encryption
 *                        * Pre-shared keys
 *                        * Public Key modes
 */
arm_uc_mm_crypto_flags_t ARM_UC_mmGetCryptoFlags(uint32_t cryptoMode)
{

    switch(cryptoMode) {
        case MFST_CRYPT_SHA256:
            return (arm_uc_mm_crypto_flags_t) {.hash = 1U};
        // case MFST_CRYPT_SHA256_HMAC:
        //     return (arm_uc_mm_crypto_flags_t) {.hash = 1, .hmac = 1};
        // case MFST_CRYPT_SHA256_HMAC_AES128_PSK:
        //     return (arm_uc_mm_crypto_flags_t) {.hash = 1, .hmac = 1, .aes = 1, .psk = 1};
        case MFST_CRYPT_SHA256_ECC:
            return (arm_uc_mm_crypto_flags_t) {.hash = 1U, .ecc = 1U};
        case MFST_CRYPT_SHA256_ECC_AES128_PSK:
            return (arm_uc_mm_crypto_flags_t) {.hash = 1U, .ecc = 1U, .aes = 1U, .psk = 1U};
    }
    return (arm_uc_mm_crypto_flags_t) {.hash = 0};

}

/**
 * @brief Extracts the hash of a manifest from the manifest wrapper.
 * @details This is a utility function that is used to extract the hash of the manifest for signature validation.
 *          This function does not perform validation of the hash buffer, so the hash buffer is expected to be populated
 *          with a known-good hash buffer. Typically, this buffer will be stack-allocated.
 * @param[in]   buffer The manifest to parse
 * @param[out]  hash   Output buffer object to fill with the hash
 * @return             MFST_ERR_NONE on success, or a parser error code otherwise
 */
arm_uc_error_t ARM_UC_mmGetManifestHashFromBin(arm_uc_buffer_t* buffer, arm_uc_buffer_t* hash)
{
    const uint32_t fieldID = ARM_UC_MM_DER_SIG_HASH;
    int rc = ARM_UC_mmDERGetSignedResourceValues(buffer, 1U, &fieldID, hash);
    if (rc) return (arm_uc_error_t){MFST_ERR_DER_FORMAT};
    return (arm_uc_error_t){MFST_ERR_NONE};
}

/**
 * Utility function for printing the hex value of a buffer. Used only for debugging.
 * @param buf [description]
 */
#if 0
static void hexprint_buffer(arm_uc_buffer_t* buf)
{
    for (size_t i = 0; i < buf->size; i++)
    {
        printf("%02x", buf->ptr[i]);
    }
}
#endif

/**
 * @brief ARM_UC_mmValidateManifestHash processes a manifest in order to validate its hash
 * @details The manifest parser extracts the manifest hash, calculates the hash of the manifest, then compares it to the
 *          hash included in the manifest.
 *
 *          The outer wrapper of the manifest is called a SignedResource. It contains a Resource object and a
 *          ResourceSignature object. The Resource object contains a Resource Type identifier, an optional URL, and
 *          either a manifest or binary data.
 *
 *          This function extracts the Resource object and the ResourceSignature object so that the Resource can be
 *          hashed and verified against the hash in the ResourceSignature.
 *
 *          TODO: The dependency on the cryptoMode contained within the manifest will be removed with the change to CMS
 *          First, the Resource object is extracted. Next, the cryptoMode is extracted from the Resource object. This
 *          requires that the Resource object be a Manifest.
 *
 * @param[in]  buffer The buffer that contains the manifest to validate
 * @retval            MFST_ERR_NONE on success
 * @retval            MFST_ERR_CRYPTO_MODE if there is a cryptographic mode error
 * @retval            Otherwise, a DER Parser error can be expected
 */
arm_uc_error_t ARM_UC_mmValidateManifestHash(arm_uc_buffer_t* buffer)
{
    uint8_t localhash[MAX_HASH_BYTES];      ///< An array to store the locally calculated hash
    arm_uc_buffer_t local = {               ///< A buffer structure to use for the locally calculated hash
        .size_max = MAX_HASH_BYTES,
        .size     = 0,
        .ptr      = localhash
    };
    arm_uc_buffer_t remote = {             ///< A buffer for the hash provided in the manifest
        .size_max = MAX_HASH_BYTES,
        .size     = 0,
        .ptr      = NULL
    };
    arm_uc_buffer_t resource = {            ///< A buffer for the resource (the manifest) that is wrapped by a signature
        .size_max = MAX_HASH_BYTES,
        .size     = 0,
        .ptr      = NULL
    };
    arm_uc_mdHandle_t hDigest = {0};        ///< This handle is for the digest algorithm
    arm_uc_error_t err = {MFST_ERR_NONE};   ///< The return code variable
    uint32_t cryptoMode = 0;                ///< A temporary local copy of the crytpoMode
    arm_uc_mdType_t mdType = 0;             ///< A type designator for the type of hash in use

    // Extract the "resource" contained in the Signed Resource object
    err = ARM_UC_mmDERSignedResourceGetSingleValue(buffer, ARM_UC_MM_DER_RESOURCE, &resource);
    if (!err.error)
    {
        // Extract the hash from the manifest
        err = ARM_UC_mmGetManifestHash(buffer, &remote);
    }
    if (!err.error)
    {
        // Extract the cryptographic mode from the manifest
        err = ARM_UC_mmGetCryptoMode(buffer, &cryptoMode);
    }
    if (!err.error)
    {
        // Set the hash type identifier
        switch(cryptoMode)
        {
            case MFST_CRYPT_SHA256_ECC_AES128_PSK:
            case MFST_CRYPT_SHA256:
            case MFST_CRYPT_SHA256_ECC:
                mdType = ARM_UC_CU_SHA256;
                break;
            default:
                err.code = MFST_ERR_CRYPTO_MODE;
                break;
        }
    }
    if (!err.error)
    {
        // Initialize the message digest API
        err = ARM_UC_cryptoHashSetup(&hDigest, mdType);
    }
    if (!err.error)
    {
        // NOTE: If a hash accelerator is present on-chip, this could be converted from a blocking call to an
        //       asynchronous one.
        // Hash the resource
        // Keep Coverity quiet - it can't resolve some semantic conditions here.
        if ( resource.ptr == NULL ) {
            ARM_UC_SET_ERROR(err, MFST_ERR_NULL_PTR);
        } else  {
            err = ARM_UC_cryptoHashUpdate(&hDigest, &resource);
        }
    }
    if (!err.error)
    {
        // Extract the locally calculated hash from the hash API
        err = ARM_UC_cryptoHashFinish(&hDigest, &local);
    }
    if (!err.error)
    {
        // Check that the hashes match
        // Keep Coverity quiet - it can't resolve some semantic conditions here.
        if ( remote.ptr == NULL ) {
            ARM_UC_SET_ERROR(err, MFST_ERR_NULL_PTR);
        } else if(ARM_UC_BinCompareCT(&local, &remote)) {
            ARM_UC_SET_ERROR(err, MFST_ERR_HASH);
        }
    }
    // Explicitly set the manifest manager's no-error code, rather than another module's, which may be present here.
    if (!err.error)
    {
        ARM_UC_SET_ERROR(err, MFST_ERR_NONE);
    }
    return err;
}

enum arm_uc_mmCertificateFetchEvents {
    ARM_UC_MM_CERTIFICATE_FETCH_UNINIT,
    ARM_UC_MM_CERTIFICATE_FETCH_SUCCESS,
    ARM_UC_MM_CERTIFICATE_FETCH_MISMATCH,
    ARM_UC_MM_CERTIFICATE_FETCH_ERROR,
};

/**
 * @brief Validates one signature of a manifest, once the signing certificate has been found.
 * @param  buffer   Holding buffer for the manifest to validate.
 * @param  ca       Buffer holding the certificate to use in verification
 * @param  sigIndex Index of the manifest signature to verify with this certificate
 * @retval          MFST_ERR_DER_FORMAT on parse error
 * @retval          MFST_ERR_CERT_INVALID if the certificate is not valid
 * @retval          MFST_ERR_INVALID_SIGNATURE if the signature is invalid
 * @retval          MFST_ERR_NONE for a valid signature
 */
static arm_uc_error_t ARM_UC_mmValidateSignatureCert(arm_uc_buffer_t* buffer, arm_uc_buffer_t* ca, uint32_t sigIndex)
{
    const uint32_t fieldIDs[] = {ARM_UC_MM_DER_SIG_HASH, ARM_UC_MM_DER_SIG_SIGNATURES};
    arm_uc_buffer_t fields[ARRAY_SIZE(fieldIDs)];

    // Get the signature list
    int rc = ARM_UC_mmDERGetSignedResourceValues(buffer, ARRAY_SIZE(fieldIDs), fieldIDs, fields);
    if (rc) return (arm_uc_error_t){MFST_ERR_DER_FORMAT};

    // Get the specified signature block
    arm_uc_buffer_t sigblock;
    rc = ARM_UC_mmDERGetSequenceElement(&fields[1], sigIndex, &sigblock);
    if (rc) return (arm_uc_error_t){MFST_ERR_DER_FORMAT};

    // Load the specified signature out of the signature block
    arm_uc_buffer_t sig;
    const uint32_t sigID = ARM_UC_MM_DER_SIG_SIGNATURE;
    rc = ARM_UC_mmDERParseTree(&arm_uc_mmSignatures[0], &sigblock, 1U, &sigID, &sig);
    if (rc) return (arm_uc_error_t){MFST_ERR_DER_FORMAT};

    // Validate the signature
    return ARM_UC_verifyPkSignature(ca, &fields[0], &sig);
}

struct {
    arm_uc_mm_validate_signature_context_t* ctx;
    arm_uc_callback_t callbackStorage;
} arm_uc_mmSignatureVerificationContext;


/**
 * @brief Callback function to continue signature verification once the certificate has been found
 * @details This function should be called by the certificate lookup function, which is provided by the application.
 *          The certificate lookup function should call this callback regardless of success or failure so that errors
 *          can be reported correctly.
 *
 *          Caveats:
 *          The certificate supplied here MUST be the same buffer as was provided to the certificate fetch function.
 *          The fingerprint supplied here MUST be the same buffer as was provided to the certificate fetch function.
 *
 *          These requirements are in place to ensure that only one signature verification may be carried out at a time.
 *
 *          Once the basic checks are performed in the callback, it schedules the manifest manager to execute later.
 *
 * @param status      Error code provided by the certificat lookup function
 * @param certificate Buffer containing the certificate
 * @param fingerprint Buffer containing the certificate fingerprint
 */
void ARM_UC_mmCertificateCallback(arm_uc_error_t status, const arm_uc_buffer_t* certificate, const arm_uc_buffer_t* fingerprint)
{
    uint32_t event = ARM_UC_MM_CERTIFICATE_FETCH_UNINIT;
    UC_MMGR_TRACE("%s (%u)\n", __PRETTY_FUNCTION__, (unsigned)event);
    if (status.error == ERR_NONE)
    {
        // Verify that this is the same buffer as was provided to the certificate fetch function.
        if (fingerprint != &arm_uc_mmSignatureVerificationContext.ctx->fingerprint ||
            certificate != &arm_uc_mmSignatureVerificationContext.ctx->cert)
        {
            event = ARM_UC_MM_CERTIFICATE_FETCH_MISMATCH;
        }
        else
        {
            event = ARM_UC_MM_CERTIFICATE_FETCH_SUCCESS;
        }
    }
    else
    {
        // Store the error for later reporting
        arm_uc_mmSignatureVerificationContext.ctx->storedError = status;
        event = ARM_UC_MM_CERTIFICATE_FETCH_ERROR;
    }
    // Post the Manifest Manager state machine entry point to the Update Client event queue
    UC_MMGR_TRACE("%s Posting ARM_UC_mmVerifySignatureEntry(%lu)\n", __PRETTY_FUNCTION__, event);
    ARM_UC_PostCallback(&arm_uc_mmSignatureVerificationContext.callbackStorage, ARM_UC_mmVerifySignatureEntry, event);
}

/**
 * @brief State machine that controls the verification of signatures.
 * @details First, the state machine attempts to fetch the certificate. When the certificate has been fetched,
 *          the state machine validates the signature, then alerts the calling application with the result.
 *
 *
 * @param[in]  ctx   Context pointer for the state machine
 * @param[in]  event Event to move the state machine forward
 * @retval           MFST_ERR_NONE on success
 * @retval           MFST_ERR_PENDING when the validation has not completed and is waiting for external input
 *                   (e.g. certificate fetching)
 * @retval           Another error code otherwise.
 */
static arm_uc_error_t ARM_UC_mmValidateSignatureFSM(arm_uc_mm_validate_signature_context_t* ctx, uint32_t event)
{
    arm_uc_error_t err = {MFST_ERR_NONE};
    enum arm_uc_mm_pk_sig_state oldState;
    UC_MMGR_TRACE("%s (%lu)\n", __PRETTY_FUNCTION__, event);
    do
    {
        oldState = ctx->state;
        UC_MMGR_TRACE("%s state:%u\n", __PRETTY_FUNCTION__, oldState);
        switch(ctx->state)
        {
            case UCMM_PKSIG_STATE_FIND_CA:
                // Start the search for a certificate
                // This state transitions automatically to UCMM_PKSIG_STATE_FINDING_CA unless there is an error
                err = ARM_UC_certificateFetch(&ctx->cert,
                                              &ctx->fingerprint,
                                              &ctx->certList,
                                              ARM_UC_mmCertificateCallback);
                if (err.error == ERR_NONE || err.code == MFST_ERR_PENDING)
                {
                    ctx->state = UCMM_PKSIG_STATE_FINDING_CA;
                    err.code = MFST_ERR_PENDING;
                }
                break;
            case UCMM_PKSIG_STATE_FINDING_CA:
                // Wait the Certificate fetch to complete. On completion, this state decides what to do with the result.
                switch(event)
                {
                    // If the certificate was fetched successfully, proceed to signature verification
                    case ARM_UC_MM_CERTIFICATE_FETCH_SUCCESS:
                        err.code = MFST_ERR_NONE;
                        ctx->state = UCMM_PKSIG_STATE_CHECK;
                        break;
                    // If an error occured, extract the error.
                    case ARM_UC_MM_CERTIFICATE_FETCH_ERROR:
                        err = ctx->storedError;
                        break;
                    // Otherwise, report a bad event.
                    case ARM_UC_MM_CERTIFICATE_FETCH_UNINIT:
                    case ARM_UC_MM_CERTIFICATE_FETCH_MISMATCH:
                    default:
                        err.code = MFST_ERR_BAD_EVENT;
                        break;
                }
                break;
            // Validate the signature
            case UCMM_PKSIG_STATE_CHECK:
                err = ARM_UC_mmValidateSignatureCert(ctx->manifest,
                    &ctx->cert, ctx->sigIndex);
                if (err.code == MFST_ERR_NONE)
                {
                    ctx->state = UCMM_PKSIG_STATE_IDLE;
                }
                break;
            case UCMM_PKSIG_STATE_IDLE:
                err.code = MFST_ERR_NONE;
                // The Entry function will report success after this state exits.
                break;
            default:
                err = (arm_uc_error_t){MFST_ERR_INVALID_STATE};
                break;
        }

    } while (err.code == MFST_ERR_NONE && ctx->state != oldState);
    UC_MMGR_TRACE("%s() return code: %c%c:%hu (%s)\n",
        __PRETTY_FUNCTION__, err.modulecc[0], err.modulecc[1], err.error, ARM_UC_err2Str(err));
    return err;
}
/**
 * @brief Start signature verification.
 * @details This API initiates a signature verification. The actual signature verification is carried out by
 *
 *
 * @param[in]  ctx        Signature validation context. This contains all the state used by the signature validator.
 * @param[in]  buffer     A buffer containing the manifest to verify
 * @param[in]  certBuffer A temporary storage buffer for certificate fetching
 * @param[in]  sigIndex   Index of the signature to verify.
 * @retval                MFST_ERR_NONE on success
 * @retval                MFST_ERR_PENDING when the validation has not completed and is waiting for external input
 *                        (e.g. certificate fetching)
 * @retval                Another error code otherwise.
 */
arm_uc_error_t ARM_UC_mmValidateSignature(arm_uc_mm_validate_signature_context_t* ctx,
                                          void (*applicationEventHandler)(uint32_t),
                                          arm_uc_buffer_t* buffer,
                                          arm_uc_buffer_t* certBuffer,
                                          uint32_t sigIndex)
{
    UC_MMGR_TRACE("%s (%u)\n", __PRETTY_FUNCTION__, (unsigned)sigIndex);
    arm_uc_error_t err = {MFST_ERR_NONE};
    if (ctx == NULL)
    {
        ARM_UC_SET_ERROR(err, MFST_ERR_NULL_PTR);
    }
    if (err.error == ERR_NONE)
    {
#ifdef ATOMIC_QUEUE_CONFIG_ELEMENT_LOCK
        arm_uc_mmSignatureVerificationContext.callbackStorage.lock = 0;
#endif
        arm_uc_mmSignatureVerificationContext.ctx = ctx;
        // Extract the certificate identifier from the manifest
        err = ARM_UC_mmGetCertificateId(buffer, sigIndex, &arm_uc_mmSignatureVerificationContext.ctx->fingerprint);
        UC_MMGR_TRACE("%s %c%c:%hu (%s)\n", "Get Certificate ID return code:", err.modulecc[0], err.modulecc[1], err.error, ARM_UC_err2Str(err));
    }
    if(err.error == 0 && ctx)
    {
        // Copy all the relevant inputs into the state variable
        err.code = MFST_ERR_NONE;
        arm_uc_mmSignatureVerificationContext.ctx->manifest                = buffer;
        arm_uc_mmSignatureVerificationContext.ctx->applicationEventHandler = applicationEventHandler;
        arm_uc_mmSignatureVerificationContext.ctx->state                   = UCMM_PKSIG_STATE_FIND_CA;
        arm_uc_mmSignatureVerificationContext.ctx->sigIndex                = sigIndex;
        ARM_UC_buffer_shallow_copy(&arm_uc_mmSignatureVerificationContext.ctx->cert, certBuffer);
        UC_MMGR_TRACE("%s Posting ARM_UC_mmVerifySignatureEntry(%lu)\n", __PRETTY_FUNCTION__, ARM_UC_MM_EVENT_BEGIN);
        ARM_UC_PostCallback(&arm_uc_mmSignatureVerificationContext.callbackStorage, ARM_UC_mmVerifySignatureEntry, ARM_UC_MM_EVENT_BEGIN);
    }
    UC_MMGR_TRACE("%s %c%c:%hu (%s)\n", __PRETTY_FUNCTION__, err.modulecc[0], err.modulecc[1], err.error, ARM_UC_err2Str(err));
    return err;
}

/**
 * @brief Main entry point for callbacks to enter the state machine.
 * @details Calls the signature verification state machine. If the result is not Pending, calls the application event
 *          handler with a result code.
 *          Application event handler is invoked directly, not queued because this function should have minimal stack
 *          and it should be called directly from the event queue.
 * @param[in] event Event to forward to the state machine
 */
void ARM_UC_mmVerifySignatureEntry(uint32_t event)
{
    UC_MMGR_TRACE("%s (%u)\n", __PRETTY_FUNCTION__, (unsigned)event);
    arm_uc_error_t err = ARM_UC_mmValidateSignatureFSM(arm_uc_mmSignatureVerificationContext.ctx , event);
    if (err.code != MFST_ERR_NONE && err.code != MFST_ERR_PENDING)
    {
        arm_uc_mmSignatureVerificationContext.ctx->storedError = err;
        arm_uc_mmSignatureVerificationContext.ctx->applicationEventHandler(ARM_UC_MM_RC_ERROR);
    }
    if (err.code == MFST_ERR_NONE && arm_uc_mmSignatureVerificationContext.ctx->state == UCMM_PKSIG_STATE_IDLE)
    {
        // A callback is not posted since this runs inside
        arm_uc_mmSignatureVerificationContext.ctx->applicationEventHandler(ARM_UC_MM_RC_DONE);
    }
    UC_MMGR_TRACE("%s %c%c:%hu (%s)\n", __PRETTY_FUNCTION__, err.modulecc[0], err.modulecc[1], err.error, ARM_UC_err2Str(err));
}
