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

#include "arm_uc_mmInit.h"
#include "arm_uc_mmCommon.h"
#if !MANIFEST_MANAGER_NO_STORAGE
#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "arm_uc_mmGetLatestTimestamp.h"
#include "arm_uc_mm_derparse.h"
#include "cfstore-fsm.h"
#include "crypto-fsm.h"
#include "accessors.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_common.h"
#include "update-client-common/arm_uc_error.h"
#include "mbedtls/sha256.h"

#include "arm_uc_mmFSMHelper.h"

#ifndef min
#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#endif

const char *ARM_UC_mmInitState2Str(uint32_t state)
{
    switch (state) {
#define ENUM_AUTO(name) case name: return #name;
#define ENUM_FIXED(name, val) ENUM_AUTO(name)
            ARM_UC_MM_INIT_STATE_LIST
#undef ENUM_FIXED
#undef ENUM_AUTO
        default:
            return "Unknown State";
    }
}



arm_uc_error_t arm_uc_mmInitFSM(uint32_t event)
{
    if (arm_uc_mmPersistentContext.ctx == NULL || *arm_uc_mmPersistentContext.ctx == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }
    struct arm_uc_mmInitContext_t *ctx = &(*arm_uc_mmPersistentContext.ctx)->init;
    arm_uc_error_t err = {MFST_ERR_PENDING};

    ARM_UC_MM_FSM_HELPER_START(*ctx, ARM_UC_mmInitState2Str) {
    case ARM_UC_MM_INIT_BEGIN:
        // Find the latest manifest.
        ARM_UC_MM_SET_BUFFER(ctx->keyPath, ctx->pathBuffer);
        err = getLatestManifestTimestamp(&ctx->timestamp, &ctx->keyPath);
        ctx->state = ARM_UC_MM_INIT_LATEST_MFST;
        // clear the missing dep flag
        ctx->missingDep = 0;
        // Set the root manifest flag
        ctx->root = 1;

        event = ARM_UC_MM_EVENT_BEGIN;
        break;
    case ARM_UC_MM_INIT_LATEST_MFST: {
            err = getLatestManifestTimestampFSM(event);
            if (err.code != MFST_ERR_NONE) {
                break;
            }
            if (ctx->timestamp == 0) {
                err.code = MFST_ERR_NO_MANIFEST;
                break;
            }
            // Copy out the root manifest's base path
            strncpy((char *)ctx->rootManifestBasePath, (char *)ctx->keyPath.ptr, sizeof(ctx->rootManifestBasePath) - 1);
            ctx->rootManifestBasePath[sizeof(ctx->rootManifestBasePath) - 1] = 0;
            // Modify the key path.
            char *pos = (char *)ctx->keyPath.ptr + strlen((char *)ctx->keyPath.ptr) - strlen("ts");
            *pos = 'm';
            *(pos + 1) = 0;
            // Setup the manifest buffer
            ARM_UC_MM_SET_BUFFER(ctx->manifest, ctx->manifestBuffer);
            // Find the manifest
            err = ARM_UC_mmCfStoreFindKey(&ctx->keyPath);
            if (err.code != MFST_ERR_NONE) {
                break;
            }
            event = ARM_UC_MM_EVENT_CF_BEGIN;
            ctx->state = ARM_UC_MM_INIT_FINDING;
            // no break;
        }
    case ARM_UC_MM_INIT_FINDING:
        if (event == UCMM_EVENT_CF_FIND_FAILED) {
            if (ctx->root) {
                //TODO: assert! This should not be possible!
                err.code = MFST_ERR_INVALID_STATE;
            } else {
                // No more deps to find.
                err.code = MFST_ERR_NONE;
            }
            break;
        }
        err = ARM_UC_mmCfStoreFindKeyFSM(event);
        if (err.code != MFST_ERR_NONE) {
            break;
        }
        // Read the manifest
        err = ARM_UC_mmCfStoreReadLastKey(&ctx->manifest);
        if (err.code != MFST_ERR_NONE) {
            break;
        }
        event = ARM_UC_MM_EVENT_CF_BEGIN;
        ctx->state = ARM_UC_MM_INIT_READING;
        // no break;
    case ARM_UC_MM_INIT_READING:
        // Read the manifest into a buffer
        err = ARM_UC_mmCfStoreReadLastKeyFSM(event);
        if (err.code != MFST_ERR_NONE) {
            break;
        }
        ctx->state = ARM_UC_MM_INIT_STATE_HASH_VERIFY;
        // Preserve the manifest key
        ARM_UC_mmCfStorePreserveLastKey();

        // no break;
    case ARM_UC_MM_INIT_STATE_HASH_VERIFY:
        // Verify the manifest hash
        err = ucmmValidateManifestHash(&ctx->manifest);
        if (err.code == MFST_ERR_NONE) {
            uint32_t val;
            err = ARM_UC_mmGetCryptoMode(&ctx->manifest, &val);
            if (err.code != MFST_ERR_NONE) {
                break;
            }
            ucmm_crypto_flags_t cryptoMode = ARM_UC_mmGetCryptoFlags(val);
            if (cryptoMode.ecc || cryptoMode.rsa) {
                ctx->state = ARM_UC_MM_INIT_STATE_PK_VERIFY;
            } else {
                ctx->state = ARM_UC_MM_INIT_STATE_ROOT_DEPS_VERIFY_BEGIN;
            }
        }
        break;
    case ARM_UC_MM_INIT_STATE_PK_VERIFY:
        // Verify the manifest signature
        err = ucmmValidateSignature(&ctx->manifest);
        if (err.code == MFST_ERR_NONE) {
            ctx->state = ARM_UC_MM_INIT_STATE_PK_VERIFYING;
        }
        break;
    case ARM_UC_MM_INIT_STATE_PK_VERIFYING:
        err = ucmmValidateSignatureFSM(event);
        if (err.code == MFST_ERR_NONE) {
            ctx->state = ARM_UC_MM_INIT_STATE_ROOT_DEPS_VERIFY_BEGIN;
        }
        break;
    case ARM_UC_MM_INIT_STATE_ROOT_DEPS_VERIFY_BEGIN:
        // ATTACKVECTOR: If an attacker can add a manifest to the dependency prefix in the config store, the manifest
        // manager has no way to know that it is not valid, due to the flat file heirarchy.
        ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_MANIFEST_BEGIN;
        // NO BREAK;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_MANIFEST_BEGIN:
        // Loop: manifest
        // Set the depidx to 0
        ctx->depidx = 0;
        ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_GET_HASH;
        // NO BREAK;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_GET_HASH: {
            arm_uc_buffer_t dependency;
            arm_uc_buffer_t hash;
            // Read the dependency at depidx
            err = ARM_UC_mmGetManifestLinksElement(&ctx->manifest, ctx->depidx, &dependency);
            // If there isn't one
            if (err.code != MFST_ERR_NONE) {
                break;
            }
            if (dependency.ptr == NULL) {
                // Exit Loop: dependency
                ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_END;
                err.code = MFST_ERR_NONE;
                break;
            }
            // Get the dependency hash
            err = ARM_UC_mmGetManifestLinksHash(&dependency, &hash);
            if (err.code != MFST_ERR_NONE) {
                break;
            }
            // Store the dependency hash
            memcpy(ctx->currentHash, hash.ptr, min(hash.size, sizeof(ctx->currentHash)));
            // Format the dependency search key
            // The result of this operation is:
            // com.arm.mbed.update.mm.m.<root manifest hash>.deps.<dependency hash>.m
            // ASSUMES sizeof keypath > sizeof rootManifestBasePath
            strncpy((char *)ctx->keyPath.ptr, (char *)ctx->rootManifestBasePath, sizeof(ctx->keyPath.ptr));
            ctx->keyPath.size = strlen(ctx->keyPath.ptr);
            // Back up one space to remove the 'm'
            strncpy((char *)ctx->keyPath.ptr + ctx->keyPath.size - 1, "deps.", ctx->keyPath.size_max - ctx->keyPath.size);
            ctx->keyPath.size = strlen(ctx->keyPath.ptr);
            ARM_UC_Base64Enc(ctx->keyPath.ptr + ctx->keyPath.size, ctx->keyPath.size_max - ctx->keyPath.size, &hash);
            ctx->keyPath.size = strlen(ctx->keyPath.ptr);
            strncpy((char *)ctx->keyPath.ptr + ctx->keyPath.size, ".m", ctx->keyPath.size_max - ctx->keyPath.size);
            ctx->keyPath.size += 3; // add one for null terminator

            // Find the dependency in the config store
            err = ucmmCfstoreFindAndRead((char *)ctx->keyPath.ptr, &ctx->manifest);
            if (err.code == MFST_ERR_NONE) {
                event = ARM_UC_MM_EVENT_BEGIN;
                ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_READING_DEPENDENCY;
            }
            break;
        }
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_READING_DEPENDENCY:
        // If there is no matching dependency
        if (event == UCMM_EVENT_CF_FIND_FAILED) {
            // Set the missing dep flag
            ctx->missingDep = 1;
            ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECK;
            // Continue...
            err.code = MFST_ERR_NONE;
            break;
        }
        // Find/Read the dependency manifest
        err = ucmmCfstoreFindAndReadFSM(event);
        if (err.code != MFST_ERR_NONE) {
            break;
        }
        // There is a matching dependency
        ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_CHECK_HASH;
        // No break;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_CHECK_HASH: {
#if MAX_HASH_BYTES != 256/8
#error Hash size mismatch
#endif
            uint8_t localhash[MAX_HASH_BYTES];
            arm_uc_buffer_t local = {
                .size_max = MAX_HASH_BYTES,
                .size     = 256 / 8,
                .ptr      = localhash
            };
            arm_uc_buffer_t resource;
            const int32_t valueID = ARM_UC_MM_DER_RESOURCE;
            int rc = ARM_UC_mmDERGetSignedResourceValues(&resource, 1, &valueID, &resource);
            if (rc) {
                err.code = MFST_ERR_DER_FORMAT;
                break;
            }
            {
                // Calculate the dependency hash
                mbedtls_sha256_context ctx;
                mbedtls_sha256_init(&ctx);
                mbedtls_sha256_starts(&ctx, 0);
                mbedtls_sha256_update(&ctx, resource.ptr, resource.size);
                mbedtls_sha256_finish(&ctx, local.ptr);
            }
            {
                arm_uc_buffer_t remote = {
                    .size_max = MAX_HASH_BYTES,
                    .size     = 256 / 8,
                    .ptr      = ctx->currentHash
                };
                // Validate the dependency hash
                if (ARM_UC_BinCompareCT(&local, &remote)) {
                    // If invalid, Set the missing dep flag
                    ctx->missingDep = 1;
                    // Delete the manifest
                    ARM_UC_mmCfStoreDeleteLastKey();
                    ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_DELETE;
                    event = ARM_UC_MM_EVENT_CF_BEGIN;
                } else {
                    // End Loop: dependency
                    ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READ;
                    // Increment the depidx
                    ctx->depidx++;
                }
            }
            break;
        }
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_DELETE:
        err = ARM_UC_mmCfStoreDeleteLastKeyFSM(event);
        if (err.code == MFST_ERR_NONE) {
            // Make sure a URI exists.
            ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECK;
        }
        break;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECK: {
            // modify the search path
            char *pos = (char *)ctx->keyPath.ptr + ctx->keyPath.size - 2; // null terminator
            strncpy(pos, "uri", ctx->keyPath.size_max - (ctx->keyPath.size - 2)); // null terminator
            // Check if there is a URI entry
            // HACK: No API for find without ovewriting the existing stored key. Use find/read even though we don't need the
            // data.
            err = ucmmCfstoreFindAndRead((char *)ctx->keyPath.ptr, &ctx->manifest);
            if (err.code != MFST_ERR_NONE) {
                break;
            }
            ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECKING;
            event = ARM_UC_MM_EVENT_CF_BEGIN;
            // no break
        }
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECKING:
        if (event == UCMM_EVENT_CF_FIND_FAILED) {
            // TODO: Erase all deps and start over.
            err.code = MFST_ERR_INVALID_STATE;
            break;
        }
        err = ucmmCfstoreFindAndReadFSM(event);
        if (err.code == MFST_ERR_NONE) {
            // Increment the depidx
            ctx->depidx++;
            // End Loop: dependency
            ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READ;
        }
        break;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READ:
        // Loop: dependency
        // Restore the manifest key
        ARM_UC_mmCfStoreRestoreLastKey();
        // Seek the current key
        err = ARM_UC_mmCfStoreSeekLastKey(0);
        if (err.code == MFST_ERR_NONE) {
            ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_SEEKING;
        }
        break;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_SEEKING:
        err = ARM_UC_mmCfStoreSeekLastKeyFSM(event);
        if (err.code != MFST_ERR_NONE) {
            break;
        }
        // Read the current key
        err = ARM_UC_mmCfStoreReadLastKey(&ctx->manifest);
        if (err.code != MFST_ERR_NONE) {
            break;
        }
        ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READING;
        event = ARM_UC_MM_EVENT_CF_BEGIN;
        // no break
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READING:
        err = ARM_UC_mmCfStoreReadLastKeyFSM(event);
        if (err.code == MFST_ERR_NONE) {
            ctx->state = ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_GET_HASH;
            // Preserve the manifest key
            ARM_UC_mmCfStorePreserveLastKey();
        }
        break;
    case ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_END:
        // Format the dependency search key
        strncpy((char *)ctx->keyPath.ptr, (char *)ctx->rootManifestBasePath, sizeof(ctx->rootManifestBasePath));
        ctx->keyPath.size = sizeof(ctx->rootManifestBasePath) - 1;
        strncpy((char *)ctx->keyPath.ptr + ctx->keyPath.size, ".deps.*", ctx->keyPath.size_max - ctx->keyPath.size);
        ctx->keyPath.size += sizeof(".deps.*") - 1;
        // If the root flag is set
        if (ctx->root) {
            // Clear the root flag
            ctx->root = 0;
            // Start the dependency search
            err = ARM_UC_mmCfStoreFindKey(&ctx->keyPath);
        } else {
            // Continue the dependency search
            err = ARM_UC_mmCfStoreFindNextKey();
        }
        if (err.code == MFST_ERR_NONE) {
            event = ARM_UC_MM_EVENT_CF_BEGIN;
            // End Loop: manifest
            ctx->state = ARM_UC_MM_INIT_FINDING;
        }
        break;
    default:
        err.code = MFST_ERR_INVALID_STATE;
        break;
    }
    ARM_UC_MM_FSM_HELPER_FINISH(*ctx);
    if (err.code == MFST_ERR_NONE && ctx->missingDep == 1) {
        // TODO: Configure & trigger insert FSM
    }
    return err;
}

#endif // !MANIFEST_MANAGER_NO_STORAGE
