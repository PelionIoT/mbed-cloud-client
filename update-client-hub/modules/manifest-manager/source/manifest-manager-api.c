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

#include "arm_uc_mmCommon.h"
#include "arm_uc_mmConfig.h"
#include "arm_uc_mmStateSelector.h"
#include "arm_uc_mmInit.h"

#include "update-client-manifest-manager/update-client-manifest-manager.h"
#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"
#include "update-client-manifest-manager/arm-pal-kv.h"

#include "update-client-common/arm_uc_scheduler.h"
#include "update-client-common/arm_uc_utilities.h"
#include "update-client-common/arm_uc_error.h"

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/**
 * @file manifest_manager.c
 * @brief Manifest Manager API
 * @details This file specifies the API used to interact with the manifest manager
 */

arm_uc_error_t ARM_UC_mmInit(arm_uc_mmContext_t **mmCtx, void (*event_handler)(uint32_t),
                             const arm_pal_key_value_api *api)
{
    arm_uc_error_t err = {ERR_NONE};
    if (mmCtx == NULL || *mmCtx == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }

    arm_uc_mmPersistentContext.ctx = mmCtx;
    arm_uc_mmPersistentContext.applicationEventHandler = event_handler;
    arm_uc_mmPersistentContext.testFSM = NULL;

    // initialize callback node
    arm_uc_mmPersistentContext.applicationCallbackStorage.lock = 0;

    ARM_UC_PostCallback(&arm_uc_mmPersistentContext.applicationCallbackStorage, event_handler, ARM_UC_MM_RC_DONE);
// This code will be re-enabled when storage is available
#if 0
    ARM_UC_mmCfStoreInit(api);

    // Initialize the Init FSM
    arm_uc_mmContext_t *ctx = *mmCtx;
    ctx->init.state = ARM_UC_MM_INIT_BEGIN;

    err = ARM_UC_mmSetState(ARM_UC_MM_STATE_INIT);
    if (err.code != ERR_NONE) {
        return err;
    }
    // Start the Init FSM
    ARM_UC_PostCallback(&ctx->init.callbackStorage, ARM_UC_mmCallbackFSMEntry, ARM_UC_MM_EVENT_BEGIN);
#endif
    return err;
}

arm_uc_error_t ARM_UC_mmInsert(arm_uc_mmContext_t **ctx, arm_uc_buffer_t *buffer, arm_uc_buffer_t *certificateStorage,
                               arm_uc_manifest_handle_t *ID)
{
    if (ctx == NULL || *ctx == NULL || buffer == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }
    arm_uc_mmPersistentContext.ctx = ctx;
    // Setup the state machine
    arm_uc_error_t err = ARM_UC_mmSetState(ARM_UC_MM_STATE_INSERTING);
    if (err.code != ERR_NONE) {
        return err;
    }
    struct arm_uc_mmInsertContext_t *insertCtx = &(*arm_uc_mmPersistentContext.ctx)->insert;
    // Store the buffer pointer
    ARM_UC_buffer_shallow_copy(&insertCtx->manifest, buffer);
    insertCtx->state = ARM_UC_MM_INS_STATE_BEGIN;
    // Store the ID pointer
    insertCtx->ID = ID;
    // Store the certificate buffer
    ARM_UC_buffer_shallow_copy(&insertCtx->certificateStorage, certificateStorage);

    // initialize callback node
    insertCtx->callbackStorage.lock = 0;

    // Start the FSM
    ARM_UC_PostCallback(&insertCtx->callbackStorage, ARM_UC_mmCallbackFSMEntry, ARM_UC_MM_EVENT_BEGIN);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmFetchFirmwareInfo(arm_uc_mmContext_t **ctx, struct manifest_firmware_info_t *info,
                                          const arm_uc_manifest_handle_t *ID)
{
    if (ctx == NULL || *ctx == NULL || info == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }
    arm_uc_mmPersistentContext.ctx = ctx;
    // Initialize the state machine
    arm_uc_error_t err = ARM_UC_mmSetState(ARM_UC_MM_STATE_FWINFO);
    if (err.code != ERR_NONE) {
        return err;
    }
    struct arm_uc_mm_fw_context_t *fwCtx = &(*arm_uc_mmPersistentContext.ctx)->getFw;
    fwCtx->state = ARM_UC_MM_FW_STATE_BEGIN;
    fwCtx->info  = info;

    // initialize callback node
    fwCtx->callbackStorage.lock = 0;

    // Start the state machine
    ARM_UC_PostCallback(&fwCtx->callbackStorage, ARM_UC_mmCallbackFSMEntry, ARM_UC_MM_EVENT_BEGIN);

    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmFetchNextFirmwareInfo(struct manifest_firmware_info_t *info)
{
    struct arm_uc_mm_fw_context_t *fwCtx = &(*arm_uc_mmPersistentContext.ctx)->getFw;
    fwCtx->info = info;

    // initialize callback node
    fwCtx->callbackStorage.lock = 0;

    // Continue the state machine
    ARM_UC_PostCallback(&fwCtx->callbackStorage, ARM_UC_mmCallbackFSMEntry, ARM_UC_MM_EVENT_BEGIN);
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetError()
{
    return arm_uc_mmPersistentContext.reportedError;
}

#if ARM_UC_MM_ENABLE_TEST_VECTORS
arm_uc_error_t ARM_UC_mmRegisterTestHook(ARM_UC_mmTestHook_t hook)
{
    arm_uc_error_t err = {ERR_NONE};
    arm_uc_mmPersistentContext.testHook = hook;
    return err;
}
#endif
