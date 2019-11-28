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
#include "arm_uc_mmInit.h"
#include "arm_uc_mmFSMHelper.h"
#include "arm_uc_mmFetchFirmwareInfo.h"
#include "arm_uc_mmInsertManifest.h"

#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "update-client-manifest-manager/update-client-manifest-manager.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"

#include "update-client-common/arm_uc_scheduler.h"

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

arm_uc_error_t ARM_UC_mmSetState(enum arm_uc_mmState_t newState)
{
    arm_uc_mmPersistentContext.state = newState;
    return (arm_uc_error_t) {ERR_NONE};
}

#if 0
static void printCryptoFlags(ucmm_crypto_flags_t *flags)
{
    printf("ucmm_crypto_flags_t @ %p = {\n", flags);
    printf("    .hash = %u,\n", flags->hash);
    printf("    .hmac = %u,\n", flags->hmac);
    printf("    .rsa  = %u,\n", flags->rsa);
    printf("    .ecc  = %u,\n", flags->ecc);
    printf("    .aes  = %u,\n", flags->aes);
    printf("}\n");
}
#endif

arm_uc_error_t ARM_UC_mmFSM(uintptr_t event)
{
    UC_MMGR_TRACE("> %s (%u)\n", __PRETTY_FUNCTION__, (unsigned)event);

    arm_uc_error_t err = {ERR_NONE};
    enum arm_uc_mmState_t oldState;
    do {
        oldState = arm_uc_mmPersistentContext.state;
        switch (arm_uc_mmPersistentContext.state) {
            case ARM_UC_MM_STATE_IDLE:
                err = (arm_uc_error_t) {ERR_NONE};
                break;
// Placeholder for init
#if 0
            case ARM_UC_MM_STATE_INIT:
                err = arm_uc_mmInitFSM(event);
                if (err.code == ERR_NONE) {
                    err = ARM_UC_mmSetState(ARM_UC_MM_STATE_IDLE);
                    ARM_UC_PostCallback(&arm_uc_mmContext.cfstore_callback_storage, arm_uc_mmPersistentContext.applicationEventHandler,
                                        ARM_UC_MM_RC_DONE);
                }
                break;
#endif
            case ARM_UC_MM_STATE_INSERTING:
                err = ARM_UC_mmInsertFSM(event);
                if (err.code == ERR_NONE) {
                    err = ARM_UC_mmSetState(ARM_UC_MM_STATE_IDLE);
                    ARM_UC_PostCallback(&arm_uc_mmPersistentContext.applicationCallbackStorage,
                                        arm_uc_mmPersistentContext.applicationEventHandler, ARM_UC_MM_RC_DONE);
                }
                break;
            case ARM_UC_MM_STATE_FWINFO:
                err = ARM_UC_mmFetchFirmwareInfoFSM(event);
                if (err.code == ERR_NONE) {
                    err = ARM_UC_mmSetState(ARM_UC_MM_STATE_IDLE);
                    ARM_UC_PostCallback(&arm_uc_mmPersistentContext.applicationCallbackStorage,
                                        arm_uc_mmPersistentContext.applicationEventHandler, ARM_UC_MM_RC_DONE);
                }
                break;
            case ARM_UC_MM_STATE_TEST:
                if (arm_uc_mmPersistentContext.testFSM != NULL) {
                    err = arm_uc_mmPersistentContext.testFSM(event);
                    if (err.code == ERR_NONE) {
                        err = ARM_UC_mmSetState(ARM_UC_MM_STATE_IDLE);
                        ARM_UC_PostCallback(&arm_uc_mmPersistentContext.applicationCallbackStorage,
                                            arm_uc_mmPersistentContext.applicationEventHandler, ARM_UC_MM_RC_DONE);
                    }
                    break;
                }
            // fall through
            case ARM_UC_MM_STATE_INVALID:
            default:
                err = (arm_uc_error_t) {MFST_ERR_INVALID_STATE};
                break;
        }
    } while (err.code == ERR_NONE && oldState != arm_uc_mmPersistentContext.state);
    UC_MMGR_TRACE("< %s %c%c:%hu (%s)\n", __PRETTY_FUNCTION__, err.modulecc[0],
                        CC_ASCII(err.modulecc[0]), CC_ASCII(err.modulecc[1]), ARM_UC_err2Str(err));
    return err;
}

void ARM_UC_mmCallbackFSMEntry(uintptr_t event)
{
    UC_MMGR_TRACE("> %s (%u)\n", __PRETTY_FUNCTION__, (unsigned)event);
    arm_uc_error_t err = ARM_UC_mmFSM(event);
    if (err.code != ERR_NONE && err.code != MFST_ERR_PENDING) {
        arm_uc_mmPersistentContext.reportedError = err;
        arm_uc_mmPersistentContext.applicationEventHandler((uint32_t)ARM_UC_MM_RC_ERROR);
    }
    UC_MMGR_TRACE("< %s %c%c:%hu (%s)\n", __PRETTY_FUNCTION__,
                        CC_ASCII(err.modulecc[0]), CC_ASCII(err.modulecc[1]), err.error, ARM_UC_err2Str(err));
}

#endif
