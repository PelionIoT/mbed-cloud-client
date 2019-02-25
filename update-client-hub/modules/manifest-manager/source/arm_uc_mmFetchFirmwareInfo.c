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
#include "arm_uc_mmDerManifestAccessors.h"
#include "arm_uc_mmDerManifestParser.h"
#include "arm_uc_mmFSMHelper.h"
#include "update-client-common/arm_uc_scheduler.h"

#include "update-client-manifest-manager/update-client-manifest-manager.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"


#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>


#undef ARRAY_SIZE
#define ARRAY_SIZE(ENUM_AUTO)\
    (sizeof(ENUM_AUTO)/sizeof((ENUM_AUTO)[0]))


#define ARM_UC_MM_MFST_IMAGE_REF_FIELDS \
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_ENUM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_STRG_ID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE)\

static const int32_t imageRefFields [] = {
#define ENUM_AUTO(ENUM_AUTO) ENUM_AUTO,
    ARM_UC_MM_MFST_IMAGE_REF_FIELDS
#undef ENUM_AUTO
};
enum imageRefFieldIdxs {
#define ENUM_AUTO(ENUM_AUTO) IRF_ ## ENUM_AUTO ## _IDX,
    ARM_UC_MM_MFST_IMAGE_REF_FIELDS
#undef ENUM_AUTO
};

#if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
static const char *ARM_UC_mmFwState2Str(uint32_t state)
{
    switch (state) {
#define ENUM_AUTO(name) case name: return #name;
#define ENUM_FIXED(name, val) ENUM_AUTO(name)
            ARM_UC_MM_FW_STATE_LIST
#undef ENUM_AUTO
#undef ENUM_FIXED
        default:
            return "Unknown State";
    }
}
#endif

int ARM_UC_mmGetImageRef(manifest_firmware_info_t *info, arm_uc_buffer_t *mfst_fwref)
{
    arm_uc_buffer_t buffers[ARRAY_SIZE(imageRefFields)];
    int rc = ARM_UC_mmDERParseTree(arm_uc_mmManifestFirmwareDescription,
                                   mfst_fwref,
                                   ARRAY_SIZE(imageRefFields),
                                   imageRefFields,
                                   buffers);
    if (rc == 0) {
        // Found local key ID and encrypted key
        info->cipherMode = ARM_UC_MM_CIPHERMODE_NONE;
        // TODO: Handle non-enum format
        uint32_t format = ARM_UC_mmDerBuf2Uint(&buffers[IRF_ARM_UC_MM_DER_MFST_FW_FMT_ENUM_IDX]);
        memset(&info->format, 0, sizeof(info->format));
        info->format.words[RFC_4122_WORDS - 1] = htobe(format);

        ARM_UC_buffer_shallow_copy(&info->strgId, &buffers[IRF_ARM_UC_MM_DER_MFST_FW_STRG_ID_IDX]);
        ARM_UC_buffer_shallow_copy(&info->hash, &buffers[IRF_ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH_IDX]);
        ARM_UC_buffer_shallow_copy(&info->uri, &buffers[IRF_ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL_IDX]);
        info->size = ARM_UC_mmDerBuf2Uint(&buffers[IRF_ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE_IDX]);
    }
    return rc;
}

#define ARM_UC_MM_MFST_CRYPT_LOCAL_ID_FIELDS \
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_ENUM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_IV)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_LOCAL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CIPHERKEY)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_STRG_ID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE)\

static const int32_t localEncKeyFields [] = {
#define ENUM_AUTO(ENUM_AUTO) ENUM_AUTO,
    ARM_UC_MM_MFST_CRYPT_LOCAL_ID_FIELDS
#undef ENUM_AUTO
};
enum localEncKeyFieldIdxs {
#define ENUM_AUTO(ENUM_AUTO) LEK_ ## ENUM_AUTO ## _IDX,
    ARM_UC_MM_MFST_CRYPT_LOCAL_ID_FIELDS
#undef ENUM_AUTO
};

int ARM_UC_mmGetLocalIDAndKey(manifest_firmware_info_t *info, arm_uc_buffer_t *mfst_fwref)
{
    arm_uc_buffer_t buffers[ARRAY_SIZE(localEncKeyFields)];
    int rc = ARM_UC_mmDERParseTree(arm_uc_mmManifestFirmwareDescription,
                                   mfst_fwref,
                                   ARRAY_SIZE(localEncKeyFields),
                                   localEncKeyFields,
                                   buffers);
    if (rc == 0) {
        // Found local key ID and encrypted key
        info->cipherMode = ARM_UC_MM_CIPHERMODE_PSK;
        // TODO: Handle non-enum format
        uint32_t format = ARM_UC_mmDerBuf2Uint(&buffers[LEK_ARM_UC_MM_DER_MFST_FW_FMT_ENUM_IDX]);
        memset(&info->format, 0, sizeof(info->format));
        info->format.words[RFC_4122_WORDS - 1] = htobe(format);
        ARM_UC_buffer_shallow_copy(&info->initVector, &buffers[LEK_ARM_UC_MM_DER_MFST_FW_CRYPT_IV_IDX]);
        ARM_UC_buffer_shallow_copy(&info->psk.keyID, &buffers[LEK_ARM_UC_MM_DER_MFST_FW_FMT_ENUM_IDX]);
        ARM_UC_buffer_shallow_copy(&info->psk.cipherKey, &buffers[LEK_ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CIPHERKEY_IDX]);

        ARM_UC_buffer_shallow_copy(&info->strgId, &buffers[LEK_ARM_UC_MM_DER_MFST_FW_STRG_ID_IDX]);
        ARM_UC_buffer_shallow_copy(&info->hash, &buffers[LEK_ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH_IDX]);
        ARM_UC_buffer_shallow_copy(&info->uri, &buffers[LEK_ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL_IDX]);
        info->size = ARM_UC_mmDerBuf2Uint(&buffers[LEK_ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE_IDX]);
    }
    return rc;
}


#define ARM_UC_MM_MFST_CRYPT_CERT_KEY_FIELDS \
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_ENUM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_IV)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_FINGERPRINT)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CIPHERKEY)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_STRG_ID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE)\

static const int32_t certEncKeyFields [] = {
#define ENUM_AUTO(ENUM_AUTO) ENUM_AUTO,
    ARM_UC_MM_MFST_CRYPT_CERT_KEY_FIELDS
#undef ENUM_AUTO
};

enum certEncKeyFieldIdxs {
#define ENUM_AUTO(ENUM_AUTO) CEK_ ## ENUM_AUTO ## _IDX,
    ARM_UC_MM_MFST_CRYPT_CERT_KEY_FIELDS
#undef ENUM_AUTO
};

int ARM_UC_mmGetCertAndKey(manifest_firmware_info_t *info, arm_uc_buffer_t *mfst_fwref)
{
    arm_uc_buffer_t buffers[ARRAY_SIZE(certEncKeyFields)];
    int rc = ARM_UC_mmDERParseTree(arm_uc_mmManifestFirmwareDescription,
                                   mfst_fwref,
                                   ARRAY_SIZE(certEncKeyFields),
                                   certEncKeyFields,
                                   buffers);
    if (rc == 0) {
        info->cipherMode = ARM_UC_MM_CIPHERMODE_CERT_CIPHERKEY;
        // TODO: Handle non-enum format
        uint32_t format = ARM_UC_mmDerBuf2Uint(&buffers[CEK_ARM_UC_MM_DER_MFST_FW_FMT_ENUM_IDX]);
        memset(&info->format, 0, sizeof(info->format));
        info->format.words[RFC_4122_WORDS - 1] = htobe(format);
        ARM_UC_buffer_shallow_copy(&info->initVector, &buffers[CEK_ARM_UC_MM_DER_MFST_FW_CRYPT_IV_IDX]);

        ARM_UC_buffer_shallow_copy(&info->certCK.certFingerPrint,
                                   &buffers[CEK_ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_FINGERPRINT_IDX]);
        ARM_UC_buffer_shallow_copy(&info->certCK.certURL, &buffers[CEK_ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_URL_IDX]);
        ARM_UC_buffer_shallow_copy(&info->certCK.cipherKey, &buffers[CEK_ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_CIPHERKEY_IDX]);

        ARM_UC_buffer_shallow_copy(&info->strgId, &buffers[CEK_ARM_UC_MM_DER_MFST_FW_STRG_ID_IDX]);
        ARM_UC_buffer_shallow_copy(&info->hash, &buffers[CEK_ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH_IDX]);
        ARM_UC_buffer_shallow_copy(&info->uri, &buffers[CEK_ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL_IDX]);
        info->size = ARM_UC_mmDerBuf2Uint(&buffers[CEK_ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE_IDX]);
    }
    return rc;
}


#define ARM_UC_MM_MFST_CRYPT_CERT_KEYTABLE_FIELDS \
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_FMT_ENUM)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_IV)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_FINGERPRINT)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_KEYTABLE_REF)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_STRG_ID)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL)\
    ENUM_AUTO(ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE)\

static const int32_t certKeyTableFields [] = {
#define ENUM_AUTO(ENUM_AUTO) ENUM_AUTO,
    ARM_UC_MM_MFST_CRYPT_CERT_KEYTABLE_FIELDS
#undef ENUM_AUTO
};

enum certKeyTableFieldIdxs {
#define ENUM_AUTO(ENUM_AUTO) CKT_ ## ENUM_AUTO ## _IDX,
    ARM_UC_MM_MFST_CRYPT_CERT_KEYTABLE_FIELDS
#undef ENUM_AUTO
};

int ARM_UC_mmGetCertAndKeyTable(manifest_firmware_info_t *info, arm_uc_buffer_t *mfst_fwref)
{
    arm_uc_buffer_t buffers[ARRAY_SIZE(certKeyTableFields)];
    int rc = ARM_UC_mmDERParseTree(arm_uc_mmManifestFirmwareDescription,
                                   mfst_fwref,
                                   ARRAY_SIZE(certKeyTableFields),
                                   certKeyTableFields,
                                   buffers);
    if (rc == 0) {
        info->cipherMode = ARM_UC_MM_CIPHERMODE_CERT_KEYTABLE;
        // TODO: Handle non-enum format
        uint32_t format = ARM_UC_mmDerBuf2Uint(&buffers[CKT_ARM_UC_MM_DER_MFST_FW_FMT_ENUM_IDX]);
        memset(&info->format, 0, sizeof(info->format));
        info->format.words[RFC_4122_WORDS - 1] = htobe(format);
        ARM_UC_buffer_shallow_copy(&info->initVector, &buffers[CKT_ARM_UC_MM_DER_MFST_FW_CRYPT_IV_IDX]);

        ARM_UC_buffer_shallow_copy(&info->certKT.certFingerPrint,
                                   &buffers[CKT_ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_FINGERPRINT_IDX]);
        ARM_UC_buffer_shallow_copy(&info->certKT.certURL, &buffers[CKT_ARM_UC_MM_DER_MFST_FW_CRYPT_ID_CERT_URL_IDX]);
        ARM_UC_buffer_shallow_copy(&info->certKT.keyTableURL, &buffers[CKT_ARM_UC_MM_DER_MFST_FW_CRYPT_KEY_KEYTABLE_REF_IDX]);

        ARM_UC_buffer_shallow_copy(&info->strgId, &buffers[CKT_ARM_UC_MM_DER_MFST_FW_STRG_ID_IDX]);
        ARM_UC_buffer_shallow_copy(&info->hash, &buffers[CKT_ARM_UC_MM_DER_MFST_FW_RSRC_REF_HASH_IDX]);
        ARM_UC_buffer_shallow_copy(&info->uri, &buffers[CKT_ARM_UC_MM_DER_MFST_FW_RSRC_REF_URL_IDX]);
        info->size = ARM_UC_mmDerBuf2Uint(&buffers[CKT_ARM_UC_MM_DER_MFST_FW_RSRC_REF_SIZE_IDX]);
    }
    return rc;
}

arm_uc_error_t ARM_UC_mmFetchFirmwareInfoFSM(uint32_t event)
{
    arm_uc_error_t err = {ERR_NONE};
    if (arm_uc_mmPersistentContext.ctx == NULL || *arm_uc_mmPersistentContext.ctx == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }
    struct arm_uc_mm_fw_context_t *ctx = &(*arm_uc_mmPersistentContext.ctx)->getFw;
    if (ctx->info == NULL) {
        return (arm_uc_error_t) {MFST_ERR_NULL_PTR};
    }
    ARM_UC_MM_FSM_HELPER_START(*ctx, ARM_UC_mmFwState2Str) {
    case ARM_UC_MM_FW_STATE_IDLE:
        err = (arm_uc_error_t) {ERR_NONE};
        break;
    case ARM_UC_MM_FW_STATE_BEGIN: {
            // If there is no manifest storage, assume it is still present in the input buffer
            ctx->state = ARM_UC_MM_FW_STATE_READ_URI;
            ARM_UC_MM_SET_BUFFER(ctx->current_data, ctx->info->manifestBuffer);
            ctx->current_data.size = ctx->info->manifestSize;
            break;
        }
    case ARM_UC_MM_FW_STATE_READ_URI: {
            // Get the encryption mode and the firmware info block.
            const int32_t fieldIDs [] = {ARM_UC_MM_DER_MFST_ENC_ENUM, ARM_UC_MM_DER_MFST_FIRMWARE};
            arm_uc_buffer_t buffers [sizeof(fieldIDs) / sizeof(fieldIDs[0])];
            int rc = ARM_UC_mmDERGetSignedResourceValues(
                         &ctx->current_data,
                         sizeof(fieldIDs) / sizeof(fieldIDs[0]),
                         fieldIDs,
                         buffers);
            if (rc < 0) {
                err.code = MFST_ERR_DER_FORMAT;
                break;
            } else if (rc > 0) {
                // in storage mode, firmware must be supplied.
                err.code = MFST_ERR_EMPTY_FIELD;
                break;
            }
            arm_uc_buffer_t fwBuf;
            ARM_UC_buffer_shallow_copy(&fwBuf, &buffers[1]);

            // Store timestamp
            ARM_UC_MM_SET_BUFFER(ctx->current_data, ctx->info->manifestBuffer);
            ctx->current_data.size = ctx->info->manifestSize;
            err = ARM_UC_mmGetTimestamp(&ctx->current_data, &ctx->info->timestamp);
            if (err.error != 0) {
                break;
            }

            ctx->info->cipherMode = ARM_UC_MM_CIPHERMODE_NONE;
            // Found an encryption mode and firmware!
            uint32_t cryptoMode = ARM_UC_mmDerBuf2Uint(&buffers[0]);
            if (!ARM_UC_mmGetCryptoFlags(cryptoMode).aes) {
                // Encryption not in use. Skip key, ID, and IV extraction.
                rc = ARM_UC_mmGetImageRef(ctx->info, &fwBuf);
                if (rc == 0) {
                    ctx->state = ARM_UC_MM_FW_STATE_NOTIFY;
                    err.code = ERR_NONE;
                } else {
                    err.code = MFST_ERR_DER_FORMAT;
                }
                break;
            }
            // There are three possible combinations of encryption info:
            // local key ID & encrypted key
            rc = ARM_UC_mmGetLocalIDAndKey(ctx->info, &fwBuf);
            if (!rc) {
                ctx->state = ARM_UC_MM_FW_STATE_NOTIFY;
                err.code = ERR_NONE;
                break;
            }
            // Certificate and encrypted key
            rc = ARM_UC_mmGetCertAndKey(ctx->info, &fwBuf);
            if (!rc) {
                ctx->state = ARM_UC_MM_FW_STATE_NOTIFY;
                err.code = ERR_NONE;
                break;
            }
            // Certificate and key table reference
            rc = ARM_UC_mmGetCertAndKeyTable(ctx->info, &fwBuf);
            if (!rc) {
                ctx->state = ARM_UC_MM_FW_STATE_NOTIFY;
                err.code = ERR_NONE;
                break;
            }

            break;
        }
    case ARM_UC_MM_FW_STATE_GET_FW_REF:

        // TODO: Ref only
    case ARM_UC_MM_FW_STATE_NOTIFY:
        ctx->state = ARM_UC_MM_FW_STATE_ROOT_NOTIFY_WAIT;
        err.code = MFST_ERR_PENDING;
        ARM_UC_PostCallback(&ctx->callbackStorage, arm_uc_mmPersistentContext.applicationEventHandler, ARM_UC_MM_RC_NEED_FW);
        break;

    case ARM_UC_MM_FW_STATE_ROOT_NOTIFY_WAIT:
        if (event == ARM_UC_MM_EVENT_BEGIN) {
            err.code = ERR_NONE;
            ctx->state = ARM_UC_MM_FW_STATE_DONE;
        }
        break;
    case ARM_UC_MM_FW_STATE_DONE:
        // NOTE: The outer FSM will send the "done" message.
        ctx->state = ARM_UC_MM_FW_STATE_IDLE;
        break;
    case ARM_UC_MM_FW_STATE_INVALID:
    default:
        err = (arm_uc_error_t) {MFST_ERR_INVALID_STATE};
        break;
    }
    ARM_UC_MM_FSM_HELPER_FINISH(*ctx);
    return err;
}
