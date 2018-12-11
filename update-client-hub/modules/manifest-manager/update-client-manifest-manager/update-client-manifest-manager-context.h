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

#ifndef ARM_UC_MM_CONTEXT_TYPES_H
#define ARM_UC_MM_CONTEXT_TYPES_H

#include "update-client-manifest-manager/update-client-manifest-types.h"
#include "update-client-manifest-manager/../source/arm_uc_mmConfig.h"
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"
#include "update-client-common/arm_uc_config.h"
#include "update-client-common/arm_uc_scheduler.h"
#include "update-client-manifest-manager/arm-pal-kv.h"


struct arm_uc_mmInitContext_t {
    uint64_t timestamp;
    uint32_t state;
    arm_uc_buffer_t manifest;
    arm_uc_buffer_t keyPath;
    uint32_t loopCounters[1];

    arm_uc_callback_t callbackStorage; // initialized in hub
    struct {
        unsigned root: 1;
        unsigned depidx: 3;
        unsigned missingDep: 1;
    };
    uint8_t rootManifestBasePath[sizeof(MANIFEST_PREFIX "..") + CFSTORE_HASH_ID_SIZE];
    uint8_t pathBuffer[220];
    uint8_t manifestBuffer[640];
    uint8_t currentHash [MAX_HASH_BYTES];

};

struct arm_uc_mm_get_latest_ts_context {
    uint64_t current_ts;
    uint64_t *max_ts;
    uint32_t state;
    arm_uc_buffer_t current_data;
    arm_uc_buffer_t max_ts_key;
};

enum arm_uc_mm_pk_sig_state {
    UCMM_PKSIG_STATE_INVALID = 0,
    UCMM_PKSIG_STATE_IDLE,
    UCMM_PKSIG_STATE_FIND_CA,
    UCMM_PKSIG_STATE_FINDING_CA,
    UCMM_PKSIG_STATE_CHECK,
};

enum arm_uc_mm_psk_sig_state {
    ARM_UC_MM_PSKSIG_STATE_INVALID = 0,
    ARM_UC_MM_PSKSIG_STATE_IDLE,
    ARM_UC_MM_PSKSIG_STATE_FIND_PSK,
    ARM_UC_MM_PSKSIG_STATE_FINDING_PSK,
    ARM_UC_MM_PSKSIG_STATE_FIND_SIG_START,
    ARM_UC_MM_PSKSIG_STATE_FIND_SIG,
    ARM_UC_MM_PSKSIG_STATE_VERIFY,
};

typedef struct arm_uc_mm_validate_signature_context {
    union {
        enum arm_uc_mm_pk_sig_state  pk_state;
        enum arm_uc_mm_psk_sig_state psk_state;
    };
    void (* applicationEventHandler)(uint32_t);
    union {
#if defined(ARM_UC_FEATURE_MANIFEST_PUBKEY) && (ARM_UC_FEATURE_MANIFEST_PUBKEY == 1)
        struct {
            arm_uc_buffer_t  fingerprint;
            arm_uc_buffer_t  certList;
            arm_uc_buffer_t  cert;
        };
#endif /* ARM_UC_FEATURE_MANIFEST_PUBKEY */
#if defined(ARM_UC_FEATURE_MANIFEST_PSK) && (ARM_UC_FEATURE_MANIFEST_PSK == 1)
        struct {
            arm_uc_buffer_t  PSKid;
            int              keyTableVersion;
            arm_uc_buffer_t  keyTableRef;
            arm_uc_buffer_t  keyTableIV;
            arm_uc_buffer_t  PSK;
            arm_uc_buffer_t  cipherText;
        };
#endif /* ARM_UC_FEATURE_MANIFEST_PSK */
    };
    arm_uc_buffer_t *manifest;
    arm_uc_error_t   storedError;
    uint32_t         sigIndex;
    uint32_t         encryptionMode;
} arm_uc_mm_validate_signature_context_t;

#define ARM_UC_MM_FW_STATE_LIST\
    ENUM_FIXED(ARM_UC_MM_FW_STATE_INVALID,0)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_IDLE)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FIND_ROOT)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_TS)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_NAME)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FIND_NEXT_ROOT)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FORMAT_ROOT_PREFIX)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FIND_MANIFEST)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_READ_MANIFEST)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_ROOT)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FIND_URI)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_READ_URI)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_URI_KEY)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_HASH)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_DEP_URI)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_FETCH_DEP_HASH)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_GET_FW_REF)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_NOTIFY)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_ROOT_NOTIFY_WAIT)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_NEXT_IMAGE)\
    ENUM_AUTO(ARM_UC_MM_FW_STATE_DONE)\


enum arm_uc_mm_fw_state {
#define ENUM_AUTO(name) name,
#define ENUM_FIXED(name, val) name = val,
    ARM_UC_MM_FW_STATE_LIST
#undef ENUM_AUTO
#undef ENUM_FIXED
};

struct arm_uc_mm_fw_context_t {
    struct arm_uc_mm_get_latest_ts_context getLatestTs;
    uint64_t ts;
    arm_uc_manifest_handle_t *ID;
    enum arm_uc_mm_fw_state state;
    struct manifest_firmware_info_t *info;
    arm_uc_callback_t callbackStorage; // initialized in hub
    arm_uc_buffer_t current_data;
    char hashIDbuffer[CFSTORE_HASH_ID_SIZE];
    uint8_t keyBuffer[ARM_PAL_KV_KEY_MAX_PATH];
};

#define ARM_UC_MM_INS_STATE_LIST\
    ENUM_FIXED(ARM_UC_MM_INS_STATE_INVALID,0)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_IDLE)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_BASIC_PARAMS)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_HASH_VERIFY)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_SIG_LOOP)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_SIG_START)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_SIG_WAIT)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_PARAMS)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_APP)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_FAIL)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_DONE)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_MATCHING)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_MATCH_FETCHING)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_MANIFEST_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_MANIFEST)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_FW_URI)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_FW_HASH)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_AES)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_DEPS)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_DEPSTART)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_DEP_WAITING)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_COMPLETION)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_COMPLETION_FINDING)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_TS_START)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_VERIFY_TS)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_TS_START)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_STORE_TS)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_DEP_CHECK)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_DEP_CHECKING)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_DEP_DELETE)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_DONE)\
    ENUM_AUTO(ARM_UC_MM_INS_STATE_ALERT)\


enum arm_uc_mm_insert_state {
#define ENUM_AUTO(name) name,
#define ENUM_FIXED(name, val) name = val,
    ARM_UC_MM_INS_STATE_LIST
#undef ENUM_AUTO
#undef ENUM_FIXED
};

struct arm_uc_mmInsertContext_t {
    struct arm_uc_mm_get_latest_ts_context getLatestTs;
    arm_uc_mm_validate_signature_context_t signatureContext;
    uint64_t max_ts;
    uint64_t current_ts;
    arm_uc_manifest_handle_t *ID;
    enum arm_uc_mm_insert_state state;
    arm_uc_callback_t callbackStorage; // initialized in hub
    arm_uc_buffer_t manifest;
    arm_uc_mm_crypto_flags_t cryptoMode;
    arm_uc_buffer_t certificateStorage;
    uint32_t loopCounters[1];
};

struct arm_uc_mmContext_t {
    // Operational Contexts
    union {
        struct arm_uc_mmInitContext_t   init;
        struct arm_uc_mm_fw_context_t   getFw;
        struct arm_uc_mmInsertContext_t insert;
    };
};
typedef struct arm_uc_mmContext_t arm_uc_mmContext_t;


enum arm_uc_mmState_t {
    ARM_UC_MM_STATE_INVALID = 0,
    ARM_UC_MM_STATE_IDLE,
    ARM_UC_MM_STATE_INIT,
    ARM_UC_MM_STATE_INSERTING,
    ARM_UC_MM_STATE_STORING_CA,
    ARM_UC_MM_STATE_FWINFO,
    ARM_UC_MM_STATE_TEST,
};

typedef void (*ARM_UC_mmTestHook_t)(const char *, arm_uc_mmContext_t *, uint32_t, uint32_t, arm_uc_error_t);

struct arm_uc_mmPersistentContext_t {
    enum arm_uc_mmState_t state;
    arm_uc_error_t reportedError;
    const char *errorFile;
    uint32_t errorLine;
    struct arm_uc_mmContext_t **ctx;
    arm_uc_callback_t applicationCallbackStorage; // initialized in mmCommon
    void (*applicationEventHandler)(uint32_t);
    arm_uc_error_t (*testFSM)(uint32_t event);
#if ARM_UC_MM_ENABLE_TEST_VECTORS
    ARM_UC_mmTestHook_t testHook;
#endif
};

typedef struct arm_uc_mmPersistentContext_t arm_uc_mmPersistentContext_t;
extern arm_uc_mmPersistentContext_t arm_uc_mmPersistentContext;

static inline arm_uc_mmContext_t *arm_uc_mmBuf2Context(arm_uc_buffer_t *b)
{
    return (arm_uc_mmContext_t *)b->ptr;
}

static inline arm_uc_error_t arm_uc_mmContextBufSizeCheck(arm_uc_buffer_t *b)
{
    arm_uc_error_t err = { .code = ERR_NONE };
    if (b->size_max < sizeof(arm_uc_mmContext_t)) {
        err.code = MFST_ERR_SIZE;
        return err;
    }
    return err;
}


#endif // ARM_UC_MM_CONTEXT_TYPES_H
