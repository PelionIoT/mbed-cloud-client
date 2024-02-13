// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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

#ifndef __FOTA_INTERNAL_H_
#define __FOTA_INTERNAL_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_manifest.h"
#include "fota/fota_app_ifs.h"
#include "fota/fota_delta.h"
#include "fota/fota_header_info.h"
#include "fota/fota_crypto.h"
#include "fota/fota_component.h"
#include "fota/fota_multicast.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FOTA_STATE_IDLE = 0, // must be zero as it is set by zeroing entire FOTA context at init
    FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION,
    FOTA_STATE_DOWNLOADING,
    FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION,
    FOTA_STATE_INSTALLING,
    FOTA_STATE_INVALID = 255,
} fota_state_e;

typedef enum {
    FOTA_RESUME_STATE_INACTIVE = 0, // must be zero as it is set by zeroing entire FOTA context at init
    FOTA_RESUME_STATE_STARTED,
    FOTA_RESUME_STATE_ONGOING,
} fota_resume_state_e;

typedef enum {
    FOTA_INSTALL_STATE_IDLE,
    FOTA_INSTALL_STATE_AUTHORIZE,
    FOTA_INSTALL_STATE_DEFER,
    FOTA_INSTALL_STATE_POSTPONE_REBOOT
} fota_install_state_e;

typedef enum {
    FOTA_RESUME_REASON_USER_APP,
    FOTA_RESUME_REASON_REGISTRATION,
    FOTA_RESUME_REASON_UPDATE_REGISTRATION
} fota_resume_reason_e;


// Internal component for BR downloader (must start with '%' as it's internal)
#define FOTA_MULTICAST_BR_INT_COMP_NAME "%MC_BR"

typedef struct {
    manifest_firmware_info_t *fw_info;
    size_t payload_offset;
    size_t fw_bytes_written;
    unsigned int comp_id;
    fota_state_e state;
    size_t frag_size;
#if !defined(FOTA_DISABLE_DELTA)
    uint8_t *delta_buf;
    fota_delta_ctx_t *delta_ctx;
#endif
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_encrypt_context_t *enc_ctx;
    uint8_t encryption_key[FOTA_ENCRYPT_KEY_SIZE];
#endif
    fota_hash_context_t *payload_hash_ctx;
#if !defined(FOTA_DISABLE_DELTA)
    fota_hash_context_t *installed_hash_ctx;
#endif
    uint8_t *page_buf;
    uint32_t page_buf_offset;
    uint32_t page_buf_size;
    uint8_t *effective_page_buf;
    uint32_t effective_page_buf_size;
    size_t storage_addr;
    uint32_t fw_header_bd_size;
    uint32_t fw_header_offset;
    uint32_t candidate_header_size;
    fota_resume_state_e resume_state;
    void *download_handle;
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
    // Tells that this is a Multicast BR mode update on a BR (unlike unicast update to the BR itself)
    bool mc_br_update;
    fota_multicast_br_post_action_callback_t mc_br_post_action_callback;
#endif
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    bool mc_node_update;
    bool mc_node_update_activated;
    fota_multicast_node_post_action_callback_t mc_node_post_action_callback;
    uint8_t *mc_node_frag_buf;
    uint8_t mc_node_manifest_hash[FOTA_CRYPTO_HASH_SIZE];
    size_t activate_in_sec;
#endif
} fota_context_t;


typedef struct {
    unsigned int comp_id;
    fota_state_e state;
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
    bool mc_br_update;
    fota_multicast_br_post_action_callback_t mc_br_post_action_callback;
#elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    bool mc_node_update;
    fota_multicast_node_post_action_callback_t mc_node_post_action_callback;
#endif
} fota_persistent_context_t;


fota_context_t *fota_get_context(void);

int  fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state);

void fota_on_manifest(uint8_t *data, size_t size);
void fota_on_reject(int32_t status);
void fota_on_defer(int32_t param);
void fota_on_authorize(int32_t status);
void fota_on_fragment(uint8_t *buf, size_t size);
void fota_on_fragment_failure(int32_t status);
void fota_on_resume(fota_resume_reason_e resume_reason);
#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_INTERNAL_H_
