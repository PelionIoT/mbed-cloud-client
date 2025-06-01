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

#ifndef __FOTA_SOURCE_H_
#define __FOTA_SOURCE_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    // Keep values conforming to the openmobile standard (omitting the ones that aren't reported)
    FOTA_SOURCE_STATE_INVALID                           = -1,
    FOTA_SOURCE_STATE_IDLE                              = 1,
    FOTA_SOURCE_STATE_PROCESSING_MANIFEST               = 2,
    FOTA_SOURCE_STATE_AWAITING_DOWNLOAD_APPROVAL        = 3,
    FOTA_SOURCE_STATE_DOWNLOADING                       = 4,
    FOTA_SOURCE_STATE_AWAITING_APPLICATION_APPROVAL     = 6,
    FOTA_SOURCE_STATE_UPDATING                          = 7,
    FOTA_SOURCE_STATE_REBOOTING                         = 8,
} fota_source_state_e;

typedef struct endpoint_s endpoint_t;

void fota_source_set_config(size_t max_frag_size, bool allow_unaligned_fragments);

int fota_source_init(
    void *m2m_interface, void *resource_list,
    const uint8_t *vendor_id, uint32_t vendor_id_size,
    const uint8_t *class_id, uint32_t class_id_size,
    const uint8_t *curr_fw_digest, uint32_t curr_fw_digest_size,
    uint64_t curr_fw_version,
    fota_source_state_e source_state);

int fota_source_add_component(unsigned int comp_id, const char *name, const char *sem_ver);

int fota_source_deinit(void);
int fota_source_firmware_request_fragment(const char *uri, size_t offset);

typedef void (*report_sent_callback_t)(void);
int fota_source_report_state(fota_source_state_e state, report_sent_callback_t on_sent, report_sent_callback_t on_failure);
int fota_source_report_state_in_ms(fota_source_state_e state, report_sent_callback_t on_sent, report_sent_callback_t on_failure, size_t in_ms);
void report_state_random_delay(bool enable);

int fota_source_get_state(void);
int fota_source_report_update_result(int result);
int fota_source_report_update_customer_result(int result);
void fota_source_send_manifest_received_ack(void);
void fota_source_enable_auto_observable_resources_reporting(bool enable);

typedef struct {
    fota_source_state_e state;
    report_sent_callback_t on_sent;
    report_sent_callback_t on_failure;
} fota_random_state_report_params_t;

#define EVENT_RANDOM_DELAY 100

#if defined(__NANOSIMULATOR__) || defined(MBED_CLOUD_CLIENT_MULTICAST_SMALL_NETWORK) || defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR)
#define RANDOM_DELAY_RANGE_IN_SEC 10
#else
#define RANDOM_DELAY_RANGE_IN_SEC 120
#endif

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_SOURCE_H_
