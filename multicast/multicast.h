// ----------------------------------------------------------------------------
// Copyright 2020-2021 Pelion.
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

#ifndef ARM_UC_MULTICAST_H
#define ARM_UC_MULTICAST_H

#include "eventOS_event.h"
#include "eventOS_event_timer.h"

#define ARM_UC_OTA_MULTICAST_INIT_EVENT             0
#define ARM_UC_OTA_MULTICAST_UPDATE_CLIENT_EVENT    1
#define ARM_UC_OTA_MULTICAST_TIMER_EVENT            2
#define ARM_UC_OTA_MULTICAST_DL_DONE_EVENT          3
#define ARM_UC_OTA_MULTICAST_EXTERNAL_UPDATE_EVENT  4
#define ARM_UC_OTA_DELETE_SESSION_EVENT             5
#define ARM_UC_OTA_FULL_REG_EVENT                   6
// Make sure that timer id does not collapse with one defined in ota_timers_e
#define ARM_UC_HUB_EVENT_TIMER                      100

#define OTA_MAX_MESH_NETWORK_ID_LENGTH  45

#if defined(MBED_CLOUD_CLIENT_MULTICAST_SMALL_NETWORK) || defined(__NANOSIMULATOR__) || defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR)
#define ARM_UC_OTA_MULTICAST_RAND_START     1   // seconds
#define ARM_UC_OTA_MULTICAST_RAND_END       10  // seconds
#else
#define ARM_UC_OTA_MULTICAST_RAND_START     10  // seconds
#define ARM_UC_OTA_MULTICAST_RAND_END       120 // seconds
#endif // MBED_CLOUD_CLIENT_MULTICAST_SMALL_NETWORK

#define MULTICAST_STATUS_RANGE_BASE 0x0700
#define MULTICAST_STATUS_RANGE_END 0x07ff

#ifdef ARM_UC_BUFFER_SIZE
// UCHub case this is used as UChub injection buffer size and max value check for fragment size
#define ARM_UC_HUB_BUFFER_SIZE_MAX (ARM_UC_BUFFER_SIZE / 2) //  define size of the double buffers
#else
// Fota case this is only used as max value check for fragment size
#define ARM_UC_HUB_BUFFER_SIZE_MAX 1024
#endif

typedef enum {
    MULTICAST_STATUS_SUCCESS = 0,
    MULTICAST_STATUS_ERROR = MULTICAST_STATUS_RANGE_BASE,
    MULTICAST_STATUS_INIT_FAILED,
    MULTICAST_MAX_STATUS = MULTICAST_STATUS_RANGE_END
} multicast_status_e;

typedef enum {
    MULTICAST_FOTA_EVENT_MANIFEST_RECEIVED = 1
} multicast_fota_event;

typedef struct  arm_uc_firmware_address {
    uint32_t start_address;
    uint32_t size;
} arm_uc_firmware_address_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief Set mesh interface id.
 *
 *  @param interface_id Mesh interface id.
 *  @return True on success otherwise False.
 */
bool arm_uc_multicast_interface_configure(int8_t interface_id);

/**
 * @brief Finalizes multicast resources.
 *
 */
void arm_uc_multicast_deinit();

/**
 *  @brief Event handler callback
 *
 *  @param event Event to process.
 */
void arm_uc_multicast_tasklet(struct arm_event_s *event);

/**
 *  @brief Called to indicate network status is changed (back) to connected, so netid should be
 *         re-set to corresponding resource.
 */
void arm_uc_multicast_network_connected();

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include "m2minterface.h"
#include "ConnectorClient.h"

/**
 *  @brief Initialize multicast resources and infrastructure.
 *
 *  @param registration_list Mbed Cloud Client resource objects list
 *  @param client Handle for ConnectorClient
 *  @param tasklet_id Event handler id
 *  @return MULTICAST_STATUS_SUCCESS on success, or some error if failed
 */
multicast_status_e arm_uc_multicast_init(M2MBaseList &list, ConnectorClient &client, const int8_t tasklet_id);

#endif // __cplusplus

#endif /* ARM_UC_MULTICAST_H */
