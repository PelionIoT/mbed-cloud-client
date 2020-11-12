// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#define ARM_UC_OTA_MULTICAST_UC_HUB_EVENT           1
#define ARM_UC_OTA_MULTICAST_TIMER_EVENT            2
#define ARM_UC_OTA_MULTICAST_DL_DONE_EVENT          3
#define ARM_UC_OTA_MULTICAST_EXTERNAL_UPDATE_EVENT  4
#define ARM_UC_OTA_DELETE_SESSION_EVENT             5
#define ARM_UC_OTA_FULL_REG_EVENT                   6

#define MULTICAST_STATUS_RANGE_BASE 0x0700
#define MULTICAST_STATUS_RANGE_END 0x07ff

#define ARM_UC_HUB_BUFFER_SIZE_MAX (ARM_UC_BUFFER_SIZE / 2) //  define size of the double buffers

typedef enum {
    MULTICAST_STATUS_SUCCESS = 0,
    MULTICAST_STATUS_ERROR = MULTICAST_STATUS_RANGE_BASE,
    MULTICAST_STATUS_INIT_FAILED,
    MULTICAST_MAX_STATUS = MULTICAST_STATUS_RANGE_END
} multicast_status_e;

typedef struct  arm_uc_firmware_address {
    uint32_t start_address;
    uint32_t size;
} arm_uc_firmware_address_t;

#ifdef __cplusplus

#include "m2minterface.h"
#include "ConnectorClient.h"
#include "eventOS_event.h"
#include "eventOS_event_timer.h"

/**
 *  @brief Initialize multicast resources and infrastructure.
 *
 *  @param registration_list Mbed Cloud Client resource objects list
 *  @param client Handle for ConnectorClient
 *  @param tasklet_id Event handler id
 *  @return MULTICAST_STATUS_SUCCESS on success, or some error if failed
 */
multicast_status_e arm_uc_multicast_init(M2MBaseList& list, ConnectorClient &client, const int8_t tasklet_id);

/**
 * @brief Finalizes multicast resources.
 *
 */
void arm_uc_multicast_deinit();

/**
 *  @brief Set mesh interface id.
 *
 *  @param interface_id Mesh interface id.
 *  @return True on success otherwise False.
 */
bool arm_uc_multicast_interface_configure(int8_t interface_id);

/**
 *  @brief Event handler callback
 *
 *  @param event Event to process.
 */
void arm_uc_multicast_tasklet(struct arm_event_s *event);

#endif // __cplusplus

#endif /* ARM_UC_MULTICAST_H */
