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

#include <inttypes.h>

#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "otaLIB.h"

#define OTA_SEGMENT_SIZE            128 // As fragments (do not change this value without changing code also)
#define TRACE_GROUP                 "MULTICAST"
#define OTA_NOTIF_MAX_LENGTH        128

// Notification payload texts
#define OTA_START_RESPONSE          "START"
#define OTA_PROCESS_COMPLETED_NOTIF "FIRMWARE DOWNLOADED"
#define OTA_CHECKSUM_FAILED_NOTIF   "CHECKSUM FAILED"
#define OTA_DELIVER_FW_RESPONSE     "DELIVER FW"
#define OTA_UPDATE_FW_RESPONSE      "ACTIVATE FW"
#define OTA_ABORT_RESPONSE          "ABORT"
#define OTA_MANIFEST_RECEIVED_NOTIF "MANIFEST RECEIVED"

// Message lengths in bytes
#define OTA_START_CMD_LENGTH            (54 + payload_ptr[OTA_START_CMD_FW_NAME_LENGTH_INDEX] + payload_ptr[OTA_START_CMD_FW_VERSION_LENGTH_INDEX] + OTA_WHOLE_FW_CHECKSUM_LENGTH + payload_ptr[OTA_START_CMD_PULL_URL_LENGTH_INDEX])
#define OTA_FRAGMENT_CMD_LENGTH         (21 + ota_parameters.fw_fragment_byte_count)
#define OTA_END_FRAGMENTS_CMD_LENGTH    17
#define OTA_FRAGMENTS_REQ_LENGTH        35
#define OTA_UPDATE_FW_CMD_LENGTH        20
#define OTA_ABORT_CMD_LENGTH            17
#define OTA_PROCESS_ID_LENGTH           20

// Message data field indexes
#define OTA_CMD_PROCESS_ID_INDEX                    1
#define OTA_START_CMD_DEVICE_TYPE_INDEX             17
#define OTA_START_CMD_RESPONSE_SENDING_DELAY_INDEX  18
#define OTA_START_CMD_MULTICAST_SELECTION_INDEX     22
#define OTA_START_CMD_WHOLE_FW_CHECKSUM_INDEX       51
#define OTA_START_CMD_FW_NAME_LENGTH_INDEX          87
#define OTA_START_CMD_FW_NAME_INDEX                 (OTA_START_CMD_FW_NAME_LENGTH_INDEX + 1)
#define OTA_START_CMD_FW_VERSION_LENGTH_INDEX       (OTA_START_CMD_FW_NAME_INDEX + payload_ptr[OTA_START_CMD_FW_NAME_LENGTH_INDEX])
#define OTA_START_CMD_FW_VERSION_INDEX              (OTA_START_CMD_FW_VERSION_LENGTH_INDEX + 1)
#define OTA_START_CMD_PULL_URL_LENGTH_INDEX         (OTA_START_CMD_FW_VERSION_INDEX + payload_ptr[OTA_START_CMD_FW_VERSION_LENGTH_INDEX])
#define OTA_START_CMD_PULL_URL_INDEX                (OTA_START_CMD_PULL_URL_LENGTH_INDEX + 1)
#define OTA_FRAGMENT_CMD_FRAGMENT_BYTES_INDEX       19

#define MULTICAST_CMD_ID_INDEX                      0
#define MULTICAST_CMD_TYPE_INDEX                    1
#define MULTICAST_CMD_VERSION                       2
#define MULTICAST_CMD_SESSION_ID_INDEX              3
#define MULTICAST_CMD_FW_SIZE_INDEX                 19
#define MULTICAST_CMD_FW_HASH_INDEX                 23
#define MULTICAST_CMD_URL_INDEX                     55

#define OTA_INVALID_PROCESS_ID_INDEX                0xFF
#define OTA_MISSING_FRAGMENTS_IP_ADDR_LENGTH        16 // In bytes, e.g: fdf9b02a9fab2d033e4a92fffef5267a

typedef enum
{
    OTA_CMD_MANIFEST = 1,
    OTA_CMD_FIRMWARE = 2,
    OTA_CMD_ACTIVATE = 3,
    OTA_START_CMD = 4, //OTA_START_RESPONSE
    OTA_FRAGMENT_CMD = 5,
    OTA_END_FRAGMENTS_CMD = 6,
    OTA_FRAGMENTS_REQUEST_CMD = 7,
    OTA_UPDATE_FW_CMD = 8, //OTA_UPDATE_FW_RESPONSE
    OTA_ABORT_CMD = 9, //OTA_ABORT_RESPONSE
    OTA_PROCESS_COMPLETED_RESPONSE = 90, //Only used to send status, not real command! //OTA_PROCESS_COMPLETED_NOTIF
    OTA_CHECKSUM_FAILED_RESPONSE //Only used to send status, not real command! //OTA_CHECKSUM_FAILED_NOTIF
} ota_commands_e;

typedef enum
{
    OTA_CMD_TYPE_NO_DATA = 0,       // Only command, no data at all
    OTA_CMD_TYPE_EMBEDDED_DATA = 1, // Data is part of the payload
    OTA_CMD_TYPE_URL_DATA = 2,      // Data needs to be downloaded from url
} ota_border_router_command_types_e;

typedef enum
{
    OTA_NOTIFICATION_TIMER = 1,
    OTA_CHECKSUM_CALCULATING_TIMER,
    OTA_FRAGMENTS_DELIVERING_TIMER,
    OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
    OTA_FRAGMENTS_REQUEST_SERVICE_TIMER,
    OTA_REPORT_OWN_DL_STATUS_TIMER,
    OTA_FALLBACK_TIMER,
    OTA_MULTICAST_MESSAGE_SENT_TIMER,
    OTA_FIRMWARE_READY_TIMER,
} ota_timers_e;

typedef struct ota_checksum_calculating_t
{
    mbedtls_sha256_context *ota_sha256_context_ptr;
    uint32_t current_byte_id;
} ota_checksum_calculating_t;

typedef struct command_responses2
{
    uint8_t         session_id[OTA_SESSION_ID_SIZE];
    bool            response_state;
    ota_commands_e  command_id;
    ns_list_link_t  link;
} notification_t;

typedef NS_LIST_HEAD(notification_t, link) ota_command_responses_list_t;
static ota_command_responses_list_t ota_notification_list;

// Stored OTA processes data
static ota_lib_config_data_t        ota_lib_config_data;
static ota_parameters_t             ota_parameters;
static ota_checksum_calculating_t   ota_checksum_calculating_ptr;
static uint8_t                      ota_fragments_request_service_bitmask_tbl[OTA_FRAGMENTS_REQ_BITMASK_LENGTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // For e.g. segment 1: (fragment 128) MSB...LSB (fragment 1) // TODO: For pointer and memory allocation dynamically
static uint16_t                     ota_update_fw_delay = 0;
static uint16_t                     ota_fragments_request_service_segment_id = 0;
static ota_ip_address_t             ota_fragments_request_source_addr;
static bool                         ota_own_device_type = false;
static bool                         ota_fragments_request_service = false;
static uint8_t                      ota_fw_update_received = false;
static bool                         ota_fw_delivering = false;
static uint16_t                     ota_fw_deliver_current_fragment_id = 0;

// * * * OTA library API function pointers * * *
static ota_error_code_e (*ota_store_new_process_fptr)(uint8_t*);
static ota_error_code_e (*ota_delete_process_fptr)(uint8_t*);
static ota_error_code_e (*ota_store_parameters_fptr)(ota_parameters_t*);
static ota_error_code_e (*ota_read_stored_parameters_fptr)(ota_parameters_t*);
static ota_error_code_e (*ota_start_received_fptr)(ota_parameters_t*);
static uint32_t         (*ota_write_fw_bytes_fptr)(uint8_t*, uint32_t, uint32_t, uint8_t*);
static uint32_t         (*ota_read_fw_bytes_fptr)(uint8_t*, uint32_t, uint32_t, uint8_t*);
static int8_t           (*ota_socket_send_fptr)(ota_ip_address_t *dest_addr, uint16_t payload_length, uint8_t *payload_ptr);
static uint16_t         (*ota_coap_send_notif_fptr)(ota_resource_types_e type, uint8_t *payload_ptr, uint16_t payload_len);
static void             *(*ota_malloc_fptr)(size_t);
static void             (*ota_free_fptr)(void*);
static void             (*ota_request_timer_fptr)(uint8_t, uint32_t);
static void             (*ota_cancel_timer_fptr)(uint8_t);
static void             (*ota_send_update_fw_cmd_received_info_fptr)(uint16_t);
static void             (*ota_process_finished_fptr)(uint8_t*);
static ota_error_code_e (*ota_manifest_received_fptr)(uint8_t*, uint32_t);
static void             (*ota_firmware_ready_fptr)();

// * * * Function prototypes * * *
static void             ota_create_notification(uint8_t *session_id, bool response_state, ota_commands_e command_id);
static ota_error_code_e ota_manage_start_command(uint16_t payload_length, uint8_t *payload_ptr);
static ota_error_code_e ota_border_router_manage_command(uint8_t command_id, uint16_t payload_length, uint8_t *payload_ptr);
static ota_error_code_e ota_parse_start_command_parameters(uint8_t *payload_ptr);
static void             ota_manage_fragment_command(uint16_t payload_length, uint8_t *payload_ptr);
static void             ota_manage_abort_command(uint16_t payload_length, uint8_t *payload_ptr);
static void             ota_manage_end_fragments_command(uint16_t payload_length, uint8_t *payload_ptr);
static void             ota_manage_update_fw_command(uint16_t payload_length, uint8_t *payload_ptr);
static void             ota_manage_fragments_request_command(uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *source_addr);
static ota_error_code_e ota_manage_manifest_command(uint16_t payload_length, uint8_t *payload_ptr);
static void             ota_serve_fragments_request_by_sending_one_fragment();
static ota_error_code_e ota_build_one_fw_fragment(uint16_t fragment_id, uint8_t *built_payload_ptr);
static void             ota_build_and_send_command(uint8_t command_id, uint8_t *session_id, uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *dest_address);
static ota_error_code_e ota_build_and_send_multicast_command(ota_commands_e command, uint8_t *payload_ptr, uint16_t payload_length);
static void             ota_request_missing_fragments(bool fallback_flag);
static bool             ota_check_if_fragment_already_received(uint16_t fragment_id);
static uint16_t         ota_get_missing_fragment_total_count();
static uint16_t         ota_get_and_log_first_missing_segment(uint8_t *missing_fragment_bitmasks_ptr);
static uint16_t         ota_get_next_missing_fragment_id_for_requester(bool bit_mask_change);
static uint16_t         ota_calculate_checksum_over_one_fragment(uint8_t *data_ptr, uint16_t data_length);
static void             ota_manage_whole_fw_checksum_calculating(void);
static void             ota_init_fragments_bit_mask(uint8_t init_value);
static ota_error_code_e ota_add_new_process(uint8_t *session_id);
static void             ota_delete_process(uint8_t *session_id);
static uint8_t          ota_get_first_missing_fragments_process_id(bool fallback_flag);
static void             ota_get_state(char *ota_state_ptr);
static void             ota_deliver_one_fragment(void);
static void             ota_resources_send_notif(notification_t *notif);
static void             ota_resources_send_dl_status_notif();
static void             ota_resources_build_status_notif(char *status_ptr, notification_t *notification);
