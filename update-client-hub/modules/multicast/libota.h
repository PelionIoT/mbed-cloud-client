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

// OTA library internal header file

// * * * Common defines * * *

// Firmware segment size
#define OTA_SEGMENT_SIZE 128 // As fragments (do not change this value without changing code also)

// For tracing
#define TRACE_GROUP "OTA_LIB"

// For CoAP resource type
#define OTA_RESOURCE_TYPE_TEXT "t"


// Notification payload maximum length
#define OTA_NOTIF_MAX_LENGTH 60

// Notification payload texts
#define OTA_START_RESPONSE          "START "
#define OTA_PROCESS_COMPLETED_NOTIF "PROCESS COMPLETED "
#define OTA_CHECKSUM_FAILED_NOTIF   "CHECKSUM FAILED "
#define OTA_DELIVER_FW_RESPONSE     "DELIVER FW "
#define OTA_UPDATE_FW_RESPONSE      "UPDATE FW "
#define OTA_ABORT_RESPONSE          "ABORT "
#define OTA_DELETE_RESPONSE         "DELETE "

// Message lengths in bytes
#define OTA_START_CMD_LENGTH (42 + payload_ptr[OTA_START_CMD_FW_NAME_LENGTH_INDEX] + payload_ptr[OTA_START_CMD_FW_VERSION_LENGTH_INDEX] + OTA_WHOLE_FW_CHECKSUM_LENGTH + payload_ptr[OTA_START_CMD_PULL_URL_LENGTH_INDEX])
#define OTA_FRAGMENT_CMD_LENGTH (9 + ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count)
#define OTA_DELIVER_FW_CMD_LENGTH 7
#define OTA_END_FRAGMENTS_CMD_LENGTH 5
#define OTA_FRAGMENTS_REQ_LENGTH 23
#define OTA_UPDATE_FW_CMD_LENGTH 8
#define OTA_ABORT_CMD_LENGTH 5
#define OTA_DELETE_CMD_LENGTH 5

// Message field lengths in bytes
#define OTA_PROCESS_ID_LENGTH 8

// Message data field indexes
#define OTA_CMD_PROCESS_ID_INDEX 1
#define OTA_START_CMD_DEVICE_TYPE_INDEX 5
#define OTA_START_CMD_RESPONSE_SENDING_DELAY_INDEX 6
#define OTA_START_CMD_MULTICAST_SELECTION_INDEX 10
#define OTA_START_CMD_WHOLE_FW_CHECKSUM_INDEX 39
#define OTA_START_CMD_FW_NAME_LENGTH_INDEX 71
#define OTA_START_CMD_FW_NAME_INDEX (OTA_START_CMD_FW_NAME_LENGTH_INDEX + 1)
#define OTA_START_CMD_FW_VERSION_LENGTH_INDEX (OTA_START_CMD_FW_NAME_INDEX + payload_ptr[OTA_START_CMD_FW_NAME_LENGTH_INDEX])
#define OTA_START_CMD_FW_VERSION_INDEX (OTA_START_CMD_FW_VERSION_LENGTH_INDEX + 1)
#define OTA_START_CMD_PULL_URL_LENGTH_INDEX (OTA_START_CMD_FW_VERSION_INDEX + payload_ptr[OTA_START_CMD_FW_VERSION_LENGTH_INDEX])
#define OTA_START_CMD_PULL_URL_INDEX (OTA_START_CMD_PULL_URL_LENGTH_INDEX + 1)
#define OTA_FRAGMENT_CMD_FRAGMENT_BYTES_INDEX 7

//#define OTA_COMMAND_NOTIF_OBS_LEN   2 // Note!!! Don't change this value without changing OTA library code also
//#define OTA_DL_STATUS_NOTIF_OBS_LEN 2 // Note!!! Don't change this value without changing OTA library code also

// Invalid Process ID index
#define OTA_INVALID_PROCESS_ID_INDEX 0xFF

// * * * Missing fragments IP address length * * *
#define OTA_MISSING_FRAGMENTS_IP_ADDR_LENGTH 16 // In bytes, e.g: fdf9b02a9fab2d033e4a92fffef5267a

// * * * Enums * * *

typedef enum
{
    OTA_START_CMD = 1, //OTA_START_RESPONSE
    OTA_FRAGMENT_CMD = 2,
    OTA_DELIVER_FW_CMD = 3, //OTA_DELIVER_FW_RESPONSE
    OTA_END_FRAGMENTS_CMD = 4,
    OTA_FRAGMENTS_REQUEST_CMD = 5,
    OTA_UPDATE_FW_CMD = 6, //OTA_UPDATE_FW_RESPONSE
    OTA_ABORT_CMD = 7, //OTA_ABORT_RESPONSE
    OTA_DELETE_CMD = 8, //OTA_DELETE_RESPONSE
    OTA_PROCESS_COMPLETED_RESPONSE = 90, //Only used to send status, not real command! //OTA_PROCESS_COMPLETED_NOTIF
    OTA_CHECKSUM_FAILED_RESPONSE //Only used to send status, not real command! //OTA_CHECKSUM_FAILED_NOTIF
} ota_commands_e;

typedef enum
{
    OTA_NOTIFICATION_TIMER = 1, //new one
//    OTA_DELIVER_FW_RESPONSE_SENDING_TIMER = 4,
//    OTA_UPDATE_FW_RESPONSE_SENDING_TIMER = 5,
    OTA_CHECKSUM_CALCULATING_TIMER = 8, // needed
    OTA_FRAGMENTS_DELIVERING_TIMER = 9, // needed
    OTA_MISSING_FRAGMENTS_REQUESTING_TIMER = 11, //needed
    OTA_FRAGMENTS_REQUEST_SERVICE_TIMER = 13, // needed
    OTA_REPORT_OWN_DL_STATUS_TIMER = 15, // needed
    OTA_FALLBACK_TIMER = 16 // needed
} ota_timers_e;

typedef struct ota_checksum_calculating_t
{
  mbedtls_sha256_context *ota_sha256_context_ptr;
  uint32_t current_byte_id;
} ota_checksum_calculating_t;

static uint8_t ota_own_device_type_process_id_index = 0xFF;
static uint8_t ota_fragments_request_service_process_id_index = 0xFF;
static uint8_t ota_fw_update_received = false;

static uint8_t ota_fw_delivering_process_id_index = 0xFF;
static uint16_t ota_fw_deliver_current_fragment_id = 0;


// For resource notifications
/*
TODO: Only resources template supported for now
static uint8_t ota_command_notif_token_len = 0;
static uint8_t *ota_command_notif_token_ptr = NULL;
static uint8_t ota_dl_status_notif_token_len = 0;
static uint8_t *ota_dl_status_notif_token_ptr = NULL;
static uint8_t *ota_command_notif_obs_ptr = NULL;
static uint8_t *ota_dl_status_notif_obs_ptr = NULL;
*/

typedef struct command_responses2
{
  uint32_t        process_id;
  bool            response_state;
  ota_commands_e  command_id;
  ns_list_link_t  link;
} notification_t;

typedef NS_LIST_HEAD(notification_t, link) ota_command_responses_list_t;

static ota_command_responses_list_t ota_notification_list;

// Stored OTA processes data
static ota_lib_config_data_t ota_lib_config_data;
static ota_processes_t ota_stored_processes;

//Array of pointers:
static ota_download_state_t **ota_stored_dl_state_ptr;
static ota_parameters_t **ota_stored_parameters_ptr;
static ota_checksum_calculating_t **ota_checksum_calculating_ptr;

static uint8_t ota_fragments_request_service_bitmask_tbl[OTA_FRAGMENTS_REQ_BITMASK_LENGTH] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; // For e.g. segment 1: (fragment 128) MSB...LSB (fragment 1) // TODO: For pointer and memory allocation dynamically
static uint16_t ota_update_fw_delay = 0; // In seconds

static uint16_t ota_fragments_request_service_segment_id = 0;
static ota_ip_address_t ota_fragments_request_source_addr;

static uint32_t ota_current_image_storage_capacity = 0;

// * * * OTA library API function pointers * * *
static void *(*ota_malloc_fptr)(size_t);
static void (*ota_free_fptr)(void*);
static void (*ota_request_timer_fptr)(uint8_t, uint32_t);
static void (*ota_cancel_timer_fptr)(uint8_t);
static ota_error_code_e (*ota_store_new_process_fptr)(uint32_t);
static ota_error_code_e (*ota_read_stored_processes_fptr)(ota_processes_t*);
static ota_error_code_e (*ota_delete_process_fptr)(uint32_t);
static ota_error_code_e (*ota_store_state_fptr)(ota_download_state_t*);
static ota_error_code_e (*ota_read_stored_state_fptr)(uint32_t, ota_download_state_t*);
static ota_error_code_e (*ota_store_parameters_fptr)(ota_parameters_t*);
static ota_error_code_e (*ota_read_stored_parameters_fptr)(uint32_t, ota_parameters_t*);
static uint32_t (*ota_write_fw_bytes_fptr)(uint32_t, uint32_t, uint32_t, uint8_t*);
static uint32_t (*ota_read_fw_bytes_fptr)(uint32_t, uint32_t, uint32_t, uint8_t*);
static void (*ota_send_update_fw_cmd_received_info_fptr)(uint32_t, uint16_t);
static void (*ota_update_device_registration_fptr)(void);
static int8_t (*ota_socket_send_fptr)(ota_ip_address_t *dest_addr, uint16_t payload_length, uint8_t *payload_ptr);
static uint16_t (*ota_coap_send_notif_fptr)(char *path, uint8_t *payload_ptr, uint16_t payload_len);

static ota_error_code_e (*ota_create_resource_fptr)(const char *path, const char *type,
                                                    int32_t flags, bool is_observable,
                                                    ota_coap_callback_t *callback, bool publish_uri);
static ota_error_code_e (*ota_start_received_fptr)(ota_parameters_t*);
static void (*ota_process_finished_fptr)(uint32_t);

// * * * Function prototypes * * *
static void ota_create_notification(uint8_t process_id_index, uint32_t process_id, bool response_state, ota_commands_e command_id);
static void ota_manage_start_command(uint16_t payload_length, uint8_t *payload_ptr);
static ota_error_code_e ota_parse_start_command_parameters(uint8_t *payload_ptr);
static void ota_manage_fragment_command(uint16_t payload_length, uint8_t *payload_ptr);
static void ota_manage_abort_command(uint16_t payload_length, uint8_t *payload_ptr);
static void ota_manage_end_fragments_command(uint16_t payload_length, uint8_t *payload_ptr);
static void ota_manage_update_fw_command(uint16_t payload_length, uint8_t *payload_ptr);
static void ota_manage_fragments_request_command(uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *source_addr);
static void ota_manage_delete_command(uint8_t process_id_index);
static void ota_serve_fragments_request_by_sending_one_fragment(uint8_t process_id_index);
static ota_error_code_e ota_build_one_fw_fragment(uint8_t process_id_index, uint16_t fragment_id, uint8_t *built_payload_ptr);
static void ota_build_and_send_command(uint8_t command_id, uint32_t process_id, uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *dest_address);
static void ota_request_missing_fragments(uint8_t process_id_index, bool fallback_flag);
static bool ota_check_if_fragment_already_received(uint8_t process_id_index, uint16_t fragment_id);
static uint16_t ota_get_missing_fragment_total_count(uint8_t process_id_index);
static uint16_t ota_get_and_log_first_missing_segment(uint8_t process_id_index, uint8_t *missing_fragment_bitmasks_ptr);
static uint16_t ota_get_next_missing_fragment_id_for_requester(uint8_t process_id_index, bool bit_mask_change);
static uint16_t ota_calculate_checksum_over_one_fragment(uint8_t *data_ptr, uint16_t data_length);
static void ota_manage_whole_fw_checksum_calculating(void);
static void ota_init_fragments_bit_mask(uint8_t process_id_index, uint8_t init_value);
static uint8_t ota_get_process_id_index(uint32_t process_id);
static uint8_t ota_get_first_free_process_id_index(void);
static uint8_t ota_add_new_process(uint32_t process_id);
static void ota_delete_process(uint32_t process_id, bool storage_capacity_updated);
static uint8_t ota_get_first_missing_fragments_process_id(bool fallback_flag);
static void ota_get_state(uint8_t process_id_index, char *ota_state_ptr);
static void ota_manage_deliver_fw_command(uint16_t payload_length, uint8_t *payload_ptr);
static void ota_deliver_one_fragment(uint8_t process_id_index);
static uint8_t ota_get_process_id_index_from_uri_path(uint16_t uri_path_length, uint8_t *uri_path_ptr);
static void ota_handle_command_forwarding(ota_ip_address_t *source_addr_ptr, uint16_t payload_length, uint8_t *payload_ptr, bool mpl_used);
static uint8_t ota_resources_image_download_data(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);

struct ota_server_s {
    void (*manage_deliver_fw_command)(uint16_t payload_length, uint8_t *payload_ptr);
    void (*deliver_one_fragment)(uint8_t process_id_index);
    uint8_t (*get_process_id_index_from_uri_path)(uint16_t uri_path_length, uint8_t *uri_path_ptr);
    void (*handle_command_forwarding)(ota_ip_address_t *source_addr_ptr, uint16_t payload_length, uint8_t *payload_ptr, bool mpl_used);
    uint8_t (*resources_image_download_data)(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto);
};

// CoAP function prototypes
#if 0
static ota_error_code_e ota_create_dynamic_resource(const char *path, const char *type, int32_t flags, bool is_observable, ota_coap_callback_t *callback, bool publish_uri);
#endif
static void ota_send_coap_text_response(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, const char *payload);
static void ota_send_coap_unhandled_response(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address);

static void ota_resources_send_notif(notification_t *notif);
static void ota_resources_send_dl_status_notif(uint8_t process_id_index);

static void ota_resources_build_dl_status_notif(uint8_t process_id_index, char *dl_status_ptr);
