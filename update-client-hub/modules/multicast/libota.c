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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "mbed-coap/sn_coap_header.h"
#include "sn_nsdl_lib.h"
#include "sn_grs.h"

#include "ip6string.h"
#include "randLIB.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "common_functions.h"
#include "mbed-trace/mbed_trace.h"
#include "otaLIB.h"
#include "libota.h"
#include "otaLIB_resources.h"
#include "update-client-common/arm_uc_config.h"

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)

static void ota_start_timer(ota_timers_e timer_id, uint32_t start_time, uint32_t random_window);

static char ota_resources_image_dl_data_tbl[]   = "2001/0/XXXXXXXX"; // XXXXXXXX = OTA process ID (4 bytes)

// * * * Checksum calculating over whole firmware * * *
// OTA library calculates checksum by OTA_CHECKSUM_CALCULATING_BYTE_COUNT bytes at a time and then generates event with
// OTA_CHECKSUM_CALCULATING_INTERVAL time for avoiding interrupting other operations for too long time
#define OTA_CHECKSUM_CALCULATING_BYTE_COUNT                 512 // In bytes
#define OTA_CHECKSUM_CALCULATING_INTERVAL                   10  // In milliseconds

#define OTA_VERIFY_FRAGMENT_WRITING_TO_DATA_STORAGE         0

// * * * Timer random timeout values (values are seconds) * * *
#define OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START      30  // After this random timeout, device will send request for its missing fragments.
#define OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM     90 // Device will wait silent moment before sending request for its missing fragments.

#define OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START         5  // After this random timeout, device will start sending fragments to requester.
#define OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_RANDOM        25 // Device will wait silent moment before sending missing fragments.

const ota_server_t ota_server_ref = {
    .manage_deliver_fw_command = ota_manage_deliver_fw_command,
    .deliver_one_fragment = ota_deliver_one_fragment,
    .get_process_id_index_from_uri_path = ota_get_process_id_index_from_uri_path,
    .handle_command_forwarding = ota_handle_command_forwarding,
    .resources_image_download_data = 0
#if 0 // Enable when multiple process support is needed
    .resources_image_download_data = ota_resources_image_download_data
#endif
};

static sn_coap_observe_e obs_number;
static const ota_server_t* ota_server;
#define OTA_TIME_HOUR2SEC(x) (uint32_t)(x * 3600)

void ota_lib_reset()
{
    if (ota_free_fptr) {
        for (uint8_t i = 0; i < ota_lib_config_data.ota_max_processes_count; i++) {
            if (ota_stored_dl_state_ptr != NULL) {
                ota_free_fptr(ota_stored_dl_state_ptr[i]);
                ota_stored_dl_state_ptr[i] = NULL;
            }
            if (ota_stored_parameters_ptr && ota_stored_parameters_ptr[i]) {
                ota_free_fptr(ota_stored_parameters_ptr[i]);
                ota_stored_parameters_ptr[i] = NULL;
            }

            if ( ota_checksum_calculating_ptr[i]) {
                if (ota_checksum_calculating_ptr[i]->ota_sha256_context_ptr) {
                    ota_free_fptr(ota_checksum_calculating_ptr[i]->ota_sha256_context_ptr);
                    ota_checksum_calculating_ptr[i]->ota_sha256_context_ptr = NULL;
                }
                ota_free_fptr(ota_checksum_calculating_ptr[i]);
                ota_checksum_calculating_ptr[i] = NULL;
            }
        }

        if (ota_checksum_calculating_ptr) {
            ota_free_fptr(ota_checksum_calculating_ptr);
            ota_checksum_calculating_ptr = NULL;
        }

        if (ota_stored_parameters_ptr) {
            ota_free_fptr(ota_stored_parameters_ptr);
            ota_stored_parameters_ptr = NULL;
        }

        if (ota_stored_dl_state_ptr) {
            ota_free_fptr(ota_stored_dl_state_ptr);
            ota_stored_dl_state_ptr = NULL;
        }

        if (ota_stored_processes.ota_process_ids_tbl) {
            ota_free_fptr(ota_stored_processes.ota_process_ids_tbl);
            ota_stored_processes.ota_process_ids_tbl = NULL;
        }
    }
}

ota_error_code_e ota_lib_configure(ota_lib_config_data_t *lib_config_data_ptr,
                                   ota_config_func_pointers_t *func_pointers_ptr,
                                   uint8_t max_process_count, const ota_server_t* server_ptr)
{
    ota_error_code_e returned_status = OTA_OK;
    obs_number = (sn_coap_observe_e) 0;
    ota_server = server_ptr;

    if (lib_config_data_ptr == NULL ||
        func_pointers_ptr == NULL) {
        tr_err("Some given function parameter is null");
        returned_status = OTA_PARAMETER_FAIL;
        goto done;
    }

    memset(&ota_lib_config_data, 0, sizeof(ota_lib_config_data_t));

    memset(&ota_stored_processes, 0, sizeof(ota_processes_t));

    ota_lib_config_data.ota_max_processes_count = max_process_count;

    ota_lib_config_data.device_type = lib_config_data_ptr->device_type;
    ota_lib_config_data.response_msg_type = lib_config_data_ptr->response_msg_type;
    ota_lib_config_data.response_sending_delay_start = lib_config_data_ptr->response_sending_delay_start;
    ota_lib_config_data.unicast_socket_addr.port = lib_config_data_ptr->unicast_socket_addr.port;

    memcpy(&ota_lib_config_data.link_local_multicast_socket_addr,
           &lib_config_data_ptr->link_local_multicast_socket_addr,
           sizeof(lib_config_data_ptr->link_local_multicast_socket_addr));

    memcpy(&ota_lib_config_data.mpl_multicast_socket_addr,
           &lib_config_data_ptr->mpl_multicast_socket_addr,
           sizeof(lib_config_data_ptr->mpl_multicast_socket_addr));

    if (func_pointers_ptr->mem_alloc_fptr == NULL || func_pointers_ptr->mem_free_fptr == NULL ||
        func_pointers_ptr->request_timer_fptr == NULL ||
        func_pointers_ptr->cancel_timer_fptr == NULL || func_pointers_ptr->store_new_ota_process_fptr == NULL ||
        func_pointers_ptr->read_stored_ota_processes_fptr == NULL || func_pointers_ptr->remove_stored_ota_process_fptr == NULL ||
        func_pointers_ptr->store_state_fptr == NULL || func_pointers_ptr->read_state_fptr == NULL ||
        func_pointers_ptr->store_parameters_fptr == NULL || func_pointers_ptr->read_parameters_fptr == NULL ||
        func_pointers_ptr->get_fw_storing_capacity_fptr == NULL || func_pointers_ptr->write_fw_bytes_fptr == NULL ||
        func_pointers_ptr->read_fw_bytes_fptr == NULL || func_pointers_ptr->send_update_fw_cmd_received_info_fptr == NULL ||
        func_pointers_ptr->socket_send_fptr == NULL || func_pointers_ptr->coap_send_notif_fptr == NULL) {

        tr_err("Some given function pointer is null");
        returned_status = OTA_FUNC_PTR_NULL;
        goto done;
    }

    ota_malloc_fptr = func_pointers_ptr->mem_alloc_fptr;
    ota_free_fptr = func_pointers_ptr->mem_free_fptr;

    ota_current_image_storage_capacity = func_pointers_ptr->get_fw_storing_capacity_fptr();
    ota_write_fw_bytes_fptr = func_pointers_ptr->write_fw_bytes_fptr;
    ota_read_fw_bytes_fptr = func_pointers_ptr->read_fw_bytes_fptr;
    ota_send_update_fw_cmd_received_info_fptr = func_pointers_ptr->send_update_fw_cmd_received_info_fptr;

    ota_request_timer_fptr = func_pointers_ptr->request_timer_fptr;
    ota_cancel_timer_fptr = func_pointers_ptr->cancel_timer_fptr;

    ota_store_new_process_fptr = func_pointers_ptr->store_new_ota_process_fptr;
    ota_read_stored_processes_fptr = func_pointers_ptr->read_stored_ota_processes_fptr;
    ota_delete_process_fptr = func_pointers_ptr->remove_stored_ota_process_fptr;

    ota_store_state_fptr = func_pointers_ptr->store_state_fptr;
    ota_read_stored_state_fptr = func_pointers_ptr->read_state_fptr;
    ota_store_parameters_fptr = func_pointers_ptr->store_parameters_fptr;
    ota_read_stored_parameters_fptr = func_pointers_ptr->read_parameters_fptr;

    ota_update_device_registration_fptr = func_pointers_ptr->update_device_registration_fptr;
    ota_socket_send_fptr = func_pointers_ptr->socket_send_fptr;
    ota_coap_send_notif_fptr = func_pointers_ptr->coap_send_notif_fptr;
    ota_create_resource_fptr = func_pointers_ptr->create_resource_fptr;
    ota_start_received_fptr = func_pointers_ptr->start_received_fptr;
    ota_process_finished_fptr = func_pointers_ptr->process_finished_fptr;

    ns_list_init(&ota_notification_list);

    //TODO: If this function is called twice, these will leak memory
    ota_stored_processes.ota_process_ids_tbl = (uint32_t*)ota_malloc_fptr(ota_lib_config_data.ota_max_processes_count*sizeof(uint32_t));

    ota_stored_dl_state_ptr = ota_malloc_fptr(ota_lib_config_data.ota_max_processes_count*sizeof(ota_download_state_t*));

    ota_stored_parameters_ptr = ota_malloc_fptr(ota_lib_config_data.ota_max_processes_count*sizeof(ota_parameters_t*));

    ota_checksum_calculating_ptr = ota_malloc_fptr(ota_lib_config_data.ota_max_processes_count*sizeof(ota_checksum_calculating_t*));

    if (!ota_stored_processes.ota_process_ids_tbl || !ota_stored_dl_state_ptr ||
        !ota_stored_parameters_ptr || !ota_checksum_calculating_ptr) {
        returned_status = OTA_OUT_OF_MEMORY;
        goto done;
    }
    memset(ota_stored_processes.ota_process_ids_tbl, 0, ota_lib_config_data.ota_max_processes_count*sizeof(uint32_t));
    memset(ota_stored_dl_state_ptr, 0, ota_lib_config_data.ota_max_processes_count*sizeof(ota_download_state_t*));
    memset(ota_stored_parameters_ptr, 0, ota_lib_config_data.ota_max_processes_count*sizeof(ota_parameters_t*));
    memset(ota_checksum_calculating_ptr, 0, ota_lib_config_data.ota_max_processes_count*sizeof(ota_checksum_calculating_t*));

    for (uint8_t i = 0; i < ota_lib_config_data.ota_max_processes_count; i++) {
        ota_stored_dl_state_ptr[i] = NULL;
        ota_stored_parameters_ptr[i] = NULL;
        ota_checksum_calculating_ptr[i] = NULL;
    }

    returned_status = ota_read_stored_processes_fptr(&ota_stored_processes);

    if (ota_stored_processes.ota_process_count > ota_lib_config_data.ota_max_processes_count)
    {
        tr_err("Stored more OTA processes than defined maximum count!!! (%d %d)", ota_stored_processes.ota_process_count, ota_lib_config_data.ota_max_processes_count);
    }

    if (returned_status != OTA_OK)
    {
        tr_err("Reading stored OTA processes from application failed!!! Error code: %d", returned_status);
        goto done;
    }

    tr_info("Found stored OTA process count: %u", ota_stored_processes.ota_process_count);

    for (uint8_t i = 0; i < ota_stored_processes.ota_process_count; i++) {
        ota_stored_dl_state_ptr[i] = ota_malloc_fptr(sizeof(ota_download_state_t));

        if (ota_stored_dl_state_ptr[i] == NULL) {
            tr_err("Memory allocation failed for ota_stored_dl_state_ptr[%u]!!! (%zu)", i, sizeof(ota_download_state_t));
            returned_status = OTA_OUT_OF_MEMORY;
            goto done;
        }

        memset(ota_stored_dl_state_ptr[i], 0, sizeof(ota_download_state_t));

        returned_status = ota_read_stored_state_fptr(ota_stored_processes.ota_process_ids_tbl[i], ota_stored_dl_state_ptr[i]);


        if (returned_status != OTA_OK) {
            tr_err("Reading stored OTA states from application failed!!! Error code: %d", returned_status);

            ota_delete_process(ota_stored_processes.ota_process_ids_tbl[i], false);
            goto done;
        }

        ota_stored_parameters_ptr[i] = ota_malloc_fptr(sizeof(ota_parameters_t));

        if (ota_stored_parameters_ptr[i] == NULL) {
            ota_delete_process(ota_stored_processes.ota_process_ids_tbl[i], false);
            returned_status = OTA_OUT_OF_MEMORY;
            goto done;
        }

        memset(ota_stored_parameters_ptr[i], 0, sizeof(ota_parameters_t));

        tr_info("Read stored OTA parameters from storage");

        returned_status = ota_read_stored_parameters_fptr(ota_stored_processes.ota_process_ids_tbl[i], ota_stored_parameters_ptr[i]);

        if (returned_status != OTA_OK) {
            tr_err("Memory allocation failed for ota_stored_parameters_ptr[%u]!!! (%zu)", i, sizeof(ota_parameters_t));
            ota_free_fptr(ota_stored_dl_state_ptr[i]);
            ota_stored_dl_state_ptr[i] = NULL;
            returned_status = OTA_OUT_OF_MEMORY;
            goto done;
        }

        if (ota_stored_parameters_ptr[i]->device_type == ota_lib_config_data.device_type)
        {
            ota_own_device_type_process_id_index = ota_get_process_id_index(ota_stored_processes.ota_process_ids_tbl[i]);
        }

        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(i);

        if (missing_fragment_total_count > 0) {
            if (ota_stored_parameters_ptr[i]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID ||
                ota_stored_parameters_ptr[i]->multicast_used_flag == true) {
                if (ota_stored_dl_state_ptr[i]->ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING)
                    {
                    ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                                    OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                                    OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM );
                } else {
                    if (ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_ABORTED &&
                        ota_stored_parameters_ptr[i]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID &&
                        ota_stored_parameters_ptr[i]->fallback_timeout != 0) {
                        ota_start_timer(OTA_FALLBACK_TIMER, OTA_TIME_HOUR2SEC(ota_stored_parameters_ptr[i]->fallback_timeout), 0);
                    }
                }
            }

            if (ota_stored_parameters_ptr[i]->device_type == ota_lib_config_data.device_type &&
                ota_stored_parameters_ptr[i]->fw_download_report_config != 0) {
                if (ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_ABORTED) {
                    ota_start_timer(OTA_REPORT_OWN_DL_STATUS_TIMER,
                                    ota_stored_parameters_ptr[i]->fw_download_report_config, 30);
                }
            }
        } else {
            if (ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_ABORTED &&
                ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_CHECKSUM_FAILED &&
                ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_PROCESS_COMPLETED &&
                ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_UPDATE_FW &&
                ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_INVALID) {

                ota_stored_dl_state_ptr[i]->ota_state = OTA_STATE_CHECKSUM_CALCULATING;
            }
        }

        if ((uint32_t)((uint32_t)ota_stored_parameters_ptr[i]->fw_fragment_count * (uint32_t)ota_stored_parameters_ptr[i]->fw_fragment_byte_count) !=
            ota_stored_parameters_ptr[i]->fw_total_byte_count)
        {
            tr_err("Stored total firmware byte count wrong! Changed to: %u", (ota_stored_parameters_ptr[i]->fw_fragment_count * ota_stored_parameters_ptr[i]->fw_fragment_byte_count));

            ota_stored_parameters_ptr[i]->fw_total_byte_count = (ota_stored_parameters_ptr[i]->fw_fragment_count * ota_stored_parameters_ptr[i]->fw_fragment_byte_count);
        }

        if (ota_stored_parameters_ptr[i]->fw_total_byte_count <= ota_current_image_storage_capacity) {
            ota_current_image_storage_capacity -= ota_stored_parameters_ptr[i]->fw_total_byte_count;
            tr_info("ota_current_image_storage_capacity = %"PRIu32, ota_current_image_storage_capacity);
        } else {
            tr_err("Stored image size is bigger than storage capacity!!! (%"PRIu32" %"PRIu32")",
            ota_stored_parameters_ptr[i]->fw_total_byte_count, ota_current_image_storage_capacity);
            ota_current_image_storage_capacity = 0;
        }

        tr_info("Missing fragments total count: %u Received fragment total count: %u",
        missing_fragment_total_count, (ota_stored_parameters_ptr[i]->fw_fragment_count - missing_fragment_total_count));

        ota_get_and_log_first_missing_segment(i, NULL);
#if 0 // Enable back when support for multiple OTA processes are needed
        if (ota_server) {
            tr_info("Image resource length: %d", ota_stored_parameters_ptr[i]->delivered_image_resource_name_length);


            if (ota_stored_parameters_ptr[i]->delivered_image_resource_name_length > 0) {
                ota_error_code_e rc = ota_create_dynamic_resource((char*)ota_stored_parameters_ptr[i]->delivered_image_resource_name_ptr,
                                                                  OTA_DYN_RESOURCE_TYPE, SN_GRS_GET_ALLOWED | SN_GRS_PUT_ALLOWED | SN_GRS_DELETE_ALLOWED,
                                                                  false, ota_server->resources_image_download_data, true);

                if (rc != OTA_OK) {
                    tr_err("Creating OTA image transfer data resource failed: %d %s", rc, ota_stored_parameters_ptr[i]->delivered_image_resource_name_ptr);
                    goto done;
                }
            }
        }
#endif

        if (ota_stored_dl_state_ptr[i]->ota_state == OTA_STATE_CHECKSUM_CALCULATING) {
            ota_manage_whole_fw_checksum_calculating();
        }
    }

//There might be memory leaks if above failed!!!!!!!
done:
    if (returned_status == OTA_OK) {
        if (server_ptr) {
            tr_info("OTA library v0.0.2 configured successfully (ROUTER)");
        } else {
            tr_info("OTA library v0.0.2 configured successfully (NODE)");
        }
    } else {
        if (server_ptr) {
            tr_err("OTA library v0.0.2 configuration failed! Error code: %d (ROUTER)", returned_status);
        } else {
            tr_err("OTA library v0.0.2 configuration failed! Error code: %d (NODE)", returned_status);
        }
  }

  return returned_status;
}

void ota_socket_receive_data(uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *source_addr_ptr)
{
    if (payload_ptr == NULL || source_addr_ptr == NULL) {
        tr_err("Function ota_socket_receive_data() called with NULL pointer");
        return;
    }

    tr_info("OTA received socket data from source address: %s Port %u", trace_ipv6(source_addr_ptr->address_tbl), source_addr_ptr->port);

    uint8_t command_id = payload_ptr[0];

    switch (command_id) {
        case OTA_DELETE_CMD:
            if (payload_length >= OTA_DELETE_CMD_LENGTH) {
                uint32_t process_id = common_read_32_bit(&payload_ptr[OTA_CMD_PROCESS_ID_INDEX]);

                tr_info("***Received OTA DELETE command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

                uint8_t process_id_index = ota_get_process_id_index(process_id);
                ota_manage_delete_command(process_id_index);
            } else {
                tr_err("Received DELETE command data length not correct: %u (%u)", payload_length, OTA_DELETE_CMD_LENGTH);
            }
            break;

        case OTA_START_CMD:
            if (!ota_server) {
                ota_manage_start_command(payload_length, payload_ptr);
            } else {
                tr_err("Unsupported START command to Border router's UDP socket. START command can be sent only via resource to Border router!");
            }
            break;

        case OTA_DELIVER_FW_CMD:
            if (ota_server) {
                ota_server->manage_deliver_fw_command(payload_length, payload_ptr);
            } else {
                tr_err("Unsupported DELIVER FW command to node's UDP socket");
            }
            break;

        case OTA_FRAGMENT_CMD:
            ota_manage_fragment_command(payload_length, payload_ptr);
            break;

        case OTA_ABORT_CMD:
            ota_manage_abort_command(payload_length, payload_ptr);
            break;

        case OTA_END_FRAGMENTS_CMD:
            ota_manage_end_fragments_command(payload_length, payload_ptr);
            break;

        case OTA_UPDATE_FW_CMD:
            ota_manage_update_fw_command(payload_length, payload_ptr);
            break;

        case OTA_FRAGMENTS_REQUEST_CMD:
            ota_manage_fragments_request_command(payload_length, payload_ptr, source_addr_ptr);
            break;

        default:
            tr_err("Unsupported OTA command %d from UDP socket", command_id);
            tr_err("Whole received invalid OTA command data: %s", trace_array(payload_ptr, payload_length));
            break;

    }
}

void ota_timer_expired(uint8_t timer_id)
{
    ota_cancel_timer_fptr(timer_id);

    if (timer_id == OTA_NOTIFICATION_TIMER ) {
        notification_t *notif = ns_list_get_first(&ota_notification_list);
        if (notif) {
            uint8_t process_id_index = ota_get_process_id_index(notif->process_id);
            if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                if (notif->command_id == OTA_PROCESS_COMPLETED_RESPONSE) {
                    if (!ota_server && ota_stored_parameters_ptr[process_id_index]->multicast_used_flag == true) {
                        ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                            true, OTA_END_FRAGMENTS_CMD);
                    }

                    if (process_id_index == ota_own_device_type_process_id_index && ota_stored_parameters_ptr[process_id_index]->fw_download_report_config != 0) {
                        ota_cancel_timer_fptr(OTA_REPORT_OWN_DL_STATUS_TIMER);
                        ota_resources_send_dl_status_notif(process_id_index);
                    }
                } else if (notif->command_id == OTA_DELIVER_FW_CMD) {
                    ota_start_timer(OTA_FRAGMENTS_DELIVERING_TIMER, (uint32_t)(ota_stored_parameters_ptr[process_id_index]->fw_fragment_sending_interval_mpl / 1000), 0);
                } else if (notif->command_id == OTA_UPDATE_FW_CMD) {
                    if (process_id_index < ota_lib_config_data.ota_max_processes_count) {
                        if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_PROCESS_COMPLETED ||
                            ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_UPDATE_FW) {
                            ota_send_update_fw_cmd_received_info_fptr(ota_stored_parameters_ptr[process_id_index]->ota_process_id, ota_update_fw_delay);
                        }
                    }
                }
            }

            if (notif->command_id == OTA_END_FRAGMENTS_CMD) {
                ota_build_and_send_command(OTA_END_FRAGMENTS_CMD, notif->process_id,
                                           0, NULL, &ota_lib_config_data.link_local_multicast_socket_addr);
            } else {
                ota_resources_send_notif(notif);
            }
            ns_list_remove(&ota_notification_list, notif);
            ota_free_fptr(notif);
            if (ns_list_count(&ota_notification_list) > 0) {
                ota_cancel_timer_fptr(timer_id);
                ota_request_timer_fptr(timer_id, 1000);
            }
        }
    } else if (timer_id == OTA_MISSING_FRAGMENTS_REQUESTING_TIMER) {
        uint8_t process_id_index = ota_get_first_missing_fragments_process_id(false);

        if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            ota_request_missing_fragments(process_id_index, false);
        } else {
            tr_warn("OTA_MISSING_FRAGMENTS_REQUESTING_TIMER: Device does not have missing fragments or request address not given or requesting is aborted");
        }
    } else if (ota_server && timer_id == OTA_FRAGMENTS_DELIVERING_TIMER) {
        if (ota_fw_delivering_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            if (ota_fw_deliver_current_fragment_id <= ota_stored_parameters_ptr[ota_fw_delivering_process_id_index]->fw_fragment_count) {
                ota_server->deliver_one_fragment(ota_fw_delivering_process_id_index);
                ota_start_timer(OTA_FRAGMENTS_DELIVERING_TIMER, (uint32_t)(ota_stored_parameters_ptr[ota_fw_delivering_process_id_index]->fw_fragment_sending_interval_mpl / 1000), 0);
            } else {
                if (ota_stored_parameters_ptr[ota_fw_delivering_process_id_index]->multicast_used_flag == true) {
                    ota_create_notification(ota_fw_delivering_process_id_index, ota_stored_processes.ota_process_ids_tbl[ota_fw_delivering_process_id_index],
                                        true, OTA_END_FRAGMENTS_CMD);
                }
                ota_fw_delivering_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
            }
        }
    } else if (timer_id == OTA_FRAGMENTS_REQUEST_SERVICE_TIMER) {
        if (ota_fragments_request_service_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            ota_serve_fragments_request_by_sending_one_fragment(ota_fragments_request_service_process_id_index);
            uint16_t missing_fragment_count_for_requester = ota_get_next_missing_fragment_id_for_requester(ota_fragments_request_service_process_id_index, false);

            if (missing_fragment_count_for_requester > 0) {
                ota_start_timer(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER, (uint32_t)(ota_stored_parameters_ptr[ota_fragments_request_service_process_id_index]->fw_fragment_sending_interval_uni / 1000), 30);
            } else {
                tr_info("All requested fragments sent");
                ota_fragments_request_service_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
            }
        }
    } else if (timer_id == OTA_REPORT_OWN_DL_STATUS_TIMER) {
        if (ota_own_device_type_process_id_index < ota_lib_config_data.ota_max_processes_count) {
            if (ota_stored_parameters_ptr[ota_own_device_type_process_id_index]->fw_download_report_config != 0 &&
                ota_stored_dl_state_ptr[ota_own_device_type_process_id_index]->ota_state != OTA_STATE_ABORTED)
            {
                ota_resources_send_dl_status_notif(ota_own_device_type_process_id_index);
            }
        }
    } else if (timer_id == OTA_FALLBACK_TIMER) {
        uint8_t process_id_index = ota_get_first_missing_fragments_process_id(true);

        if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            ota_get_and_log_first_missing_segment(process_id_index, NULL);

            ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_MISSING_FRAGMENTS_REQUESTING;

            ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

            if (rc != OTA_OK) {
                tr_err("Storing OTA states failed, RC: %d", rc);
            }

            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM);

            tr_info("State changed to \"OTA MISSING FRAGMENTS REQUESTING\"");

            if (ota_stored_parameters_ptr[process_id_index]->fallback_timeout != 0) {
                ota_start_timer(OTA_FALLBACK_TIMER, OTA_TIME_HOUR2SEC(ota_stored_parameters_ptr[process_id_index]->fallback_timeout), 0);
            }
        } else {
            tr_info("No missing fragments or missing fragments request address not given or OTA process is aborted");
        }
    } else if (timer_id == OTA_CHECKSUM_CALCULATING_TIMER) {
        ota_manage_whole_fw_checksum_calculating();
    } else {
        tr_err("Unsupported timer ID: %d", timer_id);
    }
}

static void ota_manage_start_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);

    ota_error_code_e rc = OTA_OK;

    uint32_t process_id = common_read_32_bit(&payload_ptr[OTA_CMD_PROCESS_ID_INDEX]);
    uint8_t device_type = payload_ptr[OTA_START_CMD_DEVICE_TYPE_INDEX];
    uint8_t process_id_index = ota_get_process_id_index(process_id);

    tr_info("***Received OTA START command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        if (payload_length < OTA_START_CMD_LENGTH) {
            tr_err("Received START command data length not correct: %u (%u)", payload_length, OTA_START_CMD_LENGTH);
            return;
        }

        if (!ota_server) {
            for (uint8_t i = 0; i < ota_stored_processes.ota_process_count; i++) {
                if (ota_stored_parameters_ptr[i]->device_type == device_type) {
                    tr_err("Node received START command with same Device type OTA process already created --> START command is ignored!");
                    return;
                }
            }

            if (device_type != ota_lib_config_data.device_type) {
                tr_err("Node received START command not it's own device type --> START command is ignored!");
                return;
            }
        }

        rc = ota_parse_start_command_parameters(payload_ptr);

        if (rc == OTA_OK) {
            process_id_index = ota_get_process_id_index(process_id);

            if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {

                ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length =
                        (ota_stored_parameters_ptr[process_id_index]->fw_segment_count * OTA_FRAGMENTS_REQ_BITMASK_LENGTH);

                tr_info("Bitmask length as bytes for received fragments: %u", ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length);

                ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr =
                        ota_malloc_fptr(ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length);

                if (ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr != NULL) {
                    ota_init_fragments_bit_mask(process_id_index, 0x00);

                    if (ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {
                        if (ota_stored_parameters_ptr[process_id_index]->fallback_timeout != 0) {
                            ota_start_timer(OTA_FALLBACK_TIMER, OTA_TIME_HOUR2SEC(ota_stored_parameters_ptr[process_id_index]->fallback_timeout), 0);
                        }
                    }

                    ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_STARTED;

                    tr_info("State changed to \"OTA STARTED\"");

                    if (ota_server) {
                        uint8_t process_id_i = sizeof(ota_resources_image_dl_data_tbl) - 9;

                        sprintf(&ota_resources_image_dl_data_tbl[process_id_i], "%08"PRIu32, ota_stored_parameters_ptr[process_id_index]->ota_process_id);

                        // first we need to take a copy of the resource name string, as it is needed on ota_create_dynamic_resource()
                        ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_length = sizeof(ota_resources_image_dl_data_tbl);

                        if (ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr != NULL) {
                            ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr);
                            ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr = NULL;
                        }

                        ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr = ota_malloc_fptr(sizeof(ota_resources_image_dl_data_tbl));

                        if (ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr != NULL) {
                            memcpy(ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr,
                                   &ota_resources_image_dl_data_tbl[0], sizeof(ota_resources_image_dl_data_tbl));
                        } else {
                            rc = OTA_OUT_OF_MEMORY;
                            ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_length = 0;
                            tr_err("Memory allocation failed for delivered_image_resource_name_ptr[%u] (%lu)", process_id_index, sizeof(ota_resources_image_dl_data_tbl));
                        }
#if 0 // Enable back when support for multiple OTA processes are needed
                        if (rc == OTA_OK) {
                            rc = ota_create_dynamic_resource((char*)ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr, OTA_DYN_RESOURCE_TYPE,
                                                             SN_GRS_GET_ALLOWED | SN_GRS_PUT_ALLOWED | SN_GRS_DELETE_ALLOWED,
                                                             false, ota_server->resources_image_download_data,
                                                             true);
                        }

                        if (rc == OTA_OK) {
                            tr_info("Creating OTA image transfer data resource succeeded: %s", ota_resources_image_dl_data_tbl);
                        } else {
                            tr_err("Creating OTA image transfer data resource failed: %d %s", rc, ota_resources_image_dl_data_tbl);
                        }

                        if (ota_update_device_registration_fptr != NULL) {
                            ota_update_device_registration_fptr();
                        }
#endif
                        if (rc == OTA_OK) {
                            if (ota_start_received_fptr != NULL) {
                                rc = ota_start_received_fptr(ota_stored_parameters_ptr[process_id_index]);
                                if (rc != OTA_OK) {
                                    tr_err("Ota_start_received returned error: %d", rc);
                                }
                            }
                        }
                    }

                    if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end != 0x7FFF) {
                        ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                            true, OTA_START_CMD);
                    }

                    if (ota_stored_parameters_ptr[process_id_index]->device_type == ota_lib_config_data.device_type)
                    {
                        ota_own_device_type_process_id_index = process_id_index;
                    }

                    ota_error_code_e storing_status = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

                    if (storing_status != OTA_OK) {
                        tr_err("Storing OTA states failed, RC: %d", storing_status);
                    }

                    rc = ota_store_parameters_fptr(ota_stored_parameters_ptr[process_id_index]);

                    if (rc != OTA_OK) {
                        tr_err("Storing OTA parameters failed, RC: %d", rc);
                    }

                    if (ota_stored_parameters_ptr[process_id_index]->device_type == ota_lib_config_data.device_type &&
                        ota_stored_parameters_ptr[process_id_index]->fw_download_report_config != 0) {
                        ota_start_timer(OTA_REPORT_OWN_DL_STATUS_TIMER, ota_stored_parameters_ptr[process_id_index]->fw_download_report_config, 30);
                    }
                } else {
                    tr_err("Memory allocation failed for received fragments bitmask!!! (%u bytes)",
                           ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length);
                    ota_delete_process(ota_stored_processes.ota_process_ids_tbl[process_id_index], true);
                }
            } else {
                tr_warn("ota_manage_start_command() Process not found from storage");
            }
        } else {
            if (rc != OTA_STORAGE_ERROR) {
                if (rc == OTA_STORAGE_OUT_OF_SPACE) {
                    ota_create_notification(OTA_INVALID_PROCESS_ID_INDEX, process_id, false, OTA_START_CMD);
                    ota_delete_process(process_id, false);
                } else {
                    ota_delete_process(process_id, true);
                }
            } else {
                ota_delete_process(process_id, true);
            }
        }
    } else {
        if (device_type != ota_stored_parameters_ptr[process_id_index]->device_type) {
            tr_err("Device type incorrect in updated START command (%u vs. %u)",
                   device_type, ota_stored_parameters_ptr[process_id_index]->device_type);
            return;
        }

        uint8_t whole_fw_checksum_temp_tbl[OTA_WHOLE_FW_CHECKSUM_LENGTH];

        memcpy(whole_fw_checksum_temp_tbl, &payload_ptr[OTA_START_CMD_WHOLE_FW_CHECKSUM_INDEX], OTA_WHOLE_FW_CHECKSUM_LENGTH);

        int match = memcmp(whole_fw_checksum_temp_tbl,
                           ota_stored_parameters_ptr[process_id_index]->whole_fw_checksum_tbl,
                           OTA_WHOLE_FW_CHECKSUM_LENGTH);

        if (match != 0) {
            tr_err("Whole firmware image checksum incorrect in updated START command! Match = %u", match);
            tr_err("FW checksum in START command: %s", trace_array(&payload_ptr[OTA_START_CMD_WHOLE_FW_CHECKSUM_INDEX], OTA_WHOLE_FW_CHECKSUM_LENGTH));
            tr_err("FW checksum in data storage : %s", trace_array(ota_stored_parameters_ptr[process_id_index]->whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH));
            return;
        }

        uint8_t fw_name_length_temp = payload_ptr[OTA_START_CMD_FW_NAME_LENGTH_INDEX];

        match = memcmp(&payload_ptr[OTA_START_CMD_FW_NAME_INDEX],
                       ota_stored_parameters_ptr[process_id_index]->fw_name_ptr,
                       fw_name_length_temp);

        if (match != 0) {
            tr_err("Firmware name incorrect in updated START command! Match = %u", match);
            return;
        }

        uint8_t fw_version_length_temp = payload_ptr[OTA_START_CMD_FW_NAME_INDEX + fw_name_length_temp];

        match = memcmp(&payload_ptr[OTA_START_CMD_FW_NAME_INDEX + fw_name_length_temp + 1],
                ota_stored_parameters_ptr[process_id_index]->fw_version_ptr,
                fw_version_length_temp);

        if (match != 0) {
            tr_err("Firmware version incorrect in updated START command! Match = %u", match);
            return;
        }

        tr_warn("START command parameters updated!");

        rc = ota_parse_start_command_parameters(payload_ptr);

        if (rc != OTA_OK) {
            tr_err("Received START command parameters storing failed: %d", rc);
            return;
        }

        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

        if (missing_fragment_total_count > 0) {
            if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
                if (ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {
                    if (ota_stored_parameters_ptr[process_id_index]->fallback_timeout != 0) {
                        ota_start_timer(OTA_FALLBACK_TIMER, OTA_TIME_HOUR2SEC(ota_stored_parameters_ptr[process_id_index]->fallback_timeout), 0);
                    }
                }
            }

            if (ota_stored_parameters_ptr[process_id_index]->device_type == ota_lib_config_data.device_type &&
                ota_stored_parameters_ptr[process_id_index]->fw_download_report_config != 0) {
                ota_start_timer(OTA_REPORT_OWN_DL_STATUS_TIMER, ota_stored_parameters_ptr[process_id_index]->fw_download_report_config, 30);
            }
        } else {
            if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_PROCESS_COMPLETED &&
                ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_UPDATE_FW &&
                ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_INVALID) {

                ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_CHECKSUM_CALCULATING;
                ota_manage_whole_fw_checksum_calculating();
            }
        }

        if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end != 0x7FFF) {
            ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                true, OTA_START_CMD);
        }

        if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_ABORTED) {
            ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_STARTED;
            tr_info("State changed to \"OTA STARTED\"");
        }

        ota_error_code_e storing_status = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

        if (storing_status != OTA_OK)
        {
            tr_err("Storing OTA states failed, RC: %d", storing_status);
        }

        rc = ota_store_parameters_fptr(ota_stored_parameters_ptr[process_id_index]);

        if (rc != OTA_OK)
        {
            tr_err("Storing OTA parameters failed, RC: %d", rc);
        }
    }

    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);
}

static ota_error_code_e ota_parse_start_command_parameters(uint8_t *payload_ptr)
{
    ota_error_code_e returned_status = OTA_OK;

    bool new_process_flag = true; // This flag tells if stored OTA parameters are for new OTA process or paremeters are updated

    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        process_id_index = ota_add_new_process(process_id);

        new_process_flag = true;
    } else {
        new_process_flag = false;
    }

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX)
    {
        tr_warn("ota_parse_start_command_parameters() Process not found from storage");
        return OTA_STORAGE_ERROR;
    }

    if (new_process_flag == true) {
        ota_stored_dl_state_ptr[process_id_index]->ota_process_id = process_id;
        ota_stored_parameters_ptr[process_id_index]->ota_process_id = process_id;
    }

    if (new_process_flag == true) {
        ota_stored_parameters_ptr[process_id_index]->device_type = payload_ptr[payload_index];
    }

    payload_index += 1;

    ota_stored_parameters_ptr[process_id_index]->response_sending_delay_start = ota_lib_config_data.response_sending_delay_start;

    uint16_t response_sending_delay_end = common_read_16_bit(&payload_ptr[payload_index]);

    if ((response_sending_delay_end & 0x8000) == 0) {
        ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end = response_sending_delay_end;
    } else {
        tr_err("Response sending delay: Dimensional value not supported yet!");
        ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end = response_sending_delay_end & 0x7FFF;
    }

    uint8_t multicast_used_flag_temp = payload_ptr[OTA_START_CMD_MULTICAST_SELECTION_INDEX];

    if (multicast_used_flag_temp == 1) {
        if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end < ota_stored_parameters_ptr[process_id_index]->response_sending_delay_start) {
            ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end = (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_start + 5);
        }
    } else {
        ota_stored_parameters_ptr[process_id_index]->response_sending_delay_start = ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end;
    }

    if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end == 0x7FFF) {
        tr_warn("Response sending not used!");
    }

    payload_index += 2;

    ota_stored_parameters_ptr[process_id_index]->fw_download_report_config = common_read_16_bit(&payload_ptr[payload_index]);
    payload_index += 2;

    if (ota_stored_parameters_ptr[process_id_index]->device_type == ota_lib_config_data.device_type &&
        ota_stored_parameters_ptr[process_id_index]->fw_download_report_config == 0) {
        tr_warn("Automatic own device type firmware downlink reporting disabled!");
    }

    if (multicast_used_flag_temp == 0) {
        ota_stored_parameters_ptr[process_id_index]->multicast_used_flag = false;
    } else {
        ota_stored_parameters_ptr[process_id_index]->multicast_used_flag = true;
    }
    tr_info("DL_STATUS_TIMER %us", ota_stored_parameters_ptr[process_id_index]->fw_download_report_config);
    tr_info("Multicast used flag: %d", multicast_used_flag_temp);

    payload_index += 1;

    if (new_process_flag == true) {
        ota_stored_parameters_ptr[process_id_index]->fw_fragment_count = common_read_16_bit(&payload_ptr[payload_index]);
        tr_info("Number of firmware fragments: %u", ota_stored_parameters_ptr[process_id_index]->fw_fragment_count);
        tr_info("Number of segments (fragment_count / OTA_SEGMENT_SIZE): %u", (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count / OTA_SEGMENT_SIZE));
        tr_info("Bytes over segments (fragment_count %% OTA_SEGMENT_SIZE): %u", (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count % OTA_SEGMENT_SIZE));
    }

    payload_index += 2;

    if (new_process_flag == true) {
        ota_stored_parameters_ptr[process_id_index]->fw_segment_count = (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count / OTA_SEGMENT_SIZE);

        if ((ota_stored_parameters_ptr[process_id_index]->fw_fragment_count % OTA_SEGMENT_SIZE) != 0) {
            ota_stored_parameters_ptr[process_id_index]->fw_segment_count++;
        }
        tr_info("Number of needed segments: %u", ota_stored_parameters_ptr[process_id_index]->fw_segment_count);
    }

    if (new_process_flag == true) {
        ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count = common_read_16_bit(&payload_ptr[payload_index]);
        ota_stored_parameters_ptr[process_id_index]->fw_total_byte_count =
            (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_count * (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count;
    }

    payload_index += 2;

    if (new_process_flag == true) {
        if (ota_stored_parameters_ptr[process_id_index]->fw_total_byte_count <= ota_current_image_storage_capacity) {
            ota_current_image_storage_capacity -= ota_stored_parameters_ptr[process_id_index]->fw_total_byte_count;
        } else {
            tr_err("New firmware image size is bigger than storage capacity!!! (%"PRIu32" %"PRIu32")",
                ota_stored_parameters_ptr[process_id_index]->fw_total_byte_count, ota_current_image_storage_capacity);
            returned_status = OTA_STORAGE_OUT_OF_SPACE;
        }
    }

    if (returned_status == OTA_OK) {
        ota_stored_parameters_ptr[process_id_index]->fw_fragment_sending_interval_uni = common_read_16_bit(&payload_ptr[payload_index]);
        payload_index += 2;

        ota_stored_parameters_ptr[process_id_index]->fw_fragment_sending_interval_mpl = common_read_16_bit(&payload_ptr[payload_index]);
        payload_index += 2;

        ota_stored_parameters_ptr[process_id_index]->fallback_timeout = payload_ptr[payload_index];
        payload_index += 1;

        uint8_t addr_type = payload_ptr[payload_index];
        payload_index += 1;

        switch (addr_type) {
            case 0:
                ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type = OTA_ADDRESS_NOT_VALID;
                break;
            case 1:
                ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type = OTA_ADDRESS_IPV6;
                break;
            case 2:
                ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type = OTA_ADDRESS_IPV4;
                break;
            default:
                ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type = OTA_ADDRESS_NOT_VALID;
                returned_status = OTA_PARAMETER_FAIL;
                break;
        }

        if (returned_status == OTA_OK) {
            if (ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {
                memcpy(ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.address_tbl, &payload_ptr[payload_index], OTA_MISSING_FRAGMENTS_IP_ADDR_LENGTH);
            }

            payload_index += OTA_MISSING_FRAGMENTS_IP_ADDR_LENGTH;

            if (ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {
                ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.port = common_read_16_bit(&payload_ptr[payload_index]);
            }

            payload_index += 2;

            if (new_process_flag == true) {
                memcpy(ota_stored_parameters_ptr[process_id_index]->whole_fw_checksum_tbl, &payload_ptr[payload_index], OTA_WHOLE_FW_CHECKSUM_LENGTH);
            }

            payload_index += OTA_WHOLE_FW_CHECKSUM_LENGTH;

            if (new_process_flag == true) {
                ota_stored_parameters_ptr[process_id_index]->fw_name_length = payload_ptr[payload_index];
                payload_index += 1;

                if (ota_stored_parameters_ptr[process_id_index]->fw_name_length > OTA_FW_NAME_OR_VERSION_MAX_LENGTH) {
                    ota_stored_parameters_ptr[process_id_index]->fw_name_length = OTA_FW_NAME_OR_VERSION_MAX_LENGTH;
                }

                if (ota_stored_parameters_ptr[process_id_index]->fw_name_ptr != NULL) {
                    ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->fw_name_ptr);
                    ota_stored_parameters_ptr[process_id_index]->fw_name_ptr = NULL;
                }

                if (ota_stored_parameters_ptr[process_id_index]->fw_name_length > 0) {
                    ota_stored_parameters_ptr[process_id_index]->fw_name_ptr = ota_malloc_fptr(ota_stored_parameters_ptr[process_id_index]->fw_name_length);
                }

                if (ota_stored_parameters_ptr[process_id_index]->fw_name_ptr != NULL || ota_stored_parameters_ptr[process_id_index]->fw_name_length == 0) {
                    if (ota_stored_parameters_ptr[process_id_index]->fw_name_length > 0) {
                        memset(ota_stored_parameters_ptr[process_id_index]->fw_name_ptr, 0, ota_stored_parameters_ptr[process_id_index]->fw_name_length);

                        memcpy(ota_stored_parameters_ptr[process_id_index]->fw_name_ptr,
                               &payload_ptr[payload_index],
                               ota_stored_parameters_ptr[process_id_index]->fw_name_length);
                        payload_index += ota_stored_parameters_ptr[process_id_index]->fw_name_length;
                    }

                    ota_stored_parameters_ptr[process_id_index]->fw_version_length = payload_ptr[payload_index];
                    payload_index += 1;

                    if (ota_stored_parameters_ptr[process_id_index]->fw_version_length > OTA_FW_NAME_OR_VERSION_MAX_LENGTH) {
                        ota_stored_parameters_ptr[process_id_index]->fw_version_length = OTA_FW_NAME_OR_VERSION_MAX_LENGTH;
                    }

                    if (ota_stored_parameters_ptr[process_id_index]->fw_version_ptr != NULL) {
                        ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->fw_version_ptr);
                        ota_stored_parameters_ptr[process_id_index]->fw_version_ptr = NULL;
                    }

                    if (ota_stored_parameters_ptr[process_id_index]->fw_version_length > 0) {
                        ota_stored_parameters_ptr[process_id_index]->fw_version_ptr = ota_malloc_fptr(ota_stored_parameters_ptr[process_id_index]->fw_version_length);

                        if (ota_stored_parameters_ptr[process_id_index]->fw_version_ptr != NULL) {
                            memset(ota_stored_parameters_ptr[process_id_index]->fw_version_ptr, 0, ota_stored_parameters_ptr[process_id_index]->fw_version_length);

                            memcpy(ota_stored_parameters_ptr[process_id_index]->fw_version_ptr,
                                   &payload_ptr[payload_index],
                                   ota_stored_parameters_ptr[process_id_index]->fw_version_length);

                            payload_index += ota_stored_parameters_ptr[process_id_index]->fw_version_length;

                            ota_stored_parameters_ptr[process_id_index]->pull_url_length = payload_ptr[payload_index];
                            payload_index += 1;

                            if(ota_stored_parameters_ptr[process_id_index]->pull_url_ptr != NULL) {
                                ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->pull_url_ptr);
                                ota_stored_parameters_ptr[process_id_index]->pull_url_ptr = NULL;
                            }
                            if (ota_stored_parameters_ptr[process_id_index]->pull_url_length > 0) {
                                ota_stored_parameters_ptr[process_id_index]->pull_url_ptr = ota_malloc_fptr(ota_stored_parameters_ptr[process_id_index]->pull_url_length);
                                if(ota_stored_parameters_ptr[process_id_index]->pull_url_ptr != NULL) {
                                    memset(ota_stored_parameters_ptr[process_id_index]->pull_url_ptr, 0, ota_stored_parameters_ptr[process_id_index]->pull_url_length);
                                    memcpy(ota_stored_parameters_ptr[process_id_index]->pull_url_ptr,
                                           &payload_ptr[payload_index],
                                           ota_stored_parameters_ptr[process_id_index]->pull_url_length);
                                    payload_index += ota_stored_parameters_ptr[process_id_index]->pull_url_length;
                                } else {
                                    tr_err("Memory allocation failed for pull url!!! (%u)", ota_stored_parameters_ptr[process_id_index]->pull_url_length);
                                    returned_status = OTA_OUT_OF_MEMORY;
                                }
                            }
                        } else {
                            tr_err("Memory allocation failed for FW version!!! (%u)", ota_stored_parameters_ptr[process_id_index]->fw_version_length);
                            returned_status = OTA_OUT_OF_MEMORY;
                        }
                    }
                } else {
                    tr_err("Memory allocation failed for FW name!!! (%u)", ota_stored_parameters_ptr[process_id_index]->fw_name_length);
                    returned_status = OTA_OUT_OF_MEMORY;
                }
            }
        }
    }

    return returned_status;
}

static void ota_manage_deliver_fw_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    tr_info("***Received OTA DELIVER FW command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_warn("Process not found from storage");
        return;
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_PROCESS_COMPLETED) {
        tr_err("OTA not in PROCESS COMPLETED state when received DELIVER FW command. Current state: %d",
        ota_stored_dl_state_ptr[process_id_index]->ota_state);
        return;
    }

    if (payload_length < OTA_DELIVER_FW_CMD_LENGTH) {
        tr_err("Received DELIVER FW command data length not correct: %u (%u)", payload_length, OTA_DELIVER_FW_CMD_LENGTH);
        return;
    }

    if (ota_stored_parameters_ptr[process_id_index]->multicast_used_flag == false) {
        tr_err("Received DELIVER FW command but multicast not used --> No delivering!!!");
        return;
    }

    if (ota_fw_delivering_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
        tr_err("Fragments delivery already ongoing!!!");
        return;
    }

    ota_fragments_request_service_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;

    ota_fw_deliver_current_fragment_id = common_read_16_bit(&payload_ptr[payload_index]);

    tr_info("Parameter Starting fragment ID to be delivered: %u", ota_fw_deliver_current_fragment_id);

    if (ota_fw_deliver_current_fragment_id == 0){
        tr_err("OTA command parameter Starting fragment ID to be delivered is zero!!! (must be between 1 - %u)",
                ota_stored_parameters_ptr[process_id_index]->fw_fragment_count);
    } else if (ota_fw_deliver_current_fragment_id > ota_stored_parameters_ptr[process_id_index]->fw_fragment_count) {
        tr_err("Starting fragment ID to be delivered too big!!! (max: %u)",
                ota_stored_parameters_ptr[process_id_index]->fw_fragment_count);
    } else {
        if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end != 0x7FFF) {
            ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                true, OTA_DELIVER_FW_CMD);
        }
        ota_fw_delivering_process_id_index = process_id_index;
    }
}

static void ota_manage_fragment_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    tr_info("***Received OTA FRAGMENT command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_warn("Process not found from storage.");
        return;
    }

    if (payload_length < OTA_FRAGMENT_CMD_LENGTH) {
        tr_err("Received FRAGMENT command data length not correct: %u (%u)", payload_length, OTA_FRAGMENT_CMD_LENGTH);
        return;
    }
    uint16_t fragment_id = common_read_16_bit(&payload_ptr[payload_index]);
    payload_index += 2;

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_STARTED &&
        ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_MISSING_FRAGMENTS_REQUESTING &&
        ota_fragments_request_service_process_id_index == OTA_INVALID_PROCESS_ID_INDEX)
    {
        tr_warn("OTA in wrong state when received FW fragment %u / %u. Current state: %d Fragments requesting service OTA process ID index: %u",
                fragment_id, ota_stored_parameters_ptr[process_id_index]->fw_fragment_count,
                ota_stored_dl_state_ptr[process_id_index]->ota_state,
                ota_fragments_request_service_process_id_index);
        return;
    }

    tr_info("OTA Fragment ID: %u / %u", fragment_id, ota_stored_parameters_ptr[process_id_index]->fw_fragment_count);

    uint16_t fragment_checksum = common_read_16_bit(&payload_ptr[payload_length - 2]);

    if (fragment_id == 0) {
        tr_err("Received firmware Fragment ID is zero");
    }

    if (fragment_id > ota_stored_parameters_ptr[process_id_index]->fw_fragment_count) {
        tr_err("Received firmware Fragment ID bigger than whole fragment count in image");
    }

    uint16_t calculated_fragment_checksum = ota_calculate_checksum_over_one_fragment(&payload_ptr[OTA_FRAGMENT_CMD_FRAGMENT_BYTES_INDEX],
            ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count);

    if (fragment_checksum != calculated_fragment_checksum) {
        tr_err("Checksums mismatch. Fragment checksum: 0x%X Calculated checksum: 0x%X", fragment_checksum, calculated_fragment_checksum);
    }

    if (fragment_checksum == calculated_fragment_checksum &&
        fragment_id > 0 && fragment_id <= ota_stored_parameters_ptr[process_id_index]->fw_fragment_count){

        if (ota_fragments_request_service_process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
            bool fragment_already_received_flag = ota_check_if_fragment_already_received(process_id_index, fragment_id);

            if (fragment_already_received_flag == false) {
                uint32_t written_byte_count = ota_write_fw_bytes_fptr(ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                (uint32_t)(((uint32_t)fragment_id - 1) * (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count),
                (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count,
                &payload_ptr[payload_index]);

                if (written_byte_count == ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count) {
#if (OTA_VERIFY_FRAGMENT_WRITING_TO_DATA_STORAGE == 1)
                    uint8_t *read_check_ptr = ota_malloc_fptr(written_byte_count);

                    if (read_check_ptr != NULL) {
                        uint32_t read_byte_count = ota_read_fw_bytes_fptr(ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                                (uint32_t)(((uint32_t)fragment_id - 1) * (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count),
                                written_byte_count, read_check_ptr);

                        if (read_byte_count == written_byte_count)
                        {
                            int match = memcmp(&payload_ptr[payload_index], read_check_ptr, written_byte_count);

                            // If all checks passed and fragment writing succeeded
                            if (match == 0)
                            {
#endif
                                uint16_t segment_bitmask_id = (ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length - 1) - ((fragment_id - 1) / 8);
                                uint8_t segment_bitmask_bit_number = (fragment_id - 1) % 8;

                                uint8_t segment_bitmask_bit = (0x01 << segment_bitmask_bit_number);
                                ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr[segment_bitmask_id] |= segment_bitmask_bit;

                                ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);
                                if (rc != OTA_OK) {
                                    tr_err("Storing OTA states failed, RC: %d", rc);
                                }
#if (OTA_VERIFY_FRAGMENT_WRITING_TO_DATA_STORAGE == 1)
                            } else {
                                tr_err("OTA not able to store firmware fragment to given data storage (memcmp() fails)!!! Mem index: %"PRIu32" Match: %u",
                                    (uint32_t)(((uint32_t)fragment_id - 1) * (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count), match);

                                tr_info("Received fragment: %s", trace_array(&payload_ptr[payload_index], written_byte_count));
                                tr_info("Fragment read from sata storage: %s", trace_array(read_check_ptr, written_byte_count));
                            }
                        } else {
                            tr_err("Reading firmware image fragment count check failed!!! (%"PRIu32" > %"PRIu32")", read_byte_count, written_byte_count);
                        }
#endif
                        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

                        tr_info("Missing fragments total count: %u Received fragment total count: %u",
                                missing_fragment_total_count,
                                (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count - missing_fragment_total_count));

                        ota_get_and_log_first_missing_segment(process_id_index, NULL);

                        if (missing_fragment_total_count == 0) {
                            ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_CHECKSUM_CALCULATING;

                            rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);
                            if (rc != OTA_OK){
                                tr_err("Storing OTA states failed, RC: %d", rc);
                            }

                            ota_manage_whole_fw_checksum_calculating();
                        } else {
                            if (ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {

                                if (ota_stored_parameters_ptr[process_id_index]->fallback_timeout != 0) {
                                    ota_start_timer(OTA_FALLBACK_TIMER, OTA_TIME_HOUR2SEC(ota_stored_parameters_ptr[process_id_index]->fallback_timeout), 0);
                                }
                            }
                        }
#if (OTA_VERIFY_FRAGMENT_WRITING_TO_DATA_STORAGE == 1)

                        ota_free_fptr(read_check_ptr);
                    } else {
                        tr_err("Memory allocation failed for FW fragments reading!!! (%"PRIu32")", written_byte_count);
                    }
#endif
                } else {
                    tr_err("Fragment storing to data storage failed. (%"PRIu32" <> %u)",
                    written_byte_count,
                    ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count);
                }
            } else {
                ota_get_and_log_first_missing_segment(process_id_index, NULL);
            }
        } else if (ota_fragments_request_service_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            uint16_t segment_id = (((fragment_id - 1) / OTA_SEGMENT_SIZE) + 1);

            if (segment_id == ota_fragments_request_service_segment_id) {
                uint16_t segment_bitmask_id = (OTA_FRAGMENTS_REQ_BITMASK_LENGTH - 1) - (((fragment_id - 1) % OTA_SEGMENT_SIZE) / 8);
                uint8_t segment_bitmask_bit_number = (fragment_id - 1) % 8;

                uint8_t segment_bitmask_bit = (0x01 << segment_bitmask_bit_number);
                ota_fragments_request_service_bitmask_tbl[segment_bitmask_id] |= segment_bitmask_bit;
            } else {
                tr_warn("In received fragment different segment ID than currently serving (%u <> %u)", segment_id, ota_fragments_request_service_segment_id);
            }

            tr_info("Current requested Fragment bitmasks: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            ota_fragments_request_service_bitmask_tbl[0], ota_fragments_request_service_bitmask_tbl[1], ota_fragments_request_service_bitmask_tbl[2], ota_fragments_request_service_bitmask_tbl[3],
            ota_fragments_request_service_bitmask_tbl[4], ota_fragments_request_service_bitmask_tbl[5], ota_fragments_request_service_bitmask_tbl[6], ota_fragments_request_service_bitmask_tbl[7],
            ota_fragments_request_service_bitmask_tbl[8], ota_fragments_request_service_bitmask_tbl[9], ota_fragments_request_service_bitmask_tbl[10], ota_fragments_request_service_bitmask_tbl[11],
            ota_fragments_request_service_bitmask_tbl[12], ota_fragments_request_service_bitmask_tbl[13], ota_fragments_request_service_bitmask_tbl[14], ota_fragments_request_service_bitmask_tbl[15]);

            uint16_t missing_fragment_count_for_requester = ota_get_next_missing_fragment_id_for_requester(process_id_index, false);
            if (missing_fragment_count_for_requester > 0) {
                ota_start_timer(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER,
                                OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START,
                                OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_RANDOM);
            } else {
                ota_cancel_timer_fptr(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER);
                ota_fragments_request_service_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
            }
        } else {
            tr_info("No need for this fragment!");
        }
    } else {
        tr_err("OTA will not store data to given data storage because fragment cmd validity checks failed (%u %u %u %u)",
        fragment_checksum, calculated_fragment_checksum, fragment_id, ota_stored_parameters_ptr[process_id_index]->fw_fragment_count);
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING)
    {
        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

        if (missing_fragment_total_count > 0)
        {
            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM);
        }
    }
}

static void ota_manage_abort_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);

    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    tr_info("***Received OTA ABORT command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_warn("Process not found from storage");
        return;
    }

    if (payload_length < OTA_ABORT_CMD_LENGTH) {
        tr_err("Received ABORT command data length not correct: %u (%u)", payload_length, OTA_ABORT_CMD_LENGTH);
        return;
    }

    if (process_id_index == ota_fragments_request_service_process_id_index) {
        ota_fragments_request_service_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
    }


    if (ota_server && process_id_index == ota_fw_delivering_process_id_index) {
        ota_fw_delivering_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
        tr_warn("Missing fragments requesting is aborted!!!");
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_CHECKSUM_CALCULATING) {
        tr_warn("Checksum calculating over whole received image is aborted!!!");

        mbedtls_sha256_free(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);

        ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);
        ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr = NULL;

        ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]);
        ota_checksum_calculating_ptr[process_id_index] = NULL;
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_UPDATE_FW){
        tr_warn("Taking new firmware in use is tried to abort!!! Not supported!!!");
    }

    if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end != 0x7FFF) {
        ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                            true, OTA_ABORT_CMD);
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_ABORTED) {
        if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_UPDATE_FW) {
            tr_info("State changed to \"OTA ABORTED\"");

            ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_ABORTED;

            ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);
            if (rc != OTA_OK) {
                tr_err("Storing OTA states failed, RC: %d", rc);
            }
        }
    } else {
        tr_warn("State remains \"OTA ABORTED\"");
    }

    if (ota_server != NULL) {
       ota_process_finished_fptr(process_id);
    }

    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);
}

static void ota_manage_end_fragments_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    tr_info("***Received OTA END FRAGMENTS command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_warn("Process not found from storage");
        return;
    }
    if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_STARTED) {
        if (payload_length < OTA_END_FRAGMENTS_CMD_LENGTH) {
            tr_err("Received END FRAGMENTS command data length not correct: %u (%u)", payload_length, OTA_END_FRAGMENTS_CMD_LENGTH);
            return;
        }

        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

        tr_info("Missing fragments total count: %u Received fragment total count: %u",
                missing_fragment_total_count,
                (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count - missing_fragment_total_count));

        if (missing_fragment_total_count > 0) {
            ota_get_and_log_first_missing_segment(process_id_index, NULL);

            if (ota_stored_parameters_ptr[process_id_index]->multicast_used_flag == true ||
                ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {

                ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_MISSING_FRAGMENTS_REQUESTING;
                ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

                if (rc != OTA_OK) {
                    tr_err("Storing OTA states failed, RC: %d", rc);
                }

                ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                                OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                                OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM);

                tr_info("State changed to \"OTA MISSING FRAGMENTS REQUESTING\"");
            } else {
                tr_warn("Missing fragments requesting not used");
            }
        }
    }
}

static void ota_manage_update_fw_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);

    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    tr_info("***Received OTA UPDATE FW command. Length: %d. OTA process ID: 0x%08"PRIX32, payload_length, process_id);

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_warn("Process not found from storage");
        return;
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_PROCESS_COMPLETED &&
        ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_UPDATE_FW) {
        tr_warn("OTA not in PROCESS COMPLETED or in UPDATE FW state when tried to change to FW UPDATE state. Current state: %d",
                ota_stored_dl_state_ptr[process_id_index]->ota_state);
        return;
    }

    if (payload_length < OTA_UPDATE_FW_CMD_LENGTH)
    {
        tr_err("Received UPDATE FW command data length not correct: %u (%u)", payload_length, OTA_UPDATE_FW_CMD_LENGTH);
        return;
    }

    uint8_t device_type = payload_ptr[payload_index];
    payload_index += 1;

    tr_info("Device type: %d", device_type);

    if (device_type != ota_lib_config_data.device_type)
    {
        tr_warn("State change failed (Device type check failed, msg: %d <> cnf: %d)", device_type, ota_lib_config_data.device_type);
        // the function returns here for border router, so effectively we're done in BR.
        // time to release reservations to update manager
        if (ota_server) {
            ota_process_finished_fptr(process_id);
        }
        return;
    }

    if (ota_fw_update_received == false) {
        ota_update_fw_delay = common_read_16_bit(&payload_ptr[payload_index]);
        payload_index += 2;

        tr_info("Firmware update delay: %u second(s)", ota_update_fw_delay);

        if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end != 0x7FFF) {
            ota_create_notification(process_id_index, process_id, true, OTA_UPDATE_FW_CMD);
        } else {
            ota_send_update_fw_cmd_received_info_fptr(process_id, ota_update_fw_delay);
        }
        ota_fw_update_received = true;
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state != OTA_STATE_UPDATE_FW) {
        ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_UPDATE_FW;

        ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

        if (rc != OTA_OK) {
            tr_err("Storing OTA states failed, RC: %d", rc);
        }

        tr_warn("State changed to \"OTA FW UPDATE\"");
    } else {
        tr_warn("State already \"OTA FW UPDATE\"");
    }


    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);
}

static void ota_manage_fragments_request_command(uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *source_addr)
{
    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint32_t process_id = common_read_32_bit(&payload_ptr[payload_index]);
    payload_index += 4;

    tr_info("***Received OTA FRAGMENTS REQUEST command. Length: %d. From: %s. OTA process ID: 0x%08"PRIX32, payload_length, trace_ipv6(source_addr->address_tbl), process_id);

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX)
    {
        tr_warn("Process not found from storage");
        return;
    }

    if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_PROCESS_COMPLETED ||
        ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_UPDATE_FW) {

        if (payload_length < OTA_FRAGMENTS_REQ_LENGTH) {
            tr_err("Received FRAGMENTS REQUEST command data length not correct: %u (%u)", payload_length, OTA_FRAGMENTS_REQ_LENGTH);
            return;
        }

        if (ota_fragments_request_service_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            tr_warn("Fragment request serving already ongoing!!!");
            return;
        }

        if( ota_server && ota_fw_delivering_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
            tr_warn("Firmware delivering is already ongoing!!!");
            return;
        }

        tr_info("OTA process ID checked successfully");

        memcpy(&ota_fragments_request_source_addr, source_addr, sizeof(*source_addr));

        ota_fragments_request_service_segment_id = common_read_16_bit(&payload_ptr[payload_index]);
        payload_index += 2;

        tr_info("Requested Segment ID: %u", ota_fragments_request_service_segment_id);

        memcpy(ota_fragments_request_service_bitmask_tbl, &payload_ptr[payload_index], OTA_FRAGMENTS_REQ_BITMASK_LENGTH);
        payload_index += OTA_FRAGMENTS_REQ_BITMASK_LENGTH;

        tr_info("Requested Fragment bitmasks: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                ota_fragments_request_service_bitmask_tbl[0], ota_fragments_request_service_bitmask_tbl[1], ota_fragments_request_service_bitmask_tbl[2], ota_fragments_request_service_bitmask_tbl[3],
                ota_fragments_request_service_bitmask_tbl[4], ota_fragments_request_service_bitmask_tbl[5], ota_fragments_request_service_bitmask_tbl[6], ota_fragments_request_service_bitmask_tbl[7],
                ota_fragments_request_service_bitmask_tbl[8], ota_fragments_request_service_bitmask_tbl[9], ota_fragments_request_service_bitmask_tbl[10], ota_fragments_request_service_bitmask_tbl[11],
                ota_fragments_request_service_bitmask_tbl[12], ota_fragments_request_service_bitmask_tbl[13], ota_fragments_request_service_bitmask_tbl[14], ota_fragments_request_service_bitmask_tbl[15]);

        uint16_t missing_fragment_count_for_requester = ota_get_next_missing_fragment_id_for_requester(process_id_index, false);

        if (missing_fragment_count_for_requester > 0) {
            ota_fragments_request_service_process_id_index = process_id_index;

            ota_start_timer(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER,
                            OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START,
                            OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_RANDOM);
        } else {
            tr_info("No missing fragments in request");
        }
    } else {
        if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM);
        }
    }
}

static void ota_create_notification(uint8_t process_id_index, uint32_t process_id, bool response_state, ota_commands_e command_id)
{
    tr_debug("ota_create_notification - process_id: %d", process_id);

    notification_t *temp_ptr = ota_malloc_fptr(sizeof(notification_t));
    if (temp_ptr) {
        temp_ptr->process_id = process_id;
        temp_ptr->response_state = response_state;
        temp_ptr->command_id = command_id;

        ns_list_add_to_end(&ota_notification_list, temp_ptr);

        if (ns_list_count(&ota_notification_list) == 1) {
            if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                uint16_t end = ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end - ota_stored_parameters_ptr[process_id_index]->response_sending_delay_start;
                ota_start_timer(OTA_NOTIFICATION_TIMER, ota_lib_config_data.response_sending_delay_start, end);
            } else {
                ota_start_timer(OTA_NOTIFICATION_TIMER, ota_lib_config_data.response_sending_delay_start, 10);
            }

        }
    }
}

static void ota_manage_delete_command(uint8_t process_id_index)
{
    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_err("ota_manage_delete_command() called with invalid parameter (%u)", process_id_index);
        return;
    }

    if (ota_stored_parameters_ptr[process_id_index]->response_sending_delay_end != 0x7FFF) {
        ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                            true, OTA_DELETE_CMD);
    }

#if 0 //TODO! Pelion does not support resource deletion, this might be needed for multi process support
    if (ota_server) {
        if (ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_length > 0) {
            tr_warn("OTA image resource will be deleted!!!");

            sn_nsdl_dynamic_resource_parameters_s *resource_params = sn_nsdl_get_resource(ota_nsdl_handle_ptr,
                                                                        (char*)(ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr));

            if (resource_params) {
                // remove the resource from lists
                sn_nsdl_pop_resource(ota_nsdl_handle_ptr, resource_params);

                // free the structs, but not the content from their pointers as the data was not copied
                if ((resource_params->static_resource_parameters) && (resource_params->static_resource_parameters->free_on_delete)) {
                    ota_free_fptr(resource_params->static_resource_parameters);
                }
                if (resource_params->free_on_delete) {
                    ota_free_fptr(resource_params);
                }
            }

            tr_err("Deleting resource returned: Resource: %s", ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr);

            if (ota_update_device_registration_fptr != NULL) {
                ota_update_device_registration_fptr();
            }

        }
    }
#endif

    tr_warn("OTA process data and image will be removed from data storage!!!");

    ota_delete_process(ota_stored_processes.ota_process_ids_tbl[process_id_index], true);

    tr_info("OTA process count: %u", ota_stored_processes.ota_process_count);
}

static bool ota_check_if_fragment_already_received(uint8_t process_id_index, uint16_t fragment_id)
{
    uint16_t fragment_bitmask_id = (ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length - 1) - ((fragment_id - 1) / 8);

    uint8_t fragment_bitmask_bit_number = (fragment_id - 1) % 8;

    uint8_t fragment_bitmask_bit = (0x01 << fragment_bitmask_bit_number);

    if ((ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr[fragment_bitmask_id] & fragment_bitmask_bit) != 0)
    {
        return true;
    }
    return false;
}

static uint16_t ota_get_missing_fragment_total_count(uint8_t process_id_index)
{
    uint16_t returned_missing_fragment_total_count = 0;

    uint8_t *fragment_bitmask_temp_ptr =
            &ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr[ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length - 1];

    for (uint16_t fragment_id = 1; fragment_id <= ota_stored_parameters_ptr[process_id_index]->fw_fragment_count; fragment_bitmask_temp_ptr--) {
        uint8_t one_byte_bitmask = *fragment_bitmask_temp_ptr;

        for (uint8_t bit_counter = 0; bit_counter < 8; bit_counter++, fragment_id++) {
            uint8_t bit_id = (1 << bit_counter);

            if ((one_byte_bitmask & bit_id) == 0) {
                returned_missing_fragment_total_count++;
            }
        }
    }

    return returned_missing_fragment_total_count;
}

static uint16_t ota_get_and_log_first_missing_segment(uint8_t process_id_index, uint8_t *missing_fragment_bitmasks_ptr)
{
    uint8_t *segment_bitmask_temp_ptr =
            &ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr[ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length - 1];

    if (missing_fragment_bitmasks_ptr != NULL) {
        memset(missing_fragment_bitmasks_ptr, 0, OTA_FRAGMENTS_REQ_BITMASK_LENGTH);
    }

    uint16_t fragment_id = 1;

    for (uint16_t segment_id = 1; segment_id <= ota_stored_parameters_ptr[process_id_index]->fw_segment_count; segment_id++) {
        if (missing_fragment_bitmasks_ptr != NULL) {
            memcpy(missing_fragment_bitmasks_ptr,
                   &ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr[(ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length) - (segment_id * OTA_FRAGMENTS_REQ_BITMASK_LENGTH)],
                    OTA_FRAGMENTS_REQ_BITMASK_LENGTH);
        }

        for (uint8_t j = 0; j < OTA_FRAGMENTS_REQ_BITMASK_LENGTH; j++, segment_bitmask_temp_ptr--) {
            uint8_t one_byte_bitmask = *segment_bitmask_temp_ptr;

            for (uint8_t bit_counter = 0; bit_counter < 8; bit_counter++, fragment_id++) {
                uint8_t bit_id = (1 << bit_counter);

                if ((one_byte_bitmask & bit_id) == 0) {
                    tr_info("OTA process ID: 0x%08"PRIX32" First missing segment ID: %u Fragment ID: %u",
                            ota_stored_processes.ota_process_ids_tbl[process_id_index], segment_id, fragment_id);

                    return segment_id;
                }
            }
        }
    }
    return 0;
}

static void ota_request_missing_fragments(uint8_t process_id_index, bool fallback_flag)
{
    tr_info("Missing fragments will be requested for OTA process ID: 0x%08"PRIX32, ota_stored_processes.ota_process_ids_tbl[process_id_index]);

    uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

    tr_info("Missing fragments total count: %u Received fragment total count: %u",
            missing_fragment_total_count,
            (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count - missing_fragment_total_count));

    uint8_t missing_fragment_bitmasks_tbl[OTA_FRAGMENTS_REQ_BITMASK_LENGTH];

    uint16_t first_missing_segment_id = ota_get_and_log_first_missing_segment(process_id_index, missing_fragment_bitmasks_tbl);

    uint16_t payload_length = (OTA_FRAGMENTS_REQ_LENGTH - 5);

    uint8_t *payload_ptr = ota_malloc_fptr(payload_length);


    if (payload_ptr == NULL) {
        tr_err("Memory allocation failed for fragments request!!! (%u)", payload_length);
        return;
    }

    memset(payload_ptr, 0, payload_length);

    uint16_t payload_index = 0;

    common_write_16_bit(first_missing_segment_id, &payload_ptr[payload_index]);
    payload_index += 2;

    memcpy(&payload_ptr[payload_index], missing_fragment_bitmasks_tbl, OTA_FRAGMENTS_REQ_BITMASK_LENGTH);
    payload_index += OTA_FRAGMENTS_REQ_BITMASK_LENGTH;

    if (ota_stored_parameters_ptr[process_id_index]->multicast_used_flag == false || fallback_flag == true) {
        if (ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID) {
            ota_build_and_send_command(OTA_FRAGMENTS_REQUEST_CMD,
                                       ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                                       payload_length, payload_ptr,
                                       &ota_stored_parameters_ptr[process_id_index]->missing_fragments_req_addr);
        } else {
            tr_warn("Unicast fragments request not sent because not valid request IP address given");
        }
    } else {
        ota_build_and_send_command(OTA_FRAGMENTS_REQUEST_CMD, ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                                   payload_length, payload_ptr, &ota_lib_config_data.link_local_multicast_socket_addr);
    }
    ota_free_fptr(payload_ptr);

    ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                    OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                    OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_RANDOM);
}

static void ota_deliver_one_fragment(uint8_t process_id_index)
{
    uint8_t *built_payload_ptr = ota_malloc_fptr(ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count + 4);
    if (built_payload_ptr == NULL) {
        tr_err("Memory allocation failed for delivered fragment command!!! (%u)", ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count + 4);
        return;
    }

    ota_error_code_e rc = ota_build_one_fw_fragment(process_id_index, ota_fw_deliver_current_fragment_id, built_payload_ptr);
    ota_fw_deliver_current_fragment_id++;

    if (rc == OTA_OK) {
        ota_build_and_send_command(OTA_FRAGMENT_CMD,
                                   ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                                   ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count + 4,
                                   built_payload_ptr, &ota_lib_config_data.mpl_multicast_socket_addr);
    } else {
        tr_err("Fragmend not sent because command building failed!!! rc: %d", rc);
    }

    ota_free_fptr(built_payload_ptr);
}

static void ota_serve_fragments_request_by_sending_one_fragment(uint8_t process_id_index)
{
    uint16_t fragment_id = ota_get_next_missing_fragment_id_for_requester(process_id_index, true);

    if (fragment_id <= 0) {
        tr_err("ota_serve_fragments_request_by_sending_one_fragment() has no fragments to be sent (%u)", fragment_id);
        return;
    }

    uint8_t *built_payload_ptr = ota_malloc_fptr(ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count + 4); // + 4 = Firmware fragment number and checksum

    if (!built_payload_ptr) {
        tr_err("Memory allocation failed for served fragment request!!! (%u)", ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count + 4);
        return;
    }

    ota_error_code_e rc = ota_build_one_fw_fragment(process_id_index, fragment_id, built_payload_ptr);

    if (rc == OTA_OK) {
        ota_ip_address_t* addr = &ota_fragments_request_source_addr;

        //TODO: verify that this works as the commented out code
        if (ota_lib_config_data.unicast_socket_addr.port == ota_lib_config_data.link_local_multicast_socket_addr.port ) {
            if ( (ota_stored_parameters_ptr[process_id_index]->multicast_used_flag == true &&
                  ota_fragments_request_source_addr.port == ota_lib_config_data.link_local_multicast_socket_addr.port)) {
                addr = &(ota_lib_config_data.link_local_multicast_socket_addr);
            }
        } else {
            if (ota_fragments_request_source_addr.port != ota_lib_config_data.unicast_socket_addr.port &&
                ota_fragments_request_source_addr.port == ota_lib_config_data.link_local_multicast_socket_addr.port) {
                addr = &(ota_lib_config_data.link_local_multicast_socket_addr);
            }
        }
        //TODO: Pass-by-value must be changed to pass-as-ref!
        ota_build_and_send_command(OTA_FRAGMENT_CMD,
                                   ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                                   ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count + 4,
                                   built_payload_ptr, addr);
    } else {
        tr_err("Fragmend not sent because command building failed!!! rc: %d", rc);
    }

    ota_free_fptr(built_payload_ptr);
}

static ota_error_code_e ota_build_one_fw_fragment(uint8_t process_id_index, uint16_t fragment_id, uint8_t *built_payload_ptr)
{
    tr_info("Device will build fragment %u", fragment_id);

    uint16_t payload_index = 0;

    common_write_16_bit(fragment_id, &built_payload_ptr[payload_index]);
    payload_index += 2;

    uint32_t read_byte_count = ota_read_fw_bytes_fptr(ota_stored_parameters_ptr[process_id_index]->ota_process_id,
                                                      (uint32_t)(((uint32_t)fragment_id - 1) * (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count),
                                                      (uint32_t)ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count,
                                                      &built_payload_ptr[payload_index]);

    if (read_byte_count != ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count) {
        tr_err("Building FRAGMENT command failure! Read data byte count mismatch: %"PRIu32" <> %u", read_byte_count, ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count);
        return OTA_STORAGE_ERROR;
    }

    payload_index += read_byte_count;

    uint16_t calculated_fragment_checksum = ota_calculate_checksum_over_one_fragment(&built_payload_ptr[2], // 2: Firmware fragment number takes 2 bytes
            ota_stored_parameters_ptr[process_id_index]->fw_fragment_byte_count);

    common_write_16_bit(calculated_fragment_checksum, &built_payload_ptr[payload_index]);

    return OTA_OK;
}

static void ota_build_and_send_command(uint8_t command_id, uint32_t process_id, uint16_t payload_length,
                                       uint8_t *payload_ptr, ota_ip_address_t *dest_address)
{
    uint16_t command_length = 5 + payload_length;
    uint8_t *command_ptr = ota_malloc_fptr(command_length);

    if (command_ptr == NULL) {
        tr_err("Memory allocation failed for command!!! (%u)", command_length);
        return;
    }
    memset(command_ptr, 0, command_length);

    uint16_t data_index = 0;
    command_ptr[data_index] = command_id;
    data_index += 1;

    common_write_32_bit(process_id, &command_ptr[data_index]);
    data_index += 4;

    memcpy(&command_ptr[data_index], payload_ptr, payload_length);

    if (memcmp(dest_address->address_tbl, ota_lib_config_data.link_local_multicast_socket_addr.address_tbl, 16) == 0) {
        tr_info("Device will send command %d to Link local multicast address: %s Port: %u", command_id, trace_ipv6(dest_address->address_tbl), dest_address->port);
    } else if (memcmp(dest_address->address_tbl, ota_lib_config_data.mpl_multicast_socket_addr.address_tbl, 16) == 0) {
        tr_info("Device will send command %d to MPL multicast address: %s Port: %u", command_id, trace_ipv6(dest_address->address_tbl), dest_address->port);
    } else {
        tr_info("Device will send command %d to address: %s Port: %u", command_id, trace_ipv6(dest_address->address_tbl), dest_address->port);
    }

    if (ota_socket_send_fptr(dest_address, command_length, command_ptr) != 0) {
        tr_err("Sending command to socket failed");
    }

    ota_free_fptr(command_ptr);
}

static uint16_t ota_get_next_missing_fragment_id_for_requester(uint8_t process_id_index, bool bit_mask_change)
{
    uint16_t fragment_id = 1 + ((ota_fragments_request_service_segment_id - 1) * OTA_SEGMENT_SIZE);

    if (fragment_id > ota_stored_parameters_ptr[process_id_index]->fw_fragment_count) {
        tr_err("Fragment ID in request bigger than total fragment count!");
        return 0;
    }

    for (int8_t i = (OTA_FRAGMENTS_REQ_BITMASK_LENGTH - 1); i >= 0; i--) {
        for (uint8_t bit_counter = 0; bit_counter < 8; bit_counter++, fragment_id++) {
            if (fragment_id > ota_stored_parameters_ptr[process_id_index]->fw_fragment_count) {
                ota_fragments_request_service_bitmask_tbl[i] = 0xFF;
                break;
            }

            uint8_t bit_id = (1 << bit_counter);

            if ((ota_fragments_request_service_bitmask_tbl[i] & bit_id) == 0) {
                if (bit_mask_change == true) {
                    ota_fragments_request_service_bitmask_tbl[i] += bit_id;
                }
                return fragment_id;
            }
        }
    }

    return 0;
}

static uint16_t ota_calculate_checksum_over_one_fragment(uint8_t *data_ptr, uint16_t data_length)
{
    uint16_t returned_crc = 0;
    uint16_t i = 0;
    long q = 0;
    uint8_t c = 0;

    for (i = 0; i < data_length; i++) {
        c = data_ptr[i];
        q = (returned_crc ^ c) & 0x0f;

        returned_crc = (returned_crc >> 4) ^ (q * 0x1081);
        q = (returned_crc ^ (c >> 4)) & 0xf;

        returned_crc = (returned_crc >> 4) ^ (q * 0x1081);
    }

    return returned_crc;
}

static void ota_manage_whole_fw_checksum_calculating(void)
{
    bool new_round_needed = false;

    //TODO: Loop the index only. When first 'OTA_STATE_CHECKSUM_CALCULATING' is met -> loop breaks anyway!
    for (uint8_t process_id_index = 0; process_id_index < ota_stored_processes.ota_process_count; process_id_index++) {
        if (ota_stored_dl_state_ptr[process_id_index]->ota_state == OTA_STATE_CHECKSUM_CALCULATING) {
            if (ota_checksum_calculating_ptr[process_id_index] == NULL) {
                tr_info("Whole FW checksum calculating started!!!");
                new_round_needed = true;

                ota_checksum_calculating_ptr[process_id_index] = ota_malloc_fptr(sizeof(ota_checksum_calculating_t));

                if (ota_checksum_calculating_ptr[process_id_index] != NULL) {
                    memset(ota_checksum_calculating_ptr[process_id_index], 0, sizeof(ota_checksum_calculating_t));

                    ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr = ota_malloc_fptr(sizeof(mbedtls_sha256_context));

                    if (ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr != NULL) {
                        memset(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr, 0, sizeof(mbedtls_sha256_context));

                        mbedtls_sha256_init(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);
                        mbedtls_sha256_starts(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr, 0);
                    } else {
                        tr_err("Memory allocation failed for ota_sha256_context_ptr[%u]!!! (%zu)", process_id_index, sizeof(mbedtls_sha256_context));

                        ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]);
                        ota_checksum_calculating_ptr[process_id_index] = NULL;
                    }
                } else {
                    tr_err("Memory allocation failed for ota_checksum_calculating_ptr[%u]!!! (%zu)", process_id_index, sizeof(ota_checksum_calculating_t));
                }
            } else {
                uint32_t fw_total_data_byte_count = ota_stored_parameters_ptr[process_id_index]->fw_total_byte_count;
                uint32_t pushed_fw_data_byte_count = OTA_CHECKSUM_CALCULATING_BYTE_COUNT;

                if ((ota_checksum_calculating_ptr[process_id_index]->current_byte_id + pushed_fw_data_byte_count) > fw_total_data_byte_count) {
                    pushed_fw_data_byte_count = (fw_total_data_byte_count - ota_checksum_calculating_ptr[process_id_index]->current_byte_id);
                }
                tr_info("Calculating whole FW checksum!!! OTA process ID: 0x%08"PRIX32" Pushed byte count: %"PRIu32" Byte ID: %"PRIu32" ",
                        ota_stored_processes.ota_process_ids_tbl[process_id_index],
                        pushed_fw_data_byte_count,
                        ota_checksum_calculating_ptr[process_id_index]->current_byte_id);

                uint8_t *pushed_fw_data_byte_ptr = ota_malloc_fptr(pushed_fw_data_byte_count);

                if (pushed_fw_data_byte_ptr != NULL) {
                    uint32_t read_byte_count = ota_read_fw_bytes_fptr(ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                                                      ota_checksum_calculating_ptr[process_id_index]->current_byte_id,
                                                                      pushed_fw_data_byte_count,
                                                                      pushed_fw_data_byte_ptr);

                    ota_checksum_calculating_ptr[process_id_index]->current_byte_id += read_byte_count;

                    if (read_byte_count != pushed_fw_data_byte_count) {
                        tr_err("Reading from data storage failed (%"PRIu32" <> %"PRIu32")", read_byte_count, pushed_fw_data_byte_count);
                    } else {
                        mbedtls_sha256_update(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr, pushed_fw_data_byte_ptr, read_byte_count);
                    }

                    if (ota_checksum_calculating_ptr[process_id_index]->current_byte_id == fw_total_data_byte_count ||
                        read_byte_count != pushed_fw_data_byte_count) {
                        uint8_t sha256_result[OTA_WHOLE_FW_CHECKSUM_LENGTH];

                        memset(sha256_result, 0, OTA_WHOLE_FW_CHECKSUM_LENGTH);

                        mbedtls_sha256_finish(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr, sha256_result);

                        mbedtls_sha256_free(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);

                        ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);
                        ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr = NULL;

                        ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]);
                        ota_checksum_calculating_ptr[process_id_index] = NULL;

                        int match = memcmp(sha256_result,
                                           ota_stored_parameters_ptr[process_id_index]->whole_fw_checksum_tbl,
                                           OTA_WHOLE_FW_CHECKSUM_LENGTH);

                        if (match == 0) {
                            tr_info("Whole firmware image checksum ok!");

                            ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_PROCESS_COMPLETED;

                            ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

                            if (rc != OTA_OK) {
                                tr_err("Storing OTA states failed, RC: %d", rc);
                            }

                            tr_info("State changed to \"OTA PROCESS COMPLETED\"");

                            ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                                true, OTA_PROCESS_COMPLETED_RESPONSE);
                        } else {
                            tr_err("All fragments received, but whole FW checksum calculating failed! Match = %u", match);
                            tr_err("Given whole FW checksum: %s", trace_array(ota_stored_parameters_ptr[process_id_index]->whole_fw_checksum_tbl,
                                                                              OTA_WHOLE_FW_CHECKSUM_LENGTH));
                            tr_err("Calculated from memory whole FW checksum: %s", trace_array(sha256_result, OTA_WHOLE_FW_CHECKSUM_LENGTH));

                            ota_stored_dl_state_ptr[process_id_index]->ota_state = OTA_STATE_CHECKSUM_FAILED;

                            tr_info("State changed to \"OTA CHECKSUM FAILED\"");

                            ota_error_code_e rc = ota_store_state_fptr(ota_stored_dl_state_ptr[process_id_index]);

                            if (rc != OTA_OK) {
                                tr_err("Storing OTA states failed, RC: %d", rc);
                            }

                            ota_create_notification(process_id_index, ota_stored_processes.ota_process_ids_tbl[process_id_index],
                                                true, OTA_CHECKSUM_FAILED_RESPONSE);
                        }
                    } else {
                        new_round_needed = true;
                    }

                    ota_free_fptr(pushed_fw_data_byte_ptr);
                } else {
                    tr_err("Memory allocation failed for pushed_fw_data_byte_ptr!!! (%"PRIu32")", pushed_fw_data_byte_count);
                    new_round_needed = true;
                }
            }
            break;
        }
    }

    if (new_round_needed) {
        ota_cancel_timer_fptr(OTA_CHECKSUM_CALCULATING_TIMER);
        ota_request_timer_fptr(OTA_CHECKSUM_CALCULATING_TIMER, OTA_CHECKSUM_CALCULATING_INTERVAL);
    }
}

static void ota_start_timer(ota_timers_e timer_id, uint32_t start_time, uint32_t random_window)
{
    ota_cancel_timer_fptr(timer_id);
    start_time *= 1000;
    if (random_window) {
        //Random is taken as 100ms slots
        start_time += 100*(randLIB_get_32bit()%(random_window *10));
    }
    ota_request_timer_fptr(timer_id, start_time);
}

#if 0 // Enable when multiple process support is needed
static uint8_t ota_resources_image_download_data(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    char temp_buf[40];
    memset(temp_buf, 0, coap_ptr->uri_path_len + 1);
    memcpy(temp_buf, coap_ptr->uri_path_ptr, coap_ptr->uri_path_len);
    tr_info("Device received access to %s resource", temp_buf);

    sn_coap_hdr_s *resp_ptr = NULL;

    switch (coap_ptr->msg_code) {
        case COAP_MSG_CODE_REQUEST_GET: {
            char *dl_status_ptr = ota_malloc_fptr(OTA_NOTIF_MAX_LENGTH);

            if (dl_status_ptr != NULL) {
                uint32_t process_id_index = ota_server->get_process_id_index_from_uri_path(coap_ptr->uri_path_len, coap_ptr->uri_path_ptr);

                if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                    ota_resources_build_dl_status_notif(process_id_index, dl_status_ptr);
                } else {
                    sprintf(dl_status_ptr, "OTA process for uri_path not found");
                }

                tr_info("Response to be sent: %s", dl_status_ptr);

                ota_send_coap_text_response(handle_ptr, coap_ptr, address_ptr, dl_status_ptr);
                ota_free_fptr(dl_status_ptr);
            } else {
                tr_err("Memory allocation failed for dl_status_ptr!!! (%u)", OTA_NOTIF_MAX_LENGTH);
            }
            break;
        }
        case COAP_MSG_CODE_REQUEST_PUT: {
            resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, COAP_MSG_CODE_RESPONSE_VALID);

            if (resp_ptr != NULL){
                if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
                    tr_err("Sending confirmation for PUT failed!");
                }
            } else {
                tr_err("Building CoAP confirmation for PUT failed!");
            }

            ota_manage_fragment_command(coap_ptr->payload_len, coap_ptr->payload_ptr);
            break;
        }
        case COAP_MSG_CODE_REQUEST_DELETE: {
            resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, COAP_MSG_CODE_RESPONSE_VALID);

            if (resp_ptr != NULL) {
                if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
                    tr_err("Sending confirmation for DELETE failed!");
                }
            } else {
                tr_err("Building CoAP confirmation for DELETE failed!");
            }

            uint32_t process_id_index = ota_server->get_process_id_index_from_uri_path(coap_ptr->uri_path_len, coap_ptr->uri_path_ptr);

            if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                tr_info("***Received OTA DELETE command. OTA process ID: 0x%08"PRIX32" uri_path: %s",
                        ota_stored_parameters_ptr[process_id_index]->ota_process_id, temp_buf);

                ota_manage_delete_command(process_id_index);

                if (ota_update_device_registration_fptr != NULL) {
                    ota_update_device_registration_fptr();
                }
            } else {
                tr_err("Received DELETE request but OTA process for uri_path not found!!! %s", temp_buf);
            }
            break;
        }
        default: {
            tr_warn("Response to be sent: Method not allowed");
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
    }

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}
#endif

uint8_t ota_lwm2m_command(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;
    tr_info("Device received access to COMMAND resource");
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    sn_coap_hdr_s *resp_ptr = NULL;
    char temp_data_tbl[] = "GET not recommended";

    switch (coap_ptr->msg_code) {
        case COAP_MSG_CODE_REQUEST_PUT: {
            resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, COAP_MSG_CODE_RESPONSE_VALID);

            if (resp_ptr != NULL) {
                if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
                    tr_err("Sending confirmation for PUT failed!");
                }
            } else {
                tr_err("Building CoAP confirmation for PUT failed!");
            }

            if (coap_ptr->payload_len > 0) {

                size_t buf_len = 0;
                int base64_ret = mbedtls_base64_decode(0, 0, &buf_len, coap_ptr->payload_ptr, coap_ptr->payload_len);
                tr_info("mbedtls_base64_decode check length returned %d", base64_ret);
                uint8_t* payload = (uint8_t*)ota_malloc_fptr(buf_len);
                base64_ret = mbedtls_base64_decode(payload, buf_len, &buf_len, coap_ptr->payload_ptr, coap_ptr->payload_len);
                tr_info("mbedtls_base64_decode do decode returned %d", base64_ret);

                uint8_t command_id = payload[0];

                switch (command_id) {
                    case OTA_START_CMD: {
                        ota_manage_start_command(buf_len, payload);
                        if (ota_server) {
                            ota_server->handle_command_forwarding(NULL, buf_len, payload, true);
                        }
                        break;
                    }

                    case OTA_DELIVER_FW_CMD: {
                        if (ota_server) {
                            ota_server->manage_deliver_fw_command(buf_len, payload);
                        } else {
                            tr_err("Unsupported DELIVER FW command to node's command resource");
                        }
                        break;
                    }
                    case OTA_FRAGMENT_CMD: {
                        ota_manage_fragment_command(buf_len, payload);
                        break;
                    }
                    case OTA_ABORT_CMD: {
                        if (ota_server) {
                            ota_server->handle_command_forwarding(NULL, buf_len, payload, true);
                        }
                        ota_manage_abort_command(buf_len, payload);
                        break;
                    }
                    case OTA_END_FRAGMENTS_CMD: {
                        if (ota_server) {
                            ota_server->handle_command_forwarding(NULL, buf_len, payload, false);
                        }
                        ota_manage_end_fragments_command(buf_len, payload);
                        break;
                    }
                    case OTA_UPDATE_FW_CMD: {
                        if (ota_server) {
                            ota_server->handle_command_forwarding(NULL, buf_len, payload, true);
                        }
                        ota_manage_update_fw_command(buf_len, payload);
                        break;
                    }

                    case OTA_FRAGMENTS_REQUEST_CMD: {
                        ota_ip_address_t temp_addr;
                        temp_addr.type = OTA_ADDRESS_IPV6;

                        if (address_ptr->type == SN_NSDL_ADDRESS_TYPE_IPV4) {
                            temp_addr.type = OTA_ADDRESS_IPV4;
                        }
                        memcpy(temp_addr.address_tbl, address_ptr->addr_ptr, address_ptr->addr_len);
                        temp_addr.port = address_ptr->port;

                        ota_manage_fragments_request_command(buf_len, payload, &temp_addr);
                        break;
                    }

                    case OTA_DELETE_CMD: {
                        if (ota_server) {
                            ota_server->handle_command_forwarding(NULL, buf_len, payload, true);
                        }

                        if (buf_len >= OTA_DELETE_CMD_LENGTH) {
                            uint32_t process_id = common_read_32_bit(&payload[OTA_CMD_PROCESS_ID_INDEX]);
                            uint8_t process_id_index = ota_get_process_id_index(process_id);

                            tr_info("***Received OTA DELETE command. Length: %d. OTA process ID: 0x%08"PRId32, buf_len, process_id);

                            if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                                ota_manage_delete_command(process_id_index);
                            } else {
                                tr_err("OTA process ID 0x%08"PRIX32" not exists in stored OTA processes!!!", process_id);
                            }
                        } else {
                            tr_err("Received DELETE command data length not correct: %u (%u)", buf_len, OTA_DELETE_CMD_LENGTH);
                        }

                        break;
                    }

                    default: {
                        tr_err("Unsupported command %d to command resource", command_id);
                        break;
                    }

                }
                ota_free_fptr(payload);
            }

            break;
        }

        case COAP_MSG_CODE_REQUEST_GET: {
            tr_warn("Response to be sent: %s", temp_data_tbl);
            ota_send_coap_text_response(handle_ptr, coap_ptr, address_ptr, temp_data_tbl);
            break;
        }

        default: {
            tr_warn("Response to be sent: Method not allowed");
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
    }

    if (coap_ptr->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED) {
#if SN_COAP_REDUCE_BLOCKWISE_HEAP_FOOTPRINT
        // Free the block message from the CoAP list, data copied into a resource
        sn_nsdl_remove_coap_block(handle_ptr, address_ptr, coap_ptr->payload_len, coap_ptr->payload_ptr);
#else
       handle_ptr->sn_nsdl_free(coap_ptr->payload_ptr);
#endif
    }

    sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, coap_ptr);

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}

uint8_t ota_lwm2m_command_status(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;

    tr_info("Device received access to COMMAND STATUS resource");
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    sn_coap_hdr_s *resp_ptr = NULL;
    ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}

uint8_t ota_lwm2m_dl_status(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;

    tr_info("Device received access to DL STATUS NOTIFICATION resource");
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    sn_coap_hdr_s *resp_ptr = NULL;

    switch (coap_ptr->msg_code) {
        case COAP_MSG_CODE_REQUEST_GET: {
            char *dl_status_ptr = ota_malloc_fptr(OTA_NOTIF_MAX_LENGTH);

            if (dl_status_ptr != NULL) {
                if (ota_own_device_type_process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                    ota_resources_build_dl_status_notif(ota_own_device_type_process_id_index, dl_status_ptr);
                } else {
                    sprintf(dl_status_ptr, "No active OTA Process for own device type");
                }

                tr_info("Response to be sent: %s", dl_status_ptr);
                ota_send_coap_text_response(handle_ptr, coap_ptr, address_ptr, dl_status_ptr);
                ota_free_fptr(dl_status_ptr);
            } else {
                tr_err("Memory allocation failed for dl_status_ptr!!! (%u)", OTA_NOTIF_MAX_LENGTH);
            }
            break;
        }
        default: {
            tr_warn("Response to be sent: Method not allowed");
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
    }

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}

uint8_t ota_lwm2m_connected_nodes(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;

    tr_info("Device received access to connected nodes resource");
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    sn_coap_hdr_s *resp_ptr = NULL;

    switch (coap_ptr->msg_code) {
        case COAP_MSG_CODE_REQUEST_GET: {
            // TODO! Where to read the information?
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
        default: {
            tr_warn("Response to be sent: Method not allowed");
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
    }

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}

uint8_t ota_lwm2m_ready_for_multicast(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;

    tr_info("Device received access to ready for multicast resource");
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    sn_coap_hdr_s *resp_ptr = NULL;

    switch (coap_ptr->msg_code) {
        case COAP_MSG_CODE_REQUEST_GET: {
            // TODO! Not needed yet
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
        default: {
            tr_warn("Response to be sent: Method not allowed");
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
    }

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}

uint8_t ota_lwm2m_expiration_time(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;

    tr_info("Device received access to expiration time resource");
    tr_info("Source address: %s Port %u", trace_ipv6(address_ptr->addr_ptr), address_ptr->port);

    sn_coap_hdr_s *resp_ptr = NULL;

    switch (coap_ptr->msg_code) {
        case COAP_MSG_CODE_REQUEST_GET: {
            // TODO! Not needed yet
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
        default: {
            tr_warn("Response to be sent: Method not allowed");
            ota_send_coap_unhandled_response(handle_ptr, coap_ptr, address_ptr);
            break;
        }
    }

    if (resp_ptr) {
        sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
    }

    return 0;
}

static char* get_notif_string(ota_commands_e command_id)
{
    switch (command_id) {
        case OTA_START_CMD:
            return OTA_START_RESPONSE;
        case OTA_DELIVER_FW_CMD:
            return OTA_DELIVER_FW_RESPONSE;
        case OTA_UPDATE_FW_CMD:
            return OTA_UPDATE_FW_RESPONSE;
        case OTA_ABORT_CMD:
            return OTA_ABORT_RESPONSE;
        case OTA_DELETE_CMD:
            return OTA_DELETE_RESPONSE;
        case OTA_PROCESS_COMPLETED_RESPONSE:
            return OTA_PROCESS_COMPLETED_NOTIF;
        case OTA_CHECKSUM_FAILED_RESPONSE:
            return OTA_CHECKSUM_FAILED_NOTIF;
        default: {
            return NULL;
        }
    }
}

static void ota_resources_send_notif(notification_t *notif)
{
    uint8_t data_to_be_sent_length = 0;
    uint8_t *data_to_be_sent_ptr = NULL;

    char *notif_ptr = get_notif_string(notif->command_id);
    if (!notif_ptr) {
        tr_err("ota_resources_send_notif called with invalid params");
        return;
    }

    uint8_t process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
    if (ota_server) {
        if (notif->command_id == OTA_START_CMD && notif->response_state == true) {
            process_id_index = ota_get_process_id_index(notif->process_id);

            if (process_id_index != OTA_INVALID_PROCESS_ID_INDEX) {
                data_to_be_sent_length = strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH + 1 + ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_length;
            }
        } else {
            data_to_be_sent_length = strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH + 1;
        }
    } else {
        data_to_be_sent_length = strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH + 1;
    }

    if (data_to_be_sent_length > 0) {
        uint8_t response_status_length = 5;

        if (notif->command_id == OTA_START_CMD) {
            if (notif->response_state == true) {
                response_status_length = 4;
            }
            data_to_be_sent_length += response_status_length;
        }
        data_to_be_sent_ptr = ota_malloc_fptr(data_to_be_sent_length);

        if (data_to_be_sent_ptr != NULL) {
            memset(data_to_be_sent_ptr, 0, data_to_be_sent_length);
            memcpy(data_to_be_sent_ptr, notif_ptr, strlen(notif_ptr));

            char ota_process_id_tbl[OTA_PROCESS_ID_LENGTH + 1];
            sprintf(ota_process_id_tbl, "%08"PRIu32, notif->process_id);
            memcpy(&data_to_be_sent_ptr[strlen(notif_ptr)], ota_process_id_tbl, OTA_PROCESS_ID_LENGTH);

            if (notif->command_id == OTA_START_CMD) {
                if (notif->response_state == true) {
                    strcpy((char*)&data_to_be_sent_ptr[strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH], " ACK");
                } else {
                    strcpy((char*)&data_to_be_sent_ptr[strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH], " NACK");
                }
            }

            if (ota_server && notif->command_id == OTA_START_CMD && notif->response_state == true &&
                ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_length > 0) {
                data_to_be_sent_ptr[strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH + response_status_length] = ' ';

                memcpy(&data_to_be_sent_ptr[strlen(notif_ptr) + OTA_PROCESS_ID_LENGTH + response_status_length + 1],
                        ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr,
                        ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_length - 1);
            }

            tr_info("Device will send notification: %s", data_to_be_sent_ptr);
            obs_number++;
            uint16_t msg_id = ota_coap_send_notif_fptr(ota_resource_command_status,
                                                       (uint8_t *)data_to_be_sent_ptr, data_to_be_sent_length - 1);

            int match_process_completed = strncmp(OTA_PROCESS_COMPLETED_NOTIF, notif_ptr, sizeof(OTA_PROCESS_COMPLETED_NOTIF) - 1);

            if (msg_id == 0) {
                tr_err("Sending Command notification failed!");
            } else if (match_process_completed == 0 && ota_lib_config_data.response_msg_type == COAP_MSG_TYPE_CONFIRMABLE) {
                tr_info("Sent confirmable PROCESS COMPLETED notification, CoAP Message ID: %d", msg_id);
            }

            ota_free_fptr(data_to_be_sent_ptr);
        } else {
            tr_err("Memory allocation failed for data_to_be_sent_ptr!!! (%u)", data_to_be_sent_length);
        }
    } else {
        tr_err("ota_resources_send_notif() OTA process ID index not found for OTA process ID = %"PRIu32, notif->process_id);
    }
}

static void ota_resources_send_dl_status_notif(uint8_t process_id_index)
{
    char *dl_status_ptr = ota_malloc_fptr(OTA_NOTIF_MAX_LENGTH);

    if (dl_status_ptr != NULL) {
        ota_resources_build_dl_status_notif(process_id_index, dl_status_ptr);

        tr_info("Device will send DL STATUS notification: %s ", dl_status_ptr);
        obs_number++;
        uint16_t msg_id = ota_coap_send_notif_fptr(ota_resource_dl_status,
                                                   (uint8_t *)dl_status_ptr, strlen(dl_status_ptr));

        if (msg_id == 0) {
            tr_err("Sending DL status observation notification failed!");
        }

        ota_free_fptr(dl_status_ptr);
    } else {
        tr_err("Memory allocation failed for dl_status_ptr!!! (%u)", OTA_NOTIF_MAX_LENGTH);
    }

    uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

    if (missing_fragment_total_count > 0) {
        ota_start_timer(OTA_REPORT_OWN_DL_STATUS_TIMER, ota_stored_parameters_ptr[process_id_index]->fw_download_report_config, 30);
    }

}

static void ota_init_fragments_bit_mask(uint8_t process_id_index, uint8_t init_value)
{
    if (ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr != NULL) {
        memset(ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr, 0xFF, ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length);

        uint8_t *fragment_bitmask_temp_ptr =
                &ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr[ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_length - 1];

        for (uint16_t fragment_counter_temp = 0;
             fragment_counter_temp < ota_stored_parameters_ptr[process_id_index]->fw_fragment_count;
             fragment_bitmask_temp_ptr--) {

            for (uint8_t j = 0; j < 8; j++) {
                if (init_value == 0)                {
                    *fragment_bitmask_temp_ptr &= ~(1 << j);
                } else {
                    *fragment_bitmask_temp_ptr |= (1 << j);
                }

                fragment_counter_temp++;

                if (fragment_counter_temp >= ota_stored_parameters_ptr[process_id_index]->fw_fragment_count) {
                    break;
                }
            }
        }
    }
}

#if 0 // Enable when multiple process support is needed
static ota_error_code_e ota_create_dynamic_resource(const char *path_ptr,
                                                    const char *type_ptr,
                                                    int32_t flags,
                                                    bool is_observable,
                                                    ota_coap_callback_t *callback_ptr,
                                                    bool publish_uri)
{
    tr_info("ota_create_dynamic_resource: %s", path_ptr);
    return ota_create_resource_fptr(path_ptr, type_ptr, flags, is_observable, callback_ptr, publish_uri);
}
#endif

static void ota_send_coap_text_response(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, const char *payload_ptr)
{
    sn_coap_hdr_s *resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, COAP_MSG_CODE_RESPONSE_CONTENT);

    if (resp_ptr == NULL) {
        tr_err("Building CoAP text response failed!");
        return;
    }
    resp_ptr->payload_ptr = (uint8_t *)payload_ptr;
    resp_ptr->payload_len = strlen(payload_ptr);

    if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
        tr_err("Sending CoAP text response failed!");
    }

    sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
}

static void ota_send_coap_unhandled_response(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr)
{
    sn_coap_hdr_s *resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);

    if (resp_ptr == NULL) {
        tr_err("Building CoAP unhandled response failed!");
        return;
    }

    if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
        tr_err("Sending unhandled response failed!");
    }

    sn_nsdl_release_allocated_coap_msg_mem(handle_ptr, resp_ptr);
}

static uint8_t ota_get_process_id_index(uint32_t process_id)
{
    for (uint8_t i = 0; i < ota_stored_processes.ota_process_count; i++) {
        if (ota_stored_processes.ota_process_ids_tbl[i] == process_id) {
            return i;
        }
    }
    return OTA_INVALID_PROCESS_ID_INDEX;
}

static uint8_t ota_get_first_free_process_id_index(void)
{
    if (ota_stored_processes.ota_process_count < ota_lib_config_data.ota_max_processes_count) {
        return ota_stored_processes.ota_process_count;
    }
    return OTA_INVALID_PROCESS_ID_INDEX;
}

static uint8_t ota_add_new_process(uint32_t process_id)
{
    tr_info("ota_add_new_process(): 0x%08"PRIX32, process_id);

    uint8_t process_id_index = OTA_INVALID_PROCESS_ID_INDEX;

    if (ota_stored_processes.ota_process_count >= ota_lib_config_data.ota_max_processes_count) {
        tr_err("No room for new OTA process ID!!!");
        return OTA_INVALID_PROCESS_ID_INDEX;
    }

    process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index <= ota_lib_config_data.ota_max_processes_count) {
        tr_warn("OTA process ID already exists!!!");
        return process_id_index;
    }

    if (ota_store_new_process_fptr(process_id) != OTA_OK) {
        tr_err("Storing OTA process failed!!!");
        return process_id_index;
    }
    process_id_index = ota_get_first_free_process_id_index();

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_err("OTA process ID not found!");
        return process_id_index;
    }
    ota_stored_processes.ota_process_count++;
    ota_stored_dl_state_ptr[process_id_index] = ota_malloc_fptr(sizeof(ota_download_state_t));

    if (ota_stored_dl_state_ptr[process_id_index] == NULL) {
        tr_err("Memory allocation failed for ota_stored_dl_state_ptr[%u]!!! (%zu)", process_id_index, sizeof(ota_download_state_t));
        return process_id_index;
    }
    memset(ota_stored_dl_state_ptr[process_id_index], 0, sizeof(ota_download_state_t));
    ota_stored_parameters_ptr[process_id_index] = ota_malloc_fptr(sizeof(ota_parameters_t));

    if (ota_stored_parameters_ptr[process_id_index] == NULL) {
        tr_err("Memory allocation failed for ota_stored_parameters_ptr[%u]!!! (%zu)", process_id_index, sizeof(ota_parameters_t));
        return process_id_index;
    }

    memset(ota_stored_parameters_ptr[process_id_index], 0, sizeof(ota_parameters_t));
    ota_stored_processes.ota_process_ids_tbl[process_id_index] = process_id;
    ota_stored_parameters_ptr[process_id_index]->ota_process_id = process_id;
    ota_stored_dl_state_ptr[process_id_index]->ota_process_id = process_id;

    return process_id_index;
}

static void ota_handle_command_forwarding(ota_ip_address_t *source_addr_ptr, uint16_t payload_length, uint8_t *payload_ptr, bool mpl_used)
{
    uint32_t process_id = common_read_32_bit(&payload_ptr[OTA_CMD_PROCESS_ID_INDEX]);
    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_warn("ota_handle_command_forwarding() Process not found from storage");
        return;
    }

    if (ota_stored_parameters_ptr[process_id_index]->multicast_used_flag == true && source_addr_ptr == NULL) {
        ota_ip_address_t *addr = &ota_lib_config_data.link_local_multicast_socket_addr;
        if (mpl_used == true) {
            addr = &ota_lib_config_data.mpl_multicast_socket_addr;
        }
        int8_t rc = ota_socket_send_fptr(addr, payload_length, payload_ptr);

        if (rc != 0) {
            tr_err("Sending data to socket failed: rc = %d", rc);
        }
    }
}

static void ota_get_state(uint8_t process_id_index, char *ota_state_ptr)
{
    if (process_id_index >= ota_lib_config_data.ota_max_processes_count) {
        tr_err("ota_get_state() called with invalid parameter (%u)", process_id_index);
        return;
    }
    switch (ota_stored_dl_state_ptr[process_id_index]->ota_state) {
        case OTA_STATE_STARTED:
            sprintf(ota_state_ptr, "STARTED");
            break;
        case OTA_STATE_ABORTED:
            sprintf(ota_state_ptr, "ABORTED");
            break;
        case OTA_STATE_MISSING_FRAGMENTS_REQUESTING:
            sprintf(ota_state_ptr, "MISSING_FRAGMENTS_REQUESTING");
            break;
        case OTA_STATE_CHECKSUM_CALCULATING:
            sprintf(ota_state_ptr, "CHECKSUM_CALCULATING");
            break;
        case OTA_STATE_CHECKSUM_FAILED:
            sprintf(ota_state_ptr, "CHECKSUM_FAILED");
            break;
        case OTA_STATE_PROCESS_COMPLETED:
            sprintf(ota_state_ptr, "PROCESS_COMPLETED");
            break;
        case OTA_STATE_UPDATE_FW:
            sprintf(ota_state_ptr, "UPDATE_FW");
            break;
        default:
            sprintf(ota_state_ptr, "INVALID");
            break;
    }
}

static uint8_t ota_get_first_missing_fragments_process_id(bool fallback_flag)
{
    for (uint8_t i = 0; i < ota_stored_processes.ota_process_count; i++) {
        if (ota_stored_parameters_ptr[i]->missing_fragments_req_addr.type != OTA_ADDRESS_NOT_VALID ||
            (ota_stored_parameters_ptr[i]->multicast_used_flag == true && fallback_flag == false)) {

            if (fallback_flag == true || ota_stored_dl_state_ptr[i]->ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
                if (ota_stored_dl_state_ptr[i]->ota_state != OTA_STATE_ABORTED) {
                    uint16_t missing_fragment_count = ota_get_missing_fragment_total_count(i);

                    if (missing_fragment_count != 0) {
                        if (!fallback_flag || ota_stored_parameters_ptr[i]->fallback_timeout != 0) {
                            return i;
                        }
                    }
                }
            }
        }
    }

    return OTA_INVALID_PROCESS_ID_INDEX;
}

static void ota_resources_build_dl_status_notif(uint8_t process_id_index, char *dl_status_ptr)
{
    // TODO: uint16_t copied_byte_count = 0; Check against OTA_NOTIF_MAX_LENGTH

    uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count(process_id_index);

    uint16_t received_fragment_count = (ota_stored_parameters_ptr[process_id_index]->fw_fragment_count - missing_fragment_total_count);

    sprintf(dl_status_ptr, "%u/%u ", received_fragment_count, ota_stored_parameters_ptr[process_id_index]->fw_fragment_count);

    ota_get_state(process_id_index, &dl_status_ptr[strlen(dl_status_ptr)]);

    sprintf(&dl_status_ptr[strlen(dl_status_ptr)], " %08"PRIu32, ota_stored_processes.ota_process_ids_tbl[process_id_index]);
}

static uint8_t ota_get_process_id_index_from_uri_path(uint16_t uri_path_length, uint8_t *uri_path_ptr)
{
    for (uint8_t i = 0; i < ota_stored_processes.ota_process_count; i++) {
        if ((ota_stored_parameters_ptr[i]->delivered_image_resource_name_length - 2) == uri_path_length) {
            if (memcmp(&ota_stored_parameters_ptr[i]->delivered_image_resource_name_ptr[1], uri_path_ptr, uri_path_length) == 0) {
                return i;
            }
        }
    }

    return OTA_INVALID_PROCESS_ID_INDEX;
}

static void ota_delete_process(uint32_t process_id, bool storage_capacity_updated)
{
    tr_info("ota_delete_process(): 0x%08"PRIX32, process_id);

    uint8_t process_id_index = ota_get_process_id_index(process_id);

    if (process_id_index == OTA_INVALID_PROCESS_ID_INDEX) {
        tr_err("Invalid OTA process ID tried to remove: 0x%08"PRIX32, process_id);
        return;
    }

    if (process_id_index == ota_own_device_type_process_id_index) {
        ota_own_device_type_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
    }

    if (process_id_index == ota_fragments_request_service_process_id_index) {
        ota_fragments_request_service_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
    }

    if (ota_server) {
        if (process_id_index == ota_fw_delivering_process_id_index) {
            ota_fw_delivering_process_id_index = OTA_INVALID_PROCESS_ID_INDEX;
        }

    }
    ota_error_code_e rc = ota_delete_process_fptr(process_id);

    if (rc != OTA_OK) {
        tr_err("Removing OTA process from data storage failed!!!");
    }
    ota_fw_update_received = false;

    ota_stored_processes.ota_process_ids_tbl[process_id_index] = 0;
    ota_stored_processes.ota_process_count--;

    if (ota_stored_dl_state_ptr[process_id_index] != NULL) {
        if (ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr != NULL) {
            ota_free_fptr(ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr);
            ota_stored_dl_state_ptr[process_id_index]->fragments_bitmask_ptr = NULL;
        }
        ota_free_fptr(ota_stored_dl_state_ptr[process_id_index]);
        ota_stored_dl_state_ptr[process_id_index] = NULL;
    }

    if (ota_stored_parameters_ptr[process_id_index] != NULL) {
        if (storage_capacity_updated == true) {
            if (rc == OTA_OK) {
                ota_current_image_storage_capacity += ota_stored_parameters_ptr[process_id_index]->fw_total_byte_count;
                tr_info("ota_current_image_storage_capacity = %"PRIu32, ota_current_image_storage_capacity);
            }
        }

        if (ota_stored_parameters_ptr[process_id_index]->fw_name_ptr != NULL) {
            ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->fw_name_ptr);
            ota_stored_parameters_ptr[process_id_index]->fw_name_ptr = NULL;
        }

        if (ota_stored_parameters_ptr[process_id_index]->fw_version_ptr != NULL) {
            ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->fw_version_ptr);
            ota_stored_parameters_ptr[process_id_index]->fw_version_ptr = NULL;
        }

        if (ota_server) {
            if (ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr != NULL) {
                ota_free_fptr(ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr);
                ota_stored_parameters_ptr[process_id_index]->delivered_image_resource_name_ptr = NULL;
            }
        }
        ota_free_fptr(ota_stored_parameters_ptr[process_id_index]);
        ota_stored_parameters_ptr[process_id_index] = NULL;
    }

    if (ota_checksum_calculating_ptr[process_id_index] != NULL) {
        if (ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr != NULL) {
            mbedtls_sha256_free(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);

            ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr);
            ota_checksum_calculating_ptr[process_id_index]->ota_sha256_context_ptr = NULL;
        }
        ota_free_fptr(ota_checksum_calculating_ptr[process_id_index]);
        ota_checksum_calculating_ptr[process_id_index] = NULL;
    }

    if (ota_stored_processes.ota_process_count > 0 && process_id_index != ota_stored_processes.ota_process_count) {
        tr_info("Last process moved to removed process's place (%d %d)", ota_stored_processes.ota_process_count, process_id_index);

        ota_stored_processes.ota_process_ids_tbl[process_id_index] = ota_stored_processes.ota_process_ids_tbl[ota_stored_processes.ota_process_count];
        ota_stored_processes.ota_process_ids_tbl[ota_stored_processes.ota_process_count] = 0;
        ota_stored_dl_state_ptr[process_id_index] = ota_stored_dl_state_ptr[ota_stored_processes.ota_process_count];
        ota_stored_dl_state_ptr[ota_stored_processes.ota_process_count] = NULL;
        ota_stored_parameters_ptr[process_id_index] = ota_stored_parameters_ptr[ota_stored_processes.ota_process_count];
        ota_stored_parameters_ptr[ota_stored_processes.ota_process_count] = NULL;
    }
}

void ota_firmware_pulled()
{
    memset(ota_stored_dl_state_ptr[0]->fragments_bitmask_ptr,
           0xff,
           ota_stored_dl_state_ptr[0]->fragments_bitmask_length);
    ota_stored_dl_state_ptr[0]->ota_state = OTA_STATE_CHECKSUM_CALCULATING;

    ota_manage_whole_fw_checksum_calculating();
}

#endif
