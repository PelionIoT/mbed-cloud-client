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
#include <assert.h>
#include "ip6string.h"
#include "randLIB.h"
#include "mbed-coap/sn_coap_header.h"
#include "common_functions.h"
#include "mbed-trace/mbed_trace.h"
#include "sn_nsdl_lib.h"
#include "sn_grs.h"
#include "libota.h"
#include "update-client-common/arm_uc_config.h"
#include "multicast.h"

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)

static void ota_start_timer(ota_timers_e timer_id, uint32_t start_time, uint32_t random_window);
static void ota_send_error(ota_error_code_e error);
static void ota_send_estimated_resend_time(uint32_t resend_time_in_secs);
static void ota_get_state(char *ota_state_ptr);
static bool check_session(uint8_t *payload_ptr, uint16_t *payload_index);
static uint16_t fragment_size = OTA_DEFAULT_FRAGMENT_SIZE;
static void create_multicast_header(const uint8_t command);

// Buffer for sending multicast message
typedef struct {
    uint16_t size;
    uint8_t *ptr;
} ota_multicast_buffer_t;

static ota_multicast_buffer_t socket_buf = {0, 0};

// OTA library calculates checksum by OTA_CHECKSUM_CALCULATING_BYTE_COUNT bytes at a time and then generates event with
// OTA_CHECKSUM_CALCULATING_INTERVAL time for avoiding interrupting other operations for too long time
#define OTA_CHECKSUM_CALCULATING_BYTE_COUNT                 512 // In bytes
#define OTA_CHECKSUM_CALCULATING_INTERVAL                   10  // In milliseconds
#define OTA_ONE_FRAGMENT_WAITTIME_SECS                      2 * 60 * 2 /* Sending one fragment can take 2 minutes on MPL level. Double that time for now. */

#ifdef MBED_CLOUD_CLIENT_MULTICAST_SMALL_NETWORK
#define OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START      5   // After this random timeout, device will send request for its missing fragments.
#define OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START         5   // After this random timeout, device will start sending fragments to requester.
#define OTA_TIMER_RANDOM_WINDOW                             5   // Random window for timer.
#define OTA_NOTIFICATION_TIMER_DELAY                        2   // This is start time in seconds for random timeout, which OTA library uses for sending ack to backend.
#define OTA_MULTICAST_INTERVAL                              10  // Delay between multicast messages
#define OTA_MISSING_FRAGMENT_WAITTIME_HOURS                 1
#define OTA_MISSING_FRAGMENT_FALLBACK_TIMEOUT               120 /* After this timeout, device will start requesting its missing fragments.
                                                                    This is needed if node did not receive END FRAGMENT command. */
#else
// * * * Timer random timeout values (values are seconds) * * *
#define OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START      30  // After this random timeout, device will send request for its missing fragments.
#define OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START         5   // After this random timeout, device will start sending fragments to requester.
#define OTA_TIMER_RANDOM_WINDOW                             60  // Random window for timer.
#define OTA_NOTIFICATION_TIMER_DELAY                        2   // This is start time in seconds for random timeout, which OTA library uses for sending ack to backend.

#ifndef MBED_CLOUD_CLIENT_MULTICAST_INTERVAL
#define OTA_MULTICAST_INTERVAL                              60  // Delay between multicast messages
#else
#define OTA_MULTICAST_INTERVAL MBED_CLOUD_CLIENT_MULTICAST_INTERVAL
#endif

#ifndef MBED_CLOUD_CLIENT_MULTICAST_MISSING_FRAGMENT_WAIT_TIME_HOURS
#define OTA_MISSING_FRAGMENT_WAITTIME_HOURS 24
#else
#define OTA_MISSING_FRAGMENT_WAITTIME_HOURS MBED_CLOUD_CLIENT_MULTICAST_MISSING_FRAGMENT_WAIT_TIME_HOURS
#endif

#if (OTA_MISSING_FRAGMENT_WAITTIME_HOURS < 1) || (OTA_MISSING_FRAGMENT_WAITTIME_HOURS > 120)
#error "Multicast missing fragment wait time must be 1-120 hours inclusive! (defined via MBED_CLOUD_CLIENT_MULTICAST_MISSING_FRAGMENT_WAIT_TIME_HOURS)"
#endif

#define OTA_MISSING_FRAGMENT_FALLBACK_TIMEOUT               1800 /* After this timeout, device will start requesting its missing fragments.
                                                                    This is needed if node did not receive END FRAGMENT command. */

#endif // MBED_CLOUD_CLIENT_MULTICAST_SMALL_NETWORK

void ota_lib_reset()
{
    if (ota_free_fptr) {
        ota_free_fptr(socket_buf.ptr);
        socket_buf.ptr = NULL;
        socket_buf.size = 0;

        ota_free_fptr(ota_checksum_calculating_ptr.ota_sha256_context_ptr);
        ota_checksum_calculating_ptr.ota_sha256_context_ptr = NULL;

        ota_free_fptr(ota_parameters.fragments_bitmask_ptr);
        ota_parameters.fragments_bitmask_ptr = NULL;

        ota_free_fptr(ota_parameters.pull_url_ptr);
        ota_parameters.pull_url_ptr = NULL;
    }
}

ota_error_code_e ota_lib_configure(ota_lib_config_data_t *lib_config_data_ptr,
                                   ota_config_func_pointers_t *func_pointers_ptr)
{
    tr_debug("ota_lib_configure");
    ota_error_code_e returned_status = OTA_OK;

    if (lib_config_data_ptr == NULL || func_pointers_ptr == NULL) {
        tr_err("Some given function parameter is null");
        returned_status = OTA_PARAMETER_FAIL;
        goto done;
    }

    if (func_pointers_ptr->mem_alloc_fptr == NULL || func_pointers_ptr->mem_free_fptr == NULL ||
        func_pointers_ptr->request_timer_fptr == NULL || func_pointers_ptr->cancel_timer_fptr == NULL ||
        func_pointers_ptr->store_new_ota_process_fptr == NULL || func_pointers_ptr->remove_stored_ota_process_fptr == NULL ||
        func_pointers_ptr->store_parameters_fptr == NULL || func_pointers_ptr->read_parameters_fptr == NULL ||
        func_pointers_ptr->write_fw_bytes_fptr == NULL || func_pointers_ptr->read_fw_bytes_fptr == NULL ||
        func_pointers_ptr->send_update_fw_cmd_received_info_fptr == NULL || func_pointers_ptr->socket_send_fptr == NULL ||
        func_pointers_ptr->update_resource_value_fptr == NULL || func_pointers_ptr->manifest_received_fptr == NULL ||
        func_pointers_ptr->firmware_ready_fptr == NULL || func_pointers_ptr->get_parent_addr_fptr == NULL) {
        tr_err("Some given function pointer is null");
        returned_status = OTA_PARAMETER_FAIL;
        goto done;
    }

    memset(&ota_lib_config_data, 0, sizeof(ota_lib_config_data_t));
    memset(&ota_parameters, 0, sizeof(ota_parameters_t));
    ota_lib_config_data.device_type = lib_config_data_ptr->device_type;

    memcpy(&ota_lib_config_data.unicast_socket_addr,
           &lib_config_data_ptr->unicast_socket_addr,
           sizeof(lib_config_data_ptr->unicast_socket_addr));

    memcpy(&ota_lib_config_data.mpl_multicast_socket_addr,
           &lib_config_data_ptr->mpl_multicast_socket_addr,
           sizeof(lib_config_data_ptr->mpl_multicast_socket_addr));

    memcpy(&ota_lib_config_data.link_local_multicast_socket_addr,
           &lib_config_data_ptr->link_local_multicast_socket_addr,
           sizeof(lib_config_data_ptr->link_local_multicast_socket_addr));

    ota_malloc_fptr = func_pointers_ptr->mem_alloc_fptr;
    ota_free_fptr = func_pointers_ptr->mem_free_fptr;

    ota_write_fw_bytes_fptr = func_pointers_ptr->write_fw_bytes_fptr;
    ota_read_fw_bytes_fptr = func_pointers_ptr->read_fw_bytes_fptr;
    ota_send_update_fw_cmd_received_info_fptr = func_pointers_ptr->send_update_fw_cmd_received_info_fptr;

    ota_request_timer_fptr = func_pointers_ptr->request_timer_fptr;
    ota_cancel_timer_fptr = func_pointers_ptr->cancel_timer_fptr;

    ota_store_new_process_fptr = func_pointers_ptr->store_new_ota_process_fptr;
    ota_delete_process_fptr = func_pointers_ptr->remove_stored_ota_process_fptr;

    ota_store_parameters_fptr = func_pointers_ptr->store_parameters_fptr;
    ota_read_stored_parameters_fptr = func_pointers_ptr->read_parameters_fptr;

    ota_socket_send_fptr = func_pointers_ptr->socket_send_fptr;
    ota_update_resource_value_fptr = func_pointers_ptr->update_resource_value_fptr;
    ota_start_received_fptr = func_pointers_ptr->start_received_fptr;
    ota_process_finished_fptr = func_pointers_ptr->process_finished_fptr;
    ota_manifest_received_fptr = func_pointers_ptr->manifest_received_fptr;
    ota_firmware_ready_fptr =  func_pointers_ptr->firmware_ready_fptr;
    ota_get_parent_addr_fptr = func_pointers_ptr->get_parent_addr_fptr;
    memset(&ota_checksum_calculating_ptr, 0, sizeof(ota_checksum_calculating_t));

    returned_status = ota_read_stored_parameters_fptr(&ota_parameters);

    if (returned_status != OTA_OK) {
        tr_err("Reading stored OTA parameters from application failed!, error code: %d", returned_status);
        goto done;
    }

    tr_info("Found stored OTA process count: %u", ota_parameters.ota_process_count);

    if (ota_parameters.device_type == ota_lib_config_data.device_type && ota_parameters.ota_process_count > 0) {
        ota_own_device_type = true;
    }

    ota_fw_delivering = false;

    uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count();

    if (missing_fragment_total_count > 0) {
        if (ota_parameters.ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_TIMER_RANDOM_WINDOW );
        } else {
            if (ota_parameters.ota_state != OTA_STATE_ABORTED) {
                ota_start_timer(OTA_FALLBACK_TIMER, OTA_MISSING_FRAGMENT_FALLBACK_TIMEOUT, 0);
            }
        }
    } else {
        if (ota_parameters.ota_state != OTA_STATE_ABORTED &&
            ota_parameters.ota_state != OTA_STATE_CHECKSUM_FAILED &&
            ota_parameters.ota_state != OTA_STATE_PROCESS_COMPLETED &&
            ota_parameters.ota_state != OTA_STATE_UPDATE_FW &&
            ota_parameters.ota_state != OTA_STATE_INVALID &&
            ota_parameters.ota_state != OTA_STATE_IDLE) {
            ota_parameters.ota_state = OTA_STATE_CHECKSUM_CALCULATING;
        }
    }

    tr_info("Missing fragments total count: %u Received fragment total count: %u",
    missing_fragment_total_count, (ota_parameters.fw_fragment_count - missing_fragment_total_count));

    ota_get_and_log_first_missing_segment(NULL);

    if (ota_parameters.ota_state == OTA_STATE_CHECKSUM_CALCULATING) {
        ota_manage_whole_fw_checksum_calculating();
    }

    ota_update_status_resource();

//There might be memory leaks if above failed!!!!!!!
done:
    if (returned_status == OTA_OK) {
        if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
            tr_info("OTA library configured successfully (ROUTER)");
        } else {
            tr_info("OTA library configured successfully (NODE)");
        }
    } else {
        if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
            tr_err("OTA library configuration failed! Error code: %d (ROUTER)", returned_status);
        } else {
            tr_err("OTA library configuration failed! Error code: %d (NODE)", returned_status);
        }
  }

  return returned_status;
}

void ota_socket_receive_data(uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *source_addr_ptr)
{
    if (payload_ptr == NULL || source_addr_ptr == NULL) {
        tr_err("ota_socket_receive_data() - called with NULL pointer");
        return;
    }

    uint8_t command_id = payload_ptr[0];

    tr_info("OTA received socket data from source address: %s Port %u, Length: %"PRIu16", Command id: %"PRIu8" ", trace_ipv6(source_addr_ptr->address_tbl), source_addr_ptr->port, payload_length, command_id);

    switch (command_id) {
        case OTA_CMD_START:
            if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
                if (ota_manage_start_command(payload_length, payload_ptr) != OTA_OK) {
                    ota_send_error(OTA_PARAMETER_FAIL);
                }
            }
            break;

        case OTA_CMD_FRAGMENT:
            if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
                ota_manage_fragment_command(payload_length, payload_ptr);
            }
            break;

        case OTA_CMD_ABORT:
            if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
                ota_manage_abort_command(payload_length, payload_ptr);
            }
            break;

        case OTA_CMD_END_FRAGMENTS:
            if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
                ota_manage_end_fragments_command(payload_length, payload_ptr);
            }
            break;

        case OTA_CMD_ACTIVATE:
            if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
                ota_manage_update_fw_command(payload_length, payload_ptr);
            }
            break;

        case OTA_CMD_FRAGMENTS_REQUEST:
            ota_manage_fragments_request_command(payload_length, payload_ptr, source_addr_ptr);
            break;

        case OTA_CMD_MANIFEST:
            if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
                if (ota_manage_manifest_command(payload_length, payload_ptr) != OTA_OK) {
                    ota_send_error(OTA_PARAMETER_FAIL);
                }
            }
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
    tr_debug("ota_timer_expired - id %d", timer_id);
    if (timer_id == OTA_END_FRAGMENTS_TIMER) {
        create_multicast_header(OTA_CMD_END_FRAGMENTS);
        if (ota_socket_send_fptr(&ota_lib_config_data.link_local_multicast_socket_addr, OTA_SESSION_ID_SIZE + 1, socket_buf.ptr) != 0) {
            tr_err("Failed to send END FRAGMENTS command!");
        }

        if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
            // Border router has sent all the fragments
            uint8_t payload[1] = "1";
            ota_update_resource_value_fptr(MULTICAST_READY, payload, 1);
        }
    } else if (timer_id == OTA_MISSING_FRAGMENTS_REQUESTING_TIMER) {
        if (ota_get_first_missing_fragments_process_id(false) != OTA_INVALID_PROCESS_ID_INDEX) {
            ota_request_missing_fragments();
        } else {
            tr_warn("OTA_MISSING_FRAGMENTS_REQUESTING_TIMER: Device does not have missing fragments or request address not given or requesting is aborted");
        }
    } else if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER && timer_id == OTA_FRAGMENTS_DELIVERING_TIMER) {
        if (ota_fw_delivering) {
            if (ota_fw_deliver_current_fragment_id <= ota_parameters.fw_fragment_count) {
                if (ota_deliver_one_fragment(ota_fw_deliver_current_fragment_id, ota_lib_config_data.mpl_multicast_socket_addr) == OTA_OK) {
                    ota_fw_deliver_current_fragment_id++;
                }
                ota_start_timer(OTA_FRAGMENTS_DELIVERING_TIMER, OTA_MULTICAST_INTERVAL, 0);
            } else {
                ota_start_timer(OTA_END_FRAGMENTS_TIMER, OTA_NOTIFICATION_TIMER_DELAY, OTA_TIMER_RANDOM_WINDOW);
                ota_fw_delivering = false;
            }
        }
    } else if (timer_id == OTA_FRAGMENTS_REQUEST_SERVICE_TIMER) {
        if (ota_fragments_request_service) {
            ota_serve_fragments_request_by_sending_one_fragment();
            uint16_t missing_fragment_count_for_requester = ota_get_next_missing_fragment_id_for_requester(false);

            if (missing_fragment_count_for_requester > 0) {
                ota_start_timer(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER, OTA_MULTICAST_INTERVAL, 30);
            } else {
                tr_info("All requested fragments sent");
                ota_fragments_request_service = false;
            }
        }
    } else if (timer_id == OTA_FALLBACK_TIMER) {
        if (ota_get_first_missing_fragments_process_id(true) != OTA_INVALID_PROCESS_ID_INDEX) {
            ota_get_and_log_first_missing_segment(NULL);

            ota_parameters.ota_state = OTA_STATE_MISSING_FRAGMENTS_REQUESTING;

            ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);

            if (rc != OTA_OK) {
                tr_err("Storing OTA states failed, RC: %d", rc);
            }

            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_TIMER_RANDOM_WINDOW);

            tr_info("State changed to \"OTA MISSING FRAGMENTS REQUESTING\"");
            ota_start_timer(OTA_FALLBACK_TIMER, OTA_MISSING_FRAGMENT_FALLBACK_TIMEOUT, 0);

            ota_update_status_resource();
        } else {
            tr_info("No missing fragments or missing fragments request address not given or OTA process is aborted");
        }
    } else if (timer_id == OTA_CHECKSUM_CALCULATING_TIMER) {
        ota_manage_whole_fw_checksum_calculating();
    } else if (timer_id == OTA_MULTICAST_MESSAGE_SENT_TIMER) {
        ota_send_estimated_resend_time(OTA_ONE_FRAGMENT_WAITTIME_SECS);
        ota_delete_process(ota_parameters.ota_session_id);
    } else if (timer_id == OTA_FIRMWARE_READY_TIMER) {
        ota_firmware_ready_fptr();
    } else {
        tr_err("Unsupported timer ID: %d", timer_id);
    }
}

static ota_error_code_e ota_manage_start_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    ota_error_code_e status = OTA_PARAMETER_FAIL;

    tr_info("***Received OTA START command. Length: %d", payload_length);

    if (payload_length != OTA_START_CMD_LENGTH) {
        tr_err("Received START command data length not correct: %u (%u)", payload_length, OTA_START_CMD_LENGTH);
        return status;
    }

    uint8_t session_id[OTA_SESSION_ID_SIZE];
    memcpy(session_id, &payload_ptr[OTA_CMD_PROCESS_ID_INDEX], OTA_SESSION_ID_SIZE);
    uint8_t device_type = payload_ptr[OTA_START_CMD_DEVICE_TYPE_INDEX];

    if (ota_parameters.device_type == device_type) {
        tr_err("Node received START command with same Device type OTA process already created --> START command is ignored!");
        return status;
    }

    if (device_type != ota_lib_config_data.device_type) {
        tr_err("Node received START command not it's own device type --> START command is ignored!");
        return status;
    }

    if (ota_add_new_process(session_id) != OTA_OK) {
        tr_err("ota_border_router_manage_start_command() - session already exists or not able to create!");
        return status;
    }

    status = ota_parse_start_command_parameters(payload_ptr);

    if (status == OTA_OK) {
       ota_parameters.fragments_bitmask_length = (ota_parameters.fw_segment_count * OTA_FRAGMENTS_REQ_BITMASK_LENGTH);

        tr_info("Bitmask length as bytes for received fragments: %u", ota_parameters.fragments_bitmask_length);

        ota_parameters.fragments_bitmask_ptr = ota_malloc_fptr(ota_parameters.fragments_bitmask_length);

        if (ota_parameters.fragments_bitmask_ptr != NULL) {
            ota_init_fragments_bit_mask(0x00);
            ota_start_timer(OTA_FALLBACK_TIMER, OTA_MISSING_FRAGMENT_FALLBACK_TIMEOUT, 0);
            ota_parameters.ota_state = OTA_STATE_STARTED;

            tr_info("State changed to \"OTA STARTED\"");

            status = ota_store_parameters_fptr(&ota_parameters);

            if (status != OTA_OK) {
                tr_err("Storing OTA parameters failed, status: %d", status);
                ota_delete_process(ota_parameters.ota_session_id);
                return status;
            }

            ota_free_fptr(socket_buf.ptr);
            socket_buf.ptr = ota_malloc_fptr(ota_parameters.fw_fragment_byte_count + OTA_FRAGMENT_CMD_LENGTH);
            if (!socket_buf.ptr) {
                tr_err("ota_manage_start_command - failed to allocate buffer for multicast messages!");
                return OTA_PARAMETER_FAIL;
            }
            socket_buf.size = ota_parameters.fw_fragment_byte_count + OTA_FRAGMENT_CMD_LENGTH;

            ota_update_status_resource();

            if (ota_parameters.device_type == ota_lib_config_data.device_type) {
                ota_own_device_type = true;
            }

            ota_start_received_fptr(&ota_parameters);

        } else {
            tr_err("Memory allocation failed for received fragments bitmask!!! (%u bytes)",
                   ota_parameters.fragments_bitmask_length);
            ota_delete_process(ota_parameters.ota_session_id);
            return status;
        }
    } else {
        tr_err("Failed to parse START parameters!");
        ota_delete_process(session_id);
    }

    tr_info("OTA process count: %u", ota_parameters.ota_process_count);

    return status;
}

static ota_error_code_e ota_border_router_manage_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    ota_error_code_e status = OTA_PARAMETER_FAIL;
    if (!socket_buf.ptr) {
        socket_buf.ptr = ota_malloc_fptr(OTA_MAX_MULTICAST_MESSAGE_SIZE);
        if (!socket_buf.ptr) {
            tr_err("ota_border_router_manage_command - failed to allocate buffer for multicast messages!");
            return status;
        }
        socket_buf.size = OTA_MAX_MULTICAST_MESSAGE_SIZE;
    }

    uint8_t command_id = payload_ptr[MULTICAST_CMD_ID_INDEX];
    uint8_t command_type = payload_ptr[MULTICAST_CMD_TYPE_INDEX];
    uint8_t session_id[OTA_SESSION_ID_SIZE];
    memcpy(session_id, &payload_ptr[MULTICAST_CMD_SESSION_ID_INDEX], OTA_SESSION_ID_SIZE);

    uint8_t multicast_version = payload_ptr[MULTICAST_CMD_VERSION];
    if (multicast_version != 1) {
        tr_err("ota_border_router_manage_command - multicast version (%d) not supported!", multicast_version);
        return status;
    }

    if (command_id == OTA_CMD_ACTIVATE) {
        // Delete session created by firmware command
        ota_delete_process(ota_parameters.ota_session_id);
    }

    tr_info("ota_border_router_manage_command - command id: %d, command type: %d, version: %d", command_id, command_type, multicast_version);

    if (ota_add_new_process(session_id) != OTA_OK) {
        tr_err("ota_border_router_manage_command - session already exists or not able to create!");
        return status;
    }

    switch (command_id) {
        case OTA_CMD_ACTIVATE:
        case OTA_CMD_MANIFEST:
            status = ota_send_multicast_command(command_id, payload_ptr, payload_length);
            if (status != OTA_OK) {
                tr_error("ota_border_router_manage_command - failed to build multicast command %d!", command_id);
            }
            break;

        case OTA_CMD_FIRMWARE:
            if (command_type == OTA_CMD_TYPE_URL_DATA) {
                status = OTA_OK;

                // Update fragment size if set through Pelion
                ota_parameters.fw_fragment_byte_count = fragment_size;

                ota_parameters.fw_total_byte_count = common_read_32_bit(&payload_ptr[MULTICAST_CMD_FW_SIZE_INDEX]);
                memcpy(ota_parameters.whole_fw_checksum_tbl, &payload_ptr[MULTICAST_CMD_FW_HASH_INDEX], OTA_WHOLE_FW_CHECKSUM_LENGTH);

                ota_parameters.fw_fragment_count = ota_parameters.fw_total_byte_count / ota_parameters.fw_fragment_byte_count;
                if (ota_parameters.fw_total_byte_count % ota_parameters.fw_fragment_byte_count != 0) {
                    ota_parameters.fw_fragment_count++;
                }

                ota_parameters.fw_segment_count = (ota_parameters.fw_fragment_count / OTA_SEGMENT_SIZE);

                if (ota_parameters.pull_url_ptr != NULL) {
                    ota_free_fptr(ota_parameters.pull_url_ptr);
                    ota_parameters.pull_url_ptr = NULL;
                }

                ota_parameters.pull_url_length = payload_length - MULTICAST_CMD_URL_INDEX;

                if (ota_parameters.pull_url_length > 0) {
                    ota_parameters.pull_url_ptr = ota_malloc_fptr(ota_parameters.pull_url_length);
                    if (ota_parameters.pull_url_ptr != NULL) {
                        memset(ota_parameters.pull_url_ptr, 0, ota_parameters.pull_url_length);
                        memcpy(ota_parameters.pull_url_ptr, &payload_ptr[MULTICAST_CMD_URL_INDEX], ota_parameters.pull_url_length);
                    } else {
                        tr_error("ota_border_router_manage_command - failed to allocate url!");
                        status = OTA_OUT_OF_MEMORY;
                    }
                }

                if (status == OTA_OK) {
                    status = ota_start_received_fptr(&ota_parameters);
                    if (status == OTA_OK) {
                        tr_info("State changed to \"OTA STARTED\"");
                        ota_send_estimated_resend_time((OTA_MISSING_FRAGMENT_WAITTIME_HOURS * 3600) + (OTA_MULTICAST_INTERVAL * ota_parameters.fw_fragment_count));
                        ota_parameters.ota_state = OTA_STATE_STARTED;
                        status = ota_store_parameters_fptr(&ota_parameters);
                        if (status == OTA_OK) {
                            ota_update_status_resource();
                        } else {
                            tr_error("ota_border_router_manage_command - failed to store params!");
                        }
                    } else {
                        tr_error("ota_border_router_manage_command - failed to process start!");
                    }
                }
            } else {
                tr_err("ota_border_router_manage_command() - unsupported command type!");
            }
            break;

        default:
            tr_err("ota_border_router_manage_command() - unsupported command id!");
            break;
    }

    return status;
}

static ota_error_code_e ota_parse_start_command_parameters(uint8_t *payload_ptr)
{
    tr_debug("ota_parse_start_command_parameters");
    ota_error_code_e returned_status = OTA_OK;
    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint8_t session_id[OTA_SESSION_ID_SIZE];
    memcpy(session_id, &payload_ptr[OTA_CMD_PROCESS_ID_INDEX], OTA_SESSION_ID_SIZE);
    payload_index += OTA_SESSION_ID_SIZE;

    memcpy(ota_parameters.ota_session_id, session_id, OTA_SESSION_ID_SIZE);
    ota_parameters.device_type = payload_ptr[payload_index];

    payload_index += 1;

    ota_parameters.fw_fragment_count = common_read_16_bit(&payload_ptr[payload_index]);
    tr_info("Number of firmware fragments: %u", ota_parameters.fw_fragment_count);
    tr_info("Number of segments (fragment_count / OTA_SEGMENT_SIZE): %u", (ota_parameters.fw_fragment_count / OTA_SEGMENT_SIZE));
    tr_info("Bytes over segments (fragment_count %% OTA_SEGMENT_SIZE): %u", (ota_parameters.fw_fragment_count % OTA_SEGMENT_SIZE));

    payload_index += 2;

    ota_parameters.fw_segment_count = (ota_parameters.fw_fragment_count / OTA_SEGMENT_SIZE);

    if ((ota_parameters.fw_fragment_count % OTA_SEGMENT_SIZE) != 0) {
        ota_parameters.fw_segment_count++;
    }
    tr_info("Number of needed segments: %u", ota_parameters.fw_segment_count);

    ota_parameters.fw_fragment_byte_count = common_read_16_bit(&payload_ptr[payload_index]);
    tr_info("Fragment size: %u", ota_parameters.fw_fragment_byte_count);

    payload_index += 2;

    ota_parameters.fw_total_byte_count = common_read_32_bit(&payload_ptr[payload_index]);

    payload_index += 4;

    if (returned_status == OTA_OK) {
        memcpy(ota_parameters.whole_fw_checksum_tbl, &payload_ptr[payload_index], OTA_WHOLE_FW_CHECKSUM_LENGTH);
    }

    return returned_status;
}

static void ota_manage_fragment_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    uint16_t payload_index;

    tr_info("***Received OTA FRAGMENT command. Length: %d", payload_length);

    if (!check_session(payload_ptr, &payload_index)) {
        tr_warn("Process not found from storage.");
        return;
    }

    if (payload_length < OTA_FRAGMENT_CMD_LENGTH) {
        tr_err("Received FRAGMENT command data length not correct: %u (%u)", payload_length, OTA_FRAGMENT_CMD_LENGTH);
        return;
    }

    uint16_t fragment_id = common_read_16_bit(&payload_ptr[payload_index]);
    payload_index += 2;

    if (ota_parameters.ota_state != OTA_STATE_STARTED &&
        ota_parameters.ota_state != OTA_STATE_MISSING_FRAGMENTS_REQUESTING &&
        ota_fragments_request_service == false) {
        tr_warn("OTA in wrong state when received FW fragment %u / %u. Current state: %d Fragments requesting service OTA process ID index: %u",
                fragment_id, ota_parameters.fw_fragment_count,
                ota_parameters.ota_state,
                ota_fragments_request_service);
        return;
    }

    tr_info("OTA Fragment ID: %u / %u", fragment_id, ota_parameters.fw_fragment_count);

    uint16_t fragment_checksum = common_read_16_bit(&payload_ptr[payload_length - 2]);

    if (fragment_id == 0) {
        tr_err("Received firmware Fragment ID is zero");
    }

    if (fragment_id > ota_parameters.fw_fragment_count) {
        tr_err("Received firmware Fragment ID bigger than whole fragment count in image");
    }

    uint16_t calculated_fragment_checksum = ota_calculate_checksum_over_one_fragment(&payload_ptr[OTA_FRAGMENT_CMD_FRAGMENT_BYTES_INDEX],
            ota_parameters.fw_fragment_byte_count);

    if (fragment_checksum != calculated_fragment_checksum) {
        tr_err("Checksums mismatch. Fragment checksum: 0x%X Calculated checksum: 0x%X", fragment_checksum, calculated_fragment_checksum);
    }

    if (fragment_checksum == calculated_fragment_checksum &&
        fragment_id > 0 && fragment_id <= ota_parameters.fw_fragment_count){

        if (ota_fragments_request_service == false) {
            bool fragment_already_received_flag = ota_check_if_fragment_already_received(fragment_id);

            if (fragment_already_received_flag == false) {
                uint32_t offset = (fragment_id - 1) * (uint32_t)ota_parameters.fw_fragment_byte_count;
                uint32_t len = ota_parameters.fw_fragment_byte_count;

                if (offset + len > ota_parameters.fw_total_byte_count) {
                    len = ota_parameters.fw_total_byte_count - offset;
                }

                uint32_t written_byte_count = ota_write_fw_bytes_fptr(ota_parameters.ota_session_id,
                                                                      offset,
                                                                      len,
                                                                      &payload_ptr[payload_index]);

                if (written_byte_count == len) {
                    uint16_t segment_bitmask_id = (ota_parameters.fragments_bitmask_length - 1) - ((fragment_id - 1) / 8);
                    uint8_t segment_bitmask_bit_number = (fragment_id - 1) % 8;

                    uint8_t segment_bitmask_bit = (0x01 << segment_bitmask_bit_number);
                    ota_parameters.fragments_bitmask_ptr[segment_bitmask_id] |= segment_bitmask_bit;

                    ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);
                    if (rc != OTA_OK) {
                        tr_err("Storing OTA parameters failed, RC: %d", rc);
                    }

                    uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count();

                    tr_info("Missing fragments total count: %u Received fragment total count: %u",
                            missing_fragment_total_count,
                            (ota_parameters.fw_fragment_count - missing_fragment_total_count));

                    ota_get_and_log_first_missing_segment(NULL);

                    if (missing_fragment_total_count == 0) {
                        ota_parameters.ota_state = OTA_STATE_CHECKSUM_CALCULATING;

                        rc = ota_store_parameters_fptr(&ota_parameters);
                        if (rc != OTA_OK){
                            tr_err("Storing OTA parameters failed, RC: %d", rc);
                        }

                        ota_manage_whole_fw_checksum_calculating();
                    } else {
                        ota_start_timer(OTA_FALLBACK_TIMER, OTA_MISSING_FRAGMENT_FALLBACK_TIMEOUT, 0);
                    }
                } else {
                    // TODO! should the whole process to be stopped here? do we know is this a temporary failure or permanent?
                    // This will lead to case where node is constantly asking missing fragments.
                    tr_err("Fragment storing to data storage failed. (%"PRIu32" <> %u)", written_byte_count, ota_parameters.fw_fragment_byte_count);
                }
            } else {
                ota_get_and_log_first_missing_segment(NULL);
            }
        } else if (ota_fragments_request_service) {
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

            uint16_t missing_fragment_count_for_requester = ota_get_next_missing_fragment_id_for_requester(false);
            if (missing_fragment_count_for_requester > 0) {
                ota_start_timer(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER,
                                OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START,
                                OTA_TIMER_RANDOM_WINDOW);
            } else {
                ota_cancel_timer_fptr(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER);
                ota_fragments_request_service = false;
            }
        } else {
            tr_info("No need for this fragment!");
        }
    } else {
        tr_err("OTA will not store data to given data storage because fragment cmd validity checks failed (%u %u %u %u)",
        fragment_checksum, calculated_fragment_checksum, fragment_id, ota_parameters.fw_fragment_count);
    }

    if (ota_parameters.ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count();

        if (missing_fragment_total_count > 0) {
            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_TIMER_RANDOM_WINDOW);
        }
    }

    ota_update_status_resource();
}

static void ota_manage_abort_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_info("ota_manage_abort_command - OTA process count: %u", ota_parameters.ota_process_count);

    uint16_t payload_index;

    tr_info("***Received OTA ABORT command. Length: %d", payload_length);

    if (!check_session(payload_ptr, &payload_index)) {
        tr_warn("Process not found from storage.");
        return;
    }

    if (payload_length < OTA_ABORT_CMD_LENGTH) {
        tr_err("Received ABORT command data length not correct: %u (%u)", payload_length, OTA_ABORT_CMD_LENGTH);
        return;
    }

    ota_fragments_request_service = false;
    ota_fw_delivering = false;

    if (ota_parameters.ota_state == OTA_STATE_CHECKSUM_CALCULATING) {
        tr_warn("Checksum calculating over whole received image is aborted!!!");

        mbedtls_sha256_free(ota_checksum_calculating_ptr.ota_sha256_context_ptr);

        ota_free_fptr(ota_checksum_calculating_ptr.ota_sha256_context_ptr);
        ota_checksum_calculating_ptr.ota_sha256_context_ptr = NULL;

        memset(&ota_checksum_calculating_ptr, 0, sizeof(ota_checksum_calculating_t));
    }

    if (ota_parameters.ota_state != OTA_STATE_ABORTED) {
        if (ota_parameters.ota_state != OTA_STATE_UPDATE_FW) {
            tr_info("State changed to \"OTA ABORTED\"");

            ota_parameters.ota_state = OTA_STATE_ABORTED;

            ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);
            if (rc != OTA_OK) {
                tr_err("Storing OTA parameters failed, RC: %d", rc);
            }
        }
    } else {
        tr_warn("State remains \"OTA ABORTED\"");
    }

    ota_update_status_resource();

    if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
        ota_process_finished_fptr(ota_parameters.ota_session_id);
    }

    tr_info("OTA process count: %u", ota_parameters.ota_process_count);
}

static void ota_manage_end_fragments_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_debug("ota_manage_end_fragments_command");
    uint16_t payload_index;

    tr_info("***Received OTA END FRAGMENTS command. Length: %d, state: %d", payload_length, ota_parameters.ota_state);

    if (!check_session(payload_ptr, &payload_index)) {
        tr_warn("Process not found from storage.");
        return;
    }

    if (ota_parameters.ota_state == OTA_STATE_STARTED) {
        if (payload_length < OTA_END_FRAGMENTS_CMD_LENGTH) {
            tr_err("Received END FRAGMENTS command data length not correct: %u (%u)", payload_length, OTA_END_FRAGMENTS_CMD_LENGTH);
            return;
        }

        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count();

        tr_info("Missing fragments total count: %u Received fragment total count: %u",
                missing_fragment_total_count,
                (ota_parameters.fw_fragment_count - missing_fragment_total_count));

        if (missing_fragment_total_count > 0) {
            ota_get_and_log_first_missing_segment(NULL);

            ota_parameters.ota_state = OTA_STATE_MISSING_FRAGMENTS_REQUESTING;
            ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);

            if (rc != OTA_OK) {
                tr_err("Storing OTA parameters failed, RC: %d", rc);
            }

            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_TIMER_RANDOM_WINDOW);

            tr_info("State changed to \"OTA MISSING FRAGMENTS REQUESTING\"");
        }

        ota_update_status_resource();
    }
}

static ota_error_code_e ota_manage_manifest_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_debug("ota_manage_manifest_command");

    // Clean up any existing sessions
    ota_delete_process(ota_parameters.ota_session_id);

    ota_error_code_e status = OTA_OK;
    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX;

    uint8_t session_id[OTA_SESSION_ID_SIZE];
    memcpy(session_id, &payload_ptr[payload_index], OTA_SESSION_ID_SIZE);
    payload_index += OTA_SESSION_ID_SIZE;

    tr_info("***Received OTA MANIFEST command. Length: %d", payload_length);

    if (ota_add_new_process(session_id) != OTA_OK) {
        tr_err("ota_manage_manifest_command() - session already exists or not able to create!");
        status = OTA_PARAMETER_FAIL;
    }

    if (status == OTA_OK) {
        if (ota_manifest_received_fptr(payload_ptr + 17, payload_length - 17) != OTA_OK) {
            tr_error("ota_manage_manifest_command - failed to set manifest!");
            status = OTA_PARAMETER_FAIL;
        } else {
            ota_parameters.ota_state = OTA_STATE_MANIFEST_RECEIVED;
        }
    }

    if (status == OTA_OK) {
        ota_update_status_resource();
    }

    ota_delete_process(session_id);

    return status;
}

static void ota_manage_update_fw_command(uint16_t payload_length, uint8_t *payload_ptr)
{
    tr_info("***Received OTA UPDATE FW command. Length: %d", payload_length);

    uint16_t payload_index = OTA_CMD_PROCESS_ID_INDEX + OTA_SESSION_ID_SIZE;

    // No need to continue asking missing packages if activate command already sent by border router
    ota_cancel_timer_fptr(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER);
    ota_cancel_timer_fptr(OTA_FALLBACK_TIMER);

    if (ota_parameters.ota_state != OTA_STATE_PROCESS_COMPLETED &&
        ota_parameters.ota_state != OTA_STATE_UPDATE_FW) {
        tr_warn("OTA not in PROCESS COMPLETED or in UPDATE FW state when tried to change to FW UPDATE state. Current state: %d",
                ota_parameters.ota_state);
        return;
    }

    if (payload_length < OTA_UPDATE_FW_CMD_LENGTH) {
        tr_err("Received UPDATE FW command data length not correct: %u (%u)", payload_length, OTA_UPDATE_FW_CMD_LENGTH);
        return;
    }

    uint8_t device_type = payload_ptr[payload_index];
    payload_index += 1;

    tr_info("Device type: %d", device_type);

    if (device_type != ota_lib_config_data.device_type) {
        tr_warn("State change failed (Device type check failed, msg: %d <> cnf: %d)", device_type, ota_lib_config_data.device_type);
        // the function returns here for border router, so effectively we're done in BR.
        // time to release reservations to update manager
        if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
            ota_process_finished_fptr(ota_parameters.ota_session_id);
        }

        return;
    }

    if (ota_fw_update_received == false) {
        ota_update_fw_delay = common_read_32_bit(&payload_ptr[payload_index]);
        payload_index += 4;

        tr_info("Firmware update delay: %"PRIu32" second(s)", ota_update_fw_delay);

        ota_fw_update_received = true;
    }

    if (ota_parameters.ota_state != OTA_STATE_UPDATE_FW) {
        ota_parameters.ota_state = OTA_STATE_UPDATE_FW;

        ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);

        if (rc != OTA_OK) {
            tr_err("Storing OTA states failed, RC: %d", rc);
        }

        tr_warn("State changed to \"OTA FW UPDATE\"");

        ota_send_update_fw_cmd_received_info_fptr(ota_update_fw_delay);
    } else {
        tr_warn("State already \"OTA FW UPDATE\"");
    }

    ota_update_status_resource();

    tr_info("OTA process count: %u", ota_parameters.ota_process_count);
}

static void ota_manage_fragments_request_command(uint16_t payload_length, uint8_t *payload_ptr, ota_ip_address_t *source_addr)
{
    uint16_t payload_index;

    tr_info("***Received OTA FRAGMENTS REQUEST command - length: %d, from: %s, state %d", payload_length, trace_ipv6(source_addr->address_tbl), ota_parameters.ota_state);

    if (!check_session(payload_ptr, &payload_index)) {
        tr_warn("Process not found from storage.");
        return;
    }

    if (ota_parameters.ota_state == OTA_STATE_PROCESS_COMPLETED ||
        ota_parameters.ota_state == OTA_STATE_UPDATE_FW) {
        if (payload_length < OTA_FRAGMENTS_REQ_LENGTH) {
            tr_err("Received FRAGMENTS REQUEST command data length not correct: %u (%u)", payload_length, OTA_FRAGMENTS_REQ_LENGTH);
            return;
        }

        if (ota_fragments_request_service) {
            tr_warn("Fragment request serving already ongoing!");
            return;
        }

        if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER && ota_fw_delivering) {
            tr_warn("Firmware delivering is already ongoing!");
            return;
        }

        tr_info("OTA process ID checked successfully");

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

        uint16_t missing_fragment_count_for_requester = ota_get_next_missing_fragment_id_for_requester(false);

        if (missing_fragment_count_for_requester > 0) {
            ota_fragments_request_service = true;
            ota_start_timer(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER,
                            OTA_FRAGMENTS_REQUEST_SERVICE_TIMEOUT_START,
                            OTA_TIMER_RANDOM_WINDOW);
        } else {
            tr_info("No missing fragments in request");
        }
    } else {
        if (ota_parameters.ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) {
            ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                            OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                            OTA_TIMER_RANDOM_WINDOW);
        }
    }
}

static bool ota_check_if_fragment_already_received(uint16_t fragment_id)
{
    uint16_t fragment_bitmask_id = (ota_parameters.fragments_bitmask_length - 1) - ((fragment_id - 1) / 8);
    uint8_t fragment_bitmask_bit_number = (fragment_id - 1) % 8;
    uint8_t fragment_bitmask_bit = (0x01 << fragment_bitmask_bit_number);

    if ((ota_parameters.fragments_bitmask_ptr[fragment_bitmask_id] & fragment_bitmask_bit) != 0) {
        return true;
    }

    return false;
}

static uint16_t ota_get_missing_fragment_total_count()
{
    uint16_t returned_missing_fragment_total_count = 0;
    uint8_t *fragment_bitmask_temp_ptr = &ota_parameters.fragments_bitmask_ptr[ota_parameters.fragments_bitmask_length - 1];

    for (uint16_t fragment_id = 1; fragment_id <= ota_parameters.fw_fragment_count; fragment_bitmask_temp_ptr--) {
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

static uint16_t ota_get_and_log_first_missing_segment(uint8_t *missing_fragment_bitmasks_ptr)
{
    uint8_t *segment_bitmask_temp_ptr =
            &ota_parameters.fragments_bitmask_ptr[ota_parameters.fragments_bitmask_length - 1];

    if (missing_fragment_bitmasks_ptr != NULL) {
        memset(missing_fragment_bitmasks_ptr, 0, OTA_FRAGMENTS_REQ_BITMASK_LENGTH);
    }

    uint16_t fragment_id = 1;

    for (uint16_t segment_id = 1; segment_id <= ota_parameters.fw_segment_count; segment_id++) {
        if (missing_fragment_bitmasks_ptr != NULL) {
            memcpy(missing_fragment_bitmasks_ptr,
                   &ota_parameters.fragments_bitmask_ptr[(ota_parameters.fragments_bitmask_length) - (segment_id * OTA_FRAGMENTS_REQ_BITMASK_LENGTH)],
                    OTA_FRAGMENTS_REQ_BITMASK_LENGTH);
        }

        for (uint8_t j = 0; j < OTA_FRAGMENTS_REQ_BITMASK_LENGTH; j++, segment_bitmask_temp_ptr--) {
            uint8_t one_byte_bitmask = *segment_bitmask_temp_ptr;

            for (uint8_t bit_counter = 0; bit_counter < 8; bit_counter++, fragment_id++) {
                uint8_t bit_id = (1 << bit_counter);

                if ((one_byte_bitmask & bit_id) == 0) {
                    tr_info("First missing segment ID: %u Fragment ID: %u", segment_id, fragment_id);
                    return segment_id;
                }
            }
        }
    }

    return 0;
}

static void ota_request_missing_fragments()
{
    uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count();
    tr_info("Missing fragments total count: %u Received fragment total count: %u",
            missing_fragment_total_count,
            (ota_parameters.fw_fragment_count - missing_fragment_total_count));

    uint8_t missing_fragment_bitmasks_tbl[OTA_FRAGMENTS_REQ_BITMASK_LENGTH];
    uint16_t first_missing_segment_id = ota_get_and_log_first_missing_segment(missing_fragment_bitmasks_tbl);
    uint16_t payload_length = OTA_FRAGMENTS_REQ_LENGTH + OTA_SESSION_ID_SIZE + 1;

    uint16_t payload_index = 0;

    create_multicast_header(OTA_CMD_FRAGMENTS_REQUEST);
    payload_index += OTA_SESSION_ID_SIZE + 1;

    common_write_16_bit(first_missing_segment_id, &socket_buf.ptr[payload_index]);
    payload_index += 2;

    memcpy(&socket_buf.ptr[payload_index], missing_fragment_bitmasks_tbl, OTA_FRAGMENTS_REQ_BITMASK_LENGTH);

    if (ota_get_parent_addr_fptr(ota_lib_config_data.unicast_socket_addr.address_tbl) != OTA_OK) {
        tr_warn("ota_request_missing_fragments - failed to read parent address!");
    }

    if (ota_socket_send_fptr(&ota_lib_config_data.unicast_socket_addr, payload_length, socket_buf.ptr) != 0) {
        tr_err("ota_request_missing_fragments - sending command to socket failed");
    }

    ota_start_timer(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER,
                    OTA_MISSING_FRAGMENTS_REQUESTING_TIMEOUT_START,
                    OTA_TIMER_RANDOM_WINDOW);
}

static ota_error_code_e ota_deliver_one_fragment(const uint16_t fragment_id, ota_ip_address_t address)
{
    tr_info("Device will build fragment %u", fragment_id);

    uint16_t payload_index = 0;

    create_multicast_header(OTA_CMD_FRAGMENT);
    payload_index += OTA_SESSION_ID_SIZE + 1;

    common_write_16_bit(fragment_id, &socket_buf.ptr[payload_index]);
    payload_index += 2;

    uint32_t offset = (fragment_id - 1) * (uint32_t)ota_parameters.fw_fragment_byte_count;
    uint32_t len = ota_parameters.fw_fragment_byte_count;

    if (offset + len > ota_parameters.fw_total_byte_count) {
        len = ota_parameters.fw_total_byte_count - offset;
    }

    uint32_t read_byte_count = ota_read_fw_bytes_fptr(ota_parameters.ota_session_id, offset, len, &socket_buf.ptr[payload_index]);
    if (read_byte_count != len) {
        tr_err("Building FRAGMENT command failure! Read data byte count mismatch: %"PRIu32" <> %"PRIu32" ", read_byte_count, len);
        return OTA_STORAGE_ERROR;
    }

    uint16_t calculated_fragment_checksum = ota_calculate_checksum_over_one_fragment(&socket_buf.ptr[payload_index], ota_parameters.fw_fragment_byte_count);

    payload_index += ota_parameters.fw_fragment_byte_count;
    common_write_16_bit(calculated_fragment_checksum, &socket_buf.ptr[payload_index]);

    if (ota_socket_send_fptr(&address, ota_parameters.fw_fragment_byte_count + OTA_FRAGMENT_CMD_LENGTH, socket_buf.ptr) != 0) {
        tr_err("ota_deliver_one_fragment - failed to send data!");
        return OTA_PARAMETER_FAIL;
    }

    return OTA_OK;
}

static void ota_serve_fragments_request_by_sending_one_fragment()
{
    tr_info("ota_serve_fragments_request_by_sending_one_fragment()");
    uint16_t fragment_id = ota_get_next_missing_fragment_id_for_requester(true);

    if (fragment_id <= 0) {
        tr_err("ota_serve_fragments_request_by_sending_one_fragment() has no fragments to be sent (%u)", fragment_id);
        return;
    }

    ota_deliver_one_fragment(fragment_id, ota_lib_config_data.link_local_multicast_socket_addr);
}

static uint16_t ota_get_next_missing_fragment_id_for_requester(bool bit_mask_change)
{
    uint16_t fragment_id = 1 + ((ota_fragments_request_service_segment_id - 1) * OTA_SEGMENT_SIZE);

    if (fragment_id > ota_parameters.fw_fragment_count) {
        tr_err("Fragment ID in request bigger than total fragment count!");
        return 0;
    }

    for (int8_t i = (OTA_FRAGMENTS_REQ_BITMASK_LENGTH - 1); i >= 0; i--) {
        for (uint8_t bit_counter = 0; bit_counter < 8; bit_counter++, fragment_id++) {
            if (fragment_id > ota_parameters.fw_fragment_count) {
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

    if (ota_parameters.ota_state == OTA_STATE_CHECKSUM_CALCULATING) {
        if (ota_checksum_calculating_ptr.ota_sha256_context_ptr == NULL) {
            tr_info("Whole FW checksum calculating started!!!");
            new_round_needed = true;

            memset(&ota_checksum_calculating_ptr, 0, sizeof(ota_checksum_calculating_t));
            ota_checksum_calculating_ptr.ota_sha256_context_ptr = ota_malloc_fptr(sizeof(mbedtls_sha256_context));

            if (ota_checksum_calculating_ptr.ota_sha256_context_ptr != NULL) {
                memset(ota_checksum_calculating_ptr.ota_sha256_context_ptr, 0, sizeof(mbedtls_sha256_context));

                mbedtls_sha256_init(ota_checksum_calculating_ptr.ota_sha256_context_ptr);
                mbedtls_sha256_starts(ota_checksum_calculating_ptr.ota_sha256_context_ptr, 0);
            } else {
                tr_err("Memory allocation failed for ota_sha256_context_ptr");
            }
        } else {
            uint32_t fw_total_data_byte_count = ota_parameters.fw_total_byte_count;
            uint32_t pushed_fw_data_byte_count = OTA_CHECKSUM_CALCULATING_BYTE_COUNT;

            if ((ota_checksum_calculating_ptr.current_byte_id + pushed_fw_data_byte_count) > fw_total_data_byte_count) {
                pushed_fw_data_byte_count = (fw_total_data_byte_count - ota_checksum_calculating_ptr.current_byte_id);
            }
            tr_info("Calculating whole FW checksum! pushed byte count: %"PRIu32" Byte ID: %"PRIu32" ",
                    pushed_fw_data_byte_count,
                    ota_checksum_calculating_ptr.current_byte_id);

            uint8_t *pushed_fw_data_byte_ptr = ota_malloc_fptr(pushed_fw_data_byte_count);

            if (pushed_fw_data_byte_ptr != NULL) {
                uint32_t read_byte_count = ota_read_fw_bytes_fptr(ota_parameters.ota_session_id,
                                                                  ota_checksum_calculating_ptr.current_byte_id,
                                                                  pushed_fw_data_byte_count,
                                                                  pushed_fw_data_byte_ptr);

                ota_checksum_calculating_ptr.current_byte_id += read_byte_count;

                if (read_byte_count != pushed_fw_data_byte_count) {
                    tr_err("Reading from data storage failed (%"PRIu32" <> %"PRIu32")", read_byte_count, pushed_fw_data_byte_count);
                } else {
                    mbedtls_sha256_update(ota_checksum_calculating_ptr.ota_sha256_context_ptr, pushed_fw_data_byte_ptr, read_byte_count);
                }

                if (ota_checksum_calculating_ptr.current_byte_id == fw_total_data_byte_count ||
                    read_byte_count != pushed_fw_data_byte_count) {
                    uint8_t sha256_result[OTA_WHOLE_FW_CHECKSUM_LENGTH];

                    memset(sha256_result, 0, OTA_WHOLE_FW_CHECKSUM_LENGTH);

                    mbedtls_sha256_finish(ota_checksum_calculating_ptr.ota_sha256_context_ptr, sha256_result);

                    mbedtls_sha256_free(ota_checksum_calculating_ptr.ota_sha256_context_ptr);

                    ota_free_fptr(ota_checksum_calculating_ptr.ota_sha256_context_ptr);
                    ota_checksum_calculating_ptr.ota_sha256_context_ptr = NULL;

                    int match = memcmp(sha256_result,
                                       ota_parameters.whole_fw_checksum_tbl,
                                       OTA_WHOLE_FW_CHECKSUM_LENGTH);

                    if (match == 0) {
                        tr_info("Whole firmware image checksum ok!");

                        ota_parameters.ota_state = OTA_STATE_PROCESS_COMPLETED;

                        ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);

                        if (rc != OTA_OK) {
                            tr_err("Storing OTA states failed, RC: %d", rc);
                        }

                        tr_info("State changed to \"OTA PROCESS COMPLETED\"");

                        // Firmware downloaded
                        if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
                            rc = ota_send_multicast_command(OTA_CMD_FIRMWARE, NULL, 0);
                            if (rc != OTA_OK) {
                                ota_send_error(rc);
                            }
                        } else if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_NODE) {
                            ota_start_timer(OTA_END_FRAGMENTS_TIMER, OTA_NOTIFICATION_TIMER_DELAY, OTA_TIMER_RANDOM_WINDOW);
                            ota_start_timer(OTA_FIRMWARE_READY_TIMER, 1, 0);
                        }

                    } else {
                        tr_err("All fragments received, but whole FW checksum calculating failed! Match = %u", match);
                        tr_err("Given whole FW checksum: %s", trace_array(ota_parameters.whole_fw_checksum_tbl,
                                                                          OTA_WHOLE_FW_CHECKSUM_LENGTH));
                        tr_err("Calculated from memory whole FW checksum: %s", trace_array(sha256_result, OTA_WHOLE_FW_CHECKSUM_LENGTH));

                        ota_parameters.ota_state = OTA_STATE_CHECKSUM_FAILED;

                        tr_info("State changed to \"OTA CHECKSUM FAILED\"");

                        ota_error_code_e rc = ota_store_parameters_fptr(&ota_parameters);

                        if (rc != OTA_OK) {
                            tr_err("Storing OTA states failed, RC: %d", rc);
                        }
                    }

                    ota_update_status_resource();
                } else {
                    new_round_needed = true;
                }

                ota_free_fptr(pushed_fw_data_byte_ptr);
            } else {
                tr_err("Memory allocation failed for pushed_fw_data_byte_ptr!!! (%"PRIu32")", pushed_fw_data_byte_count);
                new_round_needed = true;
            }
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

uint8_t ota_lwm2m_command(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;
    sn_coap_hdr_s *resp_ptr = NULL;
    sn_coap_msg_code_e coap_response_code = COAP_MSG_CODE_RESPONSE_VALID;

    if (coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_POST) {
        if (coap_ptr->payload_len >= MULTICAST_CMD_FW_SIZE_INDEX) {
            if (ota_border_router_manage_command(coap_ptr->payload_len, coap_ptr->payload_ptr) != OTA_OK) {
                tr_err("ota_lwm2m_command - failed to handle command");
                coap_response_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            }
        } else {
            tr_err("ota_lwm2m_command - invalid payload!");
            coap_response_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }
    } else {
        tr_err("ota_lwm2m_command - unsupported msg code!");
        coap_response_code = COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED;
    }

    if (coap_response_code == COAP_MSG_CODE_RESPONSE_BAD_REQUEST) {
        ota_delete_process(ota_parameters.ota_session_id);
    }

    // TODO! maybe to change to use delayed response
    resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, coap_response_code);

    if (resp_ptr != NULL) {
        if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
            tr_err("ota_lwm2m_command - sending response failed!");
        }
    } else {
        tr_err("ota_lwm2m_command - building response failed!");
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

uint8_t ota_fragment_size_command(struct nsdl_s *handle_ptr, sn_coap_hdr_s *coap_ptr, sn_nsdl_addr_s *address_ptr, sn_nsdl_capab_e proto)
{
    (void)proto;
    sn_coap_hdr_s *resp_ptr = NULL;
    sn_coap_msg_code_e coap_response_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;

    resp_ptr = sn_nsdl_build_response(handle_ptr, coap_ptr, coap_response_code);
    if (resp_ptr == NULL) {
        tr_err("ota_fragment_size_command - building CoAP confirmation for PUT failed!");
        return 0;
    }

    if (coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_GET) {
        coap_response_code = COAP_MSG_CODE_RESPONSE_CONTENT;
        char buf[6];
        resp_ptr->payload_len = sprintf(buf, "%"PRIu16, fragment_size);
        resp_ptr->payload_ptr = (uint8_t*)buf;
    } else if (coap_ptr->msg_code == COAP_MSG_CODE_REQUEST_PUT) {
        // Allow at max 4 digits
        if (coap_ptr->payload_ptr && coap_ptr->payload_len <= 4) {
            char value_buf[4];
            int16_t value = 0;
            memcpy(value_buf, coap_ptr->payload_ptr, coap_ptr->payload_len);
            if (sscanf(value_buf, "%hd", &value)) {
                if (value >= OTA_MIN_FRAGMENT_SIZE &&
                    value <= OTA_MAX_MULTICAST_MESSAGE_SIZE &&
                    value <= ARM_UC_HUB_BUFFER_SIZE_MAX &&
                    value % MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE == 0) {
                    coap_response_code = COAP_MSG_CODE_RESPONSE_CHANGED;
                    tr_info("ota_fragment_size_command - fragment size set to %d", value);
                    // New value is taken into use when new multicast process is started by border router
                    fragment_size = value;
                } else {
                    tr_error("ota_fragment_size_command - failed to set value %d", value);
                }
            }
        }
    }

    resp_ptr->msg_code = coap_response_code;
    if (sn_nsdl_send_coap_message(handle_ptr, address_ptr, resp_ptr) != 0) {
        tr_err("ota_fragment_size_command - sending response failed!");
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

static void ota_init_fragments_bit_mask(uint8_t init_value)
{
    if (ota_parameters.fragments_bitmask_ptr != NULL) {
        memset(ota_parameters.fragments_bitmask_ptr, 0xFF, ota_parameters.fragments_bitmask_length);

        uint8_t *fragment_bitmask_temp_ptr =
                &ota_parameters.fragments_bitmask_ptr[ota_parameters.fragments_bitmask_length - 1];

        for (uint16_t fragment_counter_temp = 0;
             fragment_counter_temp < ota_parameters.fw_fragment_count;
             fragment_bitmask_temp_ptr--) {

            for (uint8_t j = 0; j < 8; j++) {
                if (init_value == 0)                {
                    *fragment_bitmask_temp_ptr &= ~(1 << j);
                } else {
                    *fragment_bitmask_temp_ptr |= (1 << j);
                }

                fragment_counter_temp++;

                if (fragment_counter_temp >= ota_parameters.fw_fragment_count) {
                    break;
                }
            }
        }
    }
}

static ota_error_code_e ota_add_new_process(uint8_t *session_id)
{
    tr_info("ota_add_new_process()");

    if (ota_parameters.ota_process_count > 0) {
        tr_error("ota_add_new_process() - session already exists");
        return OTA_PARAMETER_FAIL;
    }

    if (ota_store_new_process_fptr(session_id) != OTA_OK) {
        tr_err("ota_add_new_process() - storing OTA process failed!");
        return OTA_PARAMETER_FAIL;
    }

    ota_parameters.ota_process_count++;
    memcpy(ota_parameters.ota_session_id, session_id, OTA_SESSION_ID_SIZE);

    // Multicast in progress
    uint8_t payload[1] = "0";
    ota_update_resource_value_fptr(MULTICAST_READY, payload, 1);
    ota_update_resource_value_fptr(MULTICAST_SESSION_ID, session_id, OTA_SESSION_ID_SIZE);

    return OTA_OK;
}

static uint8_t ota_get_first_missing_fragments_process_id(bool fallback_flag)
{
    if ((fallback_flag || ota_parameters.ota_state == OTA_STATE_MISSING_FRAGMENTS_REQUESTING) &&
        ota_parameters.ota_state != OTA_STATE_ABORTED) {
        uint16_t missing_fragment_count = ota_get_missing_fragment_total_count();
        if (missing_fragment_count != 0) {
            return 0;
        }
    }

    return OTA_INVALID_PROCESS_ID_INDEX;
}

static void ota_update_status_resource()
{
    char status[OTA_NOTIF_MAX_LENGTH];

    uint8_t *uuid = ota_parameters.ota_session_id;
    sprintf(status,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );

    if (ota_lib_config_data.device_type != OTA_DEVICE_TYPE_BORDER_ROUTER) {
        uint16_t missing_fragment_total_count = ota_get_missing_fragment_total_count();
        if (missing_fragment_total_count > 0) {
            uint16_t received_fragment_count = (ota_parameters.fw_fragment_count - missing_fragment_total_count);
            sprintf(status + 36, " %u/%u ", received_fragment_count, ota_parameters.fw_fragment_count);
        }
    }

    ota_get_state(&status[strlen(status)]);

    tr_info("ota_update_status_resource - status %s", status);
    if (ota_update_resource_value_fptr(MULTICAST_STATUS, (uint8_t*)status, strlen(status)) == 0) {
        tr_err("ota_update_status_resource  - failed to update status resource!");
    }
}

static void ota_delete_process(uint8_t *session_id)
{
    tr_info("ota_delete_process()");

    if (memcmp(ota_parameters.ota_session_id, session_id, OTA_SESSION_ID_SIZE) != 0) {
        tr_err("Tried to remove unknown session");
        return;
    }

    ota_own_device_type = false;
    ota_fragments_request_service = false;

    if (ota_lib_config_data.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
        ota_fw_delivering = false;
    }

    (void)ota_delete_process_fptr(session_id);

    ota_fw_update_received = false;

    if (ota_parameters.fragments_bitmask_ptr != NULL) {
        ota_free_fptr(ota_parameters.fragments_bitmask_ptr);
        ota_parameters.fragments_bitmask_ptr = NULL;
    }

    if (ota_checksum_calculating_ptr.ota_sha256_context_ptr != NULL) {
        mbedtls_sha256_free(ota_checksum_calculating_ptr.ota_sha256_context_ptr);
        ota_free_fptr(ota_checksum_calculating_ptr.ota_sha256_context_ptr);
        ota_checksum_calculating_ptr.ota_sha256_context_ptr = NULL;
    }

    memset(&ota_parameters, 0, sizeof(ota_parameters));

    // Ready for new multicast session
    uint8_t payload[1] = "1";
    ota_update_resource_value_fptr(MULTICAST_READY, payload, 1);

    ota_update_resource_value_fptr(MULTICAST_SESSION_ID,
                             (uint8_t*)&ota_parameters.ota_session_id,
                             sizeof(ota_parameters.ota_session_id));

    ota_cancel_timer_fptr(OTA_CHECKSUM_CALCULATING_TIMER);
    ota_cancel_timer_fptr(OTA_FRAGMENTS_DELIVERING_TIMER);
    ota_cancel_timer_fptr(OTA_MISSING_FRAGMENTS_REQUESTING_TIMER);
    ota_cancel_timer_fptr(OTA_FRAGMENTS_REQUEST_SERVICE_TIMER);
    ota_cancel_timer_fptr(OTA_FALLBACK_TIMER);
    ota_cancel_timer_fptr(OTA_FIRMWARE_READY_TIMER);
    ota_cancel_timer_fptr(OTA_END_FRAGMENTS_TIMER);
}

void ota_firmware_pulled()
{
    memset(ota_parameters.fragments_bitmask_ptr,
           0xff,
           ota_parameters.fragments_bitmask_length);
    ota_parameters.ota_state = OTA_STATE_CHECKSUM_CALCULATING;

    ota_manage_whole_fw_checksum_calculating();
}

ota_error_code_e ota_send_multicast_command(ota_commands_e command, uint8_t *payload_ptr, uint16_t payload_length)
{
    tr_debug("ota_send_multicast_command - command %d", command);
    assert(socket_buf.ptr != NULL);

    if (payload_length > OTA_MAX_MULTICAST_MESSAGE_SIZE) {
        tr_error("ota_send_multicast_command - payload is too big!");
        return OTA_PARAMETER_FAIL;
    }

    size_t multicast_payload_len = 0;

    switch (command) {
        case OTA_CMD_MANIFEST:
            create_multicast_header(OTA_CMD_MANIFEST);

            memcpy(socket_buf.ptr + 17, &payload_ptr[MULTICAST_CMD_SESSION_ID_INDEX + 16], payload_length - MULTICAST_CMD_SESSION_ID_INDEX + 16);
            multicast_payload_len = payload_length - MULTICAST_CMD_SESSION_ID_INDEX + 16 + 5;
            break;

        case OTA_CMD_FIRMWARE:
            create_multicast_header(OTA_CMD_START);

            socket_buf.ptr[17] = OTA_DEVICE_TYPE_NODE; // Device type
            common_write_16_bit(ota_parameters.fw_fragment_count, &socket_buf.ptr[18]); // FW fragment count
            common_write_16_bit(ota_parameters.fw_fragment_byte_count, &socket_buf.ptr[20]); // FW fragment size
            common_write_32_bit(ota_parameters.fw_total_byte_count, &socket_buf.ptr[22]); // FW total size
            memcpy(&socket_buf.ptr[26], ota_parameters.whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH); // FW hash
            multicast_payload_len = OTA_START_CMD_LENGTH;
            break;

        case OTA_CMD_ACTIVATE:
            create_multicast_header(OTA_CMD_ACTIVATE);

            socket_buf.ptr[17] = OTA_DEVICE_TYPE_NODE; // Device type
            common_write_32_bit(common_read_32_bit(&payload_ptr[19]), &socket_buf.ptr[18]); // FW fragment size
            multicast_payload_len = 22;
            break;

        default:
            break;
    }

    if (ota_socket_send_fptr(&ota_lib_config_data.mpl_multicast_socket_addr, multicast_payload_len, socket_buf.ptr) != OTA_OK) {
        tr_error("ota_send_multicast_command - failed to send multicast message!");
        return OTA_PARAMETER_FAIL;
    }

    if (command == OTA_CMD_FIRMWARE) {
        ota_start_timer(OTA_FRAGMENTS_DELIVERING_TIMER, OTA_MULTICAST_INTERVAL, 0);
        ota_fw_delivering = true;
        ota_fw_deliver_current_fragment_id = 1;
    } else if (command == OTA_CMD_MANIFEST) {
        ota_start_timer(OTA_MULTICAST_MESSAGE_SENT_TIMER, OTA_MULTICAST_INTERVAL, 0);
    } else {
        ota_start_timer(OTA_MULTICAST_MESSAGE_SENT_TIMER, OTA_MULTICAST_INTERVAL, 0);
        ota_process_finished_fptr(ota_parameters.ota_session_id);
    }

    return OTA_OK;
}

static void ota_send_estimated_resend_time(uint32_t resend_time_in_secs)
{
    uint8_t payload[21];
    payload[0] = 1; // Version info
    memcpy(payload + 1, ota_parameters.ota_session_id, OTA_SESSION_ID_SIZE); // Session id
    common_write_32_bit(resend_time_in_secs, payload + 17);
    ota_update_resource_value_fptr(MULTICAST_ESTIMATED_RESEND_TIME, payload, 21);
}

static void ota_send_error(ota_error_code_e error)
{
    tr_info("ota_send_error() - error code %d", error);
    uint8_t payload[18];
    payload[0] = 1; // Version info
    memcpy(payload + 1, ota_parameters.ota_session_id, OTA_SESSION_ID_SIZE); // Session id
    memcpy(payload + 17, &error, 1); // Error code
    ota_update_resource_value_fptr(MULTICAST_ERROR, payload, 18);

    // Ready for new multicast session
    payload[0] = '1';
    ota_update_resource_value_fptr(MULTICAST_READY, payload, 1);
}

void ota_delete_session(uint8_t* session)
{
    ota_delete_process(session);
}

static bool check_session(uint8_t *payload_ptr, uint16_t *payload_index)
{
    *payload_index = OTA_CMD_PROCESS_ID_INDEX;
    uint8_t session_id[OTA_SESSION_ID_SIZE];
    memcpy(session_id, &payload_ptr[OTA_CMD_PROCESS_ID_INDEX], OTA_SESSION_ID_SIZE);
    *payload_index += OTA_SESSION_ID_SIZE;
    if (memcmp(ota_parameters.ota_session_id, session_id, OTA_SESSION_ID_SIZE) != 0) {
        return false;
    }

    return true;
}

static void ota_get_state(char *ota_state_ptr)
{
    switch (ota_parameters.ota_state) {
        case OTA_STATE_IDLE:
            sprintf(ota_state_ptr, " IDLE");
            break;
        case OTA_STATE_STARTED:
            sprintf(ota_state_ptr, " STARTED");
            break;
        case OTA_STATE_ABORTED:
            sprintf(ota_state_ptr, " ABORTED");
            break;
        case OTA_STATE_MISSING_FRAGMENTS_REQUESTING:
            sprintf(ota_state_ptr, " MISSING FRAGMENTS REQUESTING");
            break;
        case OTA_STATE_CHECKSUM_CALCULATING:
            sprintf(ota_state_ptr, " CHECKSUM CALCULATING");
            break;
        case OTA_STATE_CHECKSUM_FAILED:
            sprintf(ota_state_ptr, " CHECKSUM FAILED");
            break;
        case OTA_STATE_PROCESS_COMPLETED:
            sprintf(ota_state_ptr, " FIRMWARE DOWNLOADED");
            break;
        case OTA_STATE_UPDATE_FW:
            sprintf(ota_state_ptr, " ACTIVATE FIRMWARE");
            break;
        case OTA_STATE_MANIFEST_RECEIVED:
            sprintf(ota_state_ptr, " MANIFEST RECEIVED");
            break;
        default:
            sprintf(ota_state_ptr, " INVALID");
            break;
    }
}

void create_multicast_header(const uint8_t command)
{
    assert(socket_buf.ptr != NULL);

    memset(socket_buf.ptr, 0, socket_buf.size);
    socket_buf.ptr[0] = command;
    memcpy(&socket_buf.ptr[1], ota_parameters.ota_session_id, OTA_SESSION_ID_SIZE);
}
#endif
