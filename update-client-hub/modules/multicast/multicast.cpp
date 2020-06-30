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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sn_coap_header.h"
#include "otaLIB.h"
#include "otaLIB_resources.h"
#include "pal.h"
#include "sn_nsdl_lib.h"
#include "sn_nsdl.h"
#include "sn_grs.h"
#include "m2mtimer.h"
#include "net_interface.h"
#include "eventOS_event.h"
#include "eventOS_event_timer.h"
#include "multicast.h"
#include "mbed-client/m2minterfacefactory.h"
#include "m2mobject.h"
#include "m2mobjectinstance.h"
#include "m2mresource.h"
#include "MbedCloudClient.h"
#include "socket_api.h"
#include "multicast_api.h"
#include "ip6string.h"
#include "arm_uc_types.h"
#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update_client_hub_state_machine.h"
#include "update-client-manifest-manager/update-client-manifest-types.h"
#include "update-client-common/arm_uc_config.h"

#if !defined(TARGET_LIKE_MBED) || !defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
#include "net_rpl.h"
#else
extern "C" {
    #include "ws_bbr_api.h"
};
#endif

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1)

#define OTA_SOCKET_UNICAST_PORT             48380 // Socket port number for OTA (used for Unicast)
#define OTA_SOCKET_MULTICAST_PORT           48381 // Socket port number for OTA (used for Link local multicast and MPL multicast)
#define OTA_ACK_TIMER_START                 2 // This is start time in seconds for random timeout, which OTA library uses for sending ack to backend. End time is given in OTA_START_CMD command.
#define MULTICAST_OBJECT_ID                 "26241"
#define RECEIVE_BUFFER_SIZE                 1152
#define TRACE_GROUP "MULTICAST"
#define BUFFER_SIZE_MAX (ARM_UC_BUFFER_SIZE / 2) //  define size of the double buffers

static ARM_UCFM_Setup_t arm_uc_multicast_fwmanager_configuration;
static arm_uc_firmware_details_t arm_uc_multicast_fwmanager_firmware_details;
static bool arm_uc_multicast_fwmanager_prepared = false;
static bool arm_uc_multicast_send_in_progress = false;
static arm_uc_buffer_t arm_uc_multicast_fwmanager_hashbuf;
static uint8_t arm_uc_multicast_fwmanager_buffer[BUFFER_SIZE_MAX];
static arm_uc_buffer_t arm_uc_multicast_fwmanager_armbuffer = {
    .size_max = BUFFER_SIZE_MAX,
    .size = 0,
    .ptr = arm_uc_multicast_fwmanager_buffer
};

static void             arm_uc_multicast_request_timer(uint8_t timer_id, uint32_t timeout);
static void             arm_uc_multicast_cancel_timer(uint8_t timer_id);
static ota_error_code_e arm_uc_multicast_store_new_ota_process(uint32_t ota_process_id);
static ota_error_code_e arm_uc_multicast_read_stored_ota_processes(ota_processes_t* ota_processes);
static ota_error_code_e arm_uc_multicast_remove_stored_ota_process(uint32_t ota_process_id);
static ota_error_code_e arm_uc_multicast_store_state(ota_download_state_t* ota_state);
static ota_error_code_e arm_uc_multicast_read_state(uint32_t process_id, ota_download_state_t* ota_state);
static ota_error_code_e arm_uc_multicast_store_parameters(ota_parameters_t* ota_parameters);
static ota_error_code_e arm_uc_multicast_read_parameters(uint32_t process_id, ota_parameters_t* ota_parameters);
static uint32_t         arm_uc_multicast_get_fw_storing_capacity();
static uint32_t         arm_uc_multicast_write_fw_bytes(uint32_t ota_process_id, uint32_t offset, uint32_t count, uint8_t* from);
static uint32_t         arm_uc_multicast_read_fw_bytes(uint32_t ota_process_id, uint32_t offset, uint32_t count, uint8_t* to);
static void             arm_uc_multicast_send_update_fw_cmd_received_info(uint32_t ota_process_id, uint16_t delay);
static int8_t           arm_uc_multicast_socket_send(ota_ip_address_t* destination, uint16_t count, uint8_t* payload);
static uint16_t         arm_uc_multicast_coap_send_notif(char *path, uint8_t *payload_ptr, uint16_t payload_len);
static ota_error_code_e arm_uc_multicast_create_resource(const char *path_ptr, const char *type_ptr, int32_t flags, bool is_observable, ota_coap_callback_t *callback_ptr, bool publish_uri);
static bool             arm_uc_multicast_create_static_resources();
static void             arm_uc_multicast_update_device_registration();
static uint8_t          arm_uc_multicast_send_coap_response(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_coap_msg_code_e msg_code, sn_nsdl_addr_s *address, const char* payload);
static void             arm_uc_multicast_socket_callback(void*);
static void             arm_uc_multicast_tasklet(struct arm_event_s *event);
static bool             arm_uc_multicast_open_socket(palSocket_t *socket, uint16_t port);

static ota_error_code_e arm_uc_multicast_start_received(ota_parameters_t* ota_parameters);
static void             arm_uc_multicast_process_finished(uint32_t process_id);
static bool             read_dodag_info(char *dodag_address);
static void             arm_uc_multicast_send_event(arm_uc_hub_state_t state);

struct nsdl_s*              arm_uc_multicast_nsdl_handle;
palSocket_t                 arm_uc_multicast_socket;
palSocket_t                 arm_uc_multicast_missing_frag_socket;
static int8_t               arm_uc_multicast_tasklet_id = -1;
static int8_t               arm_uc_multicast_interface_id;
static M2MBaseList*         arm_uc_multicast_m2m_object_list = NULL;
static M2MObject*           arm_uc_multicast_object = NULL;
static M2MObjectInstance*   arm_uc_multicast_object_inst = NULL;
static M2MResource*         arm_uc_multicast_dl_status_res = NULL;
static M2MResource*         arm_uc_multicast_cmd_status_res = NULL;
static ConnectorClient*     arm_uc_multicast_m2m_client;
static uint32_t             arm_uc_multicast_stored_ota_process_id;
static const uint8_t        arm_uc_multicast_link_local_multicast_address[16] = {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; // Link local multicast socket IP address
static const uint8_t        arm_uc_multicast_address[16] = {0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; // MPL multicast socket IP address
static arm_event_storage_t  arm_uc_multicast_event = {0};

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
struct manifest_firmware_info_t fw_info;
#endif

static ota_processes_t stored_ota_processes = {
    .ota_process_count = 0,
    .ota_process_ids_tbl = &arm_uc_multicast_stored_ota_process_id
};

static ota_download_state_t stored_download_state = {
    .ota_process_id = 0,
    .ota_state = OTA_STATE_INVALID,
    .fragments_bitmask_length = 0,
    .fragments_bitmask_ptr = 0
};

static ota_parameters_t stored_ota_parameters = {
    .ota_process_id = 0,
    .device_type = 0,
    .response_sending_delay_start = 0,
    .response_sending_delay_end = 0,
    .fw_download_report_config = 0,
    .multicast_used_flag = false,
    .fw_name_length = 0,
    .fw_name_ptr = 0,
    .fw_version_length = 0,
    .fw_version_ptr = 0,
    .fw_segment_count = 0,
    .fw_total_byte_count = 0,
    .fw_fragment_count = 0,
    .fw_fragment_byte_count = 0,
    .fw_fragment_sending_interval_uni = 0,
    .fw_fragment_sending_interval_mpl = 0,
    .whole_fw_checksum_tbl = {0},
    .fallback_timeout = 0,
    .missing_fragments_req_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0},
    .delivered_image_resource_name_length = 0,
    .delivered_image_resource_name_ptr = 0,
    .pull_url_length = 0,
    .pull_url_ptr = 0
};

static ota_lib_config_data_t arm_uc_multicast_ota_config = {
    .device_type = OTA_DEVICE_TYPE3,                                     // ??
    .ota_max_processes_count = 1,                                        // always 1 for node
    .response_msg_type = COAP_MSG_TYPE_CONFIRMABLE,
    .response_sending_delay_start = 1,                                   // Response sending random delay start value in seconds (end time is given in START command)
    .unicast_socket_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0},              // Unicast socket address (??)
    .link_local_multicast_socket_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0}, // BR address?
    .mpl_multicast_socket_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0}         // MPL multicast socket address (??)
};

static ota_config_func_pointers_t arm_uc_ota_function_pointers = {
    .mem_alloc_fptr = &malloc,
    .mem_free_fptr = &free,
    .request_timer_fptr = &arm_uc_multicast_request_timer,
    .cancel_timer_fptr = &arm_uc_multicast_cancel_timer,
    .store_new_ota_process_fptr = &arm_uc_multicast_store_new_ota_process,
    .read_stored_ota_processes_fptr = &arm_uc_multicast_read_stored_ota_processes,
    .remove_stored_ota_process_fptr = &arm_uc_multicast_remove_stored_ota_process,
    .store_state_fptr = &arm_uc_multicast_store_state,
    .read_state_fptr = &arm_uc_multicast_read_state,
    .store_parameters_fptr = &arm_uc_multicast_store_parameters,
    .read_parameters_fptr = &arm_uc_multicast_read_parameters,
    .start_received_fptr = &arm_uc_multicast_start_received,
    .process_finished_fptr = &arm_uc_multicast_process_finished,
    .get_fw_storing_capacity_fptr = &arm_uc_multicast_get_fw_storing_capacity,
    .write_fw_bytes_fptr = &arm_uc_multicast_write_fw_bytes,
    .read_fw_bytes_fptr = &arm_uc_multicast_read_fw_bytes,
    .send_update_fw_cmd_received_info_fptr = &arm_uc_multicast_send_update_fw_cmd_received_info,
    .update_device_registration_fptr = &arm_uc_multicast_update_device_registration,
    .socket_send_fptr = &arm_uc_multicast_socket_send,
    .coap_send_notif_fptr = &arm_uc_multicast_coap_send_notif,
    .create_resource_fptr = &arm_uc_multicast_create_resource
};
const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_connected_nodes_res = {
    0,                  // max_age
    (char*)"1",
    &ota_connected_nodes_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::INTEGER,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_ready_for_multicast_res = {
    0,                  // max_age
    (char*)"2",
    &ota_ready_for_multicast_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::INTEGER,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_command_res = {
    0,                  // max_age
    (char*)"3",
    &ota_command_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::STRING,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_cmd_notify_res = {
    0,                  // max_age
    (char*)"4",
    &ota_cmd_notify_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::STRING,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_dl_status_res = {
    0,                  // max_age
    (char*)"5",
    &ota_dl_status_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::STRING,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_expiration_time_res = {
    0,                  // max_age
    (char*)"6",
    &ota_expiration_time_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::INTEGER,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_dodag_id_res = {
    0,                  // max_age
    (char*)"7",
    &ota_dodag_id_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::STRING,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

int arm_uc_multicast_init(M2MBaseList& list, ConnectorClient& client)
{
    if (arm_uc_multicast_tasklet_id == -1) {
        arm_uc_multicast_tasklet_id = eventOS_event_handler_create(&arm_uc_multicast_tasklet, ARM_LIB_TASKLET_INIT_EVENT);
        if (arm_uc_multicast_tasklet_id == -1) {
            return -1;
        }
    }

    arm_uc_multicast_m2m_client = &client;
    arm_uc_multicast_m2m_object_list = &list;
    arm_uc_multicast_nsdl_handle = client.m2m_interface()->get_nsdl_handle();

    if (!arm_uc_multicast_open_socket(&arm_uc_multicast_socket, OTA_SOCKET_MULTICAST_PORT)) {
        return -1;
    }

    if (!arm_uc_multicast_open_socket(&arm_uc_multicast_missing_frag_socket, OTA_SOCKET_UNICAST_PORT)) {
        return -1;
    }

    if (!arm_uc_multicast_create_static_resources()) {
        return -1;
    }

    arm_uc_multicast_ota_config.response_sending_delay_start = OTA_ACK_TIMER_START;
    arm_uc_multicast_ota_config.response_msg_type = COAP_MSG_TYPE_CONFIRMABLE;

    arm_uc_multicast_ota_config.unicast_socket_addr.port = OTA_SOCKET_UNICAST_PORT;

    arm_uc_multicast_ota_config.link_local_multicast_socket_addr.port = OTA_SOCKET_MULTICAST_PORT;
    memcpy(arm_uc_multicast_ota_config.link_local_multicast_socket_addr.address_tbl, arm_uc_multicast_link_local_multicast_address, 16);

    arm_uc_multicast_ota_config.mpl_multicast_socket_addr.port = OTA_SOCKET_MULTICAST_PORT;
    memcpy(arm_uc_multicast_ota_config.mpl_multicast_socket_addr.address_tbl, arm_uc_multicast_address, 16);

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    arm_uc_multicast_ota_config.device_type = OTA_DEVICE_TYPE1;
    ota_lib_configure(&arm_uc_multicast_ota_config, &arm_uc_ota_function_pointers, 1, OTA_SERVER);
    memset(&fw_info, 0, sizeof(struct manifest_firmware_info_t));
#else
    arm_uc_multicast_ota_config.device_type = OTA_DEVICE_TYPE2;
    ota_lib_configure(&arm_uc_multicast_ota_config, &arm_uc_ota_function_pointers, 1, OTA_CLIENT);
#endif

    return 0;
}

void arm_uc_multicast_deinit()
{
    ota_lib_reset();
    pal_close(&arm_uc_multicast_socket);
    pal_close(&arm_uc_multicast_missing_frag_socket);
}

static void arm_uc_multicast_socket_callback(void *port)
{
    tr_debug("arm_uc_multicast_socket_callback - port %d", (intptr_t)port);

    size_t recv;
    palStatus_t status;
    uint8_t *recv_buffer = (uint8_t*)malloc(RECEIVE_BUFFER_SIZE);
    if (!recv_buffer) {
        tr_error("arm_uc_multicast_socket_callback - failed to allocate receive buffer!");
        return;
    }

    palSocketAddress_t address = {0};
    palSocketLength_t addrlen = 0;

    // Read from the right socket
    if ((intptr_t)port == OTA_SOCKET_MULTICAST_PORT) {
        status = pal_receiveFrom(arm_uc_multicast_socket, recv_buffer, RECEIVE_BUFFER_SIZE, &address, &addrlen, &recv);
    } else {
        status = pal_receiveFrom(arm_uc_multicast_missing_frag_socket, recv_buffer, RECEIVE_BUFFER_SIZE, &address, &addrlen, &recv);
    }

    // Skip data coming from multicast loop
    if (arm_uc_multicast_send_in_progress) {
        tr_info("arm_uc_multicast_socket_callback - multicast loopback data --> skip");
        arm_uc_multicast_send_in_progress = false;
        free(recv_buffer);
        return;
    }

    arm_uc_hub_state_t state = ARM_UC_HUB_getState();
    if (state != ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST) {
        tr_info("arm_uc_multicast_socket_callback - UC not in right state %d!", state);
        free(recv_buffer);
        return;
    }

    if (status == PAL_SUCCESS) {
        uint16_t port;
        ota_ip_address_t ota_addr;
        status = pal_getSockAddrPort(&address, &port);
        if (status != PAL_SUCCESS) {
            tr_error("arm_uc_multicast_socket_callback - pal_getSockAddrPort failed");
        }

        if (address.addressType == PAL_AF_INET6 && status == PAL_SUCCESS) {
            palIpV6Addr_t addr;
            status = pal_getSockAddrIPV6Addr(&address, addr);
            if (status == PAL_SUCCESS) {
                ota_addr.type = OTA_ADDRESS_IPV6; // TODO! can this be something else than ipv6?
                ota_addr.port = port;
                memcpy(ota_addr.address_tbl, &addr, sizeof(addr));
            } else {
                tr_error("arm_uc_multicast_socket_callback - pal_getSockAddrIPV6Addr failed");
            }
        }

        if (status == PAL_SUCCESS) {
            ota_socket_receive_data(recv, recv_buffer, &ota_addr);
        }
    } else {
        tr_debug("arm_uc_multicast_socket_callback - read error %" PRIx32, status);
    }

    free(recv_buffer);
}

static void arm_uc_multicast_tasklet(struct arm_event_s *event)
{
    if (ARM_UC_OTA_MULTICAST_TIMER_EVENT == event->event_type) {
        ota_timer_expired(event->event_id);
    } else if (ARM_UC_OTA_MULTICAST_UC_HUB_EVENT == event->event_type) {
        ARM_UC_HUB_setState((arm_uc_hub_state_t)event->event_data);
    } else if (ARM_UC_OTA_MULTICAST_DL_DONE_EVENT == event->event_type) {
        tr_info("arm_uc_multicast_tasklet - download completed");
        ota_firmware_pulled();
    } else {
        tr_error("arm_uc_multicast_tasklet - unknown event!");
    }
}

// Start of otaLIB callback functions
/*
 * request_timer_fptr() Function pointer for requesting timer event
 *            Parameters:
 *              -Timer ID of requested timer
 *              -Timeout time in milliseconds
 */
static void arm_uc_multicast_request_timer(uint8_t timer_id, uint32_t timeout)
{
    tr_info("arm_uc_multicast_request_timer - id %d, timeout %d", timer_id, timeout);
    eventOS_event_timer_request(timer_id, ARM_UC_OTA_MULTICAST_TIMER_EVENT, arm_uc_multicast_tasklet_id, timeout);
}

/*
 * cancel_timer_fptr() Function pointer for canceling requested timer event
 *            Parameters:
 *              -Timer ID of cancelled timer
 */
static void arm_uc_multicast_cancel_timer(uint8_t timer_id)
{
    eventOS_event_timer_cancel(timer_id, arm_uc_multicast_tasklet_id);
}

/*
 * store_new_ota_process_fptr() Function pointer for storing new OTA process to storage
 *            Parameters:
 *              -Added OTA process ID
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_store_new_ota_process(uint32_t ota_process_id)
{
    tr_debug("arm_uc_multicast_store_new_ota_process");
    assert(stored_ota_processes.ota_process_count == 0);
    stored_ota_processes.ota_process_count = 1;
    arm_uc_multicast_stored_ota_process_id = ota_process_id;
    return OTA_OK;
}

/*
 * read_stored_ota_processes_fptr() Function pointer for reading stored OTA processes from storage
 *            Parameters:
 *              -Stored OTA processes
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_read_stored_ota_processes(ota_processes_t* ota_processes)
{
    tr_debug("arm_uc_multicast_read_stored_ota_processes");
    // when called, ota_processes->ota_process_ids_tbl is allocated by otaLIB
    ota_processes->ota_process_count = stored_ota_processes.ota_process_count;
    if(stored_ota_processes.ota_process_count)
        ota_processes->ota_process_ids_tbl[0] = arm_uc_multicast_stored_ota_process_id;
    return OTA_OK;
}

/*
 * remove_stored_ota_process_fptr() Function pointer for removing stored OTA process from storage
 *            Parameters:
 *              -Removed OTA process ID
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_remove_stored_ota_process(uint32_t ota_process_id)
{
    tr_debug("arm_uc_multicast_remove_stored_ota_process");

    assert(stored_ota_processes.ota_process_count == 1);
    assert(arm_uc_multicast_stored_ota_process_id == ota_process_id);
    stored_ota_processes.ota_process_count = 0;
    arm_uc_multicast_stored_ota_process_id = 0;
    return OTA_OK;
}

/*
 * store_state_fptr() Function pointer for OTA library for storing one OTA process state to storage managed by application
 *            Parameters:
 *              -Stored OTA state
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_store_state(ota_download_state_t* ota_state)
{
    tr_debug("arm_uc_multicast_store_state - state %d", ota_state->ota_state);
    assert(arm_uc_multicast_stored_ota_process_id == ota_state->ota_process_id);
    stored_download_state.ota_process_id = ota_state->ota_process_id;
    stored_download_state.ota_state = ota_state->ota_state;
    if (stored_download_state.fragments_bitmask_length != ota_state->fragments_bitmask_length){
        free(stored_download_state.fragments_bitmask_ptr);
        if (ota_state->fragments_bitmask_length > 0) {
            stored_download_state.fragments_bitmask_ptr = (uint8_t*)malloc(ota_state->fragments_bitmask_length);
            memcpy(stored_download_state.fragments_bitmask_ptr, ota_state->fragments_bitmask_ptr, ota_state->fragments_bitmask_length);
        } else {
            stored_download_state.fragments_bitmask_ptr = 0;
        }
    }
    stored_download_state.fragments_bitmask_length = ota_state->fragments_bitmask_length;

    return OTA_OK;
}

/*
 * read_state_fptr() Function pointer for OTA library for reading one OTA process state from storage managed by application
 *            Parameters:
 *              -OTA process ID for selecting which OTA process state is read
 *              -Data pointer where OTA process state is read
 *               NOTE: OTA library user (OTA application) will allocate memory for data pointers of ota_download_state_t and
 *                     OTA library will free these data pointers with free function given in configure
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_read_state(uint32_t process_id, ota_download_state_t* ota_state)
{
    tr_debug("arm_uc_multicast_read_state");

    assert(stored_download_state.ota_process_id == process_id);
    ota_state->ota_process_id = stored_download_state.ota_process_id;
    ota_state->ota_state = stored_download_state.ota_state;
    ota_state->fragments_bitmask_length = stored_download_state.fragments_bitmask_length;
    if (stored_download_state.fragments_bitmask_length > 0)	{
        ota_state->fragments_bitmask_ptr = (uint8_t*)malloc(ota_state->fragments_bitmask_length);
        memcpy(ota_state->fragments_bitmask_ptr, stored_download_state.fragments_bitmask_ptr, ota_state->fragments_bitmask_length);
    } else {
        ota_state->fragments_bitmask_ptr = 0;
    }

    return OTA_OK;
}

/*
 * store_parameters_fptr() Function pointer for storing OTA parameters to storage
 *            Parameters:
 *              -Stored OTA parameters
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_store_parameters(ota_parameters_t* ota_parameters)
{
    tr_debug("arm_uc_multicast_store_parameters");

    assert(arm_uc_multicast_stored_ota_process_id == ota_parameters->ota_process_id);
    stored_ota_parameters.ota_process_id = ota_parameters->ota_process_id;
    stored_ota_parameters.device_type = ota_parameters->device_type;
    stored_ota_parameters.response_sending_delay_start = ota_parameters->response_sending_delay_start;
    stored_ota_parameters.response_sending_delay_end = ota_parameters->response_sending_delay_end;
    stored_ota_parameters.fw_download_report_config = ota_parameters->fw_download_report_config;
    stored_ota_parameters.multicast_used_flag = ota_parameters->multicast_used_flag;

    if (stored_ota_parameters.fw_name_ptr) {
        free(stored_ota_parameters.fw_name_ptr);
        stored_ota_parameters.fw_name_ptr = 0;
    }

    stored_ota_parameters.fw_name_length = ota_parameters->fw_name_length;
    if (stored_ota_parameters.fw_name_length) {
        stored_ota_parameters.fw_name_ptr = (uint8_t*)malloc(stored_ota_parameters.fw_name_length);
        memcpy(stored_ota_parameters.fw_name_ptr, ota_parameters->fw_name_ptr, stored_ota_parameters.fw_name_length);
    }

    if (stored_ota_parameters.fw_version_ptr) {
        free(stored_ota_parameters.fw_version_ptr);
        stored_ota_parameters.fw_version_ptr = 0;
    }

    stored_ota_parameters.fw_version_length = ota_parameters->fw_version_length;

    if(stored_ota_parameters.fw_version_length) {
        stored_ota_parameters.fw_version_ptr = (uint8_t*)malloc(stored_ota_parameters.fw_version_length);
        memcpy(stored_ota_parameters.fw_version_ptr, ota_parameters->fw_version_ptr, stored_ota_parameters.fw_version_length);
    }

    stored_ota_parameters.fw_segment_count = ota_parameters->fw_segment_count;
    stored_ota_parameters.fw_total_byte_count = ota_parameters->fw_total_byte_count;
    stored_ota_parameters.fw_fragment_count = ota_parameters->fw_fragment_count;
    stored_ota_parameters.fw_fragment_byte_count = ota_parameters->fw_fragment_byte_count;
    stored_ota_parameters.fw_fragment_sending_interval_uni = ota_parameters->fw_fragment_sending_interval_uni;
    stored_ota_parameters.fw_fragment_sending_interval_mpl = ota_parameters->fw_fragment_sending_interval_mpl;
    memcpy(stored_ota_parameters.whole_fw_checksum_tbl, ota_parameters->whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH);
    stored_ota_parameters.fallback_timeout = ota_parameters->fallback_timeout;
    stored_ota_parameters.missing_fragments_req_addr.port = ota_parameters->missing_fragments_req_addr.port;
    stored_ota_parameters.missing_fragments_req_addr.type = ota_parameters->missing_fragments_req_addr.type;
    memcpy(stored_ota_parameters.missing_fragments_req_addr.address_tbl, ota_parameters->missing_fragments_req_addr.address_tbl, 16);

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    stored_ota_parameters.delivered_image_resource_name_length = ota_parameters->delivered_image_resource_name_length;
    if(stored_ota_parameters.delivered_image_resource_name_length) {
        stored_ota_parameters.delivered_image_resource_name_ptr = (uint8_t*)malloc(stored_ota_parameters.delivered_image_resource_name_length);
        if (stored_ota_parameters.delivered_image_resource_name_ptr) {
            memcpy(stored_ota_parameters.delivered_image_resource_name_ptr, ota_parameters->delivered_image_resource_name_ptr, stored_ota_parameters.delivered_image_resource_name_length);
        } else {
            tr_error("arm_uc_multicast_store_parameters - failed to allocate delivered_image_resource_name_ptr!!!");
            return OTA_OUT_OF_MEMORY;
        }

    }
    stored_ota_parameters.pull_url_length = ota_parameters->pull_url_length;
    if (stored_ota_parameters.pull_url_length) {
        stored_ota_parameters.pull_url_ptr = (uint8_t*)malloc(stored_ota_parameters.pull_url_length);
        if (stored_ota_parameters.pull_url_ptr) {
            memcpy(stored_ota_parameters.pull_url_ptr, ota_parameters->pull_url_ptr, stored_ota_parameters.pull_url_length);
        } else {
            tr_error("arm_uc_multicast_store_parameters - failed to allocate pull_url_ptr!!!");
            return OTA_OUT_OF_MEMORY;
        }
    }
#else
    assert(ota_parameters->delivered_image_resource_name_length == 0);
    stored_ota_parameters.delivered_image_resource_name_length = 0;
    stored_ota_parameters.delivered_image_resource_name_ptr = 0;

    assert(ota_parameters->pull_url_length == 0);
    stored_ota_parameters.pull_url_length = 0;
    stored_ota_parameters.pull_url_ptr = 0;
#endif

    return OTA_OK;
}

/*
 * read_parameters_fptr() Function pointer for reading one OTA process parameters from storage
 *            Parameters:
 *              -OTA process ID for selecting which OTA process parameters are read
 *              -Data pointer where OTA process parameters are read
 *               NOTE: OTA library user (OTA application) will allocate memory for data pointers of ota_parameters_t and
 *                     OTA library will free these data pointers with free function given in configure
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_read_parameters(uint32_t process_id, ota_parameters_t* ota_parameters)
{
    tr_debug("arm_uc_multicast_read_parameters");

    assert(stored_ota_parameters.ota_process_id == process_id);
    ota_parameters->ota_process_id = stored_ota_parameters.ota_process_id;
    ota_parameters->device_type = stored_ota_parameters.device_type;
    ota_parameters->response_sending_delay_start = stored_ota_parameters.response_sending_delay_start;
    ota_parameters->response_sending_delay_end = stored_ota_parameters.response_sending_delay_end;
    ota_parameters->fw_download_report_config = stored_ota_parameters.fw_download_report_config;
    ota_parameters->multicast_used_flag = stored_ota_parameters.multicast_used_flag;
    ota_parameters->fw_name_length = stored_ota_parameters.fw_name_length;
    if (ota_parameters->fw_name_length > 0) {
        ota_parameters->fw_name_ptr = (uint8_t*)malloc(ota_parameters->fw_name_length);
        memcpy(ota_parameters->fw_name_ptr, stored_ota_parameters.fw_name_ptr, ota_parameters->fw_name_length);
    }

    ota_parameters->fw_version_length = stored_ota_parameters.fw_version_length;
    if (ota_parameters->fw_version_length > 0) {
        ota_parameters->fw_version_ptr = (uint8_t*)malloc(ota_parameters->fw_version_length);
        memcpy(ota_parameters->fw_version_ptr, stored_ota_parameters.fw_version_ptr, ota_parameters->fw_version_length);
    }

    ota_parameters->fw_segment_count = stored_ota_parameters.fw_segment_count;
    ota_parameters->fw_total_byte_count = stored_ota_parameters.fw_total_byte_count;
    ota_parameters->fw_fragment_count = stored_ota_parameters.fw_fragment_count;
    ota_parameters->fw_fragment_byte_count = stored_ota_parameters.fw_fragment_byte_count;
    ota_parameters->fw_fragment_sending_interval_uni = stored_ota_parameters.fw_fragment_sending_interval_uni;
    ota_parameters->fw_fragment_sending_interval_mpl = stored_ota_parameters.fw_fragment_sending_interval_mpl;
    memcpy(ota_parameters->whole_fw_checksum_tbl, stored_ota_parameters.whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH);
    ota_parameters->fallback_timeout = stored_ota_parameters.fallback_timeout;
    ota_parameters->missing_fragments_req_addr.port = stored_ota_parameters.missing_fragments_req_addr.port;
    ota_parameters->missing_fragments_req_addr.type = stored_ota_parameters.missing_fragments_req_addr.type;
    memcpy(ota_parameters->missing_fragments_req_addr.address_tbl, stored_ota_parameters.missing_fragments_req_addr.address_tbl, 16);

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    ota_parameters->delivered_image_resource_name_length = stored_ota_parameters.delivered_image_resource_name_length;
    if(ota_parameters->delivered_image_resource_name_length) {
        ota_parameters->delivered_image_resource_name_ptr = (uint8_t*)malloc(ota_parameters->delivered_image_resource_name_length);
        if (ota_parameters->delivered_image_resource_name_ptr) {
            memcpy(ota_parameters->delivered_image_resource_name_ptr, stored_ota_parameters.delivered_image_resource_name_ptr, ota_parameters->delivered_image_resource_name_length);
        } else {
            tr_error("arm_uc_multicast_read_parameters - failed to allocate delivered_image_resource_name_ptr!!!");
            return OTA_OUT_OF_MEMORY;
        }

    }
    ota_parameters->pull_url_length = stored_ota_parameters.pull_url_length;
    if (ota_parameters->pull_url_length) {
        ota_parameters->pull_url_ptr = (uint8_t*)malloc(ota_parameters->pull_url_length);
        if (ota_parameters->pull_url_ptr) {
            memcpy(ota_parameters->pull_url_ptr, stored_ota_parameters.pull_url_ptr, ota_parameters->pull_url_length);
        } else {
            tr_error("arm_uc_multicast_read_parameters - failed to allocate pull_url_ptr!!!");
            return OTA_OUT_OF_MEMORY;
        }
    }
#else
    // 'only used in router'
    assert(stored_ota_parameters.delivered_image_resource_name_length == 0);
    ota_parameters->delivered_image_resource_name_length = 0;
    ota_parameters->delivered_image_resource_name_ptr = 0;

    assert(stored_ota_parameters.pull_url_length == 0);
    ota_parameters->pull_url_length = 0;
    ota_parameters->pull_url_ptr = 0;
#endif

    return OTA_OK;
}

/*
 * get_fw_storing_capacity_fptr() Function pointer for getting byte count of firmware image storing storage
 *            Return value:
 *              -Byte count of total storage for firmware images
 */
static uint32_t arm_uc_multicast_get_fw_storing_capacity()
{
    return MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE / MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS;
}

/*
 * write_fw_bytes_fptr() Function pointer for writing firmware bytes to storage
 *            Parameters:
 *              -OTA process ID
 *              -Byte offset (tells where data to be written)
 *              -To be written data byte count
 *              -Data pointer to be written data
 *            Return value:
 *              -Written byte count
 */
static uint32_t arm_uc_multicast_write_fw_bytes(uint32_t ota_process_id, uint32_t offset, uint32_t count, uint8_t* from)
{
    tr_debug("arm_uc_multicast_write_fw_bytes, offset %d, bytes %d", offset, count);

    assert(arm_uc_multicast_stored_ota_process_id == ota_process_id);
    assert(stored_ota_processes.ota_process_count == 1);

    arm_uc_buffer_t buffer;
    buffer.size_max = count;
    buffer.size = count;
    buffer.ptr = from;

    arm_uc_error_t retval = ARM_UC_FirmwareManager.WriteWithOffset(&buffer, offset);
    if (retval.code != ERR_NONE) {
        tr_error("arm_uc_multicast_write_fw_bytes, write operation failed!");
        count = 0;
    }

    return count;
}

/*
 * read_fw_bytes_fptr() Function pointer for reading firmware bytes from storage
 *            Parameters:
 *              -OTA process ID
 *              -Byte offset (tells where data is to read)
 *              -Data byte count to be read
 *              -Data pointer to data to be read
 *            Return value:
 *              -Read byte count
 */
static uint32_t arm_uc_multicast_read_fw_bytes(uint32_t ota_process_id, uint32_t offset, uint32_t count, uint8_t* to)
{
    tr_debug("arm_uc_multicast_read_fw_bytes, offset %d, count %d", offset, count);
    assert(arm_uc_multicast_stored_ota_process_id == ota_process_id);
    assert(stored_ota_processes.ota_process_count == 1);
    arm_uc_buffer_t buffer;
    buffer.size_max = count;
    buffer.size = count;
    buffer.ptr = to;
    arm_uc_error_t ret = ARM_UC_FirmwareManager.Read(&buffer, offset);
    if (ret.code != ERR_NONE) {
        tr_error("ARM_UC_FirmwareManager.Read failed with %d", ret.code);
        count = 0;
    }
    return count;
}

/*
 * send_update_fw_cmd_received_info_fptr() Function pointer for telling to application that firmware image can be taken in use
 *                                                  NOTE: OTA user (backend) must remove OTA process from data storage with DELETE command
 *            Parameters:
 *              -OTA process ID
 *              -Delay time in seconds before taking new firmware in use
 */
static void arm_uc_multicast_send_update_fw_cmd_received_info(uint32_t ota_process_id, uint16_t delay)
{
    tr_info("arm_uc_multicast_send_update_fw_cmd_received_info");
    ARM_UC_HUB_setRebootDelay(delay);
    arm_uc_multicast_send_event(ARM_UC_HUB_STATE_LAST_FRAGMENT_STORE_DONE);
}

static void arm_uc_multicast_update_device_registration()
{
    tr_info("arm_uc_multicast_update_device_registration");
    arm_uc_multicast_m2m_client->update_registration();
}

/*
 * socket_send_fptr() Function pointer for sending data to socket
 *            Parameters:
 *              -Sent destination address
 *              -Sent payload length
 *            Return value:
 *              -Success: 0
 *              -Invalid socket ID: -1
 *              -Socket memory allocation fail: -2
 *              -TCP state not established: -3
 *              -Socket TX process busy: -4
 *              -Packet too short: -6
 */
static int8_t arm_uc_multicast_socket_send(ota_ip_address_t* destination, uint16_t count, uint8_t* payload)
{
    tr_debug("arm_uc_multicast_socket_send");

    size_t sent;
    palSocketAddress_t pal_addr = { 0 , { 0 } };
    palSocket_t socket;

    if (destination->port == OTA_SOCKET_MULTICAST_PORT) {
        socket = arm_uc_multicast_socket;
    } else {
        socket = arm_uc_multicast_missing_frag_socket;
    }

    tr_info("arm_uc_multicast_socket_send - address %s ", trace_ipv6(destination->address_tbl));

    palIpV6Addr_t addr;
    memcpy(addr, destination->address_tbl, 16);
    if (pal_setSockAddrIPV6Addr(&pal_addr, addr) != PAL_SUCCESS) {
        tr_error("arm_uc_multicast_socket_send - failed to set pal_setSockAddrIPV6Addr");
        return -1;
    }

    if (pal_setSockAddrPort(&pal_addr, destination->port) != PAL_SUCCESS) {
        tr_error("arm_uc_multicast_socket_send - failed to set pal_setSockAddrPort");
        return -1;
    }

    arm_uc_multicast_send_in_progress = true;

    return pal_sendTo(socket, payload, count, &pal_addr, sizeof(pal_addr), &sent);
}

/*
 * coap_send_notif_fptr() Function pointer for sending notifications via CoAP
 *            Parameters:
 *              -Sent destination address
 *              -Pointer to token to be used
 *              -Token length
 *              -Pointer to payload to be sent
 *              -Payload length
 *              -Pointer to observe number to be sent
 *              -Observe number len
 *              -Observation message type (confirmable or non-confirmable)
 *            Return value:
 *              -Success, observation messages message ID: !0
 *              -Failure: 0
 */
static uint16_t arm_uc_multicast_coap_send_notif(char *path, uint8_t *payload_ptr, uint16_t payload_len)
{
    uint16_t ret = 0;

    if (!strcmp(path, ota_resource_dl_status)) {
        ret = arm_uc_multicast_dl_status_res->set_value(payload_ptr, payload_len);
    } else if (!strcmp(path, ota_resource_command_status)) {
        ret = arm_uc_multicast_cmd_status_res->set_value(payload_ptr, payload_len);
    }

    return ret;
}

static ota_error_code_e arm_uc_multicast_create_resource(const char *path_ptr, const char *type_ptr, int32_t flags,
                                                         bool is_observable, ota_coap_callback_t *callback_ptr,
                                                         bool publish_uri)
{
    tr_debug("arm_uc_multicast_create_resource - path %s", path_ptr);

    if (arm_uc_multicast_object == NULL || arm_uc_multicast_object_inst == NULL) {
        tr_error("arm_uc_multicast_create_resource - object not yet created!");
        return OTA_RESOURCE_CREATING_FAILED;
    }

    sn_nsdl_dynamic_resource_parameters_s *dyn_resource_structure_ptr = (sn_nsdl_dynamic_resource_parameters_s*)malloc(sizeof(sn_nsdl_dynamic_resource_parameters_s));

    if (dyn_resource_structure_ptr == NULL) {
        tr_error("arm_uc_multicast_create_resource - failed to create dyn_resource_structure_ptr!");
        return OTA_OUT_OF_MEMORY;
    }

    memset(dyn_resource_structure_ptr, 0, sizeof(sn_nsdl_dynamic_resource_parameters_s));
    dyn_resource_structure_ptr->static_resource_parameters = (sn_nsdl_static_resource_parameters_s*)malloc(sizeof(sn_nsdl_static_resource_parameters_s));

    if (dyn_resource_structure_ptr->static_resource_parameters == NULL) {
        tr_error("arm_uc_multicast_create_resource - failed to create static_resource_parameters!");
        free(dyn_resource_structure_ptr);
        return OTA_OUT_OF_MEMORY;
    }

    memset(dyn_resource_structure_ptr->static_resource_parameters, 0, sizeof(sn_nsdl_static_resource_parameters_s));

    dyn_resource_structure_ptr->access = (sn_grs_resource_acl_e)flags;
    dyn_resource_structure_ptr->sn_grs_dyn_res_callback = callback_ptr;
    dyn_resource_structure_ptr->static_resource_parameters->mode = SN_GRS_DYNAMIC;
    dyn_resource_structure_ptr->static_resource_parameters->path = (char*)path_ptr;
    dyn_resource_structure_ptr->static_resource_parameters->resource_type_ptr = (char*)type_ptr;
    dyn_resource_structure_ptr->static_resource_parameters->free_on_delete = 1;
    dyn_resource_structure_ptr->observable = is_observable;
    dyn_resource_structure_ptr->free_on_delete = 1;
    dyn_resource_structure_ptr->publish_uri = publish_uri;

    M2MBase::lwm2m_parameters_s *params = (M2MBase::lwm2m_parameters_s*)malloc(sizeof(M2MBase::lwm2m_parameters_s));

    if (params == NULL) {
        tr_error("arm_uc_multicast_create_resource - failed to create lwm2m_parameters_s!");
        return OTA_OUT_OF_MEMORY;
    }

    memset(params, 0, sizeof(M2MBase::lwm2m_parameters_s));
    params->dynamic_resource_params = dyn_resource_structure_ptr;
    params->identifier.name = (char*)path_ptr;
    params->base_type = M2MBase::Resource;
    params->data_type = M2MBase::STRING;
    params->free_on_delete = true;

    if (!arm_uc_multicast_object_inst->create_dynamic_resource(params, M2MResourceInstance::STRING, is_observable)) {
        tr_error("arm_uc_multicast_create_resource - failed to create resource!");
        return OTA_RESOURCE_CREATING_FAILED;
    }

    return OTA_OK;
}

static bool arm_uc_multicast_create_static_resources()
{
    if (!arm_uc_multicast_object) {
        arm_uc_multicast_object = M2MInterfaceFactory::create_object(MULTICAST_OBJECT_ID);
        if (arm_uc_multicast_object) {
            arm_uc_multicast_object->set_register_uri(false);
            arm_uc_multicast_object_inst = arm_uc_multicast_object->create_object_instance();
        } else {
            tr_error("arm_uc_multicast_create_static_resources - failed to create object!");
            return false;
        }
    }

    if (arm_uc_multicast_object_inst) {
        arm_uc_multicast_object_inst->set_register_uri(false);
        if (!arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_ota_connected_nodes_res, M2MResourceInstance::INTEGER)) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_ota_connected_nodes_res!");
            return false;
        }

        if (!arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_ota_ready_for_multicast_res, M2MResourceInstance::INTEGER)) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_ota_ready_for_multicast_res!");
            return false;
        }

        if (!arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_ota_command_res, M2MResourceInstance::STRING)) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_ota_command_res!");
            return false;
        }

        if (!arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_expiration_time_res, M2MResourceInstance::INTEGER)) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_expiration_time_res!");
            return false;
        }

        arm_uc_multicast_dl_status_res = arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_ota_dl_status_res, M2MResourceInstance::STRING);
        if (arm_uc_multicast_dl_status_res) {
            arm_uc_multicast_dl_status_res->set_auto_observable(true);
        } else {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_ota_dl_status_res!");
            return false;
        }

        arm_uc_multicast_cmd_status_res = arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_ota_cmd_notify_res, M2MResourceInstance::STRING);
        if (arm_uc_multicast_cmd_status_res) {
            arm_uc_multicast_cmd_status_res->set_auto_observable(true);
        } else {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_ota_cmd_notify_res!");
            return false;
        }

        M2MResource *res = arm_uc_multicast_object_inst->create_static_resource(&arm_uc_multicast_dodag_id_res, M2MResourceInstance::STRING);
        if (res) {
            char addr[45] = {0};
            read_dodag_info(addr);
            res->set_value((const unsigned char*)addr, strlen(addr));
            res->publish_value_in_registration_msg(true);
        } else {
            tr_error("arm_uc_multicast_create_static_resources - failed to create arm_uc_multicast_dodag_id_res!");
            return false;
        }

        arm_uc_multicast_m2m_object_list->push_back(arm_uc_multicast_object);
    } else {
        tr_error("arm_uc_multicast_create_static_resources - failed to create object instance!");
        return false;
    }

    return true;
}

static bool arm_uc_multicast_open_socket(palSocket_t *socket, uint16_t port)
{
    palStatus_t status;
    palSocketAddress_t bind_address;
    palIpV6Addr_t interface_address6;

    memset(&bind_address, 0, sizeof(palSocketAddress_t));
    memset(&interface_address6, 0, sizeof(interface_address6));

    status = pal_asynchronousSocketWithArgument(PAL_AF_INET6,
                                                PAL_SOCK_DGRAM,
                                                true,
                                                0,
                                                arm_uc_multicast_socket_callback,
                                                (void*)port,
                                                socket);

    if (PAL_SUCCESS != status) {
        tr_error("arm_uc_multicast_open_socket error : %" PRIx32, status);
        return false;
    }

    status = pal_setSockAddrIPV6Addr(&bind_address, interface_address6);
    if (PAL_SUCCESS != status) {
        tr_error("arm_uc_multicast_open_socket - pal_setSockAddrIPV6Addr err: %" PRIx32, status);
        return false;
    }

    status = pal_setSockAddrPort(&bind_address, port);
    if (PAL_SUCCESS != status) {
        tr_error("arm_uc_multicast_open_socket - setSockAddrPort err: %" PRIx32, status);
        return false;
    }

    status = pal_bind(*socket, &bind_address, sizeof(bind_address));
    if (PAL_SUCCESS != status) {
        tr_error("arm_uc_multicast_open_socket - pal_bind err: %" PRIx32, status);
        return false;
    }

    tr_info("arm_uc_multicast_open_socket - opened OTA socket (port=%u)", port);

    return true;
}

bool arm_uc_multicast_interface_configure(int8_t interface_id)
{
    tr_info("arm_uc_multicast_interface_configure - interface id %d", interface_id);

    arm_uc_multicast_interface_id = interface_id;
    return true;
}

uint8_t ota_lwm2m_dodag_id(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_nsdl_addr_s *address, sn_nsdl_capab_e proto)
{
    tr_debug("ota_lwm2m_dodag_id - interface id %d", arm_uc_multicast_interface_id);
    (void)proto;

    char addr[45] = {0};
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_NOT_FOUND;
    if (coap->msg_code == COAP_MSG_CODE_REQUEST_GET) {
        if (read_dodag_info(addr)) {
            msg_code = COAP_MSG_CODE_RESPONSE_CONTENT;
        }
    }

    return arm_uc_multicast_send_coap_response(handle, coap, msg_code, address, addr);
}

static bool read_dodag_info(char *address)
{
// Border router API not available in simulator env since we are using quite old nanomesh6-rel branch
#if !defined(TARGET_LIKE_MBED) || !defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    rpl_dodag_info_t dodag_info;
    if (rpl_read_dodag_info(&dodag_info, arm_uc_multicast_interface_id)) {
        ip6tos(dodag_info.dodag_id, address);
        tr_debug("read_dodag_info - id address: %s", address);
        return true;
    } else {
        tr_error("read_dodag_info - DODAG ID not found");
        return false;
    }
#else
    bbr_information_t bbr_info = {0};
    if (ws_bbr_info_get(arm_uc_multicast_interface_id, &bbr_info) == 0) {
        ip6tos(bbr_info.dodag_id, address);
        tr_debug("read_dodag_info - address: %s", address);
        return true;
    } else {
        tr_error("read_dodag_info - DODAG ID not found");
        return false;
    }
#endif
}

static uint8_t arm_uc_multicast_send_coap_response(struct nsdl_s *handle, sn_coap_hdr_s *coap, sn_coap_msg_code_e msg_code, sn_nsdl_addr_s *address, const char* payload)
{
    sn_coap_hdr_s *resp;

    resp = sn_nsdl_build_response(handle, coap, msg_code);
    if (resp) {
        resp->payload_ptr = (uint8_t *)payload;
        resp->payload_len = strlen(payload);
    } else {
        tr_error("arm_uc_multicast_send_coap_response - failed to create response");
    }

    if (sn_nsdl_send_coap_message(handle, address, resp) != 0) {
        tr_error("arm_uc_multicast_send_coap_response - failed to send response");
    }

    sn_nsdl_release_allocated_coap_msg_mem(handle, resp);

    return 0; // TODO! Check return code
}

static ota_error_code_e arm_uc_multicast_start_received(ota_parameters_t* ota_parameters)
{
    ota_error_code_e return_value = OTA_PARAMETER_FAIL;

#if defined(ARM_UC_MULTICAST_ENABLE) && (ARM_UC_MULTICAST_ENABLE == 1) && defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    if (ota_parameters->pull_url_length) {
        tr_info("arm_uc_multicast_start_received - Received pull url: %.*s", ota_parameters->pull_url_length, ota_parameters->pull_url_ptr);
        fw_info.size = ota_parameters->fw_total_byte_count;
        fw_info.hash.ptr = ota_parameters->whole_fw_checksum_tbl;
        fw_info.hash.size = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        fw_info.hash.size_max = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        fw_info.uri.ptr = ota_parameters->pull_url_ptr;
        fw_info.uri.size = ota_parameters->pull_url_length;
        fw_info.uri.size_max = ota_parameters->pull_url_length;
        fw_info.timestamp = 1;

        fw_info.installedHash.ptr = ota_parameters->whole_fw_checksum_tbl;
        fw_info.installedHash.size = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        fw_info.installedHash.size_max = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        fw_info.installedSize = ota_parameters->fw_total_byte_count;
        fw_info.format.bytes[0] = 1;
        fw_info.cipherMode = ARM_UC_MM_CIPHERMODE_NONE;
        ARM_UC_HUB_setExternalDownload(&fw_info, arm_uc_multicast_tasklet_id);
        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP);
        return_value = OTA_OK;
    }
    else
#endif
    if (!arm_uc_multicast_fwmanager_prepared) {
        arm_uc_multicast_fwmanager_hashbuf.ptr = ota_parameters->whole_fw_checksum_tbl;
        arm_uc_multicast_fwmanager_hashbuf.size = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        arm_uc_multicast_fwmanager_hashbuf.size_max = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        arm_uc_multicast_fwmanager_configuration.mode = UCFM_MODE_NONE_SHA_256; // possible encryption handled in node
        arm_uc_multicast_fwmanager_configuration.key = 0;
        arm_uc_multicast_fwmanager_configuration.iv = 0;
        arm_uc_multicast_fwmanager_configuration.hash = &arm_uc_multicast_fwmanager_hashbuf;
        arm_uc_multicast_fwmanager_configuration.package_id = 0; // the slot where firmware gets stored
        arm_uc_multicast_fwmanager_configuration.package_size = ota_parameters->fw_total_byte_count;
#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
        arm_uc_multicast_fwmanager_configuration.is_delta = 0; // always not delta, as we want to just store this and pass along
#endif
        arm_uc_multicast_fwmanager_firmware_details.version = 1;
        arm_uc_multicast_fwmanager_firmware_details.size = ota_parameters->fw_total_byte_count;
        memcpy(arm_uc_multicast_fwmanager_firmware_details.hash, arm_uc_multicast_fwmanager_hashbuf.ptr, ARM_UC_SHA256_SIZE);
        memcpy(arm_uc_multicast_fwmanager_firmware_details.campaign, "multicastcampaig", 16);
        arm_uc_multicast_fwmanager_firmware_details.signatureSize = 0;

        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST);

        arm_uc_error_t ret = ARM_UC_FirmwareManager.Prepare(&arm_uc_multicast_fwmanager_configuration, &arm_uc_multicast_fwmanager_firmware_details, &arm_uc_multicast_fwmanager_armbuffer);
        if (ret.code == ERR_NONE)
        {
            arm_uc_multicast_fwmanager_prepared = true;
            return_value = OTA_OK;
        }
        else {
            tr_warn("ARM_UC_FirmwareManager.Prepare failed with %d", ret.code);
        }
    }
    else {
        return_value = OTA_OK;
    }
    return return_value;
}

static void arm_uc_multicast_process_finished(uint32_t process_id)
{
    tr_info("arm_uc_multicast_process_finished");
    arm_uc_multicast_send_event(ARM_UC_HUB_STATE_IDLE);
    arm_uc_multicast_fwmanager_prepared = false;
}

static void arm_uc_multicast_send_event(arm_uc_hub_state_t state)
{
    arm_uc_multicast_event.data.event_data = state;
    arm_uc_multicast_event.data.event_type = ARM_UC_OTA_MULTICAST_UC_HUB_EVENT;
    arm_uc_multicast_event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
    arm_uc_multicast_event.data.receiver = arm_uc_multicast_tasklet_id;
    eventOS_event_send_user_allocated(&arm_uc_multicast_event);
}
#endif
