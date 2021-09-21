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

#include "multicast_config.h"

#if defined(LIBOTA_ENABLED) && (LIBOTA_ENABLED)

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "sn_coap_header.h"
#include "pal.h"
#include "m2mtimer.h"
#include "multicast.h"
#include "mbed-client/m2minterfacefactory.h"
#include "m2mobject.h"
#include "m2mobjectinstance.h"
#include "m2mresource.h"
#include "MbedCloudClient.h"

#if defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)
extern char g_mesh_network_id[OTA_MAX_MESH_NETWORK_ID_LENGTH];
extern void build_mesh_shared_file_name();
extern  int8_t arm_uc_multicast_mesh_simulator_send(ota_ip_address_t *destination, uint16_t count, uint8_t *payload);

#if defined(ARM_UC_MULTICAST_NODE_MODE)
#include "pal_plat_rtos.h"
palThreadID_t tid;
extern void thread_node(void const *arg);
#endif

#endif

#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
#include "socket_api.h"
#include "ip6string.h"
#include "arm_uc_types.h"
#include "net_interface.h"

#if defined(MULTICAST_UCHUB_INTEGRATION)
#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update_client_hub_state_machine.h"
#include "update-client-common/arm_uc_config.h"

static arm_uc_hub_state_t   arm_uc_hub_state = ARM_UC_HUB_STATE_UNINITIALIZED;

#endif

#include "randLIB.h"

#if defined(ARM_UC_MULTICAST_NODE_MODE)
#include "net_rpl.h"
#include "ws_management_api.h"
#else
extern "C" {
#include "ws_bbr_api.h"
};
#endif // defined(ARM_UC_MULTICAST_NODE_MODE)

#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR

#include "libota.h"
#include "otaLIB.h"
#include "otaLIB_resources.h"

// including UC defines TRACE_GROUP already
#undef TRACE_GROUP
#define TRACE_GROUP "MULTICAST"

#define OTA_SOCKET_UNICAST_PORT             48380 // Socket port number for OTA (used for Unicast)
#define OTA_SOCKET_MULTICAST_PORT           48381 // Socket port number for OTA (used for Link local multicast and MPL multicast)
#define MULTICAST_OBJECT_ID                 "33458"
#define RECEIVE_BUFFER_SIZE                 1200  // Max radio packet size

static bool arm_uc_multicast_manifest_rejected = false;
static bool arm_uc_multicast_send_in_progress = false;
static bool arm_uc_multicast_init_done = false;

static void             arm_uc_multicast_request_timer(uint8_t timer_id, uint32_t timeout);
static void             arm_uc_multicast_cancel_timer(uint8_t timer_id);
static ota_error_code_e arm_uc_multicast_store_new_ota_process(uint8_t *ota_session_id);
static ota_error_code_e arm_uc_multicast_remove_stored_ota_process(uint8_t *ota_session_id);
static ota_error_code_e arm_uc_multicast_store_parameters(ota_parameters_t *ota_parameters);
static ota_error_code_e arm_uc_multicast_read_parameters(ota_parameters_t *ota_parameters);
static uint32_t         arm_uc_multicast_write_fw_bytes(uint8_t *ota_session_id, uint32_t offset, uint32_t count, uint8_t *from);
static uint32_t         arm_uc_multicast_read_fw_bytes(uint8_t *ota_session_id, uint32_t offset, uint32_t count, uint8_t *to);
static void             arm_uc_multicast_send_update_fw_cmd_received_info(uint32_t delay);
#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
static int8_t           arm_uc_multicast_socket_send(ota_ip_address_t *destination, uint16_t count, uint8_t *payload);
#endif // defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)    
static uint16_t         arm_uc_multicast_update_resource_value(ota_resource_types_e type, uint8_t *payload_ptr, uint16_t payload_len);
static bool             arm_uc_multicast_create_static_resources(M2MBaseList &list);
static void             arm_uc_multicast_socket_callback(void *);
static bool             arm_uc_multicast_open_socket(palSocket_t *socket, uint16_t port);
static ota_error_code_e arm_uc_multicast_manifest_received(uint8_t *payload_ptr, uint32_t payload_len);
static void             arm_uc_multicast_firmware_ready();
static ota_error_code_e arm_uc_multicast_start_received(ota_parameters_t *ota_parameters);
static void             arm_uc_multicast_process_finished(uint8_t *session_id);
static bool             read_dodag_info(char *dodag_address);
static ota_error_code_e arm_uc_multicast_get_parent_addr(uint8_t *addr);
static void             arm_uc_multicast_update_client_event(struct arm_event_s *event);
static void             arm_uc_multicast_update_client_init();
static void             arm_uc_multicast_update_client_external_update_event(struct arm_event_s *event);

palSocket_t                 arm_uc_multicast_socket;
palSocket_t                 arm_uc_multicast_missing_frag_socket;
static int8_t               arm_uc_multicast_tasklet_id = -1;
static int8_t               arm_uc_multicast_interface_id = -1;
static M2MObject           *arm_uc_multicast_object = NULL;
static M2MResource         *multicast_netid_res = NULL;
static M2MResource         *multicast_connected_nodes_res = NULL;
static M2MResource         *multicast_ready_res = NULL;
static M2MResource         *multicast_status_res = NULL;
static M2MResource         *multicast_session_res = NULL;
static M2MResource         *multicast_command_res = NULL;
static M2MResource         *multicast_estimated_total_time_res = NULL;
static M2MResource         *multicast_estimated_resend_time_res = NULL;
static M2MResource         *multicast_error_res = NULL;
static ConnectorClient     *arm_uc_multicast_m2m_client;
static const uint8_t        arm_uc_multicast_address[16] = {0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; // MPL multicast socket IP address
static const uint8_t        arm_uc_multicast_link_local_multicast_address[16] = {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; // Link local multicast socket IP addres
static arm_event_storage_t  arm_uc_multicast_event;
static const int16_t        multicast_hops = 24;


#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
#if defined(MULTICAST_FOTA_INTEGRATION)
#include "fota_manifest.h"
manifest_firmware_info_t fw_info;
#else
#include "update-client-manifest-manager/update-client-manifest-types.h"
struct manifest_firmware_info_t fw_info;
#endif
#endif

static ota_parameters_t stored_ota_parameters = {
    .ota_session_id = {0},
    .device_type = 0,
    .fw_segment_count = 0,
    .fw_total_byte_count = 0,
    .fw_fragment_count = 0,
    .fw_fragment_byte_count = OTA_DEFAULT_FRAGMENT_SIZE,
    .whole_fw_checksum_tbl = {0},
    .pull_url_length = 0,
    .pull_url_ptr = 0,
    .ota_process_count = 0,
    .ota_state = OTA_STATE_IDLE,
    .fragments_bitmask_length = 0,
    .fragments_bitmask_ptr = 0
};

static ota_lib_config_data_t arm_uc_multicast_ota_config = {
    .device_type = OTA_DEVICE_TYPE_BORDER_ROUTER,
    .unicast_socket_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0},              // Unicast socket address
    .mpl_multicast_socket_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0},        // MPL multicast socket address
    .link_local_multicast_socket_addr = {OTA_ADDRESS_NOT_VALID, {0}, 0}  // Link local multicast socket address
};

static ota_config_func_pointers_t arm_uc_ota_function_pointers = {
    .mem_alloc_fptr = &malloc,
    .mem_free_fptr = &free,
    .request_timer_fptr = &arm_uc_multicast_request_timer,
    .cancel_timer_fptr = &arm_uc_multicast_cancel_timer,
    .store_new_ota_process_fptr = &arm_uc_multicast_store_new_ota_process,
    .remove_stored_ota_process_fptr = &arm_uc_multicast_remove_stored_ota_process,
    .store_parameters_fptr = &arm_uc_multicast_store_parameters,
    .read_parameters_fptr = &arm_uc_multicast_read_parameters,
    .start_received_fptr = &arm_uc_multicast_start_received,
    .process_finished_fptr = &arm_uc_multicast_process_finished,
    .write_fw_bytes_fptr = &arm_uc_multicast_write_fw_bytes,
    .read_fw_bytes_fptr = &arm_uc_multicast_read_fw_bytes,
    .send_update_fw_cmd_received_info_fptr = &arm_uc_multicast_send_update_fw_cmd_received_info,
#if defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)
    .socket_send_fptr = &arm_uc_multicast_mesh_simulator_send,
#else
    .socket_send_fptr = &arm_uc_multicast_socket_send,
#endif // defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)    
    .update_resource_value_fptr = &arm_uc_multicast_update_resource_value,
    .manifest_received_fptr = &arm_uc_multicast_manifest_received,
    .firmware_ready_fptr = &arm_uc_multicast_firmware_ready,
    .get_parent_addr_fptr = &arm_uc_multicast_get_parent_addr
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_dodag_id_res = {
    0,                  // max_age
    (char *)"0",
    &ota_dodag_id_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::STRING,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_connected_nodes_res = {
    0,                  // max_age
    (char *)"1",
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
    (char *)"2",
    &ota_ready_for_multicast_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::INTEGER,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_status_res = {
    0,                  // max_age
    (char *)"3",
    &ota_status_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::OPAQUE,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_session_res = {
    0,                  // max_age
    (char *)"4",
    &ota_session_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::OPAQUE,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_ota_command_res = {
    0,                  // max_age
    (char *)"5",
    &ota_command_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::OPAQUE,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_estimated_total_time_res = {
    0,                  // max_age
    (char *)"6",
    &ota_estimated_total_time_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::OPAQUE,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_estimated_resend_time_res = {
    0,                  // max_age
    (char *)"7",
    &ota_estimated_resend_time_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::OPAQUE,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_error_res = {
    0,                  // max_age
    (char *)"8",
    &ota_error_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::OPAQUE,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

const static M2MBase::lwm2m_parameters arm_uc_multicast_fragment_size_res = {
    0,                  // max_age
    (char *)"9",
    &ota_fragment_size_dyn_params,
    M2MBase::Resource,  // base_type
    M2MBase::INTEGER,
    false,
    false,              // free_on_delete
    false,              // identifier_int_type
    false               // read_write_callback_set
};

/************************************************/
/* Multicast API                                */
/************************************************/
multicast_status_e arm_uc_multicast_init(M2MBaseList &list, ConnectorClient &client, const int8_t tasklet_id)
{
    tr_debug("arm_uc_multicast_init");

    if (arm_uc_multicast_init_done) {
        tr_debug("arm_uc_multicast_init - already initialized");
        return MULTICAST_STATUS_SUCCESS;
    }

    if (tasklet_id < 0) {
        tr_error("arm_uc_multicast_init - trying to pass invalid tasklet_id for arm_uc_multicast_init");
        return MULTICAST_STATUS_INIT_FAILED;
    }
#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    if (arm_uc_multicast_interface_id < 0) {
        tr_info("arm_uc_multicast_init - mesh interface not yet configured - wait next init");
        return MULTICAST_STATUS_SUCCESS;
    }
#endif
    arm_uc_multicast_tasklet_id = tasklet_id;
    arm_uc_multicast_m2m_client = &client;

#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    if (!arm_uc_multicast_open_socket(&arm_uc_multicast_socket, OTA_SOCKET_MULTICAST_PORT)) {
        return MULTICAST_STATUS_INIT_FAILED;
    }

    if (!arm_uc_multicast_open_socket(&arm_uc_multicast_missing_frag_socket, OTA_SOCKET_UNICAST_PORT)) {
        return MULTICAST_STATUS_INIT_FAILED;
    }
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR

    memset(&arm_uc_multicast_event, 0, sizeof(arm_uc_multicast_event));

#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    arm_uc_multicast_ota_config.unicast_socket_addr.port = OTA_SOCKET_UNICAST_PORT;
    arm_uc_multicast_ota_config.unicast_socket_addr.type = OTA_ADDRESS_IPV6;

    arm_uc_multicast_ota_config.mpl_multicast_socket_addr.port = OTA_SOCKET_MULTICAST_PORT;
    memcpy(arm_uc_multicast_ota_config.mpl_multicast_socket_addr.address_tbl, arm_uc_multicast_address, 16);

    arm_uc_multicast_ota_config.link_local_multicast_socket_addr.port = OTA_SOCKET_MULTICAST_PORT;
    memcpy(arm_uc_multicast_ota_config.link_local_multicast_socket_addr.address_tbl, arm_uc_multicast_link_local_multicast_address, 16);
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR

#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    arm_uc_multicast_ota_config.device_type = OTA_DEVICE_TYPE_BORDER_ROUTER;
#if defined(MULTICAST_FOTA_INTEGRATION)
    memset(&fw_info, 0, sizeof(manifest_firmware_info_t));
#else
    memset(&fw_info, 0, sizeof(struct manifest_firmware_info_t));
#endif

#else

#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    if (arm_uc_multicast_get_parent_addr(arm_uc_multicast_ota_config.unicast_socket_addr.address_tbl) != OTA_OK) {
        tr_error("arm_uc_multicast_init - failed to read parent address");
        return MULTICAST_STATUS_INIT_FAILED;
    }
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR

    arm_uc_multicast_ota_config.device_type = OTA_DEVICE_TYPE_NODE;
#endif

    if (!arm_uc_multicast_create_static_resources(list)) {
        return MULTICAST_STATUS_INIT_FAILED;
    }

    if (ota_lib_configure(&arm_uc_multicast_ota_config, &arm_uc_ota_function_pointers) != OTA_OK) {
        return MULTICAST_STATUS_INIT_FAILED;
    }

#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    arm_uc_multicast_update_client_init();
#endif

#if defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)
    build_mesh_shared_file_name();
#if defined(ARM_UC_MULTICAST_NODE_MODE)

    palStatus_t status = pal_plat_osThreadCreate(&thread_node, NULL, PAL_osPriorityAboveNormal, 2 * 1024 * 1024, &tid);
    if (status != 0) {
        tr_error("can't create node thread :[%s]", strerror(status));
    } else {
        tr_debug("Thread node created successfully");
    }
#endif
#endif

    arm_uc_multicast_init_done = true;

    return MULTICAST_STATUS_SUCCESS;
}

void arm_uc_multicast_deinit()
{
    ota_lib_reset();
    pal_close(&arm_uc_multicast_socket);
    pal_close(&arm_uc_multicast_missing_frag_socket);
    delete arm_uc_multicast_object;
    arm_uc_multicast_object = NULL;
    arm_uc_multicast_init_done = false;
}

void arm_uc_multicast_tasklet(struct arm_event_s *event)
{
    if (ARM_UC_OTA_MULTICAST_TIMER_EVENT == event->event_type) {
        ota_timer_expired(event->event_id);
    } else if (ARM_UC_OTA_MULTICAST_UPDATE_CLIENT_EVENT == event->event_type) {
        arm_uc_multicast_update_client_event(event);
    } else if (ARM_UC_OTA_MULTICAST_DL_DONE_EVENT == event->event_type) {
        tr_info("arm_uc_multicast_tasklet - download completed");
        ota_firmware_pulled();
    } else if (ARM_UC_OTA_MULTICAST_EXTERNAL_UPDATE_EVENT == event->event_type) {
        tr_info("arm_uc_multicast_tasklet - external update");
        arm_uc_multicast_update_client_external_update_event(event);
    } else if (ARM_UC_OTA_DELETE_SESSION_EVENT == event->event_type) {
        ota_delete_session(stored_ota_parameters.ota_session_id);
        memset(stored_ota_parameters.ota_session_id, 0, OTA_SESSION_ID_SIZE);
        stored_ota_parameters.ota_process_count = 0;
    } else if (ARM_UC_OTA_FULL_REG_EVENT == event->event_type) {
        arm_uc_multicast_m2m_client->start_full_registration();
    } else if (ARM_UC_HUB_EVENT_TIMER == event->event_type) {
#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
#if defined(MULTICAST_UCHUB_INTEGRATION)
        arm_uc_multicast_event.data.event_data = arm_uc_hub_state;
        arm_uc_multicast_event.data.event_type = ARM_UC_OTA_MULTICAST_UPDATE_CLIENT_EVENT;
        arm_uc_multicast_event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
        arm_uc_multicast_event.data.receiver = arm_uc_multicast_tasklet_id;
        eventOS_event_send_user_allocated(&arm_uc_multicast_event);
#endif
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR        
    } else if (ARM_UC_OTA_MULTICAST_INIT_EVENT != event->event_type) {
        tr_error("arm_uc_multicast_tasklet - unknown event! (%d)", event->event_type);
    }
}

void arm_uc_multicast_network_connected()
{
    char addr[45] = {0};
    if (read_dodag_info(addr)) {
        if (arm_uc_multicast_update_resource_value(MULTICAST_NETWORK_ID, reinterpret_cast<unsigned char *>(addr), strlen(addr)) == 2) {
            // return value 2 means value actually changed from previous, so in netid case we need to trigger full
            // registration to update device directory
            tr_info("dodag info changed during network global up. triggering full register.");
            eventOS_event_timer_request(0, ARM_UC_OTA_FULL_REG_EVENT, arm_uc_multicast_tasklet_id, 20000);
        }
    }
}

bool arm_uc_multicast_interface_configure(int8_t interface_id)
{
    tr_info("arm_uc_multicast_interface_configure - interface id %d", interface_id);

    arm_uc_multicast_interface_id = interface_id;
    return true;
}

/************************************************/
/* Network api implementations                  */
/************************************************/
static bool read_dodag_info(char *address)
{
#if defined(MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR) && (MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR == 1)
    memcpy(address, g_mesh_network_id, OTA_MAX_MESH_NETWORK_ID_LENGTH);
    return true;
#else
#if defined(ARM_UC_MULTICAST_NODE_MODE)
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
    bbr_information_t bbr_info = {};
    if (ws_bbr_info_get(arm_uc_multicast_interface_id, &bbr_info) == 0) {
        ip6tos(bbr_info.dodag_id, address);
        tr_debug("read_dodag_info - address: %s", address);
        return true;
    } else {
        tr_error("read_dodag_info - DODAG ID not found");
        return false;
    }
#endif
#endif
}

static ota_error_code_e arm_uc_multicast_get_parent_addr(uint8_t *addr)
{
#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
#if defined(ARM_UC_MULTICAST_NODE_MODE)
    // Get the parent address for unicast
    ws_stack_info_t stack_info = {};
    if (ws_stack_info_get(arm_uc_multicast_interface_id, &stack_info)) {
        return OTA_NOT_FOUND;
    }

    memcpy(addr, stack_info.parent, 16);
    tr_info("arm_uc_multicast_get_parent_addr - parent address: %s", trace_ipv6(addr));
#else
    (void)addr;
#endif
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    return OTA_OK;
}


/************************************************/
/* Socket API implementation                    */
/*  - opening sockets                           */
/*  - sending data                              */
/*  - callback                                  */
/************************************************/
static void arm_uc_multicast_socket_callback(void *port)
{
    tr_debug("arm_uc_multicast_socket_callback - port % " PRIdPTR "", (intptr_t)port);

    size_t recv;
    palStatus_t status;
    uint8_t recv_buffer[RECEIVE_BUFFER_SIZE];

    palSocketAddress_t address = { 0, { 0 } };
    palSocketLength_t addrlen = 0;

    // Read from the right socket
    if ((intptr_t)port == OTA_SOCKET_MULTICAST_PORT) {
        status = pal_receiveFrom(arm_uc_multicast_socket, recv_buffer, RECEIVE_BUFFER_SIZE, &address, &addrlen, &recv);
        // Skip data coming from multicast loop
        if (arm_uc_multicast_send_in_progress) {
            tr_info("arm_uc_multicast_socket_callback - multicast loopback data --> skip");
            arm_uc_multicast_send_in_progress = false;
            return;
        }
    } else {
        status = pal_receiveFrom(arm_uc_multicast_missing_frag_socket, recv_buffer, RECEIVE_BUFFER_SIZE, &address, &addrlen, &recv);
    }

    if (status == PAL_SUCCESS) {
        uint16_t recv_port;
        ota_ip_address_t ota_addr;
        status = pal_getSockAddrPort(&address, &recv_port);
        if (status != PAL_SUCCESS) {
            tr_error("arm_uc_multicast_socket_callback - pal_getSockAddrPort failed");
        }

        if (address.addressType == PAL_AF_INET6 && status == PAL_SUCCESS) {
            palIpV6Addr_t addr;
            status = pal_getSockAddrIPV6Addr(&address, addr);
            if (status == PAL_SUCCESS) {
                ota_addr.type = OTA_ADDRESS_IPV6; // TODO! can this be something else than ipv6?
                ota_addr.port = recv_port;
                memcpy(ota_addr.address_tbl, &addr, sizeof(addr));
            } else {
                tr_error("arm_uc_multicast_socket_callback - pal_getSockAddrIPV6Addr failed");
            }
        }

        if (status == PAL_SUCCESS) {
            ota_socket_receive_data((uint16_t)recv, recv_buffer, &ota_addr);
        }
    } else {
        tr_debug("arm_uc_multicast_socket_callback - read error %" PRIx32, status);
    }
}

#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
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
static int8_t arm_uc_multicast_socket_send(ota_ip_address_t *destination, uint16_t count, uint8_t *payload)
{
    tr_debug("arm_uc_multicast_socket_send");

    size_t sent;
    palSocketAddress_t pal_addr = { 0, { 0 } };
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

    if (destination->port == OTA_SOCKET_MULTICAST_PORT) {
        arm_uc_multicast_send_in_progress = true;
    }

    return pal_sendTo(socket, payload, count, &pal_addr, sizeof(pal_addr), &sent);
}
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR

static bool arm_uc_multicast_open_socket(palSocket_t *socket, uint16_t port)
{
#ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
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
                                                (void *)((intptr_t)port),
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

    status = pal_setSocketOptionsWithLevel(*socket,
                                           PAL_SOL_IPPROTO_IPV6,
                                           PAL_SO_IPV6_MULTICAST_HOPS,
                                           &multicast_hops,
                                           sizeof(multicast_hops));
    if (PAL_SUCCESS != status) {
        tr_error("arm_uc_multicast_open_socket - pal_setSocketOptionsWithLevel err: %" PRIx32, status);
        return false;
    }

    tr_info("arm_uc_multicast_open_socket - opened OTA socket (port=%u)", port);
#endif // #ifndef MBED_CLOUD_CLIENT_MESH_SOCKET_SIMULATOR
    return true;
}


/************************************************/
/* Timer implementation                         */
/************************************************/
/*
 * request_timer_fptr() Function pointer for requesting timer event
 *            Parameters:
 *              -Timer ID of requested timer
 *              -Timeout time in milliseconds
 */
static void arm_uc_multicast_request_timer(uint8_t timer_id, uint32_t timeout)
{
    tr_debug("arm_uc_multicast_request_timer - id %" PRIu8 ", timeout %" PRIu32 "(ms)", timer_id, timeout);
    int8_t res = eventOS_event_timer_request(timer_id, ARM_UC_OTA_MULTICAST_TIMER_EVENT, arm_uc_multicast_tasklet_id, timeout);
    assert(res == 0);
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


/************************************************/
/* otaLIB state storing implementation          */
/*  - currently stored to RAM                   */
/************************************************/
/*
 * store_new_ota_process_fptr() Function pointer for storing new OTA process to storage
 *            Parameters:
 *              -Added OTA process ID
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_store_new_ota_process(uint8_t *ota_session_id)
{
    tr_debug("arm_uc_multicast_store_new_ota_process");
    assert(stored_ota_parameters.ota_process_count == 0);
    stored_ota_parameters.ota_process_count = 1;
    memcpy(stored_ota_parameters.ota_session_id, ota_session_id, OTA_SESSION_ID_SIZE);
    return OTA_OK;
}

/*
 * remove_stored_ota_process_fptr() Function pointer for removing stored OTA process from storage
 *            Parameters:
 *              -Removed OTA process ID
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_remove_stored_ota_process(uint8_t *ota_session_id)
{
    tr_debug("arm_uc_multicast_remove_stored_ota_process");
    (void)ota_session_id;

    stored_ota_parameters.ota_process_count = 0;
    memset(stored_ota_parameters.ota_session_id, 0, OTA_SESSION_ID_SIZE);
    return OTA_OK;
}

/*
 * store_parameters_fptr() Function pointer for storing OTA parameters to storage
 *            Parameters:
 *              -Stored OTA parameters
 *            Return value:
 *              -Ok/error status code of performing function
 */
static ota_error_code_e arm_uc_multicast_store_parameters(ota_parameters_t *ota_parameters)
{
    tr_debug("arm_uc_multicast_store_parameters");
    assert(memcmp(stored_ota_parameters.ota_session_id, ota_parameters->ota_session_id, OTA_SESSION_ID_SIZE) == 0);

    memcpy(stored_ota_parameters.ota_session_id, ota_parameters->ota_session_id, OTA_SESSION_ID_SIZE);
    stored_ota_parameters.device_type = ota_parameters->device_type;
    stored_ota_parameters.ota_state = ota_parameters->ota_state;
    if (stored_ota_parameters.fragments_bitmask_length != ota_parameters->fragments_bitmask_length) {
        free(stored_ota_parameters.fragments_bitmask_ptr);
        if (ota_parameters->fragments_bitmask_length > 0) {
            stored_ota_parameters.fragments_bitmask_ptr = (uint8_t *)malloc(ota_parameters->fragments_bitmask_length);
            memcpy(stored_ota_parameters.fragments_bitmask_ptr, ota_parameters->fragments_bitmask_ptr, ota_parameters->fragments_bitmask_length);
        } else {
            stored_ota_parameters.fragments_bitmask_ptr = 0;
        }
    }
    stored_ota_parameters.fragments_bitmask_length = ota_parameters->fragments_bitmask_length;
    stored_ota_parameters.fw_segment_count = ota_parameters->fw_segment_count;
    stored_ota_parameters.fw_total_byte_count = ota_parameters->fw_total_byte_count;
    stored_ota_parameters.fw_fragment_count = ota_parameters->fw_fragment_count;
    stored_ota_parameters.fw_fragment_byte_count = ota_parameters->fw_fragment_byte_count;
    memcpy(stored_ota_parameters.whole_fw_checksum_tbl, ota_parameters->whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH);

#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    stored_ota_parameters.pull_url_length = ota_parameters->pull_url_length;
    if (stored_ota_parameters.pull_url_length) {
        free(stored_ota_parameters.pull_url_ptr);
        stored_ota_parameters.pull_url_ptr = (uint8_t *)malloc(stored_ota_parameters.pull_url_length);
        if (stored_ota_parameters.pull_url_ptr) {
            memcpy(stored_ota_parameters.pull_url_ptr, ota_parameters->pull_url_ptr, stored_ota_parameters.pull_url_length);
        } else {
            tr_error("arm_uc_multicast_store_parameters - failed to allocate pull_url_ptr!!!");
            return OTA_OUT_OF_MEMORY;
        }
    }
#else
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
static ota_error_code_e arm_uc_multicast_read_parameters(ota_parameters_t *ota_parameters)
{
    tr_debug("arm_uc_multicast_read_parameters");
    memcpy(ota_parameters->ota_session_id, stored_ota_parameters.ota_session_id, OTA_SESSION_ID_SIZE);
    ota_parameters->ota_process_count = stored_ota_parameters.ota_process_count;

    ota_parameters->device_type = stored_ota_parameters.device_type;
    ota_parameters->fw_segment_count = stored_ota_parameters.fw_segment_count;
    ota_parameters->fw_total_byte_count = stored_ota_parameters.fw_total_byte_count;
    ota_parameters->fw_fragment_count = stored_ota_parameters.fw_fragment_count;
    ota_parameters->fw_fragment_byte_count = stored_ota_parameters.fw_fragment_byte_count;
    memcpy(ota_parameters->whole_fw_checksum_tbl, stored_ota_parameters.whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH);

    ota_parameters->ota_state = stored_ota_parameters.ota_state;
    ota_parameters->fragments_bitmask_length = stored_ota_parameters.fragments_bitmask_length;
    if (stored_ota_parameters.fragments_bitmask_length > 0) {
        ota_parameters->fragments_bitmask_ptr = (uint8_t *)malloc(ota_parameters->fragments_bitmask_length);
        memcpy(ota_parameters->fragments_bitmask_ptr, stored_ota_parameters.fragments_bitmask_ptr, ota_parameters->fragments_bitmask_length);
    } else {
        ota_parameters->fragments_bitmask_ptr = 0;
    }

#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    ota_parameters->pull_url_length = stored_ota_parameters.pull_url_length;
    if (ota_parameters->pull_url_length) {
        ota_parameters->pull_url_ptr = (uint8_t *)malloc(ota_parameters->pull_url_length);
        if (ota_parameters->pull_url_ptr) {
            memcpy(ota_parameters->pull_url_ptr, stored_ota_parameters.pull_url_ptr, ota_parameters->pull_url_length);
        } else {
            tr_error("arm_uc_multicast_read_parameters - failed to allocate pull_url_ptr!!!");
            return OTA_OUT_OF_MEMORY;
        }
    }
#else
    // 'only used in router'
    assert(stored_ota_parameters.pull_url_length == 0);
    ota_parameters->pull_url_length = 0;
    ota_parameters->pull_url_ptr = 0;
#endif

    return OTA_OK;
}

/************************************************/
/* Lwm2m integration                            */
/*  - create resources                          */
/*  - set resource values                       */
/************************************************/

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
 *              -Success, perform full register: 2
 *              -Success: 1
 *              -Failure: 0
 */
static uint16_t arm_uc_multicast_update_resource_value(ota_resource_types_e type, uint8_t *payload_ptr, uint16_t payload_len)
{
    int status = 0;
    switch (type) {
        case MULTICAST_STATUS:
            status = multicast_status_res->set_value(payload_ptr, payload_len);
            break;
        case MULTICAST_ERROR:
            status = multicast_error_res->set_value(payload_ptr, payload_len);
            break;
        case MULTICAST_READY:
            if (multicast_ready_res) {
                status = multicast_ready_res->set_value(payload_ptr, payload_len);
            }
            break;
        case MULTICAST_SESSION_ID:
            status = multicast_session_res->set_value(payload_ptr, payload_len);
            break;
        case MULTICAST_NODE_COUNT:
            if (multicast_connected_nodes_res) {
                status = multicast_connected_nodes_res->set_value(payload_ptr, payload_len);
            }
            break;
        case MULTICAST_ESTIMATED_TOTAL_TIME:
            if (multicast_estimated_total_time_res) {
                status = multicast_estimated_total_time_res->set_value(payload_ptr, payload_len);
            }
            break;
        case MULTICAST_ESTIMATED_RESEND_TIME:
            if (multicast_estimated_resend_time_res) {
                status = multicast_estimated_resend_time_res->set_value(payload_ptr, payload_len);
            }
            break;
        case MULTICAST_NETWORK_ID:
            if (multicast_netid_res) {
                const String old_value = multicast_netid_res->get_value_string();
                if (old_value.length() != payload_len ||
                        memcmp(old_value.c_str(), payload_ptr, payload_len) != 0) {
                    status = multicast_netid_res->set_value(payload_ptr, payload_len);
                    if (status) {
                        status = 2;
                    }
                } else {
                    // value didn't actually change so no need to update anything really.
                    // just return success
                    status = 1;
                }
            }
            break;
        default:
            break;
    }

    return status;
}

static bool arm_uc_multicast_create_static_resources(M2MBaseList &list)
{
    M2MObjectInstance *object_inst = NULL;

    if (!arm_uc_multicast_object) {
        arm_uc_multicast_object = M2MInterfaceFactory::create_object(MULTICAST_OBJECT_ID);
        if (arm_uc_multicast_object) {
            arm_uc_multicast_object->set_register_uri(false);
            object_inst = arm_uc_multicast_object->create_object_instance();
        } else {
            tr_error("arm_uc_multicast_create_static_resources - failed to create object!");
            return false;
        }
    }

    if (object_inst) {
        object_inst->set_register_uri(false);

        if (arm_uc_multicast_ota_config.device_type == OTA_DEVICE_TYPE_BORDER_ROUTER) {
            /*multicast_connected_nodes_res = object_inst->create_static_resource(&arm_uc_multicast_ota_connected_nodes_res, M2MResourceInstance::INTEGER);
            if (!multicast_connected_nodes_res) {
                tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_connected_nodes_res!");
                return false;
            }
            multicast_connected_nodes_res->set_value(0);
            multicast_connected_nodes_res->set_register_uri(false);*/

            multicast_ready_res = object_inst->create_static_resource(&arm_uc_multicast_ota_ready_for_multicast_res, M2MResourceInstance::INTEGER);
            if (!multicast_ready_res) {
                tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_ready_res!");
                return false;
            }
            multicast_ready_res->set_value(1);
            multicast_ready_res->set_auto_observable(true);

            multicast_command_res = object_inst->create_static_resource(&arm_uc_multicast_ota_command_res, M2MResourceInstance::OPAQUE);
            if (!multicast_command_res) {
                tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_command_res!");
                return false;
            }

            /*multicast_estimated_total_time_res = object_inst->create_static_resource(&arm_uc_multicast_estimated_total_time_res, M2MResourceInstance::OPAQUE);
            if (!multicast_estimated_total_time_res) {
                tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_estimated_total_time_res!");
                return false;
            }
            multicast_estimated_total_time_res->set_value(0);
            multicast_estimated_total_time_res->set_register_uri(false);*/

            multicast_estimated_resend_time_res = object_inst->create_static_resource(&arm_uc_multicast_estimated_resend_time_res, M2MResourceInstance::OPAQUE);
            if (!multicast_estimated_resend_time_res) {
                tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_estimated_resend_time_res!");
                return false;
            }
            multicast_estimated_resend_time_res->set_value(0);

            if (!object_inst->create_static_resource(&arm_uc_multicast_fragment_size_res, M2MResourceInstance::INTEGER)) {
                tr_error("arm_uc_multicast_create_static_resources - failed to create multicast fragment size resource!");
                return false;
            }
        }

        multicast_netid_res = object_inst->create_static_resource(&arm_uc_multicast_dodag_id_res, M2MResourceInstance::STRING);
        if (multicast_netid_res) {
            char addr[45] = {0};
            if (read_dodag_info(addr)) {
                multicast_netid_res->set_value((const unsigned char *)addr, strlen(addr));
                multicast_netid_res->publish_value_in_registration_msg(true);
            } else {
                return false;
            }
        } else {
            tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_netid_res!");
            return false;
        }

        multicast_status_res = object_inst->create_static_resource(&arm_uc_multicast_ota_status_res, M2MResourceInstance::OPAQUE);
        if (!multicast_status_res) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_status_res!");
            return false;
        }


        multicast_session_res = object_inst->create_static_resource(&arm_uc_multicast_ota_session_res, M2MResourceInstance::OPAQUE);
        if (!multicast_session_res) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_session_res!");
            return false;
        }


        multicast_error_res = object_inst->create_static_resource(&arm_uc_multicast_error_res, M2MResourceInstance::OPAQUE);
        if (!multicast_error_res) {
            tr_error("arm_uc_multicast_create_static_resources - failed to create multicast_error_res!");
            return false;
        }
        multicast_error_res->set_auto_observable(true);

        list.push_back(arm_uc_multicast_object);
    } else {
        tr_error("arm_uc_multicast_create_static_resources - failed to create object instance!");
        return false;
    }

    return true;
}

/************************************************/
/* Update client integration for UCHub          */
/*  - handlers for reading/writing the firmware */
/*  - setting manifest                          */
/*  - activation of new firmware                */
/************************************************/

#if defined(MULTICAST_UCHUB_INTEGRATION)

static void arm_uc_multicast_send_event(arm_uc_hub_state_t state);



#if defined(ARM_UC_MULTICAST_NODE_MODE)
static ARM_UCFM_Setup_t arm_uc_multicast_fwmanager_configuration;
static arm_uc_firmware_details_t arm_uc_multicast_fwmanager_firmware_details;
static arm_uc_buffer_t arm_uc_multicast_fwmanager_hashbuf;
static uint8_t arm_uc_multicast_fwmanager_buffer[ARM_UC_HUB_BUFFER_SIZE_MAX];
static arm_uc_buffer_t arm_uc_multicast_fwmanager_armbuffer = {
    .size_max = ARM_UC_HUB_BUFFER_SIZE_MAX,
    .size = 0,
    .ptr = arm_uc_multicast_fwmanager_buffer
};
#endif

static void arm_uc_multicast_update_client_init()
{
    ARM_UC_HUB_setMulticastTaskletId(arm_uc_multicast_tasklet_id);
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
static uint32_t arm_uc_multicast_write_fw_bytes(uint8_t *ota_session_id, uint32_t offset, uint32_t count, uint8_t *from)
{
    tr_debug("arm_uc_multicast_write_fw_bytes, offset %" PRIu32 ", bytes %" PRIu32 "", offset, count);

    assert(memcmp(stored_ota_parameters.ota_session_id, ota_session_id, OTA_SESSION_ID_SIZE) == 0);
    assert(stored_ota_parameters.ota_process_count == 1);
    assert(stored_ota_parameters.fw_fragment_byte_count != 0);

    arm_uc_buffer_t buffer;
    buffer.size_max = stored_ota_parameters.fw_fragment_byte_count;
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
static uint32_t arm_uc_multicast_read_fw_bytes(uint8_t *ota_session_id, uint32_t offset, uint32_t count, uint8_t *to)
{
    tr_debug("arm_uc_multicast_read_fw_bytes, offset %" PRIu32 ", count %" PRIu32 "", offset, count);
    assert(memcmp(stored_ota_parameters.ota_session_id, ota_session_id, OTA_SESSION_ID_SIZE) == 0);
    assert(stored_ota_parameters.ota_process_count == 1);

    if (ARM_UC_HUB_getState() == ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST) {
        arm_uc_buffer_t buffer;
        buffer.size_max = count;
        buffer.size = count;
        buffer.ptr = to;
        arm_uc_error_t ret = ARM_UC_FirmwareManager.Read(&buffer, offset);
        if (ret.code != ERR_NONE) {
            tr_error("ARM_UC_FirmwareManager.Read failed with %" PRId32 " ", ret.code);
            count = 0;
        }
    } else {
        tr_warn("arm_uc_multicast_read_fw_bytes - uc hub not in correct state");
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
static void arm_uc_multicast_send_update_fw_cmd_received_info(uint32_t delay)
{
    tr_info("arm_uc_multicast_send_update_fw_cmd_received_info");
    if (!arm_uc_multicast_manifest_rejected) {
        ARM_UC_HUB_setRebootDelay(delay);
        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_INSTALL_AUTHORIZED);
    } else {
        tr_info("arm_uc_multicast_send_update_fw_cmd_received_info - manifest rejected, skip activation!");
        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_IDLE);
    }
}

static ota_error_code_e arm_uc_multicast_start_received(ota_parameters_t *ota_parameters)
{
    tr_info("arm_uc_multicast_start_received");
    ota_error_code_e return_value = OTA_OK;
    arm_uc_multicast_manifest_rejected = false;

#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
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

#if defined(ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST) && (ARM_UC_FEATURE_DELTA_PAAL_NEWMANIFEST == 1)
        fw_info.installedHash.ptr = ota_parameters->whole_fw_checksum_tbl;
        fw_info.installedHash.size = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        fw_info.installedHash.size_max = OTA_WHOLE_FW_CHECKSUM_LENGTH;
        fw_info.installedSize = ota_parameters->fw_total_byte_count;
#endif
        fw_info.format.bytes[0] = 1;
        fw_info.cipherMode = ARM_UC_MM_CIPHERMODE_NONE;
        ARM_UC_HUB_setExternalDownload(&fw_info);
        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_PREPARE_FIRMWARE_SETUP);
    } else {
        return_value = OTA_PARAMETER_FAIL;
    }
#else
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

    // Something went wrong when processing manifest.
    // In this case activation must not happen but fragments must be stored since those are needed for serving missing fragments.
    if (ARM_UC_HUB_getState() == ARM_UC_HUB_STATE_IDLE) {
        tr_info("arm_uc_multicast_start_received - uc hub not in right state, skip activation");
        arm_uc_multicast_manifest_rejected = true;
        arm_uc_error_t ret = ARM_UC_FirmwareManager.Prepare(&arm_uc_multicast_fwmanager_configuration, &arm_uc_multicast_fwmanager_firmware_details, &arm_uc_multicast_fwmanager_armbuffer);
        if (ret.code != ERR_NONE) {
            tr_warn("arm_uc_multicast_start_received - prepare failed with %" PRId32 " ", ret.code);
            return_value = OTA_PARAMETER_FAIL;
        } else {
            arm_uc_multicast_send_event(ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST);
        }
    } else {
        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_WAIT_FOR_MULTICAST);
    }
#endif // defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)

    return return_value;
}

static void arm_uc_multicast_process_finished(uint8_t */*session_id*/)
{
    tr_info("arm_uc_multicast_process_finished");
    arm_uc_multicast_send_event(ARM_UC_HUB_STATE_IDLE);
}

static void arm_uc_multicast_send_event(arm_uc_hub_state_t state)
{
    arm_uc_hub_state = state;
    uint16_t start_time = 0;
#if defined(ARM_UC_MULTICAST_NODE_MODE)
    // Delay cases where update client is sending notifications
    if (state == ARM_UC_HUB_STATE_MANIFEST_FETCHED || state == ARM_UC_HUB_STATE_LAST_FRAGMENT_STORE_DONE || state == ARM_UC_HUB_STATE_IDLE) {
        start_time = randLIB_get_random_in_range(ARM_UC_OTA_MULTICAST_RAND_START, ARM_UC_OTA_MULTICAST_RAND_END);
    }
#endif

    tr_info("arm_uc_multicast_send_event, sending state %d after %" PRIu32 " seconds", state, start_time);
    eventOS_event_timer_request(ARM_UC_HUB_EVENT_TIMER, ARM_UC_HUB_EVENT_TIMER, arm_uc_multicast_tasklet_id, start_time * 1000);
}

ota_error_code_e arm_uc_multicast_manifest_received(uint8_t *payload_ptr, uint32_t payload_len)
{
    if (ARM_UC_HUB_setManifest(payload_ptr, payload_len)) {
        arm_uc_multicast_send_event(ARM_UC_HUB_STATE_MANIFEST_FETCHED);
    }

    return OTA_OK;
}

void arm_uc_multicast_firmware_ready()
{
    arm_uc_multicast_send_event(ARM_UC_HUB_STATE_LAST_FRAGMENT_STORE_DONE);
}

void arm_uc_multicast_update_client_event(struct arm_event_s *event)
{
    ARM_UC_HUB_setState((arm_uc_hub_state_t)event->event_data);
}

void arm_uc_multicast_update_client_external_update_event(struct arm_event_s *event)
{
    arm_uc_firmware_address_t *address = (arm_uc_firmware_address_t *)event->data_ptr;
    arm_uc_multicast_m2m_client->external_update(address->start_address, address->size);
    arm_uc_multicast_process_finished(stored_ota_parameters.ota_session_id);
    ota_delete_session(stored_ota_parameters.ota_session_id);
    memset(stored_ota_parameters.ota_session_id, 0, OTA_SESSION_ID_SIZE);
    stored_ota_parameters.ota_process_count = 0;

    // Give some time to report UC hub state
    eventOS_event_timer_request(0, ARM_UC_OTA_FULL_REG_EVENT, arm_uc_multicast_tasklet_id, 20000);
}

#endif // defined(MULTICAST_UCHUB_INTEGRATION)

/************************************************/
/* Update client integration for Fota           */
/*  - handlers for reading/writing the firmware */
/*  - setting manifest                          */
/*  - activation of new firmware                */
/************************************************/
#if defined(MULTICAST_FOTA_INTEGRATION)

#include "fota_multicast.h"
#include "fota_status.h"
#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
static fota_multicast_br_image_params fota_br_image_params;
#endif

// fota callback declarations
void arm_uc_multicast_fota_multicast_node_post_update_fw_action_callback(int result);
void arm_uc_multicast_fota_multicast_node_post_manifest_received_action_callback(int result);
void arm_uc_multicast_fota_multicast_br_post_start_received_action_callback(int result);


static void arm_uc_multicast_update_client_init()
{
    arm_uc_multicast_manifest_rejected = true;
}

/*
 * write_fw_bytes_fptr() Function pointer for writing firmware bytes to storage
 *            Type: socket callback
 *            Valid for: Node
 *            Parameters:
 *              -OTA process ID
 *              -Byte offset (tells where data to be written)
 *              -To be written data byte count
 *              -Data pointer to be written data
 *            Return value:
 *              -Written byte count
 */
static uint32_t arm_uc_multicast_write_fw_bytes(uint8_t *ota_session_id, uint32_t offset, uint32_t count, uint8_t *from)
{
    tr_debug("arm_uc_multicast_write_fw_bytes, offset %" PRIu32 ", bytes %" PRIu32 "", offset, count);

    assert(memcmp(stored_ota_parameters.ota_session_id, ota_session_id, OTA_SESSION_ID_SIZE) == 0);
    assert(stored_ota_parameters.ota_process_count == 1);
    assert(stored_ota_parameters.fw_fragment_byte_count != 0);
    int result = FOTA_STATUS_SUCCESS;

#if defined(ARM_UC_MULTICAST_NODE_MODE)
    result = fota_multicast_node_write_image_fragment(from, offset, count);
#else
    (void)from;
    tr_error("Unexpected call to arm_uc_multicast_write_fw_bytes");
#endif

    return (result == FOTA_STATUS_SUCCESS) ? count : 0;
}

/*
 * read_fw_bytes_fptr() Function pointer for reading firmware bytes from storage
 *            Type: event queue callback
 *            Valid for: Node,BR
 *            Parameters:
 *              -OTA process ID
 *              -Byte offset (tells where data is to read)
 *              -Data byte count to be read
 *              -Data pointer to data to be read
 *            Return value:
 *              -Read byte count
 */
static uint32_t arm_uc_multicast_read_fw_bytes(uint8_t *ota_session_id, uint32_t offset, uint32_t count, uint8_t *to)
{
    tr_debug("arm_uc_multicast_read_fw_bytes, offset %" PRIu32 ", count %" PRIu32 "", offset, count);
    assert(memcmp(stored_ota_parameters.ota_session_id, ota_session_id, OTA_SESSION_ID_SIZE) == 0);
    assert(stored_ota_parameters.ota_process_count == 1);
#if defined(ARM_UC_MULTICAST_NODE_MODE)
    int result = fota_multicast_node_read_image_fragment(to, offset, count);
    return (result == FOTA_STATUS_SUCCESS) ? count : 0;
#endif
#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    int result = fota_multicast_br_read_from_image(to, offset, count);
    return (result == FOTA_STATUS_SUCCESS) ? count : 0;
#endif
    return count;
}

/*
 * send_update_fw_cmd_received_info_fptr() Function pointer for telling to application that firmware image can be taken in use
 *                                                  NOTE: OTA user (backend) must remove OTA process from data storage with DELETE command
 *            Type: socket callback
 *            Valid for: Node
 *            Parameters:
 *              -Delay time in seconds before taking new firmware in use
 */
static void arm_uc_multicast_send_update_fw_cmd_received_info(uint32_t delay)
{
    tr_info("arm_uc_multicast_send_update_fw_cmd_received_info");
#if defined(ARM_UC_MULTICAST_NODE_MODE)
    fota_multicast_node_on_activate(delay, arm_uc_multicast_fota_multicast_node_post_update_fw_action_callback);
#else
    (void)delay;
    tr_error("Unexpected call to arm_uc_multicast_send_update_fw_cmd_received_info!");
#endif
}

/*
 * start_received_fptr() Function pointer for telling to Update client that firmware multicasting is about to start.
 *                         Nodes should prepare Update client so it can receive write calls for received fragments.
 *                         Border router should initiate firmware download and signal back to libota with ota_firmware_pulled
 *                           when it's fully downloaded and Update client is ready to receive read calls.
 *            Type: resource callback (BR), socket callback (Node)
 *            Valid for: Node,BR
 *            Parameters:
 *              -Parameters for upcoming multicasting
 */
static ota_error_code_e arm_uc_multicast_start_received(ota_parameters_t *ota_parameters)
{
    tr_info("arm_uc_multicast_start_received");
    ota_error_code_e return_value = OTA_OK;

#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
    if (ota_parameters->pull_url_length && ota_parameters->pull_url_length <= FOTA_MANIFEST_URI_SIZE) {
        tr_info("arm_uc_multicast_start_received - Received pull url: %.*s", ota_parameters->pull_url_length, ota_parameters->pull_url_ptr);
        memcpy(fota_br_image_params.uri, ota_parameters->pull_url_ptr, ota_parameters->pull_url_length);
        fota_br_image_params.payload_size = ota_parameters->fw_total_byte_count;
        memcpy(fota_br_image_params.payload_digest, ota_parameters->whole_fw_checksum_tbl, OTA_WHOLE_FW_CHECKSUM_LENGTH);
        arm_uc_multicast_event.data.data_ptr = NULL;
        arm_uc_multicast_event.data.event_data = 0;
        arm_uc_multicast_event.data.event_id = MULTICAST_FOTA_EVENT_MANIFEST_RECEIVED;
        arm_uc_multicast_event.data.sender = 0;
        arm_uc_multicast_event.data.event_type = ARM_UC_OTA_MULTICAST_UPDATE_CLIENT_EVENT;
        arm_uc_multicast_event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
        arm_uc_multicast_event.data.receiver = arm_uc_multicast_tasklet_id;
        // defer handling this in Fota to give Mbed client time to respond to the POST request this comes from
        eventOS_event_send_user_allocated(&arm_uc_multicast_event);
    } else {
        return_value = OTA_PARAMETER_FAIL;
    }
#else
    int result = fota_multicast_node_set_fragment_size(ota_parameters->fw_fragment_byte_count);

    if (result != FOTA_STATUS_SUCCESS) {
        return OTA_PARAMETER_FAIL;
    }

    if (arm_uc_multicast_manifest_rejected) {
        result = fota_multicast_node_get_ready_for_image(ota_parameters->fw_total_byte_count);
        if (result != FOTA_STATUS_SUCCESS) {
            return_value = OTA_PARAMETER_FAIL;
        }
    }

#endif // defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)

    return return_value;
}

/*
 * process_finished_fptr() Function pointer for telling to Update client that process is finished and resources
 *                           can be freed to receive new updates.
 *            Type: event queue callback
 *            Valid for: BR
 */
static void arm_uc_multicast_process_finished(uint8_t */*session_id*/)
{
    tr_info("arm_uc_multicast_process_finished");
    arm_uc_multicast_event.data.data_ptr = NULL;
    arm_uc_multicast_event.data.event_data = 0;
    arm_uc_multicast_event.data.event_id = 0;
    arm_uc_multicast_event.data.sender = 0;
    arm_uc_multicast_event.data.event_type = ARM_UC_OTA_DELETE_SESSION_EVENT;
    arm_uc_multicast_event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
    arm_uc_multicast_event.data.receiver = arm_uc_multicast_tasklet_id;

    eventOS_event_send_user_allocated(&arm_uc_multicast_event);
}

/*
 * manifest_received_fptr() Function pointer for telling to Update client that firmware manifest has been received
 *            Type: socket callback
 *            Valid for: Node
 *            Parameters:
 *              -Pointer to payload with manifest contents
 *              -Length of manifest payload
 */
ota_error_code_e arm_uc_multicast_manifest_received(uint8_t *payload_ptr, uint32_t payload_len)
{
    int result = FOTA_STATUS_SUCCESS;
#if defined(ARM_UC_MULTICAST_NODE_MODE)
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (payload) {
        memcpy(payload, payload_ptr, payload_len);
        arm_uc_multicast_event.data.data_ptr = (void *)payload;
        arm_uc_multicast_event.data.event_data = payload_len;
        arm_uc_multicast_event.data.event_id = MULTICAST_FOTA_EVENT_MANIFEST_RECEIVED;
        arm_uc_multicast_event.data.sender = 0;
        arm_uc_multicast_event.data.event_type = ARM_UC_OTA_MULTICAST_UPDATE_CLIENT_EVENT;
        arm_uc_multicast_event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
        arm_uc_multicast_event.data.receiver = arm_uc_multicast_tasklet_id;

        eventOS_event_send_user_allocated(&arm_uc_multicast_event);
    } else {
        tr_error("arm_uc_multicast_manifest_received - failed to allocate memory");
        result = FOTA_STATUS_OUT_OF_MEMORY;
    }
#else
    (void)payload_ptr;
    (void)payload_len;
    tr_error("Unexpected call to arm_uc_multicast_manifest_received!");
#endif
    return (result == FOTA_STATUS_SUCCESS) ? OTA_OK : OTA_PARAMETER_FAIL;
}

/*
 * firmware_ready_fptr() Function pointer for telling to Update client that firmware image has been fully received
 *            Type: event queue callback
 *            Valid for: Node
 */
void arm_uc_multicast_firmware_ready()
{
#if defined(ARM_UC_MULTICAST_NODE_MODE)
    fota_multicast_node_on_image_ready();
#endif
}

/*
 * Fota callback after firmware has been activated with fota_multicast_node_on_activate.
 */
void arm_uc_multicast_fota_multicast_node_post_update_fw_action_callback(int result)
{
    (void)result;
    // for next update, set arm_uc_multicast_manifest_rejected = true so if node misses
    //  manifest alltogether it knows to call the fota_multicast_node_get_ready_for_image
    arm_uc_multicast_manifest_rejected = true;
}

/*
 * Fota callback after manifest has been succesfully inserted with fota_multicast_node_on_manifest.
 */
void arm_uc_multicast_fota_multicast_node_post_manifest_received_action_callback(int result)
{
    if (result != FOTA_STATUS_SUCCESS) {
        tr_error("Error setting manifest to fota: %d", result);
        arm_uc_multicast_manifest_rejected = true;
    } else {
        tr_debug("Manifest set to fota.");
        arm_uc_multicast_manifest_rejected = false;
    }
}

/*
 * Fota callback after firmware has been downloaded with fota_multicast_br_on_image_request.
 */
void arm_uc_multicast_fota_multicast_br_post_start_received_action_callback(int result)
{
    if (result == FOTA_STATUS_SUCCESS) {
        arm_uc_multicast_event.data.data_ptr = NULL;
        arm_uc_multicast_event.data.event_data = 0;
        arm_uc_multicast_event.data.event_id = 0;
        arm_uc_multicast_event.data.sender = 0;
        arm_uc_multicast_event.data.event_type = ARM_UC_OTA_MULTICAST_DL_DONE_EVENT;
        arm_uc_multicast_event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;
        arm_uc_multicast_event.data.receiver = arm_uc_multicast_tasklet_id;

        eventOS_event_send_user_allocated(&arm_uc_multicast_event);
    } else {
        // TODO: abort libota?
    }
}

/*
 * Event queue callback for decoupling libota callbacks and Update client process
 */
void arm_uc_multicast_update_client_event(struct arm_event_s *event)
{
    multicast_fota_event fota_event = (multicast_fota_event)event->event_id;

    switch (fota_event) {
        case MULTICAST_FOTA_EVENT_MANIFEST_RECEIVED:
#if defined(ARM_UC_MULTICAST_BORDER_ROUTER_MODE)
            // TODO: check error code?
            fota_multicast_br_on_image_request(&fota_br_image_params, arm_uc_multicast_fota_multicast_br_post_start_received_action_callback);
#else
            if (fota_multicast_node_on_manifest((uint8_t *)event->data_ptr,
                                                event->event_data,
                                                arm_uc_multicast_fota_multicast_node_post_manifest_received_action_callback) != FOTA_STATUS_SUCCESS) {
                ota_send_error(OTA_PARAMETER_FAIL);
            }

            free(event->data_ptr);
#endif // ARM_UC_MULTICAST_BORDER_ROUTER_MODE
            break;
        default:
            tr_error("Unknown event in arm_uc_multicast_update_client_event! (%d)", (int)fota_event);
            break;
    }
}

void arm_uc_multicast_update_client_external_update_event(struct arm_event_s *event)
{
    // to keep the event handler generic, should never get called in fota case as external update is
    // handled with component update
    (void)event;
}

#endif // defined(MULTICAST_FOTA_INTEGRATION)

#endif // defined(LIBOTA_ENABLED) && (LIBOTA_ENABLED)
