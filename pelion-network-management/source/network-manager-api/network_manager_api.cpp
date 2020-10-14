/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if defined MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)

#include "mbed.h"
#include "mbed_trace.h"
#include "eventOS_scheduler.h"
#include "eventOS_event.h"
#include "eventOS_event_timer.h"
#include "network_manager_api.h"
#include "network_manager_internal.h"
#include "interface_manager_api.h"
#include "resource_manager_api.h"

#define TRACE_GROUP "NW_mgr"

typedef enum nm_state_type_e {
    NM_STATE_IDLE,
    NM_STATE_BACKHAUL_CONNECT,
    NM_STATE_MESH_CONNECT,
    NM_STATE_PDMC_WAIT,
    NM_STATE_RUNNING
} nm_state_t;

static nm_state_t nm_state;

static nm_app_cb app_indication_handler;
static int8_t nm_handler_id = -1;
static void *mesh_interface;
static void *backhaul_interface;

void nm_event_handler(arm_event_s *event);

static int32_t mesh_ip_check_interval = 20 * 1000;   /* Milli Seconds */

void nm_application_cb(nm_app_cb register_callback)
{
    tr_info("Registered application callback");
    /* Saving callback function context */
    app_indication_handler = register_callback;
}

/* initialize network manager */
void nm_init(void *obj_list)
{
    nm_state = NM_STATE_IDLE;

    // Put the handler creation in a critical code block for the case that this function is called after the start of the event loop
    eventOS_scheduler_mutex_wait();
    if (nm_handler_id == -1) { // Register the handler only if it hadn't been registered before
        nm_handler_id = eventOS_event_handler_create(nm_event_handler, NM_EVENT_IDLE);
        if (nm_handler_id < 0) {
            tr_err("Error creating network event handler");
        }
    }
    eventOS_scheduler_mutex_release();

    if (nm_res_manager_create(obj_list) == NM_STATUS_FAIL) {
        tr_err("FAILED to create resource");
    }
}

nm_status_t nm_post_event(nm_event_t event_type, uint8_t event_id, void *data)
{
    int8_t event_status;
    arm_event_s event = {
        .receiver = nm_handler_id, // ID we got when creating our handler
        .sender = 0,
        .event_type = event_type,
        .event_id = event_id,
        .data_ptr = data,
        .priority = ARM_LIB_LOW_PRIORITY_EVENT, // Application level priority
        .event_data = 0,
    };
    event_status = eventOS_event_send(&event);
    if (event_status < 0) {
        tr_err("Error scheduling event");
    }
    return NM_STATUS_SUCCESS;
}

nm_status_t nm_post_timeout_event(nm_event_t event_type, int32_t delay)
{
    arm_event_t event = { 0 };

    event.event_type = event_type;
    event.receiver = nm_handler_id;
    event.sender =  0;
    event.priority = ARM_LIB_LOW_PRIORITY_EVENT;

    tr_debug("Posting Timeout Event to nm_handler after %ld ms", delay);
    const int32_t delay_ticks = eventOS_event_timer_ms_to_ticks(delay);

    if (eventOS_event_send_after(&event, delay_ticks) == NULL) {
        tr_err("Error scheduling timeout event");
        return NM_STATUS_FAIL;
    } else {
        return NM_STATUS_SUCCESS;
    }
}

void nm_event_handler(arm_event_s *event)
{
    switch (nm_state) {
        case NM_STATE_IDLE:
            switch (event->event_type) {
                case NM_EVENT_IDLE:
                    /*Implement Router init here*/
                    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_ROUTER) {
                        if (nm_iface_mesh_init() == NM_STATUS_FAIL) {
                            tr_err("FAILED to Initialize Mesh Interface");
                        }
                    }
                    break;
                case NM_EVENT_CONNECT:
                    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
                        nm_iface_backhaul_up();
                        nm_state = NM_STATE_BACKHAUL_CONNECT;
                    } else {
                        tr_info("Starting Mesh Interface");
                        /* Bring up mesh interface */
                        if (nm_iface_mesh_up() == NM_STATUS_FAIL) {
                            tr_err("FAILED to Bring Mesh Interface UP");
                        } else {
                            nm_state = NM_STATE_MESH_CONNECT;
                        }
                    }
                    break;
                default:
                    tr_warn("UNEXPECTED Event %d in NM_STATE_IDLE", event->event_type);
                    break;
            }
            break;
        case NM_STATE_BACKHAUL_CONNECT:
            switch (event->event_type) {
                case NM_EVENT_BACKHAUL_CONNECTED:
                    switch (event->event_id) {
                        /* Backhaul interface connect success */
                        case IFACE_STATUS_SUCCESS:
                            backhaul_interface = event->data_ptr;
                            /* Bring up mesh interface */
                            if (nm_iface_mesh_init() == NM_STATUS_FAIL) {
                                tr_err("Failed to Initialize Mesh Interface");
                                /* To-Do: Send request to application for PDMC deregistration */
                                /* To-Do: Call interface manager API to disconnect Backhaul */
                            }
                            tr_info("Starting Mesh Interface");
                            /* Bring up mesh interface */
                            if (nm_iface_mesh_up() == NM_STATUS_FAIL) {
                                tr_err("Failed to Bring Mesh Interface UP");
                                /* To-Do: Send request to application for PDMC deregistration */
                                /* To-Do: Call interface manager API to disconnect Backhaul */
                            }
                            nm_state = NM_STATE_MESH_CONNECT;
                            break;
                        /* Backhaul interface connect failure */
                        case IFACE_STATUS_FAIL:
                            nm_state = NM_STATE_IDLE;
                            /*
                             * Do we need to Send Failure indication to application ??
                             * what else need to be taken care here ??
                             */
                            break;
                    }
                    break;
                default:
                    tr_warn("UNEXPECTED Event %d in NM_STATE_BACKHAUL_CONNECT", event->event_type);
                    break;
            }
            break;
        case NM_STATE_MESH_CONNECT:
            switch (event->event_type) {
                case NM_EVENT_MESH_CONNECTED:
                    switch (event->event_id) {
                        /* Mesh interface connect success */
                        case IFACE_STATUS_SUCCESS:
                            if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
                                if (nm_iface_br_up() == NM_STATUS_FAIL) {
                                    tr_err("Failed to Bring Border Router Interface UP");
                                    break;
                                }
                            }
                            mesh_interface = event->data_ptr;
                            nm_post_timeout_event(NM_EVENT_CHECK_MESH_IFACE_IP, mesh_ip_check_interval);
                            break;
                        case IFACE_STATUS_FAIL:
                            /*
                             * Do we need to Send Failure indication to application ??
                             * what else need to be taken care here ??
                             */
                            break;
                    }
                    break;
                case NM_EVENT_CHECK_MESH_IFACE_IP:
                    if (nm_iface_check_mesh_ip() == NM_STATUS_FAIL) {
                        nm_post_timeout_event(NM_EVENT_CHECK_MESH_IFACE_IP, mesh_ip_check_interval);
                        break;
                    }
                    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
                        app_indication_handler(NM_CONNECTED, backhaul_interface);
                    } else {
                        app_indication_handler(NM_CONNECTED, mesh_interface);
                    }
                    nm_state = NM_STATE_PDMC_WAIT;
                    break;
                default:
                    tr_warn("UNEXPECTED Event %d in NM_STATE_MESH_CONNECT", event->event_type);
                    break;
            }
            break;
        case NM_STATE_PDMC_WAIT:
            switch (event->event_type) {
                case NM_EVENT_PDMC_CONNECTED:
                    nm_state = NM_STATE_RUNNING;
                    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
                        nm_res_manager_br_config_refresh();
                    }
                    nm_res_manager_ws_config_refresh();
                    app_indication_handler(NM_INIT_CONF, NULL);
                    break;
                default:
                    tr_warn("UNEXPECTED Event %d in NM_STATE_PDMC_WAIT", event->event_type);
                    break;
            }
            break;
        case NM_STATE_RUNNING:
            switch (event->event_type) {
                case NM_EVENT_RESOURCE_GET:
                    tr_info("Resource Get Event Received");
                    if (nm_res_manager_get(event->data_ptr) == NM_STATUS_FAIL) {
                        tr_warn("FAILED to get resource value");
                    }
                    break;
                case NM_EVENT_RESOURCE_SET:
                    tr_info("Resource Set Event Received");
                    if (nm_res_manager_set(event->data_ptr) == NM_STATUS_FAIL) {
                        tr_error("FAILED to set resource value");
                    }
                    break;
                case NM_EVENT_APPLY_WS_CONFIG_AFTER_DELAY:
                    tr_info("Applying ws_config after delay");
                    apply_ws_config_to_nannostack();
                    break;
                case NM_EVENT_APPLY_BR_CONFIG_AFTER_DELAY:
                    tr_info("Applying br_config after delay");
                    apply_br_config_to_nannostack();
                    break;
                default:
                    tr_warn("UNEXPECTED Event %d in NM_STATE_RUNNING", event->event_type);
                    break;
            }
            break;
        default:
            tr_warn("Network Manager State Invalid");
            break;
    }//switch (nm_state)
}

void nm_cloud_client_connect_notification(void)
{
    nm_post_event(NM_EVENT_PDMC_CONNECTED, 0, NULL);
}

void nm_connect(void)
{
    nm_post_event(NM_EVENT_CONNECT, 0, NULL);
}

void *nm_get_mesh_iface(void)
{
    return mesh_interface;
}

void *nm_get_br_instance(void)
{
    return nm_iface_get_br_instance();
}

void apply_ws_config_after_delay(uint16_t delay)
{
    tr_debug("starting ws_timer for %d seconds delay", delay);
    nm_post_timeout_event(NM_EVENT_APPLY_WS_CONFIG_AFTER_DELAY, delay * 1000);
}

void apply_br_config_after_delay(uint16_t delay)
{
    tr_debug("starting br_timer for %d seconds delay", delay);
    nm_post_timeout_event(NM_EVENT_APPLY_BR_CONFIG_AFTER_DELAY, delay * 1000);
}
#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
