/*
 * Copyright (c) 2020-2021 Pelion. All rights reserved.
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
#include "WisunInterface.h"
#include "WisunBorderRouter.h"
#include "mbed-cloud-client/MbedCloudClient.h" // Required for new MbedCloudClient()
#include "NetworkManager.h"
#include "NetworkManager_internal.h"
#include "nm_interface_manager.h"
#include "nm_resource_manager.h"

#define TRACE_GROUP "NM  "

static int8_t nm_handler_id = -1;
// Refresh time interval in minutes
#if defined MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER && (MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER != 0)
static int32_t stats_refresh_interval = MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER * 60 * 1000; /* Milli Seconds */
#else
static int32_t stats_refresh_interval = 0;
#endif

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

static void nm_event_handler(arm_event_s *event)
{
    switch (event->event_type) {
        case NM_EVENT_INIT:
#if defined MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER && (MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER != 0)
                nm_post_timeout_event(NM_EVENT_STATS_REFRESH_TIMEOUT, stats_refresh_interval);
#else
                tr_debug("Observable timer event not posted");
#endif
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
        case NM_EVENT_STATS_REFRESH_TIMEOUT:
#if defined MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER && (MBED_CONF_MBED_CLOUD_CLIENT_OBSERVABLE_TIMER != 0)
            tr_info("Statistics Resource Refresh Timeout");
            nm_manager_res_refresh();
            nm_post_timeout_event(NM_EVENT_STATS_REFRESH_TIMEOUT, stats_refresh_interval);
#else
            tr_warn("NM_EVENT_STATS_REFRESH_TIMEOUT should not occurred");
#endif
            break;
        case NM_EVENT_RESOURCE_GET:
            tr_info("Resource Get Event Received");
            if (nm_res_manager_get(event->data_ptr) == NM_STATUS_FAIL) {
                tr_warn("FAILED to get resource value");
            }
            break;
        default:
            tr_warn("UNEXPECTED Event %d", event->event_type);
            break;
    }
}

nm_error_t NetworkManager::configure_factory_mac_address(void *mesh_iface, void *backhaul_iface)
{
    if (nm_mesh_configure_factory_mac_address((NetworkInterface *)mesh_iface) == NM_STATUS_FAIL) {
        tr_error("Could not configure Factory MAC Address on Mesh Interface");
        return NM_ERROR_UNKNOWN;
    }

    if (nm_backhaul_configure_factory_mac_address((NetworkInterface *)backhaul_iface) == NM_STATUS_FAIL) {
        tr_error("Could not configure Factory MAC Address on Backhaul Interface");
        return NM_ERROR_UNKNOWN;
    }

    return NM_ERROR_NONE;
}

nm_error_t NetworkManager::configure_factory_mac_address(void *mesh_iface)
{
    if (nm_mesh_configure_factory_mac_address((NetworkInterface *)mesh_iface) == NM_STATUS_FAIL) {
        tr_error("Could not configure Factory MAC Address on Mesh Interface");
        return NM_ERROR_UNKNOWN;
    }

    return NM_ERROR_NONE;
}

nm_error_t NetworkManager::reg_and_config_iface(void *mesh_iface, void *backhaul_iface, void *br_iface)
{
    register_interfaces((NetworkInterface *)mesh_iface, (NetworkInterface *)backhaul_iface, (WisunBorderRouter *)br_iface);

    if (nm_factory_configure_mesh_iface() == NM_STATUS_FAIL) {
        tr_error("Could not SET Factory Configuration on Mesh Interface");
        return NM_ERROR_UNKNOWN;
    }
    if (nm_configure_mesh_iface() == NM_STATUS_FAIL) {
        tr_error("Could not configure Mesh Interface");
        return NM_ERROR_UNKNOWN;
    }
    if (nm_factory_configure_border_router() == NM_STATUS_FAIL) {
        tr_error("Could not SET Factory Configuration on BR Interface");
        return NM_ERROR_UNKNOWN;
    }
    if (nm_configure_border_router() == NM_STATUS_FAIL) {
        tr_error("Could not configure BR Interface");
        return NM_ERROR_UNKNOWN;
    }

    return NM_ERROR_NONE;
}

nm_error_t NetworkManager::reg_and_config_iface(void *mesh_iface)
{
    register_interfaces((NetworkInterface *)mesh_iface, NULL, NULL);

    if (nm_factory_configure_mesh_iface() == NM_STATUS_FAIL) {
        tr_error("Could not SET Factory Configuration on Mesh Interface");
        return NM_ERROR_UNKNOWN;
    }
    if (nm_configure_mesh_iface() == NM_STATUS_FAIL) {
        tr_error("Could not configure Mesh Interface");
        return NM_ERROR_UNKNOWN;
    }

    return NM_ERROR_NONE;
}

nm_error_t NetworkManager::create_resource(M2MObjectList *m2m_obj_list)
{
    if (m2m_obj_list == NULL) {
        tr_error("FAILED to create resource: M2M Object List NULL\n");
        return NM_ERROR_UNKNOWN;
    }

    if (nm_res_manager_create(m2m_obj_list) == NM_STATUS_FAIL) {
        tr_error("FAILED to create resource");
        return NM_ERROR_UNKNOWN;
    }
    return NM_ERROR_NONE;
}

void NetworkManager::nm_cloud_client_connect_indication(void)
{
    // Put the handler creation in a critical code block for the case that this function is called after the start of the event loop
    eventOS_scheduler_mutex_wait();
    if (nm_handler_id == -1) { // Register the handler only if it hadn't been registered before
        nm_handler_id = eventOS_event_handler_create(nm_event_handler, NM_EVENT_INIT);
        if (nm_handler_id < 0) {
            tr_err("Could not start Network Manager: Error Creating event handler");
            return;
        }
    }
    eventOS_scheduler_mutex_release();

    mesh_interface_connected();
}

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
