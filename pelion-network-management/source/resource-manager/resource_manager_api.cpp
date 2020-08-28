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

#include <stdio.h>
#include <stdint.h>
#include "mbed.h"
#include "mbed-cloud-client/MbedCloudClient.h" // Required for new MbedCloudClient()
#include "factory_configurator_client.h"       // Required for fcc_* functions and FCC_* defines
#include "m2mresource.h"                       // Required for M2MResource
#include "mbed-trace/mbed_trace.h"             // Required for mbed_trace_*
#include "cbor_api.h"
#include "kvstore_api.h"
#include "resource_manager_api.h"
#include "interface_manager_api.h"
#include "network_manager_internal.h"
#include "nm_dynmem_api.h"

#define TRACE_GROUP "rs_mngr"
#define ENABLE_DEBUG_PRINT_STREAM 0

#define APP_STAT_MAX_BUF APP_STAT_MAX_ENCCODER_BUF

static M2MResource *ws_config;
static M2MResource *br_config;
static M2MResource *ws_stats;
static M2MResource *app_stats;
static M2MResource *routing_table;
static M2MResource *nm_stats;
static M2MResource *br_stats;
static M2MResource *node_stats;
static M2MResource *radio_stats;

typedef struct {
    M2MResource *res_obj;
    uint8_t *data;
    size_t len;
} res_set_data_t;

/* Function to overcome limitation of 32 bytes of length in tr_array */
static void print_stream(uint8_t *datap, uint32_t datal)
{
#if (ENABLE_DEBUG_PRINT_STREAM)
    uint32_t block_size, ii = 0;

    while (datal > 0) {
        block_size = datal > 32 ? 32 : datal;
        tr_info("%s", tr_array(datap + (ii * 32), block_size));
        datal = datal - block_size;
        ii++;
    }
#endif /*ENABLE_DEBUG_PRINT_STREAM*/
}


static void ws_config_cb(const char * /*object_name*/)
{
    uint8_t *received_data = NULL;
    uint32_t received_size = 0;

    res_set_data_t *res_data = (res_set_data_t *)nm_dyn_mem_alloc(sizeof(res_set_data_t));
    if (res_data == NULL) {
        return;
    }

    received_size = (uint32_t)ws_config->value_length();
    ws_config->get_value(received_data, received_size);
    tr_info("Received ws_config [len = %lu]", received_size);
    print_stream(received_data, received_size);

    res_data->res_obj = ws_config;
    res_data->len = (size_t)received_size;
    res_data->data = received_data;
    nm_post_event(NM_EVENT_RESOURCE_SET, 0, res_data);
}

static void br_config_cb(const char * /*object_name*/)
{
    uint8_t *received_data = NULL;
    uint32_t received_size = 0;

    res_set_data_t *res_data = (res_set_data_t *)nm_dyn_mem_alloc(sizeof(res_set_data_t));
    if (res_data == NULL) {
        return;
    }

    received_size = (uint32_t)br_config->value_length();
    br_config->get_value(received_data, received_size);
    tr_info("Received br_config [len = %lu]", received_size);
    print_stream(received_data, received_size);

    res_data->res_obj = br_config;
    res_data->len = (size_t)received_size;
    res_data->data = received_data;
    nm_post_event(NM_EVENT_RESOURCE_SET, 0, res_data);
}


static nm_status_t nm_res_get_ws_config_from_kvstore(uint8_t **datap, size_t *length)
{
    if (get_lenght_from_KVstore(kv_key_ws, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to get Length from KVStore for Wi-SUN Configuration");
        return NM_STATUS_FAIL;
    }

    if (datap == NULL) {
        return NM_STATUS_FAIL;
    }

    *datap = (uint8_t *)nm_dyn_mem_alloc(*length);
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (get_data_from_kvstore(kv_key_ws, *datap, *length) == NM_STATUS_FAIL) {
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}

static nm_status_t nm_res_get_br_config_from_kvstore(uint8_t **datap, size_t *length)
{
    if (get_lenght_from_KVstore(kv_key_br, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to get Length from KVStore for Border router configuration");
        return NM_STATUS_FAIL;
    }

    if (datap == NULL) {
        return NM_STATUS_FAIL;
    }

    *datap = (uint8_t *)nm_dyn_mem_alloc(*length);
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (get_data_from_kvstore(kv_key_br, *datap, *length) == NM_STATUS_FAIL) {
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}

static nm_status_t nm_res_get_app_stats(uint8_t **datap, size_t *length)
{
    nm_app_statistics_t app_stats = {0};

    if (datap == NULL) {
        return NM_STATUS_FAIL;
    }

    const mem_stat_t *ns_mem_stats = ns_dyn_mem_get_mem_stat();
    if (ns_mem_stats != NULL) {
        memcpy((uint8_t *)&app_stats.mem_stats, ns_mem_stats, sizeof(mem_stat_t));
    }

    mbed_stats_cpu_get(&app_stats.cpu_stats);
    mbed_stats_heap_get(&app_stats.heap_stats);

    *datap = (uint8_t *)nm_dyn_mem_alloc(APP_STAT_MAX_BUF);
    if (*datap == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&app_stats, *datap, APP, length) == NM_STATUS_FAIL) {
        tr_error("FAILED to CBORise Application Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_manager_create(void *obj_list)
{
    M2MObjectList *m2m_obj_list = (M2MObjectList *)obj_list;
    tr_info("Create resources");

    if (m2m_obj_list == NULL) {
        tr_error("FAILED to create resource: M2M Object List NULL\n");
        return NM_STATUS_FAIL;
    }

    // SET resource 7777/0/1111 /* Object ID and Resource ID for used temporary */
    ws_config = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 1111, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
    if (ws_config->set_value_updated_function(ws_config_cb) != true) {
        tr_error("ws_config->set_value_updated_function() failed");
        return NM_STATUS_FAIL;
    }
    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        // SET resource 7777/0/2222 /* Object ID and Resource ID for used temporary */
        br_config = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 2222, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
        if (br_config->set_value_updated_function(br_config_cb) != true) {
            tr_error("br_config->set_value_updated_function() failed");
            return NM_STATUS_FAIL;
        }
    }

    // GET resource 7777/0/3333 /* Object ID and Resource ID for used temporary */
    app_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 3333, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    app_stats->set_auto_observable(true);

    // GET resource 7777/0/4444 /* Object ID and Resource ID for used temporary */
    nm_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 4444, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    nm_stats->set_auto_observable(true);

    // GET resource 7777/0/5555 /* Object ID and Resource ID for used temporary */
    ws_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 5555, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    ws_stats->set_auto_observable(true);

    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        // GET resource 7777/0/6666 /* Object ID and Resource ID for used temporary */
        br_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 6666, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        br_stats->set_auto_observable(true);

        // GET resource 7777/0/9999 /* Object ID and Resource ID for used temporary */
        routing_table = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 9999, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        routing_table->set_auto_observable(true);
    }
    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_ROUTER) {
        // GET resource 7777/0/7777 /* Object ID and Resource ID for used temporary */
        node_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 7777, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        node_stats->set_auto_observable(true);

        // GET resource 7777/0/8888 /* Object ID and Resource ID for used temporary */
        radio_stats= M2MInterfaceFactory::create_resource(*m2m_obj_list, 7777, 0, 8888, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        radio_stats->set_auto_observable(true);
    }
    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_manager_get(void *resource_object)
{
    M2MResource *res_obj = (M2MResource *)resource_object;
    size_t len = 0;
    uint8_t *buf = NULL;

    if (res_obj == NULL) {
        tr_error("FAILED: Got NULL res_obj in func nm_res_manager_get");
        return NM_STATUS_FAIL;
    }

    if (res_obj == ws_config) {
        if (nm_res_get_ws_config_from_kvstore(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource ws_config [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set Wi-SUN Configuration resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Wi-SUN Configuration resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to retrieve Wi-SUN Configuration from KVStore");
        return NM_STATUS_FAIL;
    }

    if (res_obj == br_config) {
        if (nm_res_get_br_config_from_kvstore(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource br_config [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set BR Configuration resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("BR Configuration resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to retrieve BR Configuration from KVStore");
        return NM_STATUS_FAIL;
    }

    if (res_obj == ws_stats) {
        if (nm_res_get_ws_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource ws_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set WS Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("WS Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch WS Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == app_stats) {
        if (nm_res_get_app_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource app_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set APP Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("APP Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch APP Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == routing_table) {
        if (nm_res_get_routing_table(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource routing_table [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set Routing Table resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Routing Table resource value Set to Cloud Client");
            /* Do not need to free buf pointer. We may use the same memory next time */
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch Routing Table");
        return NM_STATUS_FAIL;
    }

    if (res_obj == nm_stats) {
        if (nm_res_get_nm_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource nm_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set General Network Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("nm Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch nm Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == br_stats) {
        if (nm_res_get_br_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource br_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set Border router Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("br Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch br Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == node_stats) {
        if (nm_res_get_node_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource node_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set node information to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("node_stats resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch node information");
        return NM_STATUS_FAIL;
    }

    if (res_obj == radio_stats) {
        if (nm_res_get_radio_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource radio_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("FAILED to set radio quality information to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("radio_stats resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to fetch radio quality information");
        return NM_STATUS_FAIL;
    }

    /* To-Do :: Implement for other resources */
    return NM_STATUS_FAIL;
}

nm_status_t nm_res_manager_set(void *resource_data)
{
    res_set_data_t *res_data = (res_set_data_t *)resource_data;
    if (res_data == NULL) {
        return NM_STATUS_FAIL;
    }

    if (res_data->res_obj == ws_config) {
        if (nm_res_set_ws_config(res_data->data, res_data->len) == NM_STATUS_FAIL) {
            tr_error("Wi-SUN Configuration Set Request FAILED");
        } else {
            tr_info("Wi-SUN Configuration Set Request SUCCESS");
        }
        free(res_data->data);
        nm_dyn_mem_free(res_data);

        /* Setting the updated data to pelion */
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, ws_config);
        return NM_STATUS_SUCCESS;
    }

    if (res_data->res_obj == br_config) {
        if (nm_res_set_br_config(res_data->data, res_data->len) == NM_STATUS_FAIL) {
            tr_error("BR Configuration Set Request FAILED");
        } else {
            tr_info("BR Configuration Set Request SUCCESS");
        }
        free(res_data->data);
        nm_dyn_mem_free(res_data);

        /* Setting the updated data to pelion */
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, br_config);
        return NM_STATUS_SUCCESS;
    }

    /* To-Do :: Implement for other resources */
    return NM_STATUS_FAIL;
}

void nm_res_manager_stats_refresh(void)
{
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, ws_stats);
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, app_stats);
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, nm_stats);
    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, br_stats);
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, routing_table);
    } else {
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, node_stats);
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, radio_stats);
    }
}

void nm_res_manager_ws_config_refresh(void)
{
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, ws_config);
}

void nm_res_manager_br_config_refresh(void)
{
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, br_config);
}

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)