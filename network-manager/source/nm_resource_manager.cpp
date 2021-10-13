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

#include <stdio.h>
#include <stdint.h>
#include "mbed.h"
#include "mbed-cloud-client/MbedCloudClient.h" // Required for new MbedCloudClient()
#include "factory_configurator_client.h"       // Required for fcc_* functions and FCC_* defines
#include "m2mresource.h"                       // Required for M2MResource
#include "mbed-trace/mbed_trace.h"             // Required for mbed_trace_*
#include "nm_cbor_helper.h"
#include "nm_kvstore_helper.h"
#include "WisunInterface.h"
#include "WisunBorderRouter.h"
#include "nm_resource_manager.h"
#include "nm_interface_manager.h"
#include "NetworkManager_internal.h"
#include "nm_dynmem_helper.h"

#define TRACE_GROUP "NMrm"
#define ENABLE_DEBUG_PRINT_STREAM 0

#define APP_STAT_MAX_BUF APP_STAT_MAX_ENCODER_BUF

static M2MResource *ws_config;
static M2MResource *br_config;
static M2MResource *ws_stats;
static M2MResource *app_stats;
static M2MResource *routing_table;
static M2MResource *nm_stats;
static M2MResource *br_stats;
static M2MResource *node_stats;
static M2MResource *ch_noise;
#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
static M2MResource *reset_parameter;
static M2MResource *nbr_info;
#endif

#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
static M2MResource *time_sync;
#endif

typedef struct {
    M2MResource *res_obj;
    uint8_t *data;
    size_t len;
} res_set_data_t;

/* If someone re-entering get request before previous get request completes
 * will leads to memory leak
 */
static uint8_t *ws_config_buf = NULL;
static uint8_t *br_config_buf = NULL;
static uint8_t *app_stats_buf = NULL;
static uint8_t *nm_stat_buf = NULL;
static uint8_t *ws_stats_buf = NULL;
static uint8_t *ch_noise_buf = NULL;
static uint8_t *br_stats_buf = NULL;
static uint8_t *routing_table_buf = NULL;
static uint8_t *node_stats_buf = NULL;
static uint8_t *res_data = NULL;
#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
static uint8_t *nbr_info_buf = NULL;
#endif

#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
static uint8_t *time_sync_buf = NULL;
#endif

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

#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
static void reset_parameter_cb(const char * /*object_name*/)
{
    res_set_data_t *res_data = (res_set_data_t *)nm_dyn_mem_alloc(sizeof(res_set_data_t));
    if (res_data == NULL) {
        return;
    }
    tr_info("Reset Parameter callback received");
    res_data->res_obj = reset_parameter;
    res_data->len = 0;
    res_data->data = NULL;
    nm_post_event(NM_EVENT_RESOURCE_SET, 0, res_data);
}
#endif

#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
static void time_sync_cb(const char * /*object_name*/)
{
    uint8_t *received_data = NULL;
    uint32_t received_size = 0;

    res_set_data_t *res_data = (res_set_data_t *)nm_dyn_mem_alloc(sizeof(res_set_data_t));
    if (res_data == NULL) {
        return;
    }

    received_size = (uint32_t)time_sync->value_length();
    time_sync->get_value(received_data, received_size);
    tr_info("Received br_config [len = %lu]", received_size);
    print_stream(received_data, received_size);

    res_data->res_obj = time_sync;
    res_data->len = (size_t)received_size;
    res_data->data = received_data;
    nm_post_event(NM_EVENT_RESOURCE_SET, 0, res_data);
}
#endif

static nm_status_t nm_res_get_ws_config_from_kvstore(uint8_t **datap, size_t *length)
{
    if (get_lenght_from_KVstore(kv_key_ws, length) == NM_STATUS_FAIL) {
        tr_warn("Wi-SUN Configuration Key length is not available in KVStore");
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
        tr_warn("Border router configuration Key length is not available in KVStore");
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

#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
static nm_status_t nm_res_get_timing_sync_data(uint8_t **datap, size_t *length)
{
    if (get_lenght_from_KVstore(kv_key_tm, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to get Length from KVStore for time sync configuration");
        return NM_STATUS_FAIL;
    }

    if (datap == NULL) {
        return NM_STATUS_FAIL;
    }

    *datap = (uint8_t *)nm_dyn_mem_alloc(*length);
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (get_data_from_kvstore(kv_key_tm, *datap, *length) == NM_STATUS_FAIL) {
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}
#endif

static nm_status_t nm_res_get_app_stats(uint8_t **datap, size_t *length)
{

    nm_app_statistics_t app_stats = {0};

    const mem_stat_t *ns_mem_stats = ns_dyn_mem_get_mem_stat();
    if (ns_mem_stats != NULL) {
        memcpy((uint8_t *)&app_stats.mem_stats, ns_mem_stats, sizeof(mem_stat_t));
    }

    mbed_stats_cpu_get(&app_stats.cpu_stats);
    mbed_stats_heap_get(&app_stats.heap_stats);

    *datap = (uint8_t *)nm_dyn_mem_alloc(APP_STAT_MAX_BUF);
    if (*datap == NULL) {
        tr_error("FAILED: To allocate memory for App data");
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&app_stats, *datap, APP, length) == NM_STATUS_FAIL) {
        tr_error("FAILED: To CBORise Application Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}

static coap_response_code_e resource_read_requested(const M2MResourceBase &resource,
                                                    uint8_t *&buffer,
                                                    size_t &buffer_size,
                                                    size_t &total_size,
                                                    const size_t offset,
                                                    void *client_args)
{
    nm_status_t status = NM_STATUS_FAIL;
    static size_t len = 0;
    tr_info("GET request received for resource: %s", resource.uri_path());

    if (offset == 0) {
        M2MBase *obj = (M2MBase *)client_args;
        len = 0;
        if (obj == ws_config) {
            status = nm_res_get_ws_config_from_kvstore(&ws_config_buf, &len);
            res_data = ws_config_buf;
        } else if (obj == br_config) {
            status = nm_res_get_br_config_from_kvstore(&br_config_buf, &len);
            res_data = br_config_buf;
        } else if (obj == app_stats) {
            status = nm_res_get_app_stats(&app_stats_buf, &len);
            res_data = app_stats_buf;
        } else if (obj == nm_stats) {
            status = nm_res_get_nm_stats(&nm_stat_buf, &len);
            res_data = nm_stat_buf;
        } else if (obj == ws_stats) {
            status = nm_res_get_ws_stats(&ws_stats_buf, &len);
            res_data = ws_stats_buf;
        } else if (obj == ch_noise) {
            status = nm_res_get_ch_noise_stats(&ch_noise_buf, &len);
            res_data = ch_noise_buf;
        } else if (obj == br_stats) {
            status = nm_res_get_br_stats(&br_stats_buf, &len);
            res_data = br_stats_buf;
        } else if (obj == routing_table) {
            status = nm_res_get_routing_table(&routing_table_buf, &len);
            res_data = routing_table_buf;
        } else if (obj == node_stats) {
            status = nm_res_get_node_stats(&node_stats_buf, &len);
            res_data = node_stats_buf;
#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
        } else if (obj == nbr_info) {
            status = nm_res_get_nbr_info_stats(&nbr_info_buf, &len);
            res_data = nbr_info_buf;
#endif
#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
        } else if (obj == time_sync) {
            status = nm_res_get_timing_sync_data(&time_sync_buf, &len);
            res_data = time_sync_buf;
#endif //#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
        } else {
            tr_err("FAILED: Unknown client_args received in %s", __func__);
        }
        if (status != NM_STATUS_SUCCESS) {
            return COAP_RESPONSE_INTERNAL_SERVER_ERROR;
        }
    }

    if (!res_data) {
        return COAP_RESPONSE_INTERNAL_SERVER_ERROR;
    }

    total_size = len;

    // Adjust last package size
    if (offset + buffer_size > total_size) {
        buffer_size = total_size - offset;
    }

    // Read data from offset
    buffer = (uint8_t *)res_data + offset;

    return COAP_RESPONSE_CONTENT;
}

void msg_delivery_handle(const M2MBase &base,
                         const M2MBase::MessageDeliveryStatus status,
                         const M2MBase::MessageType type,
                         void *client_args)
{
    M2MBase *obj = (M2MBase *)client_args;
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (obj == ws_config) {
            if (ws_config_buf != NULL) {
                nm_dyn_mem_free(ws_config_buf);
                ws_config_buf = NULL;
                tr_debug("ws_config data Memory freed");
            }
        } else if (obj == br_config) {
            if (br_config_buf != NULL) {
                nm_dyn_mem_free(br_config_buf);
                br_config_buf = NULL;
                tr_debug("br_config data Memory freed");
            }
        } else if (obj == app_stats) {
            if (app_stats_buf != NULL) {
                nm_dyn_mem_free(app_stats_buf);
                app_stats_buf = NULL;
                tr_debug("Application data Memory freed");
            }
        } else if (obj == nm_stats) {
            if (nm_stat_buf != NULL) {
                nm_dyn_mem_free(nm_stat_buf);
                nm_stat_buf = NULL;
                tr_debug("nm_stat data Memory freed");
            }
        } else if (obj == ws_stats) {
            if (ws_stats_buf != NULL) {
                nm_dyn_mem_free(ws_stats_buf);
                ws_stats_buf = NULL;
                tr_debug("ws_stats data Memory freed");
            }
        } else if (obj == ch_noise) {
            if (ch_noise_buf != NULL) {
                nm_dyn_mem_free(ch_noise_buf);
                ch_noise_buf = NULL;
                tr_debug("ch_noise data Memory freed");
            }
        } else if (obj == br_stats) {
            if (br_stats_buf != NULL) {
                nm_dyn_mem_free(br_stats_buf);
                br_stats_buf = NULL;
                tr_debug("br_stats data Memory freed");
            }
        } else if (obj == routing_table) {
            if (routing_table_buf != NULL) {
                nm_dyn_mem_free(routing_table_buf);
                routing_table_buf = NULL;
                tr_debug("routing_table data Memory freed");
            }
        } else if (obj == node_stats) {
            if (node_stats_buf != NULL) {
                nm_dyn_mem_free(node_stats_buf);
                node_stats_buf = NULL;
                tr_debug("node_stats data Memory freed");
            }
#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
        } else if (obj == nbr_info) {
            if (nbr_info_buf != NULL) {
                nm_dyn_mem_free(nbr_info_buf);
                nbr_info_buf = NULL;
                tr_debug("nbr_info data Memory freed");
            }
#endif
#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
        } else if (obj == time_sync) {
            if (time_sync_buf != NULL) {
                nm_dyn_mem_free(time_sync_buf);
                time_sync_buf = NULL;
                tr_debug("Time sync data Memory freed");
            }
#endif //#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
        } else {
            tr_err("FAILED: Unknown client_args received in %s", __func__);
        }
    }
}

nm_status_t nm_res_manager_create(void *obj_list)
{
    M2MObjectList *m2m_obj_list = (M2MObjectList *)obj_list;
    tr_info("Creating Network Manager Resources");

    ws_config = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 1, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
    if (ws_config->set_value_updated_function(ws_config_cb) != true) {
        tr_error("ws_config->set_value_updated_function() failed");
        return NM_STATUS_FAIL;
    }
    ws_config->set_message_delivery_status_cb(msg_delivery_handle, ws_config);
    ws_config->set_read_resource_function(resource_read_requested, ws_config);

    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        br_config = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 2, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
        if (br_config->set_value_updated_function(br_config_cb) != true) {
            tr_error("br_config->set_value_updated_function() failed");
            return NM_STATUS_FAIL;
        }
        br_config->set_message_delivery_status_cb(msg_delivery_handle, br_config);
        br_config->set_read_resource_function(resource_read_requested, br_config);

#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
        time_sync = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 12, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
        if (time_sync->set_value_updated_function(time_sync_cb) != true) {
            tr_error("time_sync->set_value_updated_function() failed");
            return NM_STATUS_FAIL;
        }
        time_sync->set_message_delivery_status_cb(msg_delivery_handle, time_sync);
        time_sync->set_read_resource_function(resource_read_requested, time_sync);
#endif //#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
    }

    app_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 3, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    app_stats->set_message_delivery_status_cb(msg_delivery_handle, app_stats);
    app_stats->set_read_resource_function(resource_read_requested, app_stats);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
    app_stats->set_observable(true);
#endif

    nm_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 4, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    nm_stats->set_message_delivery_status_cb(msg_delivery_handle, nm_stats);
    nm_stats->set_read_resource_function(resource_read_requested, nm_stats);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
    nm_stats->set_observable(true);
#endif

    ws_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 5, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    ws_stats->set_message_delivery_status_cb(msg_delivery_handle, ws_stats);
    ws_stats->set_read_resource_function(resource_read_requested, ws_stats);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
    ws_stats->set_observable(true);
#endif

    ch_noise = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 10, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    ch_noise->set_message_delivery_status_cb(msg_delivery_handle, ch_noise);
    ch_noise->set_read_resource_function(resource_read_requested, ch_noise);
 #if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
    ch_noise->set_observable(true);
#endif

#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
    reset_parameter = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 8, M2MResourceInstance::OPAQUE, M2MBase::PUT_ALLOWED);
    if (reset_parameter->set_value_updated_function(reset_parameter_cb) != true) {
        tr_error("reset_parameter->set_value_updated_function() failed");
        return NM_STATUS_FAIL;
    }

    nbr_info = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 11, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    nbr_info->set_message_delivery_status_cb(msg_delivery_handle, nbr_info);
    nbr_info->set_read_resource_function(resource_read_requested, nbr_info);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
    nbr_info->set_observable(true);
#endif

#endif

    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        br_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 6, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        br_stats->set_message_delivery_status_cb(msg_delivery_handle, br_stats);
        br_stats->set_read_resource_function(resource_read_requested, br_stats);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
        br_stats->set_observable(true);
#endif

        routing_table = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 9, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        routing_table->set_message_delivery_status_cb(msg_delivery_handle, routing_table);
        routing_table->set_read_resource_function(resource_read_requested, routing_table);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
        routing_table->set_observable(true);
#endif

    }
    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_ROUTER) {
        node_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 7, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        node_stats->set_message_delivery_status_cb(msg_delivery_handle, node_stats);
        node_stats->set_read_resource_function(resource_read_requested, node_stats);
#if defined (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE) && (MBED_CLIENT_ENABLE_DYNAMIC_OBSERVABLE == 1)
        node_stats->set_observable(true);
#endif
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

    if (res_obj == app_stats) {
        if (nm_res_get_app_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource app_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set APP Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("APP Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch APP Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == nm_stats) {
        if (nm_res_get_nm_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource nm_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set General Network Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("General Network Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch General Network Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == ws_stats) {
        if (nm_res_get_ws_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource ws_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set Wi-SUN common Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Wi-SUN common Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch Wi-SUN common Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == br_stats) {
        if (nm_res_get_br_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource br_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set Border router Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Border router Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch Border router Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == node_stats) {
        if (nm_res_get_node_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource node_stats [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set Node Statistics resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Node Statistics resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch Node Statistics");
        return NM_STATUS_FAIL;
    }

    if (res_obj == routing_table) {
        if (nm_res_get_routing_table(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource routing_table [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set Routing Table resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Routing Table resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch Routing Table");
        return NM_STATUS_FAIL;
    }

    if (res_obj == ch_noise) {
        if (nm_res_get_ch_noise_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource ch_noise [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set Channel noise resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Channel noise resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch Channel noise");
        return NM_STATUS_FAIL;
    }

#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
    if (res_obj == nbr_info) {
        if (nm_res_get_nbr_info_stats(&buf, &len) == NM_STATUS_SUCCESS) {
            tr_info("Setting value of resource nbr_info [len = %u] in Cloud Client", len);
            print_stream(buf, len);
            if (res_obj->set_value(buf, len) != true) {
                tr_warn("Could not set Neighbor Info. resource to Cloud Client");
                return NM_STATUS_FAIL;
            }
            tr_info("Neighbor Info. resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("Could not fetch Neighbor Info.");
        return NM_STATUS_FAIL;
    }
#endif

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

        return NM_STATUS_SUCCESS;
    }

#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
    if (res_data->res_obj == reset_parameter) {

        if (nm_reset_parameters() == NM_STATUS_FAIL) {
            tr_info("Reset Parameter FAILED");
        } else {
            tr_info("Reset Parameter SUCCESS");
        }
        nm_dyn_mem_free(res_data);

        return NM_STATUS_SUCCESS;
    }
#endif

#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)
    if (res_data->res_obj == time_sync) {
        if (nm_res_set_time_sync_config(res_data->data, res_data->len) == NM_STATUS_FAIL) {
            tr_error("Time sync Set Request FAILED");
        } else {
            tr_info("Time sync Set Request SUCCESS");
        }
        free(res_data->data);
        nm_dyn_mem_free(res_data);

        return NM_STATUS_SUCCESS;
    }

#endif //#if defined MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK && (MBED_CONF_MBED_MESH_API_SYSTEM_TIME_UPDATE_FROM_NANOSTACK == 1)

    /* To-Do :: Implement for other resources */
    return NM_STATUS_FAIL;
}

void nm_manager_res_refresh(void)
{
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, app_stats);
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, nm_stats);
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, ws_stats);
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, ch_noise);
#if ((MBED_VERSION > MBED_ENCODE_VERSION(6, 10, 0)) || ((MBED_VERSION < MBED_ENCODE_VERSION(6, 0, 0)) && (MBED_VERSION > MBED_ENCODE_VERSION(5, 15, 7))))
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, nbr_info);
#endif
    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, br_stats);
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, routing_table);
    } else if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_ROUTER) {
        nm_post_event(NM_EVENT_RESOURCE_GET, 0, node_stats);
    }
}

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
