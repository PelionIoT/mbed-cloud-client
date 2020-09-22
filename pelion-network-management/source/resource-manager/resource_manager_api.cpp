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

#define APP_STAT_MAX_BUF APP_STAT_MAX_ENCODER_BUF

static M2MResource *ws_config;
static M2MResource *br_config;
static M2MResource *ws_stats;
static M2MResource *app_stats;
static M2MResource *routing_table;
static M2MResource *nm_stats;
static M2MResource *br_stats;
static M2MResource *node_stats;
static M2MResource *radio_stats;
static M2MResource *ch_noise;

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

static uint8_t *app_datap = NULL;
void handle_app_stat_coap_request(const M2MBase &base,
                                  M2MBase::Operation operation,
                                  const uint8_t *token,
                                  const uint8_t token_len,
                                  const uint8_t *buffer,
                                  size_t buffer_size,
                                  void *client_args)
{
    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    nm_app_statistics_t app_stats = {0};
    size_t length = 0;

    const mem_stat_t *ns_mem_stats = ns_dyn_mem_get_mem_stat();
    if (ns_mem_stats != NULL) {
        memcpy((uint8_t *)&app_stats.mem_stats, ns_mem_stats, sizeof(mem_stat_t));
    }

    mbed_stats_cpu_get(&app_stats.cpu_stats);
    mbed_stats_heap_get(&app_stats.heap_stats);

    app_datap = (uint8_t *)nm_dyn_mem_alloc(APP_STAT_MAX_BUF);
    if (app_datap == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return;
    }

    if (nm_statistics_to_cbor(&app_stats, app_datap, APP, &length) == NM_STATUS_FAIL) {
        tr_error("FAILED to CBORise Application Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(app_datap);
        return;
    }
    print_stream(app_datap, length);

    M2MBase *obj = (M2MBase *)client_args;

    if (obj->send_async_response_with_code(app_datap, length, token, token_len, COAP_RESPONSE_CHANGED) != true) {
        tr_err("FAILED to set Application Statistics resource to Cloud Client");
        nm_dyn_mem_free(app_datap);
        return;
    }
    tr_info("App Statistics resource value Setting to Cloud Client");
}

/* If someone re-entering get request before previous get request completes
 * will leads to memory leak
 */
void app_stat_msg_delivery_handle(const M2MBase &base,
                                  const M2MBase::MessageDeliveryStatus status,
                                  const M2MBase::MessageType type,
                                  void *client_args)
{
    tr_debug("app_stat");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (app_datap != NULL) {
            nm_dyn_mem_free(app_datap);
            tr_debug("Application data Memory freed");
        }
    }
}

static uint8_t *nm_stat_buf = NULL;
void handle_nm_stats_coap_request(const M2MBase &base,
                                  M2MBase::Operation operation,
                                  const uint8_t *token,
                                  const uint8_t token_len,
                                  const uint8_t *buffer,
                                  size_t buffer_size,
                                  void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_nm_stats(&nm_stat_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource nm_stats [len = %u] in Cloud Client", len);
        print_stream(nm_stat_buf, len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(nm_stat_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set General Network Statistics resource to Cloud Client");
            nm_dyn_mem_free(nm_stat_buf);
            return;
        }
        tr_info("nm Statistics resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch nm Statistics");
}

void nm_stats_msg_delivery_handle(const M2MBase &base,
                                  const M2MBase::MessageDeliveryStatus status,
                                  const M2MBase::MessageType type,
                                  void *client_args)
{
    tr_debug("nm_stat");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (nm_stat_buf != NULL) {
            nm_dyn_mem_free(nm_stat_buf);
            tr_debug("nm_stat data Memory freed");
        }
    }
}

static uint8_t *ws_stats_buf = NULL;
void handle_ws_stats_coap_request(const M2MBase &base,
                                  M2MBase::Operation operation,
                                  const uint8_t *token,
                                  const uint8_t token_len,
                                  const uint8_t *buffer,
                                  size_t buffer_size,
                                  void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_ws_stats(&ws_stats_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource ws_stats [len = %u] in Cloud Client", len);
        print_stream(ws_stats_buf, len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(ws_stats_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set WS Statistics resource to Cloud Client");
            nm_dyn_mem_free(ws_stats_buf);
            return;
        }
        tr_info("WS Statistics resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch WS Statistics");
}

void ws_stats_msg_delivery_handle(const M2MBase &base,
                                  const M2MBase::MessageDeliveryStatus status,
                                  const M2MBase::MessageType type,
                                  void *client_args)
{
    tr_debug("ws_stat");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (ws_stats_buf != NULL) {
            nm_dyn_mem_free(ws_stats_buf);
            tr_debug("ws_stats data Memory freed");
        }
    }
}

static uint8_t *ch_noise_buf = NULL;
void handle_ch_noise_coap_request(const M2MBase &base,
                                  M2MBase::Operation operation,
                                  const uint8_t *token,
                                  const uint8_t token_len,
                                  const uint8_t *buffer,
                                  size_t buffer_size,
                                  void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_ch_noise_stats(&ch_noise_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource ch_noise [len = %u] in Cloud Client", len);
        print_stream(ch_noise_buf, len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(ch_noise_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set ch_noise information to Cloud Client");
            nm_dyn_mem_free(ch_noise_buf);
            return;
        }
        tr_info("ch_noise resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch channel noise information");
}

void ch_noise_msg_delivery_handle(const M2MBase &base,
                                  const M2MBase::MessageDeliveryStatus status,
                                  const M2MBase::MessageType type,
                                  void *client_args)
{
    tr_debug("ch_noise");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (ch_noise_buf != NULL) {
            nm_dyn_mem_free(ch_noise_buf);
            tr_debug("ch_noise data Memory freed");
        }
    }
}

static uint8_t *br_stats_buf = NULL;
void handle_br_stats_coap_request(const M2MBase &base,
                                  M2MBase::Operation operation,
                                  const uint8_t *token,
                                  const uint8_t token_len,
                                  const uint8_t *buffer,
                                  size_t buffer_size,
                                  void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_br_stats(&br_stats_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource br_stats [len = %u] in Cloud Client", len);
        print_stream(br_stats_buf, len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(br_stats_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set Border router Statistics resource to Cloud Client");
            nm_dyn_mem_free(br_stats_buf);
            return;
        }
        tr_info("br Statistics resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch br Statistics");
}

void br_stats_msg_delivery_handle(const M2MBase &base,
                                  const M2MBase::MessageDeliveryStatus status,
                                  const M2MBase::MessageType type,
                                  void *client_args)
{
    tr_debug("br_stat");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (br_stats_buf != NULL) {
            nm_dyn_mem_free(br_stats_buf);
            tr_debug("br_stats data Memory freed");
        }
    }
}

uint8_t *routing_table_buf = NULL;
void handle_routing_table_coap_request(const M2MBase &base,
                                       M2MBase::Operation operation,
                                       const uint8_t *token,
                                       const uint8_t token_len,
                                       const uint8_t *buffer,
                                       size_t buffer_size,
                                       void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_routing_table(&routing_table_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource routing_table [len = %u] in Cloud Client", len);
        print_stream(routing_table_buf, len > 32 ? 32 : len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(routing_table_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set Routing Table resource to Cloud Client");
            nm_dyn_mem_free(routing_table_buf);
            return;
        }
        tr_info("Routing Table resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch Routing Table");
}

void routing_table_msg_delivery_handle(const M2MBase &base,
                                       const M2MBase::MessageDeliveryStatus status,
                                       const M2MBase::MessageType type,
                                       void *client_args)
{
    tr_debug("routing_table");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (routing_table_buf != NULL) {
            nm_dyn_mem_free(routing_table_buf);
            tr_debug("routing_table data Memory freed");
        }
    }
}

uint8_t *node_stats_buf = NULL;
void handle_node_stats_coap_request(const M2MBase &base,
                                    M2MBase::Operation operation,
                                    const uint8_t *token,
                                    const uint8_t token_len,
                                    const uint8_t *buffer,
                                    size_t buffer_size,
                                    void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_node_stats(&node_stats_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource node_stats [len = %u] in Cloud Client", len);
        print_stream(node_stats_buf, len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(node_stats_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set node information to Cloud Client");
            nm_dyn_mem_free(node_stats_buf);
            return;
        }
        tr_info("node_stats resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch node information");
}

void node_stats_msg_delivery_handle(const M2MBase &base,
                                    const M2MBase::MessageDeliveryStatus status,
                                    const M2MBase::MessageType type,
                                    void *client_args)
{
    tr_debug("node_stat");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (node_stats_buf != NULL) {
            nm_dyn_mem_free(node_stats_buf);
            tr_debug("node_stats data Memory freed");
        }
    }
}

uint8_t *radio_stats_buf = NULL;
void handle_radio_stats_coap_request(const M2MBase &base,
                                     M2MBase::Operation operation,
                                     const uint8_t *token,
                                     const uint8_t token_len,
                                     const uint8_t *buffer,
                                     size_t buffer_size,
                                     void *client_args)
{
    size_t len = 0;

    tr_info("handle_coap_request for %s, operation 0x%x", base.uri_path(), operation);
    if (nm_res_get_radio_stats(&radio_stats_buf, &len) == NM_STATUS_SUCCESS) {
        tr_debug("Setting value of resource radio_stats [len = %u] in Cloud Client", len);
        print_stream(radio_stats_buf, len);
        M2MBase *obj = (M2MBase *)client_args;
        if (obj->send_async_response_with_code(radio_stats_buf, len, token, token_len, COAP_RESPONSE_CHANGED) != true) {
            tr_err("FAILED to set radio quality information to Cloud Client");
            nm_dyn_mem_free(radio_stats_buf);
            return;
        }
        tr_info("radio_stats resource value Setting to Cloud Client");
        return;
    }
    tr_warn("FAILED to fetch radio quality information");
}

void radio_stats_msg_delivery_handle(const M2MBase &base,
                                     const M2MBase::MessageDeliveryStatus status,
                                     const M2MBase::MessageType type,
                                     void *client_args)
{
    tr_debug("radio_stat");
    tr_debug("Received MessageDeliveryStatus: %d, MessageType: %d", status, type);
    if (status == M2MBase::MESSAGE_STATUS_DELIVERED || status == M2MBase::MESSAGE_STATUS_SEND_FAILED) {
        if (radio_stats_buf != NULL) {
            nm_dyn_mem_free(radio_stats_buf);
            tr_debug("radio_stats data Memory freed");
        }
    }
}

nm_status_t nm_res_manager_create(void *obj_list)
{
    M2MObjectList *m2m_obj_list = (M2MObjectList *)obj_list;
    tr_info("Create resources");

    if (m2m_obj_list == NULL) {
        tr_error("FAILED to create resource: M2M Object List NULL\n");
        return NM_STATUS_FAIL;
    }

    // SET resource 33455/0/1 /* Resource ID used is temporary and to be changes later */
    ws_config = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 1, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
    if (ws_config->set_value_updated_function(ws_config_cb) != true) {
        tr_error("ws_config->set_value_updated_function() failed");
        return NM_STATUS_FAIL;
    }

    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        // SET resource 33455/0/2 /* Resource ID used is temporary and to be changes later */
        br_config = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 2, M2MResourceInstance::OPAQUE, M2MBase::GET_PUT_ALLOWED);
        if (br_config->set_value_updated_function(br_config_cb) != true) {
            tr_error("br_config->set_value_updated_function() failed");
            return NM_STATUS_FAIL;
        }
    }

    // GET resource 33455/0/3 /* Resource ID used is temporary and to be changes later */
    app_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 3, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    app_stats->set_auto_observable(true);
    app_stats->set_message_delivery_status_cb(app_stat_msg_delivery_handle, app_stats);
    app_stats->set_async_coap_request_cb(handle_app_stat_coap_request, app_stats);

    // GET resource 33455/0/4 /* Resource ID used is temporary and to be changes later */
    nm_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 4, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    nm_stats->set_auto_observable(true);
    nm_stats->set_message_delivery_status_cb(nm_stats_msg_delivery_handle, nm_stats);
    nm_stats->set_async_coap_request_cb(handle_nm_stats_coap_request, nm_stats);

    // GET resource 33455/0/5 /* Resource ID used is temporary and to be changes later */
    ws_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 5, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    ws_stats->set_auto_observable(true);
    ws_stats->set_message_delivery_status_cb(ws_stats_msg_delivery_handle, ws_stats);
    ws_stats->set_async_coap_request_cb(handle_ws_stats_coap_request, ws_stats);

    // GET resource 33455/0/10 /* Resource ID used is temporary and to be changes later */
    ch_noise = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 10, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
    ch_noise->set_auto_observable(true);
    ch_noise->set_message_delivery_status_cb(ch_noise_msg_delivery_handle, ch_noise);
    ch_noise->set_async_coap_request_cb(handle_ch_noise_coap_request, ch_noise);

    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER) {
        // GET resource 33455/0/6 /* Resource ID used is temporary and to be changes later */
        br_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 6, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        br_stats->set_auto_observable(true);
        br_stats->set_message_delivery_status_cb(br_stats_msg_delivery_handle, br_stats);
        br_stats->set_async_coap_request_cb(handle_br_stats_coap_request, br_stats);

        // GET resource 33455/0/9 /* Resource ID used is temporary and to be changes later */
        routing_table = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 9, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        routing_table->set_auto_observable(true);
        routing_table->set_message_delivery_status_cb(routing_table_msg_delivery_handle, routing_table);
        routing_table->set_async_coap_request_cb(handle_routing_table_coap_request, routing_table);
    }
    if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_ROUTER) {
        // GET resource 33455/0/7 /* Resource ID used is temporary and to be changes later */
        node_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 7, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        node_stats->set_auto_observable(true);
        node_stats->set_message_delivery_status_cb(node_stats_msg_delivery_handle, node_stats);
        node_stats->set_async_coap_request_cb(handle_node_stats_coap_request, node_stats);

        // GET resource 33455/0/8 /* Resource ID used is temporary and to be changes later */
        radio_stats = M2MInterfaceFactory::create_resource(*m2m_obj_list, 33455, 0, 8, M2MResourceInstance::OPAQUE, M2MBase::GET_ALLOWED);
        radio_stats->set_auto_observable(true);
        radio_stats->set_message_delivery_status_cb(radio_stats_msg_delivery_handle, radio_stats);
        radio_stats->set_async_coap_request_cb(handle_radio_stats_coap_request, radio_stats);
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
                nm_dyn_mem_free(buf);
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
                nm_dyn_mem_free(buf);
                return NM_STATUS_FAIL;
            }
            tr_info("BR Configuration resource value Set to Cloud Client");
            nm_dyn_mem_free(buf);
            return NM_STATUS_SUCCESS;
        }
        tr_warn("FAILED to retrieve BR Configuration from KVStore");
        return NM_STATUS_FAIL;
    }
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

void nm_res_manager_ws_config_refresh(void)
{
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, ws_config);
}

void nm_res_manager_br_config_refresh(void)
{
    nm_post_event(NM_EVENT_RESOURCE_GET, 0, br_config);
}

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
