/*
 * Copyright (c) 2020 Pelion. All rights reserved.
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

#include <stdint.h>
#include <stdlib.h>
#include "tinycbor.h"
#include "NetworkManager_internal.h"
#include "nm_cbor_helper.h"
#include "mbed-trace/mbed_trace.h"             // Required for mbed_trace_*

#define TRACE_GROUP "cbor"

/* CBOR Tags for all the configuration and statistics field */
//Wi-SUN Configuration
#define CBOR_TAG_WS_VER                             "ws_ver"
#define CBOR_TAG_NW_NAME                            "nw_name"
#define CBOR_TAG_REG_DOMAIN                         "reg_domain"
#define CBOR_TAG_OP_CLASS                           "op_class"
#define CBOR_TAG_OP_MODE                            "op_mode"
#define CBOR_TAG_PHY_MODE_ID                        "phy_mode_id"
#define CBOR_TAG_CHANNEL_PLAN_ID                    "ch_plan_id"
#define CBOR_TAG_UC_FUNC                            "uc_func"
#define CBOR_TAG_UC_FIX                             "uc_fix"
#define CBOR_TAG_UC_DWELL                           "uc_dwell"
#define CBOR_TAG_BC_FUNC                            "bc_func"
#define CBOR_TAG_BC_FIX                             "bc_fix"
#define CBOR_TAG_BC_DWELL                           "bc_dwell"
#define CBOR_TAG_BC_INTERVAL                        "bc_interval"
#define CBOR_TAG_TRICKLE_IMIN                       "trickle_imin"
#define CBOR_TAG_TRICKLE_IMAX                       "trickle_imax"
#define CBOR_TAG_TRICKLE_CONST                      "trickle_const"
#define CBOR_TAG_PAN_TIMEOUT                        "pan_timeout"
#define CBOR_TAG_NW_SIZE                            "nw_size"
#define CBOR_TAG_CH_MASK                            "ch_mask"
#define CBOR_TAG_WS_DELAY                           "ws_delay"
#define CBOR_TAG_DEV_MIN_SENS                       "device_min_sens"
//BR Configuration
#define CBOR_TAG_WS_BR_VER                          "br_ver"
#define CBOR_TAG_PAN_ID                             "pan_id"
#define CBOR_TAG_DIO_INTERVAL_MIN                   "dio_interval_min"
#define CBOR_TAG_DIO_INTERVAL_DOUBLING              "dio_interval_doublings"
#define CBOR_TAG_DIO_REDUNDANCY_CONST               "dio_redundancy_constant"
#define CBOR_TAG_BR_DELAY                           "br_delay"
#define CBOR_TAG_RADIUS_SERVER_SECRET               "Radius_server_secret"
#define CBOR_TAG_RADIUS_SERVER_ADDR                 "Radius_server_addr"
//Wi-SUN Statistics
#define CBOR_TAG_WS_INFO_VER                        "ws_info_ver"
#define CBOR_TAG_WS_GLOBLE_ADDR                     "global_addr"
#define CBOR_TAG_WS_LINK_LOCAL_ADDR                 "ll_addr"
#define CBOR_TAG_WS_RPL_DODAG_ID                    "rpl_dodag_id"
#define CBOR_TAG_WS_RPL_INSTANCE_ID                 "instance_id"
#define CBOR_TAG_WS_RPL_VER                         "rpl_ver"
#define CBOR_TAG_RPL_TOTAL_MEM                      "rpl_total_memory"
#define CBOR_TAG_ASYNC_TX_CNT                       "async_tx_cnt"
#define CBOR_TAG_ASYNC_RX_CNT                       "async_rx_cnt"
#define CBOR_TAG_JOIN_STATE_1                       "join_state_1"
#define CBOR_TAG_JOIN_STATE_2                       "join_state_2"
#define CBOR_TAG_JOIN_STATE_3                       "join_state_3"
#define CBOR_TAG_JOIN_STATE_4                       "join_state_4"
#define CBOR_TAG_JOIN_STATE_5                       "join_state_5"
#define CBOR_TAG_SEND_PAS                           "sent_PAS"
#define CBOR_TAG_SEND_PA                            "sent_PA"
#define CBOR_TAG_SEND_PCS                           "sent_PCS"
#define CBOR_TAG_SEND_PC                            "sent_PC"
#define CBOR_TAG_RECV_PAS                           "recv_PAS"
#define CBOR_TAG_RECV_PA                            "recv_PA"
#define CBOR_TAG_RECV_PCS                           "recv_PCS"
#define CBOR_TAG_RECV_PC                            "recv_PC"
#define CBOR_TAG_NEIGHBOUR_ADD                      "neighbour_add"
#define CBOR_TAG_NEIGHBOUR_REMOVE                   "neighbour_remove"
#define CBOR_TAG_CHILD_ADD                          "child_add"
#define CBOR_TAG_CHILD_REMOVE                       "child_remove"
//General Network Statistics
#define CBOR_TAG_MAC_RX_CNT                         "mac_rx_cnt"
#define CBOR_TAG_MAC_TX_CNT                         "mac_tx_cnt"
#define CBOR_TAG_MAC_BC_RX_CNT                      "mac_bc_rx_cnt"
#define CBOR_TAG_MAC_BC_TX_CNT                      "mac_bc_tx_cnt"
#define CBOR_TAG_MAC_TX_BYTES                       "mac_tx_bytes"
#define CBOR_TAG_MAC_RX_BYTES                       "mac_rx_bytes"
#define CBOR_TAG_MAC_TX_FAIL_CNT                    "mac_tx_fail_cnt"
#define CBOR_TAG_MAC_RETRY_CNT                      "mac_retry_cnt"
#define CBOR_TAG_MAC_CCA_ATTEMPT_CNT                "mac_cca_attempt_cnt"
#define CBOR_TAG_MAC_FAILED_CCA_CNT                 "mac_failed_cca_cnt"
//Application Statistics
#define CBOR_TAG_NS_HEAP_SIZE                       "ns_heap_size"
#define CBOR_TAG_NS_HEAP_ALLOC_CNT                  "ns_heap_alloc_cnt"
#define CBOR_TAG_NS_HEAP_ALLOCATED_BYTES            "ns_heap_allocated_bytes"
#define CBOR_TAG_NS_HEAP_ALLOCATED_BYTES_MAX        "ns_heap_allocated_bytes_max"
#define CBOR_TAG_NS_HEAP_ALLOC_TOTAL_BYTES          "ns_heap_alloc_total_bytes"
#define CBOR_TAG_NS_HEAP_ALLOC_FAIL_CNT             "ns_heap_alloc_fail_cnt"
#define CBOR_TAG_UPTIME                             "up_time"
#define CBOR_TAG_IDLE_TIME                          "idle_time"
#define CBOR_TAG_SLEEP_TIME                         "sleep_time"
#define CBOR_TAG_DEEP_SLEEP_TIME                    "deep_sleep_time"
#define CBOR_TAG_MBED_HEAP_CURR_SIZE                "mbed_heap_curr_size"
#define CBOR_TAG_MBED_HEAP_MAX_SIZE                 "mbed_heap_max_size"
#define CBOR_TAG_MBED_HEAP_TOTAL_SIZE               "mbed_heap_total_size"
#define CBOR_TAG_MBED_HEAP_RESERVED_SIZE            "mbed_heap_reserved_size"
#define CBOR_TAG_MBED_HEAP_ALLOC_CNT                "mbed_heap_alloc_cnt"
#define CBOR_TAG_MBED_HEAP_ALLOC_FAIL_CNT           "mbed_heap_alloc_fail_cnt"
//Routing Table
#define CBOR_TAG_ROUTING_TABLE                      "routing_table"
//BR statistics
#define CBOR_TAG_BR_INFO_VER                        "br_info_ver"
#define CBOR_TAG_HOST_TIME                          "host_time"
#define CBOR_TAG_DEVICE_COUNT                       "dev_cnt"
#define CBOR_TAG_GLOBAL_ADDR_NORTHBOUND             "global_addr_northbound"
#define CBOR_TAG_LOCAL_ADDR_NORTHBOUND              "local_addr_northbound"
//Node Information
#define CBOR_TAG_NODE_INFO_VER                      "node_info_ver"
#define CBOR_TAG_CURRENT_RANK                       "curent_rank"
#define CBOR_TAG_PRIMARY_PARENT_RANK                "primary_parent_rank"
#define CBOR_TAG_PARENT_ADDR                        "primary_parent_addr"
#define CBOR_TAG_ETX1ST_PARENT                      "etx_1st_parent"
#define CBOR_TAG_ETX2ND_PARENT                      "etx_2nd_parent"
#define CBOR_TAG_RSSI_IN                            "rssi_in"
#define CBOR_TAG_RSSI_OUT                           "rssi_out"
// Channel Noise
#define CBOR_TAG_CCA_TH_TABLE                       "cca_threshold_table"
//Neighbors Information
#define CBOR_TAG_NBR_COUNT                          "nbr_cnt"
#define CBOR_TAG_NBR_INFO                           "nbr_info"
#define CBOR_TAG_NBR_LINK_LOCAL_ADDR                "ll_addr"
#define CBOR_TAG_NBR_GLOGBAL_ADDR                   "gbl_addr"
#define CBOR_TAG_NBR_RSL_OUT                        "rsl_out"
#define CBOR_TAG_NBR_RSL_IN                         "rsl_in"
#define CBOR_TAG_NBR_RPL_RANK                       "rpl_rank"
#define CBOR_TAG_NBR_ETX                            "etx"
#define CBOR_TAG_NBR_LIFETIME                       "lifetime"
#define CBOR_TAG_NBR_TYPE                           "type"


static bool get_string_value_from_stream(CborValue *main_value, const char *str_name, CborValue *map_value, char **temp_buffer)
{
    CborValue element;
    size_t temp_buffer_size = 0;

    if (cbor_value_map_find_value(main_value, str_name, map_value) != CborNoError) {
        tr_debug("Finding string in map fail");
        return false;
    }
    if (cbor_value_is_text_string(map_value) != true) {
        tr_debug("Value is not string");
        return false;
    }
    if (cbor_value_calculate_string_length(map_value, &temp_buffer_size) != CborNoError) {
        tr_debug("String length fail");
        return false;
    }
    tr_debug("Length of string is %d", temp_buffer_size);
    if (cbor_value_dup_text_string(map_value, temp_buffer, &temp_buffer_size, &element) != CborNoError && temp_buffer == NULL) {
        tr_debug("Get string fail");
        return false;
    }
    return true;
}

static bool get_uint32_value_from_stream(CborValue *main_value, const char *str_name, CborValue *map_value, uint32_t *uint_value)
{
    uint64_t read_val = 0;
    if (cbor_value_map_find_value(main_value, str_name, map_value) != CborNoError) {
        tr_debug("Find unsigned integer in map fail");
        return false;
    }
    if (cbor_value_is_unsigned_integer(map_value) != true) {
        tr_debug("Value is not integer ");
        return false;
    }
    if (cbor_value_get_uint64(map_value, &read_val) != CborNoError) {
        tr_debug("Get unsigned integer fail");
        return false;
    }
    *uint_value = (uint32_t)read_val;
    return true;
}

static bool get_int_array_from_stream(CborValue *main_value, const char *str_name, CborValue *map_value, uint32_t *int_array, size_t *array_len)
{
    CborValue array_value;
    size_t array_index = 0;
    uint64_t int_value = 0;

    if (int_array == NULL) {
        tr_err("array pointer NULL");
        return false;
    }

    if (cbor_value_map_find_value(main_value, str_name, map_value) != CborNoError) {
        tr_debug("Find integer array in map fail");
        return false;
    }

    if (cbor_value_get_type(map_value) != CborArrayType) {
        tr_debug("Value is not integer array");
        return false;
    }

    if (cbor_value_enter_container(map_value, &array_value) !=  CborNoError) {
        tr_debug("Couldn't enter to the Array map");
        return false;
    }

    while (!cbor_value_at_end(&array_value)) {
        if (cbor_value_get_uint64(&array_value, &int_value) != CborNoError) {
            tr_debug("Get integer fail");
            return false;
        }
        int_array[array_index++] = (uint32_t)int_value;
        cbor_value_advance_fixed(&array_value);
    }
    *array_len = array_index;
    return true;
}

static bool get_byte_value_from_stream(CborValue *main_value, const char *str_name, CborValue *map_value, uint8_t **temp_buffer, size_t *temp_buffer_size)
{
    CborValue element;

    if (cbor_value_map_find_value(main_value, str_name, map_value) != CborNoError) {
        tr_debug("Finding byte string in map fail");
        return false;
    }
    if (cbor_value_is_byte_string(map_value) != true) {
        tr_debug("Value is not byte string");
        return false;
    }
    if (cbor_value_calculate_string_length(map_value, temp_buffer_size) != CborNoError) {
        tr_debug("Byte string length fail");
        return false;
    }
    if (cbor_value_dup_byte_string(map_value, temp_buffer, temp_buffer_size, &element) != CborNoError) {
        tr_debug("Get byte string fail");
        return false;
    }

    return true;
}

static nm_status_t update_app_config(void *st_app, uint8_t *cbor_data, size_t len)
{
    /* this is a place holder for application configuration to update ,as this configuration yet to decide */
    return NM_STATUS_SUCCESS;
}

static nm_status_t update_bb_config(void *st_app, uint8_t *cbor_data, size_t len)
{
    /* this is a place holder for backhaul configuration to update ,as this configuration yet to decide */
    return NM_STATUS_SUCCESS;
}

static nm_status_t update_ws_config(void *st_app, uint8_t *cbor_data, size_t len)
{
    /* Following structure is as per current parameters defined in code that may be going to modify, add or remove. */
    CborParser parser;
    CborValue main_value;
    CborValue map_value;

    size_t array_length = 0;
    uint32_t int_value = 0;
    char *temp_buffer = NULL;
    nm_ws_config_t *ws_cfg = (nm_ws_config_t *)st_app;

    if (cbor_parser_init(cbor_data, len, 0, &parser, &main_value) != CborNoError) {
        tr_debug("CborParser init fail");
        return NM_STATUS_FAIL;
    }
    if (cbor_value_is_map(&main_value) != true) {
        tr_debug("Cbor main_value map fail");
        return NM_STATUS_FAIL;
    }

    // Finding network_name
    if (get_string_value_from_stream(&main_value, CBOR_TAG_NW_NAME, &map_value, &temp_buffer) == true) {
        strcpy(ws_cfg->network_name, temp_buffer);
    }
    if (temp_buffer != NULL) {
        free(temp_buffer);
        temp_buffer = NULL;
    }

    // Finding channel_mask
    if (get_int_array_from_stream(&main_value, CBOR_TAG_CH_MASK, &map_value, ws_cfg->channel_mask, &array_length) == true) {
        tr_debug("Received Channel Mask Array length: %d", array_length);
    }

    // Finding Regulatory_domain
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_REG_DOMAIN, &map_value, &int_value) == true) {
        ws_cfg->regulatory_domain = (uint8_t)int_value;
    }

    // Finding operating_class
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_OP_CLASS, &map_value, &int_value) == true) {
        ws_cfg->phy_config.op_class_mode.operating_class = (uint8_t)int_value;
    }

    // Finding operating_mode
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_OP_MODE, &map_value, &int_value) == true) {
        ws_cfg->phy_config.op_class_mode.operating_mode = (uint8_t)int_value;
    }

    // Finding phy_mode_id
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_PHY_MODE_ID, &map_value, &int_value) == true) {
        ws_cfg->phy_config.net_dom.phy_mode_id = (uint8_t)int_value;
    }

    // Finding channel_plan_id
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_CHANNEL_PLAN_ID, &map_value, &int_value) == true) {
        ws_cfg->phy_config.net_dom.channel_plan_id = (uint8_t)int_value;
    }

    // Finding network_size
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_NW_SIZE, &map_value, &int_value) == true) {
        ws_cfg->network_size = (uint8_t)int_value;
    }

    // Finding uc_channel_function
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_UC_FUNC, &map_value, &int_value) == true) {
        ws_cfg->uc_ch_config.uc_channel_function = (mesh_channel_function_t)int_value;
    }

    // Finding uc_fixed_channel
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_UC_FIX, &map_value, &int_value) == true) {
        ws_cfg->uc_ch_config.uc_fixed_channel = (uint16_t)int_value;
    }

    // Finding uc_dwell_interval
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_UC_DWELL, &map_value, &int_value) == true) {
        ws_cfg->uc_ch_config.uc_dwell_interval = (uint8_t)int_value;
    }

    // Finding bc_channel_function
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_BC_FUNC, &map_value, &int_value) == true) {
        ws_cfg->bc_ch_config.bc_channel_function = (mesh_channel_function_t)int_value;
    }

    // Finding bc_fixed_channel
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_BC_FIX, &map_value, &int_value) == true) {
        ws_cfg->bc_ch_config.bc_fixed_channel = (uint16_t)int_value;
    }

    // Finding bc_dwell_interval
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_BC_DWELL, &map_value, &int_value) == true) {
        ws_cfg->bc_ch_config.bc_dwell_interval = (uint8_t)int_value;
    }

    // Finding broadcast_interval
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_BC_INTERVAL, &map_value, &int_value) == true) {
        ws_cfg->bc_ch_config.bc_interval = int_value;
    }

    // Finding disc_trickle_imin
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_TRICKLE_IMIN, &map_value, &int_value) == true) {
        ws_cfg->timing_param.disc_trickle_imin = (uint16_t)int_value;
    }

    // Finding disc_trickle_imax
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_TRICKLE_IMAX, &map_value, &int_value) == true) {
        ws_cfg->timing_param.disc_trickle_imax = (uint16_t)int_value;
    }

    // Finding disc_trickle_k
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_TRICKLE_CONST, &map_value, &int_value) == true) {
        ws_cfg->timing_param.disc_trickle_k = (uint8_t)int_value;
    }

    // Finding pan_timeout
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_PAN_TIMEOUT, &map_value, &int_value) == true) {
        ws_cfg->timing_param.pan_timeout = (uint16_t)int_value;
    }

    // Finding ws_delay
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_WS_DELAY, &map_value, &int_value) == true) {
        ws_cfg->delay = (uint16_t)int_value;
    }

    // Finding device_min_sens
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_DEV_MIN_SENS, &map_value, &int_value) == true) {
        ws_cfg->device_min_sens = (uint8_t)int_value;
    }

    /* This parameters going to update from binary only */
    ws_cfg->resource_version = WS_RESOURCE_VERSION;
    return NM_STATUS_SUCCESS;
}

static nm_status_t update_br_config(void *st_app, uint8_t *cbor_data, size_t len)
{
    /* Following structure is as per current parameters defined in code that may be going to modify, add or remove. */
    CborParser parser;
    CborValue main_value;
    CborValue map_value;

    char *temp_buffer = NULL;
    uint8_t *secret_buffer = NULL;
    size_t temp_buffer_size = 0;
    uint32_t int_value = 0;

    nm_br_config_t *br_cfg = (nm_br_config_t *)st_app;

    if (cbor_parser_init(cbor_data, len, 0, &parser, &main_value) != CborNoError) {
        tr_debug("CborParser init fail");
        return NM_STATUS_FAIL;
    }
    if (cbor_value_is_map(&main_value) != true) {
        tr_debug("Cbor main_value map fail");
        return NM_STATUS_FAIL;
    }

    // Finding dio_interval_min
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_DIO_INTERVAL_MIN, &map_value, &int_value) == true) {
        br_cfg->rpl_config.dio_interval_min = (uint8_t)int_value;
    }

    // Finding dio_interval_doublings
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_DIO_INTERVAL_DOUBLING, &map_value, &int_value) == true) {
        br_cfg->rpl_config.dio_interval_doublings = (uint8_t)int_value;
    }

    // Finding dio_redundancy_constant
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_DIO_REDUNDANCY_CONST, &map_value, &int_value) == true) {
        br_cfg->rpl_config.dio_redundancy_constant = (uint8_t)int_value;
    }

    // Finding pan_id
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_PAN_ID, &map_value, &int_value) == true) {
        br_cfg->pan_id = (uint16_t)int_value;
    }

    // Finding br_delay
    if (get_uint32_value_from_stream(&main_value, CBOR_TAG_BR_DELAY, &map_value, &int_value) == true) {
        br_cfg->delay = (uint16_t)int_value;
    }

    //Finding Radius Server Secret
    if (get_byte_value_from_stream(&main_value, CBOR_TAG_RADIUS_SERVER_SECRET, &map_value, &secret_buffer, &temp_buffer_size) == true) {
        if (br_cfg->radius_config.secret != NULL && br_cfg->radius_config.secret_len != 0) {
            free(br_cfg->radius_config.secret);
            br_cfg->radius_config.secret_len = 0;
            br_cfg->radius_config.secret = NULL;
        }
        br_cfg->radius_config.secret_len = (uint16_t)temp_buffer_size;
        br_cfg->radius_config.secret = secret_buffer;
    }

    //Finding Radius Server address
    if (get_string_value_from_stream(&main_value, CBOR_TAG_RADIUS_SERVER_ADDR, &map_value, &temp_buffer) == true) {
        if(!strcasecmp(temp_buffer,"NULL")) {
            memset(br_cfg->radius_config.address, '\0', sizeof(br_cfg->radius_config.address));
        } else {
        strcpy(br_cfg->radius_config.address, temp_buffer);
        }
    }

    if (temp_buffer != NULL) {
        free(temp_buffer);
        temp_buffer = NULL;
    }

    /* This parameters going to update from binary only */
    br_cfg->resource_version = WS_BR_RESOURCE_VERSION;
    return NM_STATUS_SUCCESS;
}

/* CBOR to structure */
nm_status_t nm_cbor_config_struct_update(void *st_cfg, uint8_t *cbor_data, config_type_t type, size_t len)
{
    nm_status_t status = NM_STATUS_FAIL;
    switch (type) {
        case APP:
            status = update_app_config(st_cfg, cbor_data, len);
            if (status) {
                tr_info("Application structure update fail");
            }
            break;
        case BB:
            status = update_bb_config(st_cfg, cbor_data, len);
            if (status) {
                tr_info("Backhaul structure update fail");
            }
            break;
        case WS:
            status = update_ws_config(st_cfg, cbor_data, len);
            if (status) {
                tr_info("Wi-Sun structure update fail");
            }
            break;
        case BR:
            status = update_br_config(st_cfg, cbor_data, len);
            if (status) {
                tr_info("BR structure update fail");
            }
            break;
        default:
            tr_info("Unknown Configuration type received");
            break;
    }
    return status;
}

static bool encode_text_string(CborEncoder *map, const char *str_name, size_t len)
{
    if (cbor_encode_text_string(map, str_name, len)) {
        tr_warn("Could not add string in map");
        return false;
    }
    return true;
}

static bool encode_uint64_value(CborEncoder *map, uint64_t uint_value)
{
    if (cbor_encode_uint(map, uint_value)) {
        tr_debug("Failed adding unsigned integer value in map");
        return false;
    }
    return true;
}

static bool encode_uint32_value(CborEncoder *map, uint32_t uint_value)
{
    if (cbor_encode_uint(map, uint_value)) {
        tr_debug("Failed adding unsigned integer value in map");
        return false;
    }
    return true;
}

static bool encode_int_array(CborEncoder *map, uint32_t *int_ptr, size_t array_len)
{
    size_t array_index;
    CborError cbor_error = CborNoError;
    CborEncoder int_array;
    cbor_error = cbor_encoder_create_array(map, &int_array, array_len);
    if (cbor_error) {
        tr_warn("Could not creat Array map for Integer: error %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    for (array_index = 0; array_index < array_len; array_index++) {
        if (cbor_encode_uint(&int_array, int_ptr[array_index])) {
            tr_warn("Could not add array of integer value in map\n");
            return false;
        }
    }

    cbor_error = cbor_encoder_close_container(map, &int_array);
    if (cbor_error) {
        tr_warn("Could not close Integer Array: error %d", cbor_error);
        return false;
    }
    return true;
}

static bool encode_int8_array(CborEncoder *map, int8_t *int_ptr, size_t array_len)
{
    size_t array_index;
    CborError cbor_error = CborNoError;
    CborEncoder int_array;
    cbor_error = cbor_encoder_create_array(map, &int_array, array_len);
    if (cbor_error) {
        tr_warn("Could not create Array map for Integer: error %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    for (array_index = 0; array_index < array_len; array_index++) {
        if (cbor_encode_int(&int_array, int_ptr[array_index])) {
            tr_warn("Could not add array of int8 value in map\n");
            return false;
        }
    }

    cbor_error = cbor_encoder_close_container(map, &int_array);
    if (cbor_error) {
        tr_warn("Could not close Integer Array: error %d", cbor_error);
        return false;
    }
    return true;
}

static bool encode_byte_array(CborEncoder *map, uint8_t *s_value, size_t array_len)
{
    if (cbor_encode_byte_string(map, s_value, array_len)) {
        tr_debug("Failed adding Byte array into map");
        return false;
    }
    return true;
}

static nm_status_t app_config_to_cbor(void *st_app, uint8_t *cbor_data, size_t *len)
{
    /* this is a place holder for application configuration to update ,as this configuration yet to decide */
    return NM_STATUS_SUCCESS;
}

static nm_status_t bb_config_to_cbor(void *st_app, uint8_t *cbor_data, size_t *len)
{
    /* this is a place holder for backhaul configuration to update ,as this configuration yet to decide */
    return NM_STATUS_SUCCESS;
}

static nm_status_t ws_config_to_cbor(void *ws_cfg, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    nm_ws_config_t *st_cfg = (nm_ws_config_t *)ws_cfg;

    cbor_encoder_init(&encoder, cbor_data, WS_CONF_MAX_ENCODER_BUF/*sizeof(cbor_data)*/, 0);

    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // Resource version no
    if (encode_text_string(&map, CBOR_TAG_WS_VER, sizeof(CBOR_TAG_WS_VER) - 1)) {
        encode_uint32_value(&map, WS_RESOURCE_VERSION);
    }

    // network_name
    if (encode_text_string(&map, CBOR_TAG_NW_NAME, sizeof(CBOR_TAG_NW_NAME) - 1)) {
        encode_text_string(&map, st_cfg->network_name, strlen(st_cfg->network_name));
    }

    // channel_mask
    if (encode_text_string(&map, CBOR_TAG_CH_MASK, sizeof(CBOR_TAG_CH_MASK) - 1)) {
        encode_int_array(&map, st_cfg->channel_mask, 8);
    }

    // regulatory_domain
    if (encode_text_string(&map, CBOR_TAG_REG_DOMAIN, sizeof(CBOR_TAG_REG_DOMAIN) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->regulatory_domain);
    }

    // operating_class
    if (encode_text_string(&map, CBOR_TAG_OP_CLASS, sizeof(CBOR_TAG_OP_CLASS) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->phy_config.op_class_mode.operating_class);
    }

    // operating_mode
    if (encode_text_string(&map, CBOR_TAG_OP_MODE, sizeof(CBOR_TAG_OP_MODE) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->phy_config.op_class_mode.operating_mode);
    }

    // phy_mode_id
    if (encode_text_string(&map, CBOR_TAG_PHY_MODE_ID, sizeof(CBOR_TAG_PHY_MODE_ID) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->phy_config.net_dom.phy_mode_id);
    }

    // channel_plan_id
    if (encode_text_string(&map, CBOR_TAG_CHANNEL_PLAN_ID, sizeof(CBOR_TAG_CHANNEL_PLAN_ID) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->phy_config.net_dom.channel_plan_id);
    }

    // network_size
    if (encode_text_string(&map, CBOR_TAG_NW_SIZE, sizeof(CBOR_TAG_NW_SIZE) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->network_size);
    }

    // uc_channel_function
    if (encode_text_string(&map, CBOR_TAG_UC_FUNC, sizeof(CBOR_TAG_UC_FUNC) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->uc_ch_config.uc_channel_function);
    }

    // uc_fixed_channel
    if (encode_text_string(&map, CBOR_TAG_UC_FIX, sizeof(CBOR_TAG_UC_FIX) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->uc_ch_config.uc_fixed_channel);
    }

    // uc_dwell_interval
    if (encode_text_string(&map, CBOR_TAG_UC_DWELL, sizeof(CBOR_TAG_UC_DWELL) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->uc_ch_config.uc_dwell_interval);
    }

    // bc_channel_function
    if (encode_text_string(&map, CBOR_TAG_BC_FUNC, sizeof(CBOR_TAG_BC_FUNC) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->bc_ch_config.bc_channel_function);
    }

    // bc_fixed_channel
    if (encode_text_string(&map, CBOR_TAG_BC_FIX, sizeof(CBOR_TAG_BC_FIX) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->bc_ch_config.bc_fixed_channel);
    }

    // bc_dwell_interval
    if (encode_text_string(&map, CBOR_TAG_BC_DWELL, sizeof(CBOR_TAG_BC_DWELL) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->bc_ch_config.bc_dwell_interval);
    }

    // bc_interval
    if (encode_text_string(&map, CBOR_TAG_BC_INTERVAL, sizeof(CBOR_TAG_BC_INTERVAL) - 1)) {
        encode_uint32_value(&map, st_cfg->bc_ch_config.bc_interval);
    }

    // disc_trickle_imin
    if (encode_text_string(&map, CBOR_TAG_TRICKLE_IMIN, sizeof(CBOR_TAG_TRICKLE_IMIN) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->timing_param.disc_trickle_imin);
    }

    // disc_trickle_imax
    if (encode_text_string(&map, CBOR_TAG_TRICKLE_IMAX, sizeof(CBOR_TAG_TRICKLE_IMAX) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->timing_param.disc_trickle_imax);
    }

    // disc_trickle_k
    if (encode_text_string(&map, CBOR_TAG_TRICKLE_CONST, sizeof(CBOR_TAG_TRICKLE_CONST) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->timing_param.disc_trickle_k);
    }

    // pan_timeout
    if (encode_text_string(&map, CBOR_TAG_PAN_TIMEOUT, sizeof(CBOR_TAG_PAN_TIMEOUT) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->timing_param.pan_timeout);
    }

    // ws_delay
    if (encode_text_string(&map, CBOR_TAG_WS_DELAY, sizeof(CBOR_TAG_WS_DELAY) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->delay);
    }

    // device_min_sens
    if (encode_text_string(&map, CBOR_TAG_DEV_MIN_SENS, sizeof(CBOR_TAG_DEV_MIN_SENS) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->device_min_sens);
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of ws_config_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

static nm_status_t br_config_to_cbor(void *br_cfg, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    nm_br_config_t *st_cfg = (nm_br_config_t *)br_cfg;

    cbor_encoder_init(&encoder, cbor_data, BR_CONF_MAX_ENCODER_BUF, 0);

    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // Resource version no
    if (encode_text_string(&map, CBOR_TAG_WS_BR_VER, sizeof(CBOR_TAG_WS_BR_VER) - 1)) {
        encode_uint32_value(&map, WS_BR_RESOURCE_VERSION);
    }

    // dio_interval_min
    if (encode_text_string(&map, CBOR_TAG_DIO_INTERVAL_MIN, sizeof(CBOR_TAG_DIO_INTERVAL_MIN) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->rpl_config.dio_interval_min);
    }

    // dio_interval_doublings
    if (encode_text_string(&map, CBOR_TAG_DIO_INTERVAL_DOUBLING, sizeof(CBOR_TAG_DIO_INTERVAL_DOUBLING) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->rpl_config.dio_interval_doublings);
    }

    // dio_redundancy_constant
    if (encode_text_string(&map, CBOR_TAG_DIO_REDUNDANCY_CONST, sizeof(CBOR_TAG_DIO_REDUNDANCY_CONST) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->rpl_config.dio_redundancy_constant);
    }

    // pan_id
    if (encode_text_string(&map, CBOR_TAG_PAN_ID, sizeof(CBOR_TAG_PAN_ID) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->pan_id);
    }

    // br_delay
    if (encode_text_string(&map, CBOR_TAG_BR_DELAY, sizeof(CBOR_TAG_BR_DELAY) - 1)) {
        encode_uint32_value(&map, (uint32_t)st_cfg->delay);
    }

    // radius_server_secret
    if (encode_text_string(&map, CBOR_TAG_RADIUS_SERVER_SECRET, sizeof(CBOR_TAG_RADIUS_SERVER_SECRET) - 1)) {
        encode_byte_array(&map, st_cfg->radius_config.secret, st_cfg->radius_config.secret_len);
    }

    // radius_server_addr
    if (encode_text_string(&map, CBOR_TAG_RADIUS_SERVER_ADDR, sizeof(CBOR_TAG_RADIUS_SERVER_ADDR) - 1)) {
        encode_text_string(&map, st_cfg->radius_config.address, strlen(st_cfg->radius_config.address));
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of br_config_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

/* Configuration to CBOR */
nm_status_t nm_config_to_cbor(void *st_cfg, uint8_t *cbor_data, config_type_t type, size_t *len)
{
    nm_status_t status = NM_STATUS_FAIL;
    switch (type) {
        case APP:
            status = app_config_to_cbor(st_cfg, cbor_data, len);
            if (status) {
                tr_info("Application structure cbor encoder fail");
            }
            break;
        case BB:
            status = bb_config_to_cbor(st_cfg, cbor_data, len);
            if (status) {
                tr_info("Backhaul structure cbor encoder fail");
            }
            break;
        case WS:
            status = ws_config_to_cbor(st_cfg, cbor_data, len);
            if (status) {
                tr_info("Wi-Sun structure cbor encoder fail");
            }
            break;
        case BR:
            status = br_config_to_cbor(st_cfg, cbor_data, len);
            if (status) {
                tr_info("BR structure cbor encoder fail");
            }
            break;
        default:
            tr_info("Unknown Configuration type received");
            break;
    }
    return status;
}

/*
 *Statistics to CBOR
 */

static nm_status_t app_stats_to_cbor(void *stats_app, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    nm_app_statistics_t *app_stats = (nm_app_statistics_t *)stats_app;

    cbor_encoder_init(&encoder, cbor_data, APP_STAT_MAX_ENCODER_BUF, 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // heap_sector_size
    if (encode_text_string(&map, CBOR_TAG_NS_HEAP_SIZE, sizeof(CBOR_TAG_NS_HEAP_SIZE) - 1)) {
        encode_uint32_value(&map, app_stats->mem_stats.heap_sector_size);
    }
    // heap_sector_alloc_cnt
    if (encode_text_string(&map, CBOR_TAG_NS_HEAP_ALLOC_CNT, sizeof(CBOR_TAG_NS_HEAP_ALLOC_CNT) - 1)) {
        encode_uint32_value(&map, app_stats->mem_stats.heap_sector_alloc_cnt);
    }
    // heap_sector_allocated_bytes
    if (encode_text_string(&map, CBOR_TAG_NS_HEAP_ALLOCATED_BYTES, sizeof(CBOR_TAG_NS_HEAP_ALLOCATED_BYTES) - 1)) {
        encode_uint32_value(&map, app_stats->mem_stats.heap_sector_allocated_bytes);
    }
    // heap_sector_allocated_bytes_max
    if (encode_text_string(&map, CBOR_TAG_NS_HEAP_ALLOCATED_BYTES_MAX, sizeof(CBOR_TAG_NS_HEAP_ALLOCATED_BYTES_MAX) - 1)) {
        encode_uint32_value(&map, app_stats->mem_stats.heap_sector_allocated_bytes_max);
    }
    // heap_alloc_fail_cnt
    if (encode_text_string(&map, CBOR_TAG_NS_HEAP_ALLOC_FAIL_CNT, sizeof(CBOR_TAG_NS_HEAP_ALLOC_FAIL_CNT) - 1)) {
        encode_uint32_value(&map, app_stats->mem_stats.heap_alloc_fail_cnt);
    }
    // uptime
    if (encode_text_string(&map, CBOR_TAG_UPTIME, sizeof(CBOR_TAG_UPTIME) - 1)) {
        encode_uint64_value(&map, app_stats->cpu_stats.uptime);
    }
    // idle_time
    if (encode_text_string(&map, CBOR_TAG_IDLE_TIME, sizeof(CBOR_TAG_IDLE_TIME) - 1)) {
        encode_uint64_value(&map, app_stats->cpu_stats.idle_time);
    }
    // sleep_time
    if (encode_text_string(&map, CBOR_TAG_SLEEP_TIME, sizeof(CBOR_TAG_SLEEP_TIME) - 1)) {
        encode_uint64_value(&map, app_stats->cpu_stats.sleep_time);
    }
    // deep_sleep_time
    if (encode_text_string(&map, CBOR_TAG_DEEP_SLEEP_TIME, sizeof(CBOR_TAG_DEEP_SLEEP_TIME) - 1)) {
        encode_uint64_value(&map, app_stats->cpu_stats.deep_sleep_time);
    }
    // current_size
    if (encode_text_string(&map, CBOR_TAG_MBED_HEAP_CURR_SIZE, sizeof(CBOR_TAG_MBED_HEAP_CURR_SIZE) - 1)) {
        encode_uint32_value(&map, app_stats->heap_stats.current_size);
    }
    // max_size
    if (encode_text_string(&map, CBOR_TAG_MBED_HEAP_MAX_SIZE, sizeof(CBOR_TAG_MBED_HEAP_MAX_SIZE) - 1)) {
        encode_uint32_value(&map, app_stats->heap_stats.max_size);
    }
    // total_size
    if (encode_text_string(&map, CBOR_TAG_MBED_HEAP_TOTAL_SIZE, sizeof(CBOR_TAG_MBED_HEAP_TOTAL_SIZE) - 1)) {
        encode_uint32_value(&map, app_stats->heap_stats.total_size);
    }
    // reserved_size
    if (encode_text_string(&map, CBOR_TAG_MBED_HEAP_RESERVED_SIZE, sizeof(CBOR_TAG_MBED_HEAP_RESERVED_SIZE) - 1)) {
        encode_uint32_value(&map, app_stats->heap_stats.reserved_size);
    }
    // alloc_cnt
    if (encode_text_string(&map, CBOR_TAG_MBED_HEAP_ALLOC_CNT, sizeof(CBOR_TAG_MBED_HEAP_ALLOC_CNT) - 1)) {
        encode_uint32_value(&map, app_stats->heap_stats.alloc_cnt);
    }
    // alloc_fail_cnt
    if (encode_text_string(&map, CBOR_TAG_MBED_HEAP_ALLOC_FAIL_CNT, sizeof(CBOR_TAG_MBED_HEAP_ALLOC_FAIL_CNT) - 1)) {
        encode_uint32_value(&map, app_stats->heap_stats.alloc_fail_cnt);
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of app_stats_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

static nm_status_t ws_stats_to_cbor(void *stats_ws, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    nm_ws_common_info_t *ws_stats = (nm_ws_common_info_t *)stats_ws;

    cbor_encoder_init(&encoder, cbor_data, WS_STAT_MAX_ENCODER_BUF, 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // Resource version no
    if (encode_text_string(&map, CBOR_TAG_WS_INFO_VER, sizeof(CBOR_TAG_WS_INFO_VER) - 1)) {
        encode_uint32_value(&map, WS_STATS_RESOURCE_VERSION);
    }

    // global_addr
    if (encode_text_string(&map, CBOR_TAG_WS_GLOBLE_ADDR, sizeof(CBOR_TAG_WS_GLOBLE_ADDR) - 1)) {
        encode_byte_array(&map, ws_stats->ws_common_id_statistics.global_addr, sizeof(ws_stats->ws_common_id_statistics.global_addr));
    }

    // link_local_addr
    if (encode_text_string(&map, CBOR_TAG_WS_LINK_LOCAL_ADDR, sizeof(CBOR_TAG_WS_LINK_LOCAL_ADDR) - 1)) {
        encode_byte_array(&map, ws_stats->ws_common_id_statistics.link_local_addr, sizeof(ws_stats->ws_common_id_statistics.link_local_addr));
    }

    // rpl_dodag_id
    if (encode_text_string(&map, CBOR_TAG_WS_RPL_DODAG_ID, sizeof(CBOR_TAG_WS_RPL_DODAG_ID) - 1)) {
        encode_byte_array(&map, ws_stats->ws_common_id_statistics.rpl_dodag_id, sizeof(ws_stats->ws_common_id_statistics.rpl_dodag_id));
    }

    // instance_id
    if (encode_text_string(&map, CBOR_TAG_WS_RPL_INSTANCE_ID, sizeof(CBOR_TAG_WS_RPL_INSTANCE_ID) - 1)) {
        encode_uint32_value(&map, (uint32_t)ws_stats->ws_common_id_statistics.instance_id);
    }

    // rpl_ver
    if (encode_text_string(&map, CBOR_TAG_WS_RPL_VER, sizeof(CBOR_TAG_WS_RPL_VER) - 1)) {
        encode_uint32_value(&map, (uint32_t)ws_stats->ws_common_id_statistics.version);
    }

    // rpl_total_memory
    if (encode_text_string(&map, CBOR_TAG_RPL_TOTAL_MEM, sizeof(CBOR_TAG_RPL_TOTAL_MEM) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.rpl_total_memory);
    }

    // asynch_tx_count
    if (encode_text_string(&map, CBOR_TAG_ASYNC_TX_CNT, sizeof(CBOR_TAG_ASYNC_TX_CNT) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.asynch_tx_count);
    }

    // asynch_rx_count
    if (encode_text_string(&map, CBOR_TAG_ASYNC_RX_CNT, sizeof(CBOR_TAG_ASYNC_RX_CNT) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.asynch_rx_count);
    }

    // join_state_1
    if (encode_text_string(&map, CBOR_TAG_JOIN_STATE_1, sizeof(CBOR_TAG_JOIN_STATE_1) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.join_state_1);
    }

    // join_state_2
    if (encode_text_string(&map, CBOR_TAG_JOIN_STATE_2, sizeof(CBOR_TAG_JOIN_STATE_2) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.join_state_2);
    }

    // join_state_3
    if (encode_text_string(&map, CBOR_TAG_JOIN_STATE_3, sizeof(CBOR_TAG_JOIN_STATE_3) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.join_state_3);
    }

    // join_state_4
    if (encode_text_string(&map, CBOR_TAG_JOIN_STATE_4, sizeof(CBOR_TAG_JOIN_STATE_4) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.join_state_4);
    }

    // join_state_5
    if (encode_text_string(&map, CBOR_TAG_JOIN_STATE_5, sizeof(CBOR_TAG_JOIN_STATE_5) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.join_state_5);
    }

    // sent_PAS
    if (encode_text_string(&map, CBOR_TAG_SEND_PAS, sizeof(CBOR_TAG_SEND_PAS) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.sent_PAS);
    }

    // sent_PA
    if (encode_text_string(&map, CBOR_TAG_SEND_PA, sizeof(CBOR_TAG_SEND_PA) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.sent_PA);
    }

    // sent_PCS
    if (encode_text_string(&map, CBOR_TAG_SEND_PCS, sizeof(CBOR_TAG_SEND_PCS) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.sent_PCS);
    }

    // sent_PC
    if (encode_text_string(&map, CBOR_TAG_SEND_PC, sizeof(CBOR_TAG_SEND_PC) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.sent_PC);
    }

    // recv_PAS
    if (encode_text_string(&map, CBOR_TAG_RECV_PAS, sizeof(CBOR_TAG_RECV_PAS) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.recv_PAS);
    }

    // recv_PA
    if (encode_text_string(&map, CBOR_TAG_RECV_PA, sizeof(CBOR_TAG_RECV_PA) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.recv_PA);
    }

    // recv_PCS
    if (encode_text_string(&map, CBOR_TAG_RECV_PCS, sizeof(CBOR_TAG_RECV_PCS) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.recv_PCS);
    }

    // recv_PC
    if (encode_text_string(&map, CBOR_TAG_RECV_PC, sizeof(CBOR_TAG_RECV_PC) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.recv_PC);
    }

    // neighbour_add
    if (encode_text_string(&map, CBOR_TAG_NEIGHBOUR_ADD, sizeof(CBOR_TAG_NEIGHBOUR_ADD) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.neighbour_add);
    }

    // neighbour_remove
    if (encode_text_string(&map, CBOR_TAG_NEIGHBOUR_REMOVE, sizeof(CBOR_TAG_NEIGHBOUR_REMOVE) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.neighbour_remove);
    }

    // child_add
    if (encode_text_string(&map, CBOR_TAG_CHILD_ADD, sizeof(CBOR_TAG_CHILD_ADD) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.child_add);
    }

    // child_remove
    if (encode_text_string(&map, CBOR_TAG_CHILD_REMOVE, sizeof(CBOR_TAG_CHILD_REMOVE) - 1)) {
        encode_uint32_value(&map, ws_stats->ws_mesh_statistics.child_remove);
    }

    // pan_id
    if (encode_text_string(&map, CBOR_TAG_PAN_ID, sizeof(CBOR_TAG_PAN_ID) - 1)) {
        encode_uint32_value(&map, (uint32_t)ws_stats->ws_common_id_statistics.pan_id);
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of ws_stats_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

static nm_status_t nm_stats_to_cbor(void *stats_nm, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    nm_general_nw_statistics_t *nm_stats = (nm_general_nw_statistics_t *)stats_nm;

    cbor_encoder_init(&encoder, cbor_data, NM_STAT_MAX_ENCODER_BUF, 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // mac_rx_count
    if (encode_text_string(&map, CBOR_TAG_MAC_RX_CNT, sizeof(CBOR_TAG_MAC_RX_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_rx_count);
    }
    // mac_tx_count
    if (encode_text_string(&map, CBOR_TAG_MAC_TX_CNT, sizeof(CBOR_TAG_MAC_TX_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_tx_count);
    }
    // mac_bc_rx_count
    if (encode_text_string(&map, CBOR_TAG_MAC_BC_RX_CNT, sizeof(CBOR_TAG_MAC_BC_RX_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_bc_rx_count);
    }
    // mac_bc_tx_count
    if (encode_text_string(&map, CBOR_TAG_MAC_BC_TX_CNT, sizeof(CBOR_TAG_MAC_BC_TX_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_bc_tx_count);
    }
    // mac_tx_bytes
    if (encode_text_string(&map, CBOR_TAG_MAC_TX_BYTES, sizeof(CBOR_TAG_MAC_TX_BYTES) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_tx_bytes);
    }
    // mac_rx_bytes
    if (encode_text_string(&map, CBOR_TAG_MAC_RX_BYTES, sizeof(CBOR_TAG_MAC_RX_BYTES) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_rx_bytes);
    }
    // mac_tx_failed_count
    if (encode_text_string(&map, CBOR_TAG_MAC_TX_FAIL_CNT, sizeof(CBOR_TAG_MAC_TX_FAIL_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_tx_failed_count);
    }
    // mac_retry_count
    if (encode_text_string(&map, CBOR_TAG_MAC_RETRY_CNT, sizeof(CBOR_TAG_MAC_RETRY_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_retry_count);
    }
    // mac_cca_attempts_count
    if (encode_text_string(&map, CBOR_TAG_MAC_CCA_ATTEMPT_CNT, sizeof(CBOR_TAG_MAC_CCA_ATTEMPT_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_cca_attempts_count);
    }
    // mac_failed_cca_count
    if (encode_text_string(&map, CBOR_TAG_MAC_FAILED_CCA_CNT, sizeof(CBOR_TAG_MAC_FAILED_CCA_CNT) - 1)) {
        encode_uint32_value(&map, nm_stats->mesh_mac_statistics.mac_failed_cca_count);
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of nm_stats_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

static nm_status_t br_stats_to_cbor(void *stats_br, uint8_t *cbor_data, size_t *len)
{

    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    nm_ws_br_info_t *br_stats = (nm_ws_br_info_t *)stats_br;

    cbor_encoder_init(&encoder, cbor_data, BR_STAT_MAX_ENCODER_BUF, 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // Resource version no
    if (encode_text_string(&map, CBOR_TAG_BR_INFO_VER, sizeof(CBOR_TAG_BR_INFO_VER) - 1)) {
        encode_uint32_value(&map, BR_STATS_RESOURCE_VERSION);
    }

    // Host_time
    if (encode_text_string(&map, CBOR_TAG_HOST_TIME, sizeof(CBOR_TAG_HOST_TIME) - 1)) {
        encode_uint64_value(&map, br_stats->host_time);
    }

    // device_count
    if (encode_text_string(&map, CBOR_TAG_DEVICE_COUNT, sizeof(CBOR_TAG_DEVICE_COUNT) - 1)) {
        encode_uint32_value(&map, (uint32_t)br_stats->device_count);
    }

    // global_addr_northbound
    if (encode_text_string(&map, CBOR_TAG_GLOBAL_ADDR_NORTHBOUND, sizeof(CBOR_TAG_GLOBAL_ADDR_NORTHBOUND) - 1)) {
        encode_byte_array(&map, br_stats->global_addr_northbound, sizeof(br_stats->global_addr_northbound));
    }

    // link_local_addr_northbound
    if (encode_text_string(&map, CBOR_TAG_LOCAL_ADDR_NORTHBOUND, sizeof(CBOR_TAG_LOCAL_ADDR_NORTHBOUND) - 1)) {
        encode_byte_array(&map, br_stats->local_addr_northbound, sizeof(br_stats->local_addr_northbound));
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of br_stats_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

static nm_status_t node_stats_to_cbor(void *stats_ni, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;
    nm_node_info_t *node_stats = (nm_node_info_t *)stats_ni;

    cbor_encoder_init(&encoder, cbor_data, NI_STAT_MAX_ENCODER_BUF, 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // Resource version no
    if (encode_text_string(&map, CBOR_TAG_NODE_INFO_VER, sizeof(CBOR_TAG_NODE_INFO_VER) - 1)) {
        encode_uint32_value(&map, NODE_INFORMATION_VERSION);
    }

    // curent_rank
    if (encode_text_string(&map, CBOR_TAG_CURRENT_RANK, sizeof(CBOR_TAG_CURRENT_RANK) - 1)) {
        encode_uint32_value(&map, (uint32_t)node_stats->routing_info.curent_rank);
    }

    // primary_parent_rank
    if (encode_text_string(&map, CBOR_TAG_PRIMARY_PARENT_RANK, sizeof(CBOR_TAG_PRIMARY_PARENT_RANK) - 1)) {
        encode_uint32_value(&map, (uint32_t)node_stats->routing_info.primary_parent_rank);
    }

    // primary_parent address
    if (encode_text_string(&map, CBOR_TAG_PARENT_ADDR, sizeof(CBOR_TAG_PARENT_ADDR) - 1)) {
        encode_byte_array(&map, node_stats->routing_info.primary_parent, sizeof(node_stats->routing_info.primary_parent));
    }

    // etx_1st_parent
    if (encode_text_string(&map, CBOR_TAG_ETX1ST_PARENT, sizeof(CBOR_TAG_ETX1ST_PARENT) - 1)) {
        encode_uint32_value(&map, (uint32_t)node_stats->routing_info.etx_1st_parent);
    }

    // etx_2nd_parent
    if (encode_text_string(&map, CBOR_TAG_ETX2ND_PARENT, sizeof(CBOR_TAG_ETX2ND_PARENT) - 1)) {
        encode_uint32_value(&map, (uint32_t)node_stats->routing_info.etx_2nd_parent);
    }

    // rssi_in
    if (encode_text_string(&map, CBOR_TAG_RSSI_IN, sizeof(CBOR_TAG_RSSI_IN) - 1)) {
        encode_uint32_value(&map, (uint32_t)node_stats->routing_info.rssi_in);
    }

    // rssi_out
    if (encode_text_string(&map, CBOR_TAG_RSSI_OUT, sizeof(CBOR_TAG_RSSI_OUT) - 1)) {
        encode_uint32_value(&map, (uint32_t)node_stats->routing_info.rssi_out);
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of node_stats_to_cbor buffer is %d", ret);
    *len = ret;
    return NM_STATUS_SUCCESS;
}

static nm_status_t neighbor_stats_to_cbor(void *stats_ns, uint8_t *cbor_data, size_t *len)
{

    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;
    CborEncoder stu_array;
    CborEncoder remap;

    nbr_info_t *nbr_info = (nbr_info_t *)stats_ns;

    cbor_encoder_init(&encoder, cbor_data,(nbr_info->count * (sizeof(nm_ws_nbr_info_t)) + NEIGHBOR_INFO_MAX_ENCODING_BUFF(nbr_info->count)), 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_warn("Could not create presence map: error %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // neighbor_count
    if (encode_text_string(&map, CBOR_TAG_NBR_COUNT, sizeof(CBOR_TAG_NBR_COUNT) - 1)) {
        encode_uint32_value(&map, (uint32_t)nbr_info->count);
    }

    if(nbr_info->count == 0) {
        // Close map
        cbor_error = cbor_encoder_close_container(&encoder, &map);
        if (cbor_error) {
            tr_warn("Could not close presence map: error %d", cbor_error);
            return NM_STATUS_FAIL;
        }

        size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
        tr_debug("Length of neighbor_info_to_cbor buffer is %d", ret);
        *len = ret;

        return NM_STATUS_SUCCESS;
    }

    // neighbor_info
    if(encode_text_string(&map, CBOR_TAG_NBR_INFO, sizeof(CBOR_TAG_NBR_INFO) - 1)) {

        // Create array
        cbor_error = cbor_encoder_create_array(&map, &stu_array, nbr_info->count);
        if (cbor_error) {
            tr_warn("Could not create array for map: error %d", cbor_error);
            return NM_STATUS_FAIL;
        }

        for (int i = 0; i < nbr_info->count; i++) {
            // Create remap
            cbor_error = cbor_encoder_create_map(&stu_array, &remap, CborIndefiniteLength);
            if (cbor_error) {
                tr_warn("Could not create presence remap: error %d", cbor_error);
                return NM_STATUS_FAIL;
            }

            // link_local_addr
            if (encode_text_string(&remap, CBOR_TAG_NBR_LINK_LOCAL_ADDR, sizeof(CBOR_TAG_NBR_LINK_LOCAL_ADDR) - 1)) {
                encode_byte_array(&remap, nbr_info->nbr_info_ptr[i].link_local_address, sizeof(nbr_info->nbr_info_ptr[i].link_local_address));
            }

            // global_addr
            if (encode_text_string(&remap, CBOR_TAG_NBR_GLOGBAL_ADDR, sizeof(CBOR_TAG_NBR_GLOGBAL_ADDR) - 1)) {
                encode_byte_array(&remap, nbr_info->nbr_info_ptr[i].global_address, sizeof(nbr_info->nbr_info_ptr[i].global_address));
            }

            // rsl_out
            if (encode_text_string(&remap, CBOR_TAG_NBR_RSL_OUT, sizeof(CBOR_TAG_NBR_RSL_OUT) - 1)) {
                encode_uint32_value(&remap, (uint32_t)nbr_info->nbr_info_ptr[i].rsl_out);
            }

            // rsl_in
            if (encode_text_string(&remap, CBOR_TAG_NBR_RSL_IN, sizeof(CBOR_TAG_NBR_RSL_IN) - 1)) {
                encode_uint32_value(&remap, (uint32_t)nbr_info->nbr_info_ptr[i].rsl_in);
            }

            // rpl_rank
            if (encode_text_string(&remap, CBOR_TAG_NBR_RPL_RANK, sizeof(CBOR_TAG_NBR_RPL_RANK) - 1)) {
                encode_uint32_value(&remap, (uint32_t)nbr_info->nbr_info_ptr[i].rpl_rank);
            }

            // etx
            if (encode_text_string(&remap, CBOR_TAG_NBR_ETX, sizeof(CBOR_TAG_NBR_ETX) - 1)) {
                encode_uint32_value(&remap, (uint32_t)nbr_info->nbr_info_ptr[i].etx);
            }

            // lifetime
            if (encode_text_string(&remap, CBOR_TAG_NBR_LIFETIME, sizeof(CBOR_TAG_NBR_LIFETIME) - 1)) {
                encode_uint32_value(&remap, (uint32_t)nbr_info->nbr_info_ptr[i].lifetime);
            }

            // type
            if (encode_text_string(&remap, CBOR_TAG_NBR_TYPE, sizeof(CBOR_TAG_NBR_TYPE) - 1)) {
                encode_uint32_value(&remap, (uint32_t)nbr_info->nbr_info_ptr[i].type);
            }

            // Close remap
            cbor_error = cbor_encoder_close_container(&stu_array, &remap);
            if (cbor_error) {
                tr_debug("Failed closing presence remap with error code %d", cbor_error);
                return NM_STATUS_FAIL;
            }
        }

        // Close array
        cbor_error = cbor_encoder_close_container(&map, &stu_array);
        if (cbor_error) {
            tr_warn("Could not close presence array of map: error %d", cbor_error);
            return NM_STATUS_FAIL;
        }

        // Close map
        cbor_error = cbor_encoder_close_container(&encoder, &map);
        if (cbor_error) {
            tr_warn("Could not close presence map: error %d", cbor_error);
            return NM_STATUS_FAIL;
        }

    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of neighbor_info_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}


nm_status_t nm_statistics_to_cbor(void *stats, uint8_t *cbor_data, config_type_t type, size_t *len)
{
    nm_status_t status = NM_STATUS_FAIL;
    switch (type) {
        case APP:
            status = app_stats_to_cbor(stats, cbor_data, len);
            if (status) {
                tr_info("Application statistics cbor encoder fail");
            }
            break;
        case BB:
            /* Not Supported */
            break;
        case WS:
            status = ws_stats_to_cbor(stats, cbor_data, len);
            if (status) {
                tr_info("Wi-Sun statistics cbor encoder fail");
            }
            break;
        case NM:
            status = nm_stats_to_cbor(stats, cbor_data, len);
            if (status) {
                tr_info("Genarel network statistics cbor encoder fail");
            }
            break;
        case BR:
            status = br_stats_to_cbor(stats, cbor_data, len);
            if (status) {
                tr_info("BR statistics cbor encoder fail");
            }
            break;
        case NI:
            status = node_stats_to_cbor(stats, cbor_data, len);
            if (status) {
                tr_info("NI statistics cbor encoder fail");
            }
            break;
        case NS:
            status = neighbor_stats_to_cbor(stats, cbor_data, len);
            if (status) {
                tr_info("Neighbor statistics cbor encoder fail");
            }
            break;
    }
    return status;
}

nm_status_t nm_routing_table_to_cbor(uint8_t *routing_table, size_t routing_table_length, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    if ((routing_table == NULL) || (cbor_data == NULL)) {
        return NM_STATUS_FAIL;
    }

    cbor_encoder_init(&encoder, cbor_data, ROUTING_TABLE_MAX_ENCODING_BUFF(routing_table_length), 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, 1);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    if (encode_text_string(&map, CBOR_TAG_ROUTING_TABLE, sizeof(CBOR_TAG_ROUTING_TABLE) - 1)) {
        if (!encode_byte_array(&map, routing_table, routing_table_length)) {
            printf("FAILED to CBORise Routing Table\n");
            return NM_STATUS_FAIL;
        }
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of ws_stats_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_ch_noise_statistics_to_cbor(int8_t *table, uint8_t index, uint8_t *cbor_data, size_t *len)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map;

    if ((table == NULL) || (cbor_data == NULL)) {
        return NM_STATUS_FAIL;
    }

    cbor_encoder_init(&encoder, cbor_data, CH_NOISE_TABLE_MAX_ENCODING_BUFF(index), 0);

    // Create map
    cbor_error = cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);
    if (cbor_error) {
        tr_debug("Failed creating presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    // cca_threshold_table
    if (encode_text_string(&map, CBOR_TAG_CCA_TH_TABLE, sizeof(CBOR_TAG_CCA_TH_TABLE) - 1)) {
        encode_int8_array(&map, table, index);
    }

    // Close Map
    cbor_error = cbor_encoder_close_container(&encoder, &map);
    if (cbor_error) {
        tr_debug("Failed closing presence map with error code %d", cbor_error);
        return NM_STATUS_FAIL;
    }

    size_t ret = cbor_encoder_get_buffer_size(&encoder, cbor_data);
    tr_debug("Length of ch_noise_stat_to_cbor buffer is %d", ret);
    *len = ret;

    return NM_STATUS_SUCCESS;
}

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
