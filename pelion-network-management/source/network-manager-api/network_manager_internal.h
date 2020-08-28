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

#ifndef NETWORK_MANAGER_INTERNAL_H_
#define NETWORK_MANAGER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


#include "nsdynmemLIB.h"
#include "mbed_stats.h"
#include "mesh_interface_types.h"

//if (MBED_CONF_MBED_MESH_API_WISUN_DEVICE_TYPE == MESH_DEVICE_TYPE_WISUN_BORDER_ROUTER)

typedef enum config {
    APP = 0,
    BB,
    WS,
    BR,
    NM,
    NI,
    RQ
} config_type_t;

typedef enum nm_status {
    NM_STATUS_FAIL = -1,
    NM_STATUS_SUCCESS = 0
} nm_status_t;

typedef enum nm_event_type_e {
    NM_EVENT_IDLE = 0,
    NM_EVENT_CONNECT,
    NM_EVENT_BACKHAUL_CONNECTED,
    NM_EVENT_PDMC_CONNECTED,
    NM_EVENT_MESH_CONNECTED,
    NM_EVENT_CHECK_MESH_IFACE_IP,
    NM_EVENT_RESOURCE_GET,
    NM_EVENT_RESOURCE_SET,
    NM_EVENT_STATS_REFRESH_TIMEOUT,
    NM_EVENT_TYPE_MAX = 0xff // Must fit in a uint8_t (field in the arm_event_s struct)
} nm_event_t;

nm_status_t nm_post_event(nm_event_t event_type, uint8_t event_id, void *data);

#define WS_RESOURCE_VERSION 1
#define WS_BR_RESOURCE_VERSION 1
#define WS_STATS_RESOURCE_VERSION 1
#define BR_STATS_RESOURCE_VERSION 1
#define NODE_INFORMATION_VERSION 1
#define RADIO_QUALITY_VERSION 1

/* Application configuration */
/* To-Do: Application configuration not decided yet (which conf. is changeable from server) */


typedef struct {
    uint8_t regulatory_domain;
    uint8_t operating_class;
    uint8_t operating_mode;
} reg_op_t;

typedef struct {
    mesh_channel_function_t uc_channel_function;
    uint16_t uc_fixed_channel;
    uint8_t uc_dwell_interval;
} uc_ch_config_t;

typedef struct {
    mesh_channel_function_t bc_channel_function;
    uint16_t bc_fixed_channel;
    uint8_t bc_dwell_interval;
    uint32_t bc_interval;
} bc_ch_config_t;

typedef struct {
    uint16_t disc_trickle_imin;
    uint16_t disc_trickle_imax;
    uint8_t disc_trickle_k;
    uint16_t pan_timeout;
} timing_param_t;

/* Wi-Sun Configuration */
typedef struct {
    uint32_t channel_mask[8];
    uint32_t resource_version;
    reg_op_t reg_op;
    uint8_t network_size;
    uc_ch_config_t uc_ch_config;
    bc_ch_config_t bc_ch_config;
    timing_param_t timing_param;
    uint16_t delay;
    uint8_t device_min_sens;
} nm_ws_config_t;

typedef struct {
    uint8_t dio_interval_min;
    uint8_t dio_interval_doublings;
    uint8_t dio_redundancy_constant;
} rpl_config_t;

typedef struct {
    char network_name[33];
    uint32_t resource_version;
    rpl_config_t rpl_config;
    uint16_t delay;
    uint16_t pan_id;
} nm_br_config_t;

/* Application Statistics */
typedef struct {
    mem_stat_t mem_stats;
    mbed_stats_cpu_t cpu_stats;
    mbed_stats_heap_t heap_stats;
} nm_app_statistics_t;

/* General Network Statistics */
typedef struct {
    mesh_mac_statistics_t mesh_mac_statistics;
} nm_general_nw_statistics_t;

/* Wi-Sun Common Identification Statistics */
typedef struct {
    uint32_t resource_version;
    uint8_t global_addr[16];
    uint8_t link_local_addr[16];
    uint8_t rpl_dodag_id[16];
    uint8_t instance_id;
    uint8_t version;
} ws_common_id_statistics_t;

/* Wi-Sun RPL Statistics */
typedef struct {
    uint32_t rpl_total_memory;  /*<! RPL current memory usage total. */
} ws_rpl_statistics_t;

/* Wi-Sun MAC Statistics */
typedef struct {
    uint32_t asynch_tx_count;   /*<! Asynch TX counter */
    uint32_t asynch_rx_count;   /*<! Asynch RX counter */
} ws_mac_statistics_t;

/* Wi-SUN common information */
typedef struct {
    ws_common_id_statistics_t ws_common_id_statistics;
    ws_rpl_statistics_t ws_rpl_statistics;
    ws_mac_statistics_t ws_mac_statistics;
} nm_ws_common_info_t;

/* Wi-SUN border router information */
typedef struct {
    uint64_t host_time;
    uint32_t resource_version;
    uint16_t device_count;
    uint8_t global_addr_northbound[16];
    uint8_t local_addr_northbound[16];
} nm_ws_br_info_t;

/* Node routing information */
typedef struct {
    uint16_t curent_rank;
    uint16_t primary_parent_rank;
    uint8_t primary_parent[16];
    uint16_t etx_1st_parent;    /*<! Primary parent ETX. */
    uint16_t etx_2nd_parent;    /*<! Secondary parent ETX. */
}routing_info_t;

/* Node information */
typedef struct {
    uint32_t resource_version;
    routing_info_t routing_info;
}nm_node_info_t;

/* Radio quality */
typedef struct {
    uint32_t resource_version;
    uint8_t rssi_in;
    uint8_t rssi_out;
}nm_radio_quality_t;

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* NETWORK_MANAGER_INTERNAL_H_ */
