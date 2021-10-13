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

#ifndef NETWORK_MANAGER_INTERNAL_H_
#define NETWORK_MANAGER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


#include "nsdynmemLIB.h"
#include "mbed_stats.h"
#include "mesh_interface_types.h"

typedef enum config {
    APP = 0,
    BB,
    WS,
    BR,
    NM,
    NI,
    NS,
    TM
} config_type_t;

typedef enum {
    /** Fixed channel. */
    NM_WS_FIXED_CHANNEL,
    /** TR51 channel function. */
    NM_WS_TR51CF,
    /** Direct Hash channel function. */
    NM_WS_DH1CF,
    /** Vendor Defined channel function. */
    NM_WS_VENDOR_DEF_CF
} nm_ws_channel_functions;

typedef enum nm_status {
    NM_STATUS_FAIL = -1,
    NM_STATUS_SUCCESS = 0,
    NM_STATUS_UNSUPPORTED
} nm_status_t;

typedef enum nm_event_type_e {
    NM_EVENT_INIT,
    NM_EVENT_RESOURCE_SET,
    NM_EVENT_APPLY_WS_CONFIG_AFTER_DELAY,
    NM_EVENT_APPLY_BR_CONFIG_AFTER_DELAY,
    NM_EVENT_STATS_REFRESH_TIMEOUT,
    NM_EVENT_RESOURCE_GET,
    NM_EVENT_TYPE_MAX = 0xff // Must fit in a uint8_t (field in the arm_event_s struct)
} nm_event_t;

nm_status_t nm_post_event(nm_event_t event_type, uint8_t event_id, void *data);
nm_status_t nm_post_timeout_event(nm_event_t event_type, int32_t delay);
nm_status_t send_ntp_rev_conf_to_app(char *server_addr, uint32_t timeout);

#define WS_RESOURCE_VERSION 1
#define WS_BR_RESOURCE_VERSION 1
#define WS_STATS_RESOURCE_VERSION 1
#define BR_STATS_RESOURCE_VERSION 1
#define NODE_INFORMATION_VERSION 1

/* Application configuration */
/* To-Do: Application configuration not decided yet (which conf. is changeable from server) */


typedef struct {
    uint8_t operating_class;
    uint8_t operating_mode;
} op_class_mode_t;

typedef struct {
    uint8_t phy_mode_id;
    uint8_t channel_plan_id;
} network_domain_t;

typedef struct {
    op_class_mode_t op_class_mode;
    network_domain_t net_dom;
} phy_config_t;

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
    char network_name[33];
    uint32_t channel_mask[8];
    uint32_t resource_version;
    uint8_t regulatory_domain;
    phy_config_t phy_config;
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
    char address[40];
    uint16_t secret_len;
    uint8_t *secret;
} radius_server_t;

typedef struct {
    uint32_t resource_version;
    rpl_config_t rpl_config;
    uint16_t delay;
    uint16_t pan_id;
    radius_server_t radius_config;
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
    uint16_t pan_id;
} ws_common_id_statistics_t;

/* Wi-Sun mesh Statistics */
typedef struct {
    uint32_t rpl_total_memory;  /*<! RPL current memory usage total. */
    uint32_t asynch_tx_count;   /*<! Asynch TX counter */
    uint32_t asynch_rx_count;   /*<! Asynch RX counter */
    uint32_t join_state_1;      /*<! Time spent in individual Wi-SUN join state 1 Discovery */
    uint32_t join_state_2;      /*<! Time spent in individual Wi-SUN join state 2 Authentication */
    uint32_t join_state_3;      /*<! Time spent in individual Wi-SUN join state 3 Configuration learn */
    uint32_t join_state_4;      /*<! Time spent in individual Wi-SUN join state 4 RPL parent discovery */
    uint32_t join_state_5;      /*<! Time spent in individual Wi-SUN join state 5 Active state */
    uint32_t sent_PAS;          /*<! Amount of Wi-SUN Pan Advertisement Solicit Message sent */
    uint32_t sent_PA;           /*<! Amount of Wi-SUN Pan Advertisement Message sent */
    uint32_t sent_PCS;          /*<! Amount of Wi-SUN Pan Configuration Solicit Message sent */
    uint32_t sent_PC;           /*<! Amount of Wi-SUN Pan Configuration Message sent */
    uint32_t recv_PAS;          /*<! Amount of Wi-SUN Pan Advertisement Solicit Message received */
    uint32_t recv_PA;           /*<! Amount of Wi-SUN Pan Advertisement Message received */
    uint32_t recv_PCS;          /*<! Amount of Wi-SUN Pan Configuration Solicit Message received */
    uint32_t recv_PC;           /*<! Amount of Wi-SUN Pan Configuration Message received */
    uint32_t neighbour_add;     /*<! New Neighbours found */
    uint32_t neighbour_remove;  /*<! New Neighbours Removed */
    uint32_t child_add;         /*<! New Child added */
    uint32_t child_remove;      /*<! Child lost */
} ws_mesh_statistics_t;

/* Wi-SUN common information */
typedef struct {
    ws_common_id_statistics_t ws_common_id_statistics;
    ws_mesh_statistics_t ws_mesh_statistics;
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
    uint8_t rssi_in;
    uint8_t rssi_out;
} routing_info_t;

/* Node information */
typedef struct {
    uint32_t resource_version;
    routing_info_t routing_info;
} nm_node_info_t;

typedef enum {
    NM_WISUN_OTHER = 0,            /**< temporary or soon to be removed neighbor*/
    NM_WISUN_PRIMARY_PARENT,       /**< Primary parent used for upward packets and used from Border router downwards*/
    NM_WISUN_SECONDARY_PARENT,     /**< Secondary parent reported to border router and might be used as alternate route*/
    NM_WISUN_CANDIDATE_PARENT,     /**< Candidate neighbor that is considered as parent if there is problem with active parents*/
    NM_WISUN_CHILD                 /**< Child with registered address*/
} nm_ws_nbr_type_e;

typedef struct {
    /** parent RSSI Out measured RSSI value calculated using EWMA specified by Wi-SUN from range of -174 (0) to +80 (254) dBm.*/
    uint8_t rsl_out;
    /** parent RSSI in measured RSSI value calculated using EWMA specified by Wi-SUN from range of -174 (0) to +80 (254) dBm.*/
    uint8_t rsl_in;
    /** RPL Rank value for parents 0xffff for neighbors RANK is unknown*/
    uint16_t rpl_rank;
    /** Measured ETX value if known set to 0xFFFF if not known or Child*/
    uint16_t etx;
    /** Remaining lifetime Link lifetime for parents and ARO lifetime for children*/
    uint32_t lifetime;
    /** Neighbour type (Primary Parent, Secondary Parent, Candidate parent, child, other(Temporary neighbours))*/
    nm_ws_nbr_type_e type;
    /** Link local address*/
    uint8_t link_local_address[16];
    /** Global address if it is known set to 0 if not available*/
    uint8_t global_address[16];
} nm_ws_nbr_info_t;

typedef struct {
    uint16_t count;
    nm_ws_nbr_info_t *nbr_info_ptr;
} nbr_info_t;

typedef struct {
    uint32_t interval;
    char server_addr[33];
} nm_time_sync_t;

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* NETWORK_MANAGER_INTERNAL_H_ */
