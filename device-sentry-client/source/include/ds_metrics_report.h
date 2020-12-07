// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#ifndef DS_METRICS_REPORT_H
#define DS_METRICS_REPORT_H

#include <stddef.h>
#include <stdint.h>
#include "ds_status.h"
#include "tinycbor.h"

// The size is suitable for IPV4 and IPV6 (if we will use IPV6 protocol it will take 39 bytes)
#define DS_MAX_IP_ADDR_SIZE 40

// Max size of the interface name buffer, taken with extra space
#define DS_MAX_INTERFACE_NAME_SIZE 128


#define DS_METRIC_CURRENT_VERSION  1
#define DS_METRIC_START_COLLECT 1
#define DS_METRIC_STOP_COLLECT 2
#define DS_METRIC_REPORT_V1 3
#define DS_METRIC_GROUP_LABELS 4
#define DS_METRIC_ACTIVE_DESTS 5
#define DS_METRIC_POLICY_ID 6

// Number of device metrics groups (cpu, threads number, network, memory)
// Note: for custom metrics see include files ds_custom_metrics_*.h
#define DS_MAX_METRIC_NUMBER 4


/** Metrics group identifiers.
 * This enums are used in configuration messages (start/stop metric collection) that are sent from Pelion to MCC.
 * 
 * Important note: when adding new metic groups, enlarge DS_MAX_METRIC_NUMBER.
 */
typedef enum{
    DS_METRIC_GROUP_BASE = 10,                              
    DS_METRIC_GROUP_CPU = DS_METRIC_GROUP_BASE + 1,         // cpu metrics group id
    DS_METRIC_GROUP_THREADS = DS_METRIC_GROUP_BASE + 2,     // threads metrics group id
    DS_METRIC_GROUP_NETWORK = DS_METRIC_GROUP_BASE + 3,     // network metrics group id
    DS_METRIC_GROUP_MEMORY = DS_METRIC_GROUP_BASE + 4,      // memory metrics group id

    // invalid metric group id, must be last
    DS_METRIC_GROUP_MAX = DS_METRIC_GROUP_BASE + 5

} ds_metric_group_id_e;

/**
 * @brief Returns index of the metric in report intervals internal array by metric group id. 
 * 
 * @param group_id metric group id, one of `ds_metric_group_id_e`.
 * @return uint32_t index of the metric in report intervals internal array.
 */
static inline uint32_t ds_array_index_by_metric_group_id_get(ds_metric_group_id_e group_id){
    return group_id - DS_METRIC_GROUP_BASE - 1;
}

/**
 * @brief Returns metric group id by index of the metric in report intervals internal array. 
 * 
 * @param uint32_t index of the metric in report intervals internal array.
 * @return ds_metric_group_id_e metric group id, one of `ds_metric_group_id_e`.
 */
static inline ds_metric_group_id_e ds_metric_group_id_by_array_index_get(uint32_t array_index){
    return (ds_metric_group_id_e)(array_index + DS_METRIC_GROUP_BASE + 1);
}

// Metrics report identifiers 
typedef enum {
    DS_METRIC_REPORT_DATA_BASE  = 50,
    DS_METRIC_BYTES_IN          = DS_METRIC_REPORT_DATA_BASE + 1,
    DS_METRIC_BYTES_OUT         = DS_METRIC_REPORT_DATA_BASE + 2,
    DS_METRIC_CPU_UP_TIME       = DS_METRIC_REPORT_DATA_BASE + 3,
    DS_METRIC_CPU_IDLE_TIME     = DS_METRIC_REPORT_DATA_BASE + 4,
    DS_METRIC_THREADS_COUNT     = DS_METRIC_REPORT_DATA_BASE + 7,
    DS_METRIC_HEAP_TOTAL        = DS_METRIC_REPORT_DATA_BASE + 8,
    DS_METRIC_HEAP_USED         = DS_METRIC_REPORT_DATA_BASE + 9,
    DS_METRIC_MEMORY_TOTAL      = DS_METRIC_REPORT_DATA_BASE + 10,
    DS_METRIC_MEMORY_USED       = DS_METRIC_REPORT_DATA_BASE + 11
} ds_metric_report_id_e;

// Metrics label identifiers
typedef enum {
    DS_METRIC_LABELS_BASE           = 100,
    DS_METRIC_LABEL_DEST_IP         = DS_METRIC_LABELS_BASE + 1,
    DS_METRIC_LABEL_DEST_PORT       = DS_METRIC_LABELS_BASE + 2,
    DS_METRIC_LABEL_INTERFACE_NAME  = DS_METRIC_LABELS_BASE + 3
} ds_metric_label_id_e;

typedef struct {
    char ip_addr[DS_MAX_IP_ADDR_SIZE];    /**< Destination ip addr of the connection */
    uint16_t port;                        /**< Destination port of the connection */
} ds_stat_ip_data_t;

typedef struct {
    uint64_t sent_bytes;                    /**< Data sent through this socket */
    uint64_t recv_bytes;                    /**< Data received through this socket */
    ds_stat_ip_data_t ip_data;              /**< Outgoing connection data */
    char interface[DS_MAX_INTERFACE_NAME_SIZE]; /**< Interface name */

} ds_stats_network_t;

typedef struct {
    uint64_t uptime;            /**< Time in seconds since the system has started */
    uint64_t idle_time;         /**< Time in seconds spent in the idle thread since the system has started */
} ds_stats_cpu_t;

typedef struct {
    uint64_t mem_available_bytes;           /**< RAM Memory in bytes that is available for using */
    uint64_t mem_used_bytes;                /**< RAM Memory in bytes that is currently used */
    ds_metric_report_id_e mem_available_id; /**< Available memory id: 
                                                 - for Linux it is always DS_METRIC_MEMORY_TOTAL
                                                 - for Mbed-OS it is always DS_METRIC_HEAP_TOTAL */
    ds_metric_report_id_e mem_used_id;      /**< Used memory id 
                                                 - for Linux it is always DS_METRIC_MEMORY_USED
                                                 - for Mbed-OS it is always DS_METRIC_HEAP_USED */
    
} ds_stats_memory_t;

/**
 * @brief Returns CPU statistics.
 * 
 * @param cpu_stats_out output paramter that will be filled CPU statistics. 
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, cpu_stats_out will be filled with CPU statistics. 
 */
ds_status_e ds_cpu_stats_get(ds_stats_cpu_t *cpu_stats_out);

/**
 * @brief  Allocates and returns array of network statistics. 
 * 
 * @param network_stats_out an output paramter that will store new allocated array that will be filled with socket information. 
 *                     Note: socket_stats parameter must be freed by a calling function (using free()) 
 *                              after the inforamtion is not required any more. 
 * 
 * @param stats_count_out an output paramter that will store number of entries in socket_stats.
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                      - In case of success, network_stats_out should be freed (using free()) by a caller. 
 *                      - In case of no network usage, returns DS_STATUS_SUCCESS, and zeros in output.                   
 *                      - In case of error, value of the network_stats_out will be NULL (freeing is not required).
 */
ds_status_e ds_network_stats_get(ds_stats_network_t **network_stats_out, uint32_t *stats_count_out);

/**
 * @brief Returns number of threads in the whole system.
 * 
 * @param thread_count_out output paramter that will be filled with number of threads. 
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, thread_count_out will be filled with number of threads. 
 */
ds_status_e ds_thread_stats_get(uint32_t *thread_count_out);

/**
 * @brief Collects active network destinations (ip addresses and ports) and encodes in to a cbor array.
 * 
 * @param main_map cbor map to which ip data should be encoded.
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 */
ds_status_e ds_active_dests_collect_and_encode(CborEncoder *main_map);

/**
 * @brief Returns memory statistics.
 * 
 * @param mem_stats_out output paramter that will be filled with memory statistics. 
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, mem_stats_out will be filled with memory statistics. 
 */
ds_status_e ds_memory_stats_get(ds_stats_memory_t *mem_stats_out);


/**
 * @brief Encodes ip data single structure (ip address and port) to cbor.
 * 
 * @param ip_data_map cbor map to which ip data should be encoded.
 * @param ip_data ip address and port number to encode.
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 */
ds_status_e ds_ip_data_encode(CborEncoder *ip_data_map, const ds_stat_ip_data_t *ip_data);

/**
 * @brief Encodes ip data structures array to cbor active destinations array.
 * 
 * @param ip_data_stats array of structures, which contains ip address and port number to encode.
 * @param ip_data_stats_count number of intems in the array.
 * @param active_dests_array cbor active destinations array.
 * @return ds_status_e ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise.
 */
ds_status_e ds_ip_data_array_encode(const ds_stat_ip_data_t *ip_data_stats, uint32_t ip_data_stats_count, CborEncoder *active_dests_array);

#endif // DS_METRICS_REPORT_H
