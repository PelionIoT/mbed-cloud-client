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

#ifndef DS_PLAT_METRICS_REPORT_H
#define DS_PLAT_METRICS_REPORT_H

#include "ds_metrics_report.h"
#include "ds_status.h"
#include "tinycbor.h"

/**
 * @brief Returns CPU statistics in a platform dependent way.
 * 
 * @param stats_out output paramter that will be filled CPU statistics. 
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, cpu_stats_out will be filled with CPU statistics. 
 */
ds_status_e ds_plat_cpu_stats_get(ds_stats_cpu_t *stats_out);

/**
 * @brief  Allocates and returns array of network statistics in a platform dependent way. 
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
ds_status_e ds_plat_network_stats_get(ds_stats_network_t **network_stats_out, uint32_t *stats_count_out);

/**
 * @brief Returns number of threads in the whole system in a platform dependent way.
 * 
 * @param thread_count_out output paramter that will be filled with number of threads. 
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, thread_count_out will be filled with number of threads. 
 */
ds_status_e ds_plat_thread_stats_get(uint32_t *thread_count_out);

/**
 * @brief Collects active network destinations (ip address and port) and encodes in to a cbor array in a platform dependent way.
 * 
 * @param main_map cbor map to which ip data should be encoded.
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 */
ds_status_e ds_plat_active_dests_collect_and_encode(CborEncoder *main_map);

/**
 * @brief Encodes ip data (ip address and port) in labaled metrics map in a platform dependent way.
 * 
 * @param ip_data_map cbor map to which ip data should be encoded.
 * @param ip_data 
 * @return ds_status_e 
 */
ds_status_e ds_plat_labeled_metric_ip_data_encode(CborEncoder *ip_data_map, const ds_stat_ip_data_t *ip_data);

/**
 * @brief Returns memory statistics in a platform dependent way.
 * 
 * @param mem_stats_out output paramter that will be filled with memory statistics. 
 * 
 * @return ds_status_e DS_STATUS_SUCCESS on successful operation of the function, or error code otherwise. 
 *                     In case of success, mem_stats_out will be filled with memory statistics. 
 */
ds_status_e ds_plat_memory_stats_get(ds_stats_memory_t *mem_stats_out);

#endif // DS_PLAT_METRICS_REPORT_H