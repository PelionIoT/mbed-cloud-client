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

#include <stdlib.h>
#include <inttypes.h>
#include "ds_metrics_report.h"
#include "ds_plat_metrics_report.h"
#include "platform/mbed_stats.h"
#include "SocketStats.h"
#include "NetworkInterface.h"
#include "pv_error_handling.h"

#define MICROSEC_TO_SEC(micro_sec) (micro_sec/1000000)

ds_status_e ds_plat_cpu_stats_get(ds_stats_cpu_t *stats)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((stats == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: stats is NULL");

    mbed_stats_cpu_t mbed_cpu_stats;
    mbed_stats_cpu_get(&mbed_cpu_stats);

    stats->uptime = MICROSEC_TO_SEC(mbed_cpu_stats.uptime);
    stats->idle_time = MICROSEC_TO_SEC(mbed_cpu_stats.idle_time);

    SA_PV_LOG_TRACE_FUNC_EXIT("uptime=%" PRIu64 ", idletime=%" PRIu64, stats->uptime, stats->idle_time);
    return DS_STATUS_SUCCESS;
}

ds_status_e ds_plat_network_stats_get(ds_stats_network_t **network_stats_out, uint32_t *stats_count_out)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((network_stats_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: network_stats_out is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((stats_count_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: stats_count_out is NULL");

    ds_stats_network_t *stats_array = NULL;
    uint32_t stats_array_index = 0;
    mbed_stats_socket_t tcp_stats[MBED_CONF_NSAPI_SOCKET_STATS_MAX_COUNT];

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    size_t num_of_sockets = SocketStats::mbed_stats_socket_get_each(tcp_stats, MBED_CONF_NSAPI_SOCKET_STATS_MAX_COUNT);

    // The only way to get interface name on MbedOS is to get default interface, and to fetch it's name. 
    // It will be the same for all sockets, even if practically we have 2 interfaces (WIFI and ETHERNET for example)
    NetworkInterface *default_if = NetworkInterface::get_default_instance(); 
    SA_PV_ERR_RECOVERABLE_RETURN_IF((default_if == NULL), DS_STATUS_ERROR, "mbed os get_default_instance failed!");

    char interface_name[DS_MAX_INTERFACE_NAME_SIZE];
    const char *interface_name_ptr = default_if->get_interface_name(interface_name);
    if(interface_name_ptr == NULL){
        // get_interface_name will return NULL if the interface does not exist
        interface_name_ptr = "not_exist";
    }

    if (num_of_sockets != 0) {

        // allocate output array
        stats_array = (ds_stats_network_t *)malloc(num_of_sockets * sizeof(ds_stats_network_t));
        
        SA_PV_ERR_RECOVERABLE_RETURN_IF((stats_array == NULL), DS_STATUS_ERROR, 
            "Memory allocation (%" PRIu32 " bytes) failed", (uint32_t)(num_of_sockets * sizeof(ds_stats_network_t)));

        for (uint32_t i = 0; i < num_of_sockets; i++) {

            // TODO: verify maybe we need to refer to the tcp_stats[i].state field of the structure 
            //       in order to differentiate between active sockets and closed sockets
            if (tcp_stats[i].reference_id != NULL && tcp_stats[i].peer) {

                strncpy(stats_array[stats_array_index].interface, interface_name_ptr, DS_MAX_INTERFACE_NAME_SIZE);

                // copy tcp_stats[i] to stats_array[stats_array_index]
                strncpy(stats_array[stats_array_index].ip_data.ip_addr, tcp_stats[i].peer.get_ip_address(), DS_MAX_IP_ADDR_SIZE);
                stats_array[stats_array_index].ip_data.port = tcp_stats[i].peer.get_port();
                stats_array[stats_array_index].recv_bytes = tcp_stats[i].recv_bytes;
                stats_array[stats_array_index].sent_bytes = tcp_stats[i].sent_bytes;
                stats_array_index++;
            }
        }
    }
    // return allocated array address and number of stats_array that were copied to the user
    *network_stats_out = stats_array;
    *stats_count_out = stats_array_index;
    SA_PV_LOG_TRACE_FUNC_EXIT("report %" PRIu32 " connections", (uint32_t)stats_array_index);
    return DS_STATUS_SUCCESS;
}

ds_status_e ds_plat_thread_stats_get(uint32_t *thread_count_out)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((thread_count_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: thread_count_out is NULL");

    *thread_count_out = osThreadGetCount();
    SA_PV_LOG_TRACE_FUNC_EXIT("thread_count_out=%" PRIu32, *thread_count_out);

    return DS_STATUS_SUCCESS;
}

ds_status_e ds_plat_memory_stats_get(ds_stats_memory_t *mem_stats_out)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((mem_stats_out == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: mem_stats_out is NULL");

    mbed_stats_heap_t mbed_heap_stats;
    mbed_stats_heap_get(&mbed_heap_stats);

    // heap reserved_size is the field that stores memory size reserved for heap in mbed-os. 
    // reserved_size calculated from the variable mbed_heap_size that has constant value.
    mem_stats_out->mem_available_bytes = mbed_heap_stats.reserved_size;
    
    // current_size is the field that summarize currently allocated bytes from the heap. 
    mem_stats_out->mem_used_bytes = mbed_heap_stats.current_size;

    // on mbed os we collect heap statistics
    mem_stats_out->mem_available_id = DS_METRIC_HEAP_TOTAL;
    mem_stats_out->mem_used_id = DS_METRIC_HEAP_USED;

    SA_PV_LOG_TRACE_FUNC_EXIT("used=%" PRIu64 ", available=%" PRIu64, mem_stats_out->mem_used_bytes, mem_stats_out->mem_available_bytes);
    return DS_STATUS_SUCCESS;
}


ds_status_e ds_plat_active_dests_collect_and_encode(CborEncoder *main_map)
{
    (void)main_map;
    // active network metrics not relevant for Mbed OS - do nothing
    return DS_STATUS_SUCCESS;
}

ds_status_e ds_plat_labeled_metric_ip_data_encode(CborEncoder *ip_data_map, const ds_stat_ip_data_t *ip_data)
{
    return ds_ip_data_encode(ip_data_map, ip_data);
}

