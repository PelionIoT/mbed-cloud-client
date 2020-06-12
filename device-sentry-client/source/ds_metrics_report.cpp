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

#include "ds_metrics_report.h"
#include "ds_plat_metrics_report.h"
#include "pv_error_handling.h"

#ifndef DS_TEST_API
ds_status_e ds_cpu_stats_get(ds_stats_cpu_t *stats)
{
    return ds_plat_cpu_stats_get(stats);
}

ds_status_e ds_network_stats_get(ds_stats_network_t **network_stats_out, uint32_t *stats_count_out)
{
    return ds_plat_network_stats_get(network_stats_out, stats_count_out);
}

ds_status_e ds_thread_stats_get(uint32_t *thread_count_out)
{
    return ds_plat_thread_stats_get(thread_count_out);
}

ds_status_e ds_active_dests_collect_and_encode(CborEncoder *main_map)
{
    return ds_plat_active_dests_collect_and_encode(main_map);
}

ds_status_e ds_memory_stats_get(ds_stats_memory_t *mem_stats_out)
{
    return ds_plat_memory_stats_get(mem_stats_out);
}

#endif

ds_status_e ds_ip_data_encode(CborEncoder *ip_data_map, const ds_stat_ip_data_t *ip_data)
{
    // encode ip address to lable
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ip_data_map == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: ip_data_map is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ip_data == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: ip_data is NULL");

    CborError cbor_err = cbor_encode_uint(ip_data_map, DS_METRIC_LABEL_DEST_IP);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode dest ip key");

    cbor_err = cbor_encode_text_stringz(ip_data_map, ip_data->ip_addr);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode dest ip addr");

    // encode socket port
    cbor_err = cbor_map_encode_uint_uint(ip_data_map, DS_METRIC_LABEL_DEST_PORT, ip_data->port);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode dest port");

    SA_PV_LOG_TRACE("net metric ip_addr=%s, port=%" PRIu16 " encoded", ip_data->ip_addr, ip_data->port);
    return DS_STATUS_SUCCESS;
}

ds_status_e ds_ip_data_array_encode(const ds_stat_ip_data_t *ip_data_stats, uint32_t ip_data_stats_count, CborEncoder *active_dests_array)
{
    SA_PV_LOG_TRACE_FUNC_ENTER("encode %" PRIu32 " destinations", ip_data_stats_count);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ip_data_stats == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: ip_data_stats is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ip_data_stats_count == 0), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: ip_data_stats_count is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((active_dests_array == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: active_dests_array is NULL");

    for (uint32_t i = 0; i<ip_data_stats_count; i++) {

        CborEncoder dest_ip_map;
        CborError cbor_err = cbor_encoder_create_map(active_dests_array, &dest_ip_map, CborIndefiniteLength);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to create %" PRIu32 " dest ip map", i);

        // encode ip address to lable
        ds_status_e status = ds_ip_data_encode(&dest_ip_map, &ip_data_stats[i]);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to encode dest ip at index %" PRIu32, i);

        //Close lable map
        cbor_err = cbor_encoder_close_container(active_dests_array, &dest_ip_map);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to close dest ip map");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return DS_STATUS_SUCCESS;
}

