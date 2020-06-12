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

#include "ds_plat_metrics_report.h"

ds_status_e ds_plat_cpu_stats_get(ds_stats_cpu_t *stats)
{
    (void)stats;
    return DS_STATUS_UNSUPPORTED_METRIC;
}

ds_status_e ds_plat_thread_stats_get(uint32_t *thread_count_out)
{
    (void)thread_count_out;
    return DS_STATUS_UNSUPPORTED_METRIC;
}

ds_status_e ds_plat_network_stats_get(ds_stats_network_t **network_stats_out, uint32_t *stats_count_out)
{
    (void)network_stats_out;
    (void)stats_count_out;
    return DS_STATUS_UNSUPPORTED_METRIC;
}

ds_status_e ds_plat_active_dests_collect_and_encode(CborEncoder *main_map)
{
    (void)main_map;
    return DS_STATUS_UNSUPPORTED_METRIC;
}

ds_status_e ds_plat_labeled_metric_ip_data_encode(CborEncoder *ip_data_map, const ds_stat_ip_data_t *ip_data)
{
    (void)ip_data_map;
    (void)ip_data;
    return DS_STATUS_UNSUPPORTED_METRIC;
}
