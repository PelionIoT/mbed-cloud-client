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
#ifndef DS_CUSTOM_METRICS_INTERNAL_API_H
#define DS_CUSTOM_METRICS_INTERNAL_API_H

#include <stddef.h>
#include <stdint.h>
#include "ds_status.h"
#include "ds_custom_metrics.h"

// Maximal number of custom metrics in the configuration message
#define DS_MAX_NUMBER_OF_CUSTOM_METRICS 10

// structure describing custom metrics meta-data
typedef struct ds_custom_metric_t {
    ds_custom_metric_id_t metric_id;
    uint32_t report_interval;           // reporting interval in seconds
} ds_custom_metric_t;


#endif // DS_CUSTOM_METRICS_INTERNAL_API_H
