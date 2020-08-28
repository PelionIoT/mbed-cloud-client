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

#ifndef CBOR_API_H_
#define CBOR_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "network_manager_internal.h"

/* What should be the max value of MAX_ENCCODER_BUF ?? */
/* Following buffer size need be change after adding/removing parameters from CBOR*/
#define WS_CONF_MAX_ENCCODER_BUF 512
#define BR_CONF_MAX_ENCCODER_BUF 256

#define APP_STAT_MAX_ENCCODER_BUF 512
#define WS_STAT_MAX_ENCCODER_BUF 512
#define NM_STAT_MAX_ENCCODER_BUF 256
#define BR_STAT_MAX_ENCCODER_BUF 256
#define NI_STAT_MAX_ENCCODER_BUF 256
#define RQ_STAT_MAX_ENCCODER_BUF 64

#define ROUTING_TABLE_CBOR_OVERHEAD                 30
#define ROUTING_TABLE_MAX_ENCODING_BUFF(table_length) (table_length+ROUTING_TABLE_CBOR_OVERHEAD)

nm_status_t nm_cbor_config_struct_update(void *st_cfg, uint8_t *cbor_data, config_type_t type, size_t len);
nm_status_t nm_config_to_cbor(void *st_cfg, uint8_t *cbor_data, config_type_t type, size_t *len);
nm_status_t nm_statistics_to_cbor(void *stats, uint8_t *cbor_data, config_type_t type, size_t *len);
nm_status_t nm_routing_table_to_cbor(uint8_t *routing_table, uint16_t routing_table_length, uint8_t *cbor_data, size_t *len);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* NETWORK_MANAGER_SOURCE_CODEC_CBOR_API_H_ */
