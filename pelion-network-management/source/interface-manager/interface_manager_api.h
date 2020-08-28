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

#ifndef INTERFACE_MANAGER_API_H_
#define INTERFACE_MANAGER_API_H_

typedef enum iface_status {
    IFACE_STATUS_FAIL = 1,
    IFACE_STATUS_SUCCESS
} iface_status_t;

void nm_iface_backhaul_up(void);
void nm_iface_backhaul_down(void);

nm_status_t nm_iface_mesh_init(void);
nm_status_t nm_iface_mesh_up(void);
void nm_iface_mesh_down(void);
nm_status_t nm_res_set_ws_config(uint8_t *data, size_t length);
nm_status_t nm_res_get_ws_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_nm_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_node_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_radio_stats(uint8_t **datap, size_t *length);

nm_status_t nm_iface_br_up(void);
nm_status_t nm_iface_check_mesh_ip(void);
void nm_iface_br_down(void);
nm_status_t nm_res_set_br_config(uint8_t *data, size_t length);
nm_status_t nm_res_get_br_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_routing_table(uint8_t **datap, size_t *length);

#endif /* INTERFACE_MANAGER_API_H_ */
