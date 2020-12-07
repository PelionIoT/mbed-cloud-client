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

#ifndef NM_INTERFACE_MANAGER_H_
#define NM_INTERFACE_MANAGER_H_

void register_interfaces(NetworkInterface *mesh_iface, NetworkInterface *backhaul_iface, WisunBorderRouter *br_iface);

nm_status_t nm_configure_mesh_iface(void);
nm_status_t nm_res_set_ws_config(uint8_t *data, size_t length);
nm_status_t nm_res_get_ws_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_nm_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_node_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_radio_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_ch_noise_stats(uint8_t **datap, size_t *length);
void apply_ws_config_after_delay(uint16_t delay);
void apply_ws_config_to_nannostack(void);
void mesh_interface_connected(void);

nm_status_t nm_configure_border_router(void);
nm_status_t nm_res_set_br_config(uint8_t *data, size_t length);
nm_status_t nm_res_get_br_stats(uint8_t **datap, size_t *length);
nm_status_t nm_res_get_routing_table(uint8_t **datap, size_t *length);
void apply_br_config_after_delay(uint16_t delay);
void apply_br_config_to_nannostack(void);


#endif /* NM_INTERFACE_MANAGER_H_ */
