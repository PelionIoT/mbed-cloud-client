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

#ifndef NETWORK_MANAGER_API_H_
#define NETWORK_MANAGER_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)

/* Enumeration for application event handler */
enum app_state {
    NM_CONNECTED = 0,
    NM_INIT_CONF
};

typedef void (* nm_app_cb)(uint8_t msg_type, void *msg);

void nm_application_cb(nm_app_cb register_callback);
void nm_init(void *);
void nm_connect(void);
void *nm_get_mesh_iface(void);
void *nm_get_br_instance(void);
void nm_cloud_client_connect_notification(void);

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* NETWORK_MANAGER_API_H_ */
