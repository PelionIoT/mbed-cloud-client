/*
 * Copyright (c) 2020-2021 Pelion. All rights reserved.
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

#ifndef NETWORK_MANAGER_H_
#define NETWORK_MANAGER_H_

#if defined MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)

/* Enumeration for Network manager error value */
typedef enum nm_error {
    NM_ERROR_UNKNOWN = -1,
    NM_ERROR_NONE = 0
} nm_error_t;

/** Network Manager class
 *
 * Class can be used to configure interfaces and create network manager resources.
 */
class NetworkManager {
public:

    /**
     * \brief Reads MAC addresses from factory configuration and set on Mesh interface and Backhaul interface.
     *
     * Function reads the MAC addresses from factory configuration and set on Mesh interface and Backhaul interface.
     *
     * \param mesh_iface Instance of Mesh interface.
     * \param backhaul_iface Instance of Backhaul interface.
     * \return NM_ERROR_NONE on success.
     * \return NM_ERROR_UNKNOWN in case of failure.
     * */
    nm_error_t configure_factory_mac_address(void *mesh_iface, void *backhaul_iface);

    /**
     * \brief Reads MAC address from factory configuration and set on Mesh interface.
     *
     * Function reads the MAC address from factory configuration and set on Mesh interface.
     *
     * \param mesh_iface Instance of mesh interface.
     * \return NM_ERROR_NONE on success.
     * \return NM_ERROR_UNKNOWN in case of failure.
     * */
    nm_error_t configure_factory_mac_address(void *mesh_iface);

    /**
     * \brief Registers the interfaces into Network manager and configures them with latest configuration.
     *
     * Function stores the Mesh Interafce mesh_iface, Backhaul Interaface backhaul_iface and
     * Border Router Interafce br_iface in network manager. Also it reads configurations from
     * the KVStore and configures the Mesh and the Border Router interface.
     *
     * \param mesh_iface Instance of Mesh interface.
     * \param backhaul_iface Instance of Backhaul interface.
     * \param br_iface Instance of Border Router interface.
     * \return NM_ERROR_NONE on success.
     * \return NM_ERROR_UNKNOWN in case of failure.
     * */
    nm_error_t reg_and_config_iface(void *mesh_iface, void *backhaul_iface, void *br_iface);

    /**
     * \brief Registers the mesh interface into Network manager and configures it with latest configuration.
     *
     * Function stores the mesh_iface in network manager. Also it reads
     * configurations from the KVStore and configures the Mesh interface.
     *
     * \param mesh_iface Instance of mesh interface.
     * \return NM_ERROR_NONE on success.
     * \return NM_ERROR_UNKNOWN in case of failure.
     * */
    nm_error_t reg_and_config_iface(void *mesh_iface);

    /**
     * \brief Creates all network manager resources.
     *
     * Function creates all network manager resources and adds to the M2M Object list.
     *
     * \param m2m_obj_list Pointer to the M2M object list
     * \return NM_ERROR_NONE on success.
     * \return NM_ERROR_UNKNOWN in case of failure.
     * */
    nm_error_t create_resource(M2MObjectList *m2m_obj_list);

    /**
     * \brief Indicates network manager that the cloud client is connected.
     *
     * Function indicates network manager that the cloud client is connected,
     * so that the network manager can set all the configuration value to it's resources.
     *
     * \param void
     * \return void
     * */
    void nm_cloud_client_connect_indication(void);
};

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
#endif /* NETWORK_MANAGER_H_ */
