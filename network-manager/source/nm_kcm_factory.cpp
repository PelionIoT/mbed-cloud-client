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

#if defined MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)

#include "string.h"
#include "mbed_trace.h"
#include "ws_management_api.h"
#include "NetworkManager_internal.h"
#include "nm_kcm_factory.h"
#include "key_config_manager.h"
#include "nm_dynmem_helper.h"

/* Trace name */
#define TRACE_GROUP "NMfc"

/* KCM configuration item names */
static const char MESH_WISUN_NETWORK_NAME_KEY[] = "mesh_wisun_network_name";
static const char MESH_WISUN_NETWORK_SIZE_KEY[] = "mesh_wisun_network_size";
static const char MESH_WISUN_REGULATORY_DOMAIN_KEY[] = "mesh_wisun_regulatory_domain";
static const char MESH_WISUN_OPERATING_MODE_KEY[] = "mesh_wisun_operating_mode";
static const char MESH_WISUN_OPERATING_CLASS_KEY[] = "mesh_wisun_operating_class";
static const char MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY[] = "radius_srv_address";
static const char MESH_WISUN_RADIUS_SERVER_SECRET_KEY[] = "radius_srv_secret";
static const char MESH_WISUN_TRUSTED_CERTIFICATE_KEY[] = "mesh_wisun_trusted_certificate";
static const char MESH_WISUN_OWN_CERTIFICATE_KEY[] = "mesh_wisun_own_certificate";
static const char MESH_MAC_ADDRESS_KEY[] = "mesh_mac_address";
static const char ETHERNET_MAC_ADDRESS_KEY[] = "ethernet_mac_address";

nm_status_t nm_kcm_wisun_network_name_init(char **network_name_buf_ptr)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_NETWORK_NAME_KEY,
                                            sizeof(MESH_WISUN_NETWORK_NAME_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        // network name found from KCM
        *network_name_buf_ptr = (char *)nm_dyn_mem_alloc((kcm_item_buff_size * sizeof(char))+1);
        memset(*network_name_buf_ptr,'\0',kcm_item_buff_size + 1);
        strncpy(*network_name_buf_ptr, (char *)kcm_item_buffer,kcm_item_buff_size);
        free(kcm_item_buffer);
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_wisun_network_size_init(uint8_t *network_size)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_NETWORK_SIZE_KEY,
                                            sizeof(MESH_WISUN_NETWORK_SIZE_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        // network size as hundreds of devices
        *network_size = kcm_item_buffer[0];
        free(kcm_item_buffer);
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_mesh_mac_address_init(uint8_t **mesh_mac_address_ptr, size_t *mesh_mac_address_len)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_MAC_ADDRESS_KEY,
                                            sizeof(MESH_MAC_ADDRESS_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        //MAC address found from KCM
        *mesh_mac_address_ptr = kcm_item_buffer;
        *mesh_mac_address_len = kcm_item_buff_size;
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_ethernet_mac_address_init(uint8_t **eth_mac_address_ptr, size_t *eth_mac_address_len)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)ETHERNET_MAC_ADDRESS_KEY,
                                            sizeof(ETHERNET_MAC_ADDRESS_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *eth_mac_address_ptr = kcm_item_buffer;
        *eth_mac_address_len = kcm_item_buff_size;
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_wisun_network_regulatory_domain_init(uint8_t *regulatory_domain, uint8_t *operating_class, uint8_t *operating_mode)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    // Init REGULATORY DOMAIN
    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_REGULATORY_DOMAIN_KEY,
                                            sizeof(MESH_WISUN_REGULATORY_DOMAIN_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *regulatory_domain = kcm_item_buffer[0];
        free(kcm_item_buffer);
    } else {
        return NM_STATUS_FAIL;
    }

    // Init OPERATING MODE
    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_OPERATING_MODE_KEY,
                                            sizeof(MESH_WISUN_OPERATING_MODE_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *operating_mode = kcm_item_buffer[0];
        free(kcm_item_buffer);
    } else {
        return NM_STATUS_FAIL;
    }

    // Init OPERATING CLASS
    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_OPERATING_CLASS_KEY,
                                            sizeof(MESH_WISUN_OPERATING_CLASS_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *operating_class = kcm_item_buffer[0];
        free(kcm_item_buffer);
    } else {
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_kcm_wisun_network_radius_addr_init(char **srv_addr, size_t *srv_addr_len)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY,
                                            sizeof(MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *srv_addr = (char *)nm_dyn_mem_alloc((kcm_item_buff_size * sizeof(char))+1);
        memset(*srv_addr,'\0',kcm_item_buff_size + 1);
        strncpy(*srv_addr, (char *)kcm_item_buffer,kcm_item_buff_size);
        free(kcm_item_buffer);
        *srv_addr_len = kcm_item_buff_size;
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_wisun_network_radius_secret_init(uint8_t **srv_secret_buf, size_t *actual_secret_len)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_RADIUS_SERVER_SECRET_KEY,
                                            sizeof(MESH_WISUN_RADIUS_SERVER_SECRET_KEY) - 1,
                                            KCM_CONFIG_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *srv_secret_buf = kcm_item_buffer;
        *actual_secret_len = kcm_item_buff_size;
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_wisun_network_trusted_certificate_init(uint8_t **trusted_cert_buf, uint16_t *trusted_cert_len)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_TRUSTED_CERTIFICATE_KEY,
                                            sizeof(MESH_WISUN_TRUSTED_CERTIFICATE_KEY) - 1,
                                            KCM_CERTIFICATE_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *trusted_cert_buf = kcm_item_buffer;
        *trusted_cert_len = kcm_item_buff_size;
        return NM_STATUS_SUCCESS;
    }

    return NM_STATUS_FAIL;
}

nm_status_t nm_kcm_wisun_network_own_certificate_init(uint8_t **own_cert_buf, uint16_t *own_cert_len, uint8_t **own_cert_key, uint16_t *own_cert_key_len)
{
    kcm_status_e kcm_status = KCM_STATUS_ERROR;
    uint8_t *kcm_item_buffer = NULL;
    size_t kcm_item_buff_size = 0;

    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_OWN_CERTIFICATE_KEY,
                                            sizeof(MESH_WISUN_OWN_CERTIFICATE_KEY) - 1,
                                            KCM_CERTIFICATE_ITEM,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *own_cert_buf = kcm_item_buffer;
        *own_cert_len = kcm_item_buff_size;
    } else {
        return NM_STATUS_FAIL;
    }

    kcm_item_buffer = NULL;
    kcm_status = kcm_item_get_size_and_data((uint8_t *)MESH_WISUN_OWN_CERTIFICATE_KEY,
                                            sizeof(MESH_WISUN_OWN_CERTIFICATE_KEY) - 1,
                                            KCM_PRIVATE_KEY_ITEM ,
                                            &kcm_item_buffer,
                                            &kcm_item_buff_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *own_cert_key = kcm_item_buffer;
        *own_cert_key_len = kcm_item_buff_size;
    } else {
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

//#define NM_KCM_TEST_DATA
#ifdef NM_KCM_TEST_DATA
#include <string.h>

void nm_kcm_test_data_store(void)
{

    static bool initialized = false;

    if (initialized) {
        return;
    }
    initialized = true;

    kcm_status_e kcm_status;

    static const char mesh_kcm_network_name[] = "KCM-Network-name";
    static const uint8_t mesh_kcm_network_size = 2;
    static const uint8_t mesh_kcm_mac_addr[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    static const uint8_t eth_kcm_mac_addr[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    static const uint8_t mesh_kcm_regulatory_domain = 5; //india
    static const uint8_t mesh_kcm_operating_mode = 255;
    static const uint8_t mesh_kcm_operating_class = 1;
    static const char mesh_kcm_radius_srv_addr[] = "2001:14b8:1830:b000:1e69:7aff:fe03:dad7";
    static const char mesh_kcm_radius_srv_secret[] = "wisun_radius_password";

    tr_info("Set nm_kcm_network_name: %s", mesh_kcm_network_name);
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_NETWORK_NAME_KEY,
                                sizeof(MESH_WISUN_NETWORK_NAME_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)mesh_kcm_network_name,
                                sizeof(mesh_kcm_network_name),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_network_name");
    }

    tr_info("Set nm_kcm_network_size: %d", mesh_kcm_network_size);
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_NETWORK_SIZE_KEY,
                                sizeof(MESH_WISUN_NETWORK_SIZE_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)&mesh_kcm_network_size,
                                sizeof(mesh_kcm_network_size),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_network_size");
    }

    tr_info("Set nm_kcm_mesh_mac_address");
    kcm_status = kcm_item_store((uint8_t *)MESH_MAC_ADDRESS_KEY,
                                sizeof(MESH_MAC_ADDRESS_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)mesh_kcm_mac_addr,
                                sizeof(mesh_kcm_mac_addr),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_mesh_mac_address");
    }

    tr_info("Set nm_kcm_eth_mac_address");
    kcm_status = kcm_item_store((uint8_t *)ETHERNET_MAC_ADDRESS_KEY,
                                sizeof(ETHERNET_MAC_ADDRESS_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)eth_kcm_mac_addr,
                                sizeof(eth_kcm_mac_addr),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_eth_mac_address");
    }

    tr_info("Set nm_kcm_regulatory_domain: %d", mesh_kcm_regulatory_domain);
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_REGULATORY_DOMAIN_KEY,
                                sizeof(MESH_WISUN_REGULATORY_DOMAIN_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)&mesh_kcm_regulatory_domain,
                                sizeof(mesh_kcm_regulatory_domain),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_regulatory_domain");
    }

    tr_info("Set nm_kcm_operating_class: %d", mesh_kcm_operating_class);
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_OPERATING_CLASS_KEY,
                                sizeof(MESH_WISUN_OPERATING_CLASS_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)&mesh_kcm_operating_class,
                                sizeof(mesh_kcm_operating_class),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_operating_class");
    }

    tr_info("Set nm_kcm_operating_mode: %d", mesh_kcm_operating_mode);
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_OPERATING_MODE_KEY,
                                sizeof(MESH_WISUN_OPERATING_MODE_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)&mesh_kcm_operating_mode,
                                sizeof(mesh_kcm_operating_mode),
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_operating_mode");
    }


    tr_info("Set nm_kcm_radius_srv_addr: %s", mesh_kcm_radius_srv_addr);
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY,
                                sizeof(MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)mesh_kcm_radius_srv_addr,
                                strlen(mesh_kcm_radius_srv_addr) + 1,
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_radius_srv_addr");
    }

    tr_info("Set nm_kcm_radius_srv_secret: %s", tr_array((uint8_t *)mesh_kcm_radius_srv_secret, sizeof(mesh_kcm_radius_srv_secret) / sizeof(uint8_t)));
    kcm_status = kcm_item_store((uint8_t *)MESH_WISUN_RADIUS_SERVER_SECRET_KEY,
                                sizeof(MESH_WISUN_RADIUS_SERVER_SECRET_KEY) - 1,
                                KCM_CONFIG_ITEM,
                                true,
                                (uint8_t *)mesh_kcm_radius_srv_secret,
                                sizeof(mesh_kcm_radius_srv_secret) / sizeof(uint8_t) -1,
                                NULL);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("Failed to set nm_kcm_radius_srv_secret");
    }
}

void nm_kcm_test_data_delete(void)
{
    kcm_item_delete((uint8_t *)MESH_WISUN_NETWORK_NAME_KEY, strlen(MESH_WISUN_NETWORK_NAME_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_WISUN_NETWORK_SIZE_KEY, strlen(MESH_WISUN_NETWORK_SIZE_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)ETHERNET_MAC_ADDRESS_KEY, strlen(ETHERNET_MAC_ADDRESS_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_MAC_ADDRESS_KEY, strlen(MESH_MAC_ADDRESS_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_WISUN_REGULATORY_DOMAIN_KEY, strlen(MESH_WISUN_REGULATORY_DOMAIN_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_WISUN_OPERATING_CLASS_KEY, strlen(MESH_WISUN_OPERATING_CLASS_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_WISUN_OPERATING_MODE_KEY, strlen(MESH_WISUN_OPERATING_MODE_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY, strlen(MESH_WISUN_RADIUS_SERVER_ADDRESS_KEY), KCM_CONFIG_ITEM);
    kcm_item_delete((uint8_t *)MESH_WISUN_RADIUS_SERVER_SECRET_KEY, strlen(MESH_WISUN_RADIUS_SERVER_SECRET_KEY), KCM_CONFIG_ITEM);
    tr_info("NM KCM Test Factory Data Deleted");
}

#endif /* NM_KCM_TEST_DATA */
#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
