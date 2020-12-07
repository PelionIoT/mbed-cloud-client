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

#if defined MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)

#include <stdio.h>
#include "mbed.h"
#include "mbed_trace.h"
#include "NetworkInterface.h"
#include "nm_cbor_helper.h"
#include "nm_kvstore_helper.h"
#include "WisunInterface.h"
#include "WisunBorderRouter.h"
#include "nm_interface_manager.h"
#include "nm_resource_manager.h"
#include "NetworkManager_internal.h"
#include "nm_dynmem_helper.h"

#define TRACE_GROUP "NMif"

#define WS_CONF_MAX_BUF WS_CONF_MAX_ENCODER_BUF
#define BR_CONF_MAX_BUF BR_CONF_MAX_ENCODER_BUF
#define WS_STAT_MAX_BUF WS_STAT_MAX_ENCODER_BUF
#define NM_STAT_MAX_BUF NM_STAT_MAX_ENCODER_BUF
#define BR_STAT_MAX_BUF BR_STAT_MAX_ENCODER_BUF
#define NI_STAT_MAX_BUF NI_STAT_MAX_ENCODER_BUF
#define RQ_STAT_MAX_BUF RQ_STAT_MAX_ENCODER_BUF

#define DEFAULT_CONFIG_DELAY 0

static SocketAddress sa;
static NetworkInterface *backhaul_interface = NULL;
static WisunInterface *ws_iface = NULL;
static WisunBorderRouter *ws_br;
static bool interface_connected = false;

static nm_status_t nm_iface_kvstore_read_cfg(char *key, void *struct_val, config_type_t type)
{
    size_t len = 0;
    nm_status_t status = NM_STATUS_FAIL;
    uint8_t *buf = NULL;

    if (get_lenght_from_KVstore(key, &len) == NM_STATUS_FAIL) {
        tr_warn("FAILED to get Length from KVStore for %s Key", key);
        return status;
    }

    buf = (uint8_t *)nm_dyn_mem_alloc(len);
    if (buf == NULL) {
        tr_error("FAILED to allocate memory to read data from KVStore");
        return status;
    }

    if (get_data_from_kvstore(key, buf, len) == NM_STATUS_FAIL) {
        tr_warn("Configuration not found in KVStore");
        nm_dyn_mem_free(buf);
        return status;
    } else {
        /* De-CBORise data and update structure */
        status = nm_cbor_config_struct_update(struct_val, buf, type, len);
        if (status != NM_STATUS_SUCCESS) {
            tr_info("Structure update fail");
            /*
             * To-Do: What will be the error handling should take..
             * do we have to load default values??
             */
        }
        nm_dyn_mem_free(buf);
    }
    return status;
}

void register_interfaces(NetworkInterface *mesh_iface, NetworkInterface *backhaul_iface, WisunBorderRouter *br_iface)
{
    backhaul_interface = backhaul_iface;
    ws_iface = reinterpret_cast<WisunInterface *>(mesh_iface);
    ws_br = br_iface;
}





/***************************Mesh Interface*******************************/

static nm_status_t ws_config_validation(nm_ws_config_t *existing_ws_config, nm_ws_config_t *updated_ws_config)
{
    mesh_error_t status = MESH_ERROR_UNKNOWN;

    if ((existing_ws_config == NULL) || (updated_ws_config == NULL)) {
        tr_debug("FAILED: Validate ws_config is NULL");
        return NM_STATUS_FAIL;
    }

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    tr_debug("Validating received ws_config");

    /* Validate network name */
    if (memcmp(existing_ws_config->network_name, updated_ws_config->network_name, sizeof(updated_ws_config->network_name)) != 0) {
        status = ws_iface->validate_network_name(updated_ws_config->network_name);
        tr_debug("Network Name: %s", updated_ws_config->network_name);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received network name is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate regulatory domain */
    if (memcmp((uint8_t *)&existing_ws_config->reg_op, (uint8_t *)&updated_ws_config->reg_op, sizeof(updated_ws_config->reg_op)) != 0) {
        status = ws_iface->validate_network_regulatory_domain(updated_ws_config->reg_op.regulatory_domain,
                                                              updated_ws_config->reg_op.operating_class, updated_ws_config->reg_op.operating_mode);
        tr_debug("Reg Domain: %d, Op Class: %d, Op Mode: %d", updated_ws_config->reg_op.regulatory_domain,
                 updated_ws_config->reg_op.operating_class, updated_ws_config->reg_op.operating_mode);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received regulatory_domain is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate network size */
    if (existing_ws_config->network_size != updated_ws_config->network_size) {
        status = ws_iface->validate_network_size(updated_ws_config->network_size);
        tr_debug("Network Size: %d", updated_ws_config->network_size);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received network_size is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate channel mask */
    if (memcmp((uint8_t *)existing_ws_config->channel_mask, (uint8_t *)updated_ws_config->channel_mask, sizeof(updated_ws_config->channel_mask)) != 0) {
        status = ws_iface->validate_channel_mask(updated_ws_config->channel_mask);
        for (int i = 0; i < 8; i++) {
            tr_debug("Channel_mask[i] = [%lu]", updated_ws_config->channel_mask[i]);
        }
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received channel_mask is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate unicast channel function */
    if (memcmp((uint8_t *)&existing_ws_config->uc_ch_config, (uint8_t *)&updated_ws_config->uc_ch_config, sizeof(updated_ws_config->uc_ch_config)) != 0) {
        status = ws_iface->validate_unicast_channel_function(updated_ws_config->uc_ch_config.uc_channel_function,
                                                             updated_ws_config->uc_ch_config.uc_fixed_channel, updated_ws_config->uc_ch_config.uc_dwell_interval);
        tr_debug("UC Ch Func: %d, UC Fixed Ch: %d, UC Dwell Interval: %d", updated_ws_config->uc_ch_config.uc_channel_function,
                 updated_ws_config->uc_ch_config.uc_fixed_channel, updated_ws_config->uc_ch_config.uc_dwell_interval);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received unicast_channel_function is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate broadcast channel function */
    if (memcmp((uint8_t *)&existing_ws_config->bc_ch_config, (uint8_t *)&updated_ws_config->bc_ch_config, sizeof(updated_ws_config->bc_ch_config)) != 0) {
        status = ws_iface->validate_broadcast_channel_function(updated_ws_config->bc_ch_config.bc_channel_function,
                                                               updated_ws_config->bc_ch_config.bc_fixed_channel, updated_ws_config->bc_ch_config.bc_dwell_interval,
                                                               updated_ws_config->bc_ch_config.bc_interval);
        tr_debug("BC Ch Func: %d, BC Fixed Ch: %d, BC Dwell Interval: %d, BC Interval = %lu", updated_ws_config->bc_ch_config.bc_channel_function,
                 updated_ws_config->bc_ch_config.bc_fixed_channel, updated_ws_config->bc_ch_config.bc_dwell_interval, updated_ws_config->bc_ch_config.bc_interval);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received broadcast_channel_function is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate timing parameters */
    if (memcmp((uint8_t *)&existing_ws_config->timing_param, (uint8_t *)&updated_ws_config->timing_param, sizeof(updated_ws_config->timing_param)) != 0) {
        status = ws_iface->validate_timing_parameters(updated_ws_config->timing_param.disc_trickle_imin,
                                                      updated_ws_config->timing_param.disc_trickle_imax, updated_ws_config->timing_param.disc_trickle_k,
                                                      updated_ws_config->timing_param.pan_timeout);
        tr_debug("Disc Trickle Imin: %d, Disc Trickle Imax: %d, Disc Trickle Const: %d, Pan Timeout: %d", updated_ws_config->timing_param.disc_trickle_imin,
                 updated_ws_config->timing_param.disc_trickle_imax, updated_ws_config->timing_param.disc_trickle_k, updated_ws_config->timing_param.pan_timeout);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received timing_parameters are not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validating device min sense parameter */
    if (interface_connected == true) {
        if (existing_ws_config->device_min_sens != updated_ws_config->device_min_sens) {
            status = ws_iface->validate_device_min_sens(updated_ws_config->device_min_sens);
            tr_debug("device_min_sens: %d", updated_ws_config->device_min_sens);
            if (status != MESH_ERROR_NONE) {
                tr_warn("FAILED: Received device min sense are not valid");
                return NM_STATUS_FAIL;
            }
        }
    }

    tr_debug("Validation complete of received ws_config");
    return NM_STATUS_SUCCESS;
}

static nm_status_t set_ws_config_to_nanostack(nm_ws_config_t *existing_ws_config, nm_ws_config_t *updated_ws_config)
{
    mesh_error_t status = MESH_ERROR_UNKNOWN;

    if ((existing_ws_config == NULL) || (updated_ws_config == NULL)) {
        tr_debug("FAILED: Set ws_config is NULL");
        return NM_STATUS_FAIL;
    }

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    /* Setting network name */
    if (memcmp(existing_ws_config->network_name, updated_ws_config->network_name, sizeof(updated_ws_config->network_name)) != 0) {
        status = ws_iface->set_network_name(updated_ws_config->network_name);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set network name to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET Network Name: %s", updated_ws_config->network_name);
    }

    /* Setting regulatory domain */
    if (memcmp((uint8_t *)&existing_ws_config->reg_op, (uint8_t *)&updated_ws_config->reg_op, sizeof(updated_ws_config->reg_op)) != 0) {
        status = ws_iface->set_network_regulatory_domain(updated_ws_config->reg_op.regulatory_domain,
                                                         updated_ws_config->reg_op.operating_class, updated_ws_config->reg_op.operating_mode);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set regulatory_domain to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET Reg Domain: %d, Op Class: %d, Op Mode: %d", updated_ws_config->reg_op.regulatory_domain,
                updated_ws_config->reg_op.operating_class, updated_ws_config->reg_op.operating_mode);
    }

    /* Setting network size */
    if (existing_ws_config->network_size != updated_ws_config->network_size) {
        status = ws_iface->set_network_size(updated_ws_config->network_size);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set network_size to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET Network Size: %d", updated_ws_config->network_size);
    }

    /* Setting channel mask */
    if (memcmp((uint8_t *)existing_ws_config->channel_mask, (uint8_t *)updated_ws_config->channel_mask, sizeof(updated_ws_config->channel_mask)) != 0) {
        status = ws_iface->set_channel_mask(updated_ws_config->channel_mask);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set channel_mask to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET Channel Mask");
    }

    /* Setting unicast channel function */
    if (memcmp((uint8_t *)&existing_ws_config->uc_ch_config, (uint8_t *)&updated_ws_config->uc_ch_config, sizeof(updated_ws_config->uc_ch_config)) != 0) {
        status = ws_iface->set_unicast_channel_function(updated_ws_config->uc_ch_config.uc_channel_function,
                                                        updated_ws_config->uc_ch_config.uc_fixed_channel, updated_ws_config->uc_ch_config.uc_dwell_interval);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set unicast_channel_function to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET UC Ch Func: %d, UC Fixed Ch: %d, UC Dwell Interval: %d", updated_ws_config->uc_ch_config.uc_channel_function,
                updated_ws_config->uc_ch_config.uc_fixed_channel, updated_ws_config->uc_ch_config.uc_dwell_interval);
    }

    /* Setting broadcast channel function */
    if (memcmp((uint8_t *)&existing_ws_config->bc_ch_config, (uint8_t *)&updated_ws_config->bc_ch_config, sizeof(updated_ws_config->bc_ch_config)) != 0) {
        status = ws_iface->set_broadcast_channel_function(updated_ws_config->bc_ch_config.bc_channel_function,
                                                          updated_ws_config->bc_ch_config.bc_fixed_channel, updated_ws_config->bc_ch_config.bc_dwell_interval,
                                                          updated_ws_config->bc_ch_config.bc_interval);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set broadcast_channel_function to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET BC Ch Func: %d, BC Fixed Ch: %d, BC Dwell Interval: %d, BC Interval = %lu", updated_ws_config->bc_ch_config.bc_channel_function,
                updated_ws_config->bc_ch_config.bc_fixed_channel, updated_ws_config->bc_ch_config.bc_dwell_interval, updated_ws_config->bc_ch_config.bc_interval);
    }

    /* Setting timing parameters */
    if (memcmp((uint8_t *)&existing_ws_config->timing_param, (uint8_t *)&updated_ws_config->timing_param, sizeof(updated_ws_config->timing_param)) != 0) {
        status = ws_iface->set_timing_parameters(updated_ws_config->timing_param.disc_trickle_imin,
                                                 updated_ws_config->timing_param.disc_trickle_imax, updated_ws_config->timing_param.disc_trickle_k,
                                                 updated_ws_config->timing_param.pan_timeout);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set timing_parameters to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET Disc Trickle Imin: %d, Disc Trickle Imax: %d, Disc Trickle Const: %d, Pan Timeout: %d", updated_ws_config->timing_param.disc_trickle_imin,
                updated_ws_config->timing_param.disc_trickle_imax, updated_ws_config->timing_param.disc_trickle_k, updated_ws_config->timing_param.pan_timeout);
    }

    /* Setting device min sense parameters */
    if (interface_connected == true) {
        if (existing_ws_config->device_min_sens != updated_ws_config->device_min_sens) {
            status = ws_iface->set_device_min_sens(updated_ws_config->device_min_sens);
            if (status != MESH_ERROR_NONE) {
                tr_warn("FAILED to set device min sense to Nanostack");
                return NM_STATUS_FAIL;
            }
            tr_info("SET Device min sense: %d", updated_ws_config->device_min_sens);
        }
    }

    updated_ws_config->resource_version = WS_RESOURCE_VERSION;
    tr_debug("WS_resource_version %lu", updated_ws_config->resource_version);
    return NM_STATUS_SUCCESS;
}

static nm_status_t get_default_ws_config_from_nanostack(nm_ws_config_t *ws_config)
{
    mesh_error_t status = MESH_ERROR_UNKNOWN;

    if ((ws_config == NULL) || (ws_iface == NULL)) {
        return NM_STATUS_FAIL;
    }

    status = ws_iface->get_network_name(ws_config->network_name);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get network name from Nanostack");
        return NM_STATUS_FAIL;
    }

    status = ws_iface->get_network_regulatory_domain(&ws_config->reg_op.regulatory_domain,
                                                     &ws_config->reg_op.operating_class, &ws_config->reg_op.operating_mode);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get regulatory_domain from Nanostack");
        return NM_STATUS_FAIL;
    }
    status = ws_iface->get_network_size(&ws_config->network_size);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get network_size from Nanostack");
        return NM_STATUS_FAIL;
    }
    status = ws_iface->get_channel_mask(ws_config->channel_mask);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get channel_mask from Nanostack");
        return NM_STATUS_FAIL;
    }
    status = ws_iface->get_unicast_channel_function(&ws_config->uc_ch_config.uc_channel_function,
                                                    &ws_config->uc_ch_config.uc_fixed_channel, &ws_config->uc_ch_config.uc_dwell_interval);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get unicast_channel_function from Nanostack");
        return NM_STATUS_FAIL;
    }
    status = ws_iface->get_broadcast_channel_function(&ws_config->bc_ch_config.bc_channel_function,
                                                      &ws_config->bc_ch_config.bc_fixed_channel, &ws_config->bc_ch_config.bc_dwell_interval,
                                                      &ws_config->bc_ch_config.bc_interval);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get broadcast_channel_function from Nanostack");
        return NM_STATUS_FAIL;
    }
    status = ws_iface->get_timing_parameters(&ws_config->timing_param.disc_trickle_imin,
                                             &ws_config->timing_param.disc_trickle_imax, &ws_config->timing_param.disc_trickle_k,
                                             &ws_config->timing_param.pan_timeout);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get timing_parameters from Nanostack");
        return NM_STATUS_FAIL;
    }
    if (interface_connected == true) {
        status = ws_iface->get_device_min_sens(&ws_config->device_min_sens);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to get device min sense from Nanostack [MESH_ERROR_PARAM]");
            return NM_STATUS_FAIL;
        }
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_configure_mesh_iface(void)
{
    nm_ws_config_t default_ws_config = {0};
    nm_ws_config_t modified_ws_config = {0};
    uint8_t *cborise_data = NULL;
    size_t cborise_data_len = 0;


    if (get_default_ws_config_from_nanostack(&default_ws_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read deafult Wi-SUN config from Nanostack");
        return NM_STATUS_FAIL;
    }

    /* Copy the default configuration to another local structure */
    memcpy((uint8_t *)&modified_ws_config, (uint8_t *)&default_ws_config, sizeof(nm_ws_config_t));

    /*
     * No need to check return value of nm_iface_kvstore_read_cfg API.
     * If it returns Success, modified_ws_config structure is modified with KVStore value.
     * If it returns Failure, modified_ws_config structure retains the default values from Nanostack.
     */
    nm_iface_kvstore_read_cfg(kv_key_ws, &modified_ws_config, WS);

    if (set_ws_config_to_nanostack(&default_ws_config, &modified_ws_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to set Wi-SUN config to Nanostack");
        return NM_STATUS_FAIL;
    }

    cborise_data = (uint8_t *)nm_dyn_mem_alloc(WS_CONF_MAX_BUF);
    if (cborise_data == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_config_to_cbor(&modified_ws_config, cborise_data, WS, &cborise_data_len) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise updated Wi-SUN Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    if (set_data_to_kvstore(kv_key_ws, cborise_data, cborise_data_len) == NM_STATUS_FAIL) {
        tr_error("FAILED to store updated CBORised Wi-SUN Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    /* Free dynamically allocated memory */
    nm_dyn_mem_free(cborise_data);

    /* Enable Statistics */
    ws_iface->enable_statistics();

    tr_info("Mesh Interface Configured with Latest Configuration");

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_set_ws_config(uint8_t *data, size_t length)
{
    nm_ws_config_t kvstored_ws_config = {0};
    nm_ws_config_t received_ws_config = {0};
    uint8_t *cborise_data = NULL;
    size_t cborise_data_len = 0;

    if (data == NULL) {
        return NM_STATUS_FAIL;
    }

    if (nm_iface_kvstore_read_cfg(kv_key_ws, &kvstored_ws_config, WS) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read Wi-SUN Configuration from KVStore");
        return NM_STATUS_FAIL;
    }

    /* Copy the existing configuration to another local structure */
    memcpy((uint8_t *)&received_ws_config, (uint8_t *)&kvstored_ws_config, sizeof(nm_ws_config_t));

    received_ws_config.delay = DEFAULT_CONFIG_DELAY;

    /* Update the received_ws_config structure with received configuration leaving the other configuration unchanged */
    if (nm_cbor_config_struct_update(&received_ws_config, data, WS, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to De-CBORise received Wi-SUN Configuration");
        return NM_STATUS_FAIL;
    }

    /* Validate ws_config parameters */
    if (ws_config_validation(&kvstored_ws_config, &received_ws_config) == NM_STATUS_FAIL) {
        tr_err("FAILED: Validation of received ws_config data");
        return NM_STATUS_FAIL;
    }

    cborise_data = (uint8_t *)nm_dyn_mem_alloc(WS_CONF_MAX_BUF);
    if (cborise_data == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_config_to_cbor(&received_ws_config, cborise_data, WS, &cborise_data_len) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise updated Wi-SUN Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    if (set_data_to_kvstore(kv_key_ws, cborise_data, cborise_data_len) == NM_STATUS_FAIL) {
        tr_error("FAILED to store updated CBORised Wi-SUN Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    /* Free dynamically allocated memory */
    nm_dyn_mem_free(cborise_data);

    /* If delay value is present then apply parameters after delay else apply immediately */
    if (received_ws_config.delay != 0) {
        apply_ws_config_after_delay(received_ws_config.delay);
    } else {
        if (set_ws_config_to_nanostack(&kvstored_ws_config, &received_ws_config) == NM_STATUS_FAIL) {
            tr_warn("FAILED to set Wi-SUN config to Nanostack");
            return NM_STATUS_FAIL;
        }
    }
    return NM_STATUS_SUCCESS;
}

void apply_ws_config_to_nannostack(void)
{
    nm_ws_config_t kvstore_ws_config = {0};
    nm_ws_config_t existing_ws_config = {0};

    if (nm_iface_kvstore_read_cfg(kv_key_ws, &kvstore_ws_config, WS) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read Wi-SUN Configuration from KVStore");
        return;
    }

    if (get_default_ws_config_from_nanostack(&existing_ws_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read existing Wi-SUN config from Nanostack");
        return ;
    }

    if (set_ws_config_to_nanostack(&existing_ws_config, &kvstore_ws_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to set Wi-SUN config to Nanostack");
        return;
    }
    tr_info("ws_config set to nanostack");
}

void apply_ws_config_after_delay(uint16_t delay)
{
    tr_debug("starting ws_timer for %d seconds delay", delay);
    nm_post_timeout_event(NM_EVENT_APPLY_WS_CONFIG_AFTER_DELAY, delay * 1000);
}

void mesh_interface_connected(void)
{
    interface_connected = true;
}

nm_status_t nm_res_get_ws_stats(uint8_t **datap, size_t *length)
{
    nm_ws_common_info_t ws_stats = {0};
    mesh_nw_statistics_t ws_stats_temp = {0};
    ws_rpl_info_t rpl_stats_temp = {0};
    ws_stack_state_t stack_state_info = {0};

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->read_nw_statistics(&ws_stats_temp) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN network statistics from Nanostack");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->info_get(&rpl_stats_temp) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN Border Router information");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->stack_info_get(&stack_state_info) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN network stack state info from Nanostack");
        return NM_STATUS_FAIL;
    }

    ws_stats.ws_rpl_statistics.rpl_total_memory = ws_stats_temp.rpl_total_memory;
    ws_stats.ws_mac_statistics.asynch_rx_count = ws_stats_temp.asynch_rx_count;
    ws_stats.ws_mac_statistics.asynch_tx_count = ws_stats_temp.asynch_tx_count;

    memcpy(ws_stats.ws_common_id_statistics.rpl_dodag_id, rpl_stats_temp.rpl_dodag_id, sizeof(rpl_stats_temp.rpl_dodag_id));
    ws_stats.ws_common_id_statistics.instance_id = rpl_stats_temp.instance_id;
    ws_stats.ws_common_id_statistics.version = rpl_stats_temp.version;

    memcpy(ws_stats.ws_common_id_statistics.global_addr, stack_state_info.global_addr, sizeof(stack_state_info.global_addr));
    memcpy(ws_stats.ws_common_id_statistics.link_local_addr, stack_state_info.link_local_addr, sizeof(stack_state_info.link_local_addr));

    *datap = (uint8_t *)nm_dyn_mem_alloc(WS_STAT_MAX_BUF);
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&ws_stats, *datap, WS, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise Wi-SUN Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_get_nm_stats(uint8_t **datap, size_t *length)
{
    nm_general_nw_statistics_t nm_stats = {0};

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->read_mac_statistics(&nm_stats.mesh_mac_statistics) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN MAC statistics from Nanostack");
        return NM_STATUS_FAIL;
    }

    *datap = (uint8_t *)nm_dyn_mem_alloc(NM_STAT_MAX_BUF);
    if (*datap == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&nm_stats, *datap, NM, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise General Network Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_get_node_stats(uint8_t **datap, size_t *length)
{
    /* Need to implement information get here from nanostack */

    ws_rpl_info_t rpl_stats_temp = {0};
    nm_node_info_t node_info = {0};
    ws_stack_state_t stack_state_info = {0};
    mesh_nw_statistics_t ws_stats_temp = {0};

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->info_get(&rpl_stats_temp) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN rpl information");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->stack_info_get(&stack_state_info) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN network stack state info from Nanostack");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->read_nw_statistics(&ws_stats_temp) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN network statistics from Nanostack");
        return NM_STATUS_FAIL;
    }

    node_info.routing_info.curent_rank = rpl_stats_temp.current_rank;
    node_info.routing_info.primary_parent_rank = rpl_stats_temp.primary_parent_rank;

    memcpy(node_info.routing_info.primary_parent, stack_state_info.parent_addr, sizeof(stack_state_info.parent_addr));
    node_info.routing_info.etx_1st_parent = ws_stats_temp.etx_1st_parent;
    node_info.routing_info.etx_2nd_parent = ws_stats_temp.etx_2nd_parent;

    *datap = (uint8_t *)nm_dyn_mem_alloc(NI_STAT_MAX_BUF);
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&node_info, *datap, NI, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise Wi-SUN Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_get_radio_stats(uint8_t **datap, size_t *length)
{
    /*need to implement get radio quality information here */
    ws_stack_state_t stack_state_info = {0};
    nm_radio_quality_t radio_quality = {0};

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->stack_info_get(&stack_state_info) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN network stack state info from Nanostack");
        return NM_STATUS_FAIL;
    }

    radio_quality.rssi_in = stack_state_info.rsl_in;
    radio_quality.rssi_out = stack_state_info.rsl_out;

    *datap = (uint8_t *)nm_dyn_mem_alloc(NI_STAT_MAX_BUF);
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&radio_quality, *datap, RQ, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise Wi-SUN Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_get_ch_noise_stats(uint8_t **datap, size_t *length)
{
    ws_cca_threshold_table_t channel_noise;

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    if (ws_iface->cca_threshold_table_get(&channel_noise) != MESH_ERROR_NONE) {
        tr_warn("FAILED: Read Wi-SUN threshold table from Nanostack");
        return NM_STATUS_FAIL;
    }

    *datap = (uint8_t *)nm_dyn_mem_alloc(CH_NOISE_TABLE_MAX_ENCODING_BUFF(channel_noise.number_of_channels));
    if (*datap == NULL) {
        return NM_STATUS_FAIL;
    }

    if (nm_ch_noise_statistics_to_cbor((int8_t *)channel_noise.cca_threshold_table, channel_noise.number_of_channels, *datap, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise Wi-SUN Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}
/************************************************************************/










/****************************BR Interface********************************/

static nm_status_t br_config_validation(nm_br_config_t *existing_br_config, nm_br_config_t *updated_br_config)
{
    mesh_error_t status = MESH_ERROR_UNKNOWN;

    if ((existing_br_config == NULL) || (updated_br_config == NULL)) {
        tr_debug("FAILED: Validate br_config is NULL");
        return NM_STATUS_FAIL;
    }

    if (ws_iface == NULL) {
        tr_warn("FAILED: Wi-SUN Interface is not initialized yet");
        return NM_STATUS_FAIL;
    }

    tr_debug("Validating received br_configuration");

    /* Validate rpl parameters */
    if (memcmp((uint8_t *)&existing_br_config->rpl_config, (uint8_t *)&updated_br_config->rpl_config, sizeof(updated_br_config->rpl_config)) != 0) {
        status = ws_br->validate_rpl_parameters(updated_br_config->rpl_config.dio_interval_min,
                                                updated_br_config->rpl_config.dio_interval_doublings, updated_br_config->rpl_config.dio_redundancy_constant);
        tr_debug("DIO Interval min: %d, DIO Interval Doublings: %d, DIO Redundancy Const: %d", updated_br_config->rpl_config.dio_interval_min,
                 updated_br_config->rpl_config.dio_interval_doublings, updated_br_config->rpl_config.dio_redundancy_constant);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received rpl_parameters are not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Validate pan id*/
    if (existing_br_config->pan_id != updated_br_config->pan_id) {
        status = ws_br->validate_pan_configuration(updated_br_config->pan_id);
        tr_debug("PAN ID: %d", updated_br_config->pan_id);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED: Received pan_configuration is not valid");
            return NM_STATUS_FAIL;
        }
    }

    /* Update for delay parameter here */
    tr_debug("Validation complete of received br_configuration");
    return NM_STATUS_SUCCESS;
}

static nm_status_t set_br_config_to_nanostack(nm_br_config_t *existing_br_config, nm_br_config_t *updated_br_config)
{
    mesh_error_t status = MESH_ERROR_UNKNOWN;

    if ((existing_br_config == NULL) || (updated_br_config == NULL)) {
        tr_debug("FAILED: Set br_config is NULL");
        return NM_STATUS_FAIL;
    }

    /* Setting rpl parameters */
    if (memcmp((uint8_t *)&existing_br_config->rpl_config, (uint8_t *)&updated_br_config->rpl_config, sizeof(updated_br_config->rpl_config)) != 0) {
        status = ws_br->set_rpl_parameters(updated_br_config->rpl_config.dio_interval_min,
                                           updated_br_config->rpl_config.dio_interval_doublings, updated_br_config->rpl_config.dio_redundancy_constant);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set rpl_parameters to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET DIO Interval min: %d, DIO Interval Doublings: %d, DIO Redundancy Const: %d", updated_br_config->rpl_config.dio_interval_min,
                updated_br_config->rpl_config.dio_interval_doublings, updated_br_config->rpl_config.dio_redundancy_constant);
    }

    /* Setting pan id */
    if (existing_br_config->pan_id != updated_br_config->pan_id) {
        status = ws_br->set_pan_configuration(updated_br_config->pan_id);
        if (status != MESH_ERROR_NONE) {
            tr_warn("FAILED to set pan_configuration to Nanostack");
            return NM_STATUS_FAIL;
        }
        tr_info("SET PAN ID: %d", updated_br_config->pan_id);
    }

    updated_br_config->resource_version = WS_BR_RESOURCE_VERSION;
    tr_debug("BR_resource_version %lu", updated_br_config->resource_version);
    return NM_STATUS_SUCCESS;
}

static nm_status_t get_default_br_config_from_nanostack(nm_br_config_t *br_config)
{
    mesh_error_t status = MESH_ERROR_UNKNOWN;

    if (br_config == NULL) {
        return NM_STATUS_FAIL;
    }

    status = ws_br->get_rpl_parameters(&br_config->rpl_config.dio_interval_min,
                                       &br_config->rpl_config.dio_interval_doublings, &br_config->rpl_config.dio_redundancy_constant);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get rpl_parameters from Nanostack");
        return NM_STATUS_FAIL;
    }
    status = ws_br->get_pan_configuration(&br_config->pan_id);
    if (status != MESH_ERROR_NONE) {
        tr_warn("FAILED to get pan_configuration from Nanostack");
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_configure_border_router(void)
{
    nm_br_config_t default_br_config = {0};
    nm_br_config_t modified_br_config = {0};
    uint8_t *cborise_data = NULL;
    size_t cborise_data_len = 0;


    if (get_default_br_config_from_nanostack(&default_br_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read deafult Border Router config from Nanostack");
        return NM_STATUS_FAIL;
    }

    /* Copy the default configuration to another local structure */
    memcpy((uint8_t *)&modified_br_config, (uint8_t *)&default_br_config, sizeof(nm_br_config_t));

    /*
     * No need to check return value of nm_iface_kvstore_read_cfg API.
     * If it returns Success, modified_br_config structure is modified with KVStore value.
     * If it returns Failure, modified_br_config structure retains the default values from Nanostack.
     */
    nm_iface_kvstore_read_cfg(kv_key_br, &modified_br_config, BR);

    if (set_br_config_to_nanostack(&default_br_config, &modified_br_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to set Border Router config to Nanostack");
        return NM_STATUS_FAIL;
    }

    cborise_data = (uint8_t *)nm_dyn_mem_alloc(BR_CONF_MAX_BUF);
    if (cborise_data == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_config_to_cbor(&modified_br_config, cborise_data, BR, &cborise_data_len) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise updated Border Router Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    if (set_data_to_kvstore(kv_key_br, cborise_data, cborise_data_len) == NM_STATUS_FAIL) {
        tr_error("FAILED to store updated CBORised Border Router Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    /* Free dynamically allocated memory */
    nm_dyn_mem_free(cborise_data);

    tr_info("Border Router Configured with Latest Configuration");

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_set_br_config(uint8_t *data, size_t length)
{
    nm_br_config_t kvstored_br_config = {0};
    nm_br_config_t received_br_config = {0};
    uint8_t *cborise_data = NULL;
    size_t cborise_data_len = 0;

    if (data == NULL) {
        return NM_STATUS_FAIL;
    }

    if (nm_iface_kvstore_read_cfg(kv_key_br, &kvstored_br_config, BR) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read BR Configuration from KVStore");
        return NM_STATUS_FAIL;
    }

    /* Copy the existing configuration to another local structure */
    memcpy((uint8_t *)&received_br_config, (uint8_t *)&kvstored_br_config, sizeof(nm_br_config_t));

    received_br_config.delay = DEFAULT_CONFIG_DELAY;

    /* Update the received_br_config structure with received configuration leaving the other configuration unchanged */
    if (nm_cbor_config_struct_update(&received_br_config, data, BR, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to De-CBORise received BR Configuration");
        return NM_STATUS_FAIL;
    }

    /* Validate br_config parameters */
    if (br_config_validation(&kvstored_br_config, &received_br_config) == NM_STATUS_FAIL) {
        tr_err("FAILED: Validation of received br_config data");
        return NM_STATUS_FAIL;
    }

    cborise_data = (uint8_t *)nm_dyn_mem_alloc(BR_CONF_MAX_BUF);
    if (cborise_data == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_config_to_cbor(&received_br_config, cborise_data, BR, &cborise_data_len) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise updated BR Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    if (set_data_to_kvstore(kv_key_br, cborise_data, cborise_data_len) == NM_STATUS_FAIL) {
        tr_error("FAILED to store updated CBORised BR Configuration");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(cborise_data);
        return NM_STATUS_FAIL;
    }
    /* Free dynamically allocated memory */
    nm_dyn_mem_free(cborise_data);

    /* If delay value is present then apply parameters after delay else apply immediately */
    if (received_br_config.delay != 0) {
        apply_br_config_after_delay(received_br_config.delay);
    } else {
        if (set_br_config_to_nanostack(&kvstored_br_config, &received_br_config) == NM_STATUS_FAIL) {
            tr_warn("FAILED to set Wi-SUN br_config to Nanostack");
            return NM_STATUS_FAIL;
        }
    }
    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_get_br_stats(uint8_t **datap, size_t *length)
{
    nm_ws_br_info_t br_stats = {0};
    ws_br_info_t br_stats_temp = {0};

    if (ws_br->info_get(&br_stats_temp) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN Border Router information");
        return NM_STATUS_FAIL;
    }

    br_stats.device_count = br_stats_temp.device_count;
    br_stats.host_time = br_stats_temp.host_timestamp;

    if ((backhaul_interface != NULL) && backhaul_interface->get_ip_address(&sa) == 0) {
        memcpy(br_stats.global_addr_northbound, (uint8_t *)sa.get_ip_bytes(), sizeof(br_stats.global_addr_northbound));
    } else {
        tr_warn("FAILED to get get IP address");
    }

    memcpy(br_stats.local_addr_northbound, br_stats_temp.gateway_addr, sizeof(br_stats.local_addr_northbound));

    *datap = (uint8_t *)nm_dyn_mem_alloc(BR_STAT_MAX_BUF);
    if (*datap == NULL) {
        tr_error("FAILED to allocate memory for Cborise data");
        return NM_STATUS_FAIL;
    }

    if (nm_statistics_to_cbor(&br_stats, *datap, BR, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise Border Router Statistics");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }

    return NM_STATUS_SUCCESS;
}

nm_status_t nm_res_get_routing_table(uint8_t **datap, size_t *length)
{
    ws_br_info_t br_info = {0};
    ws_br_route_info_t *route_info = NULL;
    size_t routing_table_length = 0;
    size_t required_length = 0;
    int dev_count = -1;

    if (ws_br->info_get(&br_info) != MESH_ERROR_NONE) {
        tr_warn("FAILED to read Wi-SUN Border Router Information from Nanostack");
        return NM_STATUS_FAIL;
    }

    if (br_info.device_count == 0) {
        routing_table_length = 1; /* 1 Byte means empty routing table */
    } else {
        routing_table_length = br_info.device_count * sizeof(ws_br_route_info_t);
    }

    required_length = routing_table_length + ROUTING_TABLE_CBOR_OVERHEAD;
    tr_info("Allocating New buffer of Size %d bytes for routing table", required_length);
    *datap = (uint8_t *)nm_dyn_mem_alloc(required_length);
    if (*datap == NULL) {
        tr_error("FAILED to allocate memory for Cborise Route Info");
        return NM_STATUS_FAIL;
    }

    route_info = (ws_br_route_info_t *)(*datap + ROUTING_TABLE_CBOR_OVERHEAD);
    if (br_info.device_count > 0) {
        dev_count = ws_br->routing_table_get(route_info, br_info.device_count);
        if (dev_count <= 0) {
            tr_warn("FAILED reading Routing Table from Nanostack");
            nm_dyn_mem_free(*datap);
            return NM_STATUS_FAIL;
        }
        tr_info("Joined device count = %d", dev_count);
    } else {
        *(uint8_t *)route_info = 0x00; /* Routing table with 1 byte of value 0 means empty table */
        tr_info("Sending EMPTY Routing Table");
    }

    if (nm_routing_table_to_cbor((uint8_t *)route_info, routing_table_length, *datap, length) == NM_STATUS_FAIL) {
        tr_warn("FAILED to CBORise Routing Table");
        /* Free dynamically allocated memory */
        nm_dyn_mem_free(*datap);
        return NM_STATUS_FAIL;
    }
    return NM_STATUS_SUCCESS;
}

void apply_br_config_to_nannostack(void)
{
    nm_br_config_t kvstore_br_config = {0};
    nm_br_config_t existing_br_config = {0};

    if (nm_iface_kvstore_read_cfg(kv_key_br, &kvstore_br_config, BR) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read Wi-SUN br_config from KVStore");
        return;
    }

    if (get_default_br_config_from_nanostack(&existing_br_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to read deafult Border Router config from Nanostack");
        return;
    }

    if (set_br_config_to_nanostack(&existing_br_config, &kvstore_br_config) == NM_STATUS_FAIL) {
        tr_warn("FAILED to set Wi-SUN br_config to Nanostack");
        return;
    }
    tr_info("br_config set to nanostack");
}

void apply_br_config_after_delay(uint16_t delay)
{
    tr_debug("starting br_timer for %d seconds delay", delay);
    nm_post_timeout_event(NM_EVENT_APPLY_BR_CONFIG_AFTER_DELAY, delay * 1000);
}
/************************************************************************/

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
