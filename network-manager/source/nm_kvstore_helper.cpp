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

#include "mbed.h"
#include <stdio.h>
#include <string.h>
#include "NetworkManager_internal.h"
#include "nm_kvstore_helper.h"
#include "kvstore_global_api.h"
#include "mbed-trace/mbed_trace.h"             // Required for mbed_trace_*

#define TRACE_GROUP "NMkv"

#define err_code(ret) MBED_GET_ERROR_CODE(ret)

char kv_key_app[KV_KEY_LENGTH] = {"/kv/app_key"};
char kv_key_bb[KV_KEY_LENGTH] = {"/kv/bb_key"};
char kv_key_ws[KV_KEY_LENGTH] = {"/kv/ws_key"};
char kv_key_br[KV_KEY_LENGTH] = {"/kv/br_key"};

/*
 * Get length of data for respective key.
 */
nm_status_t get_lenght_from_KVstore(char *key, size_t *len)
{
    /* key information container */
    kv_info_t info;

    int ret = MBED_ERROR_NOT_READY;
    /* Read the KV Pair */
    tr_debug("kv_get_info of key\n");
    ret = kv_get_info(key, &info);
    if (ret == MBED_ERROR_ITEM_NOT_FOUND) {
        tr_debug("key not found,fetch default configuration");
        return NM_STATUS_FAIL;
    }
    tr_debug("kv_get_info key: %s\n info - size: %u, flags: %lu\n", key, info.size, info.flags);
    *len = info.size;
    return NM_STATUS_SUCCESS;
}

/*
 * This api is for to read different interface configuration from KVStore
 */
nm_status_t get_data_from_kvstore(char *key, uint8_t *value, size_t len)
{
    int ret = MBED_ERROR_NOT_READY;
    size_t actual_size = 0;
    ret = kv_get(key, value, len, &actual_size);
    tr_debug("kv_get -> %d\n key: %s\n", err_code(ret), key);
    if (ret == MBED_SUCCESS) {
        return NM_STATUS_SUCCESS;
    }
    return NM_STATUS_FAIL;
}

nm_status_t set_data_to_kvstore(char *key, void *value, int len)
{
    int res = MBED_ERROR_NOT_READY;
    /* Set Key/Value pair with unprotected clear value data */
    tr_debug("set data in KVStore using key: %s\n", key);
    res = kv_set(key, value, len, 0);
    tr_debug("kv_set -> %d\n", err_code(res));
    if (res == MBED_SUCCESS) {
        return NM_STATUS_SUCCESS;
    }
    return NM_STATUS_FAIL;
}

#endif    //MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER && (MBED_CONF_MBED_CLOUD_CLIENT_NETWORK_MANAGER == 1)
