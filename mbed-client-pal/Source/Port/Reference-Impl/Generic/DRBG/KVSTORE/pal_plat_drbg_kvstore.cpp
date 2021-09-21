// ----------------------------------------------------------------------------
// Copyright 2020-2021 Pelion.
//
// SPDX-License-Identifier: Apache-2.0
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

#if defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) && !defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)

#if __MBED__
#include "mbed.h"
#endif

#include "pal.h"
#include "pal_plat_drbg.h"
#include "KVStore.h"
#include "KVMap.h"
#include "kv_config.h"
#include "storage_kcm.h"

#define TRACE_GROUP "PAL"

// This file is used by both Mbed OS and non-Mbed OS platforms and we need to be able to link MBED macros from
// two sources: Mbed OS and client-supplied kvstore.
// TODO: Move this code to factory client.
using namespace mbed;

palStatus_t storage_kvstore_read(const char *item_name, uint8_t *buffer, size_t buffer_size, size_t *buffer_actual_size_out)
{
    palStatus_t pal_status = PAL_ERR_SST_READ_FAILED;

    int status = kv_init_storage_config();
    if (status != MBED_SUCCESS) {
        tr_err("storage_kvstore_read() - init failed, status %d", status);
        return pal_status;
    }

    static KVStore *kvstore = NULL;

    KVMap &kv_map = KVMap::get_instance();
    kvstore = kv_map.get_internal_kv_instance(PAL_FS_MOUNT_POINT_PRIMARY);
    if (kvstore) {
        status = kvstore->get(item_name, buffer, buffer_size, buffer_actual_size_out, 0);
    } else {
        tr_err("storage_kvstore_read kvstore instance get failed");
    }
    if (status == MBED_SUCCESS) {
        pal_status = PAL_SUCCESS;
    } else if (status == MBED_ERROR_ITEM_NOT_FOUND) {
        pal_status = PAL_ERR_ITEM_NOT_EXIST;
    } else {
        tr_err("storage_kvstore_read failed with %d", status);
    }
    return pal_status;
}

palStatus_t storage_kvstore_write(const char *item_name, const uint8_t *buffer, size_t buffer_size)
{
    palStatus_t pal_status = PAL_ERR_SST_WRITE_FAILED;

    int status = kv_init_storage_config();
    if (status != MBED_SUCCESS) {
        tr_err("storage_kvstore_write() - init failed, status %d", status);
        return pal_status;
    }

    static uint32_t flag_mask = PAL_SST_REPLAY_PROTECTION_FLAG | PAL_SST_CONFIDENTIALITY_FLAG;
    static KVStore *kvstore = NULL;

    KVMap &kv_map = KVMap::get_instance();
    kvstore = kv_map.get_internal_kv_instance(PAL_FS_MOUNT_POINT_PRIMARY);
    if (kvstore) {
        status = kvstore->set(item_name, buffer, buffer_size, flag_mask);
    } else {
        tr_err("storage_kvstore_write kvstore instance get failed");
    }
    if (status == MBED_SUCCESS) {
        pal_status = PAL_SUCCESS;
    } else {
        tr_err("storage_kvstore_write failed with %d", status);
    }
    return pal_status;
}
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

