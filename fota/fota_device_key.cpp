// ----------------------------------------------------------------------------
// Copyright 2021 Pelion Ltd.
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

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE) && !defined(FOTA_UNIT_TEST)
#include <inttypes.h>
#include <stddef.h>
#include "fota_device_key.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_status.h"

#ifdef TARGET_LIKE_MBED
#include "mbed_error.h"
#endif

#if ((MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION == 2) && (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL == 1)) || \
    (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)

#if defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT)

#include "kv_config.h"
#include "KVMap.h"
#include "TDBStore.h"

using namespace mbed;

extern "C" int8_t fota_get_device_key_128bit(uint8_t *key, uint32_t keyLenBytes)
{
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);

    //Check key buffer
    if (key == NULL) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    //Check key buffer size
    if (keyLenBytes != FOTA_ENCRYPT_KEY_SIZE) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    //Check internal instance
    if (inner_store == NULL) {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    //Read ROT
    int ret = ((TDBStore *)inner_store)->reserved_data_get(key, keyLenBytes);
    if (ret == MBED_SUCCESS) {
        return FOTA_STATUS_SUCCESS;
    } else if (ret == MBED_ERROR_ITEM_NOT_FOUND) {
        return FOTA_STATUS_NOT_FOUND;
    } else {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

}

#else

#include "pal.h"

int8_t fota_get_device_key_128bit(uint8_t *key, uint32_t keyLenBytes)
{
    palStatus_t ret = pal_osGetDeviceKey(palOsStorageEncryptionKey128Bit, key, keyLenBytes);
    if (ret == PAL_SUCCESS) {
        return FOTA_STATUS_SUCCESS;
    } else if (ret == PAL_ERR_ITEM_NOT_EXIST) {
        return FOTA_STATUS_NOT_FOUND;
    } else {
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#endif
#endif //MBED_CLOUD_CLIENT_FOTA_ENABLE
