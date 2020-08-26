/*******************************************************************************
 * Copyright 2016-2018 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal.h"
#include "pal_plat_rot.h"
#include "KVMap.h"
#ifdef TARGET_LIKE_MBED
#include "mbed_error.h"
#endif
#include "TDBStore.h"
#include "DeviceKey.h"

#define MAX_DEVICE_KEY_SIZE_IN_BYTES DEVICE_KEY_32BYTE

using namespace mbed;
// If there is no "HW ROT", this code is enabled. It will in practice either use a pre-generated
// ROT in SOTP or generate it once on the fly.
#if (PAL_USE_HW_ROT == 0)


#define TRACE_GROUP "PAL"

palStatus_t pal_plat_osGetRoT(uint8_t * key, size_t keyLenBytes)
{
    int  error;
    KVMap &kv_map = KVMap::get_instance();
    KVStore *inner_store = kv_map.get_internal_kv_instance(NULL);

    //Check key buffer
    if (key == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    //Check key buffer size
    if (keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    //Check internal instance 
    if (inner_store == NULL) {
        return PAL_ERR_NULL_POINTER;
    }

    //Read ROT
    error = ((TDBStore *)inner_store)->reserved_data_get(key, keyLenBytes);
    if (error != MBED_SUCCESS) {
        if (error == MBED_ERROR_ITEM_NOT_FOUND) {
            return PAL_ERR_ITEM_NOT_EXIST;
        }
        return PAL_ERR_GENERIC_FAILURE;
    }

    return PAL_SUCCESS;
}
palStatus_t pal_plat_osSetRoT(uint8_t * key, size_t keyLenBytes)
{
    int  error;
    DeviceKey &devkey = DeviceKey::get_instance();

    //Check key buffer
    if (key == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }
    //Check key buffer size
    if (keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    //Set ROT
    error = devkey.device_inject_root_of_trust((uint32_t*)key, keyLenBytes);
    if (error != MBED_SUCCESS) {
        if (error == DEVICEKEY_ALREADY_EXIST) {
            return PAL_ERR_ITEM_EXIST;
        }
        return PAL_ERR_GENERIC_FAILURE;
    }

    return PAL_SUCCESS;
}
#endif // (PAL_USE_HW_ROT == 0)
#endif //#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
