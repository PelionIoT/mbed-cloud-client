// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pv_error_handling.h"
#include "pal_sst.h"
#include "kvstore_global_api.h"
#ifdef TARGET_LIKE_MBED
#include "mbed.h"
#if MBED_MAJOR_VERSION > 5
#include "DeviceKey.h"
#endif
#endif
#include "pv_macros.h"

#define EXPANSION_STR(x) STR(x) //stringification of macro value
#define STR(x) #x //stringification of the macro
#define PAL_SST_KV_PREFIX "/" EXPANSION_STR(MBED_CONF_STORAGE_DEFAULT_KV) "/"

#define TRACE_GROUP "SST"

#ifndef TARGET_LIKE_MBED
enum mbed_errors {
    MBED_SUCCESS,
    MBED_ERROR_READ_FAILED,
    MBED_ERROR_WRITE_FAILED,
    MBED_ERROR_INVALID_DATA_DETECTED,
    MBED_ERROR_ITEM_NOT_FOUND,
    MBED_ERROR_INVALID_ARGUMENT,
    MBED_ERROR_NOT_READY,
    MBED_ERROR_INVALID_SIZE,
    MBED_ERROR_OUT_OF_RESOURCES,
    MBED_ERROR_MEDIA_FULL,
    MBED_ERROR_WRITE_PROTECTED,
    MBED_ERROR_FAILED_OPERATION,
    MBED_ERROR_RBP_AUTHENTICATION_FAILED,
    MBED_ERROR_AUTHENTICATION_FAILED,
};
#endif

#if MBED_MAJOR_VERSION > 5
    // flag to save checking key existence
    static bool g_is_device_rot_exist = false;
#endif

static kcm_status_e pal_sst_translate_error(int kv_status)
{

    kcm_status_e kcm_status;

    switch (kv_status) {
        case MBED_SUCCESS:
            kcm_status = KCM_STATUS_SUCCESS;
            break;
        case MBED_ERROR_ITEM_NOT_FOUND:
            kcm_status = KCM_STATUS_ITEM_NOT_FOUND;
            break;
        case MBED_ERROR_INVALID_SIZE:
        case MBED_ERROR_NOT_READY:
        case MBED_ERROR_WRITE_FAILED:
        case MBED_ERROR_READ_FAILED:
        case MBED_ERROR_INVALID_DATA_DETECTED:
        case MBED_ERROR_FAILED_OPERATION:
        case MBED_ERROR_RBP_AUTHENTICATION_FAILED:
        case MBED_ERROR_AUTHENTICATION_FAILED:
            kcm_status = KCM_STATUS_STORAGE_ERROR;
            break;
        case MBED_ERROR_WRITE_PROTECTED:
            kcm_status = KCM_STATUS_FILE_EXIST;
            break;
        case MBED_ERROR_INVALID_ARGUMENT:
            kcm_status = KCM_STATUS_INVALID_PARAMETER;
            break;
        case MBED_ERROR_MEDIA_FULL:
            kcm_status = KCM_STATUS_OUT_OF_MEMORY;
            break;
        default:
            kcm_status = KCM_STATUS_UNKNOWN_STORAGE_ERROR;
    }

    if (kcm_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_INFO("kv_status: %" PRId16", kcm_status: %u ", kv_status, kcm_status);
    }

    return kcm_status;
}


static kcm_status_e storage_sst_build_complete_name(const char* item_name, char* complete_item_name)
{

    SA_PV_ERR_RECOVERABLE_RETURN_IF(((NULL == item_name) || (NULL == complete_item_name)), KCM_STATUS_INVALID_PARAMETER, "Invalid item name");

    size_t item_name_length = strlen(item_name);
    size_t prefix_length = strlen(PAL_SST_KV_PREFIX);
    size_t total_length = prefix_length + item_name_length;
    if (total_length > KV_MAX_KEY_LENGTH) {
        return KCM_STATUS_FILE_NAME_TOO_LONG;
    }

    //copy prefix
    memcpy(complete_item_name, PAL_SST_KV_PREFIX, prefix_length);

    //copy item name to the new buffer
    memcpy(complete_item_name + prefix_length, item_name, item_name_length);

    //null terminate
    complete_item_name[total_length] = '\0';

    return KCM_STATUS_SUCCESS;
}

kcm_status_e pal_SSTSet(const char *itemName, const void *itemBuffer, size_t itemBufferSize, uint32_t SSTFlagsBitmap)
{
    int kv_status = MBED_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint32_t kv_flags = 0;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //these bitmask is for unused bits in SSTFlagsBitmap.
    //only PAL_SST_WRITE_ONCE_FLAG, PAL_SST_CONFIDENTIALITY_FLAG and PAL_SST_REPLAY_PROTECTION_FLAG used
    uint32_t sst_flag_unused_bits_mask = ~(PAL_SST_WRITE_ONCE_FLAG | PAL_SST_CONFIDENTIALITY_FLAG | PAL_SST_REPLAY_PROTECTION_FLAG);

    PV_UNUSED_PARAM(sst_flag_unused_bits_mask);

    //arguments validation
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((SSTFlagsBitmap & sst_flag_unused_bits_mask) != 0 ), KCM_STATUS_INVALID_PARAMETER, "Invalid flag");

    //allocate buffer for itemName + prefix and copy prefix to the new buffer
    kcm_status = storage_sst_build_complete_name(itemName, sst_complete_item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status , "storage_sst_build_complete_name failed");

    //translate palSSTFlags to kv flags
    if (SSTFlagsBitmap & PAL_SST_WRITE_ONCE_FLAG) {
        kv_flags |= KV_WRITE_ONCE_FLAG;
    }
    if (SSTFlagsBitmap & PAL_SST_CONFIDENTIALITY_FLAG) {
        kv_flags |= KV_REQUIRE_CONFIDENTIALITY_FLAG;
    }
    if (SSTFlagsBitmap & PAL_SST_REPLAY_PROTECTION_FLAG) {
        kv_flags |= KV_REQUIRE_REPLAY_PROTECTION_FLAG;
    }

#if MBED_MAJOR_VERSION > 5
    if (g_is_device_rot_exist == false) {
        // auto generate rot
        DeviceKey &devkey = DeviceKey::get_instance();
        int kd_status = devkey.generate_root_of_trust();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kd_status != DEVICEKEY_SUCCESS && kd_status != DEVICEKEY_ALREADY_EXIST), KCM_STATUS_ERROR, "generate_root_of_trust() - failed, status %d\n", kd_status);
        g_is_device_rot_exist = true;
    }
#endif

    //call kv_set API
    kv_status = kv_set(sst_complete_item_name, itemBuffer, itemBufferSize, kv_flags);

    return pal_sst_translate_error(kv_status);
}

kcm_status_e pal_SSTGet(const char *itemName, void *itemBuffer, size_t itemBufferSize, size_t *actualItemSize)
{
    int kv_status = MBED_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination


    //allocate buffer for itemName + prefix and copy prefix to the new buffer
    kcm_status = storage_sst_build_complete_name(itemName, sst_complete_item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "storage_sst_build_complete_name failed");

    //call kv_get API
    kv_status = kv_get(sst_complete_item_name, itemBuffer, itemBufferSize, actualItemSize);

    return pal_sst_translate_error(kv_status);
}

kcm_status_e pal_SSTGetInfo(const char *itemName, palSSTItemInfo_t *palItemInfo)
{

    int kv_status = MBED_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kv_info_t kv_info = { 0, 0 };
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //allocate buffer for itemName + prefix and copy prefix to the new buffer
    kcm_status = storage_sst_build_complete_name(itemName, sst_complete_item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "storage_sst_build_complete_name failed");

    //call kv_get_info API
    kv_status = kv_get_info(sst_complete_item_name, &kv_info);

    if (kv_status != MBED_SUCCESS) {
        return pal_sst_translate_error(kv_status);
    }

    // translate kv flags to palSSTFlags.
    if (kv_info.flags & KV_WRITE_ONCE_FLAG) {
        palItemInfo->SSTFlagsBitmap |= PAL_SST_WRITE_ONCE_FLAG;
    }
    if (kv_info.flags & KV_REQUIRE_CONFIDENTIALITY_FLAG) {
        palItemInfo->SSTFlagsBitmap |= PAL_SST_CONFIDENTIALITY_FLAG;
    }
    if (kv_info.flags & KV_REQUIRE_REPLAY_PROTECTION_FLAG) {
        palItemInfo->SSTFlagsBitmap |= PAL_SST_REPLAY_PROTECTION_FLAG;
    }

    palItemInfo->itemSize = kv_info.size;

    return KCM_STATUS_SUCCESS;
}

kcm_status_e pal_SSTRemove(const char *itemName)
{

    int kv_status = MBED_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //allocate buffer for itemName + prefix and copy prefix to the new buffer
    kcm_status = storage_sst_build_complete_name(itemName, sst_complete_item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "storage_sst_build_complete_name failed");

    //call kv_remove API
    kv_status = kv_remove(sst_complete_item_name);

    return pal_sst_translate_error(kv_status);
}

kcm_status_e pal_SSTIteratorOpen(palSSTIterator_t *palSSTIterator, const char *itemPrefix)
{
    int kv_status = MBED_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char sst_complete_item_prefix[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //allocate buffer for itemName + prefix and copy prefix to the new buffer
    kcm_status = storage_sst_build_complete_name(itemPrefix, sst_complete_item_prefix);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "storage_sst_build_complete_name failed");

    //call kv_iterator_open API
    kv_status = kv_iterator_open((kv_iterator_t*)palSSTIterator, sst_complete_item_prefix);

    return pal_sst_translate_error(kv_status);
}

kcm_status_e pal_SSTIteratorNext(palSSTIterator_t palSSTIterator, char *itemName, size_t itemNameSize)
{
    int kv_status = MBED_SUCCESS;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //call kv_iterator_next API
    kv_status = kv_iterator_next((kv_iterator_t)palSSTIterator, sst_complete_item_name, itemNameSize + strlen(PAL_SST_KV_PREFIX));
    if (kv_status != MBED_SUCCESS) {
        return pal_sst_translate_error(kv_status);
    }

    //copy the returned value to the input buffer
    memcpy(itemName, sst_complete_item_name + strlen(PAL_SST_KV_PREFIX), itemNameSize);

    return KCM_STATUS_SUCCESS;
}

kcm_status_e pal_SSTIteratorClose(palSSTIterator_t palSSTIterator)
{
    int kv_status = MBED_SUCCESS;

    //call kv_iterator_close API
    kv_status = kv_iterator_close((kv_iterator_t)palSSTIterator);

    return pal_sst_translate_error(kv_status);
}

kcm_status_e pal_SSTReset()
{
    int kv_status = MBED_SUCCESS;

    //call kv_reset API
    kv_status = kv_reset(PAL_SST_KV_PREFIX);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kv_status != MBED_SUCCESS, pal_sst_translate_error(kv_status), "kv_reset failed");

#if MBED_MAJOR_VERSION > 5
    // reset flag too
    g_is_device_rot_exist = false;
#endif
    return KCM_STATUS_SUCCESS;
}
#endif
