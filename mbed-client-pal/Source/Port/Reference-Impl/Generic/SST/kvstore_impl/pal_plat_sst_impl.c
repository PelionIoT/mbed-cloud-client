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

#include "pal.h"
#include "pal_sst.h"
#include "kvstore_global_api.h"
#include "mbed_error.h"

#define EXPANSION_STR(x) STR(x) //stringification of macro value
#define STR(x) #x //stringification of the macro
#define PAL_SST_KV_PREFIX "/"EXPANSION_STR(MBED_CONF_STORAGE_DEFAULT_KV)"/"

#define TRACE_GROUP "PAL"

static palStatus_t pal_sst_translate_error(int kv_status)
{
    palStatus_t pal_status;

    switch (kv_status) {
        case MBED_SUCCESS:
            pal_status = PAL_SUCCESS;
            break;
        case MBED_ERROR_ITEM_NOT_FOUND:
            pal_status = PAL_ERR_SST_ITEM_NOT_FOUND;
            break;
        case  MBED_ERROR_INVALID_SIZE:
            pal_status = PAL_ERR_SST_INVALID_SIZE;
            break;
        case MBED_ERROR_NOT_READY:
            pal_status = PAL_ERR_SST_NOT_READY;
            break;
        case MBED_ERROR_WRITE_PROTECTED:
            pal_status = PAL_ERR_SST_WRITE_PROTECTED;
            break;
        case MBED_ERROR_WRITE_FAILED:
            pal_status = PAL_ERR_SST_WRITE_FAILED;
            break;
        case MBED_ERROR_READ_FAILED:
            pal_status = PAL_ERR_SST_READ_FAILED;
            break;
        case MBED_ERROR_INVALID_DATA_DETECTED:
            pal_status = PAL_ERR_SST_INVALID_DATA_DETECTED;
            break;
        case MBED_ERROR_FAILED_OPERATION:
            pal_status = PAL_ERR_SST_FAILED_OPERATION;
            break;
        case MBED_ERROR_INVALID_ARGUMENT:
            pal_status = PAL_ERR_INVALID_ARGUMENT;
            break;
        case MBED_ERROR_MEDIA_FULL:
            pal_status = PAL_ERR_SST_MEDIA_FULL;
            break;
        case MBED_ERROR_RBP_AUTHENTICATION_FAILED:
            pal_status = PAL_ERR_SST_RBP_AUTHENTICATION_FAILED;
            break;
        case MBED_ERROR_AUTHENTICATION_FAILED:
            pal_status = PAL_ERR_SST_AUTHENTICATION_FAILED;
            break;
        default:
            pal_status = PAL_ERR_SST_GENERIC_FAILURE;
    }

    if (pal_status == PAL_ERR_SST_ITEM_NOT_FOUND) {
        PAL_LOG_DBG("kv_status: %" PRId16", pal_sst status: 0x%" PRIx32 "", MBED_GET_ERROR_CODE(kv_status), pal_status);
    }
    else if (pal_status != PAL_SUCCESS) {
        PAL_LOG_ERR("kv_status: %" PRId16", pal_sst status: 0x%" PRIx32 "", MBED_GET_ERROR_CODE(kv_status), pal_status);
    }

    return pal_status;
}


static palStatus_t pal_sst_build_complete_name(const char* item_name, char* complete_item_name)
{

    PAL_VALIDATE_ARGUMENTS((NULL == item_name) || (NULL == complete_item_name));

    size_t item_name_length = strlen(item_name);
    size_t prefix_length = strlen(PAL_SST_KV_PREFIX);
    size_t total_length = prefix_length + item_name_length;
    if (total_length > KV_MAX_KEY_LENGTH) {
        return PAL_ERR_SST_INVALID_SIZE;
    }

    //copy prefix
    memcpy(complete_item_name, PAL_SST_KV_PREFIX, prefix_length);

    //copy item name to the new buffer
    memcpy(complete_item_name + prefix_length, item_name, item_name_length);

    //null terminate
    complete_item_name[total_length] = '\0';

    return PAL_SUCCESS;
}

palStatus_t pal_SSTSet(const char *itemName, const void *itemBuffer, size_t itemBufferSize, uint32_t SSTFlagsBitmap)
{
    int kv_status = MBED_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    uint32_t kv_flags = 0;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //these bitmask is for unused bits in SSTFlagsBitmap.
    //only PAL_SST_WRITE_ONCE_FLAG, PAL_SST_CONFIDENTIALITY_FLAG and PAL_SST_REPLAY_PROTECTION_FLAG used  
    uint32_t sst_flag_unused_bits_mask = ~(PAL_SST_WRITE_ONCE_FLAG | PAL_SST_CONFIDENTIALITY_FLAG | PAL_SST_REPLAY_PROTECTION_FLAG);

    //arguments validation
    PAL_VALIDATE_ARGUMENTS((NULL == itemName) || ((NULL == itemBuffer) && (itemBufferSize > 0)) || ((SSTFlagsBitmap & sst_flag_unused_bits_mask) != 0));

    //allocate buffer for itemName + prefix and copy prefix to the new buffer    
    pal_status = pal_sst_build_complete_name(itemName, sst_complete_item_name);
    if (pal_status != PAL_SUCCESS) {
        PAL_LOG_ERR("pal_SSTSet: 0x%" PRIx32 "", pal_status);
        return pal_status;
    }

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

    //call kv_set API
    kv_status = kv_set(sst_complete_item_name, itemBuffer, itemBufferSize, kv_flags);

    return pal_sst_translate_error(kv_status);
}


palStatus_t pal_SSTGet(const char *itemName, void *itemBuffer, size_t itemBufferSize, size_t *actualItemSize)
{
    int kv_status = MBED_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //arguments validation
    PAL_VALIDATE_ARGUMENTS((NULL == itemName) || ((NULL == itemBuffer) && (itemBufferSize > 0)) || (NULL == actualItemSize));

    //allocate buffer for itemName + prefix and copy prefix to the new buffer    
    pal_status = pal_sst_build_complete_name(itemName, sst_complete_item_name);
    if (pal_status != PAL_SUCCESS) {
        PAL_LOG_ERR("pal_SSTGet returned: 0x%" PRIx32 "", pal_status);
        return pal_status;
    }

    //call kv_get API
    kv_status = kv_get(sst_complete_item_name, itemBuffer, itemBufferSize, actualItemSize);

    return pal_sst_translate_error(kv_status);
}


palStatus_t pal_SSTGetInfo(const char *itemName, palSSTItemInfo_t *palItemInfo)
{

    int kv_status = MBED_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    kv_info_t kv_info = { 0 };
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //arguments validation
    PAL_VALIDATE_ARGUMENTS((NULL == itemName) || (NULL == palItemInfo));

    //allocate buffer for itemName + prefix and copy prefix to the new buffer    
    pal_status = pal_sst_build_complete_name(itemName, sst_complete_item_name);
    if (pal_status != PAL_SUCCESS) {
        PAL_LOG_ERR("pal_SSTGetInfo returned: 0x%" PRIx32 "", pal_status);
        return pal_status;
    }

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

    return PAL_SUCCESS;
}


palStatus_t pal_SSTRemove(const char *itemName)
{

    int kv_status = MBED_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //arguments validation
    PAL_VALIDATE_ARGUMENTS((NULL == itemName));

    //allocate buffer for itemName + prefix and copy prefix to the new buffer    
    pal_status = pal_sst_build_complete_name(itemName, sst_complete_item_name);
    if (pal_status != PAL_SUCCESS) {
        PAL_LOG_ERR("pal_SSTRemove returned: 0x%" PRIx32 "", pal_status);
        return pal_status;
    }

    //call kv_remove API
    kv_status = kv_remove(sst_complete_item_name);

    return pal_sst_translate_error(kv_status);
}


palStatus_t pal_SSTIteratorOpen(palSSTIterator_t *palSSTIterator, const char *itemPrefix)
{
    int kv_status = MBED_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    char sst_complete_item_prefix[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //arguments validation
    PAL_VALIDATE_ARGUMENTS((NULL == palSSTIterator));

    //allocate buffer for itemName + prefix and copy prefix to the new buffer    
    pal_status = pal_sst_build_complete_name(itemPrefix, sst_complete_item_prefix);
    if (pal_status != PAL_SUCCESS) {
        PAL_LOG_ERR("pal_SSTIteratorOpen returned: 0x%" PRIx32 "", pal_status);
        return pal_status;
    }

    //call kv_iterator_open API
    kv_status = kv_iterator_open((kv_iterator_t*)palSSTIterator, sst_complete_item_prefix);

    return pal_sst_translate_error(kv_status);
}


palStatus_t pal_SSTIteratorNext(palSSTIterator_t palSSTIterator, char *itemName, size_t itemNameSize)
{
    int kv_status = MBED_SUCCESS;
    char sst_complete_item_name[KV_MAX_KEY_LENGTH + 1]; //extra byte for null termination

    //arguments validation
    PAL_VALIDATE_ARGUMENTS(((uintptr_t)NULL == palSSTIterator) || (NULL == itemName) || (0 == itemNameSize));

    //call kv_iterator_next API
    kv_status = kv_iterator_next((kv_iterator_t)palSSTIterator, sst_complete_item_name, itemNameSize + strlen(PAL_SST_KV_PREFIX));
    if (kv_status != MBED_SUCCESS) {
        return pal_sst_translate_error(kv_status);
    }

    //copy the returned value to the input buffer
    memcpy(itemName, sst_complete_item_name + strlen(PAL_SST_KV_PREFIX), itemNameSize);

    return PAL_SUCCESS;
}


palStatus_t pal_SSTIteratorClose(palSSTIterator_t palSSTIterator)
{
    //arguments validation
    PAL_VALIDATE_ARGUMENTS(((uintptr_t)NULL == palSSTIterator));

    int kv_status = MBED_SUCCESS;

    //call kv_iterator_close API
    kv_status = kv_iterator_close((kv_iterator_t)palSSTIterator);

    return pal_sst_translate_error(kv_status);
}


palStatus_t pal_SSTReset()
{
    int kv_status = MBED_SUCCESS;

    //call kv_reset API
    kv_status = kv_reset(PAL_SST_KV_PREFIX);

    return pal_sst_translate_error(kv_status);
}

#endif

