// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#include "fcc_bundle_handler.h"
#include "cn-cbor.h"
#include "pv_error_handling.h"
#include "fcc_bundle_utils.h"
#include "key_config_manager.h"
#include "fcc_output_info_handler.h"
#include "general_utils.h"
#include "fcc_time_profiling.h"
#include "fcc_utils.h"

#define  FCC_MAX_PEM_KEY_SIZE 1024*2
/**
* Names of key types
*/
#define FCC_ECC_PRIVATE_KEY_TYPE_NAME  "ECCPrivate"
#define FCC_ECC_PUBLIC_KEY_TYPE_NAME   "ECCPublic"
#define FCC_RSA_PRIVATE_KEY_TYPE_NAME  "RSAPrivate"
#define FCC_RSA_PUBLIC_KEY_TYPE_NAME   "RSAPublic"
#define FCC_SYMMETRIC_KEY_TYPE_NAME    "Symmetric"
/**
* Group lookup record, correlating group's type and name
*/
typedef struct fcc_bundle_key_type_lookup_record_ {
    fcc_bundle_key_type_e key_type;
    const char *key_type_name;
} fcc_bundle_key_type_lookup_record_s;
/**
* Group lookup table, correlating for each group its type and name
*/
static const fcc_bundle_key_type_lookup_record_s fcc_bundle_key_type_lookup_table[FCC_MAX_KEY_TYPE] = {
    { FCC_ECC_PRIVATE_KEY_TYPE,          FCC_ECC_PRIVATE_KEY_TYPE_NAME },
    { FCC_ECC_PUBLIC_KEY_TYPE,           FCC_ECC_PUBLIC_KEY_TYPE_NAME },
    { FCC_RSA_PRIVATE_KEY_TYPE,          FCC_RSA_PRIVATE_KEY_TYPE_NAME },
    { FCC_RSA_PUBLIC_KEY_TYPE,           FCC_RSA_PUBLIC_KEY_TYPE_NAME },
    { FCC_SYM_KEY_TYPE,                  FCC_SYMMETRIC_KEY_TYPE_NAME }
};
/**  Gets type of key form cbor structure
*
* The function goes over all key types and compares it with type inside cbor structure.
*
* @param key_type_cb[in]   The cbor structure with key type data.
* @param key_type[out]     The key type
*
* @return
*     true for success, false otherwise.
*/
bool fcc_bundle_get_key_type(const cn_cbor *key_type_cb, fcc_bundle_key_type_e *key_type)
{

    int key_type_index;
    bool res;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type_cb == NULL), false, "key_type_cb is null");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type == NULL), false, "key_type is null");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*key_type != FCC_INVALID_KEY_TYPE), false, "wrong key type value");

    for (key_type_index = 0; key_type_index < FCC_MAX_KEY_TYPE -1; key_type_index++) {
        res = is_memory_equal(fcc_bundle_key_type_lookup_table[key_type_index].key_type_name,
                             strlen(fcc_bundle_key_type_lookup_table[key_type_index].key_type_name),
                             key_type_cb->v.bytes,
                             (size_t)key_type_cb->length);
        if (res) {
            *key_type = fcc_bundle_key_type_lookup_table[key_type_index].key_type;
            return true;
        }
    }
    SA_PV_LOG_TRACE_FUNC_EXIT("key_type is %d", (int)(*key_type));
    return false;

}

/** Processes  keys list.
* The function extracts data parameters for each key and stores its according to it type.
*
* @param keys_list_cb[in]   The cbor structure with keys list.
*
* @return
*     true for success, false otherwise.
*/
fcc_status_e fcc_bundle_process_keys(const cn_cbor *keys_list_cb)
{

    bool status = false;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_status_e output_info_fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_result = KCM_STATUS_SUCCESS;
    uint32_t key_index = 0;
    cn_cbor *key_cb;
    fcc_bundle_data_param_s key;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((keys_list_cb == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Invalid keys_list_cb pointer");

    //Initialize data struct
    memset(&key,0,sizeof(fcc_bundle_data_param_s));

    for (key_index = 0; key_index < (uint32_t)keys_list_cb->length; key_index++) {

        FCC_SET_START_TIMER(fcc_key_timer);

        //fcc_bundle_clean_and_free_data_param(&key);

        //Get key CBOR struct at index key_index
        key_cb = cn_cbor_index(keys_list_cb, key_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((key_cb == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Failed to get key at index (%" PRIu32 ") ", key_index);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((key_cb->type != CN_CBOR_MAP), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Wrong type of key CBOR struct at index (%" PRIu32 ")", key_index);

        status = fcc_bundle_get_data_param(key_cb, &key);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), fcc_status = FCC_STATUS_BUNDLE_ERROR, "Failed to get key data at index (%" PRIu32 ") ", key_index);

        switch (key.type) {
            case FCC_ECC_PRIVATE_KEY_TYPE:
            case FCC_RSA_PRIVATE_KEY_TYPE:
                kcm_result = kcm_item_store(key.name, key.name_len, KCM_PRIVATE_KEY_ITEM, true, key.data, key.data_size, key.acl);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to store key private at index (%" PRIu32 ") ", key_index);
                break;

            case FCC_ECC_PUBLIC_KEY_TYPE:
            case FCC_RSA_PUBLIC_KEY_TYPE:
                kcm_result = kcm_item_store(key.name, key.name_len, KCM_PUBLIC_KEY_ITEM, true, key.data, key.data_size, key.acl);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to store key public at index (%" PRIu32 ") ", key_index);
                break;

            case (FCC_SYM_KEY_TYPE):
                kcm_result = kcm_item_store(key.name, key.name_len, KCM_SYMMETRIC_KEY_ITEM, true, key.data, key.data_size, key.acl);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_result != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_result), exit, "Failed to store symmetric key at index (%" PRIu32 ") ", key_index);
                break;
            default:
                SA_PV_LOG_ERR("Invalid key type (%u)!", key.type);
                goto exit;
        }
        FCC_END_TIMER((char*)key.name, key.name_len, fcc_key_timer);
    }

exit:
    if (kcm_result != KCM_STATUS_SUCCESS) {
        output_info_fcc_status = fcc_bundle_store_error_info(key.name, key.name_len, kcm_result);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((output_info_fcc_status != FCC_STATUS_SUCCESS),
                                        fcc_status = FCC_STATUS_OUTPUT_INFO_ERROR,
                                        "Failed to create output kcm_status error %d", kcm_result);
    }
    fcc_bundle_clean_and_free_data_param(&key);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}
