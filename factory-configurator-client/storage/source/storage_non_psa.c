// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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


#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#include "storage_keys.h"
#include "storage_items.h"
#include "storage_internal.h"
#include "kcm_defs.h"
#include "pv_error_handling.h"
#include "fcc_malloc.h"
#include "pv_macros.h"


/* declare storage APIs here, so they can be used in the implementations below.
 * we can explicitly call those storage APIs and not the dispatcher since we are in non-psa mode only
 */
kcm_status_e storage_item_get_data(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type, uint8_t *kcm_item_data_out,
                                   size_t kcm_item_data_max_size, size_t *kcm_item_data_act_size_out);

kcm_status_e storage_item_get_data_size(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type, size_t *kcm_item_data_size_out);

kcm_status_e storage_item_store(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, bool kcm_item_is_factory, storage_item_prefix_type_e item_prefix_type, const uint8_t *kcm_item_data,
                                size_t kcm_item_data_size, const kcm_security_desc_s kcm_item_info);

kcm_status_e storage_item_delete(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type);


kcm_status_e storage_key_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    storage_item_prefix_type_e item_prefix_type,
    kcm_key_handle_t *key_h_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    palKeyHandle_t pal_key_handle;
    size_t key_size_out, key_size_out_actual;

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_h_out");

    *key_h_out = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name_len");
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)key_name_len, (char*)key_name, (uint32_t)key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid key_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != KCM_PRIVATE_KEY_ITEM && key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid key type");

    // Check key size
    kcm_status = storage_item_get_data_size(key_name, key_name_len, key_type, item_prefix_type, &key_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto exit;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_item_get_data_size read");

    //allocate buffer for new key
    pal_status = pal_newKeyHandle(&pal_key_handle, key_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_OUT_OF_MEMORY, "Failed during pal_newKeyHandle");

    // read the key
    kcm_status = storage_item_get_data(key_name, key_name_len, key_type, item_prefix_type, ((palCryptoBuffer_t*)pal_key_handle)->buffer, key_size_out, &key_size_out_actual);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "Failed during storage_item_get_data");

    *key_h_out = (kcm_key_handle_t)pal_key_handle;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    goto exit;

free_and_exit:
    storage_key_close_handle((kcm_key_handle_t*)&key_h_out);

exit:
    return kcm_status;


}

kcm_status_e storage_key_close_handle(kcm_key_handle_t *key_handle)
{

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_handle");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (*key_handle == 0) {
        return KCM_STATUS_SUCCESS;
    }

    pal_freeKeyHandle(key_handle);
    //check: *key_handle = 0;


    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e storage_key_pair_generate_and_store(
    const kcm_crypto_key_scheme_e     key_scheme,
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    storage_item_prefix_type_e        item_prefix_type,
    bool                              is_factory)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_del_status;
    size_t actual_kcm_priv_key_size = 0;
    size_t actual_kcm_pub_key_size = 0;
    cs_key_handle_t cs_key_h;
    bool write_public_key = false;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Check if current private exists in the storage
    kcm_status = storage_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                            item_prefix_type, &actual_kcm_priv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //Check if current public exists in the storage
    if (public_key_name != NULL) {
        SA_PV_LOG_INFO("public_key_name = %.*s public_key_name = %" PRIu32, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);
        kcm_status = storage_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, item_prefix_type,
                                                &actual_kcm_pub_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");

        //write public key
        write_public_key = true;
    }

    //create cs_ec_context
    kcm_status = cs_key_pair_new(&cs_key_h, write_public_key);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to create key context");

    //generate key pair
    kcm_status = cs_key_pair_generate(key_scheme, cs_key_h);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "failed to generate key pair");

    //store private key
    cs_key_pair_context_s* cs_key_ctx = (cs_key_pair_context_s*)cs_key_h;

    kcm_status = storage_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, is_factory, item_prefix_type, ((palCryptoBuffer_t*)(cs_key_ctx->generated_priv_key_handle))->buffer,
        ((palCryptoBuffer_t*)(cs_key_ctx->generated_priv_key_handle))->size, NULL);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "failed to store private key");

    //store public key if exists
    if (public_key_name != NULL) {
        kcm_status = storage_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, is_factory, item_prefix_type, ((palCryptoBuffer_t*)(cs_key_ctx->generated_pub_key_handle))->buffer,
            ((palCryptoBuffer_t*)(cs_key_ctx->generated_pub_key_handle))->size, NULL);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), delete_priv_and_exit, "failed to store public key");
    }

    goto free_and_exit;

delete_priv_and_exit:
    // Failed to store public, remove stored private key
    kcm_del_status = storage_item_delete(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, item_prefix_type);
    if (kcm_del_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("failed destorying PSA key during cleanup (%u)", kcm_del_status);
    }

free_and_exit:
    cs_key_pair_free(&cs_key_h);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_init(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_specific_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed initializing storage specific backend (kcm_status %d)", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_finalize(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_specific_finalize();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed finalizing storage specific backend (kcm_status %d)", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_reset_to_factory_state(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_factory_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed perform factory reset");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_reset(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_specific_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for storage specific reset");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

