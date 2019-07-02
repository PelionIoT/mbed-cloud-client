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

kcm_status_e storage_key_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    storage_item_prefix_type_e item_prefix_type,
    kcm_key_handle_t *key_h_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t key_size_out, key_size_out_actual;

    PV_UNUSED_PARAM(item_prefix_type);

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_h_out");

    *key_h_out = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name_len");
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)key_name_len, (char*)key_name, (uint32_t)key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid key_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != KCM_PRIVATE_KEY_ITEM && key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid key type");

    // Check key size
    kcm_status = kcm_item_get_data_size(key_name, key_name_len, key_type, &key_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        goto exit;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_item_get_data_size read");

    //allocate palCryptoBuffer_t struct
    palCryptoBuffer_t* crypto_buffer = (palCryptoBuffer_t*)fcc_malloc(sizeof(palCryptoBuffer_t));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((crypto_buffer == NULL), KCM_STATUS_OUT_OF_MEMORY, "Failed during malloc palCryptoBuffer_t");

    crypto_buffer->buffer = NULL;
    crypto_buffer->size = 0;

    //allocate buffer for the key
    crypto_buffer->buffer = fcc_malloc(key_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((crypto_buffer->buffer == NULL), kcm_status = KCM_STATUS_OUT_OF_MEMORY, free_and_exit, "Failed during malloc key");

    // read the key
    kcm_status = kcm_item_get_data(key_name, key_name_len, key_type, crypto_buffer->buffer, key_size_out, &key_size_out_actual);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, free_and_exit, "Key was not found");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, free_and_exit, "Failed during storage_item_get_data");

    crypto_buffer->size = (uint32_t)key_size_out_actual;

    *key_h_out = (kcm_key_handle_t)crypto_buffer;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    goto exit;


free_and_exit:
    storage_key_close_handle((kcm_key_handle_t*)&crypto_buffer);

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

    palCryptoBuffer_t* crypto_buffer = (palCryptoBuffer_t*)*key_handle;

    // free buffer
    if (crypto_buffer->buffer != NULL) {
        fcc_free(crypto_buffer->buffer);
    }

    //free struct
    fcc_free(crypto_buffer);
    *key_handle = 0;

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
    uint8_t priv_key_buffer[KCM_EC_SECP256R1_MAX_PRIV_KEY_DER_SIZE];
    uint8_t pub_key_buffer[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    PV_UNUSED_PARAM(item_prefix_type);

    //Check if current private exists in the storage
    kcm_status = kcm_item_get_data_size(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM,
                                        &actual_kcm_priv_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "private key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check private key existence");

    //Check if current public exists in the storage
    if (public_key_name != NULL) {
        SA_PV_LOG_INFO("public_key_name = %.*s public_key_name = %" PRIu32, (int)public_key_name_len, (char*)public_key_name, (uint32_t)public_key_name_len);
        kcm_status = kcm_item_get_data_size(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM,
                                            &actual_kcm_pub_key_size);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_KEY_EXIST, "public key already exists");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "failed to check public key existence");
    }

    //generate key pair
    kcm_status = cs_key_pair_generate(key_scheme, priv_key_buffer, sizeof(priv_key_buffer), &actual_kcm_priv_key_size, pub_key_buffer, sizeof(pub_key_buffer), &actual_kcm_pub_key_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to generate key pair");

    //store private key
    kcm_status = kcm_item_store(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, is_factory, priv_key_buffer, actual_kcm_priv_key_size, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to store private key");

    //store public key if exists
    if (public_key_name != NULL) {
        kcm_status = kcm_item_store(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, is_factory, pub_key_buffer, actual_kcm_pub_key_size, NULL);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), delete_priv_and_exit, "failed to store public key");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;

delete_priv_and_exit:
    // Failed to store public, remove stored private key
    kcm_del_status = kcm_item_delete(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM);
    if (kcm_del_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("failed destorying PSA key during cleanup (%u)", kcm_del_status);
    }
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

