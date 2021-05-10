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
#include <stdbool.h>
#include "key_config_manager.h"
#include "pv_error_handling.h"
#include "cs_der_certs.h"
#include "cs_der_keys_and_csrs.h"
#include "fcc_malloc.h"
#ifndef FCC_NANOCLIENT_ENABLED
#include "pal.h"
#endif
#include "cs_pal_plat_crypto.h"
#include "cs_utils.h"
#include "pv_macros.h"
#include "key_slot_allocator.h"
#include "storage_kcm.h"

bool g_kcm_initialized = false;

kcm_status_e kcm_init(void)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (!g_kcm_initialized) {
        palStatus_t pal_status;
#ifndef FCC_NANOCLIENT_ENABLED
        //Initialize PAL
        pal_status = pal_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_ERROR, "Failed initializing PAL (%" PRIu32 ")", pal_status);
#else
       pal_status = pal_plat_DRBGInit();
       SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), KCM_STATUS_ERROR, "Failed initializing DRBG (%" PRIu32 ")", pal_status);
#endif
        //Initialize back-end storage
        status = storage_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "Failed initializing storage\n");

        /*
         * Do not initialize the time module inside pal_init since pal_initTime() uses storage functions.
         * At KCM init it is guaranteed that any entropy and RoT that should be injected - is already injected.
         */
#ifndef FCC_NANOCLIENT_ENABLED
        pal_status = pal_initTime();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), KCM_STATUS_ERROR, "Failed PAL time module (%" PRIu32 ")", pal_status);
#endif

        // Mark as "initialized"
        g_kcm_initialized = true;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return status;
}

kcm_status_e kcm_finalize(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();


    if (g_kcm_initialized) {

        kcm_status = storage_finalize();
        if (kcm_status != KCM_STATUS_SUCCESS) {
            SA_PV_LOG_ERR("Failed finalizing storage\n");
        }
#ifndef FCC_NANOCLIENT_ENABLED
        //Finalize PAL
        pal_destroy();
#else
        palStatus_t pal_status;
        pal_status = pal_plat_DRBGDestroy();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), KCM_STATUS_ERROR, "Failed to finalize DRBG (%" PRIu32 ")", pal_status);
#endif
        // Mark as "not initialized"
        g_kcm_initialized = false;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_item_store(const uint8_t * kcm_item_name,
                            size_t kcm_item_name_len,
                            kcm_item_type_e kcm_item_type,
                            bool kcm_item_is_factory,
                            const uint8_t * kcm_item_data,
                            size_t kcm_item_data_size,
                            const kcm_security_desc_s kcm_item_info)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_info != NULL), KCM_STATUS_INVALID_PARAMETER, "Passing additional info is not supported. kcm_item_info must be set to NULL.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_data == NULL) && (kcm_item_data_size > 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data NULL and kcm_item_data_size greater than 0.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_CONFIG_ITEM && kcm_item_data_size == 0), KCM_STATUS_ITEM_IS_EMPTY, "The data of the current item is empty.");

    switch (kcm_item_type) {
        case KCM_PRIVATE_KEY_ITEM:
            kcm_status = cs_der_priv_key_verify(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Private key validation failed");
            break;
        case KCM_PUBLIC_KEY_ITEM:
            kcm_status = cs_der_public_key_verify(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Public key validation failed");
            break;
        case KCM_SYMMETRIC_KEY_ITEM:
            //currently possible to write a symmetric key of size 0 since we do not check format
            break;
        case KCM_CERTIFICATE_ITEM:
            kcm_status = cs_check_der_x509_format(kcm_item_data, kcm_item_data_size);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Certificate validation failed");
            break;
        case KCM_CONFIG_ITEM:
            break;
        default:
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_type");
    }

    kcm_status = storage_item_store(kcm_item_name, kcm_item_name_len, kcm_item_type, kcm_item_is_factory, STORAGE_ITEM_PREFIX_KCM, kcm_item_data, kcm_item_data_size, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_data_write");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e kcm_item_get_data_size(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, size_t *kcm_item_data_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;


    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status = storage_item_get_data_size(kcm_item_name, kcm_item_name_len, kcm_item_type, STORAGE_ITEM_PREFIX_KCM, kcm_item_data_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_data_size_read");

    return kcm_status;
}

kcm_status_e kcm_item_get_data(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, uint8_t * kcm_item_data_out, size_t kcm_item_data_max_size, size_t * kcm_item_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status =  storage_item_get_data(kcm_item_name, kcm_item_name_len, kcm_item_type, STORAGE_ITEM_PREFIX_KCM, kcm_item_data_out, kcm_item_data_max_size, kcm_item_data_act_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_data_read");

    return kcm_status;
}

kcm_status_e kcm_item_get_size_and_data(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, uint8_t ** kcm_item_data_out, size_t * kcm_item_data_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status = storage_item_get_size_and_data(kcm_item_name, kcm_item_name_len, kcm_item_type, STORAGE_ITEM_PREFIX_KCM, kcm_item_data_out, kcm_item_data_size_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get item size and data");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_item_delete(const uint8_t * kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status = storage_item_delete(kcm_item_name, kcm_item_name_len, kcm_item_type, STORAGE_ITEM_PREFIX_KCM);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_data_delete");

    return kcm_status;
}


#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
kcm_status_e kcm_item_get_handle(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, kcm_key_handle_t *key_handle_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status = storage_key_get_handle((const uint8_t *)kcm_item_name, kcm_item_name_len, kcm_item_type, STORAGE_ITEM_PREFIX_KCM, key_handle_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_get_handle");

    return kcm_status;
}

kcm_status_e kcm_item_close_handle(kcm_key_handle_t *key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status = storage_key_close_handle(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_close_handle");

    return kcm_status;
}

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
kcm_status_e kcm_item_get_location(const uint8_t *item_name, size_t item_name_len, kcm_item_type_e kcm_item_type, kcm_item_location_e *item_location_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Only asymmetric keys allowed
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_PRIVATE_KEY_ITEM) && (kcm_item_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Only key types allowed");

    kcm_status = storage_item_get_location((const uint8_t *)item_name, item_name_len, kcm_item_type, STORAGE_ITEM_PREFIX_KCM, item_location_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting item location");

    return kcm_status;
}

kcm_status_e kcm_se_private_key_get_slot(const uint8_t *prv_key_name, size_t prv_key_name_len, uint64_t *se_prv_key_slot)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    kcm_status = storage_se_private_key_get_slot(prv_key_name, prv_key_name_len, se_prv_key_slot);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting key slot from storage");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

kcm_status_e kcm_factory_reset(void)
{
    kcm_status_e status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "KCM initialization failed\n");
    }

    status = storage_factory_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != KCM_STATUS_SUCCESS), status, "Failed perform factory reset");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return status;
}

kcm_status_e kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t kcm_chain_len, bool kcm_chain_is_factory)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Call internal storage_cert_chain_create
    kcm_status = storage_cert_chain_create(kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, kcm_chain_len, kcm_chain_is_factory, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_cert_chain_create");

    return kcm_status;
}

kcm_status_e kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle, const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, size_t *kcm_chain_len_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Call internal storage_cert_chain_open
    kcm_status = storage_cert_chain_open(kcm_chain_handle, kcm_chain_name, kcm_chain_name_len, STORAGE_ITEM_PREFIX_KCM, kcm_chain_len_out);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_cert_chain_open");

    return kcm_status;
}
/*
* If not first certificate in chain:
*     1. Validate previously added certificate with the public key inside kcm_cert_data
*     2. Set the chain_context->prev_cert_params to be the params of the current certificate so it can be validated with next call to this function.
*     3. Store the current certificate
*     4. Update the index of the chain handle iterator for next use of this function
* If is first certificate in chain:
*    File already open - skip step 1 (no previous cert available). Note in this case the file should already be open so no need to reopen it
*/
kcm_status_e kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle, const uint8_t *kcm_cert_data, size_t kcm_cert_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER("cert_data_size =%" PRIu32 "", (uint32_t)kcm_cert_data_size);

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // call internal storage_chain_add_next
    kcm_status = storage_cert_chain_add_next(kcm_chain_handle, kcm_cert_data, kcm_cert_data_size, STORAGE_ITEM_PREFIX_KCM, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed in storage_chain_add_next");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e kcm_cert_chain_delete(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //Call internal storage_cert_chain_delete
    kcm_status = storage_cert_chain_delete(kcm_chain_name, kcm_chain_name_len, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_cert_chain_delete");

    return kcm_status;
}


kcm_status_e kcm_cert_chain_get_next_size(kcm_cert_chain_handle kcm_chain_handle, size_t *kcm_cert_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal storage_cert_chain_get_next_size
    kcm_status = storage_cert_chain_get_next_size(kcm_chain_handle, STORAGE_ITEM_PREFIX_KCM, kcm_cert_data_size );
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_cert_chain_get_next_size");

    return kcm_status;
}

kcm_status_e kcm_cert_chain_get_next_data(kcm_cert_chain_handle kcm_chain_handle, uint8_t *kcm_cert_data, size_t kcm_max_cert_data_size, size_t *kcm_actual_cert_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal storage_cert_chain_get_next_data
    kcm_status = storage_cert_chain_get_next_data(kcm_chain_handle, kcm_cert_data, kcm_max_cert_data_size, STORAGE_ITEM_PREFIX_KCM, kcm_actual_cert_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_cert_chain_get_next_data");

    return kcm_status;
}


kcm_status_e kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Call internal storage_cert_chain_close
    kcm_status = storage_cert_chain_close(kcm_chain_handle, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_cert_chain_close")

    return kcm_status;
}

kcm_status_e kcm_key_pair_generate_and_store(const kcm_crypto_key_scheme_e key_scheme,
                                             const uint8_t                 *private_key_name,
                                             size_t                        private_key_name_len,
                                             const uint8_t                 *public_key_name,
                                             size_t                        public_key_name_len,
                                             bool                          kcm_item_is_factory,
                                             const kcm_security_desc_s     kcm_item_info)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_scheme != KCM_SCHEME_EC_SECP256R1), KCM_STATUS_INVALID_PARAMETER, "Invalid key_scheme");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name != NULL) && (public_key_name_len == 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is not NULL, but its size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name == NULL) && (public_key_name_len != 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is NULL, but its size is not 0");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32,
                              (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len);

    kcm_status = storage_key_pair_generate_and_store(private_key_name, private_key_name_len, public_key_name, public_key_name_len, STORAGE_ITEM_PREFIX_KCM, kcm_item_is_factory, kcm_item_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_KEY_EXIST), KCM_STATUS_KEY_EXIST, "key already exists");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "failed to check key existence");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e kcm_csr_generate(
    const uint8_t            *private_key_name,
    size_t                   private_key_name_len,
    const kcm_csr_params_s   *csr_params,
    uint8_t                  *csr_buff_out,
    size_t                   csr_buff_max_size,
    size_t                   *csr_buff_act_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_close_status = KCM_STATUS_SUCCESS;
    kcm_key_handle_t priv_key_h;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->md_type == KCM_MD_NONE), KCM_STATUS_INVALID_PARAMETER, "Invalid md type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_act_size");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32", csr_buff_max_size = %" PRIu32,
                              (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len, (uint32_t)csr_buff_max_size);

    kcm_status = storage_key_get_handle(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, &priv_key_h);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting private key handle");

    //generate csr
    kcm_status = cs_csr_generate(priv_key_h, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("failed to cs_csr_generate");
    }

    kcm_close_status = storage_key_close_handle(&priv_key_h);
    if (kcm_close_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("failed to kcm_close_status");
    }

    if (kcm_status == KCM_STATUS_SUCCESS) {
        kcm_status = kcm_close_status;
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to kcm_csr_generate");

    SA_PV_LOG_INFO_FUNC_EXIT("csr_buff_act_size = %" PRIu32 "", (uint32_t)*csr_buff_act_size);

    return kcm_status;
}


kcm_status_e kcm_generate_keys_and_csr(kcm_crypto_key_scheme_e     key_scheme,
                                       const uint8_t              *private_key_name,
                                       size_t                      private_key_name_len,
                                       const uint8_t              *public_key_name,
                                       size_t                      public_key_name_len,
                                       bool                        kcm_item_is_factory,
                                       const kcm_csr_params_s     *csr_params,
                                       uint8_t                    *csr_buff_out,
                                       size_t                      csr_buff_max_size,
                                       size_t                     *csr_buff_act_size_out,
                                       const kcm_security_desc_s   kcm_item_info)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    bool pub_name_exists = false;
    kcm_status_e kcm_exit_status;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_scheme != KCM_SCHEME_EC_SECP256R1), KCM_STATUS_INVALID_PARAMETER, "Invalid key_scheme");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name != NULL) && (public_key_name_len == 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is not NULL, but its size is 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((public_key_name == NULL) && (public_key_name_len != 0)), KCM_STATUS_INVALID_PARAMETER, "public_key_name is NULL, but its size is not 0");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_params");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->subject == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid subject name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params->md_type == KCM_MD_NONE), KCM_STATUS_INVALID_PARAMETER, "Invalid md type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_max_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_buff_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid csr_buff_act_size");

    SA_PV_LOG_INFO_FUNC_ENTER("priv_key_name = %.*s priv_key_len = %" PRIu32,
                              (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len);

    pub_name_exists = ((public_key_name != NULL) && (public_key_name_len != 0));

    kcm_status = kcm_key_pair_generate_and_store(key_scheme, private_key_name, private_key_name_len, public_key_name, public_key_name_len, kcm_item_is_factory, kcm_item_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), "failed to generate/storing keypair");

    kcm_status = kcm_csr_generate(private_key_name, private_key_name_len, csr_params, csr_buff_out, csr_buff_max_size, csr_buff_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), delete_and_exit, "failed to generate keys and csr");

    SA_PV_LOG_INFO_FUNC_EXIT("csr_buff_act_size_out = %" PRIu32 "", (uint32_t)*csr_buff_act_size_out);

    return kcm_status;

delete_and_exit:
    kcm_exit_status = kcm_item_delete(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM);
    if (kcm_exit_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("failed to delete private during cleanup");
    }
    if (pub_name_exists) {
        kcm_exit_status = kcm_item_delete(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM);
        if (kcm_exit_status != KCM_STATUS_SUCCESS) {
            SA_PV_LOG_ERR("failed to delete public key during cleanup");
        }
    }

    return kcm_status;
}

kcm_status_e kcm_certificate_verify_with_private_key(
    const uint8_t * kcm_cert_data,
    size_t kcm_cert_data_size,
    const uint8_t * kcm_priv_key_name,
    size_t kcm_priv_key_name_len)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palX509Handle_t x509_cert;
    kcm_key_handle_t priv_key_h = 0;
    kcm_status_e kcm_close_handle_status = KCM_STATUS_SUCCESS;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    //check input params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_cert_data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_cert_data_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_priv_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_priv_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_priv_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_priv_key_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("priv key name =  %.*s, cert size=%" PRIu32 "", (int)kcm_priv_key_name_len, (char*)kcm_priv_key_name, (uint32_t)kcm_cert_data_size);

    //Create certificate handle
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_cert_data, kcm_cert_data_size, &x509_cert);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to create certificate handle");

    kcm_status = storage_key_get_handle(kcm_priv_key_name, kcm_priv_key_name_len, KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, &priv_key_h);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed creating private key handle");

    //Check current certificate against given private key
    kcm_status = cs_check_cert_with_priv_handle(x509_cert, priv_key_h);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR), Exit, "Certificate verification failed against private key");

Exit:
    if (priv_key_h != 0) {
        kcm_close_handle_status = storage_key_close_handle(&priv_key_h);
        if (kcm_close_handle_status != KCM_STATUS_SUCCESS ) {
            SA_PV_LOG_ERR("failed to close key handle");
            if (kcm_status == KCM_STATUS_SUCCESS ) {
                kcm_status = kcm_close_handle_status;
            }
        }
    }

    cs_close_handle_x509_cert(&x509_cert);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;

}



kcm_status_e kcm_asymmetric_sign(const uint8_t *private_key_name, size_t private_key_name_len, const uint8_t *hash_digest, size_t hash_digest_size,uint8_t *signature_data_out,
                                 size_t signature_data_max_size, size_t *signature_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e close_handle_status;
    kcm_key_handle_t kcm_handle;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_digest == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid hash_digest");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_digest_size != KCM_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "invalid hash_digest_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_out == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid signature_data_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_max_size < KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE), KCM_STATUS_INVALID_PARAMETER, "invalid signature_data_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid signature_data_act_size_out");

    //Call storage_get_handle to get handle of the private key.
    kcm_status = storage_key_get_handle(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, &kcm_handle);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_key_get_handle");

    //Call cs_asymmetric_sign to calculate the signature
    kcm_status = cs_asymmetric_sign(kcm_handle, hash_digest, hash_digest_size, signature_data_out, signature_data_max_size, signature_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed during cs_asymmetric_sign");

exit:

    if (kcm_handle != 0) {
        close_handle_status = storage_key_close_handle(&kcm_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((close_handle_status != KCM_STATUS_SUCCESS && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Failed during storage_close_handle");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e kcm_asymmetric_verify(const uint8_t *public_key_name, size_t public_key_name_len, const uint8_t *hash_digest, size_t hash_digest_size, const uint8_t *signature,
                                   size_t signature_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_key_handle_t kcm_handle;
    kcm_status_e close_handle_status;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid public_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "invalid public_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_digest == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid hash_digest");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((hash_digest_size != KCM_SHA256_SIZE), KCM_STATUS_INVALID_PARAMETER, "invalid hash_digest_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid signature");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((signature_size == 0), KCM_STATUS_INVALID_PARAMETER, "invalid signature_size");

    //Call storage_get_handle to get handle of the public key.
    kcm_status = storage_key_get_handle(public_key_name, public_key_name_len, KCM_PUBLIC_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, &kcm_handle);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_key_get_handle");

    //call cs_asymmetric_sign to verify the signature
    kcm_status = cs_asymmetric_verify(kcm_handle, hash_digest, hash_digest_size, signature, signature_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed during cs_asymmetric_verify");

exit:

    if (kcm_handle != 0) {
        close_handle_status = storage_key_close_handle(&kcm_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((close_handle_status != KCM_STATUS_SUCCESS && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Failed during storage_close_handle");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e kcm_generate_random(uint8_t *buffer, size_t buffer_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    palStatus_t pal_status;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((buffer == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid buffer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((buffer_size == 0), KCM_STATUS_INVALID_PARAMETER, "invalid buffer_size");

    pal_status = pal_osRandomBuffer(buffer,buffer_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status == FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED), KCM_CRYPTO_STATUS_ENTROPY_MISSING, "Failed generate random buffer (%" PRIu32 ")", pal_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != FCC_PAL_SUCCESS), KCM_STATUS_ERROR, "Failed generate random buffer (%" PRIu32 ")", pal_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e kcm_ecdh_key_agreement(const uint8_t *private_key_name, size_t private_key_name_len, const uint8_t *peer_public_key, size_t peer_public_key_size,
                                    uint8_t *shared_secret, size_t shared_secret_max_size, size_t *shared_secret_act_size_out)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e close_handle_status;
    kcm_key_handle_t kcm_handle;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }

    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((peer_public_key == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid peer_public_key");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((peer_public_key_size == 0), KCM_STATUS_INVALID_PARAMETER, "invalid peer_public_key_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((shared_secret == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid shared_secret");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((shared_secret_max_size < KCM_EC_SECP256R1_SHARED_SECRET_SIZE), KCM_STATUS_INVALID_PARAMETER, "invalid shared_secret_max_size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((shared_secret_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "invalid shared_secret_act_size_out");

    //Call storage_get_handle to get handle of the private key.
    kcm_status = storage_key_get_handle(private_key_name, private_key_name_len, KCM_PRIVATE_KEY_ITEM, STORAGE_ITEM_PREFIX_KCM, &kcm_handle);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during storage_key_get_handle");

    //Call cs_ecdh_key_agreement to calculate shared secret
    kcm_status = cs_ecdh_key_agreement(kcm_handle, peer_public_key, peer_public_key_size, shared_secret, shared_secret_max_size, shared_secret_act_size_out);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed during cs_ecdh_key_agreement");

exit:

    if (kcm_handle != 0) {
        close_handle_status = storage_key_close_handle(&kcm_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((close_handle_status != KCM_STATUS_SUCCESS && kcm_status == KCM_STATUS_SUCCESS), KCM_STATUS_ERROR, "Failed during storage_close_handle");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


