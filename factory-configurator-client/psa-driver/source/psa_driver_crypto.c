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
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "psa_driver.h"
#include "psa/protected_storage.h"
#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "key_slot_allocator.h"
#include "pv_error_handling.h"
#include "cs_der_keys_and_csrs.h"
#include "pv_macros.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#include "se_slot_manager.h"
#include "se_driver_config.h"
#endif

/*============================================== Static functions CRYPTO driver implementation =========================================*/
static kcm_status_e psa_import_or_generate(const void* raw_data,
                                            size_t raw_data_size,
                                            psa_key_attributes_t *psa_key_attr,
                                            psa_key_handle_t* psa_key_handle)
{
    psa_status_t psa_status = PSA_SUCCESS;

    if (raw_data_size != 0) {//if data size is not 0 perform import
        //Import the key
        psa_status = psa_import_key(psa_key_attr, raw_data, raw_data_size, psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS),
                                        psa_drv_translate_to_kcm_error(psa_status), "Failed to import the key (%" PRIi32 ")", (int32_t)psa_status);
    } else {
        // Generate the key 
        psa_status = psa_generate_key(psa_key_attr, psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS),
                                        psa_drv_translate_to_kcm_error(psa_status), "Failed to generate a key (%" PRIi32 ")", (int32_t)psa_status);
    }
    return KCM_STATUS_SUCCESS;
}

/* The function set algorithm, usage, type and size attributes of the item */
static void set_generic_attr(uint32_t extra_flags, psa_key_attributes_t *psa_key_attr)
{
    psa_key_usage_t psa_key_usage;

    //Set size
    psa_set_key_bits(psa_key_attr, PSA_BYTES_TO_BITS(32));

    //Set key type and usage
    if ((extra_flags&PSA_CRYPTO_TYPE_MASK_FLAG) == PSA_CRYPTO_PRIVATE_KEY_FLAG) {
        // set key type
        psa_set_key_type(psa_key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));
        psa_key_usage = (PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY);

    } else { // PSA_CRYPTO_PUBLIC_KEY_FLAG
             // set key type
        psa_set_key_type(psa_key_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1));
        psa_key_usage = (PSA_KEY_USAGE_VERIFY);
    }

    //Set algorithm and usage flags
#if !defined(TARGET_LPC55S69_NS)
    /* FIXME - we should skip this if key should be generated into secure element */
    /* FIXME: currently, mbed-os has no SPM (Secure Partitioning Manager) support for LPC55S69_NS platforms.
    *          that is why we mask the PSA multiple usage for those platforms, however, this workaround should be reverted once mbed-os
    *          team will add the necessary implementation to support the psa_key_policy_set_enrollment_algorithm API.
    */
    // Set policy for ECDH (key agreement)
    psa_key_usage |= (PSA_KEY_USAGE_DERIVE);
#endif

    // set key usage
    psa_set_key_usage_flags(psa_key_attr, psa_key_usage);
    // set key algorithm
    psa_set_key_algorithm(psa_key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
#if !defined(TARGET_LPC55S69_NS)
    psa_set_key_enrollment_algorithm(psa_key_attr, PSA_ALG_ECDH);
#endif
}

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
/*The function set SE and generic attributes : slot, lifetime, size, type and usage */
static void set_se_attr(psa_key_attributes_t *psa_key_attr, psa_key_slot_number_t slot_number, psa_key_id_t psa_id)
{
    //Set SE lifetime
    psa_set_key_lifetime(psa_key_attr, PSA_DRIVER_SE_DRIVER_LIFETIME_VALUE);

    // set key id in key attribute
    psa_set_key_id(psa_key_attr, (psa_key_id_t)psa_id);

    //Set physical slot number of the SE item
    psa_set_key_slot_number(psa_key_attr, (psa_key_slot_number_t)slot_number);
}

static kcm_status_e import_or_generate_se_item(const void* raw_data,
                                          size_t raw_data_size,
                                          uint32_t extra_flags,
                                          psa_key_attributes_t *psa_key_attr,
                                          uint16_t *ksa_id,
                                          psa_key_handle_t* psa_key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint64_t slot_id = 0;
    uint16_t psa_id = 0;
    uint16_t num_of_slots;

    SA_PV_LOG_TRACE_FUNC_ENTER("extra_flags = %" PRIu32 "", extra_flags);

    *ksa_id = PSA_INVALID_SLOT_ID;

    //Get number of slots for current type
    kcm_status = sem_get_num_of_slots(extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG, &num_of_slots);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get num of aslots");

    for (size_t slot_index = 0; slot_index < num_of_slots; slot_index++) {
        //Get current slot and psa id
        kcm_status = sem_get_next_slot_and_psa_id(extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG, &slot_id, &psa_id);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get slot and id");

        //Set SE attributes - slot id and psa id
        set_se_attr(psa_key_attr, slot_id, psa_id);

        kcm_status =psa_import_or_generate(raw_data, raw_data_size, psa_key_attr, psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_FILE_EXIST), kcm_status, "Failed to perfomrm psa operation");

        if (kcm_status == KCM_STATUS_FILE_EXIST) {
            // key with that id already exists. try with next id
            continue;
        }// else, succeeded  to generate a key with psa_id

        *ksa_id = psa_id;
        break;
    }

    // set error if no free id found
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*ksa_id == PSA_INVALID_SLOT_ID), kcm_status = KCM_STATUS_OUT_OF_MEMORY, "Failed to find free id");
    SA_PV_LOG_TRACE_FUNC_EXIT("ksa_id = %" PRIu16, *ksa_id);
    return kcm_status;
}
#endif
/**
* Internal API to import/generate keys based on an provided attributes and returns it's opened id and handle.
* The registration performed only for secure element items.
*    @param[in] raw_data  key data to import.
*    @param[in] raw_data_size  key data size. if 0, generate new key
*    @param[in] psa_key_attr  key's attributes to be used
*    @param[out] ksa_id  The KSA PSA id of the new imported/generated key.
*    @param[out] psa_key_handle  The new key handle of the new key.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e import_or_generate_item(const void* raw_data,
                                       size_t raw_data_size,
                                       psa_key_attributes_t *psa_key_attr,
                                       uint16_t *ksa_id,
                                       psa_key_handle_t* psa_key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    uint16_t id = PSA_CRYPTO_MIN_ID_VALUE - 1;
    size_t actual_data_size = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // get last used id
    psa_status = psa_ps_get((psa_storage_uid_t)PSA_PS_LAST_USED_CRYPTO_ID, 0, sizeof(id), &id, &actual_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_DOES_NOT_EXIST) ||
        (psa_status == PSA_SUCCESS && actual_data_size != sizeof(id)),
                                    psa_drv_translate_to_kcm_error(psa_status), "Failed to get last used id data (%" PRIi32 ")", (int32_t)psa_status);

    for (size_t i = 0; i < PSA_CRYPTO_NUM_OF_ID_ENTRIES_FOR_NON_SE_ITEMS; i++) {//Use only range of ids for non SE items
        // advance id by 1, if needed, wrap around id
        id++;
        if (id > PSA_CRYPTO_NUM_OF_ID_ENTRIES_FOR_NON_SE_ITEMS) {
            id = PSA_CRYPTO_MIN_ID_VALUE;
        }

        // set key id in key attribute (this also set key lifetime to persistent)
        psa_set_key_id(psa_key_attr, (psa_key_id_t)id);


        kcm_status = psa_import_or_generate(raw_data, raw_data_size, psa_key_attr, psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_FILE_EXIST), kcm_status, "Failed to perfomrm psa operation");

        if (kcm_status == KCM_STATUS_FILE_EXIST) {
            // key with that id already exists. try with next id
            continue;
        }
        // else, succeeded  to import/generate/register key with psa_id

        // Save used id
        kcm_status = psa_drv_ps_set_data_direct(PSA_PS_LAST_USED_CRYPTO_ID, &id, sizeof(id), PSA_PS_CONFIDENTIALITY_FLAG);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to save last used id data");

        // update out ksa_id
        *ksa_id = id;

        // finish, break from for loop
        break;
    }

    // set error if no free id found
    SA_PV_ERR_RECOVERABLE_GOTO_IF((*ksa_id == PSA_INVALID_SLOT_ID), kcm_status = KCM_STATUS_OUT_OF_MEMORY, exit, "Failed to find free id");
exit:
    // on error, destroy created key and reset out params
    if (kcm_status != KCM_STATUS_SUCCESS && *psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        psa_destroy_key(*psa_key_handle);
        *ksa_id = PSA_INVALID_SLOT_ID;
        *psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT("ksa_id = %" PRIu16, *ksa_id);
    return kcm_status;
}

/*============================================== main flow CRYPTO driver implementation =========================================*/
kcm_status_e psa_drv_crypto_init(void)
{
    psa_status_t psa_status = PSA_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    psa_status = psa_crypto_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to initialize crypto module");

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
    //Register se driver
    psa_status = psa_register_se_driver(PSA_DRIVER_SE_DRIVER_LIFETIME_VALUE, g_se_driver_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != psa_status), psa_drv_translate_to_kcm_error(psa_status), "Failed psa_register_se_driver (%" PRIu32 ")", (uint32_t)psa_status);
#endif
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
kcm_status_e psa_drv_crypto_register(uint32_t extra_flags, uint64_t slot_number, uint16_t *ksa_id)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_key_attributes_t psa_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint16_t temp_ksa_id = 0;
    psa_status_t psa_status = PSA_SUCCESS;

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG) != PSA_CRYPTO_PUBLIC_KEY_FLAG &&
        (extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG) != PSA_CRYPTO_PRIVATE_KEY_FLAG), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((extra_flags & PSA_CRYPTO_LOCATION_MASK_FLAG) != PSA_CRYPTO_SECURE_ELEMENT_LOCATION_FLAG), KCM_STATUS_INVALID_PARAMETER, "Invalid location type");
    SA_PV_LOG_TRACE_FUNC_ENTER("slot_number = %" PRIu64, slot_number);


    //Get the specific psa id for current slot
    kcm_status = sem_get_preprovisioned_psa_id(slot_number, &temp_ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to find psa id for preprovisioned item");

    //Set generic attributes
    set_generic_attr(extra_flags, &psa_key_attr);

    //Set SE attributes
    set_se_attr(&psa_key_attr, slot_number, temp_ksa_id);

    //Register SE item
    psa_status = mbedtls_psa_register_se_key(&psa_key_attr);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_ALREADY_EXISTS),
                                    kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit,"Failed to register a SE key (%" PRIi32 ")", (int32_t)psa_status);

exit:
    // reset psa_key_attr to free resources the structure may contain
    psa_reset_key_attributes(&psa_key_attr);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *ksa_id = temp_ksa_id;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT("ksa_id = %" PRIu16, *ksa_id);
    return kcm_status;
}
#endif

kcm_status_e psa_drv_crypto_import_or_generate(const void* data, size_t data_size, uint32_t extra_flags, uint16_t *ksa_id)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_handle_t psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    psa_key_attributes_t psa_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t raw_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE]; // should be bigger than KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE
    size_t raw_key_act_size = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG) != PSA_CRYPTO_PUBLIC_KEY_FLAG &&
        (extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG) != PSA_CRYPTO_PRIVATE_KEY_FLAG), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG) == PSA_CRYPTO_PUBLIC_KEY_FLAG  && data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid data pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((data != NULL && data_size == 0) && (extra_flags & PSA_CRYPTO_GENERATION_MASK_FLAG) == PSA_CRYPTO_GENERATION_FLAG), KCM_STATUS_INVALID_PARAMETER, "Invalid data size");
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((extra_flags & PSA_CRYPTO_LOCATION_MASK_FLAG) == PSA_CRYPTO_SECURE_ELEMENT_LOCATION_FLAG), KCM_STATUS_INVALID_PARAMETER, "Invalid location type");
#endif

    // initialize out params to invalid values
    *ksa_id = PSA_INVALID_SLOT_ID;

    if (data != NULL) {
        // Convert key from DER to RAW representation before importing to PSA
        if ((extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG) == PSA_CRYPTO_PRIVATE_KEY_FLAG) {
            kcm_status = cs_priv_key_get_der_to_raw(data, data_size, raw_key, sizeof(raw_key), &raw_key_act_size);
        } else { //key_type == PSA_CRYPTO_PUBLIC_KEY_FLAG
            kcm_status = cs_pub_key_get_der_to_raw(data, data_size, raw_key, sizeof(raw_key), &raw_key_act_size);
        }
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed converting EC key from DER to RAW");
    }

    //Set item attributes
    set_generic_attr(extra_flags, &psa_key_attr);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
    if ((extra_flags & PSA_CRYPTO_LOCATION_MASK_FLAG) == PSA_CRYPTO_SECURE_ELEMENT_LOCATION_FLAG) {
        //SE generate item
        kcm_status = import_or_generate_se_item(raw_key, raw_key_act_size, extra_flags, &psa_key_attr, ksa_id, &psa_key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to assign SE item");
    } else
#endif 
    {
        //Assign item
        kcm_status = import_or_generate_item(raw_key, raw_key_act_size, &psa_key_attr, ksa_id, &psa_key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to assign SE item");
    }

exit:
    // reset psa_key_attr to free resources the structure may contain
    psa_reset_key_attributes(&psa_key_attr);

    if (kcm_status == KCM_STATUS_SUCCESS && psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {

        // Close new key handle. Not need it anymore.
        psa_status = psa_close_key(psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT("ksa_id = %" PRIu16, *ksa_id);
    return kcm_status;
}

kcm_status_e psa_drv_crypto_export_data(const uint16_t ksa_id, void* data, size_t data_size, size_t* actual_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_handle_t psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    uint8_t raw_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE];
    size_t raw_key_act_size;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL || data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid data buffer parameters");

    //Open key handle
    psa_status = psa_open_key((psa_key_id_t)ksa_id, &psa_key_handle);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF(psa_status == PSA_ERROR_DOES_NOT_EXIST, psa_drv_translate_to_kcm_error(psa_status), "Item not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to open the key handle");

    //Export the key
    psa_status = psa_export_public_key(psa_key_handle, (uint8_t*)raw_key, sizeof(raw_key), &raw_key_act_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed export PSA key data");

    // Convert key from RAW representation to DER
    kcm_status = cs_pub_key_get_raw_to_der(raw_key, raw_key_act_size, data, data_size, actual_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed converting EC key from RAW to DER");

exit:
    if (psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        //Close a key handle.
        psa_status = psa_close_key(psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e psa_drv_crypto_export_data_size(const uint16_t ksa_id, size_t* actual_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t raw_pub_key[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    size_t actual_size = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);

    //TODO : use location_type_flag to get certificate or key
    kcm_status = psa_drv_crypto_export_data((psa_key_id_t)ksa_id, raw_pub_key, sizeof(raw_pub_key), &actual_size);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF(kcm_status == KCM_STATUS_ITEM_NOT_FOUND, kcm_status, "Item not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status, "Failed to get data from id %d", ksa_id);

    *actual_data_size = actual_size;

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_crypto_destroy(const uint16_t ksa_id)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_handle_t psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);

    //TODO : use location_type_flag to get certificate or key
    //Open key handle
    psa_status = psa_open_key((psa_key_id_t)ksa_id, &psa_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), "Failed to open the key handle");

    psa_status = psa_destroy_key(psa_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), "Failed to destroy key at id %d", ksa_id);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e psa_drv_crypto_generate_keys_from_existing_ids(const uint16_t exist_prv_ksa_id,
                                                            const uint16_t exist_pub_ksa_id,
                                                            uint16_t* new_prv_ksa_id,
                                                            uint16_t* new_pub_ksa_id,
                                                            psa_key_handle_t* new_prv_psa_key_handle,
                                                            psa_key_handle_t* new_pub_psa_key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_attributes_t psa_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t exist_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    size_t actual_data_size = 0;
    uint8_t raw_pub_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE];
    //uint32_t extra_flags = PSA_CRYPTO_GENERATION_FLAG;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_prv_ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (exist_prv_ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "exist_prv_ksa_id invalid range %d", exist_prv_ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_pub_ksa_id != PSA_INVALID_SLOT_ID) && ((exist_pub_ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (exist_pub_ksa_id > PSA_CRYPTO_MAX_ID_VALUE)), KCM_STATUS_INVALID_PARAMETER, "exist_pub_ksa_id invalid range %d", exist_pub_ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((new_prv_ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_prv_ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_pub_ksa_id != PSA_INVALID_SLOT_ID) && (new_pub_ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_pub_ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((new_prv_psa_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_prv_psa_key_handle pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_pub_ksa_id != PSA_INVALID_SLOT_ID) && (new_pub_psa_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_pub_psa_key_handle pointer");

    // Open existing private key
    psa_status = psa_open_key((psa_key_id_t)exist_prv_ksa_id, &exist_psa_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to open the existing private key (%" PRIi32 ")", (int32_t)psa_status);

    // Get attr of the exiting private key.
    psa_status = psa_get_key_attributes(exist_psa_key_handle, &psa_key_attr);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed to get key's attributes (%" PRIi32 ")", (int32_t)psa_status);

    // Close existing private key handle
    psa_status = psa_close_key(exist_psa_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    exist_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

    // generate new keypair
    kcm_status = import_or_generate_item(NULL, 0, &psa_key_attr, new_prv_ksa_id, new_prv_psa_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate new private key");

    if (exist_pub_ksa_id != PSA_INVALID_SLOT_ID) {
        // export also public key

        // reset psa_key_attr to free resources the structure may contain
        psa_reset_key_attributes(&psa_key_attr);

        // Open existing public key
        psa_status = psa_open_key((psa_key_id_t)exist_pub_ksa_id, &exist_psa_key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed to open the existing public key (%" PRIi32 ")", (int32_t)psa_status);

        // Get attr of the exiting public key.
        psa_status = psa_get_key_attributes(exist_psa_key_handle, &psa_key_attr);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed to get key's attributes (%" PRIi32 ")", (int32_t)psa_status);

        // Close existing public key handle
        psa_status = psa_close_key(exist_psa_key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
        exist_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

        // Export public key form the newly generated private key
        psa_status = psa_export_public_key(*new_prv_psa_key_handle, (uint8_t*)raw_pub_key, sizeof(raw_pub_key), &actual_data_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit, "Failed to export PSA key data (%" PRIi32 ")", (int32_t)psa_status);

        // import public key data
        kcm_status = import_or_generate_item(raw_pub_key, actual_data_size, &psa_key_attr, new_pub_ksa_id, new_pub_psa_key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to import public key");
    }

exit:
    // if failed during import public, destroy generated private key
    if (kcm_status != KCM_STATUS_SUCCESS && new_prv_psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        psa_destroy_key(*new_prv_psa_key_handle);
        *new_prv_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    }

    // reset psa_key_attr to free resources the structure may contain
    psa_reset_key_attributes(&psa_key_attr);

    // cleanup
    if (exist_psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        // Close key handle if needed
        psa_status = psa_close_key(exist_psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

void psa_drv_crypto_fini(void)
{

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    mbedtls_psa_crypto_free();

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return;
}

kcm_status_e psa_drv_crypto_get_handle(uint16_t key_id, psa_key_handle_t *key_handle_out)
{
    psa_status_t psa_status = PSA_SUCCESS;

    //TODO: check correct range one we move to KSA table for all items
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_id == PSA_INVALID_SLOT_ID || key_id > KSA_MAX_PSA_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "Invalid key id ");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Wrong key handle pointer");

    //Open key handle
    psa_status = psa_open_key(key_id, key_handle_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to open the key with  ");

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_crypto_close_handle(psa_key_handle_t key_handle)
{
    psa_status_t psa_status = PSA_SUCCESS;

    //Close key handle
    psa_status = psa_close_key(key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to close the key");

    return KCM_STATUS_SUCCESS;
}


#if defined(MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT)
kcm_status_e psa_drv_crypto_se_private_key_get_slot(uint16_t psa_prv_key_id, uint64_t *se_prv_key_id)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_key_attributes_t psa_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t exist_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

    SA_PV_LOG_TRACE_FUNC_ENTER("psa_prv_key_id = %" PRIu16 "", psa_prv_key_id);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((se_prv_key_id == NULL), KCM_STATUS_INVALID_PARAMETER, "se_prv_key_id can't be NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_prv_key_id < PSA_CRYPTO_MIN_ID_VALUE) || (psa_prv_key_id > PSA_CRYPTO_MAX_ID_VALUE),
                                    KCM_STATUS_INVALID_PARAMETER, "psa_prv_key_id invalid range %u", psa_prv_key_id);

    // get handle to psa private key
    psa_status_t psa_status = psa_open_key(psa_prv_key_id, &exist_psa_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status),
                                    "Failed to open the existing private key (%" PRIi32 ")", (int32_t)psa_status);

    // get attributes of the key using the handle
    psa_status = psa_get_key_attributes(exist_psa_key_handle, &psa_key_attr);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit,
                                  "Failed to get key's attributes (%" PRIi32 ")", (int32_t)psa_status);

    psa_key_slot_number_t slot_number = 0;
    // call psa_get_key_slot_number to get a physical SE slot number using the key attributes
    psa_status = psa_get_key_slot_number(&psa_key_attr, &slot_number);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), exit,
                                  "Failed to get key slot number (%" PRIi32 ")", (int32_t)psa_status);

exit:

    // reset psa_key_attr to free resources the structure may contain
    psa_reset_key_attributes(&psa_key_attr);

    // close key handle
    psa_status = psa_close_key(exist_psa_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status),
                                    "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    exist_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

    if (kcm_status == KCM_STATUS_SUCCESS) {
        *se_prv_key_id = slot_number;
        SA_PV_LOG_TRACE_FUNC_EXIT("returning se_prv_key_id = %" PRIu64, *se_prv_key_id);
    } else {
        SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    }

    return kcm_status;
}
#endif //MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
