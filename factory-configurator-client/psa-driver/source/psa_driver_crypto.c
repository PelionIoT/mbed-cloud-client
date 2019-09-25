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

kcm_status_e psa_drv_crypto_init(void)
{
    psa_status_t psa_status = PSA_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    psa_status = psa_crypto_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to initialize crypto module");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return KCM_STATUS_SUCCESS;
}


/**
* internal API to import/generate keys based on an provided attributes and returns it's opened id and handle.
*
*    @param[in] raw_data  key data to import.
*    @param[in] raw_data_size  key data size. if 0, generate new key
*    @param[in] psa_key_attr  key's attributes to be used
*    @param[out] ksa_id  The KSA PSA id of the new imported/generated key.
*    @param[out] psa_key_handle  The new key handle of the new key.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e import_key_by_atrr( const void* raw_data, size_t raw_data_size, psa_key_attributes_t *psa_key_attr, uint16_t *ksa_id, psa_key_handle_t* psa_key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    uint16_t id = PSA_CRYPTO_MIN_ID_VALUE - 1;
    size_t actual_data_size = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // initialize out params to invalid values
    *ksa_id = PSA_INVALID_ID_NUMBER;
    *psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

    // get last used id
    psa_status = psa_ps_get((psa_storage_uid_t)PSA_PS_LAST_USED_CRYPTO_ID, 0, sizeof(id), &id, &actual_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_DOES_NOT_EXIST) ||
                                    (psa_status == PSA_SUCCESS && actual_data_size != sizeof(id)),
                                    psa_drv_translate_to_kcm_error(psa_status), "Failed to get last used id data (%" PRIi32 ")", (int32_t)psa_status);
    
    for (size_t i = 0; i < PSA_CRYPTO_NUM_OF_ID_ENTRIES; i++)
    {
        // advance id by 1, if needed, wrap around id
        id++;
        if (id > PSA_CRYPTO_MAX_ID_VALUE) {
            id = PSA_CRYPTO_MIN_ID_VALUE;
        }

        // set key id in key attr (this also set key lifetime to persistent)
        psa_set_key_id(psa_key_attr, (psa_key_id_t)id);

        if (raw_data_size == 0) {
            
            // Generate the key 
            psa_status = psa_generate_key(psa_key_attr, psa_key_handle);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_ALREADY_EXISTS), 
                psa_drv_translate_to_kcm_error(psa_status), "Failed to generate a key (%" PRIi32 ")", (int32_t)psa_status);
        } else {

            //Import the key
            psa_status = psa_import_key(psa_key_attr, raw_data, raw_data_size, psa_key_handle);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS && psa_status != PSA_ERROR_ALREADY_EXISTS), 
                psa_drv_translate_to_kcm_error(psa_status), "Failed to import the key (%" PRIi32 ")", (int32_t)psa_status);
        }

        if (psa_status == PSA_ERROR_ALREADY_EXISTS) {
            // key with that id already exists. try with next id
            continue;
        }
        // else, success to import/generate key with psa_id

        // Save used id
        kcm_status = psa_drv_ps_set_data_direct(PSA_PS_LAST_USED_CRYPTO_ID, &id, sizeof(id), PSA_PS_CONFIDENTIALITY_FLAG);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to save last used id data");

        // update out ksa_id
        *ksa_id = id;

        // finish, break from for loop
        break;
    }

    // set error if no free id found
    SA_PV_ERR_RECOVERABLE_GOTO_IF((*ksa_id == PSA_INVALID_ID_NUMBER), kcm_status = KCM_STATUS_OUT_OF_MEMORY, exit, "Failed to find free id");
exit:
    // on error, destroy created key and reset out params
    if (kcm_status != KCM_STATUS_SUCCESS && *psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        psa_destroy_key(*psa_key_handle);
        *ksa_id = PSA_INVALID_ID_NUMBER;
        *psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e psa_drv_crypto_import( const void* data, size_t data_size, uint32_t extra_flags, uint16_t *ksa_id)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_handle_t psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    psa_key_attributes_t psa_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint32_t item_type_flag = extra_flags & PSA_CRYPTO_TYPE_MASK_FLAG;
    uint8_t raw_key[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE]; // should be bigger than KCM_EC_SECP256R1_MAX_PRIV_KEY_RAW_SIZE
    size_t raw_key_act_size = 0;
    psa_key_usage_t psa_key_usage;

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_type_flag != PSA_CRYPTO_PUBLIC_KEY_FLAG &&
                                    item_type_flag != PSA_CRYPTO_PRIVATE_KEY_FLAG), KCM_STATUS_INVALID_PARAMETER, "Invalid item type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_type_flag == PSA_CRYPTO_PUBLIC_KEY_FLAG  && data == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid data pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data != NULL && data_size == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid data size");
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    if (data != NULL) { // import
        // Convert key from DER to RAW representation before importing to PSA
        if (item_type_flag == PSA_CRYPTO_PRIVATE_KEY_FLAG) {
            kcm_status = cs_priv_key_get_der_to_raw(data, data_size, raw_key, sizeof(raw_key), &raw_key_act_size);
        } else { //key_type == PSA_CRYPTO_PUBLIC_KEY_FLAG
            kcm_status = cs_pub_key_get_der_to_raw(data, data_size, raw_key, sizeof(raw_key), &raw_key_act_size);
        }
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed converting EC key from DER to RAW");
    } else { // generate
        // set key size
        psa_set_key_bits(&psa_key_attr, PSA_BYTES_TO_BITS(32));
    }

    if (item_type_flag == PSA_CRYPTO_PRIVATE_KEY_FLAG) {
        // set key type
        psa_set_key_type(&psa_key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1));
        psa_key_usage = (PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY);

    } else { // PSA_CRYPTO_PUBLIC_KEY_FLAG
        // set key type
        psa_set_key_type(&psa_key_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1));
        psa_key_usage = (PSA_KEY_USAGE_VERIFY);

    }

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
    psa_set_key_usage_flags(&psa_key_attr, psa_key_usage);
    // set key algorithm
    psa_set_key_algorithm(&psa_key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
#if !defined(TARGET_LPC55S69_NS)
    psa_set_key_enrollment_algorithm(&psa_key_attr, PSA_ALG_ECDH);
#endif

    kcm_status = import_key_by_atrr(raw_key, raw_key_act_size, &psa_key_attr, ksa_id, &psa_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to import/generate new key");

exit:
    // reset psa_key_attr to free resources the structure may contain
    psa_reset_key_attributes(&psa_key_attr);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        // Close new key handle. Not need it anymore.
        psa_status = psa_close_key(psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), psa_drv_translate_to_kcm_error(psa_status), "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    }
    // else, handle should be closed

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
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
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

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

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

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

    //Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "ksa_id is in invalid range %d", ksa_id);
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

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

    // Check parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_prv_ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (exist_prv_ksa_id > PSA_CRYPTO_MAX_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "exist_prv_ksa_id invalid range %d", exist_prv_ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_pub_ksa_id != PSA_INVALID_ID_NUMBER) && ((exist_pub_ksa_id < PSA_CRYPTO_MIN_ID_VALUE) || (exist_pub_ksa_id > PSA_CRYPTO_MAX_ID_VALUE)), KCM_STATUS_INVALID_PARAMETER, "exist_pub_ksa_id invalid range %d", exist_pub_ksa_id);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((new_prv_ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_prv_ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_pub_ksa_id != PSA_INVALID_ID_NUMBER) && (new_pub_ksa_id == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_pub_ksa_id pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((new_prv_psa_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_prv_psa_key_handle pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((exist_pub_ksa_id != PSA_INVALID_ID_NUMBER) && (new_pub_psa_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid new_pub_psa_key_handle pointer");

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

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
    kcm_status = import_key_by_atrr(NULL, 0, &psa_key_attr, new_prv_ksa_id, new_prv_psa_key_handle);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to generate new private key");

    if (exist_pub_ksa_id != PSA_INVALID_ID_NUMBER) {
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
        kcm_status = import_key_by_atrr(raw_pub_key, actual_data_size, &psa_key_attr, new_pub_ksa_id, new_pub_psa_key_handle);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to import public key");
    }

exit:
    // if failed during import public, destroy generated private key
    if (kcm_status != KCM_STATUS_SUCCESS && new_prv_psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        psa_destroy_key(*new_prv_psa_key_handle);
        *new_prv_psa_key_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
    }
    // cleanup
    if (exist_psa_key_handle != PSA_CRYPTO_INVALID_KEY_HANDLE) {
        // Close key handle if needed
        psa_status = psa_close_key(exist_psa_key_handle);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), kcm_status = psa_drv_translate_to_kcm_error(psa_status), "Failed to close a key handle (%" PRIi32 ")", (int32_t)psa_status);
    }
    // reset psa_key_attr to free resources the structure may contain
    psa_reset_key_attributes(&psa_key_attr);

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
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_id == PSA_INVALID_ID_NUMBER || key_id > KSA_MAX_PSA_ID_VALUE), KCM_STATUS_INVALID_PARAMETER, "Invalid key id ");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Wrong key handle pointer");

    //Open key handle
    psa_status = psa_open_key(key_id, key_handle_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle_out == NULL), psa_drv_translate_to_kcm_error(psa_status), "Failed to open the key with  ");

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
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
