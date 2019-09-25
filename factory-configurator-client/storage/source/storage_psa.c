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

#include <stdbool.h>
#include "key_slot_allocator.h"
#include "pv_error_handling.h"
#include "storage_items.h"
#include "storage_keys.h"
#include "storage_internal.h"
#include "pv_macros.h"
#ifdef TARGET_LIKE_MBED
#include "psa/lifecycle.h"
#endif
#include "psa/crypto_types.h"
#include "psa/crypto.h"
#include "fcc_malloc.h"
#include "storage_internal.h"


extern bool g_kcm_initialized;


#define STORAGE_PSA_WRITE_ONCE_BIT                  (0x1 << 0)
#define STORAGE_PSA_CONFIDENTIALITY_BIT             (0x1 << 1)
#define STORAGE_PSA_REPLAY_PROTECTION_BIT           (0x1 << 2)

//TODO: remove this after sst defines moved to h file
#define STORAGE_CHAIN_CERTIFICATE_INDEX_OFFSET_IN_PREFIX 3  //a,b,c,.. ==> Crta__, Crtb__,
#define STORAGE_CHAIN_CERTIFICATE_END_SIGN_OFFSET_IN_PREFIX 4  // e ==> Crtae_
#define STORAGE_CHAIN_CERTIFICATE_END_OFFSET_IN_NAME  strlen(KCM_FILE_PREFIX_CERTIFICATE)//6 Size of certificate chain prefixes,the same for all chain certificates


static kcm_status_e build_key_pair_working_complete_names(
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    uint8_t                           *complete_private_key_name,
    size_t                            *complete_private_key_name_len,
    uint8_t                           *complete_public_key_name,
    size_t                            *complete_public_key_name_len,
    storage_item_prefix_type_e        item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    //Create complete data names
    kcm_status = storage_build_complete_working_item_name(KCM_PRIVATE_KEY_ITEM,
                                                          item_prefix_type,
                                                          private_key_name,
                                                          private_key_name_len,
                                                          (char*)complete_private_key_name,
                                                          complete_private_key_name_len,
                                                          NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

    if (public_key_name != NULL) {
        kcm_status = storage_build_complete_working_item_name(KCM_PUBLIC_KEY_ITEM,
                                                              item_prefix_type,
                                                              public_key_name,
                                                              public_key_name_len,
                                                              (char*)complete_public_key_name,
                                                              complete_public_key_name_len,
                                                              NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");
    }

    return kcm_status;

}


static kcm_status_e storage_get_first_cert_in_chain_name_and_info(storage_item_prefix_type_e item_prefix_type,
                                                                  const uint8_t *kcm_item_name,
                                                                  size_t kcm_item_name_len,
                                                                  char *kcm_complete_name,
                                                                  size_t kcm_complete_name_len,
                                                                  size_t *item_data_act_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_info_s cert_chain_info = { 0 };
    cert_chain_info.certificate_index = 0;
    cert_chain_info.is_last_certificate = false;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_complete_name_len != STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH || kcm_complete_name == NULL), kcm_status = KCM_STATUS_INVALID_PARAMETER, "Wrong kcm_complete_name parameter");

    //Change complete certificate name to first certificate in chain with the same name
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, NULL, &cert_chain_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to change single certificate name");

    //Fetch size
    kcm_status = ksa_item_get_data_size((const uint8_t *)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM, item_data_act_size);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF(kcm_status == KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, "Fist cert in chain was not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, kcm_status = kcm_status, "Failed to check existence");

    SA_PV_LOG_WARN("Warning: The operation made on first certificate of the chain using single certificate API!");

    return kcm_status;
}


#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

static void set_item_location(const kcm_security_desc_s kcm_item_info, kcm_item_extra_info_s *item_extra_info_out)
{
    kcm_item_extra_info_s *item_extra_info = (kcm_item_extra_info_s *)kcm_item_info;

    if (item_extra_info != NULL) {
        // set the location as given by the caller
        item_extra_info_out->priv_key_location = item_extra_info->priv_key_location;
        item_extra_info_out->pub_key_location = item_extra_info->pub_key_location;
    }

    // if the user pass NULL for 'kcm_item_info' the default will be used as set by kcm_item_policy_init()
}


static kcm_status_e check_item_location(kcm_item_location_e item_location)
{
    switch (item_location) {
        case KCM_LOCATION_PSA:
        case KCM_LOCATION_SECURE_ELEMENT:
            return KCM_STATUS_SUCCESS;
        default:
            return KCM_STATUS_INVALID_PARAMETER;
    }
}

#endif


kcm_status_e storage_specific_init()
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //check if flag file exist
    kcm_status = ksa_item_check_existence((const uint8_t*)STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, strlen(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM), STORAGE_RBP_ITEM);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        //flag file was not found - positive scenario
        return KCM_STATUS_SUCCESS;
    } else if (kcm_status == KCM_STATUS_SUCCESS) {
        //flag file can be opened for reading
        //previous factory reset failed during execution
        //call factory reset to complete the process
        kcm_status = storage_factory_reset();
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e check_certificate_existance(const uint8_t *kcm_chain_name, size_t kcm_chain_name_len, storage_item_prefix_type_e item_prefix_type)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_chain_cert_info_s cert_name_info = { 0 };

    //Build complete name of single certificate with given certificate chain name
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, kcm_chain_name, kcm_chain_name_len, kcm_complete_name, NULL, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //If single certificate with the chain name is exists in the data base - return an error
    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");

    //Build complete name of first certificate name in the chain
    cert_name_info.certificate_index = 0;
    cert_name_info.is_last_certificate = false;
    kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, kcm_chain_name, kcm_chain_name_len, kcm_complete_name, NULL, &cert_name_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = KCM_STATUS_FILE_EXIST, "Data with the same name already exists");

    return kcm_status;
}


kcm_status_e set_certificates_info(storage_cert_chain_context_s *chain_context, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t cert_size;
    kcm_chain_cert_info_s cert_name_info = { 0, false };
    int certificate_index = 0;

    //Try to read all certificate in the chain, retrieve the number of certificates in the chain and their sizes
    for (certificate_index = 0; (certificate_index < KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN) && (cert_name_info.is_last_certificate == false); certificate_index++) {
        cert_name_info.certificate_index = (uint32_t)certificate_index;

        //Build certificate name according to its index in certificate chain
        kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

        SA_PV_LOG_INFO("kcm_complete_name %s", kcm_complete_name);

        //Try to read certificate as not last certificate
        kcm_status = ksa_item_get_data_size((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM, &cert_size);
        //If current name wasn't found, try to read the certificate as last one in the chain
        if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {

            cert_name_info.is_last_certificate = true;

            //Set the name certificate as last certificate in the chain
            kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, item_prefix_type, chain_context->chain_name, chain_context->chain_name_len, kcm_complete_name, NULL, &cert_name_info);

            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

            //retrieve item info (size and flags)
            kcm_status = ksa_item_get_data_size((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM, &cert_size);
            SA_PV_LOG_INFO("kcm_complete_name %s, %zu", kcm_complete_name, strlen(kcm_complete_name));
            //Indication for last certificate
            if (kcm_status == KCM_STATUS_SUCCESS) {
                cert_name_info.is_last_certificate = true;
            }

        }
        if (kcm_status == KCM_STATUS_ERROR) {
            return kcm_status;
        }
        SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), kcm_status = kcm_status, "item not found");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, "Failed ksa_item_get_data_size  (%" PRId16 ")", kcm_status);

        //Set in certificate info array the size of current index
        chain_context->certificates_info[certificate_index] = cert_size;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_name_info.is_last_certificate != true), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, "Failed to set size of certificate chain");

    chain_context->num_of_certificates_in_chain = (uint32_t)(certificate_index);
    return kcm_status;
}


void chain_delete(storage_cert_chain_context_s *chain_context, storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_chain_cert_info_s cert_name_info = { 0, false };
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };

    do {
        cert_name_info.certificate_index = chain_context->current_cert_index;

        //Set the name of the certificate in working
        kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM,
                                                              item_prefix_type,
                                                              chain_context->chain_name,
                                                              chain_context->chain_name_len,
                                                              kcm_complete_name,
                                                              NULL,
                                                              &cert_name_info);

        //we don't check the result of storage_file_delete, as it is possible that not all certificates were saved to the storage
        if (kcm_status == KCM_STATUS_SUCCESS) {
            ksa_item_delete((const uint8_t*)kcm_complete_name, strlen(kcm_complete_name), KCM_CERTIFICATE_ITEM);
        }

        if (chain_context->current_cert_index == 0) {
            break;
        }

        //
        chain_context->current_cert_index--;
    } while (true);
}


kcm_status_e storage_item_store_impl(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    bool kcm_item_is_factory,
    bool kcm_item_is_encrypted,
    storage_item_prefix_type_e item_prefix_type,
    const uint8_t *kcm_item_data,
    size_t kcm_item_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;
    uint32_t storage_flags = 0;
    ksa_type_location_e ksa_item_location = KSA_PSA_TYPE_LOCATION;

    SA_PV_LOG_INFO_FUNC_ENTER("kcm_item_name_len =%" PRIu32 " kcm_item_data_size =%" PRIu32 "", (uint32_t)kcm_item_name_len, (uint32_t)kcm_item_data_size);

    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    //set confidentiality flag if enabled
    if (kcm_item_is_encrypted) {
        storage_flags |= STORAGE_PSA_CONFIDENTIALITY_BIT;
    }

    kcm_status = ksa_item_store((const uint8_t *)kcm_complete_name, kcm_complete_name_len, storage_flags, kcm_item_type, kcm_item_data, kcm_item_data_size, ksa_item_location, kcm_item_is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed storing item in PSA (%u)", kcm_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e storage_item_get_data(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    uint8_t *item_data_out,
    size_t item_data_max_size,
    size_t *item_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;
    size_t item_data_act_size;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type == KCM_PRIVATE_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Private key fetch is not permitted");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 ", data max size = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len, (uint32_t)item_data_max_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_data_act_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_type != KCM_CONFIG_ITEM) && (item_data_out == NULL)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((kcm_item_type != KCM_CONFIG_ITEM) && (item_data_max_size == 0)), KCM_STATUS_INVALID_PARAMETER, "Provided kcm_item_data is empty");

    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_item_check_existence((const uint8_t *)kcm_complete_name, kcm_complete_name_len, kcm_item_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed getting item data from PSA store (%u)", kcm_status);

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
            kcm_status = storage_get_first_cert_in_chain_name_and_info(item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, sizeof(kcm_complete_name), &item_data_act_size);
            if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
                //We don't want print log in case the item wasn't found
                return kcm_status;
            }
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to check single certificate name");
        } else {//not certificate
            SA_PV_LOG_INFO("Item not found");
            return KCM_STATUS_ITEM_NOT_FOUND;
        }
    }

    kcm_status = ksa_item_get_data((const uint8_t *)kcm_complete_name, kcm_complete_name_len, (uint32_t)kcm_item_type, item_data_out, item_data_max_size, item_data_act_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting data from from PSA (%u)", kcm_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_item_get_data_size(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type,
    size_t *item_data_act_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t item_data_act_size = 0;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;


    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type == KCM_PRIVATE_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Private key fetch is not permitted");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_data_act_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Provided item_data_act_size_out is NULL");


    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_item_get_data_size((const uint8_t *)kcm_complete_name, kcm_complete_name_len, kcm_item_type, &item_data_act_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed getting item data from PSA store (%u)", kcm_status);

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
            kcm_status = storage_get_first_cert_in_chain_name_and_info(item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, sizeof(kcm_complete_name), &item_data_act_size);
            if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
                //We don't want print log in case the item wasn't found
                return kcm_status;
            }
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to check single certificate name");
        } else {//not certificate
            SA_PV_LOG_INFO("Item not found");
            return KCM_STATUS_ITEM_NOT_FOUND;
        }
    }

    // Set the effective data size for the caller
    *item_data_act_size_out = item_data_act_size;

    SA_PV_LOG_INFO_FUNC_EXIT("item_data_act_size_out =%" PRIu32 "", (uint32_t)(*item_data_act_size_out));

    return kcm_status;
}


palStatus_t storage_rbp_read(
    const char *item_name,
    uint8_t *data,
    size_t data_size,
    size_t *data_actual_size_out)
{
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;


    // Validate function parameters
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_LOG_INFO_FUNC_ENTER("item name =  %s", (char*)item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size == 0 || data_size > UINT16_MAX), PAL_ERR_INVALID_ARGUMENT, "Invalid data_length");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_actual_size_out == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid data_actual_size_out");

    //RPB item stored in separate table in KSA, so we don't care about its prefix. KCM_CONFIG_ITEM chosen randomly
    kcm_status = storage_build_complete_working_item_name(KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_KCM, (const uint8_t*)item_name, strlen(item_name), kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_name, kcm_complete_name_len, STORAGE_RBP_ITEM);
    SA_PV_TRACE_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), PAL_ERR_ITEM_NOT_EXIST, "Item not found");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), PAL_ERR_GENERIC_FAILURE, "Failed getting item data from PSA store (%u)", kcm_status);

    kcm_status = ksa_item_get_data((const uint8_t*)kcm_complete_name, kcm_complete_name_len, STORAGE_RBP_ITEM, data, data_size, data_actual_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(kcm_status != KCM_STATUS_SUCCESS, PAL_ERR_GENERIC_FAILURE, "Failed to get data");

    return pal_status;
}


palStatus_t storage_rbp_write(
    const char *item_name,
    const uint8_t *data,
    size_t data_size,
    bool is_write_once)
{
    uint32_t storage_flags = STORAGE_PSA_REPLAY_PROTECTION_BIT | STORAGE_PSA_CONFIDENTIALITY_BIT;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_name == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data_size > UINT16_MAX || data_size == 0), PAL_ERR_INVALID_ARGUMENT, "Invalid param data");
    SA_PV_LOG_INFO_FUNC_ENTER("data_size = %" PRIu32 " item_name = %s", (uint32_t)data_size, item_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((data == NULL), PAL_ERR_INVALID_ARGUMENT, "Invalid param data");

    if (is_write_once == true) {
        storage_flags |= STORAGE_PSA_WRITE_ONCE_BIT;
    }

    //RPB item stored in separate table in KSA, so we don't care about its prefix. KCM_CONFIG_ITEM chosen randomly
    kcm_status = storage_build_complete_working_item_name(KCM_CONFIG_ITEM, STORAGE_ITEM_PREFIX_KCM, (const uint8_t*)item_name, strlen(item_name), kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_item_store((const uint8_t *)kcm_complete_name, kcm_complete_name_len, storage_flags, STORAGE_RBP_ITEM, data, data_size, KSA_PSA_TYPE_LOCATION, false);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status == KCM_STATUS_NOT_PERMITTED), PAL_ERR_ITEM_EXIST, "rbp data write not permitted");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), PAL_ERR_GENERIC_FAILURE, "Failed to write rbp data");

    SA_PV_LOG_INFO_FUNC_EXIT();
    return pal_status;
}



kcm_status_e storage_generate_ce_keys(
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    kcm_key_handle_t                   *private_key_handle,
    kcm_key_handle_t                   *public_key_handle)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_priv_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_priv_name_size = 0;
    char kcm_complete_pub_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_pub_name_size = 0;
    uint8_t *kcm_complete_name_pointer = NULL;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name != NULL && public_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid public_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_handle");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name != NULL && public_key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid public_key_handle");
    SA_PV_LOG_TRACE_FUNC_ENTER("private_key_name = %.*s len = %" PRIu32 "", (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len);

    //Create complete key names of existing kcm keys
    kcm_status = build_key_pair_working_complete_names(private_key_name, private_key_name_len, public_key_name, public_key_name_len, (uint8_t*)kcm_complete_priv_name, &kcm_complete_priv_name_size, (uint8_t*)kcm_complete_pub_name, &kcm_complete_pub_name_size, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete keys names");

    if (public_key_name != NULL) {
        kcm_complete_name_pointer = (uint8_t*)&kcm_complete_pub_name;
    }

    kcm_status = ksa_generate_ce_keys((const uint8_t *)kcm_complete_priv_name,
                                      kcm_complete_priv_name_size,
                                      (const uint8_t*)kcm_complete_name_pointer,
                                      kcm_complete_pub_name_size,
                                      (psa_key_handle_t*)private_key_handle,
                                      (psa_key_handle_t*)public_key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed in ksa_generate_ce_keys");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}


kcm_status_e storage_item_copy(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e source_item_prefix_type,
    storage_item_prefix_type_e destination_item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_source_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    char kcm_destination_complete_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_destination_complete_name_len = 0;
    size_t kcm_complete_name_len = 0;
    kcm_cert_chain_handle kcm_source_chain_handle;
    size_t kcm_chain_len_out = 0;
    size_t max_index = 1;
    void* extra_param = NULL;
    kcm_chain_cert_info_s cert_name_info = { 0, false };

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((source_item_prefix_type != STORAGE_ITEM_PREFIX_KCM && source_item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid source_item_prefix_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((destination_item_prefix_type != STORAGE_ITEM_PREFIX_KCM && destination_item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid destination_item_prefix_type");

    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        //Open chain 
        kcm_status = storage_cert_chain_open(&kcm_source_chain_handle, kcm_item_name, kcm_item_name_len, source_item_prefix_type, &kcm_chain_len_out);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open chain");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_chain_len_out == 0), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, exit, "Invalid kcm_chain_len_out");

        //certificate chain
        if (storage_is_cert_chain(kcm_source_chain_handle) == true || kcm_chain_len_out > 1) {
            extra_param = (void*)&cert_name_info;
            max_index = kcm_chain_len_out;
        }
    }

    for (size_t index = 1; index <= max_index; index++) {

        cert_name_info.certificate_index = (uint32_t)index - 1;
        if (index == max_index) {
            cert_name_info.is_last_certificate = true;
        }

        //Build name of source item
        kcm_status = storage_build_complete_working_item_name(kcm_item_type, source_item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_source_complete_name, &kcm_complete_name_len, extra_param);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to build complete source data name ");

        SA_PV_LOG_TRACE("kcm_complete_name %s, %zu", kcm_source_complete_name, kcm_complete_name_len);
        //Build name of destination item
        kcm_status = storage_build_complete_working_item_name(kcm_item_type, destination_item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_destination_complete_name, &kcm_destination_complete_name_len, extra_param);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to build complete destination data name ");

        SA_PV_LOG_TRACE("kcm_complete_name %s,  %zu", kcm_destination_complete_name, kcm_destination_complete_name_len);
        //Copy existing source item to a new destination item
        kcm_status = ksa_copy_item((const uint8_t *)&kcm_source_complete_name, strlen(kcm_source_complete_name), kcm_item_type, (const uint8_t *)&kcm_destination_complete_name, strlen(kcm_destination_complete_name));
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to copy an item");
    }

exit:

    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        //close chain
        kcm_status = storage_cert_chain_close(kcm_source_chain_handle, source_item_prefix_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close chain");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_entry_remove(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;
    kcm_cert_chain_handle chain_handle;
    size_t chain_len_out = 0;
    size_t max_index = 1;
    void* extra_param = NULL;
    kcm_chain_cert_info_s cert_name_info = { 0, false };

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_PRIVATE_KEY_ITEM && kcm_item_type != KCM_PUBLIC_KEY_ITEM && kcm_item_type != KCM_CERTIFICATE_ITEM), KCM_STATUS_INVALID_PARAMETER, "key type not supported");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid item_prefix_type");

    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        //Open chain 
        kcm_status = storage_cert_chain_open(&chain_handle, kcm_item_name, kcm_item_name_len, item_prefix_type, &chain_len_out);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open chain");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((chain_len_out == 0), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, exit, "Invalid chain_len_out");

        //certificate chain
        if (storage_is_cert_chain(chain_handle) == true || chain_len_out > 1) {
            extra_param = (void*)&cert_name_info;
            max_index = chain_len_out;
        }
    }

    for (size_t index = 1; index <= max_index; index++) {

        cert_name_info.certificate_index = (uint32_t)index - 1;
        if (index == max_index) {
            cert_name_info.is_last_certificate = true;
        }

        //Build name of source item
        kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, &kcm_complete_name_len, extra_param);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to build complete source data name ");

        SA_PV_LOG_TRACE("kcm_complete_name %s", kcm_complete_name);

        kcm_status = ksa_remove_entry((const uint8_t*)&kcm_complete_name, kcm_complete_name_len, kcm_item_type);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to remove the key ");

    }

exit:

    if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
        //close chain
        kcm_status = storage_cert_chain_close(chain_handle, item_prefix_type);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close chain");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_key_activate_ce(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_type != KCM_PRIVATE_KEY_ITEM && kcm_item_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "key type not supported");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_activate_ce_key((const uint8_t *)kcm_complete_name, kcm_complete_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to update CE key (%u)", kcm_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_destory_old_active_and_remove_backup_entries(
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    const uint8_t                     *cert_name,
    size_t                            cert_name_len)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_priv_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_priv_name_size = 0;
    char kcm_complete_pub_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_pub_name_size = 0;
    char kcm_complete_cert_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_cert_name_size = 0;
    //uint8_t *kcm_complete_name_pointer = NULL;
    kcm_cert_chain_handle chain_handle;
    size_t chain_len_out = 0;
    size_t max_index = 1;
    void* extra_param = NULL;
    kcm_chain_cert_info_s cert_name_info = { 0, false };

    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((private_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid private_key_name_len");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((public_key_name != NULL && public_key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid public_key_name_len");
    SA_PV_LOG_TRACE_FUNC_ENTER("private_key_name = %.*s len = %" PRIu32 "", (int)private_key_name_len, (char*)private_key_name, (uint32_t)private_key_name_len);

    //Create complete key names of existing kcm keys with CE item prefix
    kcm_status = build_key_pair_working_complete_names(private_key_name, private_key_name_len, public_key_name, public_key_name_len, (uint8_t*)kcm_complete_priv_name, &kcm_complete_priv_name_size, (uint8_t*)kcm_complete_pub_name, &kcm_complete_pub_name_size, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete keys names");

    kcm_status = ksa_destroy_old_active_and_remove_backup_entry((const uint8_t *)&kcm_complete_priv_name, kcm_complete_priv_name_size, KCM_PRIVATE_KEY_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to clean backup private key");

    if (public_key_name != NULL) {
        kcm_status = ksa_destroy_old_active_and_remove_backup_entry((const uint8_t *)&kcm_complete_pub_name, kcm_complete_pub_name_size, KCM_PUBLIC_KEY_ITEM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to clean backup private key");
    }

    //Open chain 
    kcm_status = storage_cert_chain_open(&chain_handle, cert_name, cert_name_len, STORAGE_ITEM_PREFIX_CE, &chain_len_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to open chain");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((chain_len_out == 0), kcm_status = KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN, exit, "Invalid chain_len_out");

    //certificate chain
    if (storage_is_cert_chain(chain_handle) == true || chain_len_out > 1) {
        extra_param = (void*)&cert_name_info;
        max_index = chain_len_out;
    }

    for (size_t index = 1; index <= max_index; index++) {

        cert_name_info.certificate_index = (uint32_t)index - 1;
        if (index == max_index) {
            cert_name_info.is_last_certificate = true;
        }

        //Build name of source item
        kcm_status = storage_build_complete_working_item_name(KCM_CERTIFICATE_ITEM, STORAGE_ITEM_PREFIX_CE, cert_name, cert_name_len, kcm_complete_cert_name, &kcm_complete_cert_name_size, extra_param);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to build complete data name ");

        SA_PV_LOG_TRACE("kcm_complete_name %s", kcm_complete_cert_name);

        kcm_status = ksa_destroy_old_active_and_remove_backup_entry((const uint8_t *)&kcm_complete_cert_name, kcm_complete_cert_name_size, KCM_CERTIFICATE_ITEM);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status = kcm_status, exit, "Failed to clean backup private key");
    }

exit:
    //close chain
    kcm_status = storage_cert_chain_close(chain_handle, STORAGE_ITEM_PREFIX_CE);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close chain");

    return kcm_status;

}


kcm_status_e storage_item_delete(
    const uint8_t *kcm_item_name,
    size_t kcm_item_name_len,
    kcm_item_type_e kcm_item_type,
    storage_item_prefix_type_e item_prefix_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_complete_name_len = 0;
    size_t item_data_act_size;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid kcm_item_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid origin_type");

    kcm_status = storage_build_complete_working_item_name(kcm_item_type, item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_name, kcm_complete_name_len, kcm_item_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS && kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status, "Failed getting item data from PSA store (%u)", kcm_status);

    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        if (kcm_item_type == KCM_CERTIFICATE_ITEM) {
            kcm_status = storage_get_first_cert_in_chain_name_and_info(item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_complete_name, sizeof(kcm_complete_name), &item_data_act_size);
            if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
                //We don't want print log in case the item wasn't found
                return kcm_status;
            }
            SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to check single certificate name");
        } else {//not certificate
            SA_PV_LOG_INFO("Item not found");
            return KCM_STATUS_ITEM_NOT_FOUND;
        }
    }

    kcm_status = ksa_item_delete((const uint8_t *)kcm_complete_name, kcm_complete_name_len, kcm_item_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed destorying PSA key (%u)", kcm_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}


kcm_status_e storage_factory_reset()
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //set "FR_ON" flag to indicate that Factory Reset process started
    //RBP item type is used, so this flag won't be affected by factory reset process
    kcm_status = ksa_item_store((const uint8_t*)STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, strlen(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM), 0, STORAGE_RBP_ITEM, NULL, 0, KSA_PSA_TYPE_LOCATION, false);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed storing item in PSA (%u)", kcm_status);

    kcm_status = ksa_factory_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed in ksa_factory_reset");

    //remove "FR_ON" flag after factory reset finished successfully
    kcm_status = ksa_item_delete((const uint8_t*)STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM, strlen(STORAGE_FACTORY_RESET_IN_PROGRESS_ITEM), STORAGE_RBP_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to remove item");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_key_get_handle(
    const uint8_t *key_name,
    size_t key_name_len,
    kcm_item_type_e key_type,
    storage_item_prefix_type_e item_prefix_type,
    kcm_key_handle_t *key_h_out)
{
    char kcm_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_complete_name_len = 0;
    psa_key_handle_t key_handle;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != KCM_PRIVATE_KEY_ITEM && key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "key type not supported");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid key_name_len");
    SA_PV_LOG_INFO_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)key_name_len, (char*)key_name, (uint32_t)key_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((item_prefix_type != STORAGE_ITEM_PREFIX_KCM && item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid key_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_type != KCM_PRIVATE_KEY_ITEM && key_type != KCM_PUBLIC_KEY_ITEM), KCM_STATUS_INVALID_PARAMETER, "Invalid key type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_h_out");

    *key_h_out = 0;

    // Check if KCM initialized, if not initialize it
    if (!g_kcm_initialized) {
        kcm_status = kcm_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "KCM initialization failed\n");
    }
    //Build complete data name
    kcm_status = storage_build_complete_working_item_name(key_type, item_prefix_type, key_name, key_name_len, kcm_complete_name, &kcm_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete name");

    //Check if current key exists in the storage
    kcm_status = ksa_item_check_existence((const uint8_t *)kcm_complete_name, kcm_complete_name_len, key_type);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return kcm_status;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed during ksa_get_existing_entry");

    //Get key handle
    kcm_status = ksa_key_get_handle((const uint8_t *)kcm_complete_name, kcm_complete_name_len, &key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get key handle (%d)", kcm_status);

    *key_h_out = (kcm_key_handle_t)key_handle;

    SA_PV_LOG_INFO_FUNC_EXIT("kcm_item_h_out = %" PRIu32 "", (uint32_t)(*key_h_out));
    return kcm_status;
}

kcm_status_e storage_key_close_handle(kcm_key_handle_t *key_handle)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_handle == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid key_handle");
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (*key_handle == 0) {
        return KCM_STATUS_SUCCESS;
    }

    kcm_status = ksa_key_close_handle((psa_key_handle_t)*key_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to close key handle (%d)", kcm_status);

    //Reset handle value
    *key_handle = 0;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_key_pair_generate_and_store(
    const uint8_t                     *private_key_name,
    size_t                            private_key_name_len,
    const uint8_t                     *public_key_name,
    size_t                            public_key_name_len,
    storage_item_prefix_type_e        item_prefix_type,
    bool                              is_factory,
    const kcm_security_desc_s         kcm_item_info)
{
    char kcm_complete_priv_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_priv_name_size = 0;
    char kcm_complete_pub_name[KCM_MAX_FILENAME_SIZE] = { 0 };
    size_t kcm_complete_pub_name_size = 0;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    kcm_status_e kcm_del_status;
    uint8_t pub_key[KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE];
    size_t pub_key_size;
    ksa_type_location_e prv_key_location = KSA_PSA_TYPE_LOCATION;
    ksa_type_location_e pub_key_location = KSA_PSA_TYPE_LOCATION;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
    kcm_item_extra_info_s item_extra_info = kcm_item_extra_info_init();

    //Set location and location flag
    set_item_location(kcm_item_info, &item_extra_info);

    kcm_status = check_item_location(item_extra_info.priv_key_location);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), KCM_STATUS_INVALID_PARAMETER, "Wrong item location");

    prv_key_location = (item_extra_info.priv_key_location == KCM_LOCATION_PSA) ? KSA_PSA_TYPE_LOCATION : KSA_SECURE_ELEMENT_TYPE_LOCATION;

    if (public_key_name != NULL) {

        kcm_status = check_item_location(item_extra_info.pub_key_location);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), KCM_STATUS_INVALID_PARAMETER, "Wrong item location");

        pub_key_location = (item_extra_info.pub_key_location == KCM_LOCATION_PSA) ? KSA_PSA_TYPE_LOCATION : KSA_SECURE_ELEMENT_TYPE_LOCATION;
    }
#else
    //kcm_item_info undefined in non-secure element mode
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_info != NULL), KCM_STATUS_INVALID_PARAMETER, "Expected NULL for kcm_item_info");
#endif

    //Create complete key names
    build_key_pair_working_complete_names(private_key_name, private_key_name_len, public_key_name, public_key_name_len, (uint8_t*)kcm_complete_priv_name, &kcm_complete_priv_name_size, (uint8_t*)kcm_complete_pub_name, &kcm_complete_pub_name_size, item_prefix_type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to to build complete keys names");

    //check if key exists
    kcm_status = ksa_item_check_existence((const uint8_t*)kcm_complete_priv_name, kcm_complete_priv_name_size, KCM_PRIVATE_KEY_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = KCM_STATUS_KEY_EXIST, "The key already exists");

    if (public_key_name != NULL) {
        //Check if current public exists in the storage
        kcm_status = ksa_item_check_existence((const uint8_t *)kcm_complete_pub_name, kcm_complete_pub_name_size, KCM_PUBLIC_KEY_ITEM);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_ITEM_NOT_FOUND), kcm_status = KCM_STATUS_KEY_EXIST, "The key already exists");
    }

    //Generate and import the generated keypair to PSA slot
    kcm_status = ksa_item_store((const uint8_t *)kcm_complete_priv_name, strlen(kcm_complete_priv_name), 0, KCM_PRIVATE_KEY_ITEM, NULL, 0, prv_key_location, is_factory);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to import the key to PSA slot");

    if (public_key_name != NULL) {
        // read public key from keypair using kcm complete private name
        kcm_status = ksa_item_get_data((const uint8_t *)kcm_complete_priv_name, strlen(kcm_complete_priv_name), KCM_PUBLIC_KEY_ITEM, pub_key, sizeof(pub_key), &pub_key_size);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), exit, "failed to export public key from pair");

        // store public key using different slot
        kcm_status = ksa_item_store((const uint8_t *)kcm_complete_pub_name, strlen(kcm_complete_pub_name), 0, KCM_PUBLIC_KEY_ITEM, pub_key, pub_key_size, pub_key_location, is_factory);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), exit, "failed to import public key");
    }

exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        // Failed to store public, remove stored private key


        kcm_del_status = ksa_item_delete((const uint8_t *)kcm_complete_priv_name, kcm_complete_priv_name_size, KCM_PRIVATE_KEY_ITEM);
        if (kcm_del_status != KCM_STATUS_SUCCESS) {
            SA_PV_LOG_ERR("failed destorying PSA key during cleanup (%u)", kcm_del_status);
        }
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_init(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_specific_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed initializing storage specific backend (kcm_status %d)", kcm_status);

    kcm_status = ksa_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed initializing KSA (kcm_status %d)", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_finalize(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = ksa_fini();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed finalizing KSA (kcm_status %d)", kcm_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_reset_to_factory_state(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = ksa_factory_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for KSA factory reset");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return kcm_status;
}

kcm_status_e storage_specific_reset(void)
{
    return  ksa_reset();

}

kcm_status_e storage_reset(void)
{
    kcm_status_e kcm_status;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = storage_specific_reset();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for storage specific reset");

#ifdef TARGET_LIKE_MBED
    psa_status_t psa_status;

    /* Go back to an empty storage state
    * * In case of non-PSA boards (such as K64F and K66F) with KVSTORE config, this is not really needed, as kv_reset()
    *   called by storage_reset()) as PSA and RBP items are stored in the same TDBStore. In this case, the call will
    *   get us from an empty storage state to an empty storage state.
    * * In case of a user provided SST, we do not know whether pal_SSTReset() will also remove the PSA storage (probably
    *   not), so we probably need this call.
    * * In case of actual PSA boards, with KVSTORE config, we must call this function so the PSA storage is removed.
    * * Irrelevant for PSA over Linux
    */
    psa_status = mbed_psa_reboot_and_request_new_security_state(PSA_LIFECYCLE_ASSEMBLY_AND_TEST);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != PSA_SUCCESS), KCM_STATUS_ERROR, "Failed for mbed_psa_reboot_and_request_new_security_state() (status %" PRIu32 ")", psa_status);
#endif

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

kcm_status_e storage_item_get_location(const uint8_t *kcm_item_name,
                                       size_t kcm_item_name_len,
                                       kcm_item_type_e kcm_item_type,
                                       storage_item_prefix_type_e kcm_item_prefix_type,
                                       kcm_item_location_e *kcm_item_location_out)
{
    kcm_status_e kcm_status;
    char kcm_item_complete_name[STORAGE_MAX_COMPLETE_ITEM_NAME_LENGTH] = { 0 };
    size_t kcm_item_complete_name_len = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_name_len == 0), KCM_STATUS_INVALID_PARAMETER, "Invalid item name length");
    SA_PV_LOG_TRACE_FUNC_ENTER("item name = %.*s len = %" PRIu32 "", (int)kcm_item_name_len, (char*)kcm_item_name, (uint32_t)kcm_item_name_len);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_prefix_type != STORAGE_ITEM_PREFIX_KCM && kcm_item_prefix_type != STORAGE_ITEM_PREFIX_CE), KCM_STATUS_INVALID_PARAMETER, "Invalid item_source_type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_item_location_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid item_location_out");

    kcm_status = storage_build_complete_working_item_name(kcm_item_type, kcm_item_prefix_type, kcm_item_name, kcm_item_name_len, kcm_item_complete_name, &kcm_item_complete_name_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build complete data name");

    kcm_status = ksa_get_item_location((const uint8_t *)kcm_item_complete_name, kcm_item_complete_name_len, kcm_item_type, kcm_item_location_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed getting the key location");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
