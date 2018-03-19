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
#include "factory_configurator_client.h"
#include "fcc_bundle_utils.h"
#include "fcc_output_info_handler.h"
#include "fcc_malloc.h"
#include "fcc_sotp.h"
#include "general_utils.h"
#include "fcc_time_profiling.h"
#include "fcc_utils.h"

/**
* Defines for cbor layer
*/
#ifdef USE_CBOR_CONTEXT
#define CONTEXT_NULL , NULL
#define CONTEXT_NULL_COMMA NULL,
#else
#define CONTEXT_NULL
#define CONTEXT_NULL_COMMA
#endif

/**
* Definition of size and value of current protocol scheme version
*/
#define FCC_SIZE_OF_VERSION_FIELD 5
const char fcc_bundle_scheme_version[] = "0.0.1";
/**
* Types of configuration parameter groups
*/
typedef enum {
    FCC_KEY_GROUP_TYPE,                //!< Key group type
    FCC_CERTIFICATE_GROUP_TYPE,        //!< Certificate group type
    FCC_CSR_GROUP_TYPE,                //!< CSR group type
    FCC_CONFIG_PARAM_GROUP_TYPE,       //!< Configuration parameter group type
    FCC_CERTIFICATE_CHAIN_GROUP_TYPE,  //!< Certificate chain group type
    FCC_SCHEME_VERSION_TYPE,           //!< Scheme version group type
    FCC_ENTROPY_TYPE,                  //!< Entropy group type
    FCC_ROT_TYPE,                      //!< Root of trust group type
    FCC_VERIFY_DEVICE_IS_READY_TYPE,   //!< Verify device readiness type
    FCC_FACTORY_DISABLE_TYPE,             //!< Disable FCC flow type
    FCC_MAX_CONFIG_PARAM_GROUP_TYPE    //!< Max group type
} fcc_bundle_param_group_type_e;
/**
* Group lookup record, correlating group's type and name
*/
typedef struct fcc_bundle_group_lookup_record_ {
    fcc_bundle_param_group_type_e group_type;
    const char *group_name;
} fcc_bundle_group_lookup_record_s;
/**
* Group lookup table, correlating for each group its type and name.
* Order is important - it is the order that fcc_bundle_handler() reads the cbor fields.
* FCC_ENTROPY_TYPE and FCC_ROT_TYPE Must be processed first and second respectively.
*/
static const fcc_bundle_group_lookup_record_s fcc_groups_lookup_table[FCC_MAX_CONFIG_PARAM_GROUP_TYPE] = {
    { FCC_SCHEME_VERSION_TYPE,           FCC_BUNDLE_SCHEME_GROUP_NAME },
    { FCC_ENTROPY_TYPE,                  FCC_ENTROPY_NAME },
    { FCC_ROT_TYPE,                      FCC_ROT_NAME },
    { FCC_KEY_GROUP_TYPE,                FCC_KEY_GROUP_NAME },
    { FCC_CERTIFICATE_GROUP_TYPE,        FCC_CERTIFICATE_GROUP_NAME },
    { FCC_CSR_GROUP_TYPE,                FCC_CSR_GROUP_NAME },
    { FCC_CONFIG_PARAM_GROUP_TYPE,       FCC_CONFIG_PARAM_GROUP_NAME },
    { FCC_CERTIFICATE_CHAIN_GROUP_TYPE,  FCC_CERTIFICATE_CHAIN_GROUP_NAME },
    { FCC_VERIFY_DEVICE_IS_READY_TYPE,   FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME },
    { FCC_FACTORY_DISABLE_TYPE,          FCC_FACTORY_DISABLE_GROUP_NAME },
};

/** Prepare a response message
*
* The function prepare response buffer according to result of bundle buffer processing.
* In case of failure, the function prepare buffer with status,scheme version and error logs,
* in case of success - only the status and scheme version.
*
* @param bundle_response_out[in/out]   The pointer to response buffer.
* @param bundle_response_size_out[out/out]     The size of response buffer.
* @param fcc_status[in]     The result of bundle buffer processing.
* @return
*     true for success, false otherwise.
*/
static bool prepare_reponse_message(uint8_t **bundle_response_out, size_t *bundle_response_size_out, fcc_status_e fcc_status)
{
    bool status = false;
    cn_cbor_errback err;
    cn_cbor *cb_map = NULL;
    cn_cbor *cbor_struct_cb = NULL;
    int size_of_cbor_buffer = 0;
    int size_of_out_buffer = 0;
    uint8_t *out_buffer = NULL;
    char *error_string_info = NULL;
    char *warning_string_info = NULL;
    const char success_message[] = { "The Factory process succeeded\n" };
    *bundle_response_out = NULL;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    cb_map = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &err);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cb_map == NULL), false, "Failed to create cbor map");

    /**
    * Create cbor with return status
    */
    cbor_struct_cb = cn_cbor_int_create(fcc_status CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create return_status_cb ");

    //Put the cbor return status in cbor map with string key "ReturnStatus"
    status = cn_cbor_mapput_string(cb_map, FCC_RETURN_STATUS_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put return status to cbor map");

    /**
    * Create cbor with scheme version
    */
    cbor_struct_cb = NULL;
    cbor_struct_cb = cn_cbor_data_create((const uint8_t *)fcc_bundle_scheme_version,sizeof(fcc_bundle_scheme_version) CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create scheme_version_cb ");

    //Put the cbor return status in cbor map with string key "SchemeVersion"
    status = cn_cbor_mapput_string(cb_map, FCC_BUNDLE_SCHEME_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put return status to cbor map");

    /**
    * Create cbor with error info
    */
    cbor_struct_cb = NULL;
    if (fcc_status == FCC_STATUS_SUCCESS) {
        cbor_struct_cb = cn_cbor_data_create((const uint8_t*)success_message, (int)strlen(success_message) CBOR_CONTEXT_PARAM, &err);
    } else {
        error_string_info = fcc_get_output_error_info();
        if (error_string_info == NULL) {
            cbor_struct_cb = cn_cbor_data_create((const uint8_t*)g_fcc_general_status_error_str, (int)strlen(g_fcc_general_status_error_str) CBOR_CONTEXT_PARAM, &err);
        } else {
            cbor_struct_cb = cn_cbor_data_create((const uint8_t*)error_string_info, (int)strlen(error_string_info) CBOR_CONTEXT_PARAM, &err);
       }
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create cbor_struct_cb ");

    //Put the cbor info message in cbor map with string key "infoMessage"
    status = cn_cbor_mapput_string(cb_map, FCC_ERROR_INFO_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put cbor_struct_cb to cbor map");

    /**
    * Create cbor with warning info
    */
    cbor_struct_cb = NULL;
    status = fcc_get_warning_status();
    warning_string_info = fcc_get_output_warning_info();
    SA_PV_ERR_RECOVERABLE_GOTO_IF(status == true && warning_string_info == NULL, status = false, exit, "Failed to get created warnings");
    if (warning_string_info != NULL) {
        cbor_struct_cb = cn_cbor_data_create((const uint8_t *)warning_string_info, (int)strlen(warning_string_info) CBOR_CONTEXT_PARAM, &err);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create warning_message_cb ");

        //Put the cbor info message in cbor map with string key "WarningInfo"
        status = cn_cbor_mapput_string(cb_map, FCC_WARNING_INFO_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put warning_message_cb to cbor map");
    } 

    status = true;
    //Get size of encoded cbor buffer
    size_of_cbor_buffer = cn_cbor_get_encoded_size(cb_map, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((size_of_cbor_buffer == -1), status = false, exit, "Failed to get cbor buffer size");

    //Allocate out buffer
    out_buffer = fcc_malloc((size_t)size_of_cbor_buffer);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((out_buffer == NULL), status = false, exit, "Failed to allocate memory for out buffer");

    //Write cbor blob to output buffer
    size_of_out_buffer = cn_cbor_encoder_write(cb_map, out_buffer, size_of_cbor_buffer, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((size_of_out_buffer == -1), status = false, exit_without_out_buffer, "Failed to  write cbor buffer to output buffer");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((size_of_out_buffer != size_of_cbor_buffer), status = false, exit_without_out_buffer, "Wrong written size for outbut buffer");

    //Update pointer and size of output buffer
    *bundle_response_out = out_buffer;
    *bundle_response_size_out = (size_t)size_of_out_buffer;
    goto exit;

exit_without_out_buffer:
    fcc_free(out_buffer);

    // Nullify pointer so that the user cannot accidentally double free it.
    *bundle_response_out = NULL;
exit:
    fcc_free(warning_string_info);
    if (cb_map != NULL) {
        cn_cbor_free(cb_map CBOR_CONTEXT_PARAM);
    }
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return status;
}

/** Checks bundle scheme version
*
* @param cbor_blob[in]   The pointer to main cbor blob.
* @return
*     true for success, false otherwise.
*/
static bool check_scheme_version(cn_cbor *cbor_blob)
{
    cn_cbor *scheme_version_cb = NULL;
    int result;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_blob == NULL), false, "Invalid cbor_blob");

    scheme_version_cb = cn_cbor_mapget_string(cbor_blob, FCC_BUNDLE_SCHEME_GROUP_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((scheme_version_cb == NULL), false, "Failed to find scheme version group");

    result = is_memory_equal(scheme_version_cb->v.bytes, (size_t)(scheme_version_cb->length), fcc_bundle_scheme_version, (size_t)strlen(fcc_bundle_scheme_version));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!result), false, "Wrong scheme version");

    return true;
}


fcc_status_e fcc_bundle_handler(const uint8_t *encoded_blob, size_t encoded_blob_size, uint8_t **bundle_response_out, size_t *bundle_response_size_out)
{
    bool status = false;
    bool is_fcc_factory_disabled;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    cn_cbor *main_list_cb = NULL;
    cn_cbor *group_value_cb = NULL;
    cn_cbor_errback err;
    size_t group_index;
    fcc_bundle_param_group_type_e group_type;
    size_t num_of_groups_in_message = 0;
    bool fcc_verify_status = true; // the default value of verify status is true
    bool fcc_disable_status = false;// the default value of dasable status is false


    FCC_SET_START_TIMER(fcc_bundle_timer);

    SA_PV_LOG_INFO_FUNC_ENTER("encoded_blob_size = %" PRIu32 "", (uint32_t)encoded_blob_size);

    // Set *bundle_response_out to NULL before fcc_is_factory_disabled call so that in case factory is disabled - return FCC_STATUS_FACTORY_DISABLED_ERROR and nullify *bundle_response_out
    if (bundle_response_out != NULL) {
        // Set to NULL so that the user does not accidentally free a non NULL pointer after the function returns.
        *bundle_response_out = NULL;
    }

    // Check if factory flow is disabled, if yes, do not proceed
    fcc_status = fcc_is_factory_disabled(&is_fcc_factory_disabled);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "Failed for fcc_is_factory_disabled");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_fcc_factory_disabled), FCC_STATUS_FACTORY_DISABLED_ERROR, "FCC is disabled, service not available");

    // Check params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((bundle_response_out == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid bundle_response_out");
    

    SA_PV_ERR_RECOVERABLE_RETURN_IF((bundle_response_size_out == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid bundle_response_size_out");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((encoded_blob == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Invalid encoded_blob");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((encoded_blob_size == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Invalid encoded_blob_size");

    /*Initialize fcc_output_info_s structure , in case of error during store process the
    function will exit without fcc_verify_device_configured_4mbed_cloud where we perform additional fcc_clean_output_info_handler*/
    fcc_clean_output_info_handler();

    /* Decode CBOR message
    Check the size of the CBOR structure */
    main_list_cb = cn_cbor_decode(encoded_blob, encoded_blob_size CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((main_list_cb == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "cn_cbor_decode failed (%" PRIu32 ")", (uint32_t)err.err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((main_list_cb->type != CN_CBOR_MAP), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "Wrong CBOR structure type");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((main_list_cb->length <= 0 || main_list_cb->length > FCC_MAX_CONFIG_PARAM_GROUP_TYPE *FCC_CBOR_MAP_LENGTH), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "Wrong CBOR structure size");

    /* Check scheme version*/
    status = check_scheme_version(main_list_cb);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), fcc_status = FCC_STATUS_BUNDLE_INVALID_SCHEME, free_cbor_list_and_out, "check_scheme_version failed");

    //Go over parameter groups
    for (group_index = 0; group_index < FCC_MAX_CONFIG_PARAM_GROUP_TYPE; group_index++) {
        //Get content of current group (value of map, when key of map is name of group and value is list of params of current group)
        SA_PV_LOG_INFO(" fcc_groups_lookup_table[group_index].group_name is %s", fcc_groups_lookup_table[group_index].group_name);
        group_value_cb = cn_cbor_mapget_string(main_list_cb, fcc_groups_lookup_table[group_index].group_name);

        if (group_value_cb != NULL) {
            //Get type of group
            group_type = fcc_groups_lookup_table[group_index].group_type;
            num_of_groups_in_message++;

            switch (group_type) {
                case FCC_SCHEME_VERSION_TYPE:
                    break;
                case FCC_KEY_GROUP_TYPE:
                    FCC_SET_START_TIMER(fcc_gen_timer);
                    fcc_status = fcc_bundle_process_keys(group_value_cb);
                    FCC_END_TIMER("Total keys process", 0 ,fcc_gen_timer);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_keys failed");
                    break;
                case FCC_CERTIFICATE_GROUP_TYPE:
                    FCC_SET_START_TIMER(fcc_gen_timer);
                    fcc_status = fcc_bundle_process_certificates(group_value_cb);
                    FCC_END_TIMER("Total certificates process", 0, fcc_gen_timer);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_certificates failed");
                    break;
                case FCC_CONFIG_PARAM_GROUP_TYPE:
                    FCC_SET_START_TIMER(fcc_gen_timer);
                    fcc_status = fcc_bundle_process_config_params(group_value_cb);
                    FCC_END_TIMER("Total config params process", 0, fcc_gen_timer);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_config_params failed");
                    break;
                case FCC_CERTIFICATE_CHAIN_GROUP_TYPE:
                    FCC_SET_START_TIMER(fcc_gen_timer);
                    fcc_status = fcc_bundle_process_certificate_chains(group_value_cb);
                    FCC_END_TIMER("Total certificate chains process", 0, fcc_gen_timer);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_certificate_chains failed");
                    break;
                case FCC_ENTROPY_TYPE: // Entropy for random generator
                    fcc_status = fcc_bundle_process_sotp_buffer(group_value_cb, SOTP_TYPE_RANDOM_SEED);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_sotp_buffer failed for entropy");
                    break;
                case FCC_ROT_TYPE: // Key for ESFS
                    fcc_status = fcc_bundle_process_sotp_buffer(group_value_cb, SOTP_TYPE_ROT);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_sotp_buffer failed for ROT");
                    break;
                case FCC_VERIFY_DEVICE_IS_READY_TYPE: //Check if device need to be verified
                    fcc_status = bundle_process_status_field(group_value_cb, (char*)FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME, strlen((char*)FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME), &fcc_verify_status);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "process_device_verify failed");
                    break;
                case FCC_FACTORY_DISABLE_TYPE://Check if device need to be disabled for factory
                    fcc_status = bundle_process_status_field(group_value_cb, (char*)FCC_FACTORY_DISABLE_GROUP_NAME, strlen((char*)FCC_FACTORY_DISABLE_GROUP_NAME), &fcc_disable_status);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_factory_disable failed");
                    break;
                default:
                    fcc_status = FCC_STATUS_BUNDLE_UNSUPPORTED_GROUP;
                    SA_PV_LOG_ERR("Wrong group type");
                    goto free_cbor_list_and_out;
            }
        }
    }

    SA_PV_ERR_RECOVERABLE_GOTO_IF((num_of_groups_in_message == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, free_cbor_list_and_out, "No groups in message");
    SA_PV_ERR_RECOVERABLE_GOTO_IF(((size_t)(main_list_cb->length/FCC_CBOR_MAP_LENGTH)!= num_of_groups_in_message), fcc_status = FCC_STATUS_BUNDLE_INVALID_GROUP, free_cbor_list_and_out, "One ore more names of groups are invalid");

    // Note that FCC_STATUS_CA_ERROR is being return only in case where the CA is already exist
    // in SOTP, if in the future more error conditions will be attached to FCC_STATUS_CA_ERROR error code
    // then the logic here MUST be change.
    fcc_status = fcc_trust_ca_cert_id_set();
    SA_PV_ERR_RECOVERABLE_GOTO_IF(((fcc_status != FCC_STATUS_SUCCESS) && (fcc_status != FCC_STATUS_CA_ERROR)), (fcc_status = fcc_status), free_cbor_list_and_out, "CA store error %u", fcc_status);

    if (fcc_verify_status == true) {
        // device VERIFY group does NOT exist in the CBOR message and device is NOT disabled.
        // Perform device verification to keep backward compatibility.
        FCC_SET_START_TIMER(fcc_gen_timer);
        fcc_status = fcc_verify_device_configured_4mbed_cloud();
        FCC_END_TIMER("Total verify device", 0, fcc_gen_timer);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_verify_device_configured_4mbed_cloud failed");
    }

    if (fcc_disable_status == true) {
        fcc_status = fcc_bundle_factory_disable();
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_factory_disable failed");
    }

free_cbor_list_and_out:
    cn_cbor_free(main_list_cb CBOR_CONTEXT_PARAM);

exit:
    //Prepare bundle response message
    status = prepare_reponse_message(bundle_response_out, bundle_response_size_out, fcc_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), FCC_STATUS_BUNDLE_RESPONSE_ERROR, "Failed to prepare out response");
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    FCC_END_TIMER("Total fcc_bundle_handler device", 0, fcc_bundle_timer);
    return fcc_status;
}
