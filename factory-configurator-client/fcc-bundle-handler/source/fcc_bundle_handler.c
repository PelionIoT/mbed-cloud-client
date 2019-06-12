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
#include "general_utils.h"
#include "fcc_time_profiling.h"
#include "fcc_utils.h"
#include "fcc_bundle_fields.h"
#include "storage_items.h"

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
extern bool g_is_session_finished;

// FIXME: temporary. Will be removed when migration to tinycbor is complete
void g_csr_buf_free(void);

/**
* Types of configuration parameter groups
*/
typedef enum {
    FCC_KEY_GROUP_TYPE,                //!< Key group type
    FCC_CERTIFICATE_GROUP_TYPE,        //!< Certificate group type
    FCC_CONFIG_PARAM_GROUP_TYPE,       //!< Configuration parameter group type
    FCC_CERTIFICATE_CHAIN_GROUP_TYPE,  //!< Certificate chain group type
    FCC_SCHEME_VERSION_TYPE,           //!< Scheme version group type
    FCC_ENTROPY_TYPE,                  //!< Entropy group type
    FCC_ROT_TYPE,                      //!< Root of trust group type
    FCC_VERIFY_DEVICE_IS_READY_TYPE,   //!< Verify device readiness type
    FCC_FACTORY_DISABLE_TYPE,          //!< Disable FCC flow type
    FCC_IS_ALIVE_SESSION_GROUP_TYPE,   //!< Indicates current message status - last message or not
    FCC_FCU_SESSION_ID_GROUP_TYPE,     //!< Session ID sent by the FCU
    FCC_CSR_REQUESTS_GROUP_TYPE,       //!< CSR requests type
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
    { FCC_IS_ALIVE_SESSION_GROUP_TYPE,   FCC_KEEP_ALIVE_SESSION_GROUP_NAME },
    { FCC_KEY_GROUP_TYPE,                FCC_KEY_GROUP_NAME },
    { FCC_CERTIFICATE_GROUP_TYPE,        FCC_CERTIFICATE_GROUP_NAME },
    { FCC_CONFIG_PARAM_GROUP_TYPE,       FCC_CONFIG_PARAM_GROUP_NAME },
    { FCC_CERTIFICATE_CHAIN_GROUP_TYPE,  FCC_CERTIFICATE_CHAIN_GROUP_NAME },
    { FCC_VERIFY_DEVICE_IS_READY_TYPE,   FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME },
    { FCC_FACTORY_DISABLE_TYPE,          FCC_FACTORY_DISABLE_GROUP_NAME },
    { FCC_FCU_SESSION_ID_GROUP_TYPE,     FCC_FCU_SESSION_ID_GROUP_TYPE_NAME },
    { FCC_CSR_REQUESTS_GROUP_TYPE,       FCC_CSR_REQUESTS_GROUP_NAME }
};




/* Response cbor blob structure

{  "SchemeVersion": "0.0.1",
   "FCUSessionID": uint32_t,
   "Csrs": [ {"Name": "__", "Format":"_","Data":"__"},
             {"Name": "__", "Format":"_","Data":"__"}],
   "WarningInfo": "string of warnings",
   "ReturnStatus": uint32_t,
   "InfoMessage": "detailed error string"}
*/
/** Prepare a response message
*
* The function prepare response buffer according to result of bundle buffer processing.
* In case of failure, the function prepare buffer with status,scheme version and error logs,
* in case of success - only the status and scheme version.
*
* @param bundle_response_out[in/out]   The pointer to response buffer.
* @param bundle_response_size_out[out/out]     The size of response buffer.
* @param fcc_status[in]     The result of bundle buffer processing.
* 
* @return
*     true for success, false otherwise.
*/
static bool prepare_reponse_message(uint8_t **bundle_response_out, size_t *bundle_response_size_out, fcc_status_e fcc_status, cn_cbor *encoder, const uint8_t *session_id, size_t session_id_len)
{
    bool status = false;
    cn_cbor_errback err;
    cn_cbor *cbor_struct_cb = NULL;
    int size_of_cbor_buffer = 0;
    int size_of_out_buffer = 0;
    uint8_t *out_buffer = NULL;
    char *error_string_info = NULL;
    char *warning_string_info = NULL;
    const char success_message[] = { "The Factory process succeeded\n" };
    *bundle_response_out = NULL;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // If error has occurred during bundle processing - create a new encoder (all that was encoded is not needed)
    // If no error occurred - the encoder will already have the scheme version and the FCU session ID inside an open map - therefore, in case of an error, we add them to a new map
    if (fcc_status != FCC_STATUS_SUCCESS) {
        // Free the old encoder and create a new one
        if (encoder) {
            cn_cbor_free(encoder CBOR_CONTEXT_PARAM);
        }
        encoder = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &err);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((encoder == NULL), false, "Failed to create cbor map");

        /**
        * Create cbor with scheme version
        */
        cbor_struct_cb = NULL;
        cbor_struct_cb = cn_cbor_text_create((const uint8_t *)fcc_bundle_scheme_version, sizeof(fcc_bundle_scheme_version) CBOR_CONTEXT_PARAM, &err);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create scheme_version_cb ");

        //Put the cbor scheme version in cbor map with string key "SchemeVersion"
        status = cn_cbor_mapput_string(encoder, FCC_BUNDLE_SCHEME_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed to put return status to cbor map");

        //Put the cbor session ID in cbor map with string key "SID"
        if(session_id != NULL) { 
            cbor_struct_cb = cn_cbor_text_create(session_id, (int)session_id_len CBOR_CONTEXT_PARAM, &err);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "CBOR error");

            status = cn_cbor_mapput_string(encoder, FCC_FCU_SESSION_ID_GROUP_TYPE_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed to put return session ID");
        }
    }


    /**
    * Create cbor with return status
    */
    cbor_struct_cb = cn_cbor_int_create(fcc_status CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create return_status_cb ");

    //Put the cbor return status in cbor map with string key "ReturnStatus"
    status = cn_cbor_mapput_string(encoder, FCC_RETURN_STATUS_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put return status to cbor map");


    /**
    * Create cbor with error info
    */
    cbor_struct_cb = NULL;
    if (fcc_status == FCC_STATUS_SUCCESS) {
        cbor_struct_cb = cn_cbor_text_create((const uint8_t*)success_message, (int)strlen(success_message) CBOR_CONTEXT_PARAM, &err);
    } else {
        error_string_info = fcc_get_output_error_info();
        if (error_string_info == NULL) {
            cbor_struct_cb = cn_cbor_text_create((const uint8_t*)g_fcc_general_status_error_str, (int)strlen(g_fcc_general_status_error_str) CBOR_CONTEXT_PARAM, &err);
        } else {
            cbor_struct_cb = cn_cbor_text_create((const uint8_t*)error_string_info, (int)strlen(error_string_info) CBOR_CONTEXT_PARAM, &err);
       }
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create cbor_struct_cb ");

    //Put the cbor info message in cbor map with string key "infoMessage"
    status = cn_cbor_mapput_string(encoder, FCC_ERROR_INFO_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put cbor_struct_cb to cbor map");

    /**
    * Create cbor with warning info
    */
    cbor_struct_cb = NULL;
    status = fcc_get_warning_status();
    warning_string_info = fcc_get_output_warning_info();
    SA_PV_ERR_RECOVERABLE_GOTO_IF(status == true && warning_string_info == NULL, status = false, exit, "Failed to get created warnings");
    if (warning_string_info != NULL) {
        cbor_struct_cb = cn_cbor_text_create((const uint8_t *)warning_string_info, (int)strlen(warning_string_info) CBOR_CONTEXT_PARAM, &err);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_struct_cb == NULL), status = false, exit, "Failed to create warning_message_cb ");

        //Put the cbor info message in cbor map with string key "WarningInfo"
        status = cn_cbor_mapput_string(encoder, FCC_WARNING_INFO_GROUP_NAME, cbor_struct_cb CBOR_CONTEXT_PARAM, &err);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), status = false, exit, "Failed top put warning_message_cb to cbor map");
    } 

    status = true;
    //Get size of encoded cbor buffer
    size_of_cbor_buffer = cn_cbor_get_encoded_size(encoder, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((size_of_cbor_buffer == -1), status = false, exit, "Failed to get cbor buffer size");

    //Allocate out buffer
    out_buffer = fcc_malloc((size_t)size_of_cbor_buffer);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((out_buffer == NULL), status = false, exit, "Failed to allocate memory for out buffer");

    //Write cbor blob to output buffer
    size_of_out_buffer = cn_cbor_encoder_write(encoder, out_buffer, size_of_cbor_buffer, &err);
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
    // FIXME: Free the CSRs buffer after the writing to the encoder buffer. Not needed after migration to tinycbor
    g_csr_buf_free();
    fcc_free(warning_string_info);
    if (encoder != NULL) {
        cn_cbor_free(encoder CBOR_CONTEXT_PARAM);
    }
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return status;
}


/** Checks bundle scheme version
*
* @param cbor_blob[in]   The pointer to main cbor blob.
* @param encoder[in]     Pointer to an encoder that points to the beginning of the CBOR response encoder
*
* FIXME: When we migrate to tinycbor encoder should be pointer to the encoder so that after encoding, the encoder will point to the next available spot in the response CBOR
* @return
*     true for success, false otherwise.
*/
static bool check_scheme_version(cn_cbor *cbor_blob, cn_cbor *encoder)
{
    cn_cbor *cbor = NULL;
    bool status;
    int result;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_blob == NULL), false, "Invalid cbor_blob");

    cbor = cn_cbor_mapget_string(cbor_blob, FCC_BUNDLE_SCHEME_GROUP_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor == NULL), false, "Failed to find scheme version group");

    result = is_memory_equal(cbor->v.bytes, (size_t)(cbor->length), fcc_bundle_scheme_version, (size_t)strlen(fcc_bundle_scheme_version));
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!result), false, "Wrong scheme version");

    // append the scheme version key-value into the encoder
    cbor = cn_cbor_text_create((const uint8_t *)fcc_bundle_scheme_version, sizeof(fcc_bundle_scheme_version) CBOR_CONTEXT_PARAM, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor == NULL), false, "Failed to create scheme_version_cb ");

    status = cn_cbor_mapput_string(encoder, FCC_BUNDLE_SCHEME_GROUP_NAME, cbor, CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status == false), status, "CBOR error");

    return true;
}

/** Checks the FCU session ID and encodes it into the encoder
*
* @param parser[in]             Pointer to cbor containing the FCU session ID (the value of the KV pair where the key is FCC_FCU_SESSION_ID_GROUP_TYPE_NAME).
* @param encoder[in]            Pointer to an encoder that points to the beginning of the CBOR response encoder.
* @param session_id[out]        Pointer to a pointer that will point to the session ID in the incoming message.
* @param session_id_len[out]    The length of the session ID in the incoming message.
*
* FIXME: When we migrate to tinycbor encoder should be pointer to the encoder so that after encoding, the encoder will point to the next available spot in the response CBOR
* @return
*     true for success, false otherwise.
*/
static bool fcc_bundle_process_session_id(cn_cbor *parser, cn_cbor *encoder, const uint8_t **session_id, size_t *session_id_len)
{
    cn_cbor *cbor = NULL;
    bool status;

    // Get the session ID from the message and make sure that it is either a text or bytes string
    SA_PV_ERR_RECOVERABLE_RETURN_IF((parser->type != CN_CBOR_TEXT), false, "Session ID of wrong type");

    // Output the values for use of the prepare_reponse_message() function in case of an error during the bundle handling process
    *session_id = (uint8_t *)parser->v.bytes;
    *session_id_len = (size_t)parser->length;

    cbor = cn_cbor_text_create(*session_id, (int)*session_id_len CBOR_CONTEXT_PARAM, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor == NULL), false, "CBOR error");
	
    // append the session id key-value into the encoder
    status = cn_cbor_mapput_string(encoder, FCC_FCU_SESSION_ID_GROUP_TYPE_NAME, cbor, CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status == false), false, "CBOR error");

    return true;
}



/** The function parses group that indicates if current session will be closed after the processing of the message.
*  The function checks existence and value of the group and sets the result to global variable g_is_alive_sesssion.
*
* @param cbor_blob[in]   The pointer to main cbor blob.
* @return
*     true for success, false otherwise.
*/
static bool parse_keep_alive_session_group(cn_cbor *cbor_blob)
{
    cn_cbor *is_alive_message = NULL;

    is_alive_message = cn_cbor_mapget_string(cbor_blob, FCC_KEEP_ALIVE_SESSION_GROUP_NAME);
    //In case current group wasn't found -  set g_is_not_last_message to false (for backward compatibility)
    if (is_alive_message == NULL) {
        g_is_session_finished = true;
        return true;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_alive_message->type != CN_CBOR_UINT || is_alive_message->v.uint > 1), false, "Wrong is alive session structure");

    // Session is finished if value is 0, and alive if value is 1
    g_is_session_finished = !(is_alive_message->v.uint);

    return true;
}

/* CBOR blob structure
{   "SchemeVersion": "0.0.1",
    "FCUSessionID": uint32_t,
    "IsNotLastMessage": 1 or 0,
    "Entropy": [byte array - 48 bytes],
    "Csrs": [ {"PrivKeyName":"__",
               "PubKeyName": "__", -optional
               "Extensions": [
                               {"TrustLevel": uint32_t },
                               {
                                   "KeyUsage":  [uint32_t,uint32_t,unit32_t ],
                               },
                               {
                                   "ExtendedKeyUsage":  [byte array],
                               }]
               "Subject": "C=__,ST=__ ,L=__, O=__,OU=__,CN=__,",
                },
                { ... },
                { ... }
              ],
    "ROT": "byte array",
    "Certificates": [ {"Name": "__", "Format":" _","Data":"__", "ACL" : "__"},
                      {..},
                      {"Name": "__", "Format":" _","Data":"__", "ACL" : "__"}],
    "Keys": [ {"Name": "__", "Type":"__", "Format":"__", "Data":"**","ACL" : "__"},
              {"Name": "__", "Type":"__", "Format":"__", "Data":"**","ACL": "__"},
               ...
              {"Name": "__", "Type":"__", "Format":"__", "Data":"**","ACL": "__"}],
    "ConfigParams": [ {"Name": "__", "Data":"__", "ACL" : "__"},
                      {"Name": "__", "Format":"__", "Data":"__", "ACL": "__"},
                       ...,
                      {"Name": "__", "Format":"__", "Data":"__", "ACL": "__"}],
    "CertificateChains": [ {"Name": "mbed.CertificateChain",
                            "DataArray":[h'3081870.....',h'308187020100...',h'308187020....'],
                            "Format":"Der",
                            "ACL":"_____"},
                          {"Name": "mbed.LwM2MCertificateChain",
                           "DataArray":[h'308187...',h'30818702...',h'308187020...',h'308187020...',h'308187020...'],
                           "Format":"Der",
                           "ACL":"_____"}],
    "Verify":1, 
    "Disable":1}
*/
fcc_status_e fcc_bundle_handler(const uint8_t *encoded_blob, size_t encoded_blob_size, uint8_t **bundle_response_out, size_t *bundle_response_size_out)
{
    bool status = false;
    bool is_fcc_factory_disabled = false;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    cn_cbor *main_list_cb = NULL;
    cn_cbor *group_value_cb = NULL;
    cn_cbor *response_cbor = NULL;
    cn_cbor_errback err;
    size_t group_index;
    fcc_bundle_param_group_type_e group_type;
    size_t num_of_groups_in_message = 0;
    const uint8_t *session_id = NULL;
    size_t session_id_len = 0;
    bool fcc_verify_status = true; // the default value of verify status is true
    bool fcc_disable_status = false;// the default value of disable status is false
    kcm_status_e kcm_status;

    FCC_SET_START_TIMER(fcc_bundle_timer);

    SA_PV_LOG_INFO_FUNC_ENTER("encoded_blob_size = %" PRIu32 "", (uint32_t)encoded_blob_size);

    // Set *bundle_response_out to NULL before fcc_is_factory_disabled call so that in case factory is disabled - return FCC_STATUS_FACTORY_DISABLED_ERROR and nullify *bundle_response_out
    if (bundle_response_out != NULL) {
        // Set to NULL so that the user does not accidentally free a non NULL pointer after the function returns.
        *bundle_response_out = NULL;
    }
    // Check params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!fcc_is_initialized()), FCC_STATUS_NOT_INITIALIZED, "FCC not initialized");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((bundle_response_out == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid bundle_response_out");

    SA_PV_ERR_RECOVERABLE_RETURN_IF((bundle_response_size_out == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid bundle_response_size_out");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((encoded_blob == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Invalid encoded_blob");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((encoded_blob_size == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Invalid encoded_blob_size");

    /*Initialize fcc_output_info_s structure , in case of error during store process the
    function will exit without fcc_verify_device_configured_4mbed_cloud where we perform additional fcc_clean_output_info_handler*/
    fcc_clean_output_info_handler();

    // Create the CBOR encoder, an empty map
    response_cbor = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((response_cbor == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, exit, "Failed to instantiate cbor structure");

    /* Decode CBOR message
    Check the size of the CBOR structure */
    main_list_cb = cn_cbor_decode(encoded_blob, encoded_blob_size CBOR_CONTEXT_PARAM, &err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((main_list_cb == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "cn_cbor_decode failed (%" PRIu32 ")", (uint32_t)err.err);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((main_list_cb->type != CN_CBOR_MAP), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "Wrong CBOR structure type");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((main_list_cb->length <= 0 || main_list_cb->length > FCC_MAX_CONFIG_PARAM_GROUP_TYPE *FCC_CBOR_MAP_LENGTH), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "Wrong CBOR structure size");

    /* Check scheme version*/
    status = check_scheme_version(main_list_cb, response_cbor);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), fcc_status = FCC_STATUS_BUNDLE_INVALID_SCHEME, free_cbor_list_and_out, "check_scheme_version failed");

    /* Parse and save is message status */
    status = parse_keep_alive_session_group(main_list_cb);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), fcc_status = FCC_STATUS_BUNDLE_INVALID_KEEP_ALIVE_SESSION_STATUS, free_cbor_list_and_out, "parse_keep_alive_session_group failed");

/*
     * In order for file functions to work properly, we must first inject the entropy, 
     * if we have one to inject. If entropy is expected, its existance is required for
     * every random number generation in the system.
     * If FCC_ENTROPY_NAME not in bundle (and user did not use the fcc_entropy_set()), 
     * then device must have TRNG or storage functions will fail.
     */
    group_value_cb = cn_cbor_mapget_string(main_list_cb, FCC_ENTROPY_NAME);
    if (group_value_cb) {
        fcc_status = fcc_bundle_process_buffer(group_value_cb, STORAGE_RBP_RANDOM_SEED_NAME, FCC_BUNDLE_BUFFER_TYPE_ENTROPY);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_buffer failed for entropy");
    }

    /* If RoT injection is expected (to derive storage key) it also must be done prior to storage calls */
    group_value_cb = cn_cbor_mapget_string(main_list_cb, FCC_ROT_NAME);
    if (group_value_cb) {
        fcc_status = fcc_bundle_process_buffer(group_value_cb, STORAGE_RBP_ROT_NAME, FCC_BUNDLE_BUFFER_TYPE_ROT);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_buffer failed for RoT");
    }

    /*
     * At this point we assume that if user expects to inject an entropy - it exists
     * in storage, and if not - device has TRNG and it is safe to call storage functions.
     * The next calls may fail if for some unlikely reason, one of the following is true:
     *     1. User expects an entropy (i.e MBEDTLS_ENTROPY_NV_SEED is defined), yet entropy
     *        was not included in bundle, and fcc_entropy_set() was not called.
     *     2. User does not expect an entropy and device does not have a TRNG (PAL_USE_HW_TRNG=0)
     */

    // Now we may initialize the KCM, including the secure time and the file systen
    kcm_status = kcm_init();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_status), free_cbor_list_and_out, "Failed for kcm_init");

    // Check if factory flow is disabled (if flag in storage), if it is, do not proceed
    // Turn on is_fcc_factory_disabled even if we get an error, so that we know not tp prepare a response
    fcc_status = fcc_is_factory_disabled(&is_fcc_factory_disabled);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), is_fcc_factory_disabled = true, free_cbor_list_and_out, "Failed for fcc_is_factory_disabled");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((is_fcc_factory_disabled), fcc_status = FCC_STATUS_FACTORY_DISABLED_ERROR, free_cbor_list_and_out, "FCC is disabled, service not available");

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
                // Scheme version, Entropy, RoT and Keep Alive were handled prior to this switch statement
                case FCC_SCHEME_VERSION_TYPE:
                case FCC_ENTROPY_TYPE: // Non volatile entropy for random generator
                case FCC_ROT_TYPE: // Root of trust for deriving secure storage key
                case FCC_IS_ALIVE_SESSION_GROUP_TYPE:
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
                case FCC_VERIFY_DEVICE_IS_READY_TYPE: //Check if device need to be verified
                    fcc_status = bundle_process_status_field(group_value_cb, (char*)FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME, strlen((char*)FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME), &fcc_verify_status);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "process_device_verify failed");
                    break;
                case FCC_FACTORY_DISABLE_TYPE://Check if device need to be disabled for factory
                    fcc_status = bundle_process_status_field(group_value_cb, (char*)FCC_FACTORY_DISABLE_GROUP_NAME, strlen((char*)FCC_FACTORY_DISABLE_GROUP_NAME), &fcc_disable_status);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_factory_disable failed");
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_disable_status == true && g_is_session_finished == false), fcc_status = FCC_STATUS_BUNDLE_INVALID_KEEP_ALIVE_SESSION_STATUS, free_cbor_list_and_out, "can not disable fcc for intermidiate message");
                    break;
                case FCC_FCU_SESSION_ID_GROUP_TYPE:
                    status = fcc_bundle_process_session_id(group_value_cb, response_cbor, &session_id, &session_id_len);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "fcc_bundle_process_session_id failed");
                    break;
                case FCC_CSR_REQUESTS_GROUP_TYPE:
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((session_id == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "Session ID is required when providing CSR requests");
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_verify_status || fcc_disable_status), fcc_status = FCC_STATUS_BUNDLE_ERROR, free_cbor_list_and_out, "Verify and Disable flags must not exist with CSR requests");
                    FCC_SET_START_TIMER(fcc_gen_timer);
                    fcc_status = fcc_bundle_process_csrs(group_value_cb, response_cbor);
                    FCC_END_TIMER("Total keys and CSR creation process", 0, fcc_gen_timer);
                    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, free_cbor_list_and_out, "fcc_bundle_process_csrs failed");
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

    // If not keep alive
    if (g_is_session_finished) {
        // Note that FCC_STATUS_CA_ERROR is being return only in case where the CA already exists
        // in SOTP, if in the future more error conditions will be attached to FCC_STATUS_CA_ERROR error code
        // then the logic here MUST be change.
        // Only if this is the last message - set the certificate ID
        fcc_status = fcc_trust_ca_cert_id_set();
        SA_PV_ERR_RECOVERABLE_GOTO_IF(((fcc_status != FCC_STATUS_SUCCESS) && (fcc_status != FCC_STATUS_CA_ERROR)), (fcc_status = fcc_status), free_cbor_list_and_out, "CA store error %u", fcc_status);

    }

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
    // If we discovered that factory is disabled (or fcc_is_factory_disabled failed) - do not prepare a response
    if (is_fcc_factory_disabled == false) {
        //Prepare bundle response message
        status = prepare_reponse_message(bundle_response_out, bundle_response_size_out, fcc_status, response_cbor, session_id, session_id_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != true), FCC_STATUS_BUNDLE_RESPONSE_ERROR, "Failed to prepare out response");
        SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
        FCC_END_TIMER("Total fcc_bundle_handler device", 0, fcc_bundle_timer);
    } else {
        // We may have started encoding the response, but gotten an error, if so - free the encoder
        if (response_cbor) {
            cn_cbor_free(response_cbor CBOR_CONTEXT_PARAM);
        }
    }
    return fcc_status;
}
