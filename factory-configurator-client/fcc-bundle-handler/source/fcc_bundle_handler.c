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
#include "pv_error_handling.h"
#include "factory_configurator_client.h"
#include "fcc_bundle_utils.h"
#include "fcc_output_info_handler.h"
#include "fcc_malloc.h"
#include "general_utils.h"
#include "fcc_time_profiling.h"
#include "fcc_utils.h"
#include "fcc_bundle_fields.h"
#include "storage_kcm.h"
#include "tinycbor.h"

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
const char g_fcc_bundle_scheme_version[] = "0.0.1";
extern bool g_is_session_finished;

/**
* Definition of max (key,value) in cbor top map
*/
#define FCC_MAX_KEYS_IN_MAP 12

/**
* Definition of max response buffer size
*/
// FIXME - use better allocation mechanism
#define MAX_RESPONSE_WITHOUT_CSRS 512
#define MAX_RESPONSE_WITH_CSRS 512*5

/* Response cbor blob structure
{  "Csrs": [ {"Name": "__", "Format":"_","Data":"__"},
             {"Name": "__", "Format":"_","Data":"__"}],
   "SchemeVersion": "0.0.1",
   "SID": text string,   
   "ReturnStatus": uint32_t,
   "InfoMessage": "detailed error string",
   "WarningInfo": "string of warnings"}
*/
/** Encode params to response cbor top map
*
* The function encode scheme version, session id, result of bundle buffer processing, error and warning strings.
* Note, CSR responses encoded during bundle process.
* 
* @return
*     true for success, false otherwise.
*/
static bool encode_response_params(CborEncoder *tcbor_map_encoder, const char *session_id, size_t session_id_len, fcc_status_e fcc_status)
{
    CborError tcbor_error = CborNoError;
    const char success_message[] = { "The Factory process succeeded\n" };
    char *p_info_msg = NULL;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    /* FCC_BUNDLE_SCHEME_GROUP_NAME - "SchemeVersion" */
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_BUNDLE_SCHEME_GROUP_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");
    /* Value */
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, g_fcc_bundle_scheme_version);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");

    /* FCC_FCU_SESSION_ID_GROUP_TYPE_NAME - "SID" */
    if(session_id != NULL) { 
        tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_FCU_SESSION_ID_GROUP_TYPE_NAME);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");
        /* Value */
        tcbor_error = cbor_encode_text_string(tcbor_map_encoder, session_id, session_id_len);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");
    }

    /* FCC_RETURN_STATUS_GROUP_NAME - "ReturnStatus" */
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_RETURN_STATUS_GROUP_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");
    /* Value */
    tcbor_error = cbor_encode_int(tcbor_map_encoder, fcc_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");

    /* FCC_ERROR_INFO_GROUP_NAME - "InfoMessage" */
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_ERROR_INFO_GROUP_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");
    /* Value */
    if (fcc_status == FCC_STATUS_SUCCESS) {
        p_info_msg = (char*)success_message;
    } else {
        p_info_msg = fcc_get_output_error_info();
        if (p_info_msg == NULL) {
            p_info_msg = (char*)g_fcc_general_status_error_str;
        }
    }
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, p_info_msg);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");

    /* FCC_WARNING_INFO_GROUP_NAME - "WarningInfo" */
    p_info_msg = fcc_get_output_warning_info();
    if (p_info_msg) {
        tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_WARNING_INFO_GROUP_NAME);
        if (tcbor_error != CborNoError) {
            goto free_info_msg;
        }
        /* Value */
        tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, p_info_msg);
free_info_msg:
        // free warning string
        fcc_free(p_info_msg);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "CBOR encode failure");
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return true;
}

/** Checks bundle scheme version
*
* @param tcbor_top_map[in]  The pointer to top cbor map in blob.
*
*  The function search for "SchemeVersion" key in the map and compare it to g_fcc_bundle_scheme_version.
*      "SchemeVersion" value can be byte or text string.
*
* @return
*     true for success, false otherwise.
*/
static bool check_scheme_version(CborValue *tcbor_top_map)
{
    CborError tcbor_error = CborNoError;
    CborValue tcbor_val;
    CborType tcbor_type;
    bool status;
    const char *scheme_version = NULL;
    size_t        scheme_version_len = 0;

    tcbor_error = cbor_value_map_find_value(tcbor_top_map, FCC_BUNDLE_SCHEME_GROUP_NAME, &tcbor_val);
    tcbor_type = cbor_value_get_type(&tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError || !(tcbor_type == CborTextStringType || tcbor_type == CborByteStringType)), 
                                    false, "Failed to get scheme version group");

    status = fcc_bundle_get_variant(&tcbor_val, (const uint8_t**)&scheme_version, &scheme_version_len, NULL, NULL, 0);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), status, "Failed to parse scheme version");

    SA_PV_ERR_RECOVERABLE_RETURN_IF((scheme_version_len != strlen(g_fcc_bundle_scheme_version)), false, "Wrong scheme version length");

    SA_PV_ERR_RECOVERABLE_RETURN_IF((strncmp(g_fcc_bundle_scheme_version, scheme_version, scheme_version_len) != 0), false, "Wrong scheme version");

    return true;
}

static bool run_basic_validation(const uint8_t *encoded_blob, size_t encoded_blob_size)
{
    CborParser tcbor_parser;
    CborValue tcbor_val;
    CborError tcbor_error = CborNoError;

    /* Init CBOR parser with blob message */
    tcbor_error = cbor_parser_init(encoded_blob, encoded_blob_size, 0, &tcbor_parser, &tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "cbor_parser_init failed (%" PRIu32 ")", (uint32_t)tcbor_error);

    // run tinycbor basic validation on the cbor message
    tcbor_error = cbor_value_validate_basic(&tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "cbor basic validation failed (%" PRIu32 ")", (uint32_t)tcbor_error);

    // advance tcbor_val by one element, skipping over containers.
    // expect it to point at the end of the blob (cbor blob size equal encoded_blob_size)
    tcbor_error = cbor_value_advance(&tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "cbor basic validation failed (%" PRIu32 ")", (uint32_t)tcbor_error);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_val.ptr != (encoded_blob + encoded_blob_size)), false, "cbor validation failed. unexpected blob size.");

    return true;
}

/* Request CBOR blob structure
{   "SchemeVersion": "0.0.1",
    "SID": text string,
    "IsNotLastMessage": 1 or 0,
    "Entropy": [byte array - 48 bytes],
    "CsrReqs": [ {"PrivKeyName":"__",
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
/* Response CBOR blob structure
{  "Csrs": [ {"Name": "__", "Format":"_","Data":"__"},
             {"Name": "__", "Format":"_","Data":"__"}],
   "SchemeVersion": "0.0.1",
   "SID": text string,   
   "ReturnStatus": uint32_t,
   "InfoMessage": "detailed error string",
   "WarningInfo": "string of warnings"}
*/
fcc_status_e fcc_bundle_handler(const uint8_t *encoded_blob, size_t encoded_blob_size, uint8_t **bundle_response_out, size_t *bundle_response_size_out)
{
    bool status = false;
    bool is_fcc_factory_disabled = false;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    const char *session_id = NULL;
    size_t session_id_len = 0;
    bool fcc_verify_status = true; // the default value of verify status is true
    bool fcc_keep_alive_status = false;// the default value of keep alive status is false
    bool fcc_disable_status = false;// the default value of disable status is false
    kcm_status_e kcm_status;

    CborParser tcbor_parser;
    CborValue tcbor_top_map;
    CborValue tcbor_val;
    CborValue tcbor_csr_reqs_val;
    size_t keys_in_map;
    const char *key_name;
    size_t key_name_len;

    CborEncoder tcbor_encoder;
    CborEncoder tcbor_map_encoder;
    CborError tcbor_error = CborNoError;
    uint8_t *response_buf = NULL;
    size_t response_buf_size = 0;

    FCC_SET_START_TIMER(fcc_bundle_timer);

    SA_PV_LOG_INFO_FUNC_ENTER("encoded_blob_size = %" PRIu32 "", (uint32_t)encoded_blob_size);

    // Check params
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!fcc_is_initialized()), FCC_STATUS_NOT_INITIALIZED, "FCC not initialized");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((bundle_response_out == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid bundle_response_out");
    *bundle_response_out = NULL;
    SA_PV_ERR_RECOVERABLE_RETURN_IF((bundle_response_size_out == NULL), FCC_STATUS_INVALID_PARAMETER, "Invalid bundle_response_size_out");
    *bundle_response_size_out = 0;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((encoded_blob == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit_and_response, "Invalid encoded_blob");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((encoded_blob_size == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit_and_response, "Invalid encoded_blob_size");

    // Initialize tcbor_csr_reqs_val type to invalid to indicate non existance of "CsrReqs" key
    tcbor_csr_reqs_val.type = CborInvalidType;

    /* Initialize fcc_output_info_s structure , in case of error during store process the
    function will exit without fcc_verify_device_configured_4mbed_cloud where we perform additional fcc_clean_output_info_handler*/
    fcc_clean_output_info_handler();

    // check blob validity. 
    status = run_basic_validation(encoded_blob, encoded_blob_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "cbor validation failed");

    /* Init CBOR parser with blob message */
    tcbor_error = cbor_parser_init(encoded_blob, encoded_blob_size, 0, &tcbor_parser, &tcbor_top_map);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "cbor_parser_init failed (%" PRIu32 ")", (uint32_t)tcbor_error);

    // check tcbor_top_map point is map
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_value_is_map(&tcbor_top_map) == false), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Wrong CBOR structure type");

    // check num of keys in top map. note: currently, we are not supporting indefinite map
    tcbor_error = cbor_value_get_map_length(&tcbor_top_map, &keys_in_map);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError || keys_in_map > FCC_MAX_KEYS_IN_MAP), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Wrong CBOR structure size");

    /* Check scheme version*/
    status = check_scheme_version(&tcbor_top_map);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), fcc_status = FCC_STATUS_BUNDLE_INVALID_SCHEME, exit_and_response, "check_scheme_version failed");

    /* In order for file functions to work properly, we must first inject the entropy, 
    *  if we have one to inject. If entropy is expected, its existance is required for
    *  every random number generation in the system.
    *  If FCC_ENTROPY_NAME not in bundle (and user did not use the fcc_entropy_set()), 
    *  then device must have TRNG or storage functions will fail.
    */
#ifndef FCC_NANOCLIENT_ENABLED
    fcc_status = fcc_bundle_process_rbp_buffer(&tcbor_top_map, FCC_ENTROPY_NAME, STORAGE_RBP_RANDOM_SEED_NAME);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_rbp_buffer failed for entropy");

    /* If RoT injection is expected (to derive storage key) it also must be done prior to storage calls */
    fcc_status = fcc_bundle_process_rbp_buffer(&tcbor_top_map, FCC_ROT_NAME, STORAGE_RBP_ROT_NAME);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_rbp_buffer failed for RoT");
#endif
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
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_status), exit_and_response, "Failed for kcm_init");

    // Check if factory flow is disabled (if flag in storage), if it is, do not proceed
    // Turn on is_fcc_factory_disabled even if we get an error, so that we know not to prepare a response
    fcc_status = fcc_is_factory_disabled(&is_fcc_factory_disabled);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), is_fcc_factory_disabled = true, exit_and_response, "Failed for fcc_is_factory_disabled");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((is_fcc_factory_disabled), fcc_status = FCC_STATUS_FACTORY_DISABLED_ERROR, exit_and_response, "FCC is disabled, service not available");
    
    // Enter top map container
    tcbor_error = cbor_value_enter_container(&tcbor_top_map, &tcbor_val);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Failed during parse of blob");

    // go over top map keys and process key values
    while (!cbor_value_at_end(&tcbor_val)) {

        // get key name
        status = fcc_bundle_get_text_string(&tcbor_val, &key_name, &key_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Failed during parse of blob");
        SA_PV_LOG_INFO(" key name %.*s", (int)key_name_len, key_name);

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Failed during parse of blob");

        if ((strncmp(FCC_BUNDLE_SCHEME_GROUP_NAME, key_name, key_name_len) == 0) ||
            (strncmp(FCC_ENTROPY_NAME, key_name, key_name_len) == 0) ||
            (strncmp(FCC_ROT_NAME, key_name, key_name_len) == 0)) {

            // key was handled before while loop

        } else if (strncmp(FCC_KEY_GROUP_NAME, key_name, key_name_len) == 0) {

            FCC_SET_START_TIMER(fcc_gen_timer);
            fcc_status = fcc_bundle_process_maps_in_arr(&tcbor_val, fcc_bundle_process_keys_cb, NULL);
            FCC_END_TIMER("Total keys process", 0 ,fcc_gen_timer);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_keys failed");

        } else if (strncmp(FCC_CERTIFICATE_GROUP_NAME, key_name, key_name_len) == 0) {

            FCC_SET_START_TIMER(fcc_gen_timer);
            fcc_status = fcc_bundle_process_maps_in_arr(&tcbor_val, fcc_bundle_process_certificates_cb, (void*)false);
            FCC_END_TIMER("Total certificates process", 0, fcc_gen_timer);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_certificates failed");

        } else if (strncmp(FCC_CERTIFICATE_CHAIN_GROUP_NAME, key_name, key_name_len) == 0) {

            FCC_SET_START_TIMER(fcc_gen_timer);
            fcc_status = fcc_bundle_process_maps_in_arr(&tcbor_val, fcc_bundle_process_certificates_cb, (void*)true);
            FCC_END_TIMER("Total certificate chains process", 0, fcc_gen_timer);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_certificate_chains failed");

        } else if (strncmp(FCC_CONFIG_PARAM_GROUP_NAME, key_name, key_name_len) == 0) {

            FCC_SET_START_TIMER(fcc_gen_timer);
            fcc_status = fcc_bundle_process_maps_in_arr(&tcbor_val, fcc_bundle_process_config_param_cb, NULL);
            FCC_END_TIMER("Total config params process", 0, fcc_gen_timer);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_config_params failed");

        } else if (strncmp(FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME, key_name, key_name_len) == 0) {

            // Check if device need to be verified
            status = fcc_bundle_get_bool(&tcbor_val, &fcc_verify_status, FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME, strlen(FCC_VERIFY_DEVICE_IS_READY_GROUP_NAME));
            SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "fcc_bundle_get_bool failed");

        } else if (strncmp(FCC_FACTORY_DISABLE_GROUP_NAME, key_name, key_name_len) == 0) {

            // Check if device need to be disabled for factory
            status = fcc_bundle_get_bool(&tcbor_val, &fcc_disable_status, FCC_FACTORY_DISABLE_GROUP_NAME, strlen(FCC_FACTORY_DISABLE_GROUP_NAME));
            SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "fcc_bundle_get_bool failed");

        } else if (strncmp(FCC_KEEP_ALIVE_SESSION_GROUP_NAME, key_name, key_name_len) == 0) {

            status = fcc_bundle_get_bool(&tcbor_val, &fcc_keep_alive_status, FCC_KEEP_ALIVE_SESSION_GROUP_NAME, strlen(FCC_KEEP_ALIVE_SESSION_GROUP_NAME));
            SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_INVALID_KEEP_ALIVE_SESSION_STATUS, exit_and_response, "fcc_bundle_get_bool failed");

        } else if (strncmp(FCC_FCU_SESSION_ID_GROUP_TYPE_NAME, key_name, key_name_len) == 0) {

            //Check if device need to be disabled for factory
            status = fcc_bundle_get_text_string(&tcbor_val, &session_id, &session_id_len, FCC_FCU_SESSION_ID_GROUP_TYPE_NAME, strlen(FCC_FCU_SESSION_ID_GROUP_TYPE_NAME));
            SA_PV_ERR_RECOVERABLE_GOTO_IF((!status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "fcc_bundle_get_text_string failed");

        } else if (strncmp(FCC_CSR_REQUESTS_GROUP_NAME, key_name, key_name_len) == 0) {

            // CSR requests depend on other keys so
            //  copy tcbor_val to tcbor_csr_reqs_val for later use.
            tcbor_csr_reqs_val = tcbor_val;
            
        } else {
            SA_PV_ERR_RECOVERABLE_GOTO_IF(true, fcc_status = FCC_STATUS_BUNDLE_INVALID_GROUP, exit_and_response, "Wrong group type");
        }

        // advance tcbor_val to next key in top map
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Failed during parse of blob");

    } // end loop (key,value)

    // set g_is_session_finished to the opossite value of keep alive flag
    g_is_session_finished = !fcc_keep_alive_status;

    // test illegal request - request to disable while not last blob in session
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_disable_status == true && g_is_session_finished == false), fcc_status = FCC_STATUS_BUNDLE_INVALID_KEEP_ALIVE_SESSION_STATUS, exit_and_response, "can not disable fcc for intermidiate message");

    // Check if there was CSR request waiting to be handled (is tcbor_csr_reqs_val point to valid type)
    if (cbor_value_is_valid(&tcbor_csr_reqs_val)) {
        SA_PV_ERR_RECOVERABLE_GOTO_IF((session_id == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Session ID is required when providing CSR requests");
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_verify_status || fcc_disable_status), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit_and_response, "Verify and Disable flags must not exist with CSR requests");
        FCC_SET_START_TIMER(fcc_gen_timer);
        if (response_buf == NULL) {
            // If not allocated before, allocate response message buffer to be used by tinycbor encoder
            // FIXME - use better allocation mechanism
            response_buf_size = MAX_RESPONSE_WITH_CSRS;
            response_buf = fcc_malloc(response_buf_size);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((response_buf == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, exit_and_free, "Failed to allocate message response buffer");    
            // initialize response encoder
            cbor_encoder_init(&tcbor_encoder, response_buf, response_buf_size, 0);
            // create the top map response encoder
            tcbor_error = cbor_encoder_create_map(&tcbor_encoder, &tcbor_map_encoder, CborIndefiniteLength);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit_and_free, "Failed to prepare out response");
        }
        fcc_status = fcc_bundle_process_csr_reqs(&tcbor_csr_reqs_val, &tcbor_map_encoder);
        FCC_END_TIMER("Total keys and CSR creation process", 0, fcc_gen_timer);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_bundle_process_csrs failed");
    }

    // If session finished
    if (g_is_session_finished) {
        // Note that FCC_STATUS_CA_ERROR is being return only in case where the CA already exists
        // in SOTP, if in the future more error conditions will be attached to FCC_STATUS_CA_ERROR error code
        // then the logic here MUST be change.
        // Only if this is the last message - set the certificate ID
#if defined (PAL_USE_SECURE_TIME) && (PAL_USE_SECURE_TIME == 1)
        fcc_status = fcc_trust_ca_cert_id_set();
        SA_PV_ERR_RECOVERABLE_GOTO_IF(((fcc_status != FCC_STATUS_SUCCESS) && (fcc_status != FCC_STATUS_CA_ERROR)), (fcc_status = fcc_status), exit_and_response, "CA store error %u", fcc_status);
#endif
    }

    if (fcc_verify_status == true) {
        // device VERIFY group does NOT exist in the CBOR message and device is NOT disabled.
        // Perform device verification to keep backward compatibility.

        FCC_SET_START_TIMER(fcc_gen_timer);
        fcc_status = fcc_verify_device_configured_4mbed_cloud();
        FCC_END_TIMER("Total verify device", 0, fcc_gen_timer);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_verify_device_configured_4mbed_cloud failed");
    }

    if (fcc_disable_status == true) {
        fcc_status = fcc_bundle_factory_disable();
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit_and_response, "fcc_factory_disable failed");
    }

exit_and_response:
    // If we discovered that factory is disabled (or fcc_is_factory_disabled failed) - do not prepare a response
    if (!is_fcc_factory_disabled) {
        if (response_buf == NULL) {
            // If not allocated before, allocate response message buffer to be used by tinycbor encoder
            // FIXME - use better allocation mechanism
            response_buf_size = MAX_RESPONSE_WITHOUT_CSRS;
            response_buf = fcc_malloc(response_buf_size);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((response_buf == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, exit_and_free, "Failed to allocate message response buffer");    
            // initialize response encoder
            cbor_encoder_init(&tcbor_encoder, response_buf, response_buf_size, 0);
            // create the top map response encoder
            tcbor_error = cbor_encoder_create_map(&tcbor_encoder, &tcbor_map_encoder, CborIndefiniteLength);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit_and_free, "Failed to prepare out response");
        } else {
            // If response_buf was allocated and there was error during message process, drop previously encoded data
            if (fcc_status != FCC_STATUS_SUCCESS) {
                // initialize response encoder
                cbor_encoder_init(&tcbor_encoder, response_buf, response_buf_size, 0);
                // create the top map response encoder
                tcbor_error = cbor_encoder_create_map(&tcbor_encoder, &tcbor_map_encoder, CborIndefiniteLength);
                SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit_and_free, "Failed to prepare out response");
            }
        }

        // Encode bundle response params
        status = encode_response_params(&tcbor_map_encoder, session_id, session_id_len, fcc_status);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != true), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit_and_free, "Failed to prepare out response");

        // close top map response encoder
        tcbor_error = cbor_encoder_close_container(&tcbor_encoder, &tcbor_map_encoder);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit_and_free, "Failed to prepare out response");

        // set bundle_response_out
        *bundle_response_out = response_buf;

        // set bundle_response_size_out to actual cbor buffer size
        *bundle_response_size_out = cbor_encoder_get_buffer_size(&tcbor_encoder, response_buf);

        FCC_END_TIMER("Total fcc_bundle_handler device", 0, fcc_bundle_timer);
    }
exit_and_free:
    if (response_buf && *bundle_response_out != response_buf) {
        // We have start encoding the response but got an error before setting *bundle_response_out, free the response_buf
        fcc_free(response_buf);
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}
