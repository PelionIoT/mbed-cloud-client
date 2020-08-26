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
#include "fcc_bundle_utils.h"
#include "fcc_bundle_handler.h"
#include "fcc_malloc.h"
#include "pv_error_handling.h"
#include "fcc_utils.h"
#include "fcc_bundle_fields.h"
#include "cs_der_keys_and_csrs.h"
#include "pv_macros.h"

static bool parse_csr_extensions(const CborValue *tcbor_map_val, kcm_csr_params_s *csr_params)
{
    bool status;
    CborError tcbor_error = CborNoError;
    const char    *ext_name = NULL;
    size_t        ext_name_len = 0;
    uint64_t      ext_val;
    CborValue tcbor_val;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((!cbor_value_is_map(tcbor_map_val)), false, "Failed during parse CSR request");

    tcbor_error = cbor_value_enter_container(tcbor_map_val, &tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "Failed during parse of blob");

    // go over the map elements (key,value)
    while (!cbor_value_at_end(&tcbor_val)) {

        // get ext name
        status = fcc_bundle_get_text_string(&tcbor_val, &ext_name, &ext_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), false, "Failed during parse CSR request");

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "Failed during parse CSR request");

        if (strncmp(FCC_CSRREQ_INBOUND_EXTENSION_KEYUSAGE_NAME, ext_name, ext_name_len) == 0) {

            // extension found
            status = fcc_bundle_get_uint64(&tcbor_val, &ext_val, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), false, "Failed during parse CSR request");
            // save extension in csr_params
            csr_params->key_usage = (uint32_t)ext_val;

        } else if (strncmp(FCC_CSRREQ_INBOUND_EXTENSION_EXTENDEDKEYUSAGE_NAME, ext_name, ext_name_len) == 0) {
            
            // extension found
            status = fcc_bundle_get_uint64(&tcbor_val, &ext_val, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), false, "Failed during parse CSR request");
            // save extension in csr_params
            csr_params->ext_key_usage = (uint32_t)ext_val;
        }
        // Note: Currently , 'trust level' is not supported

        // advance tcbor_val to next extension
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), false, "Failed during parse CSR request");

    } // end loop element

    return true;
}

static fcc_status_e parse_csr_storage_medium(const CborValue *tcbor_map_val, void *kcm_item_ctx_out, bool *is_gen_public_key_out)
{
    bool status;
    CborError tcbor_error = CborNoError;
    const char *key_name = NULL;
    size_t key_name_len = 0;
    const char *priv_key_storage_medium_val = NULL;
    size_t priv_key_storage_medium_val_len = 0;
    const char *pub_key_storage_medium_val = NULL;
    size_t pub_key_storage_medium_val_len = 0;
    CborValue tcbor_val;
    size_t storage_medium_map_length = 0;
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
    kcm_item_extra_info_s *kcm_item_ctx = (kcm_item_extra_info_s *)kcm_item_ctx_out;
#endif

    SA_PV_ERR_RECOVERABLE_RETURN_IF((!cbor_value_is_map(tcbor_map_val)), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

    tcbor_error = cbor_value_enter_container(tcbor_map_val, &tcbor_val);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse of blob");

    tcbor_error = cbor_value_get_map_length(tcbor_map_val, &storage_medium_map_length);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse of blob");

    SA_PV_ERR_RECOVERABLE_RETURN_IF((storage_medium_map_length != 1) && (storage_medium_map_length != 2), FCC_STATUS_BUNDLE_ERROR, "Storage Medium map length is invalid");

    *is_gen_public_key_out = false; // assume no public key request

    // go over the map elements (key,value)
    while (!cbor_value_at_end(&tcbor_val)) {

        // get 'Prv' or 'Pub' name ('Prv' stands for Private key, 'Pub' stands for Public key)
        status = fcc_bundle_get_text_string(&tcbor_val, &key_name, &key_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        if (strncmp(FCC_CSRREQ_INBOUND_STORAGE_MEDIUM_PRIVATE_KEY_NAME, key_name, key_name_len) == 0) {
            // private key found in Storage Medium group
            status = fcc_bundle_get_text_string(&tcbor_val, &priv_key_storage_medium_val, &priv_key_storage_medium_val_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

            // store the selected storage medium of the private key
            if (strncmp(FCC_CSRREQ_INBOUND_SM_SECURE_ELEMENT_NAME, priv_key_storage_medium_val, priv_key_storage_medium_val_len) == 0) {
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
                kcm_item_ctx->priv_key_location = KCM_LOCATION_SECURE_ELEMENT;
#else
                SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_NOT_SUPPORTED, "CSR request field is not supported");
#endif
            } else if (strncmp(FCC_CSRREQ_INBOUND_SM_DEVICE_NAME, priv_key_storage_medium_val, priv_key_storage_medium_val_len) == 0) {
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
                kcm_item_ctx->priv_key_location = KCM_LOCATION_PSA;
#else
                PV_UNUSED_PARAM(kcm_item_ctx_out); // nothing todo for no PSA/SE, avoid warning
#endif
            } else {
                // Got invalid value for storage medium
                SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");
            }
        } else if (strncmp(FCC_CSRREQ_INBOUND_STORAGE_MEDIUM_PUBLIC_KEY_NAME, key_name, key_name_len) == 0) {

            // private key found in Storage Medium group
            status = fcc_bundle_get_text_string(&tcbor_val, &pub_key_storage_medium_val, &pub_key_storage_medium_val_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!status), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

            // store the selected storage medium of the private key
            if (strncmp(FCC_CSRREQ_INBOUND_SM_SECURE_ELEMENT_NAME, pub_key_storage_medium_val, pub_key_storage_medium_val_len) == 0) {
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
                kcm_item_ctx->pub_key_location = KCM_LOCATION_SECURE_ELEMENT;
#else
                SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_NOT_SUPPORTED, "CSR request field is not supported");
#endif
            } else if (strncmp(FCC_CSRREQ_INBOUND_SM_DEVICE_NAME, pub_key_storage_medium_val, pub_key_storage_medium_val_len) == 0) {
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
                kcm_item_ctx->pub_key_location = KCM_LOCATION_PSA;
#else
                PV_UNUSED_PARAM(kcm_item_ctx_out); // nothing todo for no PSA/SE, avoid warning
#endif
            } else {
                // Got invalid value for storage medium
                SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");
            }

            *is_gen_public_key_out = true; // generate public key
        } else {
            return FCC_STATUS_BUNDLE_ERROR;  // unsupported string detected
        }

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(&tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");
    } // while

    // check a case where the blob contains only a public key (private key is absence)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((storage_medium_map_length == 1) && ((*is_gen_public_key_out) == true), FCC_STATUS_BUNDLE_ERROR, "CSR request field is not supported");

    return FCC_STATUS_SUCCESS;
}

static fcc_status_e generate_and_encode_csr_response(const uint8_t             *priv_key_name, size_t priv_key_name_len,
                                                     const uint8_t             *pub_key_name,  size_t pub_key_name_len,
                                                     const kcm_csr_params_s    *csr_params,
                                                     const kcm_security_desc_s  kcm_item_ctx,
                                                     CborEncoder               *tcbor_map_encoder)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    CborError tcbor_error = CborNoError;
    uint8_t *csr_buff = NULL;
    size_t csr_buff_len = 0;
    size_t act_csr_len = 0;

    /* Encode FCC_CSR_OUTBOUND_MAP_PRIVATE_KEY_NAME - "PrKN" */
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_CSR_OUTBOUND_MAP_PRIVATE_KEY_NAME);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR, Exit, "CBOR encode failure");
    /* Value */
    tcbor_error = cbor_encode_text_string(tcbor_map_encoder, (char*)priv_key_name, priv_key_name_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR, Exit, "CBOR encode failure");

    /* Encode FCC_CSR_OUTBOUND_MAP_DATA - "Data" */
    tcbor_error = cbor_encode_text_stringz(tcbor_map_encoder, FCC_CSR_OUTBOUND_MAP_DATA);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR, Exit, "CBOR encode failure");

    // Start encoding CSR as byte string - gets pointer to encoded buffer and the size can be used
    tcbor_error = cbor_encode_byte_string_start(tcbor_map_encoder, (const uint8_t**)&csr_buff, &csr_buff_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR, Exit, "CBOR encode failure");

    // Generate the keys and the CSR (directly to the encoded buffer)
    kcm_status = kcm_generate_keys_and_csr(KCM_SCHEME_EC_SECP256R1, priv_key_name, priv_key_name_len,
                                            pub_key_name, pub_key_name_len, true, csr_params,
                                            csr_buff, csr_buff_len, &act_csr_len, kcm_item_ctx);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = fcc_convert_kcm_to_fcc_status(kcm_status), Exit, "failed to generate csr");

    // Finish encoding the CSR byte string with the actual bytes used
    tcbor_error = cbor_encode_byte_string_finish(tcbor_map_encoder, act_csr_len);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR, Exit, "CBOR encode failure");
    
Exit:
    // If KCM error - store the KCM error, If FCC error, store the FCC error
    if (kcm_status != KCM_STATUS_SUCCESS) {
        (void)fcc_bundle_store_kcm_error_info(NULL, 0, kcm_status);
    } 
    
    return fcc_status;
}

static fcc_status_e process_csr_request_cb(CborValue *tcbor_val, void *extra_info)
{
    CborEncoder *tcbor_arr_encoder = (CborEncoder*)extra_info;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    bool success;
    CborError tcbor_error = CborNoError;
    const char    *key_name = NULL;
    size_t        key_name_len = 0;
    const char    *priv_key_name = NULL;
    size_t        priv_key_name_len = 0;
    const char    *pub_key_name = NULL;
    size_t        pub_key_name_len = 0;
    const char    *subject = NULL;
    size_t        subject_len = 0;
    uint64_t      val64;
    kcm_csr_params_s csr_params;
    CborEncoder tcbor_map_encoder;
    bool is_gen_public_key = false; // assume no need to generate public key
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
    kcm_item_extra_info_s item_extra_info = kcm_item_extra_info_init();
    kcm_item_extra_info_s *kcm_item_ctx = &item_extra_info;
#else
    void *kcm_item_ctx = NULL;  // no PSA neither SE
#endif

    memset(&csr_params, 0, sizeof(kcm_csr_params_s));

    // go over the map elements (key,value)
    while (!cbor_value_at_end(tcbor_val)) {

        // get key name
        success = fcc_bundle_get_text_string(tcbor_val, &key_name, &key_name_len, NULL, 0);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        // advance tcbor_val to key value
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        if (strncmp(FCC_CSRREQ_INBOUND_PRIVATE_KEY_NAME, key_name, key_name_len) == 0) {

            // get private key name
            success = fcc_bundle_get_text_string(tcbor_val, &priv_key_name, &priv_key_name_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        } else if (strncmp(FCC_CSRREQ_INBOUND_EXTENSIONS_NAME, key_name, key_name_len) == 0) {

            // parse extensions
            success = parse_csr_extensions(tcbor_val, &csr_params);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        } else if (strncmp(FCC_CSRREQ_INBOUND_SUBJECT_NAME, key_name, key_name_len) == 0) {

            // get CSR's subject
            success = fcc_bundle_get_text_string(tcbor_val, &subject, &subject_len, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

        } else if (strncmp(FCC_CSRREQ_INBOUND_MESSAGEDIGEST_NAME, key_name, key_name_len) == 0) {

            // get CSR's MD
            success = fcc_bundle_get_uint64(tcbor_val, &val64, NULL, 0);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((!success), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");
            // save MD type in csr_params
            csr_params.md_type = (kcm_md_type_e)val64;

        } else if (strncmp(FCC_CSRREQ_INBOUND_STORAGE_MEDIUM_NAME, key_name, key_name_len) == 0) {

            // get CSR's Storage Medium for private and public keys (the public key may be absent)
            fcc_status = parse_csr_storage_medium(tcbor_val, kcm_item_ctx, &is_gen_public_key);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "Failed during parse CSR request");

        } else {
            SA_PV_ERR_RECOVERABLE_RETURN_IF((true), FCC_STATUS_NOT_SUPPORTED, "CSR request field is not supported");
        }

        // advance tcbor_val to next key name
        tcbor_error = cbor_value_advance(tcbor_val);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_ERROR, "Failed during parse CSR request");

    } // end loop element

    // check existence of mandatory fields (name and data)
    SA_PV_ERR_RECOVERABLE_RETURN_IF((priv_key_name == NULL || subject == NULL || csr_params.md_type == KCM_MD_NONE),
                                    FCC_STATUS_BUNDLE_ERROR, "mandatory CSR request fields is missing");

    // Copy subject to new buffer and set csr_params.subject
    // Note, subject must be terminated with a '\0'.
    // Allocate new buffer, copy subject and add '\0' terminator
    csr_params.subject = fcc_malloc(subject_len + 1);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params.subject == NULL), FCC_STATUS_MEMORY_OUT, "Error allocating subject");
    memcpy(csr_params.subject, subject, subject_len);
    csr_params.subject[subject_len] = '\0';

    // Create map encoder for next CSR
    tcbor_error = cbor_encoder_create_map(tcbor_arr_encoder, &tcbor_map_encoder, CborIndefiniteLength);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_RESPONSE_ERROR, "Error encoding CSR");

    // The public key carry the exact name of the private key,
    // so we just need to point the private key name. Otherwise
    // those will pass as NULL values by declaration.
    if (is_gen_public_key) {
        pub_key_name = priv_key_name;
        pub_key_name_len = priv_key_name_len;
    }

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#ifdef MBED_CONF_APP_SECURE_ELEMENT_PARSEC_TPM_SUPPORT
    if (memcmp((const char*)priv_key_name, g_fcc_bootstrap_device_private_key_name, priv_key_name_len) == 0) {
        //Set SE location to create parsec bootstrap private key inside tpm
        item_extra_info.priv_key_location = KCM_LOCATION_SECURE_ELEMENT;
        item_extra_info.pub_key_location = KCM_LOCATION_SECURE_ELEMENT;
        kcm_item_ctx = &item_extra_info;
    }
#endif
#endif//MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

    // parse and process CSR request and encode CSR response into tcbor_map_encoder
    fcc_status = generate_and_encode_csr_response(
        (const uint8_t*)priv_key_name, priv_key_name_len,
        (const uint8_t*)pub_key_name, pub_key_name_len,
        &csr_params, kcm_item_ctx, &tcbor_map_encoder);

    // free csr_params.subject anyway
    fcc_free(csr_params.subject);

    SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "Error generate and encode CSR");

    // close map encoder
    tcbor_error = cbor_encoder_close_container(tcbor_arr_encoder, &tcbor_map_encoder);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tcbor_error != CborNoError), FCC_STATUS_BUNDLE_RESPONSE_ERROR, "Error encoding CSR");

    return fcc_status;
}

fcc_status_e fcc_bundle_process_csr_reqs(const CborValue *tcbor_csr_reqs_val, CborEncoder *tcbor_top_map_encoder)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_status_e output_info_fcc_status = FCC_STATUS_SUCCESS;
    CborEncoder tcbor_arr_encoder;
    CborError tcbor_error = CborNoError;
    size_t num_of_reqs = 0;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cbor_value_is_array(tcbor_csr_reqs_val)), fcc_status = FCC_STATUS_BUNDLE_ERROR, exit, "Unexpected CBOR type");

    tcbor_error = cbor_value_get_array_length(tcbor_csr_reqs_val, &num_of_reqs);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit, "Failed during parse CSR requests");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((num_of_reqs > CSR_MAX_NUMBER_OF_CSRS), fcc_status = FCC_STATUS_TOO_MANY_CSR_REQUESTS, exit, "More CSR requests than the maximum allowed");
    
    // Encode FCC_CSR_OUTBOUND_GROUP_NAME - "Csrs"
    tcbor_error = cbor_encode_text_stringz(tcbor_top_map_encoder, FCC_CSR_OUTBOUND_GROUP_NAME);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit, "Error encoding CSR");

    // Create array with size num_of_reqs for each CSR request
    tcbor_error = cbor_encoder_create_array(tcbor_top_map_encoder, &tcbor_arr_encoder, num_of_reqs);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit, "Error encoding CSR");

    // go over csr reqs maps, parse request and encode csr response
    fcc_status = fcc_bundle_process_maps_in_arr(tcbor_csr_reqs_val, process_csr_request_cb, (void*)&tcbor_arr_encoder);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = fcc_status), exit, "Failed during parse CSR requests");

    // close array encoder
    tcbor_error = cbor_encoder_close_container(tcbor_top_map_encoder, &tcbor_arr_encoder);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((tcbor_error != CborNoError), (fcc_status = FCC_STATUS_BUNDLE_RESPONSE_ERROR), exit, "Failed to prepare out response");

exit:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        output_info_fcc_status = fcc_store_error_info(NULL, 0, fcc_status);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((output_info_fcc_status != FCC_STATUS_SUCCESS),
                                        fcc_status = FCC_STATUS_OUTPUT_INFO_ERROR,
                                        "Failed to create output fcc_status error %d", fcc_status);
    }

    return fcc_status;
}
