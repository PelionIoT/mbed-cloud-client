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

#include "fcc_bundle_utils.h"
#include "fcc_bundle_handler.h"
#include "fcc_malloc.h"
#include "pv_error_handling.h"
#include "fcc_utils.h"
#include "kcm_internal.h"
#include "fcc_bundle_fields.h"

// For convenience when migrating to tinycbor
#define CN_CBOR_NEXT_GET(cn) cn->next 

// Initial attempt to allocate buffer for generated CSR will be <size (in bytes) of the encoded CSR request map (part of the CBOR)> + CSR_INITIAL_EXTRA_ALLOCATION_BYTES.
// If the allocation is not enough we keep allocating an extra CSR_ALLOCATION_STEP until the buffer is sufficiently large, or, the allocation fails.
#define CSR_INITIAL_EXTRA_ALLOCATION_BYTES 100
#define CSR_ALLOCATION_STEP 100


// FIXME: Temporary. This is a workaround so that the memory is still allocated when calling cn_cbor_encoder_write().
// When we migrate to tinycbor we could either write the CSR directly into the preallocated encoder buffer, or write to a separate buffer, then write to the encoder, then immediately free the separate buffer.
uint8_t *g_csr_buf[CSR_MAX_NUMBER_OF_CSRS] = { 0 };

void g_csr_buf_free()
{
    int i;

    for (i = 0; i < CSR_MAX_NUMBER_OF_CSRS; i++) {
        fcc_free(g_csr_buf[i]);
        g_csr_buf[i] = NULL;
    }
}

static uint8_t **g_csr_next_available()
{
    int i;

    for (i = 0; i < CSR_MAX_NUMBER_OF_CSRS; i++) {
        if (!g_csr_buf[i]) {
            return &g_csr_buf[i];
        }
    }

    return NULL;
}


static fcc_status_e csr_extensions_parse(const cn_cbor *parser, kcm_csr_params_s *csr_params_out)
{
    cn_cbor *cbor_iterator, *cbor_extension_map;

    // Get the extensions from the map - a map (optional, return success if does not exist)
    cbor_extension_map = cn_cbor_mapget_string(parser, FCC_CSRREQ_INBOUND_EXTENSIONS_NAME);
    if (!cbor_extension_map) {
        return FCC_STATUS_SUCCESS;
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_extension_map->type != CN_CBOR_MAP), FCC_STATUS_BUNDLE_ERROR, "Extensions wrong format");

    // FIXME: Should parse the trust level from the extensions. Currently not in use

    // Parse key usage (optional)
    cbor_iterator = cn_cbor_mapget_string(cbor_extension_map, FCC_CSRREQ_INBOUND_EXTENSION_KEYUSAGE_NAME);
    if (cbor_iterator) {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_iterator->type != CN_CBOR_UINT), FCC_STATUS_BUNDLE_ERROR, "Key usage wrong format");
        csr_params_out->key_usage = (uint32_t)cbor_iterator->v.uint;
    }

    // Parse extended key usage (optional)
    cbor_iterator = cn_cbor_mapget_string(cbor_extension_map, FCC_CSRREQ_INBOUND_EXTENSION_EXTENDEDKEYUSAGE_NAME);
    if (cbor_iterator) {
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_iterator->type != CN_CBOR_UINT), FCC_STATUS_BUNDLE_ERROR, "Extended Key usage wrong format");
        csr_params_out->ext_key_usage = (uint32_t)cbor_iterator->v.uint;
    }

    return FCC_STATUS_SUCCESS;
}
/*
* parser - points to a CSR request map
*/
static fcc_status_e csr_params_parse(const cn_cbor *parser, kcm_csr_params_s *csr_params_out)
{
    cn_cbor *cbor_iterator;
    fcc_status_e fcc_status;

    // Parse the extension (optional - will return success if extensions do not exist)
    fcc_status = csr_extensions_parse(parser, csr_params_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "Error parsing CSR extensions");

    // Retrieve the MD type
    cbor_iterator = cn_cbor_mapget_string(parser, FCC_CSRREQ_INBOUND_MESSAGEDIGEST_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_iterator == NULL), FCC_STATUS_BUNDLE_ERROR, "No MD type");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_iterator->type != CN_CBOR_UINT), FCC_STATUS_BUNDLE_ERROR, "MD type wrong format");

    csr_params_out->md_type = (kcm_md_type_e)cbor_iterator->v.uint;

    // Retrieve the subject
    cbor_iterator = cn_cbor_mapget_string(parser, FCC_CSRREQ_INBOUND_SUBJECT_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_iterator == NULL), FCC_STATUS_BUNDLE_ERROR, "No subject");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_iterator->type != CN_CBOR_BYTES && cbor_iterator->type != CN_CBOR_TEXT), FCC_STATUS_BUNDLE_ERROR, "Subject wrong format");

    // Allocate memory for the subject, it may be large and must be terminated with a '\0' terminator
    csr_params_out->subject = fcc_malloc((size_t)cbor_iterator->length + 1);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((csr_params_out->subject == NULL), FCC_STATUS_MEMORY_OUT, "Error allocating subject");

    memcpy(csr_params_out->subject, cbor_iterator->v.bytes, (size_t)cbor_iterator->length);

    // Append the NULL terminator
    csr_params_out->subject[cbor_iterator->length] = '\0';

    return FCC_STATUS_SUCCESS;
}

/** Parse, create, and encode the next CSR map into the CSR cbor array in the response CBOR
* The outcome of this function is that the following map will be appended to the encoder: {"PrKN: "<name>", "Data": <CSR byte array>}
* @param parser CSRrequest map:
*    INBOUND MESSAGE:
*    {
*     ...
*
*     "CsrReqs" : [ { ... }, { ... }, ... , <YOU ARE HERE> ]
*
*     ...
*    }
*
* @param encoder - points to the next place in the CSR CBOR array:
*    OUTBOUND MESSAGE:
*    {
*     ...
*
*     "Csrs" : [ { ... }, { ... }, ... , <YOU ARE HERE> ]
*
*     ...
*    }
*
*
*/
static fcc_status_e encode_next_csr(const cn_cbor *parser, cn_cbor *encoder)
{
    kcm_csr_params_s csr_params;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_status_e output_info_fcc_status = FCC_STATUS_SUCCESS;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    bool status;
    size_t csr_extra_bytes = CSR_INITIAL_EXTRA_ALLOCATION_BYTES;
    size_t csr_buf_len;
    const uint8_t *private_key_name, *public_key_name;
    size_t private_key_name_len, public_key_name_len;
    int approximated_csr_size = 0;
    uint8_t **csr_buf;
    size_t csr_len = 0;

    char *key;
    cn_cbor *val, *cbor, *encoder_iterator;

    memset(&csr_params, 0, sizeof(kcm_csr_params_s));

    // First, Create and open a new map for the encoder, that will eventually look like that {"PrKN: "<name>", "Data": <CSR byte array>}
    encoder_iterator = cn_cbor_map_create(CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((encoder_iterator == NULL), FCC_STATUS_MEMORY_OUT, "Error creating CBOR");

    // Push the empty map into the encoder (open the container part 2)
    status = cn_cbor_array_append(encoder, encoder_iterator, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status == false), FCC_STATUS_BUNDLE_ERROR, "CBOR error");

    // Get private key name
    cbor = cn_cbor_mapget_string(parser, FCC_CSRREQ_INBOUND_PRIVATE_KEY_NAME);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor == NULL), FCC_STATUS_BUNDLE_ERROR, "No private key in message");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor->type != CN_CBOR_TEXT), FCC_STATUS_BUNDLE_ERROR, "No private key in message");

    private_key_name = cbor->v.bytes;
    private_key_name_len = (size_t)cbor->length;

    // Append Name key-value into the encoder
    val = cn_cbor_text_create(private_key_name, (int)private_key_name_len, CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((val == NULL), FCC_STATUS_MEMORY_OUT, "Error creating CBOR");
    status = cn_cbor_mapput_string(encoder_iterator, FCC_CSR_OUTBOUND_MAP_PRIVATE_KEY_NAME, val, CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status == false), FCC_STATUS_BUNDLE_ERROR, "CBOR error");

    // Get public key name. Field is optional, if does not exist - set to NULL
    cbor = cn_cbor_mapget_string(parser, FCC_CSRREQ_INBOUND_PUBLIC_KEY_NAME);
    if (cbor == NULL) {
        public_key_name = NULL;
        public_key_name_len = 0;
    } else {
        public_key_name = cbor->v.bytes;
        public_key_name_len = (size_t)cbor->length;
    }

    // Extract CSR params
    fcc_status = csr_params_parse(parser, &csr_params);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, Exit, "Error parsing CSR params");

    // Gets the size in bytes of the encoded CSR request map
    approximated_csr_size = cn_cbor_get_encoded_container_size(parser);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((approximated_csr_size < 0), fcc_status = FCC_STATUS_BUNDLE_ERROR, Exit, "Error getting encoded CBOR size");

    approximated_csr_size += KCM_EC_SECP256R1_MAX_PUB_KEY_DER_SIZE + KCM_ECDSA_SECP256R1_MAX_SIGNATURE_SIZE_IN_BYTES;

    csr_buf = g_csr_next_available();

    // Start with an approximate allocation and keep trying to increase the allocation until it is sufficiently large, or some error occurres.
    while (true) {
        csr_buf_len = (size_t)approximated_csr_size + csr_extra_bytes;
        *csr_buf = fcc_malloc(csr_buf_len);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((*csr_buf == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, Exit, "Error generating CSR");

        // Generate the CSR into the encoder 
        // FIXME: when migrating to tinycbor we might want to try to encode it directly into the encoder buffer. This may require manually creating the cbor byte-array prefix (major type 3)
        // Requires understanding the CBOR mechanism but could save significant space since this way the CSR will not be duplicated.
        kcm_status = kcm_generate_keys_and_csr(KCM_SCHEME_EC_SECP256R1, private_key_name, private_key_name_len,
                                               public_key_name, public_key_name_len, true, &csr_params,
                                               *csr_buf, csr_buf_len, &csr_len,
                                               NULL);
        if (kcm_status == KCM_STATUS_SUCCESS) {
            break;
        } else if (kcm_status == KCM_STATUS_INSUFFICIENT_BUFFER) { // If buffer insufficient - attempt with larger buffer
            csr_extra_bytes += CSR_ALLOCATION_STEP;
        } else {
            fcc_status = fcc_convert_kcm_to_fcc_status(kcm_status);
            goto Exit;
        }
    }

    // Append the encoded CSR data key-value to the CSR response map
    key = FCC_CSR_OUTBOUND_MAP_DATA;
    val = cn_cbor_data_create(*csr_buf, (int)csr_len, CBOR_CONTEXT_PARAM_COMMA NULL);    
    SA_PV_ERR_RECOVERABLE_GOTO_IF((val == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, Exit, "Error creating CBOR");

    status = cn_cbor_mapput_string(encoder_iterator, key, val, CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status == false), fcc_status = FCC_STATUS_BUNDLE_ERROR, Exit, "CBOR error");

    // FIXME: For tinycbor - this would be the time to close the map opened in the beginning - {"Name: "<name>", "Format": "der", "Data": <CSR byte array>}

Exit:
    fcc_free(csr_params.subject);
    // If KCM error - store the KCM error, If FCC error, store the FCC error
    if (kcm_status != KCM_STATUS_SUCCESS) {
        output_info_fcc_status = fcc_bundle_store_error_info(private_key_name, private_key_name_len, kcm_status);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((output_info_fcc_status != FCC_STATUS_SUCCESS),
                                        fcc_status = FCC_STATUS_OUTPUT_INFO_ERROR,
                                        "Failed to create output kcm_status error %d", kcm_status);
    } 
    

    return fcc_status;
}

/** Parse a CBOR array of CSR requests, for each CSR request - generate the keys and the CSR, save the keys in the persistent storage, and encode the CSR in the response encoder.
* @param csrs_list_cb CSR Requests array:
*    INBOUND MESSAGE:
*    {
*     ...
*
*     "CsrReqs" : <YOU ARE HERE>
*
*     ...
*    }
*
* @param response_encoder - points to the next place in the CSR CBOR array:
*    OUTBOUND MESSAGE:
*    {
*     "SchemeVersion": "0.0.1", 
*     ...
*
*     <YOU ARE HERE>
*
*     ...
*    }
*
*
*/
fcc_status_e fcc_bundle_process_csrs(const cn_cbor *csrs_list_cb, cn_cbor *response_encoder)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    fcc_status_e output_info_fcc_status = FCC_STATUS_SUCCESS;
    cn_cbor *cbor, *encoder_iterator;
    const cn_cbor *parser_iterator;
    bool status;
    int i = 0;

    SA_PV_ERR_RECOVERABLE_GOTO_IF((csrs_list_cb == NULL || response_encoder == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, SetError, "Invalid cbor_blob");
    
    // Make sure we get a array of CSR requests
    SA_PV_ERR_RECOVERABLE_GOTO_IF((csrs_list_cb->type != CN_CBOR_ARRAY), fcc_status = FCC_STATUS_BUNDLE_ERROR, SetError, "CSR requests must be array");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((csrs_list_cb->length > CSR_MAX_NUMBER_OF_CSRS), fcc_status = FCC_STATUS_TOO_MANY_CSR_REQUESTS, SetError, "More CSR requests than the maximum allowed");

    parser_iterator = csrs_list_cb;

    // Open a new map for the encoder (open the container part 1)
    cbor = cn_cbor_array_create(CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, SetError, "Error creating CBOR");

    // Push the empty array into the encoder (open the container part 2)
    status = cn_cbor_mapput_string(response_encoder, FCC_CSR_OUTBOUND_GROUP_NAME, cbor, CBOR_CONTEXT_PARAM_COMMA NULL);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status == false), fcc_status = FCC_STATUS_BUNDLE_ERROR, SetError, "Error appending");

    // Step into the encoder array (the last child is the value of the last appended KV pair which is the empty array)
    encoder_iterator = response_encoder->last_child;

    // Go to the first value of the array
    parser_iterator = parser_iterator->first_child;

    for (i = 0; i < csrs_list_cb->length; i++) {

        SA_PV_ERR_RECOVERABLE_GOTO_IF((parser_iterator == NULL), fcc_status = FCC_STATUS_BUNDLE_ERROR, SetError, "Error getting CBOR");

        fcc_status = encode_next_csr(parser_iterator, encoder_iterator);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, SetError, "Error encoding CSR");
        
        // step into next value in the CBOR array
        parser_iterator = CN_CBOR_NEXT_GET(parser_iterator);
    }

SetError:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        output_info_fcc_status = fcc_store_error_info(NULL, 0, fcc_status);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((output_info_fcc_status != FCC_STATUS_SUCCESS),
                                        fcc_status = FCC_STATUS_OUTPUT_INFO_ERROR,
                                        "Failed to create output fcc_status error %d", fcc_status);
    }

    return fcc_status;
}
