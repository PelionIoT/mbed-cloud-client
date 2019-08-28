// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

#include "sda_bundle_parser.h"
#include "sda_error_handling.h"
#include "sda_malloc.h"
#include "sda_internal_defs.h"
#include "sda_macros.h"
#include "sda_cose.h"
#include "sda_verification.h"
#include "secure_device_access.h"
#include "cose.h"
#include "tinycbor.h"

/* The function assumes that cbor_value is a iterator of initialized container,
  the function calculates payload of current value by iteration to a next value in the container*/
static sda_status_internal_e get_parameter_data(CborValue *operation_parameters_array, sda_parameter_data_s *parameter_data)
{
    
    CborError cbor_error = CborNoError;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    switch (parameter_data->parameter_type) {
    case SDA_STRING_FUNCTION_PARAMETER:
        //Check type of current member
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(operation_parameters_array) != CborTextStringType), SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "Wrong type of type-id member");

        //Get data parameter 
        cbor_error = cbor_value_get_text_string_chunk(operation_parameters_array, (const char **)&(parameter_data->data_param), &parameter_data->data_param_size, NULL);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get data parameter pointer");
        break;

    case SDA_NUMERIC_PARAMETER:
        //Check type of current member
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(operation_parameters_array) != CborIntegerType), SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "Wrong type of type-id member");

        //Get numeric parameter 
        cbor_error = cbor_value_get_int64(operation_parameters_array, &parameter_data->numeric_parameter);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError),SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get numeric parameter");

        break;
    default:
        SDA_LOG_ERR("Incorrect type of parameter %" PRIu32, (uint32_t)(parameter_data->parameter_type));
        return SDA_STATUS_INTERNAL_MESSAGE_INVALID_OPERATION_ID;
    }

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    return SDA_STATUS_INTERNAL_SUCCESS;
}

static sda_status_internal_e sda_func_call_message_parse_tiny(CborValue  *user_operation_data, CborValue *user_operation_array, sda_message_data_s *bundle_data)
{

    uint8_t *string_buffer;
    size_t string_buffer_size = 0;
    CborError cbor_error = CborNoError;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // Get <function-name>
    cbor_error = cbor_value_advance(user_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(user_operation_array) != CborTextStringType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed getting <function-name>");

    cbor_error = cbor_value_get_text_string_chunk(user_operation_array, (const char **)&string_buffer, &string_buffer_size, NULL);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed getting <function-name>");
    SDA_ERR_RECOVERABLE_RETURN_IF((string_buffer == NULL), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Got NULL for <function-name>");

    //Update message data parameter with function name
    bundle_data->parsed_user_operation.function_name = (char*)string_buffer;
    bundle_data->parsed_user_operation.function_name_size = string_buffer_size;

    // Get <function-paramas> (is array of its own)
    cbor_error = cbor_value_advance(user_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(user_operation_array) != CborArrayType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get user parametes array");

    //Get pointer and size of encoded parameters buffer
    cbor_error = cbor_get_cbor_payload_buffer_in_container(user_operation_array, (uint8_t**)&bundle_data->parsed_user_operation.encoded_params_buffer, &bundle_data->parsed_user_operation.encoded_params_buffer_size);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get encoded user parameters buffer");

    //point to last element of the container 
    cbor_error = cbor_value_advance(user_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_at_end(user_operation_array) != true),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to reach last element of user operation array");

    //Get next element pointer outside of user operation array
    cbor_error = cbor_value_leave_container(user_operation_data, user_operation_array);

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return SDA_STATUS_INTERNAL_SUCCESS;
}

static sda_status_internal_e sda_lwm2m_message_parse_tiny(sda_message_data_s *bundle_data)
{
    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SDA_UNUSED_PARAM(bundle_data);
    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return SDA_STATUS_INTERNAL_INVALID_COMMAND_ERROR;
    
}


// encoded_access_token  - cbor value of bytes (CborByteStringType) of encoded access token
static  sda_status_internal_e  get_cwt_from_access_token(const uint8_t *encoded_access_token_ptr, size_t  encoded_access_token_size, uint8_t **cwt_buffer, size_t *cwt_buffer_size)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    CborParser cbor_parser;
    CborValue parsed_access_token;
    CborValue parsed_access_token_array;
    CborTag cbor_tag = 0;

    SDA_LOG_TRACE_FUNC_ENTER("encoded_access_token_size = %" PRIu32 "", (uint32_t)encoded_access_token_size);

    /* Structure of parsed access_token :
    *0                    (tag = 61)                                           //CborTagType
    *1                    (tag = 18)[                                          //CborTagType
    *2                                  3 bytes                                //CborByteStringType
    *3                                  {}                                     //CborMapType
    *4                                  CWT(encoded)                           //CborByteStringType
    *5                                  signature:encoded CWT signed by server //CborByteStringType
                                     ]                                                                     
    */

    // Initialize cbor parser
    cbor_error = cbor_parser_init((const uint8_t *)encoded_access_token_ptr, encoded_access_token_size, 0, &cbor_parser, &parsed_access_token);
    //Check that current cbor type is tag
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&parsed_access_token) != CborTagType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to initialize access token parser");

    cbor_error = cbor_value_get_tag(&parsed_access_token, &cbor_tag);
    // Check tag value - should be 61 - cwt tag
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_tag != SDA_CBOR_TAG_CWT), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed/wrong main tag");

    //get the value next to first tag
    cbor_error = cbor_value_advance_fixed(&parsed_access_token);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&parsed_access_token) != CborTagType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get main tag");

    cbor_error = cbor_value_get_tag(&parsed_access_token, &cbor_tag);
    //  Check tag value - should be 18 - cose tag
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_tag != CborCOSE_Sign1Tag), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed/wrong cose tag");

    //get the value next to second tag -> cbor now points to operation_bundle without tag
    cbor_error = cbor_value_skip_tag(&parsed_access_token);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&parsed_access_token) != CborArrayType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to skip cose tag");

    //Check index *2
    cbor_error = cbor_value_enter_container(&parsed_access_token, &parsed_access_token_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&parsed_access_token_array) != CborByteStringType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get cose protected flag");

    //Check index *3
    cbor_error = cbor_value_advance(&parsed_access_token_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&parsed_access_token_array) != CborMapType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get protected map");

    //Check index *4
    cbor_error = cbor_value_advance(&parsed_access_token_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&parsed_access_token_array) != CborByteStringType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get CWT cbor value");

    //Get cwt buffer pointer and size
    cbor_error = cbor_value_get_byte_string_chunk(&parsed_access_token_array, (const uint8_t **)cwt_buffer, cwt_buffer_size, NULL);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get cwt buffer");

    SDA_LOG_TRACE_FUNC_EXIT("cwt_buffer_size %" PRIu32 "", (uint32_t)*cwt_buffer_size);

    return sda_status_internal;
}

static sda_status_internal_e get_data_from_unsigned_request_bundle(uint8_t *unsigned_request_bundle_ptr, size_t unsigned_request_bundle_size, sda_unsigned_request_data_s *request_data)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    CborParser cbor_parser;
    size_t array_length = 0;
    CborValue unsigned_operation_array;
    CborValue unsigned_request_bundle;

    SDA_LOG_TRACE_FUNC_ENTER("unsigned_request_bundle_size = %" PRIu32 "", (uint32_t)unsigned_request_bundle_size);

    /*  Structure of unsigned operation bundle array:
    * 0 - Nonce
    * 1 - encoded user operation (output as pointer and size)
    * 2 - Encoded Access Token(Array) (output as pointer and size)  ---> */

    cbor_error = cbor_parser_init((const uint8_t *)unsigned_request_bundle_ptr, unsigned_request_bundle_size, 0, &cbor_parser, &unsigned_request_bundle);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&unsigned_request_bundle) != CborArrayType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to initialize unsigned request array");

    //Check that current cbor type is array
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&unsigned_request_bundle) != CborArrayType), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to decode operation bundle");

    //Get the array size
    cbor_error = cbor_value_get_array_length(&unsigned_request_bundle, &array_length);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && array_length != SDA_UNTAGGED_REQUEST_ARRAY_SIZE),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get unsigned request array size");

    //Start unsigned operation array iteration
    cbor_error = cbor_value_enter_container(&unsigned_request_bundle, &unsigned_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError  && cbor_value_get_type(&unsigned_operation_array) != CborIntegerType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get nonce cbor value");

    //Get nonce value
    cbor_error = cbor_value_get_uint64(&unsigned_operation_array, &(request_data->nonce));
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && request_data->nonce != 0), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get nonce value");

    //Check and get user operation bundle
    cbor_error = cbor_value_advance(&unsigned_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&unsigned_operation_array) != CborArrayType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get user operation array");

    //Get pointer and size of encoded user operation bundle
    cbor_error = cbor_get_cbor_payload_buffer_in_container(&unsigned_operation_array, (uint8_t**)&request_data->user_operation_ptr, &request_data->user_operation_size);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError ), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed user operation buffer");

    //Check and get access token
    cbor_error = cbor_value_advance(&unsigned_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&unsigned_operation_array) != CborByteStringType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get access token array");

    //Get pointer and size of encoded access token
    cbor_error = cbor_value_get_byte_string_chunk(&unsigned_operation_array, (const uint8_t **)&(request_data->encoded_access_token_ptr), &request_data->encoded_access_token_size, NULL);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get access token buffer");

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    return sda_status_internal;
}

static sda_status_internal_e get_unsigned_request_buffer(CborValue *main_signed_request_bundle , uint8_t **unsigned_request_bundle_ptr, size_t *unsigned_request_bundle_size) {

    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    CborValue request_array;

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    /* Structure of untagged request_bundle:
    * 0- 3 bytes                                               //CborByteStringType
    * 1- {}                                                    //CborMapType
    * 2- encoded unsigned_operation_bundle_operation_bundle    //CborByteStringType
    * 3- signature: encoded operation_bundle signed by proxy   // Not retrieved yet*/

    //Start to iterate main request bundle array
    //Check field - 0
    cbor_error = cbor_value_enter_container(main_signed_request_bundle, &request_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&request_array) != CborByteStringType),
        sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to start request bundle array iteration");

    //Check field - 1 - should be a map
    cbor_error = cbor_value_advance(&request_array);
    SDA_ERR_RECOVERABLE_RETURN_IF( ( (cbor_error != CborNoError) && (cbor_value_get_type(&request_array) != CborMapType) ), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to decode operation bundle");

    //Check field - 2
    cbor_error = cbor_value_advance(&request_array);
    SDA_ERR_RECOVERABLE_RETURN_IF( ( (cbor_error != CborNoError) && (cbor_value_get_type(&request_array) != CborByteStringType) ), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to decode operation bundle");

    //Get field data -2  : pointer and size of unsigned encoded operational bundle
    cbor_error = cbor_value_get_byte_string_chunk(&request_array, (const uint8_t **)unsigned_request_bundle_ptr, unsigned_request_bundle_size, NULL);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to decode operation bundle");

    SDA_LOG_TRACE_FUNC_EXIT("unsigned_request_bundle_size %" PRIu32 "", (uint32_t)*unsigned_request_bundle_size);

    return sda_status_internal;
}

/* This API checks structure of first level and tags of the main request bundle,
parses it and retrieves unsigned request bundle pointer and its size*/
static sda_status_internal_e sda_get_unsigned_request_bundle(const uint8_t *main_bundle, size_t main_bundle_size, uint8_t **unsigned_bundle, size_t *unsigned_bundle_size) {

    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    CborParser cbor_parser;
    CborValue main_request_bundle;
    CborTag  signed_request_bundle_tag;
    size_t array_length = 0;

    SDA_LOG_TRACE_FUNC_ENTER("main_bundle_size = %" PRIu32 "", (uint32_t)main_bundle_size);

    //Initialize cbor parser
    cbor_error = cbor_parser_init((const uint8_t *)main_bundle, main_bundle_size, 0, &cbor_parser, &main_request_bundle);
    //Check that current cbor type is tag
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&main_request_bundle) != CborTagType),
        sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to initialize parser of request bundle");

    //Get value of the tag
    // Must check tags 18 for COSE
    cbor_error = cbor_value_get_tag(&main_request_bundle, &signed_request_bundle_tag);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && signed_request_bundle_tag != CborCOSE_Sign1Tag), 
        sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to get leading tag");

    //get the value next to tag -> cbor now points to operation_bundle without tag
    cbor_error = cbor_value_skip_tag(&main_request_bundle);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&main_request_bundle) != CborArrayType),
        sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to skip leading tag");

    //Get size of main array
    cbor_error = cbor_value_get_array_length(&main_request_bundle, &array_length);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && array_length != SDA_COSE_SIGN0_ARRAY_LENGTH),
        sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Wrong size of main request bundle array");

    // Retrieve unsigned-request-bundle
    // Get unsigned-request-bundle as raw bytes
    sda_status_internal = get_unsigned_request_buffer(&main_request_bundle, unsigned_bundle, unsigned_bundle_size);
    SDA_ERR_RECOVERABLE_RETURN_IF(cbor_error != CborNoError, sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get unsigned request bundle");

    SDA_LOG_TRACE_FUNC_EXIT("unsigned_bundle_size %" PRIu32 "", (uint32_t)*unsigned_bundle_size);
    return sda_status_internal;
}

sda_status_internal_e sda_get_function_parameter_tiny(sda_operation_ctx_h handle, sda_parameter_data_s *parameter_data, uint32_t index)
{
    CborError cbor_error = CborNoError;
    CborParser parser;
    CborValue  operation_parameters;
    CborValue  operation_parameters_array;
    sda_ctx_internal_s *sda_internal_ctx = NULL;
    uint32_t array_index = 0;
    size_t array_length = 0;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    uint8_t *user_operation_params;
    size_t user_operation_params_size = 0;

    SDA_LOG_TRACE_FUNC_ENTER("index %" PRIu32 "", index);

    //Get internal context
    sda_internal_ctx = (sda_ctx_internal_s*)handle;
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_internal_ctx == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid SDA operation handle");
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_internal_ctx->message_state != SDA_OP_PROCESSING_MESSAGE), SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT, "Cann't proccess message (%d)", sda_internal_ctx->message_state);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_internal_ctx->message_data.parsed_user_operation.type_id != SDA_OPERATION_FUNC_CALL), SDA_STATUS_INTERNAL_FUNCTION_CALL_TYPE_ID_ERROR, "Wrong value of type-id");

    user_operation_params = (uint8_t *)sda_internal_ctx->message_data.parsed_user_operation.encoded_params_buffer;
    user_operation_params_size = sda_internal_ctx->message_data.parsed_user_operation.encoded_params_buffer_size;

    //Initialize cbor parser with encoded buffer
    cbor_error = cbor_parser_init(user_operation_params, user_operation_params_size, 0, &parser, &operation_parameters);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "cbor_parser_init failed (%" PRIu32 ")", (uint32_t)cbor_error);

    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_is_array(&operation_parameters) != true), sda_status_internal = SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "Wrong type of operation parameters data");

    cbor_error = cbor_value_get_array_length(&operation_parameters, &array_length);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "Failed to get size of parameters array");
    SDA_ERR_RECOVERABLE_RETURN_IF((array_length < index), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAM_INDEX, "Wrong parameter index");

    //Start iterations on the current array
    cbor_error = cbor_value_enter_container(&operation_parameters, &operation_parameters_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "cbor_value_enter_container failed");

    for (array_index = 0; array_index <= index; array_index++) {

        if (array_index == index) {
            sda_status_internal = get_parameter_data(&operation_parameters_array, parameter_data);
            SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal = sda_status_internal, "failed to get parameter");
            break;
        }
        //Get to the temp value next map member
        cbor_error = cbor_value_advance(&operation_parameters_array);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError),  SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR, "Failed to get next parameter");
    }

    SDA_LOG_DATA_FUNC_EXIT_NO_ARGS();
    return sda_status_internal;

}
bool sda_get_data_buffer_from_cbor_tiny(CborValue *cbor_value, uint8_t **out_data_buffer, size_t *out_size)
{
    CborError cbor_error = CborNoError;
    CborType cb_type;
    CborValue next;

    SDA_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value == NULL), false, "key_data_cb is null");
    SDA_ERR_RECOVERABLE_RETURN_IF((out_size == NULL), false, "Size buffer is null ");
    SDA_ERR_RECOVERABLE_RETURN_IF((out_data_buffer == NULL), false, "Data buffer is null");

    cb_type = cbor_value_get_type(cbor_value);

    switch (cb_type) {
        //  CborTagType Not checked
        /*case CborTagType:
        cbor_error = cbor_value_get_tag(cbor_value, &cb_tag);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), false, "cbor_value_get_tag failed");
        *out_data_buffer = (uint8_t*)&cb_tag;
        *out_size = sizeof(CborTag);
        break;*/
    case CborTextStringType:
        cbor_error = cbor_value_get_text_string_chunk(cbor_value, (const char**)out_data_buffer, out_size, &next);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), false, "cbor_value_get_text_string_chunk failed");
        break;
    case CborByteStringType:
        cbor_error = cbor_value_get_byte_string_chunk(cbor_value, (const uint8_t**)out_data_buffer, out_size, &next);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), false, "cbor_value_get_text_string_chunk failed");
        break;
    case CborMapType:
    default:
        SDA_LOG_ERR("Invalid cbor data type (%u)!", cb_type);
        return false;
    }
    SDA_LOG_TRACE_FUNC_EXIT("out_size=%" PRIu32 "", (uint32_t)*out_size);
    return true;
}

sda_status_internal_e sda_operation_bundle_parse(const uint8_t *encoded_operation_bundle, size_t encoded_operation_bundle_size, sda_message_data_s *bundle_data_out)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    uint8_t *unsigned_requst_bundle_ptr = NULL;
    size_t unsigned_requst_bundle_size = 0;
    sda_unsigned_request_data_s unsigned_request_data = { 0 };
    uint8_t *cwt_buffer;
    size_t cwt_buffer_size = 0;

    SDA_LOG_INFO_FUNC_ENTER("encoded_operation_bundle_size = %" PRIu32 "", (uint32_t)encoded_operation_bundle_size);

    //Check params
    SDA_ERR_RECOVERABLE_RETURN_IF((encoded_operation_bundle == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid encoded operation bundle");
    SDA_ERR_RECOVERABLE_RETURN_IF((bundle_data_out == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid bundle_data_out");
    SDA_ERR_RECOVERABLE_RETURN_IF((encoded_operation_bundle_size == 0), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Encoded operation bundle size 0");

    bundle_data_out->main_signed_operation_bundle.data_buffer_ptr = encoded_operation_bundle;
    bundle_data_out->main_signed_operation_bundle.data_buffer_size = encoded_operation_bundle_size;



    //Parse first level of signed request bundle  and get untagged request bundle data
    sda_status_internal = sda_get_unsigned_request_bundle(encoded_operation_bundle, encoded_operation_bundle_size, &unsigned_requst_bundle_ptr, &unsigned_requst_bundle_size);
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, Exit, "Failed to get unsigned request bundle");

    //Get nonce, user operation and encoded access token from unsigned request  bundle
    sda_status_internal = get_data_from_unsigned_request_bundle(unsigned_requst_bundle_ptr, unsigned_requst_bundle_size, &unsigned_request_data);
    SDA_ERR_RECOVERABLE_GOTO_IF(cbor_error != CborNoError, sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, Exit, "Failed to get data from unsigned request bundle");

    //Save the nonce
    bundle_data_out->nonce = unsigned_request_data.nonce;

    //Save the user operation data
    bundle_data_out->user_operation_encoded_buffer.data_buffer_ptr = unsigned_request_data.user_operation_ptr;
    bundle_data_out->user_operation_encoded_buffer.data_buffer_size = unsigned_request_data.user_operation_size;

    // Get CWT form the Access Token
    sda_status_internal = get_cwt_from_access_token(unsigned_request_data.encoded_access_token_ptr, 
        unsigned_request_data.encoded_access_token_size, 
        &cwt_buffer,
        &cwt_buffer_size);
    SDA_ERR_RECOVERABLE_GOTO_IF(cbor_error != CborNoError, sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, Exit, "Failed to get cwt buffer");

    bundle_data_out->access_token.data_buffer_ptr = unsigned_request_data.encoded_access_token_ptr;
    bundle_data_out->access_token.data_buffer_size = unsigned_request_data.encoded_access_token_size;
    // Retrieve all CWT claims
    sda_status_internal = sda_cwt_parse_tiny(cwt_buffer, (size_t)cwt_buffer_size, &(bundle_data_out->claims));
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), (sda_status_internal = sda_status_internal), Exit, "Failed to parse cwt");

Exit:
    SDA_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return sda_status_internal;
}

sda_status_internal_e sda_user_operation_parse(sda_message_data_s *bundle_data)
{
    int type_id = 0;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    CborError cbor_error = CborNoError;
    size_t array_length = 0;
    CborValue  user_operation;
    CborValue  user_operation_array;
    CborParser parser;

    /* Structure of user operation bundle
    *0          - operation type id    // CborIntegerType
    *1          - function name        // CborTextStringType
    *2          - array of parameters // CborArrayType
    */

    SDA_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    //Initialize cbor parser with encoded buffer
    cbor_error = cbor_parser_init(bundle_data->user_operation_encoded_buffer.data_buffer_ptr, bundle_data->user_operation_encoded_buffer.data_buffer_size, 0, &parser, &user_operation);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&user_operation) != CborArrayType),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Failed to initialize cbor array of user operation");

    //Get and check size of user operation array
    cbor_error = cbor_value_get_array_length(&user_operation, &array_length);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && array_length != SDA_USER_OPERATION_ARRAY_SIZE),
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,
        "Wrong size of user operation array");

    //Start to iterate user operation array
    cbor_error = cbor_value_enter_container(&user_operation, &user_operation_array);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError && cbor_value_get_type(&user_operation_array) != CborIntegerType), SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to decode user operation bundle");

    cbor_error = cbor_value_get_int(&user_operation_array, &type_id);

    switch (type_id) {

    case SDA_OPERATION_FUNC_CALL:
        sda_status_internal = sda_func_call_message_parse_tiny(&user_operation, &user_operation_array, bundle_data);
        SDA_LOG_DEMO_INFO("Operation Function Callback");
        SDA_LOG_INFO("Operation Function Callback");
        break;

    case SDA_OPERATION_LWM2M:
        sda_status_internal = sda_lwm2m_message_parse_tiny(bundle_data);
        SDA_LOG_DEMO_INFO("Operation LWM2M");
        SDA_LOG_INFO("Operation LWM2M");
        break;

    default:
        sda_status_internal = SDA_STATUS_INTERNAL_INVALID_COMMAND_ERROR;
        SDA_LOG_DEMO_ERROR("Invalid operation type");
        break;
    }

    bundle_data->parsed_user_operation.type_id = (uint8_t)type_id; //assign type_id value
    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return sda_status_internal;
}

sda_status_internal_e sda_cwt_parse_tiny(const uint8_t *encoded_blob, size_t encoded_blob_size, cwt_claims_s *cwt_out)
{
    bool status = false;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    int group_index;
    int param_type;
    char* cbor_str = NULL;
    size_t time_out_size = 0;
    uint64_t time_value;
    CborError cbor_error = CborNoError;
    CborParser parser;
    CborValue main_map;
    size_t main_map_size = 0;
    CborValue internal_cwt_single_map = { 0 };
    CborValue cose_key_value;
    uint8_t *cbor_key_pointer = NULL;
    size_t cbor_key_buffer_size = 0;

    SDA_LOG_INFO_FUNC_ENTER("encoded_blob_size = %" PRIu32 "", (uint32_t)encoded_blob_size);

    //Check parameters
    SDA_ERR_RECOVERABLE_RETURN_IF((cwt_out == NULL), SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid bundle_response_size_out");
    SDA_ERR_RECOVERABLE_RETURN_IF((encoded_blob == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid encoded_blob");
    SDA_ERR_RECOVERABLE_RETURN_IF((encoded_blob_size == 0), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, "Invalid encoded_blob_size");

    //Initialize cbor parser with encoded buffer
    cbor_error = cbor_parser_init(encoded_blob, encoded_blob_size, 0, &parser, &main_map);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "cbor_parser_init failed (%" PRIu32 ")", (uint32_t)cbor_error);

    //Check that encoded buffer is a map
    status = cbor_value_is_map(&main_map);
    SDA_ERR_RECOVERABLE_RETURN_IF((status != true), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Wrong CBOR structure type");

    //Get map's length
    cbor_error = cbor_value_get_map_length(&main_map, &main_map_size);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Failed to get size of map");

    //Start iterations on the current map
    cbor_error = cbor_value_enter_container(&main_map, &internal_cwt_single_map);
    SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "cbor_value_enter_container failed");

    //Go over parameter groups
    for (group_index = 0; group_index < (int)main_map_size; group_index++) {

        //Get next map's pair (key : value)
        if (group_index != 0) {
            cbor_error = cbor_value_advance(&internal_cwt_single_map);
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "cbor_value_enter_container failed");

        }

        //Get a key of the current map -  parameter type
        cbor_error = cbor_value_get_int(&internal_cwt_single_map, &param_type);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "cbor_value_get_int failed");

        //Get a value of the current map
        cbor_error = cbor_value_advance(&internal_cwt_single_map);
        SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Parsing of param type %d failed", param_type);

        switch (param_type) {
        case SDA_ISS:
            //Get value's data
            status = sda_get_data_buffer_from_cbor_tiny(&internal_cwt_single_map, (uint8_t**)&cwt_out->issuer_data, &cwt_out->issuer_data_size);
            SDA_ERR_RECOVERABLE_RETURN_IF((!status), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "Issuer data parsing failed");
            break;
        case SDA_SUB:
            //Get value's data
            status = sda_get_data_buffer_from_cbor_tiny(&internal_cwt_single_map, (uint8_t**)&cbor_str, &time_out_size);
            SDA_ERR_RECOVERABLE_RETURN_IF((!status), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_SUB data parsing failed");
            // Do nothing
            SDA_LOG_INFO("\nSDA_SUB %.*s\n", (int)time_out_size, cbor_str);
            break;
        case SDA_AUD:
            //Update cwt audience array with current value
            cbor_error = cbor_get_cbor_payload_buffer_in_container(&internal_cwt_single_map, (uint8_t**)&cwt_out->audience_array_ptr, &cwt_out->audience_array_size);
             SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "SDA_AUD parsing failed");
            break;
        case SDA_EXP:
            //Get value's data
            //TODO : remove this check when assertion issue will be handled in tinycbor
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_is_integer(&internal_cwt_single_map) != true), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_EXP parsing failed");
            cbor_error = cbor_value_get_uint64(&internal_cwt_single_map, &time_value);
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_EXP parsing failed");
            cwt_out->exp = time_value;
            break;
        case SDA_NBF:
            //Get value's data
            //TODO : remove this check when assertion issue will be handled in tinycbor
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_is_integer(&internal_cwt_single_map) != true), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_NBF parsing failed");
            cbor_error = cbor_value_get_uint64(&internal_cwt_single_map, &time_value);
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_NBF parsing failed");
            cwt_out->nbf = time_value;
            break;
        case SDA_IAT:
            //Get value's data
            //TODO : remove this check when assertion issue will be handled in tinycbor
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_value_is_integer(&internal_cwt_single_map) != true), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_IAT parsing failed");
            cbor_error = cbor_value_get_uint64(&internal_cwt_single_map, &time_value);
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_IAT parsing failed");
            cwt_out->iat = time_value;
            break;
        case SDA_CTI:
            //Get value's data
            status = sda_get_data_buffer_from_cbor_tiny(&internal_cwt_single_map, (uint8_t**)&cwt_out->cti_data, &cwt_out->cti_data_size);
            SDA_ERR_RECOVERABLE_RETURN_IF((!status), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_CTI data parsing failed");
            //FIXME: check how to use this macro with string of certain size
            SDA_LOG_BYTE_BUFF_INFO("\nSDA_CTI: ", cwt_out->cti_data, (uint16_t)cwt_out->cti_data_size);
            break;
        case SDA_SCOPE:
            //Get value's data
            status = sda_get_data_buffer_from_cbor_tiny(&internal_cwt_single_map, (uint8_t**)&cwt_out->scope_data, &cwt_out->scope_data_size);
            SDA_ERR_RECOVERABLE_RETURN_IF((!status), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_SCOPE data parsing failed");
            break;
        case SDA_CNF:
            //Get value of COSE key
            cbor_error = cbor_get_map_element_by_int_key(&internal_cwt_single_map, SDA_COSE_KEY_MAP_KEY, &cose_key_value);
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP, "SDA_CNF getting cose key map failed");

            //Calculate size of COSE key buffer
            cbor_error = cbor_get_cbor_payload_buffer_in_container(&cose_key_value, &cbor_key_pointer, &cbor_key_buffer_size);
            SDA_ERR_RECOVERABLE_RETURN_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "Geting cose object buffer failed");

            //Retrieve ec key from COSE buffer
            status = GetECKeyFromCoseBuffer(cbor_key_pointer, cbor_key_buffer_size, cwt_out->pk, sizeof(cwt_out->pk), &(cwt_out->pk_size), NULL);
            SDA_ERR_RECOVERABLE_RETURN_IF((!status), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, "GetECKeyFromCoseBuffer failed");
            break;
        default:
            sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_UNSUPPORTED_GROUP;
            SDA_LOG_ERR("Wrong group type");
            goto exit;

        }
    }
exit:
    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    //SDA_END_TIMER("Total sda_bundle_handler device", 0, sda_bundle_timer);
    return sda_status_internal;
}
