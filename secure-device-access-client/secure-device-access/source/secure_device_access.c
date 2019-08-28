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

#if defined(MBED_CLOUD_CLIENT_ENABLE_SDA) && (MBED_CLOUD_CLIENT_ENABLE_SDA == 1)

#include "secure_device_access.h"
#include "sda_bundle_parser.h"
#include "sda_status.h"
#include "sda_error_handling.h"
#include "sda_nonce_mgr.h"
#include "sda_malloc.h"
#include "sda_status_internal.h"
#include "sda_verification.h"
#include "sda_error_translation.h"
#include "key_config_manager.h"


bool g_sda_initialized = false;

// SDA_RESPONSE_HEADER_SIZE explanaion:
// Indefenite size map + terminator(2 byte),
// small integer keys(less than 24), 3 bytes
// type integer(2 byte),
// 32 bit integer status(5 bytes)
// 64 bit nonce(9 bytes in get nonce) or byte string header(less than 2 ^ 16 size) (3 bytes)
// Example of max response size
// { 1: 255, 2 : 2147483647, 3 : 18446744073709551615 or 4 : h'user buffer' }
// BF                     # map(*)                                                          // indefenite size map
// 01                  # unsigned(1)                                                     // SDA_RESPONSE_MAP_KEY_TYPE
// 18 FF               # unsigned(255)                                                   // sda_message_id_e
// 02                  # unsigned(2)                                                     // SDA_RESPONSE_MAP_KEY_RESULT
// 1A 7FFFFFFF         # unsigned(2147483647)                                            // sda_status_e
// 03                  # unsigned(3) or 04          # unsigned(4)    // SDA_RESPONSE_MAP_KEY_NONCE or SDA_RESPONSE_MAP_KEY_USER_BUFFER
// 1B FFFFFFFFFFFFFFFF # unsigned(18446744073709551615) or 42          # bytes(2) + user buffer
// FF                  # primitive(*)                                                    // map terminator

//The function parses operation bundle and verifies its validity
static sda_status_internal_e sda_operation_bundle_process(sda_message_data_s *operation_bundle_ctx, const uint8_t *encoded_operation_bundle, size_t encoded_operation_bundle_size)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;

    SDA_LOG_TRACE_FUNC_ENTER("encoded_operation_bundle_size=%" PRIu32, (uint32_t)encoded_operation_bundle_size);

    sda_status_internal = sda_operation_bundle_parse(encoded_operation_bundle, encoded_operation_bundle_size, operation_bundle_ctx);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal, "Operation bundle parsing failed");
    SDA_LOG_INFO("Operation bundle parsed");

    sda_status_internal = sda_operation_bundle_verify(operation_bundle_ctx);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), (sda_status_internal = sda_status_internal), "Failed to verify operation bundle");
    SDA_LOG_INFO("Operation bundle verified successfully");

    sda_status_internal = sda_user_operation_parse(operation_bundle_ctx);
    SDA_ERR_RECOVERABLE_RETURN_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), (sda_status_internal = sda_status_internal),  "Failed to verify user operation");

    SDA_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return sda_status_internal;
}

//TODO : add pal_init function + remove pal_init from unitests
sda_status_e sda_init(void)
{
    sda_status_internal_e sda_status_internal;
    sda_status_e sda_status = SDA_STATUS_SUCCESS;

    SDA_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (!g_sda_initialized) {

        sda_status_internal = sda_nonce_init();

        // kcm_init also initializes PAL
        if (kcm_init() != KCM_STATUS_SUCCESS) {
            sda_status_internal = SDA_STATUS_INTERNAL_KCM_ERROR;
        }

        sda_status = sda_return_status_translate(sda_status_internal);
        SDA_ERR_RECOVERABLE_RETURN_IF((sda_status != SDA_STATUS_SUCCESS), sda_status, "Failed initializing sda");

        // Mark as "initialized"
        g_sda_initialized = true;
    }

    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}

//TODO : add pal_destroy function + remove pal_destroy from unitests
sda_status_e sda_finalize(void)
{
    sda_status_internal_e sda_status_internal;
    sda_status_e sda_status = SDA_STATUS_SUCCESS;

    SDA_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (g_sda_initialized) {
        sda_status_internal = sda_nonce_fini();

        // kcm_init also initializes PAL
        if (kcm_finalize() != KCM_STATUS_SUCCESS) {
            sda_status_internal = SDA_STATUS_INTERNAL_KCM_ERROR;
        }

        sda_status = sda_return_status_translate(sda_status_internal);
        SDA_ERR_RECOVERABLE_RETURN_IF((sda_status != SDA_STATUS_SUCCESS), sda_status, "Failed finalizing sda");

        // Mark as "not initialized"
        g_sda_initialized = false;
    }

    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}


sda_status_e sda_operation_process(const uint8_t *message,
                                   size_t message_size,
                                   user_callback callback,
                                   void *callback_context,
                                   uint8_t *response_buffer_out,
                                   size_t response_buffer_out_max_size,
                                   size_t *response_message_actual_size_out)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_status_e sda_status;
    sda_status_e callback_status = SDA_STATUS_SUCCESS;
    sda_ctx_internal_s sda_internal_ctx;
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map_encoder;
    CborParser parser;
    CborValue message_array;
    CborValue type_id_cb_value;
    CborValue operation_bundle_value;
    int type_id_int = SDA_ERROR_MESSAGE_ID;
    uint8_t *operation_bundle_bytes = NULL;
    size_t operation_bundle_size = 0;
    const char scope_delimeter[] = " ";
    uint8_t map_key_type_value = SDA_ERROR_MESSAGE_ID;

    SDA_LOG_INFO("Got input message, processing it..");
    SDA_LOG_INFO_FUNC_ENTER("message_size=%" PRIu32, (uint32_t)message_size);

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    //check parameters
    SDA_ERR_RECOVERABLE_RETURN_IF((response_message_actual_size_out == NULL), sda_return_status_translate(SDA_STATUS_INTERNAL_INVALID_PARAMETER),
                                  "Invalid response_message_actual_size_out");
    SDA_ERR_RECOVERABLE_RETURN_IF((response_buffer_out == NULL), sda_return_status_translate(SDA_STATUS_INTERNAL_INVALID_PARAMETER), "Invalid response_buffer_out");
    SDA_ERR_RECOVERABLE_RETURN_IF((response_buffer_out_max_size < SDA_RESPONSE_HEADER_SIZE),
                                  sda_return_status_translate(SDA_STATUS_INTERNAL_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR), "response buffer too small");
    SDA_ERR_RECOVERABLE_RETURN_IF((message == NULL), sda_return_status_translate(SDA_STATUS_INTERNAL_INVALID_PARAMETER), "Invalid input message");
    SDA_ERR_RECOVERABLE_RETURN_IF((message_size == 0), sda_return_status_translate(SDA_STATUS_INTERNAL_INVALID_PARAMETER), "Invalid message size");

    // Set actual response message to 0
    *response_message_actual_size_out = 0;

    // Set initial state
    sda_internal_ctx.message_state = SDA_OP_START_PROCESSING_MESSAGE;

    // save response_max_size
    sda_internal_ctx.response_max_size = response_buffer_out_max_size;

    // open a CBOR encoder (map) allocated on the stack
    sda_internal_ctx.map_encoder = NULL;
    cbor_encoder_init(&encoder, response_buffer_out, response_buffer_out_max_size, 0);
    cbor_error = cbor_encoder_create_map(&encoder, &map_encoder, CborIndefiniteLength);
    SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR), exit, "Cbor create map error");
    sda_internal_ctx.map_encoder = &map_encoder;

    //Initialize cbor parser with encoded buffer
    cbor_error = cbor_parser_init(message, message_size, 0, &parser, &message_array);
    SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), exit, "cbor_parser_init failed (%" PRIu32 ")", (uint32_t)cbor_error);
    
    //Get first member of array
    cbor_error = cbor_get_array_element(&message_array, 0, &type_id_cb_value);
    SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError || (!cbor_value_is_integer(&type_id_cb_value))), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), exit, "cbor_get_array_element  failed (%" PRIu32 ")", (uint32_t)cbor_error);

    //Get id type from the first array member
    cbor_error = cbor_value_get_int(&type_id_cb_value, &type_id_int);
    SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError || type_id_int <= 0), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), exit, "cbor_value_get_int  failed (%" PRIu32 ")", (uint32_t)cbor_error);

    switch ((uint32_t)type_id_int) {

        case SDA_NONCE_REQUEST_MESSAGE_ID:

            SDA_LOG_INFO("Input message is get nonce request");

            map_key_type_value = SDA_NONCE_RESPONSE_MESSAGE_ID;

            SDA_ERR_RECOVERABLE_GOTO_IF(sda_internal_ctx.message_state == SDA_OP_PROCESSING_MESSAGE,
                                        sda_status_internal = SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT, exit, "Previous operation was not finished");

            sda_status_internal = sda_nonce_get(&(sda_internal_ctx.nonce_response));
            SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), (sda_status_internal = sda_status_internal), exit, "Failed generating nonce (%u)", sda_status_internal);
            cbor_error = cbor_map_encode_uint_uint(&map_encoder, SDA_RESPONSE_MAP_KEY_NONCE, sda_internal_ctx.nonce_response);
            SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR), exit, "Cbor append error");

            break;
        case SDA_OPERATION_REQUEST_MESSAGE_ID:


            SDA_LOG_INFO("Input message is an operation command request");

            map_key_type_value = SDA_OPERATION_RESPONSE_MESSAGE_ID;

            SDA_ERR_RECOVERABLE_GOTO_IF(sda_internal_ctx.message_state == SDA_OP_PROCESSING_MESSAGE,
                                        sda_status_internal = SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT, exit, "Previous operation was not finished");

            /*
            operation-bundle should be in the following format:
            [
                <type-id = 3>,
                <operation-bundle : encoded COSE as byte string>,
            ]
            */
            //Get first member of array
            cbor_error = cbor_get_array_element(&message_array, 1, &operation_bundle_value);
            SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError), sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR, exit, "Failed getting operation from CBOR");
            SDA_ERR_RECOVERABLE_GOTO_IF((!cbor_value_is_byte_string(&operation_bundle_value)), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), exit, "Incorrect operation type (should be bytes)");

            cbor_error = cbor_value_get_byte_string_chunk(&operation_bundle_value, (const uint8_t**)&operation_bundle_bytes, &operation_bundle_size, NULL);
            SDA_ERR_RECOVERABLE_GOTO_IF((cbor_error != CborNoError || operation_bundle_size == 0), (sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_ERROR), exit, "Failed getting operation bundle bytes");

            //perform parsing and verification of the internal data.
            //All internal data will be stored in message_data struct
            sda_status_internal = sda_operation_bundle_process(&(sda_internal_ctx.message_data), (const uint8_t*)operation_bundle_bytes, operation_bundle_size);
            SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal = sda_status_internal, exit, "Operation bundle request failed (%u)", sda_status_internal);

            //init token context on scope list upon successful process
            sda_status_internal = sda_helper_init_token_context(&(sda_internal_ctx.message_data.data_token_ctx), sda_internal_ctx.message_data.claims.scope_data,
                                  sda_internal_ctx.message_data.claims.scope_data_size, scope_delimeter);
            SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), (sda_status_internal = sda_status_internal), exit, "Operation bundle request failed (%u)", sda_status_internal);

            //Check that user function is not NULL
            SDA_ERR_RECOVERABLE_GOTO_IF((callback == NULL), (sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER), exit, "User callback is NULL");
            sda_internal_ctx.message_state = SDA_OP_PROCESSING_MESSAGE;

            //Call user function
            callback_status = callback((sda_operation_ctx_h*)&sda_internal_ctx, callback_context);
            SDA_ERR_RECOVERABLE_GOTO_IF((callback_status != SDA_STATUS_SUCCESS), (callback_status = callback_status), exit, "Operation callback failed (%u)", callback_status);

            break;

        default:
            SDA_LOG_ERR("Incorrect or unsupported <type-id> %" PRIu32, (uint32_t)(type_id_int));
            sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_INVALID_OPERATION_ID;
    }


exit:
    if (sda_status_internal == SDA_STATUS_INTERNAL_SUCCESS) {
        sda_internal_ctx.message_state = SDA_OP_PROCESSING_MESSAGE;
    }
    else {
        sda_internal_ctx.message_state = SDA_OP_INVALID_MESSAGE;
    }

    SDA_LOG_INFO("Processing input message completed");

    sda_status = sda_return_status_translate(sda_status_internal);
    if (sda_status == SDA_STATUS_SUCCESS) {
        sda_status = callback_status;
    }
    // Complete the encoding only if map_encoder was actually created
    if (sda_internal_ctx.map_encoder) {
        // Append type map_key_type_value to encoder
        cbor_error = cbor_map_encode_uint_uint(&map_encoder, SDA_RESPONSE_MAP_KEY_TYPE, map_key_type_value);
        if (cbor_error != CborNoError) {
            if (sda_status == SDA_STATUS_SUCCESS) {
                sda_status = sda_return_status_translate(SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR);
            }
            SDA_LOG_ERR("Cbor append error");
        }
        // Append status to encoder
        cbor_error = cbor_map_encode_uint_uint(&map_encoder, SDA_RESPONSE_MAP_KEY_RESULT, sda_status);
        if (cbor_error != CborNoError) {
            if (sda_status == SDA_STATUS_SUCCESS) {
                sda_status = sda_return_status_translate(SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR);
            }
            SDA_LOG_ERR("Cbor append error");
        }
        // Close the CBOR container
        cbor_error = cbor_encoder_close_container(&encoder, &map_encoder);
        if (cbor_error != CborNoError) {
            if (sda_status == SDA_STATUS_SUCCESS) {
                sda_status = sda_return_status_translate(SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR);
            }
            SDA_LOG_ERR("Cbor close container error");
        } 
        else {
            // set response_message_actual_size_out to actual cbor buffer size
            *response_message_actual_size_out = cbor_encoder_get_buffer_size(&encoder, (const uint8_t*)response_buffer_out);
        }
    }

    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}

sda_status_e sda_command_type_get(sda_operation_ctx_h handle, sda_command_type_e *command_type)
{
    sda_ctx_internal_s *sda_internal_ctx;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_status_e sda_status;

    SDA_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    //check parameters
    SDA_ERR_RECOVERABLE_GOTO_IF(handle == NULL, sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Got NULL for handle");
    SDA_ERR_RECOVERABLE_GOTO_IF(command_type == NULL, sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid command type");

    sda_internal_ctx = (sda_ctx_internal_s*)handle;
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_internal_ctx->message_state != SDA_OP_PROCESSING_MESSAGE),
    sda_status_internal = SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT, exit, "Cann't proccess message (%d)", sda_internal_ctx->message_state);
    //assign the command type
    *command_type = (sda_command_type_e)sda_internal_ctx->message_data.parsed_user_operation.type_id;

exit:

    sda_status = sda_return_status_translate(sda_status_internal);
    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}


sda_status_e sda_scope_get_next(sda_operation_ctx_h handle, const uint8_t **scope_out, size_t *scope_size_out)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_ctx_internal_s *sda_internal_ctx;
    sda_status_e sda_status;

    SDA_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    //check parameters
    SDA_ERR_RECOVERABLE_GOTO_IF(handle == NULL, sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Got NULL for handle");
    SDA_ERR_RECOVERABLE_GOTO_IF((scope_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid scope parameter");
    SDA_ERR_RECOVERABLE_GOTO_IF((scope_size_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid scope size out parameter");

    sda_internal_ctx = (sda_ctx_internal_s*)handle;
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_internal_ctx->message_state != SDA_OP_PROCESSING_MESSAGE),
                                sda_status_internal = SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT, exit, "Cann't proccess message (%d)", sda_internal_ctx->message_state);

    //get next scope
    sda_status_internal = sda_helper_get_next_data_token(&(sda_internal_ctx->message_data.data_token_ctx), (uint8_t**)scope_out, scope_size_out);
    if (sda_status_internal == SDA_STATUS_INTERNAL_NO_TOKENS_TO_SEARCH_ERROR) {

        const char scope_delimeter[] = " ";

        //init token context again
        //no return value is checked, since the return value we are interested in is the sda_status from sda_helper_get_next_data_token()
        //the initialization of the token context is required in case sda_scope_get_next() will be called again
        (void)sda_helper_init_token_context(&(sda_internal_ctx->message_data.data_token_ctx), sda_internal_ctx->message_data.claims.scope_data,
                                            sda_internal_ctx->message_data.claims.scope_data_size, scope_delimeter);

        sda_status_internal = SDA_STATUS_INTERNAL_NO_SCOPES_TO_SEARCH_ERROR;
    }


exit:
    sda_status = sda_return_status_translate(sda_status_internal);
    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}


sda_status_e sda_func_call_name_get(sda_operation_ctx_h handle, const uint8_t **func_call_name_out, size_t *func_call_name_size_out)
{
    sda_ctx_internal_s *sda_internal_ctx;

    uint64_t type_id;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_status_e sda_status;

    SDA_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    //check parameters
    SDA_ERR_RECOVERABLE_GOTO_IF(handle == NULL, sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Got NULL for handle");
    SDA_ERR_RECOVERABLE_GOTO_IF((func_call_name_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid func_call_name");
    SDA_ERR_RECOVERABLE_GOTO_IF((func_call_name_size_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid func_call_name_size_out");

    sda_internal_ctx = (sda_ctx_internal_s*)handle;
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_internal_ctx->message_state != SDA_OP_PROCESSING_MESSAGE),
        sda_status_internal = SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT, exit, "Cann't proccess message (%d)", sda_internal_ctx->message_state);

    //get type_id from context
    type_id = sda_internal_ctx->message_data.parsed_user_operation.type_id;
    SDA_ERR_RECOVERABLE_GOTO_IF((type_id != SDA_OPERATION_FUNC_CALL),
        sda_status_internal = SDA_STATUS_INTERNAL_INVALID_COMMAND_ERROR, exit, "Got wrong <type-id> in command!");

    *func_call_name_out = (const uint8_t*)sda_internal_ctx->message_data.parsed_user_operation.function_name;
    *func_call_name_size_out = (size_t)sda_internal_ctx->message_data.parsed_user_operation.function_name_size;

exit:
    sda_status = sda_return_status_translate(sda_status_internal);
    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}




sda_status_e sda_func_call_data_parameter_get(sda_operation_ctx_h handle, uint32_t index, const uint8_t **data_param_out, size_t *data_param_size_out)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_status_e sda_status;

    sda_parameter_data_s parameter_data ;
    memset(&parameter_data, 0, sizeof(parameter_data));

    SDA_LOG_INFO_FUNC_ENTER("Index = %" PRIu32, index);

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    //Check parameters
    SDA_ERR_RECOVERABLE_GOTO_IF(handle == NULL, sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Got NULL for handle");
    SDA_ERR_RECOVERABLE_GOTO_IF((data_param_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid data param pointer");
    SDA_ERR_RECOVERABLE_GOTO_IF((data_param_size_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid data param size pointer");

    parameter_data.parameter_type = SDA_STRING_FUNCTION_PARAMETER;

    sda_status_internal = sda_get_function_parameter_tiny(handle, &parameter_data, index);
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal = sda_status_internal, exit, "Failed to get data function parameter");

    //Update out variables
    *data_param_out = (uint8_t*)parameter_data.data_param;
    *data_param_size_out = (size_t)parameter_data.data_param_size;

    SDA_LOG_DEMO_INFO("Getting data (%u) parameter", index);

exit:
    sda_status = sda_return_status_translate(sda_status_internal);
    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}


sda_status_e sda_func_call_numeric_parameter_get(sda_operation_ctx_h handle, uint32_t index, int64_t *num_param_out)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_status_e sda_status;

    sda_parameter_data_s parameter_data;
    memset(&parameter_data, 0, sizeof(parameter_data));

    SDA_LOG_INFO_FUNC_ENTER("index=%" PRIu32, index);

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    //Check parameters
    SDA_ERR_RECOVERABLE_GOTO_IF(handle == NULL, sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Got NULL for handle");
    SDA_ERR_RECOVERABLE_GOTO_IF((num_param_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid num_param_out pointer");
    SDA_ERR_RECOVERABLE_GOTO_IF((num_param_out == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid num_param_out pointer");

    parameter_data.parameter_type = SDA_NUMERIC_PARAMETER;

    sda_status_internal = sda_get_function_parameter_tiny(handle, &parameter_data, index);
    SDA_ERR_RECOVERABLE_GOTO_IF((sda_status_internal != SDA_STATUS_INTERNAL_SUCCESS), sda_status_internal = sda_status_internal, exit, "Failed to get data function parameter");

    //Update out variable
    *num_param_out = parameter_data.numeric_parameter;

    SDA_LOG_DEMO_INFO("Getting INTEGER (%u) parameter", index);

exit:
    sda_status = sda_return_status_translate(sda_status_internal);
    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}

sda_status_e sda_response_data_set(sda_operation_ctx_h handle, uint8_t *buffer, size_t buffer_size)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_status_e sda_status;
    sda_ctx_internal_s *sda_internal_ctx;
    CborError cbor_error;

    sda_internal_ctx = (sda_ctx_internal_s*)handle;
    SDA_LOG_INFO_FUNC_ENTER("buffer_size=%" PRIu32, (uint32_t)buffer_size);

    // Check if SDA initialized, if not return an error
    SDA_ERR_RECOVERABLE_RETURN_IF((g_sda_initialized != true), SDA_STATUS_NOT_INITIALIZED, "SDA not initialized");

    SDA_ERR_RECOVERABLE_GOTO_IF((sda_internal_ctx == NULL), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid handle");
    SDA_ERR_RECOVERABLE_GOTO_IF((buffer == NULL || buffer_size == 0), sda_status_internal = SDA_STATUS_INTERNAL_INVALID_PARAMETER, exit, "Invalid buffer");
    SDA_ERR_RECOVERABLE_GOTO_IF(((buffer_size + SDA_RESPONSE_HEADER_SIZE) > sda_internal_ctx->response_max_size),
                                sda_status_internal = SDA_STATUS_INTERNAL_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR,
                                exit, "response buffer too small");

    // Encode buffer directly into the response map_encoder
    // Encode key
    cbor_error = cbor_encode_uint(sda_internal_ctx->map_encoder, SDA_RESPONSE_MAP_KEY_USER_BUFFER);
    SDA_ERR_RECOVERABLE_GOTO_IF(cbor_error != CborNoError, sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR, exit, "Cbor append error");
    // Encode byte string
    cbor_error = cbor_encode_byte_string(sda_internal_ctx->map_encoder, buffer, buffer_size);
    SDA_ERR_RECOVERABLE_GOTO_IF(cbor_error != CborNoError, sda_status_internal = SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR, exit, "Cbor append error");

exit:
    sda_status = sda_return_status_translate(sda_status_internal);
    SDA_LOG_INFO_FUNC_EXIT("status = %" PRId32, (int32_t)sda_status);
    return sda_status;
}

#endif // MBED_CLOUD_CLIENT_ENABLE_SDA
