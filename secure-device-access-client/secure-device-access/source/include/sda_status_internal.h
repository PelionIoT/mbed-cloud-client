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

#ifndef __SDA_INTERNAL_H__
#define __SDA_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SDA_STATUS_INTERNAL_BASE_ERROR       0x64   //100
#define SDA_STATUS_INTERNAL_MAX_ERROR       0xFF   //255

    typedef enum {
        SDA_STATUS_INTERNAL_SUCCESS,                                         //!< Operation completed successfully.
        SDA_STATUS_INTERNAL_GENERAL_ERROR,                                   //!< Operation ended with an unspecified error.
        SDA_STATUS_INTERNAL_OUT_OF_MEMORY = SDA_STATUS_INTERNAL_BASE_ERROR,  //!< An out-of-memory condition occurred.
        SDA_STATUS_INTERNAL_INVALID_PARAMETER,                               //!< A parameter provided to the function was invalid.
        SDA_STATUS_INTERNAL_MESSAGE_ERROR,                                   //!< Protocol layer general error.
        SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR,                          //!< Protocol layer failed to create response buffer.
        SDA_STATUS_INTERNAL_MESSAGE_UNSUPPORTED_GROUP,                       //!< Protocol layer detected unsupported group was found in a message.
        SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP,                           //!< Protocol layer detected invalid group in a message.
        SDA_STATUS_INTERNAL_MESSAGE_INVALID_OPERATION_ID,                    //!< Protocol layer detected invalid operation id in a message.
        SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT,                       //!< Out of order context
        SDA_STATUS_INTERNAL_FUNCTION_PARAM_TYPE_ERROR,                       //!< Current operation failed to check type of specific parameter
        SDA_STATUS_INTERNAL_INVALID_PARAM_INDEX,                             //!< Current operation tried to fetch parameter with invalid index.
        SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR,                       //!< Current operation failed to parse function call data.
        SDA_STATUS_INTERNAL_FUNCTION_CALL_TYPE_ID_ERROR,                     //!< Current operation failed to check type id of function call.
        SDA_STATUS_INTERNAL_SCOPE_PARSING_ERROR,                             //!< Operation failed due to invalid scope.
        SDA_STATUS_INTERNAL_COSE_PARSING_ERROR,                              //!< Operation failed to parse data.
        SDA_STATUS_INTERNAL_VERIFICATION_ERROR,                              //!< Operation failed to validate data.
        SDA_STATUS_INTERNAL_TOKEN_VERIFICATION_ERROR,                        //!< Current operation failed to validate token.
        SDA_STATUS_INTERNAL_OPERATION_VERIFICATION_ERROR,                    //!< Current operation failed to validate requested operation.
        SDA_STATUS_INTERNAL_INVALID_COMMAND_ERROR,                           //!< Current operation failed due to invalid command error
        SDA_STATUS_INTERNAL_NONCE_VERIFICATION_ERROR,                        //!< Current operation failed to process nonce data.
        SDA_STATUS_INTERNAL_NONCE_GENERATION_ERROR,                          //!< Current operation failed to generate nonce process.
        SDA_STATUS_INTERNAL_TRUST_ANCHOR_NOT_FOUND,                          //!< Trust anchor does not exist.
        SDA_STATUS_INTERNAL_EXPORT_FROM_DER_TRUST_ANCHOR_ERROR,              //!< Current operation failed to export trust anchor from der format.
        SDA_STATUS_INTERNAL_AUDIENCE_PARAMETER_ERROR,                        //!< Current operation failed due to invalid audience parameter.
        SDA_STATUS_INTERNAL_AUDIENCE_VERIFICATION_ERROR,                     //!< Current operation failed to validate audience.
        SDA_STATUS_INTERNAL_AUDIENCE_ERROR,                                  //!< Current operation failed to check audience.
        SDA_STATUS_INTERNAL_DEVICE_ID_ERROR,                                 //!< Current operation failed to due to invalid device id
        SDA_STATUS_INTERNAL_ENDPOINT_NAME_ERROR,                             //!< Current operation failed to due to invalid endpoint name
        SDA_STATUS_INTERNAL_KCM_ERROR,                                       //!< Failed during a KCM operation.
        SDA_STATUS_INTERNAL_NO_TOKENS_TO_SEARCH_ERROR,                       //!< Failed to detect token.
        SDA_STATUS_INTERNAL_NO_SCOPES_TO_SEARCH_ERROR,                       //!< Failed to detect scope.
        SDA_STATUS_INTERNAL_TOKEN_EXPIRATION_ERROR,                          //!< Current token is failed in expiration VERIFICATION.
        SDA_STATUS_INTERNAL_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR,         //!< Insufficient response buffer size for user buffer.
        SDA_STATUS_INTERNAL_LAST_ERROR = SDA_STATUS_INTERNAL_MAX_ERROR       //!< max error

    } sda_status_internal_e;

#ifdef __cplusplus
}
#endif

#endif

