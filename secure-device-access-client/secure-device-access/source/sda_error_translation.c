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
 
#include "sda_status.h"
#include "sda_status_internal.h"

sda_status_e sda_return_status_translate(sda_status_internal_e internal_status)
{
    sda_status_e sda_status;

    switch (internal_status) {

        case SDA_STATUS_INTERNAL_SUCCESS:

            sda_status = SDA_STATUS_SUCCESS;
            break;

        case SDA_STATUS_INTERNAL_GENERAL_ERROR:

            sda_status = SDA_STATUS_ERROR;
            break;

        case SDA_STATUS_INTERNAL_MESSAGE_ERROR:
        case SDA_STATUS_INTERNAL_MESSAGE_UNSUPPORTED_GROUP:
        case SDA_STATUS_INTERNAL_MESSAGE_INVALID_OPERATION_ID:
        case SDA_STATUS_INTERNAL_INVALID_PARAMETER:
        case SDA_STATUS_INTERNAL_OPERATION_INVALID_CONTEXT:
        case SDA_STATUS_INTERNAL_FUNCTION_PARAM_TYPE_ERROR:
        case SDA_STATUS_INTERNAL_INVALID_PARAM_INDEX:
        case SDA_STATUS_INTERNAL_FUNCTION_CALL_PARSE_ERROR:
        case SDA_STATUS_INTERNAL_FUNCTION_CALL_TYPE_ID_ERROR:
        case SDA_STATUS_INTERNAL_SCOPE_PARSING_ERROR:
        case SDA_STATUS_INTERNAL_COSE_PARSING_ERROR:
        case SDA_STATUS_INTERNAL_INVALID_COMMAND_ERROR:
        case SDA_STATUS_INTERNAL_MESSAGE_INVALID_GROUP:

            sda_status = SDA_STATUS_INVALID_REQUEST;
            break;

        case SDA_STATUS_INTERNAL_VERIFICATION_ERROR:
        case SDA_STATUS_INTERNAL_TOKEN_VERIFICATION_ERROR:
        case SDA_STATUS_INTERNAL_OPERATION_VERIFICATION_ERROR:
        case SDA_STATUS_INTERNAL_NONCE_VERIFICATION_ERROR:
        case SDA_STATUS_INTERNAL_AUDIENCE_PARAMETER_ERROR:
        case SDA_STATUS_INTERNAL_AUDIENCE_VERIFICATION_ERROR:
        case SDA_STATUS_INTERNAL_TOKEN_EXPIRATION_ERROR:
        case SDA_STATUS_INTERNAL_TRUST_ANCHOR_NOT_FOUND:

            sda_status = SDA_STATUS_VERIFICATION_ERROR;
            break;

        case SDA_STATUS_INTERNAL_EXPORT_FROM_DER_TRUST_ANCHOR_ERROR:
        case SDA_STATUS_INTERNAL_AUDIENCE_ERROR:
        case SDA_STATUS_INTERNAL_KCM_ERROR:
        case SDA_STATUS_INTERNAL_OUT_OF_MEMORY:
        case SDA_STATUS_INTERNAL_MESSAGE_RESPONSE_ERROR:

            sda_status = SDA_STATUS_DEVICE_INTERNAL_ERROR;
            break;

        case SDA_STATUS_INTERNAL_NO_SCOPES_TO_SEARCH_ERROR:

            sda_status = SDA_STATUS_NO_MORE_SCOPES;
            break;

        case SDA_STATUS_INTERNAL_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR:

            sda_status = SDA_STATUS_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR;
            break;

        default:
            sda_status = SDA_STATUS_ERROR;

    }

    return sda_status;
}
