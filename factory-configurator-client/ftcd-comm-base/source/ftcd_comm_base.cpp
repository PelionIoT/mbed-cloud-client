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

#include <stdlib.h>
#include <string.h>
#include "pv_endian.h"
#include "mbed-trace/mbed_trace.h"
#include "ftcd_comm_base.h"
#include "cs_hash.h"
#include "fcc_malloc.h"

#define TRACE_GROUP "fcbs"

FtcdCommBase::FtcdCommBase(ftcd_comm_network_endianness_e network_endianness, const uint8_t *header_token, bool use_signature)
{
    _network_endianness = network_endianness;
    _header_token = NULL;
    _use_token = (header_token != NULL);
    if (_use_token) {
        _header_token = (uint8_t*)fcc_malloc(FTCD_MSG_HEADER_TOKEN_SIZE_BYTES);
        if (_header_token == NULL) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed to allocate token buffer");
        } else {
            memcpy(_header_token, header_token, FTCD_MSG_HEADER_TOKEN_SIZE_BYTES);
        }
    }

    _use_signature = use_signature;
}

FtcdCommBase::~FtcdCommBase()
{
    if (_header_token) {
        fcc_free(_header_token);
    }
}


bool FtcdCommBase::init()
{
    return true;
}

void FtcdCommBase::finish()
{
}

ftcd_comm_status_e FtcdCommBase::wait_for_message(uint8_t **message_out, uint32_t *message_size_out)
{
    bool success = false;
    ftcd_comm_status_e status_code = FTCD_COMM_STATUS_SUCCESS;
    uint8_t *message = NULL;
    uint32_t message_size = 0;

    if (message_out == NULL || message_size_out == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid parameter");
        return FTCD_COMM_INVALID_PARAMETER;
    }

    *message_out = NULL;
    *message_size_out = 0;

    if (_use_token == true) {
        //detect token
        status_code = is_token_detected();
        if (status_code != FTCD_COMM_STATUS_SUCCESS) {
            if (status_code != FTCD_COMM_NETWORK_CONNECTION_CLOSED) {
                mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Network error (%d)", status_code);
            }
            return status_code;
        } 
    }

    // Read message size
    message_size = read_message_size();
    if (_network_endianness == FTCD_COMM_NET_ENDIANNESS_LITTLE) {
        message_size = pv_le32_to_h(message_size);
    } else { // big endian
        message_size = pv_be32_to_h(message_size);
    }
    if (message_size == 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Unable to read message size (got ZERO)");
        status_code = FTCD_COMM_FAILED_TO_READ_MESSAGE_SIZE;
        return status_code;
    }

    //read message
    message = (uint8_t *)fcc_malloc(message_size);
    if (message == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed to allocate message buffer");
        status_code = FTCD_COMM_MEMORY_OUT;
        return status_code;
    }
    success = read_message(message, message_size);
    if (!success) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed getting message bytes");
        status_code = FTCD_COMM_FAILED_TO_READ_MESSAGE_BYTES;
        fcc_free(message);
        return status_code;
    }

    if (_use_signature == true) {
        //read message signature

        uint8_t sig_from_message[CS_SHA256_SIZE];
        success = read_message_signature(sig_from_message, sizeof(sig_from_message));
        if (!success) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed getting signature bytes");
            status_code = FTCD_COMM_FAILED_TO_READ_MESSAGE_SIGNATURE;
            fcc_free(message);
            return status_code;
        }

        //calculate message signature
        uint8_t self_calculated_sig[CS_SHA256_SIZE];
        kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
        kcm_status = cs_hash(CS_SHA256, message, message_size, self_calculated_sig, sizeof(self_calculated_sig));
        if (kcm_status != KCM_STATUS_SUCCESS) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed calculating message signature");
            status_code = FTCD_COMM_FAILED_TO_CALCULATE_MESSAGE_SIGNATURE;
            fcc_free(message);
            return status_code;
        }

        //compare signatures
        if (memcmp(self_calculated_sig, sig_from_message, CS_SHA256_SIZE) != 0) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Inconsistent message signature");
            status_code = FTCD_COMM_INCONSISTENT_MESSAGE_SIGNATURE;
            fcc_free(message);
            return status_code;
        }
    }

    *message_out = message;
    *message_size_out = message_size;
    return status_code;
}

ftcd_comm_status_e FtcdCommBase::send_response(const uint8_t *response_message, uint32_t response_message_size)
{
    return _send_response(response_message, response_message_size, false, FTCD_COMM_STATUS_SUCCESS);
}

ftcd_comm_status_e FtcdCommBase::send_response(const uint8_t *response_message, uint32_t response_message_size, ftcd_comm_status_e status_code)
{
    return _send_response(response_message, response_message_size, true, status_code);
}

ftcd_comm_status_e FtcdCommBase::_send_response(const uint8_t *response_message, uint32_t response_message_size, bool send_status_code, ftcd_comm_status_e status_code)
{
    uint32_t response_size = 0;
    if (_use_token == true) {
        response_size += (uint32_t)sizeof(uint64_t); // TOKEN
    }
    if (send_status_code == true) {
        response_size += (uint32_t)sizeof(uint32_t); // STATUS
    }
    if (status_code == FTCD_COMM_STATUS_SUCCESS) {
        response_size += (uint32_t)sizeof(uint32_t); // MESSAGE SIZE
        response_size += response_message_size; // MESSAGE DATA
        if (_use_signature == true) {
            response_size += CS_SHA256_SIZE; // SIGNATURE
        }
    }

    uint8_t *response = (uint8_t *)fcc_malloc(response_size);
    if (response == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed to allocate response message buffer");
        status_code = FTCD_COMM_MEMORY_OUT;
        return status_code;
    }

    uint32_t offset = 0;

    if (_use_token == true) {
        // TOKEN
        memcpy(response, _header_token, FTCD_MSG_HEADER_TOKEN_SIZE_BYTES);
        offset = FTCD_MSG_HEADER_TOKEN_SIZE_BYTES;
    }

    if (send_status_code == true) {
        //STATUS
        uint32_t aligned_status_code = static_cast<uint32_t>(status_code);
        if (_network_endianness == FTCD_COMM_NET_ENDIANNESS_LITTLE) {
            aligned_status_code = pv_h_to_le32(aligned_status_code);
        } else { // big endian
            aligned_status_code = pv_h_to_be32(aligned_status_code);
        }
        memcpy(response + offset, &aligned_status_code, sizeof(uint32_t));
        offset += (uint32_t)sizeof(status_code);
    }

    if (status_code == FTCD_COMM_STATUS_SUCCESS) {

        if (response_message != NULL && response_message_size > 0) {
            // MESSAGE SIZE
            uint32_t aligned_msg_size = response_message_size;
            if (_network_endianness == FTCD_COMM_NET_ENDIANNESS_LITTLE) {
                aligned_msg_size = pv_h_to_le32(aligned_msg_size);
            } else { // big endian
                aligned_msg_size = pv_h_to_be32(aligned_msg_size);
            }
            memcpy(response + offset, &aligned_msg_size, sizeof(uint32_t));
            offset += (uint32_t)sizeof(uint32_t);

            // MESSAGE DATA
            memcpy(response + offset, response_message, response_message_size);
            offset += response_message_size;

        } else {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid response message");
        }

        if (_use_signature == true) {
            kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
            uint8_t sig[CS_SHA256_SIZE];

            kcm_status = cs_hash(CS_SHA256, response_message, response_message_size, sig, CS_SHA256_SIZE);
            if (kcm_status != KCM_STATUS_SUCCESS) {
                mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed calculating response message signature");
                fcc_free(response);
                return FTCD_COMM_INTERNAL_ERROR;
            }

            // SIGNATURE
            memcpy(response + offset, sig, CS_SHA256_SIZE);
        }
    }

    // Send the response...
    bool success = send(response, response_size);

    fcc_free(response);

    if (!success) {
        return FTCD_COMM_FAILED_TO_SEND_VALID_RESPONSE;
    }
    return FTCD_COMM_STATUS_SUCCESS;
}


