// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "ce_tlv.h"
#include "pv_log.h"
#include "pal_macros.h"
#include "pv_error_handling.h"

#define TYPE_LENGTH_IN_BYTES 2
#define LEN_LENGTH_IN_BYTES 2

// Get the number of bit in a specific variable
#define CE_BITS(var) (sizeof(var) * 8)
// Get the MSB bit number
#define CE_MSB(var) (CE_BITS(var) - 1)


static bool is_element_in_range(const ce_tlv_element_s *element, uint16_t num_of_bytes_to_take)
{
    if (element->_end < element->_current) {
        return false;
    }
    if ((element->_end - element->_current) >= num_of_bytes_to_take) {
        return true;
    }
    return false;
}

static ce_tlv_status_e take_16bit_number(ce_tlv_element_s *element, uint16_t *number_out)
{
    if (!is_element_in_range(element, sizeof(*number_out))) {
        return CE_TLV_STATUS_MALFORMED_TLV;
    }

    memcpy(number_out, element->_current, sizeof(*number_out));

    // Convert from network endianity (big endian) to host endianity in a portable manner
    *number_out = (uint16_t)PAL_NTOHS(*number_out);
    element->_current += sizeof(*number_out);
    return CE_TLV_STATUS_SUCCESS;
}

static ce_tlv_status_e take_bytes(ce_tlv_element_s *element)
{
    if (!is_element_in_range(element, element->len)) {
        return CE_TLV_STATUS_MALFORMED_TLV;
    }

    element->val.bytes = element->_current;
    element->_current += element->len;
    return CE_TLV_STATUS_SUCCESS;
}

bool is_required(const ce_tlv_element_s *element)
{
    return element->is_required;
}

static ce_tlv_status_e take_type(ce_tlv_element_s *element)
{
    ce_tlv_status_e status = take_16bit_number(element, &element->type);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != CE_TLV_STATUS_SUCCESS), status, "failed in take_16bit_number()");

    // keep order, test "is required" and then clear the type MSB
    element->is_required = (((element->type >> CE_MSB(element->type)) & 1) == 1) ? false : true;
    element->type &= (uint16_t)(~(1 << CE_MSB(element->type))); // clear the MSB bit
    return CE_TLV_STATUS_SUCCESS;
}

static ce_tlv_status_e take_length(ce_tlv_element_s *element)
{
    return take_16bit_number(element, &element->len);
}

// Element where element->len is the length of the string
static ce_tlv_status_e take_string(ce_tlv_element_s *element)
{
    // Take the bytes
    ce_tlv_status_e status = take_bytes(element);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != CE_TLV_STATUS_SUCCESS), status, "failed in take_bytes()");
    
    // Assert null terminator at the end
    if (element->val.bytes[element->len - 1] != '\0') {
        return CE_TLV_STATUS_TEXT_NOT_TERMINATED;
    }

    return CE_TLV_STATUS_SUCCESS;
}

static ce_tlv_status_e take_value(ce_tlv_element_s *element)
{
    switch (element->type) {
        case CE_TLV_TYPE_CERT_NAME:
            return take_string(element);
        default:
            // Skip next
            element->_current += element->len;
            break;
    }

    return CE_TLV_STATUS_SUCCESS;
}


ce_tlv_status_e ce_tlv_parser_init(const uint8_t *tlv_buf, size_t tlv_buf_len, ce_tlv_element_s *element_out)
{ 
    // Null check
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tlv_buf == NULL), CE_TLV_STATUS_INVALID_ARG, "Invalid tlv_buf");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((element_out == NULL), CE_TLV_STATUS_INVALID_ARG, "Invalid element_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((tlv_buf_len == 0), CE_TLV_STATUS_INVALID_ARG, "empty tlv_buf_len");

    memset(element_out, 0, sizeof(ce_tlv_element_s));

    element_out->_current = tlv_buf;
    element_out->_end = (tlv_buf + tlv_buf_len);

    return CE_TLV_STATUS_SUCCESS;
}

ce_tlv_status_e ce_tlv_parse_next(ce_tlv_element_s *element)
{
    ce_tlv_status_e status = CE_TLV_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((element == NULL), CE_TLV_STATUS_INVALID_ARG, "Invalid element");

    // Check if we are at the end of the buffer
    if (element->_current == element->_end) {
        return CE_TLV_STATUS_END;
    }

    // If this is true then there is a bug in the code
    // TBD: check if we need to remove this assert
    assert(element->_current < element->_end);

    // Parse type
    status = take_type(element);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != CE_TLV_STATUS_SUCCESS), status, "failed in take_bytes()");

    // Parse length
    status = take_length(element);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != CE_TLV_STATUS_SUCCESS), status, "failed in take_length()");

    // Parse value
    status = take_value(element);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != CE_TLV_STATUS_SUCCESS), status, "failed in take_value()");

    return CE_TLV_STATUS_SUCCESS;
}

#ifdef CERT_RENEWAL_TEST
static void _append_16bit_number(uint16_t number, ce_tlv_encoder_s *encoder)
{
    uint16_t num_buf = (uint16_t)PAL_HTONS(number);

    memcpy(encoder->buf + (uint8_t)encoder->encoded_length, &num_buf, sizeof(num_buf));
    encoder->encoded_length = (uint16_t)(encoder->encoded_length +sizeof(num_buf));
}

static void _append_value_string(const char *str, uint16_t str_length, ce_tlv_encoder_s *encoder)
{
    // str_length should contain the '\0'
    memcpy(encoder->buf + encoder->encoded_length, str, str_length);
    // FIXME: Cast is needed here, need to check why getting compilation warning in Native GCC (Linux)
    encoder->encoded_length = (uint16_t)(str_length + encoder->encoded_length);
}

ce_tlv_status_e tlv_add_str(ce_tlv_type_e type, uint16_t length, const char *value, bool is_tlv_required, ce_tlv_encoder_s *encoder)
{
    uint16_t _type = type;

    // If out of range - update the length - and return CE_TLV_STATUS_ENCODER_INSUFFICIENT_BUFFER
    // Next encoding will do the same and any time we may know how big the buffer must be: encoder->encoded_length
    if (encoder->encoded_length + TYPE_LENGTH_IN_BYTES + LEN_LENGTH_IN_BYTES + length > encoder->_buf_size) {
        encoder->encoded_length = (uint16_t)(encoder->encoded_length + (TYPE_LENGTH_IN_BYTES + LEN_LENGTH_IN_BYTES + length));
        return CE_TLV_STATUS_ENCODER_INSUFFICIENT_BUFFER;
    }

    // Append type

    if (!is_tlv_required) {
        // set MSB only if optional
        _type |= 1 << CE_MSB(_type);
    }
    _append_16bit_number(_type, encoder);

    // Append length
    _append_16bit_number(length, encoder);

    // Append value
    _append_value_string(value, length, encoder);

    return CE_TLV_STATUS_SUCCESS;
}

void ce_tlv_encoder_init(uint8_t *buf, uint16_t buf_size, ce_tlv_encoder_s *encoder)
{
    memset(buf, 0, buf_size);
    memset(encoder, 0, sizeof(*encoder));
    encoder->buf = buf;
    encoder->encoded_length = 0; // Explicit assignment for readability
    encoder->_buf_size = buf_size;
}

#endif // CERT_RENEWAL_TEST
