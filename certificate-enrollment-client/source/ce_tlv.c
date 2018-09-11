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


#include "ce_tlv.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "pv_log.h"
#include "pal_macros.h"

#define TYPE_LENGTH_IN_BYTES 2
#define LEN_LENGTH_IN_BYTES 2

#define CE_TLV_ASSERT_ARG(arg) if (!arg) { return CE_TLV_STATUS_INVALID_ARG;}
#define CE_TLV_CHECK_CALL(call) if ((status = call) != CE_TLV_STATUS_SUCCESS) { return status;}


static bool assert_in_buffer(const ce_tlv_element_s *element, uint16_t num_of_bytes_to_take)
{
    if (element->_end < element->_current) {
        return false;
    }
    if (element->_end - element->_current >= num_of_bytes_to_take) {
        return true;
    }

    return false;
}

static ce_tlv_status_e take_16bit_number(ce_tlv_element_s *element, uint16_t *number_out)
{
    if(assert_in_buffer(element, sizeof(*number_out))) { 
        memcpy(number_out, element->_current, sizeof(*number_out));

        // Convert from network endianity (big endian) to host endianity in a portable manner
        *number_out = PAL_NTOHS(*number_out);
        element->_current += sizeof(*number_out);
        return CE_TLV_STATUS_SUCCESS;
    }

    return CE_TLV_STATUS_ERROR; // Malformed TLV
}

static ce_tlv_status_e take_bytes(ce_tlv_element_s *element)
{
    if (assert_in_buffer(element, element->len)) {
        element->val.bytes = element->_current;
        element->_current += element->len;
        return CE_TLV_STATUS_SUCCESS;
    }
    return CE_TLV_STATUS_ERROR;
}


static ce_tlv_status_e take_type(ce_tlv_element_s *element)
{
    return take_16bit_number(element, &element->type);
}

static ce_tlv_status_e take_length(ce_tlv_element_s *element)
{
    return take_16bit_number(element, &element->len);
}

// Element where element->len is the length of the string
static ce_tlv_status_e take_string(ce_tlv_element_s *element)
{
    ce_tlv_status_e status = CE_TLV_STATUS_SUCCESS;

    // Take the bytes
    CE_TLV_CHECK_CALL(take_bytes(element));

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
            // FIXME: Return what?
            break;
    }

    return CE_TLV_STATUS_SUCCESS;
}


ce_tlv_status_e ce_tlv_parser_init(const uint8_t *tlv_buf, size_t tlv_buf_len, ce_tlv_element_s *element_out)
{ 
    // Null check
    if (!tlv_buf || !element_out || tlv_buf_len == 0) {
        return CE_TLV_STATUS_INVALID_ARG;
    }

    memset(element_out, 0, sizeof(ce_tlv_element_s));

    element_out->_current = tlv_buf;
    element_out->_end = tlv_buf + tlv_buf_len;

    return CE_TLV_STATUS_SUCCESS;
}

ce_tlv_status_e ce_tlv_parse_next(ce_tlv_element_s *element)
{
    ce_tlv_status_e status = CE_TLV_STATUS_SUCCESS;

    CE_TLV_ASSERT_ARG(element);

    // Check if we are at the end of the buffer
    if (element->_current == element->_end) {
        return CE_TLV_STATUS_END;
    }

    // If this is true then there is a bug in the code
    assert(element->_current <= element->_end);

    // Parse type
    CE_TLV_CHECK_CALL(take_type(element));

    // Parse length
    CE_TLV_CHECK_CALL(take_length(element));

    // Parse value
    CE_TLV_CHECK_CALL(take_value(element));

    return CE_TLV_STATUS_SUCCESS;
}

#ifdef CERT_RENEWAL_TEST
static void _append_16bit_number(uint16_t number, ce_tlv_encoder_s *encoder)
{
    uint16_t num_buf = PAL_HTONS(number);

    memcpy(encoder->buf + (uint8_t)encoder->encoded_length, &num_buf, sizeof(num_buf));
    encoder->encoded_length += (uint16_t)sizeof(num_buf);
}

static void _append_value_buffer(const uint8_t *val_buf, uint16_t val_buf_len, ce_tlv_encoder_s *encoder)
{
    memcpy(encoder->buf + (uint8_t)encoder->encoded_length, val_buf, val_buf_len);
    encoder->encoded_length += (uint16_t)val_buf_len;
}

static ce_tlv_status_e append_tlv(ce_tlv_type_e type, uint16_t length, const uint8_t *value, ce_tlv_encoder_s *encoder)
{
    // If out of range - update the length - and return CE_TLV_STATUS_ENCODER_INSUFFICIENT_BUFFER
    // Next encoding will do the same and any time we may know how big the buffer must be: encoder->encoded_length
    if (encoder->encoded_length + TYPE_LENGTH_IN_BYTES + LEN_LENGTH_IN_BYTES + length > encoder->_buf_size) {
        encoder->encoded_length += (uint16_t)(TYPE_LENGTH_IN_BYTES + LEN_LENGTH_IN_BYTES + length);
        return CE_TLV_STATUS_ENCODER_INSUFFICIENT_BUFFER;
    }

    // Append type
    _append_16bit_number(type, encoder);

    // Append length
    _append_16bit_number(length, encoder);

    // Append value
    _append_value_buffer(value, length, encoder);

    return CE_TLV_STATUS_SUCCESS;
}

static ce_tlv_status_e append_text(ce_tlv_type_e type, const char *text, ce_tlv_encoder_s *encoder)
{
    // In text type - copy the null terminator as well
    return append_tlv(type, (uint16_t)strlen(text) + 1, (uint8_t *)text, encoder);
}

void ce_tlv_encoder_init(uint8_t *buf, uint16_t buf_size, ce_tlv_encoder_s *encoder)
{
    memset(encoder, 0, sizeof(*encoder));
    encoder->buf = buf;
    encoder->encoded_length = 0; // Explicit assignment for readability
    encoder->_buf_size = buf_size;
}
ce_tlv_status_e ce_tlv_encoder_append_cert_name(const char *cert_name, ce_tlv_encoder_s *encoder)
{
    return append_text(CE_TLV_TYPE_CERT_NAME, cert_name, encoder);
}

#endif // CERT_RENEWAL_TEST
