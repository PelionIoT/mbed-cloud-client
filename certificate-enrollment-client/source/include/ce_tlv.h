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

#ifndef __CE_TLV_H__
#define __CE_TLV_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum  {
    CE_TLV_STATUS_SUCCESS,
    CE_TLV_STATUS_END,
    CE_TLV_STATUS_INVALID_ARG,
    CE_TLV_STATUS_TEXT_NOT_TERMINATED,
    CE_TLV_STATUS_MALFORMED_TLV,
    CE_TLV_STATUS_ERROR,
    CE_TLV_STATUS_ENCODER_INSUFFICIENT_BUFFER
} ce_tlv_status_e;

typedef enum {
    CE_TLV_TYPE_CERT_NAME = 1
} ce_tlv_type_e;

typedef struct ce_tlv_element_ {
    const uint8_t *_current; // 4 bytes
    const uint8_t *_end; // 4 bytes
    union { 
        const uint8_t *bytes;
        const char *text;
        int integer;
    } val; // 4 bytes
    bool is_required;
    uint16_t type; // 2 bytes
    uint16_t len; // 2 bytes
} ce_tlv_element_s;

ce_tlv_status_e ce_tlv_parser_init(const uint8_t *tlv_buf, size_t tlv_buf_len, ce_tlv_element_s *element_out);
ce_tlv_status_e ce_tlv_parse_next(ce_tlv_element_s *element);

/* Checks if the given element is required or optional by testing 
* the "type" MSB bit. [0 == required] while [1 == optional]
*
* @param element[IN] The element to test
*
* @return "true" if element is required, "false" otherwise.
*/
bool is_required(const ce_tlv_element_s *element);

#ifdef CERT_RENEWAL_TEST
typedef struct ce_tlv_encoder_ {
    uint8_t *buf; // 4 bytes
    uint16_t encoded_length; // 2 bytes
    uint16_t _buf_size; // 2 bytes
} ce_tlv_encoder_s;

void ce_tlv_encoder_init(uint8_t *buf, uint16_t buf_size, ce_tlv_encoder_s *encoder);
ce_tlv_status_e tlv_add_str(ce_tlv_type_e type, uint16_t length, const char *value, bool is_tlv_required, ce_tlv_encoder_s *encoder);

#endif // CERT_RENEWAL_TEST

#ifdef __cplusplus
}
#endif

#endif // __CE_TLV_H__

