// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifndef VARINT_H
#define VARINT_H

#include <stdint.h>

typedef enum {
    ERR_BUFFER_TOO_SMALL = -7,
    ERR_PARAMETTERS = -6,
    OPERATION_COMPLETED = 0,
    OPERATION_NEEDS_MORE_DATA = 1
}var_int_op_code;

// decodes varint with multiple calls one byte at a time, returns 1 of more data is needed caller should pass
// number of calls already done int count
var_int_op_code decode_unsigned_varint(unsigned char varIntByte, uint64_t* varIntValue, int count);
var_int_op_code decode_signed_varint(unsigned char varIntByte, int64_t* varIntValue, int count);

// encodes varint to stream, BUFF_SIZE_MAX should containt maxbytes in buf to avoid overwrites
int encode_unsigned_varint(uint64_t value, unsigned char *buf, uint32_t BUFF_SIZE_MAX);
int encode_signed_varint(int64_t value, unsigned char *buf, uint32_t BUFF_SIZE_MAX);

#endif
