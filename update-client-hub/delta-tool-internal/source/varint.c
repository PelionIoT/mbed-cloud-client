/*-
 * Copyright (c) 2018-2019 ARM Limited
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdint.h>
#include <varint.h>

unsigned char TOP_BIT_ON_BYTE = (128);
unsigned char TOP_BIT_OFF_BYTE = (127);

// return 0 if decode completed otherwise 1 negative on error
var_int_op_code decode_unsigned_varint(unsigned char varIntByte, uint64_t* varIntValue, int count)
{
    var_int_op_code returnValue = OPERATION_COMPLETED;

    if (count > 9 || varIntValue == 0) {
        return ERR_PARAMETTERS;
    }

    if (count == 0) {
        *varIntValue = 0;
    }

    int hasMore = varIntByte & TOP_BIT_ON_BYTE;
    varIntByte &= TOP_BIT_OFF_BYTE;

    uint64_t byteAs64int = varIntByte;

    for (int i = 0; i < count; i++) {
        byteAs64int <<= 7;
    }
    *varIntValue |= byteAs64int;

    if (hasMore) {
        returnValue = OPERATION_NEEDS_MORE_DATA;
    } else {
        returnValue = OPERATION_COMPLETED;
    }

    return returnValue;
}

int encode_unsigned_varint(uint64_t value, unsigned char *buf, uint32_t BUFF_SIZE_MAX)
{
    unsigned int pos = 0;
    do {
        if (pos >= BUFF_SIZE_MAX) {
            return ERR_BUFFER_TOO_SMALL;  // protecting buf from overwrite
        }
        buf[pos] = (char) value;
        value >>= 7;
        if (value > 0) {
            buf[pos] |= TOP_BIT_ON_BYTE;
        } else {
            buf[pos] &= TOP_BIT_OFF_BYTE;
        }
        pos++;
    } while (value > 0);

    return pos;
}

int encode_signed_varint(int64_t value, unsigned char *buf, uint32_t BUFF_SIZE_MAX)
{
    unsigned int pos = 0;

    if (value < 0) {
        value = value * -1;  // change value to positive number.
        value <<= 1;
        value |= 1; // set lowest bit 1 if it was negative;
    } else {
        value <<= 1; // lower bit set to 0 if not negative.
    }

    do {
        if (pos >= BUFF_SIZE_MAX) {
            return ERR_BUFFER_TOO_SMALL;  // protecting buf from overwrite
        }
        buf[pos] = (char) value;
        value >>= 7;
        if (value > 0) {
            buf[pos] |= TOP_BIT_ON_BYTE;
        } else {
            buf[pos] &= TOP_BIT_OFF_BYTE;
        }
        pos++;
    } while (value > 0);

    return pos;
}

var_int_op_code decode_signed_varint(unsigned char varIntByte, int64_t* varIntValue, int count)
{
    var_int_op_code returnValue = OPERATION_COMPLETED;

    if (count > 9 || varIntValue == 0) {
        return ERR_PARAMETTERS;
    }

    if (count == 0) {
        *varIntValue = 0;
    }

    int hasMore = varIntByte & TOP_BIT_ON_BYTE;
    varIntByte &= TOP_BIT_OFF_BYTE;

    uint64_t byteAs64int = varIntByte;

    for (int i = 0; i < count; i++) {
        byteAs64int <<= 7;
    }
    *varIntValue |= byteAs64int;

    if (hasMore) {
        returnValue = OPERATION_NEEDS_MORE_DATA;
    } else {
        returnValue = OPERATION_COMPLETED;
        if (*varIntValue & 1)  // this is negative value
                {
            *varIntValue >>= 1;
            *varIntValue = *varIntValue * -1;
        } else {
            *varIntValue >>= 1; // positive value just eat the lowest bit away.
        }
    }

    return returnValue;
}

