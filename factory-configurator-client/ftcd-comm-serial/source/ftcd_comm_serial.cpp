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

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include "mbed-trace/mbed_trace.h"
#include "ftcd_comm_serial.h"
#if defined(__MBED__)
    #include "mbed.h"
#elif defined(__SXOS__)
    extern "C" int sxos_uart_write(const char *data, uint16_t len);
#else
    #error OS not supported
#endif

#define TRACE_GROUP "fcsr"

FtcdCommSerial::FtcdCommSerial(ftcd_comm_network_endianness_e network_endianness, const uint8_t *header_token, bool use_signature)
    : FtcdCommBase(network_endianness, header_token, use_signature)
{
}

FtcdCommSerial::~FtcdCommSerial()
{
}

size_t FtcdCommSerial::_serial_read(char *buffOut, size_t buffSize)
{
    ssize_t count = 0;
    size_t left_to_read = buffSize;
    char* buffer = buffOut;
    while (left_to_read > 0) {
#if defined(__MBED__)
        count = read(STDIN_FILENO, buffer, left_to_read);
#elif defined(__SXOS__)
        *buffer = (char)getchar();
        count = 1;
#endif
        if (count < 0) {
            break;
        }
        buffer += count;
        left_to_read -= count;
    }

    return buffSize - left_to_read;
}

size_t FtcdCommSerial::_serial_write(const char *buff, size_t buffSize)
{
    ssize_t count = 0;
    size_t left_to_write = buffSize;
    char* buffer = (char*)buff;
    while (left_to_write > 0) {
#if defined(__MBED__)
        count = write(STDOUT_FILENO, buffer, left_to_write);
#elif defined(__SXOS__)
        count = sxos_uart_write(buffer, left_to_write);
#endif
        if (count < 0) {
            break;
        }
        buffer += count;
        left_to_write -= count;
    }

    return buffSize - left_to_write;
}

ftcd_comm_status_e FtcdCommSerial::is_token_detected()
{
    char c;
    size_t idx = 0;

    //read char by char to detect token
    while (idx < FTCD_MSG_HEADER_TOKEN_SIZE_BYTES) {
        _serial_read(&c, 1);
        if (c == _header_token[idx]) {
            idx++;
        } else {
            idx = 0;
        }
    }
    return FTCD_COMM_STATUS_SUCCESS;
}

uint32_t FtcdCommSerial::read_message_size()
{
    uint32_t message_size = 0;

    size_t read_chars = _serial_read(reinterpret_cast<char*>(&message_size), sizeof(message_size));
    if (read_chars != sizeof(message_size)) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed reading message size (read %d bytes out of %d)", read_chars, sizeof(message_size));
        return 0;
    }

    return message_size;
}

bool FtcdCommSerial::read_message(uint8_t *message_out, size_t message_size)
{
    if (message_out == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid message buffer");
        return false;
    }

    // Read CBOR message bytes
    // We assume that LENGTH is NOT bigger than INT_MAX
    size_t read_chars = _serial_read(reinterpret_cast<char*>(message_out), message_size);
    if (read_chars != message_size) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed reading message bytes (read %d bytes out of %d)", read_chars, message_size);
        return false;
    }

    return true;
}

bool FtcdCommSerial::read_message_signature(uint8_t *sig, size_t sig_size)
{
    if (sig == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid sig buffer");
        return false;
    }

    // Read signature from medium
    size_t read_chars = _serial_read(reinterpret_cast<char*>(sig), sig_size);
    if (read_chars != sig_size) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed reading message signature bytes (read %d bytes out of %d)", read_chars, sig_size);
        return false;
    }

    return true;
}

bool FtcdCommSerial::send(const uint8_t *data, uint32_t data_size)
{
    if (data == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid response_message");
        return false;
    }
    if (data_size == 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Got an empty message");
        return false;
    }

    // Send data on the serial medium
    size_t write_chars = _serial_write(reinterpret_cast<const char*>(data), data_size);
    if (write_chars != data_size) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed writing message bytes (wrote %" PRIu32 " bytes out of %" PRIu32 ")", (uint32_t)write_chars, data_size);
        return false;
    }

    return true;
}
