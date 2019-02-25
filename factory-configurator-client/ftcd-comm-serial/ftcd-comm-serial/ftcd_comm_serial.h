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

#ifndef __FTCD_COMM_SERIAL_H__
#define __FTCD_COMM_SERIAL_H__

#include "ftcd_comm_base.h"
#include <inttypes.h>

class FtcdCommSerial : public FtcdCommBase {

public:
    /** Initialize serial object that communicate via stdin and stdout */
    FtcdCommSerial(ftcd_comm_network_endianness_e network_endianness, const uint8_t *header_token, bool use_signature);

    /** Not certain that we need to do anything here, but just in case we need
     * to do some clean-up at some point.
     */
    virtual ~FtcdCommSerial();

    /** Detects the message token from the communication line medium.
    *
    * @returns
    *     zero, if token detected and different value otherwise
    */
    virtual ftcd_comm_status_e is_token_detected(void);

    /** Reads the message size in bytes from the communication line medium.
    * This is the amount of bytes needed to allocate for the upcoming message bytes.
    *
    * @returns
    *     The message size in bytes in case of success, zero bytes otherwise.
    */
    virtual uint32_t read_message_size(void);

    /** Reads the message size in bytes from the communication line medium.
    * This is the amount of bytes needed to allocate for the upcoming message bytes.
    *
    * @param message_out The buffer to read into and return to the caller.
    * @param message_size The message size in bytes.
    *
    * @returns
    *     true upon success, false otherwise
    */
    virtual bool read_message(uint8_t *message_out, size_t message_size);

    /** Reads the message size in bytes from the communication line medium.
    * This is the amount of bytes needed to allocate for the upcoming message bytes.
    *
    * @param sig The buffer to read into and return to the caller.
    * @param sig_size The sig buffer size in bytes.
    *
    * @returns
    *     The message size in bytes in case of success, zero bytes otherwise.
    */
    virtual bool read_message_signature(uint8_t *sig, size_t sig_size);

    /** Writes the given data to the communication line medium.
    *
    * @param data The bytes to send through the communication line medium
    * @param data_size The data size in bytes
    *
    * @returns
    *     true upon success, false otherwise
    */
    virtual bool send(const uint8_t *data, uint32_t data_size);

private:

    /** Reads a buffer from the serial line.
    *
    * @param buff_out A pointer to the buffer to read into, should be allocated by the caller
    * @param buff_max_size The max chars to read
    *
    * @returns
    *     the number of chars read, zero in case of an error
    */
    size_t _serial_read(char *buff_out, size_t buff_max_size);

    /** Writes a buffer to the serial line.
    *
    * @param buff A buffer to write.
    * @param buff_size The number of chars in buffer
    *
    * @returns
    *     the number of chars that was written, zero in case of an error
    */
    size_t _serial_write(const char *buff, size_t buff_size);
};

#endif  // __FTCD_COMM_SERIAL_H__
