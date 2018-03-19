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

#ifndef __FTCD_COMM_BASE_H__
#define __FTCD_COMM_BASE_H__

#include <stdint.h>

/**
* @file ftcd_comm_base.h
*
*  Token      [64bit]   : The message identifier
*  Status     [32 bit]  : Status of message parameters (exists in response messages only)
*  Length     [32bit]   : The message length in bytes
*  Message    [Length]  : A message to be processed
*  Signature  [32B]     : The hash (SHA256) value of the message
*/


/** Unique message identifiers
*/
#define FTCD_MSG_HEADER_TOKEN_FCC { 0x6d, 0x62, 0x65, 0x64, 0x70, 0x72, 0x6f, 0x76 }
#define FTCD_MSG_HEADER_TOKEN_SDA { 0x6d, 0x62, 0x65, 0x64, 0x64, 0x62, 0x61, 0x70 }
#define FTCD_MSG_HEADER_TOKEN_SIZE_BYTES 8


typedef enum {
    FTCD_COMM_STATUS_SUCCESS,
    FTCD_COMM_STATUS_ERROR, //generic error
    FTCD_COMM_INVALID_PARAMETER,
    FTCD_COMM_MEMORY_OUT,
    FTCD_COMM_FAILED_TO_READ_MESSAGE_SIZE,
    FTCD_COMM_FAILED_TO_READ_MESSAGE_BYTES,
    FTCD_COMM_FAILED_TO_READ_MESSAGE_SIGNATURE,
    FTCD_COMM_FAILED_TO_CALCULATE_MESSAGE_SIGNATURE,
    FTCD_COMM_INCONSISTENT_MESSAGE_SIGNATURE,
    FTCD_COMM_FAILED_TO_PROCESS_DATA,
    FTCD_COMM_FAILED_TO_PROCESS_MESSAGE,
    FTCD_COMM_FAILED_TO_SEND_VALID_RESPONSE,

    FTCD_COMM_NETWORK_TIMEOUT,          //socket timeout error
    FTCD_COMM_NETWORK_CONNECTION_ERROR, //socket error
    FTCD_COMM_INTERNAL_ERROR,

    FTCD_COMM_STATUS_MAX_ERROR = 0xFFFFFFFF
} ftcd_comm_status_e;

typedef enum {
    FTCD_COMM_NET_ENDIANNESS_LITTLE,
    FTCD_COMM_NET_ENDIANNESS_BIG,
} ftcd_comm_network_endianness_e;

/**
* \brief ::FtcdCommBase implements the logic of processing incoming requests from the remote Factory Tool Demo.
*/
class FtcdCommBase {

public:

    FtcdCommBase(ftcd_comm_network_endianness_e network_endianness,const uint8_t *header_token = NULL, bool use_signature = false);

    /** Not certain that we need to do anything here, but just in case we need
     * to do some clean-up at some point.
     */
    virtual ~FtcdCommBase() = 0;

    /**
    * Initializes Network interface and opens socket
    * Prints IP address
    */
    virtual bool init(void);

    /**
    * Closes the opened socket
    */
    virtual void finish(void);

    /** Wait and read complete message from the communication line.
    * The method waits in blocking mode for new message,
    * allocate and read the message,
    * and sets message_out and message_size_out
    *
    * @param message_out The message allocated and read from the communication line
    * @param message_size_out The message size in bytes
    *
    * @returns
    *     FTCD_COMM_STATUS_SUCCESS on success, otherwise appropriate error from  ftcd_comm_status_e
    */
    virtual ftcd_comm_status_e wait_for_message(uint8_t **message_out, uint32_t *message_size_out);

    /** Writes a response message to the communication line.
    * The method build response message with header and signature (if requested)
    * and writes it to the line
    *
    * @param response_message The message to send through the communication line medium
    * @param response_message_size The message size in bytes
    *
    * @returns
    *     FTCD_COMM_STATUS_SUCCESS on success, otherwise appropriate error from  ftcd_comm_status_e
    */
    ftcd_comm_status_e send_response(const uint8_t *response_message, uint32_t response_message_size);

    /** Writes a response message with status to the communication line.
    * The method build response message with status, header and signature (if requested)
    * and writes it to the line
    *
    * @param response_message The message to send through the communication line medium
    * @param response_message_size The message size in bytes
    *
    * @returns
    *     FTCD_COMM_STATUS_SUCCESS on success, otherwise appropriate error from  ftcd_comm_status_e
    */
    ftcd_comm_status_e send_response(const uint8_t *response_message, uint32_t response_message_size, ftcd_comm_status_e status_code);

    /** Writes an allocated response message to the communication line medium.
    *
    * @param response_message The message to send through the communication line medium
    * @param response_message_size The message size in bytes
    *
    * @returns
    *     true upon success, false otherwise
    */
    virtual bool send(const uint8_t *response_message, uint32_t response_message_size) = 0;

    /** Detects the message token from the communication line medium.
    *
    * @returns
    *     zero, if token detected and different value otherwise
    */
    virtual ftcd_comm_status_e is_token_detected(void) = 0;

    /** Reads the message size in bytes from the communication line medium.
    * This is the amount of bytes needed to allocate for the upcoming message bytes.
    *
    * @returns
    *     The message size in bytes in case of success, zero bytes otherwise.
    */
    virtual uint32_t read_message_size(void) = 0;

    /** Reads the message size in bytes from the communication line medium.
    * This is the amount of bytes needed to allocate for the upcoming message bytes.
    *
    * @param message_out The buffer to read into and return to the caller.
    * @param message_size The message size in bytes.
    *
    * @returns
    *     true upon success, false otherwise
    */
    virtual bool read_message(uint8_t *message_out, size_t message_size) = 0;

    /** Reads the message size in bytes from the communication line medium.
    * This is the amount of bytes needed to allocate for the upcoming message bytes.
    *
    * @param sig The buffer to read into and return to the caller.
    * @param sig_size The sig buffer size in bytes.
    *
    * @returns
    *     The message size in bytes in case of success, zero bytes otherwise.
    */
    virtual bool read_message_signature(uint8_t *sig, size_t sig_size) = 0;

protected:

    /* Member point to the token array */
    uint8_t *_header_token;

private:

    /* Internal method that build response message with status, header and signature (if requested)
    * and writes it to the line */
    ftcd_comm_status_e _send_response(const uint8_t *response_message, uint32_t response_message_size, bool send_status_code, ftcd_comm_status_e status_code);

    /** Holds the requested network bytes order */
    ftcd_comm_network_endianness_e _network_endianness;

    /** Holds the requested message format (with token or without) */
    bool _use_token;

    /** Holds the requested message format (with signature or without) */
    bool _use_signature;
};

#endif  // __FTCD_COMM_BASE_H__
