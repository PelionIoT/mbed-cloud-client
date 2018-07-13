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

#ifndef __FTCD_COMM_SOCKET_H__
#define __FTCD_COMM_SOCKET_H__

#include "ftcd_comm_base.h"
#include "pal.h"
#include <inttypes.h>

#define INFINITE_SOCKET_TIMEOUT -1

/**
* List of supported networks domains. Current supported domain is ipv4 only.
*/
typedef enum {
    FTCD_AF_UNSPEC = 0,//!< Unspecified IP protocol.
    FTCD_IPV4 = 2,     //!< Internet IP Protocol.
} ftcd_socket_domain_e;

/**
* Type for sockets.
*/
typedef void* palSocket_t;
/**
* Structure for Ethernet interface info.
*/
struct palNetInterfaceInfo;
/**
* Class for Ethernet interface.
*/
class EthernetInterface;

/** FtcdCommSocket implements the logic of listening for TCP connections and
*  process incoming messages from the Factory Tool.
*/
class FtcdCommSocket : public FtcdCommBase {

public:

    /**
    * The Socket Constructor
    * Initializes private variables and sets network interface handler, IP and port number.
    * If port_num is 0, then random port will be generated.
    */
    FtcdCommSocket(const void *interfaceHandler, ftcd_socket_domain_e domain, const uint16_t port_num, ftcd_comm_network_endianness_e network_endianness = FTCD_COMM_NET_ENDIANNESS_BIG, int32_t timeout = INFINITE_SOCKET_TIMEOUT);

    /**
    * The Socket Constructor
    * Initializes private variables and sets network interface handler, IP and port number.
    * If port_num is 0, then random port will be generated.
    */
    FtcdCommSocket(const void *interfaceHandler, ftcd_socket_domain_e domain, const uint16_t port_num, ftcd_comm_network_endianness_e network_endianness, const uint8_t *header_token, bool use_signature, int32_t timeout = INFINITE_SOCKET_TIMEOUT);

    /**
    * The Socket Destructor
    * Closes opened resources and frees allocated memory.
    */
    virtual ~FtcdCommSocket();

    /**
    * Initializes Network interface and prints its address.
    */
    virtual bool init(void);

    /**
    * Closes opened sockets
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
    *     FTCD_COMM_STATUS_SUCCESS - On success. In this case the client socket, and accepted connection remain open waiting for the next message with next call.
    *     FTCD_COMM_NETWORK_TIMEOUT - This means a timeout has occurred, client socket close and next call will create a new socket and accept a new connection.
    *     Other ftcd_comm_status_e error code - some other error has occurred, client socket will be closed and next call will create and open a new socket, and wait for a new connection.
    */
    virtual ftcd_comm_status_e wait_for_message(uint8_t **message_out, uint32_t *message_size_out);

    /** Detects the message token from the communication line medium.
    *
    * @returns
    *     true, if token detected and false otherwise
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
    enum connection_state_e {
        SOCKET_WAIT_FOR_CONNECTION,
        SOCKET_CONNECTION_ACCEPTED
    };

    connection_state_e _connection_state;
    const void *_interface_handler;
    palSocket_t _server_socket;
    palSocket_t _client_socket;
    palNetInterfaceInfo *_net_interface_info;
    uint16_t _port;
    ftcd_socket_domain_e _current_domain_type;
    ftcd_socket_domain_e _required_domain_type;
    uint32_t _interface_index;
    int32_t _rcv_timeout;

    /** Starts listening for incoming TCP socket connection
    *   A single connection allowed at a time
    *
    *   @returns
    *       true, if listen to the socket succeeded.
    */
    bool _listen(void);

    /**Reads a requested amount of bytes from a TCP socket
    *
    * @param data_out Pre-allocated buffer to be filled
    * @param data_out_size Buffer length in bytes
    *
    * @returns
    *    0, if the number of bytes read from the socket were exactly bufferOutSize, error status otherwise.
    */
    ftcd_comm_status_e _read_from_socket(void *data_out, int data_out_size);

};


#endif //__FTCD_COMM_SOCKET_H__
