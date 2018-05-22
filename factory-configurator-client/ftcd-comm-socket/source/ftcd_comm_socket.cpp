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

#include <stdlib.h>
#include "pal.h"
#include "pv_log.h"
#include "ftcd_comm_socket.h"
#include "fcc_malloc.h"

#define NUM_OF_PENDING_CONNECTIONS 1
#define NUM_OF_TRIES_TO_GET_INTERFACE_INFO 5
#define TRACE_GROUP "fcsk"
#define RANDOM_PORT_MIN 1024
#define RANDOM_PORT_MAX 65535

FtcdCommSocket::FtcdCommSocket(const void *interfaceHandler, ftcd_socket_domain_e domain, const uint16_t port_num, ftcd_comm_network_endianness_e network_endianness, int32_t timeout)
    : FtcdCommBase(network_endianness, NULL, false)
{
    _interface_handler = interfaceHandler;
    _required_domain_type = domain;
    _port = port_num;
    _rcv_timeout = timeout;
    _current_domain_type = FTCD_AF_UNSPEC;
    _interface_index = 0;
    _net_interface_info = NULL;
    _server_socket = NULL;
    _client_socket = NULL;
}

FtcdCommSocket::FtcdCommSocket(const void *interfaceHandler, ftcd_socket_domain_e domain, const uint16_t port_num, ftcd_comm_network_endianness_e network_endianness, const uint8_t *header_token, bool use_signature, int32_t timeout)
    : FtcdCommBase(network_endianness,header_token, use_signature)

{
    _interface_handler = interfaceHandler;
    _required_domain_type = domain;
    _port = port_num;
    _rcv_timeout = timeout;
    _current_domain_type = FTCD_AF_UNSPEC;
    _interface_index = 0;
    _net_interface_info = NULL;
    _server_socket = NULL;
    _client_socket = NULL;
}

FtcdCommSocket::~FtcdCommSocket()
{

    if (_net_interface_info != NULL) {
        fcc_free(_net_interface_info);
    }
    if (_server_socket != NULL) {
        pal_close(&_server_socket);
    }
    if (_client_socket != NULL) {
        pal_close(&_client_socket);
    }
}


bool FtcdCommSocket::init()
{
    int retries = NUM_OF_TRIES_TO_GET_INTERFACE_INFO;
    palIpV4Addr_t ip_v4_addr;
    char ip_and_port_string[32] = { 0 };
    uint32_t index = 0;

    //Call to pal init
    palStatus_t result = pal_init();
    if (result != PAL_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Error initializing pal");
        return false;
    }

    // If port is 0, generate random port
    // Pal currently does not support binding with port 0.
    if (_port == 0) {
        srand((unsigned int)pal_osKernelSysTick());
        // Generate random port int the range [RANDOM_PORT_MIN, RANDOM_PORT_MAX - 1] including.
        _port = (uint16_t)(rand() % (RANDOM_PORT_MAX - RANDOM_PORT_MIN) + RANDOM_PORT_MIN);
    }

    //Register connected interface handler
    result = pal_registerNetworkInterface((void*)_interface_handler, &_interface_index);
    if (result != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n pal_RegisterNetworkInterface Failed");
        return false;
    }

    //Allocate memory for interface info
    if (_net_interface_info == NULL) {
        _net_interface_info = (palNetInterfaceInfo_t*)fcc_malloc(sizeof(palNetInterfaceInfo_t));
        if (_net_interface_info == NULL) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Failed to allocate memory for network interface");
            return false;
        }
    }

    //Try to get interface info
    while (retries--) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Trying receive interface ...");
        result = pal_getNetInterfaceInfo(_interface_index, _net_interface_info);
        if (result != 0) {
            pal_osDelay(200);
        } else {//In case we have interface info we print it
            if (_required_domain_type != FTCD_IPV4) {
                mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Illegal domain type");
                break;
            }
            //Update domain type
            _current_domain_type = _required_domain_type;

            result = pal_getSockAddrIPV4Addr(&(_net_interface_info->address), ip_v4_addr);
            if (result != PAL_SUCCESS) {
                mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n palGetSockAddrIPV4Addr failed");
                break;
            }
            memset(ip_and_port_string, 0, sizeof(ip_and_port_string));
            index = 0;
            for (uint32_t i = 0; i < sizeof(palIpV4Addr_t); i++) {
                if (i < sizeof(palIpV4Addr_t) - 1) {
                    index += sprintf(&ip_and_port_string[index], "%d.", ip_v4_addr[i]);
                } else {
                    index += sprintf(&ip_and_port_string[index], "%d:", ip_v4_addr[i]);
                    index += sprintf(&ip_and_port_string[index], "%d\n", _port);
                }
            }

            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Factory Client IP Address and Port :  %s", ip_and_port_string);
            //open and listen to socket
            if (_listen()) {
                return true;
            } else {
                mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed to listen to socket");
            }

        }

    }

    mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n FCC did not succeed receive network interface !!!!!!");
    //If we couldn't get interface info free allocated memory
    fcc_free(_net_interface_info);
    _net_interface_info = NULL;
    return false;

}


void FtcdCommSocket::finish(void)
{
    if (_server_socket != NULL) {
        pal_close(&_server_socket);
        _server_socket = NULL;
    }
    if (_client_socket != NULL) {
        pal_close(&_client_socket);
        _client_socket = NULL;
    }
    pal_destroy();
}

ftcd_comm_status_e FtcdCommSocket::wait_for_message(uint8_t **message_out, uint32_t *message_size_out)
{
    int result = PAL_SUCCESS;

    palSocketLength_t addrlen = sizeof(palSocketAddress_t);
    palSocketAddress_t address = { 0 };

    // wait to accept connection
    result = pal_accept(_server_socket, &address, &addrlen, &_client_socket);
    if (result == PAL_ERR_SOCKET_WOULD_BLOCK) {
        return FTCD_COMM_NETWORK_TIMEOUT;
    } else if (result != PAL_SUCCESS) {
        return FTCD_COMM_NETWORK_CONNECTION_ERROR;
    }

    return FtcdCommBase::wait_for_message(message_out, message_size_out);
}

ftcd_comm_status_e FtcdCommSocket::is_token_detected(void)
{
    char c;
    int result = PAL_SUCCESS;
    size_t idx = 0;

    //read char by char to detect token
    while (idx < FTCD_MSG_HEADER_TOKEN_SIZE_BYTES) {
        result = _read_from_socket(reinterpret_cast<void*>(&c), 1);
        if (result == PAL_ERR_SOCKET_WOULD_BLOCK) {
            return FTCD_COMM_NETWORK_TIMEOUT;
        } else if (result != PAL_SUCCESS) {
            return FTCD_COMM_NETWORK_CONNECTION_ERROR;
        }

        if (c == _header_token[idx]) {
            idx++;
        } else {
            idx = 0;
        }
    }
    return FTCD_COMM_STATUS_SUCCESS;
}


uint32_t FtcdCommSocket::read_message_size(void)
{
    uint32_t message_size = 0;
    ftcd_comm_status_e result = FTCD_COMM_STATUS_SUCCESS;

    result = _read_from_socket(reinterpret_cast<void*>(&message_size), sizeof(message_size));
    if (result != FTCD_COMM_STATUS_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed reading message size");
        return 0;
    }

    return message_size;
}

bool FtcdCommSocket::read_message(uint8_t *message_out, size_t message_size)
{
    ftcd_comm_status_e result = FTCD_COMM_STATUS_SUCCESS;

    if (message_out == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid message buffer");
        return false;
    }

    // Read CBOR message bytes
    // We assume that message_size is NOT bigger than INT_MAX
    result = _read_from_socket(reinterpret_cast<void*>(message_out), (int)message_size);
    if (result != FTCD_COMM_STATUS_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed reading message bytes");
        return false;
    }
    return true;
}


bool FtcdCommSocket::read_message_signature(uint8_t *sig, size_t sig_size)
{
    ftcd_comm_status_e result = FTCD_COMM_STATUS_SUCCESS;

    if (sig == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid sig buffer");
        return false;
    }

    // Read signature from medium
    // We assume that sig_size is NOT bigger than INT_MAX
    result = _read_from_socket(reinterpret_cast<void*>(sig), (int)sig_size);
    if (result != FTCD_COMM_STATUS_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed reading message signature bytes");
        return false;
    }
    return true;
}


bool FtcdCommSocket::send(const uint8_t *data, uint32_t data_size)
{
    bool success = true;
    palStatus_t result = PAL_SUCCESS;
    size_t sent_bytes = 0;
    size_t remaind_bytes = (size_t)data_size;

    do {
        result = pal_send(_client_socket, data, remaind_bytes, &sent_bytes);
        if (result != PAL_SUCCESS) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed pal_send");
            success = false;
            break;
        }

        if (sent_bytes == 0 || sent_bytes > remaind_bytes) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Sending response message failed");
            success = false;
            break;
        }
        remaind_bytes = remaind_bytes - sent_bytes;
        data += sent_bytes;

    } while (remaind_bytes != 0);

    return success;
}

bool FtcdCommSocket::_listen(void)
{
    int status;
    palStatus_t result = PAL_SUCCESS;
    palSocketAddress_t address = { 0 };
    palIpV4Addr_t ipv4 = { 0 };
    int enable_reuseaddr = 1;

    //Check port number and domain type
    if (_port == 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Wrong port number");
        return false;
    }

    if (_current_domain_type != FTCD_IPV4) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Wrong domain type");
        return false;
    }

    //Open server and client sockets
    result = pal_socket((palSocketDomain_t)_current_domain_type, PAL_SOCK_STREAM_SERVER, false, _interface_index, &_server_socket);
    if (result != PAL_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "pal_socket failed");
        return false;
    }

    result = pal_socket((palSocketDomain_t)_current_domain_type, PAL_SOCK_STREAM, false, _interface_index, &_client_socket);
    if (result != PAL_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "pal_socket failed");
        return false;
    }

    status = pal_setSocketOptions(_server_socket, PAL_SO_REUSEADDR, &enable_reuseaddr, sizeof(enable_reuseaddr));
    if (status != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed to set SO_REUSEADDR (status %d)", status);
        return false;
    }

    //Get ipv4 format address from interface info structure
    status = pal_getSockAddrIPV4Addr(&(_net_interface_info->address), ipv4);
    if (status != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Cannot palGetSockAddrIPV4Addr (status %d)", status);
        return false;
    }

    //Set the retrieved address to pal socket address
    status = pal_setSockAddrIPV4Addr(&address, ipv4);
    if (status != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Cannot set socket ipv4 address (status %d)", status);
        return false;
    }

    //Set current port number to pal socket address
    status = pal_setSockAddrPort(&address, _port);
    if (status != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Cannot set socket port address (status %d)", status);
        return false;
    }

    //set server socket timeout
    if (_rcv_timeout >= 0) {
        status = pal_setSocketOptions(_server_socket, PAL_SO_RCVTIMEO, &_rcv_timeout, sizeof(_rcv_timeout));
        if (status != 0) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Cannot set server socket timeout (status %d)", status);
            return false;
        }
    }

    status = pal_bind(_server_socket, &address, _net_interface_info->addressSize);
    if (status != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "pal_bind failed (status %d)", status);
        return false;
    }

    status = pal_listen(_server_socket, NUM_OF_PENDING_CONNECTIONS);
    if (status != 0) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "pal_listen failed (status %d)", status);
        return false;
    }

    mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Factory Client is waiting for incoming connection...");

    return true;
}


ftcd_comm_status_e FtcdCommSocket::_read_from_socket(void * data_out, int data_out_size)
{
    int status = PAL_SUCCESS;
    size_t bytes_received = 0;

    if (data_out == NULL) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Invalid message");
        return FTCD_COMM_INTERNAL_ERROR;
    }

    status = pal_recv(_client_socket, data_out, data_out_size, &bytes_received);
    if (status == PAL_ERR_SOCKET_WOULD_BLOCK) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Receive socket timeout, (status = %i)", status);
        return FTCD_COMM_NETWORK_TIMEOUT;
    } else if (status != PAL_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Receive socket error, (status = %i)", status);
        return FTCD_COMM_NETWORK_CONNECTION_ERROR;
    }

    /* FIXME: The socket reads up to MSS (Max Segment Size) which is 1460 bytes.
    A bigger message would result in a partial message read. A temporary solution
    is to loop through until socket emptiness */

    // The number of bytes we had managed to read so far
    size_t bytes_read_successfully = bytes_received;

    // The remaining bytes left to read
    size_t remaining_bytes = data_out_size - bytes_received;

    // Loop through until nothing left to read
    // remaining_bytes will never be less than 0 since a max of remaining_bytes will be read into bytes_received,
    // and we do remaining_bytes -= bytes_received
    while (remaining_bytes != 0) {

        //Zero bytes_received before next receive
        bytes_received = 0;

        status = pal_recv(_client_socket, (uint8_t *)data_out + bytes_read_successfully, remaining_bytes, &bytes_received);
        if (status == PAL_ERR_SOCKET_WOULD_BLOCK) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Receive socket timeout, (status = %i)", status);
            return FTCD_COMM_NETWORK_TIMEOUT;
        } else if (status != PAL_SUCCESS) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Receive socket error, (status = %i)", status);
            return FTCD_COMM_NETWORK_CONNECTION_ERROR;
        }
        // Should never happen - this means that pal_recv behaved incorrectly.
        if (bytes_received > remaining_bytes) {
            return FTCD_COMM_INTERNAL_ERROR;
        }
        remaining_bytes -= bytes_received;
        bytes_read_successfully += bytes_received;
    }
    return FTCD_COMM_STATUS_SUCCESS;
}


