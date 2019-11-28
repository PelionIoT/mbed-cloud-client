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

#define FTCD_SEM_TIMEOUT ( (_rcv_timeout == INFINITE_SOCKET_TIMEOUT) ? (PAL_RTOS_WAIT_FOREVER) : (_rcv_timeout) )

// Cabllback triggered by socket events
// Non-blocking async sockets are used with blocking wrappers that wait on _async_sem.
// This callback signals the waiting semaphore in the blocking wrappers

// We must be sure that we do not have a situations where sem is being waited and then 2 releases prior to the next wait:


/* Scenario 1 (All according to plan)
************************************************************************************************************************************************************************************************************************************************************************************
Network thread/threads: ----------------------------------------------_socket_event_ready_cb -> take _lock -> signal (release) _aync_sem=1 ----------------------------------------------------------- _socket_event_ready_cb -> take _lock -> signal (release) _aync_sem=1



application thread:     _wait_for_socket_event (on _async_sem=0) --------------------------------------------------------------------------_aync_sem=0------- release _lock ------------- _wait_for_socket_event --------------------------------------------------------------->>>
************************************************************************************************************************************************************************************************************************************************************************************
*/

/* Scenario 2 (Event signals _async_sem before release _lock in _wait_for_socket_event)
************************************************************************************************************************************************************************************************************************************************************************************
Network thread/threads: ----------------------------------------------_socket_event_ready_cb -> take _lock -> signal (release) _aync_sem=1 ---- _socket_event_ready_cb -> ----try to take _lock and fail (locked)-------------------------------------------------------------------



application thread:     _wait_for_socket_event (on _async_sem=0) --------------------------------------------------------------------------_aync_sem=0--------------------------------------------------------- release _lock ------next action attempt and probably fail---- _wait_for_socket_event (block)-->>>
************************************************************************************************************************************************************************************************************************************************************************************
*/

/* Scenario 3 (Multiple events are invoked before _wait_for_socket_event() stops blocking)
************************************************************************************************************************************************************************************************************************************************************************************
Network thread/threads: ----------------------------------------------_socket_event_ready_cb -> take _lock -> signal (release) _aync_sem=1 ---- _socket_event_ready_cb -> try to take _lock and fail (locked) ------------------------------------



application thread:     _wait_for_socket_event (on _async_sem=0) ---------------------------------------------------------------------------------------------------------------------------------------_aync_sem=0--release _lock---------next action attempt and probably succeed (2nd event)-->>>
************************************************************************************************************************************************************************************************************************************************************************************
*/



void FtcdCommSocket::_socket_event_ready_cb(void *socket_obj)
{
    palStatus_t pal_status;
    // No need for NULL check, we pass a valid pointer
    FtcdCommSocket *obj = static_cast<FtcdCommSocket *>(socket_obj);
    // Do not print log, may be called from ISR

    // First lock - this prevents a scenario where sem count is greater then n (1 in our case) which is undefined behavior
    pal_status = pal_osSemaphoreWait(obj->_lock, 0, NULL);

    // If lock is taken by another thread - do not signal _async_sem because its count is 1. 
    // This scenario will happen if _socket_event_ready_cb() is triggered twice, before _lock is released in _wait_for_socket_event()
    // No need to signal _async_sem because it is already free
    // Note that our blocking wrappers first try to do the operation, and then block until an event occurs
    if (pal_status != PAL_SUCCESS) { 
        return;
    }

    // After we take the lock, we may signal sem
    (void)pal_osSemaphoreRelease(obj->_async_sem);
}

palStatus_t FtcdCommSocket::_wait_for_socket_event()
{
    palStatus_t pal_status;
    // Wait for signal from a new event, signaled by _socket_event_ready_cb()
    pal_status = pal_osSemaphoreWait(_async_sem, FTCD_SEM_TIMEOUT, NULL);

    // Unlock the lock so that one more signal may be signaled from an event
    (void)pal_osSemaphoreRelease((palSemaphoreID_t)_lock);

    return pal_status;
}

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
    _connection_state = SOCKET_WAIT_FOR_CONNECTION;
    (void)pal_osSemaphoreCreate(0, &_async_sem); // Create with count 0 so first wait will block
    (void)pal_osSemaphoreCreate(1, &_lock);

}

FtcdCommSocket::FtcdCommSocket(const void *interfaceHandler, ftcd_socket_domain_e domain, const uint16_t port_num, ftcd_comm_network_endianness_e network_endianness, const uint8_t *header_token, bool use_signature, int32_t timeout)
    : FtcdCommBase(network_endianness, header_token, use_signature)

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
    _connection_state = SOCKET_WAIT_FOR_CONNECTION;
    (void)pal_osSemaphoreCreate(0, &_async_sem); // Create with count 0 so first wait will block
    (void)pal_osSemaphoreCreate(1, &_lock);
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

    (void)pal_osSemaphoreDelete(&_async_sem);
    (void)pal_osSemaphoreDelete(&_lock);
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

            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "\n Client IP Address and Port :  %s", ip_and_port_string);
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


/* 
 There are 2 possible scenarios where _accept() is called:
 1. Very likely: sem=1 -> _listen(), sem=0 -> create socket -> _accept(), sem=0(block) -> _socket_event_ready_cb(), sem=1 -> accept() resumes, sem=0 -> nonblocking pal_accept()
 2. Very unlikely: sem=1 -> _listen(), sem=0 -> create socket -> _socket_event_ready_cb(), sem=1 -> _accept() never blocks, sem=0 -> nonblocking pal_accept()
*/
palStatus_t FtcdCommSocket::_accept(palSocket_t socket, palSocketAddress_t* address, palSocketLength_t* addressLen, palSocket_t* acceptedSocket)
{
    palStatus_t pal_status, result;

    while (true) {
        pal_status = pal_accept(socket, address, addressLen, acceptedSocket, _socket_event_ready_cb, (void*)this);
        if (pal_status == PAL_ERR_SOCKET_WOULD_BLOCK) { // Async socket has no connection to accept - wait on semaphore and try again
            pal_status = _wait_for_socket_event();
            if (pal_status == PAL_ERR_RTOS_TIMEOUT) { // Semaphore timeout means no event was triggered for _rcv_timeout ms so we return a WOULDBLOCK error according to blocking socket convention
                result = PAL_ERR_SOCKET_WOULD_BLOCK;
                break;
            } else if (pal_status != PAL_SUCCESS){ // Should not happen - some unknown semaphore error
                result = pal_status;
                break;
            }
            // else: Semaphore signaled by event try accepting again

        } else { // Either success, or error other than PAL_ERR_SOCKET_WOULD_BLOCK, return the status
            result = pal_status;
            break;
        }
    }
                    
    return result;
}


void FtcdCommSocket::_close_client_socket(void)
{
    if (_client_socket != NULL) {
        pal_close(&_client_socket);
        _client_socket = NULL;
    }
}

// no_open_connection, connection_open, connection_open_timeout
ftcd_comm_status_e FtcdCommSocket::wait_for_message(uint8_t **message_out, uint32_t *message_size_out)
{
    int result = PAL_SUCCESS;
    ftcd_comm_status_e comm_status = FTCD_COMM_STATUS_SUCCESS;
    palSocketLength_t addrlen = sizeof(palSocketAddress_t);
    palSocketAddress_t address = { 0 , { 0 } };
    bool reiterate;

    do {
        reiterate = false;

        if (_connection_state == SOCKET_WAIT_FOR_CONNECTION) {
            //Before getting a new client socket close the old one
            if (_client_socket != NULL) {
                _close_client_socket();
            }
            // wait to accept connection
            result = _accept(_server_socket, &address, &addrlen, &_client_socket);
            if (result == PAL_ERR_SOCKET_WOULD_BLOCK) {
                // Timeout
                return FTCD_COMM_NETWORK_TIMEOUT;
            } else if (result != PAL_SUCCESS) {
                return FTCD_COMM_NETWORK_CONNECTION_ERROR;
            }

        }

        // Set state as accepted connection
        _connection_state = SOCKET_CONNECTION_ACCEPTED;

        // Read the message from an open connection,
        // if the connection has been closed by the client wait for a new connection
        comm_status = FtcdCommBase::wait_for_message(message_out, message_size_out);
        if (comm_status == FTCD_COMM_NETWORK_CONNECTION_CLOSED) {
            reiterate = true; // Set the reiterate flag so that we will wait for a new connection before returning from function
        } 
        if (comm_status != FTCD_COMM_STATUS_SUCCESS) { // If error reading - close the client socket and back to SOCKET_CLOSED state
            _connection_state = SOCKET_WAIT_FOR_CONNECTION;
        }

    } while (reiterate);
    return comm_status;
}

ftcd_comm_status_e FtcdCommSocket::is_token_detected()
{
    char c;
    ftcd_comm_status_e result = FTCD_COMM_STATUS_SUCCESS;
    size_t idx = 0;

    //read char by char to detect token
    while (idx < FTCD_MSG_HEADER_TOKEN_SIZE_BYTES) {
        result = _read_from_socket(reinterpret_cast<void*>(&c), 1);
        
        if (result != FTCD_COMM_STATUS_SUCCESS) {
            return result;
        }

        if (c == _header_token[idx]) {
            idx++;
        } else {
            idx = 0;
        }
    }
    return result;
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

#define MS_BETWEEN_SOCKET_SEND_RETRIES 500
palStatus_t FtcdCommSocket::_send(palSocket_t socket, const void* buf, size_t len, size_t* sentDataSize)
{
    palStatus_t result = PAL_SUCCESS;
    
    // in blocking mode (linux socket) - pal_send will block until the buffer is copied into the kernel's networking stack buffer
    // In our case, non-blocking (linux socket) - will return a EWOULDBLOCK error if the kernel's buffer, so we will wait and retry (should work on first try)

    while (true) {
        result = pal_send(socket, buf, len, sentDataSize);
        if (result == PAL_ERR_SOCKET_WOULD_BLOCK) {
            pal_osDelay(MS_BETWEEN_SOCKET_SEND_RETRIES);
        } else { // If any other error, or success - return the status
            break;
        }
    }

    return result;
}

bool FtcdCommSocket::send(const uint8_t *data, uint32_t data_size)
{
    bool success = true;
    palStatus_t result = PAL_SUCCESS;
    size_t sent_bytes = 0;
    size_t remaind_bytes = (size_t)data_size;

    do {
        if (_connection_state != SOCKET_CONNECTION_ACCEPTED) {
            return FTCD_COMM_NETWORK_CONNECTION_CLOSED;
        }
        result = _send(_client_socket, data, remaind_bytes, &sent_bytes);
        if (result != PAL_SUCCESS) {
            // Drop current client for all errors
            _connection_state = SOCKET_WAIT_FOR_CONNECTION;
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
    palSocketAddress_t address = { 0 , { 0 } };
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

    //Open server socket
    result = pal_asynchronousSocketWithArgument((palSocketDomain_t)_current_domain_type, PAL_SOCK_STREAM_SERVER, true, _interface_index, _socket_event_ready_cb, (void*)this, &_server_socket);
    if (result != PAL_SUCCESS) {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "pal_socket failed");
        return false;
    }

    // reset connection state
    _connection_state = SOCKET_WAIT_FOR_CONNECTION;

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

    mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, " Client is waiting for incoming connection...");

    return true;
}

palStatus_t FtcdCommSocket::_recv(palSocket_t socket, void* buf, size_t len, size_t* recievedDataSize)
{
    palStatus_t pal_status, result;

    while (true) {
        pal_status = pal_recv(socket, buf, len, recievedDataSize);
        if (pal_status == PAL_ERR_SOCKET_WOULD_BLOCK) { // // The event was not a receive event - wait for next one
            pal_status = _wait_for_socket_event();
            if (pal_status == PAL_ERR_RTOS_TIMEOUT) { // Semaphore timeout means no event was triggered for _rcv_timeout ms so we return a WOULDBLOCK error according to blocking socket convention
                result = PAL_ERR_SOCKET_WOULD_BLOCK;
                break;
            } else if (pal_status != PAL_SUCCESS) { // Should not happen - some unknown semaphore error
                result = pal_status;
                break;
            }
            // else: Semaphore signaled by event try receiving again

        } else { // Either success, or error other than PAL_ERR_SOCKET_WOULD_BLOCK, return the status
            result = pal_status;
            break;
        }
    }

    return result;

}

ftcd_comm_status_e FtcdCommSocket::_read_from_socket(void * data_out, int data_out_size)
{
    palStatus_t pal_status = PAL_SUCCESS;
    size_t bytes_received = 0;
    size_t left_to_read = data_out_size;
    uint8_t* buffer = (uint8_t*)data_out;
    while (left_to_read > 0) {
        if (_connection_state != SOCKET_CONNECTION_ACCEPTED) {
            return FTCD_COMM_NETWORK_CONNECTION_CLOSED;
        }
        bytes_received = 0;
        pal_status = _recv(_client_socket, buffer, left_to_read, &bytes_received);
        if (pal_status == PAL_ERR_SOCKET_CONNECTION_CLOSED) {
            // Drop current client
            _connection_state = SOCKET_WAIT_FOR_CONNECTION;
            return FTCD_COMM_NETWORK_CONNECTION_CLOSED;
        }
        else if (pal_status == PAL_ERR_SOCKET_WOULD_BLOCK) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Receive socket timeout");
            return FTCD_COMM_NETWORK_TIMEOUT;
        } else if (pal_status != PAL_SUCCESS) {
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Receive socket error, (status = 0x%" PRIx32 ")", (uint32_t)pal_status);
            return FTCD_COMM_NETWORK_CONNECTION_ERROR;
        }
        buffer += bytes_received;
        if (left_to_read < bytes_received) {
            return FTCD_COMM_INTERNAL_ERROR;
        }
        left_to_read -= bytes_received;
    }

    return FTCD_COMM_STATUS_SUCCESS;
}

