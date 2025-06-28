/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-client/m2mconnectionsecurity.h"
#include "mbed-client-mbedtls/m2mconnectionsecuritypimpl.h"

M2MConnectionSecurity::M2MConnectionSecurity(SecurityMode mode)
{
    _private_impl = new M2MConnectionSecurityPimpl(mode);
}

M2MConnectionSecurity::~M2MConnectionSecurity(){
    delete _private_impl;
}

void M2MConnectionSecurity::reset(){
    _private_impl->reset();
}

int M2MConnectionSecurity::init(const M2MSecurity *security, uint16_t security_instance_id, bool is_server_ping, const char *hostname){
    return _private_impl->init(security, security_instance_id, is_server_ping, hostname);
}

int M2MConnectionSecurity::connect(M2MConnectionHandler* connHandler, bool is_server_ping){
    return _private_impl->connect(connHandler, is_server_ping);
}

int M2MConnectionSecurity::send_message(unsigned char *message, int len){
    return _private_impl->send_message(message, len);
}

int M2MConnectionSecurity::read(unsigned char* buffer, uint16_t len){
    return _private_impl->read(buffer, len);
}

void M2MConnectionSecurity::set_random_number_callback(random_number_cb callback)
{
    _private_impl->set_random_number_callback(callback);
}

void M2MConnectionSecurity::set_entropy_callback(entropy_cb callback)
{
    _private_impl->set_entropy_callback(callback);
}

void M2MConnectionSecurity::set_socket(void *socket, void *address)
{
    _private_impl->set_socket((palSocket_t) socket, (palSocketAddress_t*) address);
}

int M2MConnectionSecurity::set_dtls_socket_callback(void(*foo)(void*), void *argument)
{
    return _private_impl->set_dtls_socket_callback(foo, argument);
}

void M2MConnectionSecurity::update_network_rtt_estimate(uint8_t rtt_estimate)
{
    _private_impl->update_network_rtt_estimate(rtt_estimate);
}

void M2MConnectionSecurity::store_cid()
{
    _private_impl->store_cid();
}

void M2MConnectionSecurity::remove_cid()
{
    _private_impl->remove_cid();
}

bool M2MConnectionSecurity::is_cid_available()
{
    return _private_impl->is_cid_available();
}

void M2MConnectionSecurity::set_cid_value(const uint8_t *data_ptr, const size_t data_len)
{
    _private_impl->set_cid_value(data_ptr, data_len);
}
