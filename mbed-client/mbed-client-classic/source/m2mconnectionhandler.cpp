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
#include "mbed-client-classic/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-client/m2mconstants.h"

M2MConnectionHandler::M2MConnectionHandler(M2MConnectionObserver &observer,
                                           M2MConnectionSecurity* sec,
                                           M2MInterface::BindingMode mode,
                                           M2MInterface::NetworkStack stack)
:_observer(observer)
{
    _private_impl = new M2MConnectionHandlerPimpl(this, observer, sec, mode, stack);
}

M2MConnectionHandler::~M2MConnectionHandler()
{
    delete _private_impl;
}

bool M2MConnectionHandler::bind_connection(const uint16_t listen_port)
{

    return _private_impl->bind_connection(listen_port);
}

bool M2MConnectionHandler::resolve_server_address(const String& server_address,
                                                      const uint16_t server_port,
                                                      M2MConnectionObserver::ServerType server_type,
                                                      const M2MSecurity* security,
                                                      bool is_server_ping)
{
    return _private_impl->resolve_server_address(server_address, server_port,
                                                 server_type, security, is_server_ping);
}

bool M2MConnectionHandler::start_listening_for_data()
{
    return _private_impl->start_listening_for_data();
}

void M2MConnectionHandler::stop_listening()
{
    _private_impl->stop_listening();
}

bool M2MConnectionHandler::send_data(uint8_t *data,
                                     uint16_t data_len,
                                     sn_nsdl_addr_s *address)
{
    return _private_impl->send_data(data, data_len, address);
}

void M2MConnectionHandler::handle_connection_error(int error)
{
    _private_impl->handle_connection_error(error);
}

void M2MConnectionHandler::set_platform_network_handler(void *handler)
{
    _private_impl->set_platform_network_handler(handler);
}

void M2MConnectionHandler::claim_mutex()
{
    _private_impl->claim_mutex();
}

void M2MConnectionHandler::release_mutex()
{
    _private_impl->release_mutex();
}

void M2MConnectionHandler::force_close()
{
    _private_impl->force_close();
}

void M2MConnectionHandler::unregister_network_handler()
{
    _private_impl->unregister_network_handler();
}

void M2MConnectionHandler::store_cid()
{
    _private_impl->store_cid();
}

void M2MConnectionHandler::remove_cid()
{
    _private_impl->remove_cid();
}

bool M2MConnectionHandler::is_cid_available()
{
    return _private_impl->is_cid_available();
}

void M2MConnectionHandler::set_cid_value(const uint8_t *data_ptr, const size_t data_len)
{
    _private_impl->set_cid_value(data_ptr, data_len);
}
