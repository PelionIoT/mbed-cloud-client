/*
 * Copyright (c) 2015 - 2021 Pelion. All rights reserved.
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

// fixup the compilation on ARMCC for PRIu32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mbed-client-classic/m2mconnectionhandlerpimpl.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mconnectionhandler.h"
#if (PAL_DNS_API_VERSION == 2)
#include "mbed-client/m2mtimer.h"
#endif
#include "pal.h"
#include "eventOS_scheduler.h"
#include "eventOS_event_timer.h"
#include "mbed-trace/mbed_trace.h"
#include <stdlib.h> // free() and malloc()

#define TRACE_GROUP "mClt"

#if (PAL_DNS_API_VERSION == 1) && defined(TARGET_LIKE_MBED)
#error "For async PAL DNS only API v2 or greater is supported on Mbed."
#endif

#if (PAL_DNS_API_VERSION == 2)
#define DNS_FALLBACK_TIMEOUT 600000
#endif

extern "C" void network_status_event(palNetworkStatus_t status, void *client_arg)
{
    if (!client_arg) {
        return;
    }
    assert(client_arg);
    M2MConnectionHandlerPimpl *instance = (M2MConnectionHandlerPimpl *)client_arg;
    instance->interface_event(status);
}

int8_t M2MConnectionHandlerPimpl::_tasklet_id = -1;

// This is called from event loop, but as it is static C function, this is just a wrapper
// which calls C++ on the instance.
extern "C" void eventloop_event_handler(arm_event_s *event)
{
    if (!event->data_ptr) {
        return;
    }
    tr_debug("M2MConnectionHandlerPimpl::eventloop_event_handler %d", event->event_type);
    if (event->event_type != M2MConnectionHandlerPimpl::ESocketIdle) {
        if (!event->data_ptr) {
            tr_error("M2MConnectionHandlerPimpl::eventloop_event_handler event->data_ptr=NULL !!!!");
            assert(event->data_ptr);
        }
        M2MConnectionHandlerPimpl *instance = (M2MConnectionHandlerPimpl *)event->data_ptr;
        instance->event_handler(event);
    }
}

// event handler that forwards the event according to its type and/or connection state
void M2MConnectionHandlerPimpl::event_handler(arm_event_s *event)
{
    event->event_data = false;

    switch (event->event_type) {

        // Event from socket callback method
        case M2MConnectionHandlerPimpl::EInterfaceConnected:
            _observer.network_interface_status_change(M2MConnectionObserver::NetworkInterfaceConnected);
            break;
        case M2MConnectionHandlerPimpl::EInterfaceDisconnected:
            _observer.network_interface_status_change(M2MConnectionObserver::NetworkInterfaceDisconnected);
            break;

        case M2MConnectionHandlerPimpl::ESocketCallback:

            if (_socket_state == M2MConnectionHandlerPimpl::ESocketStateHandshaking) {
                receive_handshake_handler();
            } else if ((_socket_state == M2MConnectionHandlerPimpl::ESocketStateUnsecureConnection) ||
                       (_socket_state == M2MConnectionHandlerPimpl::ESocketStateSecureConnection)) {
                // the connection is established
                receive_handler();
            } else {
                socket_connect_handler();
            }

            // Receive processing could have changed state, so recheck
            if ((_socket_state == M2MConnectionHandlerPimpl::ESocketStateUnsecureConnection) ||
                    (_socket_state == M2MConnectionHandlerPimpl::ESocketStateSecureConnection)) {
                // the connection is established
                send_socket_data();
            }
            break;

        // Data send request from client side
        case M2MConnectionHandlerPimpl::ESocketSend:
            send_socket_data();
            break;

        // DNS resolved successfully
        case M2MConnectionHandlerPimpl::ESocketDnsResolved:
            handle_dns_result(true);
            break;

        // DNS resolving failed
        case M2MConnectionHandlerPimpl::ESocketDnsError:
            handle_dns_result(false);
            break;

        // Establish the connection by connecting the socket
        case M2MConnectionHandlerPimpl::ESocketConnect:
            socket_connect_handler();
            break;

        case M2MConnectionHandlerPimpl::ESocketClose:
            close_socket();
            break;

        default:
            tr_debug("M2MConnectionHandlerPimpl::connection_event_handler: default type: %d", (int)event->event_type);
            break;
    }
}

// This callback is used from PAL sockets, it is called with object instance as argument.
// This is received from "some" socket event from "some" socket and the C++ side is responsible
// of forwarding it or ignoring the event completely.
extern "C" void socket_event_handler(void *arg)
{
    M2MConnectionHandlerPimpl *instance = (M2MConnectionHandlerPimpl *)arg;

    if (!instance) {
        tr_error("Invalid callback argument");
        return;
    }

    instance->send_event(M2MConnectionHandlerPimpl::ESocketCallback);
}

M2MConnectionHandlerPimpl::M2MConnectionHandlerPimpl(M2MConnectionHandler *base, M2MConnectionObserver &observer,
                                                     M2MConnectionSecurity *sec,
                                                     M2MInterface::BindingMode mode,
                                                     M2MInterface::NetworkStack stack)
    : _base(base),
      _observer(observer),
      _security_impl(sec),
      _security(NULL),
      _binding_mode(mode),
      _socket(0),
      _server_type(M2MConnectionObserver::LWM2MServer),
      _server_port(0),
      _listen_port(0),
      _net_iface(0),
#if (PAL_DNS_API_VERSION == 0) || (PAL_DNS_API_VERSION == 1)
      _socket_address_len(0),
#elif (PAL_DNS_API_VERSION == 2)
      _handler_async_DNS(0),
#endif
      _socket_state(ESocketStateDisconnected),
      _secure_connection(false),
      _is_server_ping(false)
{
#ifndef PAL_NET_TCP_AND_TLS_SUPPORT
    if (is_tcp_connection()) {
        tr_error("ConnectionHandler: TCP support not available.");
        return;
    }
#endif
#if (PAL_DNS_API_VERSION == 2)
    _dns_fallback_timer = new M2MTimer(*this);
#endif
    if (PAL_SUCCESS != pal_init()) {
        tr_error("PAL init failed.");
    }

    memset(&_address, 0, sizeof _address);
    memset((void *)&_socket_address, 0, sizeof _socket_address);
    memset(&_ipV4Addr, 0, sizeof(palIpV4Addr_t));
    memset(&_ipV6Addr, 0, sizeof(palIpV6Addr_t));
    ns_list_init(&_linked_list_send_data);

    eventOS_scheduler_mutex_wait();
    if (M2MConnectionHandlerPimpl::_tasklet_id == -1) {
        M2MConnectionHandlerPimpl::_tasklet_id = eventOS_event_handler_create(&eventloop_event_handler, ESocketIdle);
    }
    eventOS_scheduler_mutex_release();

    initialize_event(&_event);
    initialize_event(&_socket_callback_event);
}

M2MConnectionHandlerPimpl::~M2MConnectionHandlerPimpl()
{
    tr_debug("~M2MConnectionHandlerPimpl()");
#if (PAL_DNS_API_VERSION == 2)
    if (_handler_async_DNS > 0) {
        pal_cancelAddressInfoAsync(_handler_async_DNS);
    }
    delete _dns_fallback_timer;
#endif

    close_socket();
    delete _security_impl;
    _security_impl = NULL;
    pal_destroy();
    tr_debug("~M2MConnectionHandlerPimpl() - OUT");
}

bool M2MConnectionHandlerPimpl::bind_connection(const uint16_t listen_port)
{
    _listen_port = listen_port;
    return true;
}

void M2MConnectionHandlerPimpl::send_event(SocketEvent event_type)
{
    if (event_type == M2MConnectionHandlerPimpl::ESocketCallback) {
        if (!_socket_callback_event.data.event_data) {
            _socket_callback_event.data.event_data = true;
            _socket_callback_event.data.event_type = event_type;
            eventOS_event_send_user_allocated(&_socket_callback_event);
        }
    } else {
        // Remove outstanding event from the queue and let close event always go through.
        if (_event.data.event_data && event_type == ESocketClose) {
            eventOS_cancel(&_event);
            _event.data.event_data = false;
        }

        if (!_event.data.event_data) {
            _event.data.event_data = true;
            _event.data.event_type = event_type;
            eventOS_event_send_user_allocated(&_event);
        }
    }
}

// This callback is used from PAL pal_getAddressInfoAsync,
#if (PAL_DNS_API_VERSION == 2)
extern "C" void address_resolver_cb(const char *url, palSocketAddress_t *address, palStatus_t status, void *callbackArgument)
{
    tr_debug("M2MConnectionHandlerPimpl::address_resolver callback");
    M2MConnectionHandlerPimpl *instance = (M2MConnectionHandlerPimpl *)callbackArgument;
    instance->stop_dns_fallback_timer();
    if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::address_resolver callback failed with %" PRIx32, status);
        instance->send_event(M2MConnectionHandlerPimpl::ESocketDnsError);
    } else {
        instance->send_event(M2MConnectionHandlerPimpl::ESocketDnsResolved);
    }
}
#endif

bool M2MConnectionHandlerPimpl::address_resolver(void)
{
    palStatus_t status;
    bool ret = false;

#if (PAL_DNS_API_VERSION == 2)
    tr_debug("M2MConnectionHandlerPimpl::address_resolver:asynchronous DNS");
    _handler_async_DNS = 0;
    tr_debug("M2MConnectionHandlerPimpl::address_resolver start _dns_fallback_timer");
    _dns_fallback_timer->stop_timer();
    _dns_fallback_timer->start_timer(DNS_FALLBACK_TIMEOUT, M2MTimerObserver::DnsQueryFallback, true);
    status = pal_getAddressInfoAsync(_server_address.c_str(), (palSocketAddress_t *)&_socket_address, &address_resolver_cb, this, &_handler_async_DNS);
    if (PAL_SUCCESS != status) {
        _dns_fallback_timer->stop_timer();
        tr_error("M2MConnectionHandlerPimpl::address_resolver, pal_getAddressInfoAsync fail. %" PRIx32, status);
        _observer.socket_error(M2MConnectionHandler::DNS_RESOLVING_ERROR);
    } else {
        ret = true;
    }
#else // #if (PAL_DNS_API_VERSION == 0)
    tr_debug("M2MConnectionHandlerPimpl::address_resolver:synchronous DNS");
    status = pal_getAddressInfo(_server_address.c_str(), (palSocketAddress_t *)&_socket_address, &_socket_address_len);
    if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::getAddressInfo failed with %" PRIx32, status);
        send_event(ESocketDnsError);
    } else {
        send_event(ESocketDnsResolved);
        ret = true;
    }
#endif

    return ret;
}

void M2MConnectionHandlerPimpl::handle_dns_result(bool success)
{
#if (PAL_DNS_API_VERSION == 2)
    _handler_async_DNS = 0;
#endif
    if (_socket_state != ESocketStateDNSResolving) {
        tr_warn("M2MConnectionHandlerPimpl::handle_dns_result() called, not in ESocketStateDNSResolving state!");
        return;
    }

    if (success) {
        _socket_state = EsocketStateInitializeConnection;
        socket_connect_handler();

    } else {
        _observer.socket_error(M2MConnectionHandler::DNS_RESOLVING_ERROR);
    }
}

bool M2MConnectionHandlerPimpl::resolve_server_address(const String &server_address,
                                                       const uint16_t server_port,
                                                       M2MConnectionObserver::ServerType server_type,
                                                       const M2MSecurity *security,
                                                       bool is_server_ping)
{
#if (PAL_DNS_API_VERSION == 2)
    if (_handler_async_DNS > 0) {
        if (pal_cancelAddressInfoAsync(_handler_async_DNS) != PAL_SUCCESS) {
            return false;
        }
    }
#endif
    _socket_state = ESocketStateDNSResolving;
    _security = security;

    int32_t security_instance_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
    if (server_type == M2MConnectionObserver::Bootstrap) {
        security_instance_id = _security->get_security_instance_id(M2MSecurity::Bootstrap);
    }

    if (_security &&
            security_instance_id >= 0 &&
            (_security->resource_value_int(M2MSecurity::SecurityMode, security_instance_id) == M2MSecurity::Certificate ||
             _security->resource_value_int(M2MSecurity::SecurityMode, security_instance_id) == M2MSecurity::Psk)) {
        _secure_connection = true;
    } else {
        _secure_connection = false;
    }

    _server_port = server_port;
    _server_type = server_type;
    _server_address = server_address;
    _is_server_ping = is_server_ping;


    return address_resolver();
}

void M2MConnectionHandlerPimpl::socket_connect_handler()
{
    palStatus_t status;
    int32_t security_instance_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
    if (_server_type == M2MConnectionObserver::Bootstrap) {
        security_instance_id = _security->get_security_instance_id(M2MSecurity::Bootstrap);
    }

    tr_debug("M2MConnectionHandlerPimpl::socket_connect_handler - _socket_state = %d", _socket_state);

    switch (_socket_state) {
        case ESocketStateCloseBeingCalled:
        case ESocketStateDNSResolving:
        case ESocketStateDisconnected:
        case ESocketStateHandshaking:
        case ESocketStateUnsecureConnection:
        case ESocketStateSecureConnection:
            // Ignore these events
            break;

        case EsocketStateInitializeConnection:

            // Initialize the socket to stable state
            close_socket();

            status = pal_setSockAddrPort((palSocketAddress_t *)&_socket_address, _server_port);

            if (PAL_SUCCESS != status) {
                tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - setSockAddrPort err: %" PRIx32, status);
            } else {
                tr_debug("address family: %d", (int)_socket_address.addressType);
            }

            if (_socket_address.addressType == PAL_AF_INET) {
                status = pal_getSockAddrIPV4Addr((palSocketAddress_t *)&_socket_address, _ipV4Addr);
                if (PAL_SUCCESS != status) {
                    tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - sockAddr4, err: %" PRIx32, status);
                    _observer.socket_error(M2MConnectionHandler::DNS_RESOLVING_ERROR);
                    return;
                }

                tr_info("M2MConnectionHandlerPimpl::socket_connect_handler - IPv4 Address %d.%d.%d.%d",
                        _ipV4Addr[0], _ipV4Addr[1], _ipV4Addr[2], _ipV4Addr[3]);

                _address._address = (void *)_ipV4Addr;
                _address._length = PAL_IPV4_ADDRESS_SIZE;
                _address._port = _server_port;
            } else if (_socket_address.addressType == PAL_AF_INET6) {
                status = pal_getSockAddrIPV6Addr((palSocketAddress_t *)&_socket_address, _ipV6Addr);
                if (PAL_SUCCESS != status) {
                    tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - sockAddr6, err: %" PRIx32, status);
                    _observer.socket_error(M2MConnectionHandler::DNS_RESOLVING_ERROR);
                    return;
                }

                tr_info("M2MConnectionHandlerPimpl::socket_connect_handler - IPv6 Address: %s", mbed_trace_ipv6(_ipV6Addr));

                _address._address = (void *)_ipV6Addr;
                _address._length = PAL_IPV6_ADDRESS_SIZE;
                _address._port = _server_port;
            } else {
                tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - socket config error, stack: %d", (int)_socket_address.addressType);
                _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
                return;
            }

            if (!init_socket()) {
                tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - socket init error");
                // The init_socket() calls the socket_error() -callback directly, so it must not be
                // done here too.
                return;
            }

            // This state was used to ignore the spurious events _during_ the call of non-blocking pal_connect().
            // Now that we just retry connect when it is not yet succeeded anyway this state might be removed completely.
            _socket_state = ESocketStateConnectBeingCalled;

        // fall through is intentional
        case ESocketStateConnectBeingCalled:
        case ESocketStateConnecting:
            if (is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
                tr_info("M2MConnectionHandlerPimpl::socket_connect_handler - Using TCP");

                status = pal_connect(_socket, (palSocketAddress_t *)&_socket_address, sizeof(_socket_address));

                if ((status == PAL_ERR_SOCKET_IN_PROGRES) || (status == PAL_ERR_SOCKET_WOULD_BLOCK)) {
                    // In this case the connect is done asynchronously, and the pal_socketMiniSelect()
                    // will be used to detect the end of connect.
                    tr_debug("M2MConnectionHandlerPimpl::socket_connect_handler - pal_connect(): %" PRIx32 ", async connect started", status);
                    // we need to wait for the event
                    _socket_state = ESocketStateConnecting;
                    break;

                } else if (status == PAL_SUCCESS || status == PAL_ERR_SOCKET_ALREADY_CONNECTED) {

                    tr_debug("M2MConnectionHandlerPimpl::socket_connect_handler - pal_connect(): success");
                    _socket_state = ESocketStateConnected;

                } else {
                    tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - pal_connect(): failed: %" PRIx32, status);
                    close_socket();
                    _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
                    return;
                }
#else
                tr_error("socket_connect_handler() - TCP not configured"
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
            } else {
                tr_info("M2MConnectionHandlerPimpl::socket_connect_handler - Using UDP");
                _socket_state = ESocketStateConnected;
            }

        // fall through is a normal flow in case the UDP was used or pal_connect() happened to return immediately with PAL_SUCCESS
        case ESocketStateConnected:
            if (_security && security_instance_id >= 0) {
                if (_secure_connection) {
                    if (_security_impl != NULL) {
                        _security_impl->reset();
                        int ret_code = _security_impl->init(_security, security_instance_id, _is_server_ping);
                        if (ret_code == M2MConnectionHandler::ERROR_NONE) {
                            ret_code = _security_impl->set_dtls_socket_callback(&socket_event_handler, this);
                        }
                        if (ret_code == M2MConnectionHandler::ERROR_NONE) {
                            // Initiate handshake. Perhaps there could be a separate event type for this?
                            _socket_state = ESocketStateHandshaking;
                            send_event(ESocketCallback);
                        } else {
                            tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - init failed");
                            close_socket();

                            if (ret_code == M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS) {
                                _observer.socket_error(M2MConnectionHandler::FAILED_TO_READ_CREDENTIALS, false);
                            } else if (ret_code == M2MConnectionHandler::SSL_CONNECTION_ERROR) {
                                _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, true);
                            }

                            return;
                        }
                    } else {
                        tr_error("M2MConnectionHandlerPimpl::socket_connect_handler - sec is null");
                        close_socket();
                        _observer.socket_error(M2MConnectionHandler::SSL_CONNECTION_ERROR, true);
                        return;
                    }
                }
            }
            if (_socket_state != ESocketStateHandshaking) {
                _socket_state = ESocketStateUnsecureConnection;
                _observer.address_ready(_address,
                                        _server_type,
                                        _address._port);
            }
            break;

    }
}

bool M2MConnectionHandlerPimpl::send_data(uint8_t *data,
                                          uint16_t data_len,
                                          sn_nsdl_addr_s *address)
{
    if (address == NULL || data == NULL || !data_len || _socket_state < ESocketStateUnsecureConnection) {
        tr_warn("M2MConnectionHandlerPimpl::send_data() - too early");
        return false;
    }

    send_data_queue_s *out_data = (send_data_queue_s *)malloc(sizeof(send_data_queue_s));
    if (!out_data) {
        return false;
    }

    memset(out_data, 0, sizeof(send_data_queue_s));

    uint8_t offset = 0;
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
    if (is_tcp_connection() && !_secure_connection) {
        offset = 4;
    }
#endif

    out_data->data = (uint8_t *)malloc(data_len + offset);
    if (!out_data->data) {
        free(out_data);
        return false;
    }

    // TCP non-secure
    // We need to "shim" the length in front
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
    if (is_tcp_connection() && !_secure_connection) {
        out_data->data[0] = 0;
        out_data->data[1] = 0;
        out_data->data[2] = (data_len >> 8) & 0xff;
        out_data->data[3] = data_len & 0xff;
    }
#endif //PAL_NET_TCP_AND_TLS_SUPPORT

    memcpy(out_data->data + offset, data, data_len);
    out_data->data_len = data_len + offset;

    claim_mutex();
    ns_list_add_to_end(&_linked_list_send_data, out_data);
    release_mutex();

    send_event(ESocketSend);

    return true;
}

void M2MConnectionHandlerPimpl::send_socket_data()
{
    tr_debug("M2MConnectionHandlerPimpl::send_socket_data()");
    int bytes_sent = 0;
    bool success = true;

    send_data_queue_s *out_data = get_item_from_list();
    if (!out_data) {
        return;
    }

    if (!out_data->data || !out_data->data_len || _socket_state < ESocketStateUnsecureConnection) {
        tr_warn("M2MConnectionHandlerPimpl::send_socket_data() - too early");
        add_item_to_list(out_data);
        return;
    }

    // Loop until all the data is sent
    while (out_data->offset < out_data->data_len) {
        // Secure send
        if (_socket_state == ESocketStateSecureConnection) {
            // TODO! Change the send_message API to take bytes_sent as a out param like the pal send API's.
            while ((bytes_sent = _security_impl->send_message(out_data->data + out_data->offset,
                                                              out_data->data_len - out_data->offset)) <= 0) {
                if (bytes_sent == M2MConnectionHandler::CONNECTION_ERROR_WANTS_WRITE) {
                    // Return and wait the next event
                    add_item_to_list(out_data);
                    return;
                }

                if (bytes_sent != M2MConnectionHandler::CONNECTION_ERROR_WANTS_READ) {
                    tr_error("M2MConnectionHandlerPimpl::send_socket_data() - secure, failed %d", bytes_sent);
                    success = false;
                    break;
                }
            }
            if (!success) {
                break;
            }
        }
        // Unsecure send
        else {
            bytes_sent = 0;
            palStatus_t ret;
            if (is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
                ret = pal_send(_socket,
                               out_data->data + out_data->offset,
                               out_data->data_len - out_data->offset,
                               (size_t *)&bytes_sent);
#endif
            } else {
                ret = pal_sendTo(_socket,
                                 out_data->data + out_data->offset,
                                 out_data->data_len - out_data->offset,
                                 (palSocketAddress_t *)&_socket_address,
                                 sizeof(_socket_address),
                                 (size_t *)&bytes_sent);
            }
            if (ret == PAL_ERR_SOCKET_WOULD_BLOCK) {
                // Return and wait next event
                add_item_to_list(out_data);
                return;
            }
            if (ret < 0) {
                tr_error("M2MConnectionHandlerPimpl::send_socket_data() - unsecure failed %" PRIx32, ret);
                success = false;
                break;
            }
        }
        int new_offset = out_data->offset + bytes_sent;
        if (new_offset >= out_data->data_len) {
            break;
        } else {
            out_data->offset += bytes_sent;
        }
    }

    free(out_data->data);
    free(out_data);

    if (!success) {
        if (bytes_sent == M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY) {
            _observer.socket_error(bytes_sent, true);
        } else if (bytes_sent == M2MConnectionHandler::MEMORY_ALLOCATION_FAILED) {
            tr_error("M2MConnectionHandlerPimpl::send_socket_data() - memory allocation failed!");
            _observer.socket_error(bytes_sent, false);
        } else if (bytes_sent == M2MConnectionHandler::SOCKET_SEND_ERROR) {
            tr_error("M2MConnectionHandlerPimpl::send_socket_data() - SOCKET_SEND_ERROR");
            _observer.socket_error(bytes_sent, true);
        }
        close_socket();
    } else {
        _observer.data_sent();
    }
}

bool M2MConnectionHandlerPimpl::start_listening_for_data()
{
    return true;
}

void M2MConnectionHandlerPimpl::stop_listening()
{
    // Do not call close_socket() directly here.
    // This can be called from multiple locations.
    send_event(ESocketClose);
}

void M2MConnectionHandlerPimpl::handle_connection_error(int error)
{
    tr_error("M2MConnectionHandlerPimpl::handle_connection_error - error %d", error);
    _observer.socket_error(error);
}

void M2MConnectionHandlerPimpl::set_platform_network_handler(void *handler)
{
    tr_debug("M2MConnectionHandlerPimpl::set_platform_network_handler");

    palStatus_t status = pal_registerNetworkInterface(handler, &_net_iface);

    if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::set_platform_network_handler - Interface registration failed 0x%" PRIx32, status);
    }
    status = pal_setConnectionStatusCallback(_net_iface, network_status_event, this);
    if (PAL_ERR_NOT_SUPPORTED == status) {
        // On Linux pal_setConnectionStatusCallback will return PAL_ERR_NOT_SUPPORTED
        tr_info("Connection status callback set not supported.");
    } else if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::set_platform_network_handler - Connection status callback set failed 0x%" PRIx32, status);
    }

    tr_debug("M2MConnectionHandlerPimpl::set_platform_network_handler - index = %d", _net_iface);
}

void M2MConnectionHandlerPimpl::receive_handshake_handler()
{
    int return_value;
    tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler()");

    // assert(_socket_state == ESocketStateHandshaking);

    return_value = _security_impl->connect(_base, _is_server_ping);

    if (_is_server_ping && return_value == M2MConnectionHandler::ERROR_NONE) {
        // The callback for server-ping may trigger more than once.
        // Only handle it if CID exists, ignore otherwise.
        if (_security_impl->is_cid_available()) {
            tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler() - Server ping success");
            _observer.data_available(NULL, 0, _address);
        }
        return;
    }

    if (return_value == M2MConnectionHandler::ERROR_NONE) {

        _socket_state = ESocketStateSecureConnection;
        _observer.address_ready(_address,
                                _server_type,
                                _server_port);

    } else if (return_value == M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY ||
               return_value == M2MConnectionHandler::SSL_HANDSHAKE_ERROR   ||
               return_value == M2MConnectionHandler::SOCKET_READ_ERROR     ||
               return_value == M2MConnectionHandler::SOCKET_TIMEOUT        ||
               return_value == M2MConnectionHandler::MEMORY_ALLOCATION_FAILED) {
        tr_error("M2MConnectionHandlerPimpl::receive_handshake_handler() - retcode %d", return_value);
        _observer.socket_error(return_value, true);
        close_socket();
    } else {
        tr_debug("M2MConnectionHandlerPimpl::receive_handshake_handler() - waiting next event");
    }
}

bool M2MConnectionHandlerPimpl::is_handshake_ongoing() const
{
    return (_socket_state == ESocketStateHandshaking);
}

void M2MConnectionHandlerPimpl::receive_handler()
{
    // assert(_socket_state > ESocketStateHandshaking);

    if (_socket_state == ESocketStateSecureConnection) {

        int rcv_size;
        unsigned char recv_buffer[BUFFER_LENGTH];

        // we need to read as much as there is data available as the events may or may not be suppressed
        do {
            tr_debug("M2MConnectionHandlerPimpl::receive_handler()..");
            rcv_size = _security_impl->read(recv_buffer, sizeof(recv_buffer));
            tr_debug("M2MConnectionHandlerPimpl::receive_handler() res: %d", rcv_size);
            if (rcv_size > 0) {
                _observer.data_available((uint8_t *)recv_buffer,
                                         rcv_size, _address);
            } else if (M2MConnectionHandler::SSL_PEER_CLOSE_NOTIFY == rcv_size) {
                // This is common notification for termination of BS.
                tr_info("M2MConnectionHandlerPimpl::receive_handler() - peer close notify!");
                _observer.socket_error(rcv_size, true);
                return;
            } else if (M2MConnectionHandler::MEMORY_ALLOCATION_FAILED == rcv_size) {
                tr_error("M2MConnectionHandlerPimpl::receive_handler() - memory allocation failed!");
                _observer.socket_error(rcv_size, false);
                close_socket();
                return;
            } else if (M2MConnectionHandler::SOCKET_READ_ERROR == rcv_size) {
                tr_error("M2MConnectionHandlerPimpl::receive_handler() - secure SOCKET_READ_ERROR");
                _observer.socket_error(rcv_size, true);
                close_socket();
                return;
            }
        } while (rcv_size > 0 && _socket_state == ESocketStateSecureConnection);

    } else {
        size_t recv;
        palStatus_t status;
        unsigned char recv_buffer[BUFFER_LENGTH];
        do {
            if (is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
                status = pal_recv(_socket, recv_buffer, sizeof(recv_buffer), &recv);
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
            } else {
                status = pal_receiveFrom(_socket, recv_buffer, sizeof(recv_buffer), NULL, NULL, &recv);
            }

            if (status == PAL_ERR_SOCKET_WOULD_BLOCK) {
                return;
            } else if (status != PAL_SUCCESS) {
                tr_error("M2MConnectionHandlerPimpl::receive_handler() - SOCKET_READ_ERROR %" PRIx32, status);
                _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                close_socket();
                return;
            }

            tr_debug("M2MConnectionHandlerPimpl::receive_handler() - data received, len: %zu", recv);

            if (!is_tcp_connection()) { // Observer for UDP plain mode
                _observer.data_available((uint8_t *)recv_buffer, recv, _address);
            } else {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
                if (recv < 4) {
                    tr_error("M2MConnectionHandlerPimpl::receive_handler() - TCP SOCKET_READ_ERROR");
                    _observer.socket_error(M2MConnectionHandler::SOCKET_READ_ERROR, true);
                    close_socket();
                    return;
                }

                //We need to "shim" out the length from the front
                uint32_t len = (recv_buffer[0] << 24 & 0xFF000000) + (recv_buffer[1] << 16 & 0xFF0000);
                len += (recv_buffer[2] << 8 & 0xFF00) + (recv_buffer[3] & 0xFF);
                if (len > 0 && len <= recv - 4) {
                    // Observer for TCP plain mode
                    _observer.data_available(recv_buffer + 4, len, _address);
                }
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
            }
        } while (recv > 0 && _socket_state == ESocketStateUnsecureConnection);
    }
}

void M2MConnectionHandlerPimpl::claim_mutex()
{
    eventOS_scheduler_mutex_wait();
}

void M2MConnectionHandlerPimpl::release_mutex()
{
    eventOS_scheduler_mutex_release();
}

bool M2MConnectionHandlerPimpl::init_socket()
{
    palSocketType_t socket_type = PAL_SOCK_DGRAM;
    palStatus_t status;
    palSocketAddress_t bind_address;
    palIpV4Addr_t interface_address4;
    palIpV6Addr_t interface_address6;

    memset(&bind_address, 0, sizeof(palSocketAddress_t));
    memset(&interface_address4, 0, sizeof(interface_address4));
    memset(&interface_address6, 0, sizeof(interface_address6));

    if (is_tcp_connection()) {
#ifdef PAL_NET_TCP_AND_TLS_SUPPORT
        socket_type = PAL_SOCK_STREAM;
#else
        // Somebody has built code without TCP support but tries to use it.
        // Perhaps a "assert(false)" would be sufficient.
        tr_error("M2MConnectionHandlerPimpl::init_socket() - TCP config error");
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return;
#endif //PAL_NET_TCP_AND_TLS_SUPPORT
    }
    status = pal_asynchronousSocketWithArgument((palSocketDomain_t)_socket_address.addressType,
                                                socket_type, true, _net_iface, &socket_event_handler,
                                                this, &_socket);

    if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::init_socket() - socket create error : %" PRIx32, status);
        _observer.socket_error(M2MConnectionHandler::SOCKET_ABORT);
        return false;
    }

    if (_socket_address.addressType == PAL_AF_INET) {
        status = pal_setSockAddrIPV4Addr(&bind_address, interface_address4);
    } else if (_socket_address.addressType == PAL_AF_INET6) {
        status = pal_setSockAddrIPV6Addr(&bind_address, interface_address6);
    } else {
        tr_warn("M2MConnectionHandlerPimpl::init_socket() - stack type: %d", (int)_socket_address.addressType);
    }
    if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::init_socket - setSockAddrIPV err: %" PRIx32, status);
        return false;
    }
    status = pal_setSockAddrPort(&bind_address, _listen_port);
    if (PAL_SUCCESS != status) {
        tr_error("M2MConnectionHandlerPimpl::init_socket - setSockAddrPort err: %" PRIx32, status);
        return false;
    }
    pal_bind(_socket, &bind_address, sizeof(bind_address));

    if (_secure_connection) {
        _security_impl->set_socket(_socket, (palSocketAddress_t *)&_socket_address);
    }
    return true;
}

bool M2MConnectionHandlerPimpl::is_tcp_connection() const
{
    return (_binding_mode == M2MInterface::TCP ||
            _binding_mode == M2MInterface::TCP_QUEUE);
}

void M2MConnectionHandlerPimpl::close_socket()
{
    _event.data.event_data = false;

    if (_socket) {
        // At least on mbed-os the pal_close() will perform callbacks even during it
        // is called, which we will ignore when this state is set.
        _socket_state = ESocketStateCloseBeingCalled;
        pal_close(&_socket);
        tr_info("M2MConnectionHandlerPimpl::close_socket");
        _socket = 0;
    }

    // make sure the socket connection statemachine is reset too.
    _socket_state = ESocketStateDisconnected;

    if (_security_impl) {
        _security_impl->reset();
    }

    claim_mutex();
    /*ns_list_foreach_safe(M2MConnectionHandlerPimpl::send_data_queue_s, tmp, &_linked_list_send_data) {
        ns_list_remove(&_linked_list_send_data, tmp);
        free(tmp->data);
        free(tmp);
    }*/
    // Workaround for IAR compilation issue. ns_list_foreach does not compile with IAR.
    // Error[Pe144]: a value of type "void *" cannot be used to initialize an entity of type "M2MConnectionHandlerPimpl::send_data_queue *"
    while (!ns_list_is_empty(&_linked_list_send_data)) {
        send_data_queue_s *data = (send_data_queue_s *)ns_list_get_first(&_linked_list_send_data);
        ns_list_remove(&_linked_list_send_data, data);
        free(data->data);
        free(data);
    }
    release_mutex();
}

M2MConnectionHandlerPimpl::send_data_queue_s *M2MConnectionHandlerPimpl::get_item_from_list()
{
    claim_mutex();
    send_data_queue_s *out_data = (send_data_queue_s *)ns_list_get_first(&_linked_list_send_data);
    if (out_data) {
        ns_list_remove(&_linked_list_send_data, out_data);
    }
    release_mutex();
    return out_data;
}

void M2MConnectionHandlerPimpl::add_item_to_list(M2MConnectionHandlerPimpl::send_data_queue_s *data)
{
    claim_mutex();
    ns_list_add_to_start(&_linked_list_send_data, data);
    release_mutex();
}

void M2MConnectionHandlerPimpl::force_close()
{
    close_socket();
}

void M2MConnectionHandlerPimpl::unregister_network_handler()
{
    pal_unregisterNetworkInterface(_net_iface);
}

void M2MConnectionHandlerPimpl::store_cid()
{
    _security_impl->store_cid();
}

void M2MConnectionHandlerPimpl::remove_cid()
{
    _security_impl->remove_cid();
}

bool M2MConnectionHandlerPimpl::is_cid_available()
{
    return _security_impl->is_cid_available();
}

void M2MConnectionHandlerPimpl::set_cid_value(const uint8_t *data_ptr, const size_t data_len)
{
    _security_impl->set_cid_value(data_ptr, data_len);
}

void M2MConnectionHandlerPimpl::interface_event(palNetworkStatus_t status)
{
    if (!_event.data.event_data) {
        _event.data.event_data = true;
        if (status == PAL_NETWORK_STATUS_CONNECTED) {
            _event.data.event_type = M2MConnectionHandlerPimpl::EInterfaceConnected;
        } else {
            _event.data.event_type = M2MConnectionHandlerPimpl::EInterfaceDisconnected;
        }

        eventOS_event_send_user_allocated(&_event);
    }
}

void M2MConnectionHandlerPimpl::initialize_event(arm_event_storage_t *event)
{
    event->data.data_ptr = this;
    event->data.event_data = 0;
    event->data.event_id = 0;
    event->data.sender = 0;
    event->data.event_type = 0;
    event->data.priority = ARM_LIB_HIGH_PRIORITY_EVENT;
    event->data.receiver = M2MConnectionHandlerPimpl::_tasklet_id;
    event->allocator = arm_event_storage::ARM_LIB_EVENT_STARTUP_POOL;
    event->state = arm_event_storage::ARM_LIB_EVENT_UNQUEUED;
    event->link.next = NULL;
    event->link.prev = NULL;
}
#if (PAL_DNS_API_VERSION == 2)
void M2MConnectionHandlerPimpl::stop_dns_fallback_timer()
{
    _dns_fallback_timer->stop_timer();
}

void M2MConnectionHandlerPimpl::timer_expired(M2MTimerObserver::Type type)
{
    switch (type) {
        case M2MTimerObserver::DnsQueryFallback:
            tr_warn("DNS Query Fallback timer expired!");
            if (_handler_async_DNS > 0) {
                pal_cancelAddressInfoAsync(_handler_async_DNS);
            }
            send_event(ESocketDnsError);
            break;
        default:
            break;
    }
}
#endif
