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

// Needed for PRIu64 on FreeRTOS
#include <stdio.h>
// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "include/nsdlaccesshelper.h"
#include "include/m2mnsdlobserver.h"
#include "include/m2mtlvdeserializer.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mnsdlinterface.h"
#include "include/m2mreporthandler.h"
#include "mbed-client/m2mstring.h"
#include "mbed-client/m2msecurity.h"
#include "mbed-client/m2mserver.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mblockmessage.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-trace/mbed_trace.h"
#include "sn_grs.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mdevice.h"
#include "randLIB.h"
#include "common_functions.h"
#include "sn_nsdl_lib.h"
#include "sn_coap_protocol.h"
#include "m2mnotificationhandler.h"
#include "eventOS_event_timer.h"
#include "eventOS_scheduler.h"
#include "ns_hal_init.h"

#define MBED_CLIENT_NSDLINTERFACE_TASKLET_INIT_EVENT 0 // Tasklet init occurs always when generating a tasklet
#define MBED_CLIENT_NSDLINTERFACE_EVENT 30
#define MBED_CLIENT_NSDLINTERFACE_BS_EVENT 31

#ifdef MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE
#define MBED_CLIENT_EVENT_LOOP_SIZE MBED_CONF_MBED_CLIENT_EVENT_LOOP_SIZE
#else
#define MBED_CLIENT_EVENT_LOOP_SIZE 1024
#endif


#define BUFFER_SIZE 21
#define TRACE_GROUP "mClt"
#define MAX_QUERY_COUNT 10

const char *MCC_VERSION = "mccv=1.3.3";

int8_t M2MNsdlInterface::_tasklet_id = -1;

extern "C" void nsdlinterface_tasklet_func(arm_event_s *event)
{
    // skip the init event as there will be a timer event after
    if (event->event_type == MBED_CLIENT_NSDLINTERFACE_EVENT) {
        eventOS_scheduler_mutex_wait();
        M2MNsdlInterface::nsdl_coap_data_s *coap_data = (M2MNsdlInterface::nsdl_coap_data_s*)event->data_ptr;
        M2MNsdlInterface *interface = (M2MNsdlInterface*)sn_nsdl_get_context(coap_data->nsdl_handle);
        if (interface) {
            interface->resource_callback_handle_event(coap_data->received_coap_header, &coap_data->address);
            if (coap_data->received_coap_header->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED &&
                coap_data->received_coap_header->payload_ptr) {
                coap_data->nsdl_handle->grs->sn_grs_free(coap_data->received_coap_header->payload_ptr);
                coap_data->received_coap_header->payload_ptr = 0;
            }
        }

        M2MNsdlInterface::memory_free(coap_data->received_coap_header->payload_ptr);
        sn_coap_parser_release_allocated_coap_msg_mem(coap_data->nsdl_handle->grs->coap, coap_data->received_coap_header);
        M2MNsdlInterface::memory_free(coap_data->address.addr_ptr);
        M2MNsdlInterface::memory_free(coap_data);
        eventOS_scheduler_mutex_release();

    } else if (event->event_type == MBED_CLIENT_NSDLINTERFACE_BS_EVENT) {
        M2MNsdlInterface::nsdl_coap_data_s *coap_data = (M2MNsdlInterface::nsdl_coap_data_s*)event->data_ptr;
        M2MNsdlInterface *interface = (M2MNsdlInterface*)sn_nsdl_get_context(coap_data->nsdl_handle);

        sn_coap_hdr_s *coap_response = sn_nsdl_build_response(coap_data->nsdl_handle,
                                                              coap_data->received_coap_header,
                                                              coap_data->received_coap_header->msg_code);
        if (coap_response) {
            coap_response->msg_type = coap_data->received_coap_header->msg_type;

            if (sn_nsdl_send_coap_message(coap_data->nsdl_handle, &coap_data->address, coap_response) == 0) {
                interface->store_bs_finished_response_id(coap_response->msg_id);
            } else {
                tr_error("Failed to send final response for BS finished");
            }

            sn_coap_parser_release_allocated_coap_msg_mem(coap_data->nsdl_handle->grs->coap, coap_response);

        } else {
            tr_error("Failed to create final response message for BS finished");
        }

        // Release the memory
        M2MNsdlInterface::memory_free(coap_data->received_coap_header->payload_ptr);
        sn_coap_parser_release_allocated_coap_msg_mem(coap_data->nsdl_handle->grs->coap, coap_data->received_coap_header);
        M2MNsdlInterface::memory_free(coap_data->address.addr_ptr);
        M2MNsdlInterface::memory_free(coap_data);
    }
}

M2MNsdlInterface::M2MNsdlInterface(M2MNsdlObserver &observer, M2MConnectionHandler &connection_handler)
: _observer(observer),
  _endpoint(NULL),
  _nsdl_handle(NULL),
  _security(NULL),
  _server(NULL),
  _nsdl_execution_timer(*this),
  _registration_timer(*this),
  _connection_handler(connection_handler),
  _counter_for_nsdl(0),
  _next_coap_ping_send_time(0),
  _bootstrap_id(0),
  _server_address(NULL),
  _unregister_ongoing(false),
  _identity_accepted(false),
  _nsdl_execution_timer_running(false),
  _binding_mode(M2MInterface::NOT_SET),
  _custom_uri_query_params(NULL),
  _notification_handler(new M2MNotificationHandler()),
  _notification_send_ongoing(false),
  _registered(false)
{
    tr_debug("M2MNsdlInterface::M2MNsdlInterface()");
    _sn_nsdl_address.addr_len = 0;
    _sn_nsdl_address.addr_ptr = NULL;
    _sn_nsdl_address.port = 0;
    _sn_nsdl_address.type = SN_NSDL_ADDRESS_TYPE_NONE;

    _event.data.data_ptr = NULL;
    _event.data.event_data = 0;
    _event.data.event_id = 0;
    _event.data.sender = 0;
    _event.data.event_type = 0;
    _event.data.priority = ARM_LIB_MED_PRIORITY_EVENT;

    _server = new M2MServer();

    // This initializes libCoap and libNsdl
    // Parameters are function pointers to used memory allocation
    // and free functions in structure and used functions for sending
    // and receiving purposes.
    _nsdl_handle = sn_nsdl_init(&(__nsdl_c_send_to_server), &(__nsdl_c_received_from_server),
                 &(__nsdl_c_memory_alloc), &(__nsdl_c_memory_free), &(__nsdl_c_auto_obs_token));

    sn_nsdl_set_context(_nsdl_handle, this);

    ns_hal_init(NULL, MBED_CLIENT_EVENT_LOOP_SIZE, NULL, NULL);
    eventOS_scheduler_mutex_wait();
    if (M2MNsdlInterface::_tasklet_id < 0) {
        M2MNsdlInterface::_tasklet_id = eventOS_event_handler_create(nsdlinterface_tasklet_func, MBED_CLIENT_NSDLINTERFACE_TASKLET_INIT_EVENT);
        assert(M2MNsdlInterface::_tasklet_id >= 0);
    }
    eventOS_scheduler_mutex_release();

    _event.data.receiver = M2MNsdlInterface::_tasklet_id;

    // Randomize the initial auto obs token. Range is in 1 - 1023
    _auto_obs_token = randLIB_get_random_in_range(AUTO_OBS_TOKEN_MIN, AUTO_OBS_TOKEN_MAX);

    initialize();
}

M2MNsdlInterface::~M2MNsdlInterface()
{
    tr_debug("M2MNsdlInterface::~M2MNsdlInterface() - IN");
    if (_endpoint) {
         memory_free(_endpoint->endpoint_name_ptr);
         memory_free(_endpoint->domain_name_ptr);
         memory_free(_endpoint->type_ptr);
         memory_free(_endpoint->lifetime_ptr);
         memory_free(_endpoint);
    }

    delete _notification_handler;
    _base_list.clear();
    _security = NULL;
    delete _server;
    sn_nsdl_destroy(_nsdl_handle);
    _nsdl_handle = NULL;
    memory_free(_server_address);
    free_get_request_list();
    memory_free(_custom_uri_query_params);
    tr_debug("M2MNsdlInterface::~M2MNsdlInterface() - OUT");
}

bool M2MNsdlInterface::initialize()
{
    tr_debug("M2MNsdlInterface::initialize()");
    bool success = false;

    // Sets the packet retransmission attempts and time interval
    sn_nsdl_set_retransmission_parameters(_nsdl_handle,
                                          MBED_CLIENT_RECONNECTION_COUNT,
                                          MBED_CLIENT_RECONNECTION_INTERVAL);

    sn_nsdl_handle_block2_response_internally(_nsdl_handle, false);

    // Allocate the memory for endpoint
    _endpoint = (sn_nsdl_ep_parameters_s*)memory_alloc(sizeof(sn_nsdl_ep_parameters_s));
    if (_endpoint) {
        memset(_endpoint, 0, sizeof(sn_nsdl_ep_parameters_s));
        success = true;
    }

    M2MResource* update_trigger = _server->get_resource(M2MServer::RegistrationUpdate);
    if (update_trigger) {
        update_trigger->set_execute_function(execute_callback(this,
                                                              &M2MNsdlInterface::update_trigger_callback));
    }

    add_object_to_list(_server);
    create_nsdl_object_structure(_server);
    ns_list_init(&_get_request_list);

    return success;
}

void M2MNsdlInterface::create_endpoint(const String &name,
                                       const String &type,
                                       const int32_t life_time,
                                       const String &domain,
                                       const uint8_t mode,
                                       const String &/*context_address*/)
{
    tr_info("M2MNsdlInterface::create_endpoint( name %s type %s lifetime %" PRId32 ", domain %s, mode %d)",
              name.c_str(), type.c_str(), life_time, domain.c_str(), mode);
    _endpoint_name = name;
    _binding_mode = mode;

    calculate_new_coap_ping_send_time();

    if (_endpoint){
        memset(_endpoint, 0, sizeof(sn_nsdl_ep_parameters_s));
        if (!_endpoint_name.empty()) {
            memory_free(_endpoint->endpoint_name_ptr);
            _endpoint->endpoint_name_ptr = alloc_string_copy((uint8_t*)_endpoint_name.c_str(), _endpoint_name.length());
            _endpoint->endpoint_name_len = _endpoint_name.length();
        }
        if (!type.empty()) {
            _endpoint->type_ptr = alloc_string_copy((uint8_t*)type.c_str(), type.length());
            _endpoint->type_len =  type.length();
        }
        if (!domain.empty()) {
            _endpoint->domain_name_ptr = alloc_string_copy((uint8_t*)domain.c_str(), domain.length());
            _endpoint->domain_name_len = domain.length();
        }

        // nsdl binding mode is only 3 least significant bits
        _endpoint->binding_and_mode = (sn_nsdl_oma_binding_and_mode_t)((uint8_t)mode & 0x07);

        // If lifetime is less than zero then leave the field empty
        if (life_time > 0) {
            set_endpoint_lifetime_buffer(life_time);
        }
    }
}

void M2MNsdlInterface::update_endpoint(const String &name)
{
    _endpoint_name = name;
    if (_endpoint){
        if (!_endpoint_name.empty()) {
            memory_free(_endpoint->endpoint_name_ptr);
            _endpoint->endpoint_name_ptr = alloc_string_copy((uint8_t*)_endpoint_name.c_str(), _endpoint_name.length());
            _endpoint->endpoint_name_len = _endpoint_name.length();
        }
    }
}

void M2MNsdlInterface::update_domain(const String &domain)
{
    if (_endpoint){
        memory_free(_endpoint->domain_name_ptr);
        _endpoint->domain_name_len = 0;
        if (!domain.empty()) {
            _endpoint->domain_name_ptr = alloc_string_copy((uint8_t*)domain.c_str(), domain.length());
            _endpoint->domain_name_len = domain.length();
        }
    }
}

void M2MNsdlInterface::set_endpoint_lifetime_buffer(int lifetime)
{
    tr_debug("M2MNsdlInterface::set_endpoint_lifetime_buffer - %d", lifetime);
    if (lifetime < 60) {
        return;
    }

    _server->set_resource_value(M2MServer::Lifetime, lifetime);

    if (_endpoint && _endpoint->lifetime_ptr) {
        memory_free(_endpoint->lifetime_ptr);
        _endpoint->lifetime_ptr = NULL;
        _endpoint->lifetime_len = 0;
    }

    char buffer[20+1];
    uint32_t size = m2m::itoa_c(lifetime, buffer);
    if (_endpoint && size <= sizeof(buffer)) {
        _endpoint->lifetime_len = 0;
        _endpoint->lifetime_ptr = alloc_string_copy((uint8_t*)buffer, size);
        if (_endpoint->lifetime_ptr) {
            _endpoint->lifetime_len = size;
        }
    }
}


void M2MNsdlInterface::delete_endpoint()
{
    tr_debug("M2MNsdlInterface::delete_endpoint()");
    if (_endpoint) {
        free(_endpoint->lifetime_ptr);
        memory_free(_endpoint);
        _endpoint = NULL;
    }
}

bool M2MNsdlInterface::create_nsdl_list_structure(const M2MBaseList &list)
{
    tr_debug("M2MNsdlInterface::create_nsdl_list_structure()");
    bool success = false;
    if(!list.empty()) {
       tr_debug("M2MNsdlInterface::create_nsdl_list_structure - Object count is %d", list.size());
        M2MBaseList::const_iterator it;
        it = list.begin();
        for ( ; it != list.end(); it++ ) {
            // Create NSDL structure for all Objects inside
            success = create_nsdl_structure(*it);
            tr_debug("M2MNsdlInterface::create_nsdl_list_structure - create %d", success);
            add_object_to_list(*it);
        }
    }
    if (!success) {
        tr_error("M2MNsdlInterface::create_nsdl_list_structure - fail!");
    }
    return success;
}

bool M2MNsdlInterface::remove_nsdl_resource(M2MBase *base)
{
    sn_nsdl_dynamic_resource_parameters_s* resource = base->get_nsdl_resource();
    return sn_nsdl_pop_resource(_nsdl_handle, resource);
}

bool M2MNsdlInterface::create_bootstrap_resource(sn_nsdl_addr_s *address)
{
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    tr_debug("M2MNsdlInterface::create_bootstrap_resource()");
    _identity_accepted = false;
    bool success = false;
    sn_nsdl_bs_ep_info_t bootstrap_endpoint;
    tr_debug("M2MNsdlInterface::create_bootstrap_resource() - endpoint name: %.*s", _endpoint->endpoint_name_len,
             _endpoint->endpoint_name_ptr);

    if (_bootstrap_id == 0) {
        // Take copy of the address, uri_query_parameters() will modify the source buffer
        bool msg_sent = false;
        if (_server_address) {
            char *address_copy = M2MBase::alloc_string_copy(_server_address);
            if (address_copy) {
                char* query = parse_uri_query_parameters(_server_address);
                if (query != NULL) {
                    size_t query_len = 1 + strlen(query) + 1 + strlen(MCC_VERSION) + 1;
                    if (query_len <= MAX_URI_QUERY_LEN) {
                        char query_params[MAX_URI_QUERY_LEN];
                        strcpy(query_params, "&");
                        strcat(query_params, query);
                        strcat(query_params, "&");
                        strcat(query_params, MCC_VERSION);
                        msg_sent = true;
                        sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
                        _bootstrap_id = sn_nsdl_oma_bootstrap(_nsdl_handle,
                                                              address,
                                                              _endpoint,
                                                              &bootstrap_endpoint,
                                                              query_params);
                        free(_server_address);
                        _server_address = M2MBase::alloc_string_copy(address_copy);
                    } else {
                        tr_error("M2MNsdlInterface::create_bootstrap_resource() - max uri param length reached (%lu)",
                                  (unsigned long)query_len);
                    }
                }
                free(address_copy);
            }
        }
        if (!msg_sent) {
            sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
            _bootstrap_id = sn_nsdl_oma_bootstrap(_nsdl_handle,
                                                  address,
                                                  _endpoint,
                                                  &bootstrap_endpoint,
                                                  NULL);
        }
        success = _bootstrap_id != 0;
        tr_debug("M2MNsdlInterface::create_bootstrap_resource - _bootstrap_id %d", _bootstrap_id);
    }
    return success;
#else
    (void)address;
    (void)bootstrap_endpoint_name;
    return false;
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
}

void M2MNsdlInterface::set_server_address(uint8_t* address,
                                          uint8_t address_length,
                                          const uint16_t port,
                                          sn_nsdl_addr_type_e address_type)
{
    tr_debug("M2MNsdlInterface::set_server_address()");
    set_NSP_address(_nsdl_handle, address, address_length, port, address_type);
}

bool M2MNsdlInterface::send_register_message()
{
    tr_info("M2MNsdlInterface::send_register_message()");
    bool success = false;
    if (_server_address) {
        success = parse_and_send_uri_query_parameters();
    }
    // If URI parsing fails or there is no parameters, try again without parameters
    if (!success) {
        sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
        success = sn_nsdl_register_endpoint(_nsdl_handle,_endpoint, NULL) != 0;
    }
    return success;
}

bool M2MNsdlInterface::send_get_data_request(const char *uri,
                                             const size_t offset,
                                             const bool async,
                                             get_data_cb data_cb,
                                             get_data_error_cb error_cb,
                                             void *context)
{
    int32_t message_id = 0;
    uint32_t token = 0;
    get_data_request_s *data_request = (get_data_request_s*)memory_alloc(sizeof(get_data_request_s));
    if (data_request == NULL) {
        return false;
    }
    data_request->context = context;
    data_request->async_req = async;
    data_request->received_size = offset;
    data_request->uri_path = (char*)alloc_string_copy((uint8_t*)uri, strlen(uri));
    if (data_request->uri_path == NULL) {
        memory_free(data_request);
        return false;
    }

    data_request->on_get_data_cb = data_cb;
    data_request->on_get_data_error_cb = error_cb;

    randLIB_get_n_bytes_random(&token, sizeof(token));

    if (!token) {
        token++;
    }

    data_request->msg_token = token;

    message_id = sn_nsdl_send_get_data_request(_nsdl_handle, uri, token, offset);
    if (message_id == 0) {
        memory_free(data_request->uri_path);
        memory_free(data_request);
        return false;
    }

    ns_list_add_to_end(&_get_request_list, data_request);

    return true;
}

bool M2MNsdlInterface::send_update_registration(const uint32_t lifetime, bool clear_queue)
{
    tr_info("M2MNsdlInterface::send_update_registration( lifetime %" PRIu32 ")", lifetime);
    bool success = false;
    int32_t ret = 0;

    _registration_timer.stop_timer();
    bool lifetime_changed = true;

    // Check if resource(1/0/1) value has been updated and update it into _endpoint struct
    if (lifetime == 0) {
        lifetime_changed = lifetime_value_changed();
        if (lifetime_changed) {
            set_endpoint_lifetime_buffer(_server->resource_value_int(M2MServer::Lifetime));
        }
    } else {
        set_endpoint_lifetime_buffer(lifetime);
    }

    if (_nsdl_handle) {
        if (clear_queue) {
            sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
        }
        if (!lifetime_changed) {
            tr_debug("M2MNsdlInterface::send_update_registration - regular update");
            ret = sn_nsdl_update_registration(_nsdl_handle, NULL, 0);
        } else {
            if (_endpoint && _endpoint->lifetime_ptr) {
                tr_debug("M2MNsdlInterface::send_update_registration - new lifetime value");
                ret = sn_nsdl_update_registration(_nsdl_handle,
                                                      _endpoint->lifetime_ptr,
                                                      _endpoint->lifetime_len);
            }
        }
        if (ret == -4) {
            tr_warn("Failed to send registration update. Clearing queue and retrying.");
            sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
            if (!lifetime_changed) {
                tr_debug("M2MNsdlInterface::send_update_registration - regular update - retry");
                ret = sn_nsdl_update_registration(_nsdl_handle, NULL, 0);
            } else {
                tr_debug("M2MNsdlInterface::send_update_registration - new lifetime value - retry");
                ret = sn_nsdl_update_registration(_nsdl_handle,
                                                      _endpoint->lifetime_ptr,
                                                      _endpoint->lifetime_len);
            }
        }
    }
    if (ret >= 0) {
        success = true;
    }

    _registration_timer.start_timer(registration_time() * 1000,
                                     M2MTimerObserver::Registration,
                                     false);

    return success;
}

bool M2MNsdlInterface::send_unregister_message()
{
    tr_info("M2MNsdlInterface::send_unregister_message");
    if (_unregister_ongoing) {
        tr_debug("M2MNsdlInterface::send_unregister_message - unregistration already in progress");
        return true;
    }

    bool success = false;
    int32_t ret = 0;

    _unregister_ongoing = true;
    ret = sn_nsdl_unregister_endpoint(_nsdl_handle);
    if (ret == -4) {
        tr_warn("Failed to send registration update. Clearing queue and retrying.");
        sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
        ret = sn_nsdl_unregister_endpoint(_nsdl_handle);
    }
    if (ret >= 0) {
        success = true;
    }
    return success;
}

// XXX: move these to common place, no need to copy these wrappers to multiple places:
void *M2MNsdlInterface::memory_alloc(uint32_t size)
{
    if(size)
        return malloc(size);
    else
        return 0;
}

void M2MNsdlInterface::memory_free(void *ptr)
{
    if(ptr)
        free(ptr);
}

uint8_t* M2MNsdlInterface::alloc_string_copy(const uint8_t* source, uint16_t size)
{
    assert(source != NULL);

    uint8_t* result = (uint8_t*)memory_alloc(size + 1);
    if (result) {
        memcpy(result, source, size);
        result[size] = '\0';
    }
    return result;
}

uint8_t M2MNsdlInterface::send_to_server_callback(struct nsdl_s * /*nsdl_handle*/,
                                                  sn_nsdl_capab_e /*protocol*/,
                                                  uint8_t *data_ptr,
                                                  uint16_t data_len,
                                                  sn_nsdl_addr_s *address)
{
    tr_debug("M2MNsdlInterface::send_to_server_callback(data size %d)", data_len);
    _observer.coap_message_ready(data_ptr,data_len,address);
    return 1;
}

uint8_t M2MNsdlInterface::received_from_server_callback(struct nsdl_s *nsdl_handle,
                                                        sn_coap_hdr_s *coap_header,
                                                        sn_nsdl_addr_s *address)
{
    tr_debug("M2MNsdlInterface::received_from_server_callback");
    _observer.coap_data_processed();
    uint8_t value = 0;
    get_data_request_s get_data_req;
    if(nsdl_handle && coap_header) {
        bool is_bootstrap_msg = address && (nsdl_handle->oma_bs_address_len == address->addr_len) &&
                                   (nsdl_handle->oma_bs_port == address->port) &&
                                   !memcmp(nsdl_handle->oma_bs_address_ptr, address->addr_ptr, nsdl_handle->oma_bs_address_len);

        if (coap_header->token_len == sizeof(nsdl_handle->register_token) &&
            memcmp(coap_header->token_ptr, &nsdl_handle->register_token, sizeof(nsdl_handle->register_token)) == 0) {

            handle_register_response(coap_header);

        } else if (coap_header->token_len == sizeof(nsdl_handle->unregister_token) &&
                   memcmp(coap_header->token_ptr,
                          &nsdl_handle->unregister_token,
                          sizeof(nsdl_handle->unregister_token)) == 0) {

            handle_unregister_response(coap_header);

        } else if (coap_header->token_len == sizeof(nsdl_handle->update_register_token) &&
                   memcmp(coap_header->token_ptr,
                          &nsdl_handle->update_register_token,
                          sizeof(nsdl_handle->update_register_token)) == 0) {

            handle_register_update_response(coap_header);

        } else if (coap_header->token_ptr && is_response_to_get_req(coap_header, get_data_req)) {

            handle_get_response(coap_header, &get_data_req);

        }
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        else if (coap_header->token_len == sizeof(nsdl_handle->bootstrap_token) &&
                 memcmp(coap_header->token_ptr, &nsdl_handle->bootstrap_token, sizeof(nsdl_handle->bootstrap_token)) == 0) {

            handle_bootstrap_response(coap_header);

        }
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        else {

            sn_coap_hdr_s *coap_response = NULL;
            bool execute_value_updated = false;
            M2MObjectInstance *obj_instance = NULL;

            if (COAP_MSG_CODE_REQUEST_PUT == coap_header->msg_code) {
                if (is_bootstrap_msg) {
                    handle_bootstrap_put_message(coap_header, address);
                } else {
                    tr_debug("M2MNsdlInterface::received_from_server_callback - Method not allowed (PUT).");
                    coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                           coap_header,
                                                           COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
                }
            }
            else if (COAP_MSG_CODE_REQUEST_DELETE == coap_header->msg_code) {
                if (is_bootstrap_msg) {
                    handle_bootstrap_delete(coap_header, address);
                } else {
                    tr_debug("M2MNsdlInterface::received_from_server_callback - Method not allowed (DELETE).");
                    coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                           coap_header,
                                                           COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED);
                }
            } else if (COAP_MSG_CODE_REQUEST_POST == coap_header->msg_code) {

                execute_value_updated = handle_post_response(coap_header,
                                                             address,
                                                             coap_response,
                                                             obj_instance,
                                                             is_bootstrap_msg);

            } else if (COAP_STATUS_BUILDER_BLOCK_SENDING_DONE == coap_header->coap_status &&
                       coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT) {

                M2MBase *base = find_resource("", coap_header->msg_id);
                if (base) {
                    handle_notification_delivered(base);
                }

            } else if (COAP_MSG_CODE_EMPTY == coap_header->msg_code) {

                handle_empty_ack(coap_header, is_bootstrap_msg);

            // Retransmission done
            } else if (COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED == coap_header->coap_status) {

                tr_info("M2MNsdlInterface::received_from_server_callback - message sending failed, id %d", coap_header->msg_id);

                // Report notification status back to application
                M2MBase *base = find_resource("", coap_header->msg_id);
                if (base) {
                    base->send_notification_delivery_status(*base, NOTIFICATION_STATUS_SEND_FAILED);
                }

                _observer.registration_error(M2MInterface::NetworkError, true);

            // Handle Server-side expections during registration flow
            // Client might receive error from server due to temporary connection/operability reasons,
            // server might not recover the flow in this case, so it is better for Client to restart registration.
            } else if (nsdl_handle->register_token &&
                       ((coap_header->msg_code == COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR) ||
                       (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_BAD_GATEWAY) ||
                       (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE) ||
                       (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT))) {

                tr_error("M2MNsdlInterface::received_from_server_callback - registration error %d", coap_header->msg_code);
                tr_error("M2MNsdlInterface::received_from_server_callback - unexpected error received from server");
                // Try to do clean register again
                _observer.registration_error(M2MInterface::NetworkError, true);

            } else {
                // Add warn for any message that gets this far. We might be missing some handling in above.
                tr_warn("M2MNsdlInterface::received_from_server_callback - msg was ignored %d", coap_header->msg_code);
            }

            // Send response to server
            if (coap_response) {
                tr_debug("M2MNsdlInterface::received_from_server_callback - send CoAP response");
                (sn_nsdl_send_coap_message(_nsdl_handle, address, coap_response) == 0) ? value = 0 : value = 1;
                sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, coap_response);
            }

            // Tell to application that value has been updated
            if (execute_value_updated) {
                value_updated(obj_instance);
            }

        }
    }
    return value;
}


uint8_t M2MNsdlInterface::resource_callback(struct nsdl_s *nsdl_handle,
                                            sn_coap_hdr_s *received_coap_header,
                                            sn_nsdl_addr_s *address,
                                            sn_nsdl_capab_e /*nsdl_capab*/)
{
    tr_debug("M2MNsdlInterface::resource_callback()");

    assert(received_coap_header);
    _observer.coap_data_processed();

    // Use piggypacked response for any other types than POST
    if (received_coap_header->msg_code != COAP_MSG_CODE_REQUEST_POST) {
        uint8_t status = resource_callback_handle_event(received_coap_header, address);

        if (received_coap_header->coap_status == COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED) {
            memory_free(received_coap_header->payload_ptr);
        }

        sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, received_coap_header);
        return status;
    }

    send_empty_ack(received_coap_header, address);

    nsdl_coap_data_s *nsdl_coap_data = create_coap_event_data(received_coap_header,
                                                              address,
                                                              nsdl_handle,
                                                              received_coap_header->msg_code);
    if (nsdl_coap_data) {
        _event.data.event_type = MBED_CLIENT_NSDLINTERFACE_EVENT;
        _event.data.data_ptr = (void*)nsdl_coap_data;
        eventOS_event_send_user_allocated(&_event);
    } else {
        tr_error("M2MNsdlInterface::resource_callback() - failed to allocate nsdl_coap_data_s!");
    }
    return 0;
}

uint8_t M2MNsdlInterface::resource_callback_handle_event(sn_coap_hdr_s *received_coap_header,
                                                         sn_nsdl_addr_s *address)
{
    tr_debug("M2MNsdlInterface::resource_callback_handle_event");
    uint8_t result = 1;
    uint8_t *payload = NULL;
    bool free_payload = true;
    sn_coap_hdr_s *coap_response = NULL;
    sn_coap_msg_code_e msg_code = COAP_MSG_CODE_RESPONSE_CHANGED; // 4.00
    String resource_name = coap_to_string(received_coap_header->uri_path_ptr,
                                          received_coap_header->uri_path_len);

    bool execute_value_updated = false;
    M2MBase* base = find_resource(resource_name, 0);
    bool subscribed = false;
    if (base) {
        if (COAP_MSG_CODE_REQUEST_GET == received_coap_header->msg_code) {
            coap_response = base->handle_get_request(_nsdl_handle, received_coap_header,this);

            if (coap_response && coap_response->options_list_ptr && coap_response->options_list_ptr->observe != STOP_OBSERVATION) {
                subscribed = true;
            }
        } else if (COAP_MSG_CODE_REQUEST_PUT == received_coap_header->msg_code) {
            coap_response = base->handle_put_request(_nsdl_handle, received_coap_header, this, execute_value_updated);
        } else if (COAP_MSG_CODE_REQUEST_POST == received_coap_header->msg_code) {
            if (base->base_type() == M2MBase::ResourceInstance) {
                msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
            } else {
                coap_response = base->handle_post_request(_nsdl_handle,
                                                          received_coap_header,
                                                          this,
                                                          execute_value_updated,
                                                          address);

                if (base->base_type() == M2MBase::Resource) {
                    M2MResource *res = (M2MResource*) base;
                    if (res->delayed_response()) {
                        tr_debug("M2MNsdlInterface::resource_callback_handle_event - final response sent by application");
                        sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, coap_response);
                        return 0;
                    }
                }

                // Separate response used for POST
                if (coap_response) {
                    coap_response->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
                }
            }
        } else if (COAP_MSG_CODE_REQUEST_DELETE == received_coap_header->msg_code) {
            // Delete the object instance
            M2MBase::BaseType type = base->base_type();
            if(M2MBase::ObjectInstance == type) {
                M2MBase* base_object = find_resource(base->uri_path(), 0);
                if(base_object) {
                    M2MObject &object = ((M2MObjectInstance*)base_object)->get_parent_object();
                    int slash_found = resource_name.find_last_of('/');
                    // Object instance validty checks done in upper level, no need for error handling
                    if (slash_found != -1) {
                        String object_name;
                        object_name = resource_name.substr(slash_found + 1, resource_name.length());
                        if (object.remove_object_instance(strtoul(
                                object_name.c_str(),
                                NULL,
                                10))) {
                            msg_code = COAP_MSG_CODE_RESPONSE_DELETED;
                        }
                    }
                }
            } else {
                msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST; // 4.00
            }
        }
    } else  {
        tr_error("M2MNsdlInterface::resource_callback_handle_event() - Resource NOT FOUND");
        msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST; // 4.00
    }

    if (!coap_response) {
        coap_response = sn_nsdl_build_response(_nsdl_handle,
                                               received_coap_header,
                                               msg_code);
    }

    // This copy will be passed to resource instance
    if (received_coap_header->payload_len > 0 && received_coap_header->payload_ptr) {
        payload = (uint8_t*)memory_alloc(received_coap_header->payload_len);
        if (payload) {
            assert(received_coap_header->payload_ptr);
            memcpy(payload, received_coap_header->payload_ptr, received_coap_header->payload_len);
        }
        else {
            if (coap_response) {
                coap_response->msg_code = COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE;
            }
        }
    }

    if (coap_response &&
        coap_response->coap_status != COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING &&
        coap_response->msg_code != COAP_MSG_CODE_EMPTY) {

        (sn_nsdl_send_coap_message(_nsdl_handle, address, coap_response) == 0) ? result = 0 : result = 1;

        if (coap_response->payload_ptr) {
            free(coap_response->payload_ptr);
            coap_response->payload_ptr = NULL;
        }

        // See if there any pending notification to be sent after resource is subscribed.
        if (subscribed) {
            _notification_handler->send_notification(this);
        }
    }

    // If the external blockwise storing is enabled call value updated only when all blocks have been received
    if (execute_value_updated &&
        coap_response &&
        coap_response->coap_status != COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVING &&
        coap_response->msg_code < COAP_MSG_CODE_RESPONSE_BAD_REQUEST) {
        if ((COAP_MSG_CODE_REQUEST_PUT == received_coap_header->msg_code) &&
            (base->base_type() == M2MBase::Resource ||
             base->base_type() == M2MBase::ResourceInstance)) {
            M2MResourceBase* res = (M2MResourceBase*)base;

            // Clear the old resource value since the data is now passed to application
            if (res->block_message() && res->block_message()->is_block_message()) {
                res->clear_value();
            }
            else {
                // Ownership of payload moved to resource, skip the freeing.
                free_payload = false;
                res->set_value_raw(payload, received_coap_header->payload_len);
            }
        }

        if (coap_response->msg_code != COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE) {
            value_updated(base);
        }
    }

    if (free_payload) {
        free(payload);
    }

    sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, coap_response);

    return result;
}

bool M2MNsdlInterface::process_received_data(uint8_t *data,
                                             uint16_t data_size,
                                             sn_nsdl_addr_s *address)
{
    tr_debug("M2MNsdlInterface::process_received_data(data size %d)", data_size);
    return (0 == sn_nsdl_process_coap(_nsdl_handle,
                                      data,
                                      data_size,
                                      address)) ? true : false;
}

void M2MNsdlInterface::stop_timers()
{
    tr_debug("M2MNsdlInterface::stop_timers()");
    _registration_timer.stop_timer();
    _nsdl_execution_timer.stop_timer();
    _nsdl_execution_timer_running = false;
    _bootstrap_id = 0;
    _unregister_ongoing = false;
}

void M2MNsdlInterface::timer_expired(M2MTimerObserver::Type type)
{
    if(M2MTimerObserver::NsdlExecution == type) {
        sn_nsdl_exec(_nsdl_handle, _counter_for_nsdl);
        _counter_for_nsdl++;
        send_coap_ping();
    } else if((M2MTimerObserver::Registration) == type && (_unregister_ongoing==false)) {
        tr_debug("M2MNsdlInterface::timer_expired - Send update registration");
        if (lifetime_value_changed()) {
            send_update_registration(_server->resource_value_int(M2MServer::Lifetime));
        } else {
            send_update_registration();
        }
    }
}

bool M2MNsdlInterface::observation_to_be_sent(M2MBase *object,
                                              uint16_t obs_number,
                                              const m2m::Vector<uint16_t> &changed_instance_ids,
                                              bool send_object)
{
    claim_mutex();

    if (object && _nsdl_execution_timer_running && _registered) {
        tr_debug("M2MNsdlInterface::observation_to_be_sent() uri %s", object->uri_path());

        if (!_notification_send_ongoing) {
            _notification_send_ongoing = true;
            object->report_handler()->set_notification_in_queue(false);
            M2MBase::BaseType type = object->base_type();

            clear_sent_blockwise_messages();

            if (type == M2MBase::Object) {
                send_object_observation(static_cast<M2MObject*> (object),
                                        obs_number,
                                        changed_instance_ids,
                                        send_object);
            } else if (type == M2MBase::ObjectInstance) {
                send_object_instance_observation(static_cast<M2MObjectInstance*> (object), obs_number);
            } else if (type == M2MBase::Resource) {
                send_resource_observation(static_cast<M2MResource*> (object), obs_number);
            }

            release_mutex();
            return true;
        } else {
            tr_info("M2MNsdlInterface::observation_to_be_sent() - send already in progress");
        }
    } else {
        tr_info("M2MNsdlInterface::observation_to_be_sent() - object NULL, in reconnection mode or not registered");
    }

    release_mutex();

    return false;
}

#ifndef DISABLE_DELAYED_RESPONSE
void M2MNsdlInterface::send_delayed_response(M2MBase *base)
{
    claim_mutex();
    tr_debug("M2MNsdlInterface::send_delayed_response()");
    M2MResource *resource = NULL;
    if(base) {
        if(M2MBase::Resource == base->base_type()) {
            resource = static_cast<M2MResource *> (base);
        }
        if(resource) {
            sn_coap_hdr_s coap_response;

            memset(&coap_response,0,sizeof(sn_coap_hdr_s));

            coap_response.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
            coap_response.msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
            resource->get_delayed_token(coap_response.token_ptr,coap_response.token_len);

            uint32_t length = 0;
            resource->get_value(coap_response.payload_ptr, length);
            coap_response.payload_len = length;

            sn_nsdl_send_coap_message(_nsdl_handle, _nsdl_handle->nsp_address_ptr->omalw_address_ptr, &coap_response);

            free(coap_response.payload_ptr);
            free(coap_response.token_ptr);
        }
    }
    release_mutex();
}
#endif

void M2MNsdlInterface::resource_to_be_deleted(M2MBase *base)
{
    tr_debug("M2MNsdlInterface::resource_to_be_deleted() %p", base);
    claim_mutex();
    remove_nsdl_resource(base);

    // Since the M2MObject's are stored in _base_list, they need to be removed from there also.
    if (base && base->base_type() == M2MBase::Object) {
        remove_object(base);
    }

    release_mutex();
}

void M2MNsdlInterface::value_updated(M2MBase *base)
{
    tr_debug("M2MNsdlInterface::value_updated()");
    String name;
    if(base) {
        switch(base->base_type()) {
            case M2MBase::Object:
                create_nsdl_object_structure(static_cast<M2MObject*> (base));
                name =  base->name();
            break;
            case M2MBase::ObjectInstance:
                create_nsdl_object_instance_structure(static_cast<M2MObjectInstance*> (base));
                name = static_cast<M2MObjectInstance*> (base)->get_parent_object().name();

            break;
            case M2MBase::Resource: {
                M2MResource* resource = static_cast<M2MResource*> (base);
                create_nsdl_resource_structure(resource, resource->supports_multiple_instances());
                name = base->name();
            }
            break;
            case M2MBase::ResourceInstance: {
                M2MResourceInstance* instance = static_cast<M2MResourceInstance*> (base);
                create_nsdl_resource(instance);
                name = static_cast<M2MResourceInstance*> (base)->get_parent_resource().name();
            }
            break;
        }
    }

    if (base && base->is_value_updated_function_set()) {
        base->execute_value_updated(name);
    }
    else {
        _observer.value_updated(base);
    }
}

void M2MNsdlInterface::remove_object(M2MBase *object)
{
    claim_mutex();
    tr_debug("M2MNsdlInterface::remove_object() %p", object);
    M2MObject* rem_object = static_cast<M2MObject*> (object);
    if(rem_object && !_base_list.empty()) {
        M2MBaseList::const_iterator it;
        it = _base_list.begin();
        int index = 0;
        for ( ; it != _base_list.end(); it++, index++ ) {
            if((*it)->base_type() == M2MBase::Object && (*it) == rem_object) {
                _base_list.erase(index);
                break;
            }
        }
    }
    release_mutex();
}

bool M2MNsdlInterface::create_nsdl_structure(M2MBase *base)
{
    tr_debug("M2MNsdlInterface::create_nsdl_structure()");
    bool success = false;
    if(base) {
        switch (base->base_type()) {
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
        case M2MBase::ObjectDirectory:
            success = create_nsdl_endpoint_structure((M2MEndpoint*)base);
            break;
#endif
        case M2MBase::Object:
            success = create_nsdl_object_structure((M2MObject*)base);
            break;
        default:
            break;
        }
    }
    return success;
}

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
bool M2MNsdlInterface::create_nsdl_endpoint_structure(M2MEndpoint *endpoint)
{
    tr_debug("M2MNsdlInterface::create_nsdl_endpoint_structure()");
    bool success = false;
    if(endpoint) {
        success = true;
        if (endpoint->get_changed()) {
            const M2MObjectList &object_list = endpoint->objects();
            tr_debug("M2MNsdlInterface::create_nsdl_endpoint_structure - Object count %d", object_list.size());
            if(!object_list.empty()) {
                M2MObjectList::const_iterator it;
                it = object_list.begin();
                for ( ; it != object_list.end(); it++ ) {
                    // Create NSDL structure for all object instances inside
                    success = create_nsdl_object_structure(*it);
                }
            }
            if (!create_nsdl_resource(endpoint)) {
                success = false;
            }
            endpoint->clear_changed();
        }
    }
    return success;
}
#endif

bool M2MNsdlInterface::create_nsdl_object_structure(M2MObject *object)
{
    bool success = false;
    if(object) {
        const M2MObjectInstanceList &instance_list = object->instances();
        if(!instance_list.empty()) {
           M2MObjectInstanceList::const_iterator it;
           it = instance_list.begin();
           for ( ; it != instance_list.end(); it++ ) {
               // Create NSDL structure for all object instances inside
               success = create_nsdl_object_instance_structure(*it);
           }
        }
    }
    if(object && object->operation() != M2MBase::NOT_ALLOWED) {
        success = create_nsdl_resource(object);
    }

    return success;
}

bool M2MNsdlInterface::create_nsdl_object_instance_structure(M2MObjectInstance *object_instance)
{
    bool success = false;
    if( object_instance) {
        const M2MResourceList &res_list = object_instance->resources();
        if(!res_list.empty()) {
            M2MResourceList::const_iterator it;
            it = res_list.begin();
            for ( ; it != res_list.end(); it++ ) {
                // Create NSDL structure for all resources inside
                success = create_nsdl_resource_structure(*it,
                                                         (*it)->supports_multiple_instances());
            }
        }
        if(object_instance->operation() != M2MBase::NOT_ALLOWED) {
            success = create_nsdl_resource(object_instance);
        }
    }
    return success;
}

bool M2MNsdlInterface::create_nsdl_resource_structure(M2MResource *res,
                                                      bool multiple_instances)
{
    bool success = false;
    if(res) {
        // if there are multiple instances supported
        if(multiple_instances) {
            const M2MResourceInstanceList &res_list = res->resource_instances();
            if(!res_list.empty()) {
                M2MResourceInstanceList::const_iterator it;
                it = res_list.begin();
                for ( ; it != res_list.end(); it++ ) {
                    success = create_nsdl_resource((*it));
                    if(!success) {
                        tr_error("M2MNsdlInterface::create_nsdl_resource_structure - instance creation failed");
                        return false;
                    }
                }
                // Register the main Resource as well along with ResourceInstances
                success = create_nsdl_resource(res);
            }
        } else {
            success = create_nsdl_resource(res);
        }
    }
    return success;
}

bool M2MNsdlInterface::create_nsdl_resource(M2MBase *base)
{
    claim_mutex();
    bool success = false;
    if(base) {
        int8_t result = 0;
        sn_nsdl_dynamic_resource_parameters_s* nsdl_resource = base->get_nsdl_resource();

        // needed on deletion
        if (base->observation_handler() == NULL) {
            base->set_observation_handler(this);
        }

        result = sn_nsdl_put_resource(_nsdl_handle, nsdl_resource);

        // Put under observation if auto-obs feature is set.
        // TODO! What if the observation is set in multiple levels?
        if (nsdl_resource && nsdl_resource->auto_observable && result != SN_GRS_RESOURCE_ALREADY_EXISTS) {
            base->set_under_observation(true, base->observation_handler());

            // Increment auto-obs token to be unique in every object
            _auto_obs_token++;
            if (_auto_obs_token > AUTO_OBS_TOKEN_MAX) {
                _auto_obs_token = 1;
            }

            // Store token in big-endian byte order
            uint8_t token[sizeof(uint16_t)];
            common_write_16_bit(_auto_obs_token, token);
            base->set_observation_token(token, sizeof(uint16_t));

            switch (base->base_type()) {
                case M2MBase::Object:
                    base->add_observation_level(M2MBase::O_Attribute);
                break;

                case M2MBase::ObjectInstance:
                    base->add_observation_level(M2MBase::OI_Attribute);
                break;

                case M2MBase::Resource:
                case M2MBase::ResourceInstance:
                    base->add_observation_level(M2MBase::R_Attribute);
                break;
            }
        }

        // Either the resource is created or it already
        // exists , then result is success.
        if (result == 0 ||
            result == SN_GRS_RESOURCE_ALREADY_EXISTS){
            success = true;
        }
    }
    release_mutex();
    return success;
}

// convenience method to get the URI from its buffer field...
String M2MNsdlInterface::coap_to_string(const uint8_t *coap_data, int coap_data_length)
{
    String value = "";
    if (coap_data != NULL && coap_data_length > 0) {
        value.append_raw((char *)coap_data,coap_data_length);
    }
    return value;
}

uint64_t M2MNsdlInterface::registration_time() const
{
    uint64_t value = 0;
    if(_endpoint) {
        value = _server->resource_value_int(M2MServer::Lifetime);
    }

    if(value >= OPTIMUM_LIFETIME) {
        value = value - REDUCE_LIFETIME;
    } else {
        value = REDUCTION_FACTOR * value;
    }
    tr_debug("M2MNsdlInterface::registration_time - value (in seconds) %" PRIu64, value);
    return value;
}

M2MBase* M2MNsdlInterface::find_resource(const String &object_name,
                                         const uint16_t msg_id) const
{
    tr_debug("M2MNsdlInterface::find_resource(object level) - from %p name (%s) ", this, object_name.c_str());
    M2MObject *current = NULL;
    M2MBase *found = NULL;
    if(!_base_list.empty()) {
        M2MBaseList::const_iterator it;
        it = _base_list.begin();
        for ( ; it != _base_list.end(); it++ ) {
            if ((*it)->base_type() == M2MBase::Object) {
                current = (M2MObject*)*it;
                if (!msg_id) {
                    tr_debug("M2MNsdlInterface::find_resource(object level) - path (%s)",
                             (char*)current->uri_path());
                    if (strcmp((char*)current->uri_path(), object_name.c_str()) == 0) {
                        found = current;
                        tr_debug("M2MNsdlInterface::find_resource(%s) found", object_name.c_str());
                        break;
                    }
                } else {
                    uint16_t stored_msg_id = current->get_notification_msgid();
                    tr_debug("M2MNsdlInterface::find_resource(object level) - stored msgid (%d)", stored_msg_id);
                    if (stored_msg_id == msg_id) {
                        found = current;
                        tr_debug("M2MNsdlInterface::find_resource - msg id found");
                        break;
                    }
                }
                found = find_resource(current, object_name, msg_id);
                if(found != NULL) {
                    break;
                }
            }
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
            else if ((*it)->base_type() == M2MBase::ObjectDirectory) {
                M2MEndpoint *ep = (M2MEndpoint*)*it;
                if(!strcmp((char*)(*it)->uri_path(), object_name.c_str())) {
                    found = NULL;
                    break;
                } else {
                    found = find_resource(ep, object_name, msg_id);
                }
                if(found != NULL) {
                    break;
                }
            }
#endif
        }
    }
    return found;
}

#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
M2MBase* M2MNsdlInterface::find_resource(const M2MEndpoint *endpoint,
                                         const String &object_name,
                                         const uint16_t msg_id) const
{
    tr_debug("M2MNsdlInterface::find_resource(endpoint level) - name (%s)", object_name.c_str());
    M2MBase *object = NULL;
    if(endpoint) {
        const M2MObjectList &list = endpoint->objects();
        if(!list.empty()) {
            M2MObjectList::const_iterator it;
            it = list.begin();
            for ( ; it != list.end(); it++ ) {
                if (!msg_id) {
                    if (!strcmp((char*)(*it)->uri_path(), object_name.c_str())) {
                        tr_debug("M2MNsdlInterface::find_resource(endpoint level) - object %p object name (%s)",
                            object, object_name.c_str());
                        object = (*it);
                        break;
                    }
                } else {
                    uint16_t stored_msg_id = (*it)->get_notification_msgid();
                    tr_debug("M2MNsdlInterface::find_resource(endpoint level) - stored msgid (%d)", stored_msg_id);
                    if (stored_msg_id == msg_id) {
                        object = (*it);
                        break;
                    }
                }
                object = find_resource((*it),object_name, msg_id);
                if(object != NULL){
                    break;
                }
            }
        }
    }
    return object;
}
#endif

M2MBase* M2MNsdlInterface::find_resource(const M2MObject *object,
                                         const String &object_instance,
                                         const uint16_t msg_id) const
{
    M2MBase *instance = NULL;
    if(object) {
        const M2MObjectInstanceList &list = object->instances();
        if(!list.empty()) {
            M2MObjectInstanceList::const_iterator it;
            it = list.begin();
            for ( ; it != list.end(); it++ ) {
                if (!msg_id) {
                    if(!strcmp((char*)(*it)->uri_path(), object_instance.c_str())){
                        instance = (*it);
                        tr_debug("M2MNsdlInterface::find_resource(object instance level) - found (%s)",
                                 (char*)(*it)->uri_path());
                        break;
                    }
                } else {
                    uint16_t stored_msg_id = (*it)->get_notification_msgid();
                    if (stored_msg_id == msg_id) {
                        instance = (*it);
                        tr_debug("M2MNsdlInterface::find_resource(object instance level) - found msgid (%d)", stored_msg_id);
                        break;
                    }
                }
                instance = find_resource((*it),object_instance, msg_id);
                if(instance != NULL){
                    break;
                }
            }
        }
    }
    return instance;
}

M2MBase* M2MNsdlInterface::find_resource(const M2MObjectInstance *object_instance,
                                         const String &resource_instance,
                                         const uint16_t msg_id) const
{
    M2MBase *instance = NULL;
    if(object_instance) {
        const M2MResourceList &list = object_instance->resources();
        if(!list.empty()) {
            M2MResourceList::const_iterator it;
            it = list.begin();
            for ( ; it != list.end(); it++ ) {
                if (!msg_id) {
                    if(!strcmp((char*)(*it)->uri_path(), resource_instance.c_str())) {
                        instance = *it;
                        break;
                    }
                    else if((*it)->supports_multiple_instances()) {
                        instance = find_resource((*it), (*it)->uri_path(),
                                                 resource_instance);
                        if(instance != NULL){
                            break;
                        }
                    }
                } else {
                    uint16_t stored_msg_id = (*it)->get_notification_msgid();
                    if (stored_msg_id == msg_id) {
                        instance = *it;
                        tr_debug("M2MNsdlInterface::find_resource(resource level) - found msgid (%d)", stored_msg_id);
                        break;
                    }
                }
            }
        }
    }
    return instance;
}

M2MBase* M2MNsdlInterface::find_resource(const M2MResource *resource,
                                         const String &object_name,
                                         const String &resource_instance) const
{
    M2MBase *res = NULL;
    if(resource) {
        if(resource->supports_multiple_instances()) {
            const M2MResourceInstanceList &list = resource->resource_instances();
            if(!list.empty()) {
                M2MResourceInstanceList::const_iterator it;
                it = list.begin();
                for ( ; it != list.end(); it++ ) {
                    if(!strcmp((char*)(*it)->uri_path(), resource_instance.c_str())){
                        res = (*it);
                        break;
                    }
                }
            }
        }
    }
    return res;
}

bool M2MNsdlInterface::object_present(M2MBase* base) const
{
    bool success = false;
    if(base && !_base_list.empty()) {
        M2MBaseList::const_iterator it;
        it = _base_list.begin();
        for ( ; it != _base_list.end(); it++ ) {
            if((*it) == base) {
                success = true;
                break;
            }
        }
    }
    return success;
}

int M2MNsdlInterface::object_index(M2MBase* base) const
{
    int found_index = -1;
    int index;
    if(base && !_base_list.empty()) {
        M2MBaseList::const_iterator it;

        for (it = _base_list.begin(), index = 0; it != _base_list.end(); it++, index++) {
            if((*it) == base) {
                found_index = index;
                break;
            }
        }
    }
    return found_index;
}


bool M2MNsdlInterface::add_object_to_list(M2MBase* object)
{
    tr_debug("M2MNsdlInterface::add_object_to_list this=%p object=%p", this, object);
    bool success = false;
    if(object && !object_present(object)) {
        _base_list.push_back(object);
        success = true;
    }
    return success;
}

bool M2MNsdlInterface::remove_object_from_list(M2MBase* object)
{
    tr_debug("M2MNsdlInterface::remove_object_from_list this=%p object=%p", this, object);
    bool success = false;
    int index;
    if(object && (-1 != (index = object_index(object)))) {
        tr_debug("  object found at index %d", index);
        _base_list.erase(index);
        success = true;
    }
    return success;
}

M2MInterface::Error M2MNsdlInterface::interface_error(const sn_coap_hdr_s &coap_header)
{
    M2MInterface::Error error;
    switch(coap_header.msg_code) {
        case COAP_MSG_CODE_RESPONSE_BAD_REQUEST:
        case COAP_MSG_CODE_RESPONSE_BAD_OPTION:
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE:
        case COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED:
        case COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE:
        case COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT:
            error = M2MInterface::InvalidParameters;
            break;
        case COAP_MSG_CODE_RESPONSE_UNAUTHORIZED:
        case COAP_MSG_CODE_RESPONSE_FORBIDDEN:
        case COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE:
        case COAP_MSG_CODE_RESPONSE_NOT_FOUND:
        case COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED:
            error = M2MInterface::NotAllowed;
            break;
        case COAP_MSG_CODE_RESPONSE_CREATED:
        case COAP_MSG_CODE_RESPONSE_DELETED:
        case COAP_MSG_CODE_RESPONSE_VALID:
        case COAP_MSG_CODE_RESPONSE_CHANGED:
        case COAP_MSG_CODE_RESPONSE_CONTENT:
            error = M2MInterface::ErrorNone;
            break;
        default:
            error = M2MInterface::UnknownError;
            break;
    }
    if(coap_header.coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {
        error = M2MInterface::NetworkError;
    }
    return error;
}

const char *M2MNsdlInterface::coap_error(const sn_coap_hdr_s &coap_header)
{
    if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_BAD_REQUEST) {
        return COAP_ERROR_REASON_1;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_BAD_OPTION) {
        return COAP_ERROR_REASON_2;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_INCOMPLETE) {
        return COAP_ERROR_REASON_3;
    }else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED) {
        return COAP_ERROR_REASON_4;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_REQUEST_ENTITY_TOO_LARGE) {
        return COAP_ERROR_REASON_5;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_UNSUPPORTED_CONTENT_FORMAT) {
        return COAP_ERROR_REASON_6;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_UNAUTHORIZED) {
        return COAP_ERROR_REASON_7;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_FORBIDDEN) {
        return COAP_ERROR_REASON_8;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_NOT_ACCEPTABLE) {
        return COAP_ERROR_REASON_9;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_NOT_FOUND) {
        return COAP_ERROR_REASON_10;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_METHOD_NOT_ALLOWED) {
        return COAP_ERROR_REASON_11;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_SERVICE_UNAVAILABLE) {
        return COAP_ERROR_REASON_13;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR) {
        return COAP_ERROR_REASON_14;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_BAD_GATEWAY) {
        return COAP_ERROR_REASON_15;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_GATEWAY_TIMEOUT) {
        return COAP_ERROR_REASON_16;
    } else if (coap_header.msg_code == COAP_MSG_CODE_RESPONSE_PROXYING_NOT_SUPPORTED) {
        return COAP_ERROR_REASON_17;
    } else if (coap_header.coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {
        return COAP_ERROR_REASON_12;
    }
    return COAP_NO_ERROR;
}

void M2MNsdlInterface::send_object_observation(M2MObject *object,
                                               uint16_t obs_number,
                                               const m2m::Vector<uint16_t> &changed_instance_ids,
                                               bool send_object)
{
    tr_info("M2MNsdlInterface::send_object_observation");
    if(object) {
        uint8_t *value = 0;
        uint32_t length = 0;
        uint8_t token[MAX_TOKEN_SIZE];
        uint8_t token_length = 0;

        // Send whole object structure
        if (send_object) {
            value = M2MTLVSerializer::serialize(object->instances(), length);
        }
        // Send only changed object instances
        else {
            M2MObjectInstanceList list;
            Vector<uint16_t>::const_iterator it;
            it = changed_instance_ids.begin();
            for (; it != changed_instance_ids.end(); it++){
                M2MObjectInstance* obj_instance = object->object_instance(*it);
                if (obj_instance){
                    list.push_back(obj_instance);
                }
            }
            if (!list.empty()) {
                value = M2MTLVSerializer::serialize(list, length);
                list.clear();
            }
        }

        object->get_observation_token((uint8_t*)&token,token_length);

        object->report_handler()->set_blockwise_notify(is_blockwise_needed(length));

        int32_t msgid = sn_nsdl_send_observation_notification(_nsdl_handle, token, token_length, value, length,
                                                              sn_coap_observe_e(obs_number), COAP_MSG_TYPE_CONFIRMABLE,
                                                              sn_coap_content_format_e(object->coap_content_type()), -1);
        execute_notification_delivery_status_cb(object, msgid);

        memory_free(value);
    }
}

void M2MNsdlInterface::send_object_instance_observation(M2MObjectInstance *object_instance,
                                                        uint16_t obs_number)
{
    tr_info("M2MNsdlInterface::send_object_instance_observation");
    if(object_instance) {
        uint8_t *value = 0;
        uint32_t length = 0;
        uint8_t token[MAX_TOKEN_SIZE];
        uint8_t token_length = 0;

        value = M2MTLVSerializer::serialize(object_instance->resources(), length);

        object_instance->get_observation_token((uint8_t*)&token,token_length);

        object_instance->report_handler()->set_blockwise_notify(is_blockwise_needed(length));

        int32_t msgid = sn_nsdl_send_observation_notification(_nsdl_handle, token, token_length, value, length,
                                                               sn_coap_observe_e(obs_number), COAP_MSG_TYPE_CONFIRMABLE,
                                                               sn_coap_content_format_e(object_instance->coap_content_type()), -1);

        execute_notification_delivery_status_cb(object_instance, msgid);


        memory_free(value);
    }
}

void M2MNsdlInterface::send_resource_observation(M2MResource *resource,
                                                 uint16_t obs_number)
{
    if(resource) {
        tr_info("M2MNsdlInterface::send_resource_observation - uri %s", resource->uri_path());
        uint8_t *value = 0;
        uint32_t length = 0;
        uint8_t token[MAX_TOKEN_SIZE];
        uint8_t token_length = 0;

        resource->get_observation_token((uint8_t*)token,token_length);
        uint16_t content_type = resource->coap_content_type();
        if (M2MResourceBase::OPAQUE == resource->resource_instance_type()) {
            content_type = COAP_CONTENT_OMA_OPAQUE_TYPE;
        }

        if (resource->resource_instance_count() > 0 || content_type == COAP_CONTENT_OMA_TLV_TYPE) {
            value = M2MTLVSerializer::serialize(resource, length);
        } else {
            resource->get_value(value,length);
        }

        resource->report_handler()->set_blockwise_notify(is_blockwise_needed(length));

        int32_t msgid = sn_nsdl_send_observation_notification(_nsdl_handle, token, token_length, value, length,
                                                                   sn_coap_observe_e(obs_number),
                                                                   COAP_MSG_TYPE_CONFIRMABLE,
                                                                   sn_coap_content_format_e(content_type), -1);
        execute_notification_delivery_status_cb(resource, msgid);

        memory_free(value);
    }
}
nsdl_s * M2MNsdlInterface::get_nsdl_handle() const
{
    return _nsdl_handle;
}

void M2MNsdlInterface::handle_bootstrap_put_message(sn_coap_hdr_s *coap_header,
                                                sn_nsdl_addr_s *address) {
#ifndef M2M_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    tr_info("M2MNsdlInterface::handle_bootstrap_put_message");
    uint8_t response_code = COAP_MSG_CODE_RESPONSE_CHANGED;
    sn_coap_hdr_s *coap_response = NULL;
    bool success = false;
    uint16_t content_type = 0;
    char buffer[MAX_ALLOWED_ERROR_STRING_LENGTH];
    buffer[0] = '\0';
    M2MNsdlInterface::ObjectType object_type = M2MNsdlInterface::SECURITY;

    if (!_security) {
        _security = M2MSecurity::get_instance();
    }

    String resource_name = coap_to_string(coap_header->uri_path_ptr,
                                          coap_header->uri_path_len);
    tr_debug("M2MNsdlInterface::handle_bootstrap_put_message - object path %s", resource_name.c_str());

    // Security object
    if (resource_name.compare(0,1,"0") == 0) {
        object_type = M2MNsdlInterface::SECURITY;
        success = true;
    }
    // Server object
    else if (resource_name.compare(0,1,"1") == 0) {
        object_type = M2MNsdlInterface::SERVER;
        success = true;
    }
    // Device object
    else if (resource_name.compare(0,1,"3") == 0) {
        M2MDevice* dev = M2MInterfaceFactory::create_device();
        // Not mandatory resource, that's why it must be created first
        dev->create_resource(M2MDevice::CurrentTime, 0);
        object_type = M2MNsdlInterface::DEVICE;
        success = true;
    }

    if (success) {
        if(coap_header->content_format != COAP_CT_NONE) {
            content_type = coap_header->content_format;
        }

        if (content_type != COAP_CONTENT_OMA_TLV_TYPE &&
            content_type != COAP_CONTENT_OMA_TLV_TYPE_OLD) {
            tr_error("M2MNsdlInterface::handle_bootstrap_put_message - content_type %d", content_type);
            success = false;
        }
        // Parse TLV message and check is the object valid
        if (success) {
            change_operation_mode(_security, M2MBase::PUT_ALLOWED);
            success = parse_bootstrap_message(coap_header, object_type);
            if (success && object_type == M2MNsdlInterface::SECURITY) {
                success = validate_security_object();
                if (!success) {
                    const char *desc = "Invalid security object";
                    if (strlen(ERROR_REASON_22) + strlen(desc) <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
                        snprintf(buffer, sizeof(buffer), ERROR_REASON_22, desc);
                    }
                    response_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
                }
            }
            // Set operation back to default ones
            if (_security) {
                change_operation_mode(_security, M2MBase::NOT_ALLOWED);
            }
        }
    }

    if (!success) {
        response_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    }

    coap_response = sn_nsdl_build_response(_nsdl_handle,
                                           coap_header,
                                           response_code);

    if (coap_response) {
        sn_nsdl_send_coap_message(_nsdl_handle, address, coap_response);
        sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, coap_response);
    }

    if (!success) {
        // Do not overwrite ERROR_REASON_22
        if (strlen(buffer) == 0) {
            if (strlen(ERROR_REASON_20) + resource_name.size() <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
                snprintf(buffer, sizeof(buffer), ERROR_REASON_20, resource_name.c_str());
            }
        }
        handle_bootstrap_error(buffer, true);
    }
#else
    (void) coap_header;
    (void) address;
#endif
}

bool M2MNsdlInterface::parse_bootstrap_message(sn_coap_hdr_s *coap_header,
                                               M2MNsdlInterface::ObjectType lwm2m_object_type)
{
#ifndef M2M_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    tr_info("M2MNsdlInterface::parse_bootstrap_message");
    bool ret = false;
    bool is_obj_instance = false;
    uint16_t instance_id = 0;
    if (_security) {
        ret = is_obj_instance = M2MTLVDeserializer::is_object_instance(coap_header->payload_ptr);
        if (!is_obj_instance) {
            ret = M2MTLVDeserializer::is_resource(coap_header->payload_ptr);
        }
        if (ret) {
            M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
            if (is_obj_instance) {
                M2MObject* dev_object = static_cast<M2MObject*> (M2MInterfaceFactory::create_device());
                switch (lwm2m_object_type) {
                    case M2MNsdlInterface::SECURITY:
                        instance_id = M2MTLVDeserializer::instance_id(coap_header->payload_ptr);
                        if (_security->object_instance(instance_id) == NULL) {
                            _security->create_object_instance(M2MSecurity::M2MServer);
                            change_operation_mode(_security, M2MBase::PUT_ALLOWED);
                        }
                        error = M2MTLVDeserializer::deserialise_object_instances(coap_header->payload_ptr,
                                                                   coap_header->payload_len,
                                                                   *_security,
                                                                   M2MTLVDeserializer::Put);
                        break;
                    case M2MNsdlInterface::SERVER:
                        error = M2MTLVDeserializer::deserialise_object_instances(coap_header->payload_ptr,
                                                                   coap_header->payload_len,
                                                                   *_server,
                                                                   M2MTLVDeserializer::Put);
                        break;
                    case M2MNsdlInterface::DEVICE:
                        error = M2MTLVDeserializer::deserialise_object_instances(coap_header->payload_ptr,
                                                                   coap_header->payload_len,
                                                                   *dev_object,
                                                                   M2MTLVDeserializer::Put);
                        break;
                    default:
                        break;
                }
            }
            else {
                instance_id = M2MTLVDeserializer::instance_id(coap_header->payload_ptr);
                M2MObjectInstance* instance = NULL;
                switch (lwm2m_object_type) {
                    case M2MNsdlInterface::SECURITY:
                        instance = _security->object_instance(instance_id);
                        if (instance) {
                            error = M2MTLVDeserializer::deserialize_resources(coap_header->payload_ptr,
                                                                       coap_header->payload_len,
                                                                       *instance,
                                                                       M2MTLVDeserializer::Put);
                        } else {
                            error = M2MTLVDeserializer::NotValid;
                        }

                        break;
                    case M2MNsdlInterface::SERVER:
                        instance = _server->object_instance(instance_id);
                        if (instance) {
                            error = M2MTLVDeserializer::deserialize_resources(coap_header->payload_ptr,
                                                                       coap_header->payload_len,
                                                                       *instance,
                                                                       M2MTLVDeserializer::Post);
                        } else {
                            error = M2MTLVDeserializer::NotValid;
                        }

                        break;
                    case M2MNsdlInterface::DEVICE:
                    default:
                        break;
                }
            }

            if (error != M2MTLVDeserializer::None) {
                tr_error("M2MNsdlInterface::parse_bootstrap_message - error %d", error);
                ret = false;
            }
        }
    } else {
        tr_error("M2MNsdlInterface::parse_bootstrap_message -- no security object!");
    }
    return ret;
#else
    (void) coap_header;
    (void) is_security_object;
    return false;
#endif
}

void M2MNsdlInterface::handle_bootstrap_finished(sn_coap_hdr_s *coap_header,sn_nsdl_addr_s *address)
{
#ifndef M2M_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    char buffer[MAX_ALLOWED_ERROR_STRING_LENGTH];

    String object_name = coap_to_string(coap_header->uri_path_ptr,
                                        coap_header->uri_path_len);

    tr_info("M2MNsdlInterface::handle_bootstrap_finished - path: %s", object_name.c_str());
    sn_coap_hdr_s *coap_response = NULL;
    uint8_t msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;

    // Accept only '/bs' path and check that needed data is in security object
    if (object_name.size() != 2 ||
        object_name.compare(0, 2, BOOTSTRAP_URI) != 0) {
        if (strlen(ERROR_REASON_22) + object_name.size() <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
            snprintf(buffer, sizeof(buffer), ERROR_REASON_22, object_name.c_str());
        }
        msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    }
    else {
        // Add short server id to server object
        int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
        if (m2m_id == -1) {
            snprintf(buffer,sizeof(buffer), ERROR_REASON_4);
            msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
        }
        else {
            _server->set_resource_value(M2MServer::ShortServerID,
                                        _security->resource_value_int(M2MSecurity::ShortServerID, m2m_id));
        }
    }

    // In ok case send response as a separate response
    if (msg_code == COAP_MSG_CODE_RESPONSE_CHANGED) {
        send_empty_ack(coap_header, address);
    // In error case use piggybacked response
    } else {
        coap_response = sn_nsdl_build_response(_nsdl_handle, coap_header, msg_code);
        if (coap_response) {
            sn_nsdl_send_coap_message(_nsdl_handle, address, coap_response);
            sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, coap_response);
        }

        handle_bootstrap_error(buffer, true);
    }

    // Send a event which is responsible of sending the final response
    if (COAP_MSG_CODE_RESPONSE_CHANGED == msg_code) {
        sn_coap_hdr_s *coap_message = sn_nsdl_build_response(_nsdl_handle, coap_header, (sn_coap_msg_code_e)msg_code);
        nsdl_coap_data_s *nsdl_coap_data = create_coap_event_data(coap_message,
                                                                  address,
                                                                  _nsdl_handle,
                                                                  (sn_coap_msg_code_e)msg_code);

        if (nsdl_coap_data) {
            _event.data.event_type = MBED_CLIENT_NSDLINTERFACE_BS_EVENT;
            _event.data.data_ptr = (void*)nsdl_coap_data;
            eventOS_event_send_user_allocated(&_event);

            // Switch back to original ep name
            if (_endpoint->endpoint_name_ptr) {
                memory_free(_endpoint->endpoint_name_ptr);
            }

            _endpoint->endpoint_name_ptr = alloc_string_copy((uint8_t*)_endpoint_name.c_str(), _endpoint_name.length());
            _endpoint->endpoint_name_len = _endpoint_name.length();

            // The final bootstrap_done callback is called once the ACK for final response is received
            _observer.bootstrap_wait();
        } else {
            const char *desc = "memory allocation failed";
            if (strlen(ERROR_REASON_22) + strlen(desc) <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
                snprintf(buffer, sizeof(buffer), ERROR_REASON_22, desc);
            }

            handle_bootstrap_error(buffer, true);
        }
    }
#else
    (void) coap_header;
    (void) address;
#endif
}

void M2MNsdlInterface::handle_bootstrap_delete(sn_coap_hdr_s *coap_header,sn_nsdl_addr_s *address)
{

#ifndef M2M_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    char buffer[MAX_ALLOWED_ERROR_STRING_LENGTH];
    memset(buffer,0,sizeof(buffer));
    sn_coap_hdr_s *coap_response = NULL;
    uint8_t msg_code = COAP_MSG_CODE_RESPONSE_DELETED;
    String object_name = coap_to_string(coap_header->uri_path_ptr,
                                          coap_header->uri_path_len);
    tr_info("M2MNsdlInterface::handle_bootstrap_delete - obj %s", object_name.c_str());
    if(!_identity_accepted) {
        const char *desc = "/bs un-init";
        if (strlen(ERROR_REASON_21) + strlen(desc) <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
            snprintf(buffer, sizeof(buffer), ERROR_REASON_21, desc);
        }
        msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    }
    // Only following paths are accepted, 0, 0/0
    else if (object_name.size() == 2 || object_name.size() > 3) {
        if (strlen(ERROR_REASON_21) + object_name.size() <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
            snprintf(buffer, sizeof(buffer), ERROR_REASON_21,object_name.c_str());
        }
        msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    }
    else if ((object_name.size() == 1 && object_name.compare(0,1,"0") != 0) ||
            (object_name.size() == 3 && object_name.compare(0,3,"0/0") != 0)) {
        if (strlen(ERROR_REASON_21) + object_name.size() <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
            snprintf(buffer, sizeof(buffer), ERROR_REASON_21, object_name.c_str());
        }
        msg_code = COAP_MSG_CODE_RESPONSE_BAD_REQUEST;
    }

    coap_response = sn_nsdl_build_response(_nsdl_handle,
                                           coap_header,
                                           msg_code);

    if(coap_response) {
        sn_nsdl_send_coap_message(_nsdl_handle, address, coap_response);
        sn_nsdl_release_allocated_coap_msg_mem(_nsdl_handle, coap_response);
        if(_security) {
            _security->clear_resources();
        }
    }
    if (!coap_response || COAP_MSG_CODE_RESPONSE_DELETED != msg_code) {
        handle_bootstrap_error(buffer, true);
    }
#else
    (void) coap_header;
    (void) address;
#endif
}

bool M2MNsdlInterface::validate_security_object()
{
    bool valid = false;
#ifndef M2M_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    M2MObjectInstanceList instances = _security->instances();
    M2MObjectInstanceList::const_iterator it;
    it = instances.begin();
    uint16_t instance_id = 0;
    for ( ; it != instances.end(); it++ ) {
        valid = true;
        instance_id = (*it)->instance_id();
        tr_debug("M2MNsdlInterface::validate_security_object - instance %d", instance_id);
        String address = _security->resource_value_string(M2MSecurity::M2MServerUri, instance_id);
        uint32_t sec_mode = _security->resource_value_int(M2MSecurity::SecurityMode, instance_id);
        uint32_t is_bs_server = _security->resource_value_int(M2MSecurity::BootstrapServer, instance_id);
        uint32_t public_key_size = 0;
        uint32_t server_key_size = 0;
        uint32_t pkey_size = 0;

        M2MResource* resource = _security->get_resource(M2MSecurity::PublicKey, instance_id);
        if (resource) {
            public_key_size = resource->value_length();
        }
        resource = _security->get_resource(M2MSecurity::ServerPublicKey, instance_id);
        if (resource) {
            server_key_size = resource->value_length();
        }
        resource = _security->get_resource(M2MSecurity::Secretkey, instance_id);
        if (resource) {
            pkey_size = resource->value_length();
        }

        tr_info("M2MNsdlInterface::validate_security_object - Server URI /0/0: %s", address.c_str());
        tr_info("M2MNsdlInterface::validate_security_object - is bs server /0/1: %" PRIu32, is_bs_server);
        tr_info("M2MNsdlInterface::validate_security_object - Security Mode /0/2: %" PRIu32, sec_mode);
        tr_info("M2MNsdlInterface::validate_security_object - Public key size /0/3: %" PRIu32, public_key_size);
        tr_info("M2MNsdlInterface::validate_security_object - Server Public key size /0/4: %" PRIu32, server_key_size);
        tr_info("M2MNsdlInterface::validate_security_object - Secret key size /0/5: %" PRIu32, pkey_size);
        if (address.empty()) {
            return false;
        }
        // Only NoSec and Certificate modes are supported
        if (M2MSecurity::Certificate == sec_mode) {
            if (!public_key_size || !server_key_size || !pkey_size) {
                return false;
            }
        } else if (M2MSecurity::NoSecurity != sec_mode){
            return false;
        }
    }
#endif
    return valid;
}


void M2MNsdlInterface::handle_bootstrap_error(const char *reason, bool wait)
{
    tr_error("M2MNsdlInterface::handle_bootstrap_error(%s)",reason);
    _identity_accepted = false;
    if (_security) {
        int32_t m2m_id = _security->get_security_instance_id(M2MSecurity::M2MServer);
        if (m2m_id >= 0) {
            _security->remove_object_instance(m2m_id);
        }
    }

    if (wait) {
        _observer.bootstrap_error_wait(reason);
    } else {
        _observer.bootstrap_error(reason);
    }
}

const String& M2MNsdlInterface::endpoint_name() const
{
    return _endpoint_name;
}

const String M2MNsdlInterface::internal_endpoint_name() const
{
    String iep("");
    if (_nsdl_handle->ep_information_ptr->location_ptr) {
        String temp((const char*)_nsdl_handle->ep_information_ptr->location_ptr,
                   _nsdl_handle->ep_information_ptr->location_len);
        // Get last part of the location path.
        // In mbed Cloud environment full path is /rd/accountid/internal_endpoint
        int location = temp.find_last_of('/') + 1;
        iep.append_raw((const char*)_nsdl_handle->ep_information_ptr->location_ptr + location,
                   _nsdl_handle->ep_information_ptr->location_len - location);
    }
    return iep;
}

void M2MNsdlInterface::change_operation_mode(M2MObject *object, M2MBase::Operation operation)
{
    M2MObjectInstanceList instances = object->instances();
    M2MObjectInstanceList::const_iterator inst = instances.begin();
    for (; inst != instances.end(); inst++ ) {
        (*inst)->set_operation(operation);
        M2MResourceList list = (*inst)->resources();
        if(!list.empty()) {
            M2MResourceList::const_iterator it;
            it = list.begin();
            for ( ; it != list.end(); it++ ) {
                (*it)->set_operation(operation);
            }
        }
    }
}

void M2MNsdlInterface::set_server_address(const char* server_address)
{
    free(_server_address);
    _server_address = M2MBase::alloc_string_copy(server_address);
}

M2MTimer &M2MNsdlInterface::get_nsdl_execution_timer()
{
    return _nsdl_execution_timer;
}

bool M2MNsdlInterface::get_unregister_ongoing() const
{
    return _unregister_ongoing;
}

bool M2MNsdlInterface::parse_and_send_uri_query_parameters()
{
    bool msg_sent = false;
    char *address_copy = M2MBase::alloc_string_copy(_server_address);
    if (address_copy) {
        char* query = parse_uri_query_parameters(_server_address);
        if (query != NULL) {
            size_t query_len = 1 + strlen(query) + 1 + strlen(MCC_VERSION) + 1;
            if (_custom_uri_query_params) {
                query_len += 1 + strlen(_custom_uri_query_params);
            }

            if (query_len <= MAX_URI_QUERY_LEN) {
                char query_params[MAX_URI_QUERY_LEN];
                strcpy(query_params, "&");
                strcat(query_params, query);
                strcat(query_params, "&");
                strcat(query_params, MCC_VERSION);
                if (_custom_uri_query_params) {
                    strcat(query_params, "&");
                    strcat(query_params, _custom_uri_query_params);
                }

                tr_debug("M2MNsdlInterface::parse_and_send_uri_query_parameters - uri params: %s", query_params);
                sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
                msg_sent = sn_nsdl_register_endpoint(_nsdl_handle,_endpoint,query_params) != 0;
            } else {
                tr_error("M2MNsdlInterface::parse_and_send_uri_query_parameters - max uri param length reached (%lu)",
                          (unsigned long)query_len);
            }
        }
        free(address_copy);
    }
    return msg_sent;
}

void M2MNsdlInterface::claim_mutex()
{
    _connection_handler.claim_mutex();
}

void M2MNsdlInterface::release_mutex()
{
    _connection_handler.release_mutex();
}

void M2MNsdlInterface::start_nsdl_execution_timer()
{
    tr_debug("M2MNsdlInterface::start_nsdl_execution_timer");
    _nsdl_execution_timer_running = true;
    _nsdl_execution_timer.stop_timer();
    _nsdl_execution_timer.start_timer(ONE_SECOND_TIMER * 1000,
                                      M2MTimerObserver::NsdlExecution,
                                      false);
}

M2MSecurity* M2MNsdlInterface::get_security_object()
{
    return _security;
}

void M2MNsdlInterface::update_trigger_callback(void */*argument*/)
{
    if (lifetime_value_changed()) {
        send_update_registration(_server->resource_value_int(M2MServer::Lifetime));
    } else {
        send_update_registration();
    }
}

bool M2MNsdlInterface::lifetime_value_changed() const
{
    uint64_t value = 0;
    if (_endpoint && _endpoint->lifetime_ptr) {
        value = atol((const char*)_endpoint->lifetime_ptr);
    }
    if (_server->resource_value_int(M2MServer::Lifetime) != value) {
        return true;
    }
    return false;
}

void M2MNsdlInterface::execute_notification_delivery_status_cb(M2MBase* object, int32_t msgid)
{
    if (msgid > 0) {
        object->send_notification_delivery_status(*object, NOTIFICATION_STATUS_SENT);
        object->set_notification_msgid(msgid);
    } else {
        object->send_notification_delivery_status(*object, NOTIFICATION_STATUS_BUILD_ERROR);
        _notification_send_ongoing = false;
    }
}

uint8_t M2MNsdlInterface::find_auto_obs_token(const char *path, uint8_t *token) const
{
    uint8_t token_len = 0;
    const String name(path);
    M2MBase *object = find_resource(name, 0);
    if (object) {
        object->get_observation_token(token, token_len);
    }
    return token_len;
}

bool M2MNsdlInterface::is_response_to_get_req(const sn_coap_hdr_s *coap_header, get_data_request_s &get_data)
{
    // ns_list_foreach() replacement since it does not compile with IAR 7.x versions.
    get_data_request_s *data = (get_data_request_s *)ns_list_get_first(&_get_request_list);
    while (data) {
        if (memcmp(coap_header->token_ptr, &data->msg_token, sizeof(data->msg_token)) == 0) {
            get_data = *data;
            return true;
        }
        data = (get_data_request_s *)ns_list_get_next(&_get_request_list, data);
    }

    return false;
}

void M2MNsdlInterface::free_get_request_list(const sn_coap_hdr_s *coap_header)
{
    // Clean up whole list
    if (coap_header == NULL) {
        // ns_list_foreach() replacement since it does not compile with IAR 7.x versions.
        while (!ns_list_is_empty(&_get_request_list)) {
            get_data_request_s* data = (get_data_request_s*)ns_list_get_first(&_get_request_list);
            ns_list_remove(&_get_request_list, data);
            memory_free(data->uri_path);
            memory_free(data);
        }

    // Clean just one item from the list
    } else {
        // ns_list_foreach() replacement since it does not compile with IAR 7.x versions.
        get_data_request_s *data = (get_data_request_s *)ns_list_get_first(&_get_request_list);
        while (data) {
            if (memcmp(coap_header->token_ptr, &data->msg_token, sizeof(data->msg_token)) == 0) {
                ns_list_remove(&_get_request_list, data);
                memory_free(data->uri_path);
                memory_free(data);
                return;
            }
            data = (get_data_request_s *)ns_list_get_next(&_get_request_list, data);
        }
    }
}

char* M2MNsdlInterface::parse_uri_query_parameters(char* uri)
{
    char* query = strchr((char*)uri, '?');
    if (query != NULL) {
        query++;
        if (*query == '\0') {
            return NULL;
        } else {
            return query;
        }
    } else {
        return NULL;
    }
}

bool M2MNsdlInterface::set_uri_query_parameters(const char *uri_query_params)
{
    tr_debug("M2MNsdlInterface::set_uri_query_parameters");
    size_t query_len = uri_query_params == NULL ? 0:strlen(uri_query_params);
    size_t current_len = _custom_uri_query_params == NULL ? 0:strlen(_custom_uri_query_params);
    size_t new_size = query_len + current_len;

    if (query_len == 0 ||
        query_len > MAX_ALLOWED_STRING_LENGTH ||
        new_size > MAX_ALLOWED_STRING_LENGTH) {
        tr_error("M2MNsdlInterface::set_uri_query_parameters - invalid params!");
        return false;
    }

    // Append into existing string
    if (_custom_uri_query_params) {
        // Reserve space for "&" and null marks
        _custom_uri_query_params = (char*)realloc(_custom_uri_query_params, 1 + new_size + 1);
        if (_custom_uri_query_params == NULL) {
            return false;
        }

        memcpy(_custom_uri_query_params + current_len, "&", 1);
        memcpy(_custom_uri_query_params + current_len + 1, uri_query_params, query_len);
        _custom_uri_query_params[1 + new_size] = '\0';
    } else {
        _custom_uri_query_params = (char*)alloc_string_copy((uint8_t*)uri_query_params, query_len + 1);
        if (_custom_uri_query_params == NULL) {
            return false;
        }
    }

    tr_info("M2MNsdlInterface::set_uri_query_parameters - query %s", _custom_uri_query_params);
    return true;
}

void M2MNsdlInterface::clear_sent_blockwise_messages()
{
    sn_nsdl_clear_coap_sent_blockwise_messages(_nsdl_handle);
}

void M2MNsdlInterface::send_coap_ping()
{
    if (_binding_mode != M2MInterface::TCP) {
        return;
    }

    if (MBED_CLIENT_TCP_KEEPALIVE_INTERVAL > 0 && _counter_for_nsdl == _next_coap_ping_send_time) {
        tr_info("M2MNsdlInterface::send_coap_ping()");
        calculate_new_coap_ping_send_time();

        // Build the CoAP here as the CoAP builder would add the message to re-sending queue.
        uint8_t packet_ptr[4];

        /* Add CoAP version and message type */
        packet_ptr[0] = COAP_VERSION_1;
        packet_ptr[0] |= COAP_MSG_TYPE_CONFIRMABLE;

        /* Add message code */
        packet_ptr[1] = COAP_MSG_CODE_EMPTY;

        /* Add message ID */
        packet_ptr[2] = 0;
        packet_ptr[3] = 0;

        /* Send ping */
        _nsdl_handle->sn_nsdl_tx_callback(_nsdl_handle, SN_NSDL_PROTOCOL_COAP, packet_ptr, 4, &_sn_nsdl_address);
    }
}

void M2MNsdlInterface::calculate_new_coap_ping_send_time()
{
    if (_binding_mode != M2MInterface::TCP) {
        return;
    }

    _next_coap_ping_send_time = _counter_for_nsdl + MBED_CLIENT_TCP_KEEPALIVE_INTERVAL;
}

void M2MNsdlInterface::send_next_notification(bool clear_token)
{
    tr_debug("M2MNsdlInterface::send_next_notification");
    claim_mutex();
    if (!_base_list.empty()) {
        M2MBaseList::const_iterator base_iterator;
        base_iterator = _base_list.begin();
        for ( ; base_iterator != _base_list.end(); base_iterator++ ) {
            if ((*base_iterator)->base_type() == M2MBase::Object) {
                if (send_next_notification_for_object(*(M2MObject*)*base_iterator, clear_token)) {
                    release_mutex();
                    return;
                }
            }
#ifdef MBED_CLOUD_CLIENT_EDGE_EXTENSION
            else if ((*base_iterator)->base_type() == M2MBase::ObjectDirectory) {
                M2MEndpoint* endpoint = static_cast<M2MEndpoint*> (*base_iterator);
                const M2MObjectList& object_list = endpoint->objects();
                if (!object_list.empty()) {
                    M2MObjectList::const_iterator object_iterator;
                    object_iterator = object_list.begin();
                    // Object level
                    for ( ; object_iterator != object_list.end(); object_iterator++ ) {
                        if (send_next_notification_for_object(**object_iterator, clear_token)) {
                            release_mutex();
                            return;
                        }
                    }
                }
            }
#endif
        }
    }

    _notification_send_ongoing = false;
    release_mutex();
    tr_debug("M2MNsdlInterface::send_next_notification - nothing to send");
}

bool M2MNsdlInterface::send_next_notification_for_object(M2MObject& object, bool clear_token) {
    const M2MObjectInstanceList &object_instance_list = object.instances();
    M2MReportHandler* reporter = object.report_handler();
    if (reporter) {
        if (clear_token && !object.get_nsdl_resource()->auto_observable) {
            reporter->set_observation_token(NULL, 0);
        } else if (reporter->is_under_observation() &&
                   (reporter->notification_in_queue() || reporter->notification_send_in_progress())) {
            reporter->schedule_report(true);
            return true;
        }
    }

    // Object instance level
    if (!object_instance_list.empty()) {
        M2MObjectInstanceList::const_iterator object_instance_iterator;
        object_instance_iterator = object_instance_list.begin();
        for ( ; object_instance_iterator != object_instance_list.end(); object_instance_iterator++ ) {
            M2MReportHandler* reporter = (*object_instance_iterator)->report_handler();
            if (reporter) {
                if (clear_token && !(*object_instance_iterator)->get_nsdl_resource()->auto_observable) {
                    reporter->set_observation_token(NULL, 0);
                } else if (reporter->is_under_observation() &&
                           (reporter->notification_in_queue() || reporter->notification_send_in_progress())) {
                    reporter->schedule_report(true);
                    return true;
                }
            }

            // Resource level
            const M2MResourceList &resource_list = (*object_instance_iterator)->resources();
            if (!resource_list.empty()) {
                M2MResourceList::const_iterator resource_iterator;
                resource_iterator = resource_list.begin();
                for ( ; resource_iterator != resource_list.end(); resource_iterator++) {
                    M2MReportHandler* reporter = (*resource_iterator)->report_handler();
                    if (reporter) {
                        // Auto obs token can't be cleared
                        if (clear_token && !(*resource_iterator)->get_nsdl_resource()->auto_observable) {
                            reporter->set_observation_token(NULL, 0);
                        } else if (reporter->is_under_observation() &&
                                   (reporter->notification_in_queue() || reporter->notification_send_in_progress())) {
                            reporter->schedule_report(true);
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;
}

void M2MNsdlInterface::send_empty_ack(const sn_coap_hdr_s *header, sn_nsdl_addr_s *address)
{
    tr_debug("M2MNsdlInterface::send_empty_ack()");
    sn_coap_hdr_s *empty_coap_ack = (sn_coap_hdr_s *) memory_alloc(sizeof(sn_coap_hdr_s));
    if (empty_coap_ack) {
        memset(empty_coap_ack, 0, sizeof(sn_coap_hdr_s));
        empty_coap_ack->msg_code = COAP_MSG_CODE_EMPTY;
        empty_coap_ack->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
        empty_coap_ack->msg_id = header->msg_id;
        sn_nsdl_send_coap_message(_nsdl_handle, address, empty_coap_ack);
        memory_free(empty_coap_ack);
    }
}

void M2MNsdlInterface::store_bs_finished_response_id(uint16_t msg_id)
{
    tr_debug("M2MNsdlInterface::store_bs_finished_response_id - id %d", msg_id);
    _bootstrap_id = msg_id;
}

struct M2MNsdlInterface::nsdl_coap_data_s* M2MNsdlInterface::create_coap_event_data(
        sn_coap_hdr_s *received_coap_header,
        sn_nsdl_addr_s *address,
        struct nsdl_s *nsdl_handle,
        uint8_t coap_msg_code)
{
    nsdl_coap_data_s *nsdl_coap_data = (nsdl_coap_data_s*)memory_alloc(sizeof(nsdl_coap_data_s));

    if (nsdl_coap_data) {
        nsdl_coap_data->nsdl_handle = nsdl_handle;
        nsdl_coap_data->address.addr_len = address->addr_len;
        nsdl_coap_data->address.type = address->type;
        nsdl_coap_data->address.port = address->port;

        // Needs to copy all the dynamic data since it resides on stack and this wil turn into an event based call.
        nsdl_coap_data->address.addr_ptr = (uint8_t*) memory_alloc(address->addr_len);

        if (nsdl_coap_data->address.addr_ptr) {
            memcpy(nsdl_coap_data->address.addr_ptr, address->addr_ptr, address->addr_len);
            nsdl_coap_data->received_coap_header = received_coap_header;
            nsdl_coap_data->received_coap_header->msg_type = COAP_MSG_TYPE_CONFIRMABLE;
            nsdl_coap_data->received_coap_header->msg_code = (sn_coap_msg_code_e)coap_msg_code;

            // Copy payload
            if ((received_coap_header->payload_len > 0) &&
                (received_coap_header->coap_status != COAP_STATUS_PARSER_BLOCKWISE_MSG_RECEIVED)) {
                assert(received_coap_header->payload_ptr);

                uint8_t *temp_ptr = (uint8_t*) memory_alloc(received_coap_header->payload_len);
                if (temp_ptr) {
                    memcpy(temp_ptr, received_coap_header->payload_ptr, received_coap_header->payload_len);
                    nsdl_coap_data->received_coap_header->payload_ptr = temp_ptr;
                    nsdl_coap_data->received_coap_header->payload_len = received_coap_header->payload_len;
                } else {
                    sn_coap_parser_release_allocated_coap_msg_mem(nsdl_handle->grs->coap, nsdl_coap_data->received_coap_header);
                    memory_free(nsdl_coap_data->address.addr_ptr);
                    memory_free(nsdl_coap_data);
                    return NULL;
                }
            }
        } else {
            memory_free(nsdl_coap_data);
            return NULL;
        }
    } else {
        return NULL;
    }

    return nsdl_coap_data;
}

void M2MNsdlInterface::set_registration_status(bool registered)
{
    _registered = registered;
}

void M2MNsdlInterface::handle_register_response(const sn_coap_hdr_s *coap_header)
{
    if(coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CREATED) {
        tr_info("M2MNsdlInterface::handle_register_response - registered");
        // If lifetime is less than zero then leave the field empty
        if(coap_header->options_list_ptr) {
            uint32_t max_time = coap_header->options_list_ptr->max_age;

            // If a sufficiently-large Max-Age option is present, we interpret it as registration lifetime;
            // mbed server (mDS) reports lifetime this way as a non-standard extension. Other servers
            // would likely not include an explicit Max-Age option, in which case we'd see the default 60 seconds.
            if( max_time >= MINIMUM_REGISTRATION_TIME) {
                set_endpoint_lifetime_buffer(max_time);
            }
            if(coap_header->options_list_ptr->location_path_ptr) {
                sn_nsdl_set_endpoint_location(_nsdl_handle,
                                              coap_header->options_list_ptr->location_path_ptr,
                                              coap_header->options_list_ptr->location_path_len);
            }

        }
        if (_endpoint->lifetime_ptr) {
            _registration_timer.stop_timer();
            _registration_timer.start_timer(registration_time() * 1000,
                                             M2MTimerObserver::Registration,
                                             false);
        }

        _observer.client_registered(_server);

        calculate_new_coap_ping_send_time();

        _notification_send_ongoing = false;

        // Clear the observation tokens
        send_next_notification(true);

    } else {
        tr_error("M2MNsdlInterface::handle_register_response - registration error %d", coap_header->msg_code);
        if(coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {
            tr_error("M2MNsdlInterface::handle_register_response - message sending failed !!!!");
        }
        // Try to do clean register again
        if(COAP_MSG_CODE_RESPONSE_BAD_REQUEST == coap_header->msg_code ||
           COAP_MSG_CODE_RESPONSE_FORBIDDEN == coap_header->msg_code) {
            _observer.registration_error(M2MInterface::InvalidParameters, false);
        } else {
            _observer.registration_error(M2MInterface::NetworkError, true);
        }

    }
}

void M2MNsdlInterface::handle_unregister_response(const sn_coap_hdr_s *coap_header)
{
    _unregister_ongoing = false;
    tr_info("M2MNsdlInterface::handle_unregister_response - unregistered");
    if(coap_header->msg_code == COAP_MSG_CODE_RESPONSE_DELETED) {
        _registration_timer.stop_timer();
        _observer.client_unregistered();
    } else {
        tr_error("M2MNsdlInterface::handle_unregister_response - unregistration error %d", coap_header->msg_code);
        M2MInterface::Error error = M2MInterface::UnregistrationFailed;
        if (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_NOT_FOUND) {
            _observer.registration_error(error, false);
        } else {
            _observer.registration_error(error, true);
        }
    }
}

void M2MNsdlInterface::handle_register_update_response(const sn_coap_hdr_s *coap_header)
{
    if (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CHANGED) {
        tr_info("M2MNsdlInterface::handle_register_update_response - registration_updated");
        _observer.registration_updated(*_server);

        _notification_send_ongoing = false;
        // Check if there are any pending notifications in queue
        _notification_handler->send_notification(this);
        calculate_new_coap_ping_send_time();
    } else {
        tr_error("M2MNsdlInterface::handle_register_update_response - registration_updated failed %d, %d", coap_header->msg_code, coap_header->coap_status);

        _registration_timer.stop_timer();

        if (coap_header->coap_status == COAP_STATUS_BUILDER_MESSAGE_SENDING_FAILED) {
            // Inform interfaceimpl to do a reconnection and registration update
            // till we get CoAP level response for the request
            _observer.registration_error(M2MInterface::NetworkError, true);
        } else {
            // Do a full registration
            bool msg_sent = false;
            if (_server_address) {
                msg_sent = parse_and_send_uri_query_parameters();
            }
            if (!msg_sent) {
                sn_nsdl_clear_coap_resending_queue(_nsdl_handle);
                sn_nsdl_register_endpoint(_nsdl_handle, _endpoint, NULL);
            }
        }
    }
}

void M2MNsdlInterface::handle_get_response(const sn_coap_hdr_s *coap_header, get_data_request_s *get_data)
{
    tr_info("M2MNsdlInterface::handle_get_response - GET response");
    size_t total_size = 0;

    if (coap_header->options_list_ptr) {
        if (coap_header->options_list_ptr->use_size2) {
            total_size = coap_header->options_list_ptr->size2;
        }
    } else {
        total_size = coap_header->payload_len;
    }

    if (coap_header->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT) {
        get_data->received_size += coap_header->payload_len;
        get_data->on_get_data_cb(coap_header->payload_ptr,
                                    coap_header->payload_len,
                                    total_size,
                                    get_data->context);

        // In sync mode, call next GET automatically until all blocks have been received
        if (!get_data->async_req) {
            if (coap_header->options_list_ptr && coap_header->options_list_ptr->block2 & 0x08) {
                send_get_data_request(get_data->uri_path,
                                      get_data->received_size,
                                      get_data->async_req,
                                      get_data->on_get_data_cb,
                                      get_data->on_get_data_error_cb,
                                      get_data->context);
            } else {
                tr_info("M2MNsdlInterface::handle_get_response - GET response, all blocks received");
            }
        }
    } else {
        // TODO! Convert coap error code
        get_data_req_error_e error = FAILED_TO_SEND_MSG;
        get_data->on_get_data_error_cb(error, get_data->context);
    }

    free_get_request_list(coap_header);
}

void M2MNsdlInterface::handle_bootstrap_response(const sn_coap_hdr_s *coap_header)
{
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    tr_info("M2MNsdlInterface::handle_bootstrap_response");
    _bootstrap_id = 0;
    M2MInterface::Error error = interface_error(*coap_header);
    if (error != M2MInterface::ErrorNone) {

#ifdef DISABLE_ERROR_DESCRIPTION
        // this ifdef is saving +800B on ARMCC as it gets rid of the COAP_ERROR_* -strings from binary
        const char *buffer = "";
#else
        char buffer[MAX_ALLOWED_ERROR_STRING_LENGTH];

        const char* error = coap_error(*coap_header);
        strncpy(buffer, error, MAX_ALLOWED_ERROR_STRING_LENGTH);
        size_t free_space = MAX_ALLOWED_ERROR_STRING_LENGTH - strlen(buffer) + 1;
        if(coap_header->payload_ptr && free_space > coap_header->payload_len) {
            strncat(buffer, ":" , 1);
            strncat(buffer, (char*)coap_header->payload_ptr, coap_header->payload_len);
        }
#endif
        handle_bootstrap_error(buffer, false);
    } else {
        _identity_accepted = true;
    }
#else
    (void)coap_header;
#endif //MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
}

bool M2MNsdlInterface::handle_post_response(sn_coap_hdr_s* coap_header,
                                            sn_nsdl_addr_s* address,
                                            sn_coap_hdr_s *&coap_response,
                                            M2MObjectInstance *&obj_instance,
                                            bool is_bootstrap_msg)
{
    bool execute_value_updated = false;

    if (is_bootstrap_msg) {
        handle_bootstrap_finished(coap_header, address);
    } else if (coap_header->uri_path_ptr) {

        String resource_name = coap_to_string(coap_header->uri_path_ptr,
                                       coap_header->uri_path_len);

        String object_name;
        int slash_found = resource_name.find_last_of('/');
        //The POST operation here is only allowed for non-existing object instances
        if (slash_found != -1) {
            object_name = resource_name.substr(0,slash_found);
            if (object_name.find_last_of('/') != -1){
                coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                       coap_header,
                                                       COAP_MSG_CODE_RESPONSE_NOT_FOUND);
            } else {
                int32_t instance_id = atoi(resource_name.substr(slash_found+1,
                                         resource_name.size()-object_name.size()).c_str());
                M2MBase* base = find_resource(object_name, 0);
                if(base) {
                    if((instance_id >= 0) && (instance_id < UINT16_MAX)) {
                        if(coap_header->payload_ptr) {
                            M2MObject* object = static_cast<M2MObject*> (base);
                            obj_instance = object->create_object_instance(instance_id);
                            if(obj_instance) {
                                obj_instance->set_operation(M2MBase::GET_PUT_POST_ALLOWED);
                                coap_response = obj_instance->handle_post_request(_nsdl_handle,
                                                                                  coap_header,
                                                                                  this,
                                                                                  execute_value_updated);
                            }
                            if (coap_response && coap_response->msg_code != COAP_MSG_CODE_RESPONSE_CREATED) {
                                //Invalid request so remove created ObjectInstance
                                object->remove_object_instance(instance_id);
                            } else  {
                                tr_debug("M2MNsdlInterface::handle_post_response - Send Update registration for Create");
                                if (lifetime_value_changed()) {
                                    send_update_registration(_server->resource_value_int(M2MServer::Lifetime));
                                } else {
                                    send_update_registration();
                                }
                            }
                        } else {
                            tr_error("M2MNsdlInterface::handle_post_response - Missing Payload - Cannot create");
                            coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                                   coap_header,
                                                                   COAP_MSG_CODE_RESPONSE_BAD_REQUEST);
                        }
                    } else { // instance id out of range
                        tr_error("M2MNsdlInterface::handle_post_response - instance id out of range - Cannot create");
                        coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                               coap_header,
                                                               COAP_MSG_CODE_RESPONSE_BAD_REQUEST);
                    }
                } else { // if(base)
                    tr_error("M2MNsdlInterface::handle_post_response - Missing BASE - Cannot create");
                    coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                           coap_header,
                                                           COAP_MSG_CODE_RESPONSE_NOT_FOUND);
                }
            }
        } else { // if(slash_found != -1)
            tr_error("M2MNsdlInterface::handle_post_response - slash_found - Cannot create");
            coap_response = sn_nsdl_build_response(_nsdl_handle,
                                                   coap_header,
                                                   COAP_MSG_CODE_RESPONSE_NOT_FOUND);
        }

    }
    return execute_value_updated;
}

void M2MNsdlInterface::handle_empty_ack(const sn_coap_hdr_s *coap_header, bool is_bootstrap_msg)
{
    // Cancel ongoing observation
    if (COAP_MSG_TYPE_RESET == coap_header->msg_type) {
        M2MBase *base = find_resource("", coap_header->msg_id);
        if (base) {
            M2MBase::BaseType type = base->base_type();
            switch (type) {
                case M2MBase::Object:
                    base->remove_observation_level(M2MBase::O_Attribute);
                    break;
                case M2MBase::Resource:
                    base->remove_observation_level(M2MBase::R_Attribute);
                    break;
                case M2MBase::ObjectInstance:
                    base->remove_observation_level(M2MBase::OI_Attribute);
                    break;
                default:
                    break;
            }
            base->set_under_observation(false, this);
            _notification_send_ongoing = false;
            base->send_notification_delivery_status(*base, NOTIFICATION_STATUS_UNSUBSCRIBED);
            _notification_handler->send_notification(this);
        }
    } else if (is_bootstrap_msg) {
        // EMPTY ACK for BS finished
        if (_bootstrap_id == coap_header->msg_id) {
            _observer.bootstrap_wait();
            _bootstrap_id = 0;
        } else {
            tr_error("M2MNsdlInterface::handle_empty_ack - empty ACK id does not match to BS finished response id!");
            char buffer[MAX_ALLOWED_ERROR_STRING_LENGTH];
            const char *desc = "message id does not match";
            if (strlen(ERROR_REASON_22) + strlen(desc) <= MAX_ALLOWED_ERROR_STRING_LENGTH) {
                snprintf(buffer, sizeof(buffer), ERROR_REASON_22, desc);
            }
            handle_bootstrap_error(buffer, false);
        }
    } else {
        // Notification delivered
        M2MBase *base = find_resource("", coap_header->msg_id);
        if (base && !base->report_handler()->blockwise_notify()) {
            handle_notification_delivered(base);
        }
    }
}

void M2MNsdlInterface::handle_notification_delivered(M2MBase *base)
{
    base->report_handler()->set_notification_send_in_progress(false);
    _notification_send_ongoing = false;
    base->send_notification_delivery_status(*base, NOTIFICATION_STATUS_DELIVERED);
    _notification_handler->send_notification(this);

    // Supported only in Resource level
    // TODO! remove below code once old API is removed
    if (M2MBase::Resource == base->base_type()) {
        M2MResource *resource = static_cast<M2MResource *> (base);
        resource->notification_sent();
    }
}

bool M2MNsdlInterface::is_blockwise_needed(uint32_t length) const
{
    uint16_t block_size = sn_nsdl_get_block_size(_nsdl_handle);

    if (length > block_size && block_size > 0) {
        return true;
    } else {
        return false;
    }
}
