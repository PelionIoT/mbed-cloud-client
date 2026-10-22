/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include <string>
#include "pal.h"
#include "ns_hal_init.h"
#include "ns_event_loop.h"
#include "eventOS_scheduler.h"
#include "mbed-client/m2mconnectionhandler.h"
#include "mbed-client/m2mconnectionobserver.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "include/m2mnsdlinterface.h"
#include "include/m2mnsdlobserver.h"
#include "include/m2mreporthandler.h"
#include "include/sn_grs.h"
#include "mbed-client-classic/m2mconnectionhandlerpimpl.h"

extern "C" int8_t sn_nsdl_build_registration_body(struct nsdl_s *, sn_coap_hdr_s *, uint8_t);

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "Registry test line %d: %s failed\n", __LINE__, #value); exit(1); \
} } while (0)

class Test_M2MNsdlInterface {
public:
    static void pending(M2MNsdlInterface &registry, const char *uri, int32_t id, M2MBase::MessageType type)
    {
        registry._notification_send_ongoing = true;
        registry.store_to_response_list(uri, id, type);
    }
    static bool add(M2MNsdlInterface &registry, M2MBase *object) { return registry.add_object_to_list(object); }
    static bool sending(const M2MNsdlInterface &registry) { return registry._notification_send_ongoing; }
    static bool has_response(M2MNsdlInterface &registry, int32_t id) { return registry.find_response(id) != NULL; }
    static void remove(M2MNsdlInterface &registry, const char *uri) { registry.remove_items_from_response_list_for_uri(uri); }
};

class Observer : public M2MNsdlObserver, public M2MConnectionObserver {
public:
    virtual ~Observer() {}
    unsigned messages = 0;
    unsigned sent = 0;
    uint8_t packet[128] = {};
    uint16_t packet_length = 0;
    void coap_message_ready(uint8_t *data, uint16_t length, sn_nsdl_addr_s *) override {
        ++messages;
        CHECK(length <= sizeof(packet));
        memcpy(packet, data, length);
        packet_length = length;
    }
    void client_registered(M2MServer *) override {}
    void registration_updated(const M2MServer &) override {}
    void registration_error(uint8_t, bool, bool, bool) override {}
    void client_unregistered(bool) override {}
#ifndef MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    void init_security_object(uint16_t) override {}
    void bootstrap_done() override {}
    void bootstrap_finish() override {}
    void bootstrap_wait() override {}
    void bootstrap_error_wait(const char *) override {}
    void bootstrap_error(M2MInterface::Error, const char *) override {}
#endif
    void coap_data_processed() override {}
    void value_updated(M2MBase *) override {}
    void data_available(uint8_t *, uint16_t, const SocketAddress &) override {}
    void socket_error(int, bool) override {}
    void address_ready(const SocketAddress &, ServerType, uint16_t) override {}
    void data_sent() override { ++sent; }
    void network_interface_status_change(NetworkInterfaceStatus) override {}
};

class Test_M2MConnectionHandlerPimpl_classic {
    static void socket_ready(void *) {}
public:
    static void check_send_burst() {
        Observer observer;
        M2MConnectionHandlerPimpl connection(NULL, observer, NULL, M2MInterface::UDP, M2MInterface::LwIP_IPv4);
        palSocket_t receiver = 0;
        CHECK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_DGRAM, true, PAL_NET_DEFAULT_INTERFACE, socket_ready, NULL, &receiver) == PAL_SUCCESS);
        palSocketAddress_t destination = {};
        palIpV4Addr_t loopback = {127, 0, 0, 1};
        CHECK(pal_setSockAddrIPV4Addr(&destination, loopback) == PAL_SUCCESS);
        bool bound = false;
        for (uint16_t port = 51000; port < 52000; ++port) {
            CHECK(pal_setSockAddrPort(&destination, port) == PAL_SUCCESS);
            if (pal_bind(receiver, &destination, sizeof(destination)) == PAL_SUCCESS) { bound = true; break; }
        }
        CHECK(bound);
        CHECK(pal_asynchronousSocketWithArgument(PAL_AF_INET, PAL_SOCK_DGRAM, true, PAL_NET_DEFAULT_INTERFACE, socket_ready, NULL, &connection._socket) == PAL_SUCCESS);
        memcpy((void *)&connection._socket_address, &destination, sizeof(destination));
        connection._socket_state = M2MConnectionHandlerPimpl::ESocketStateUnsecureConnection;
        sn_nsdl_addr_s address = {};
        for (unsigned i = 0; i < 8; ++i) {
            uint8_t packet[] = {0x44, 0x84, 0, static_cast<uint8_t>(i), 0x55, 0x66, 0x77, static_cast<uint8_t>(i)};
            CHECK(connection.send_data(packet, sizeof(packet), &address));
        }
        CHECK(connection._event.data.event_data);
        eventOS_scheduler_run_until_idle();
        CHECK(observer.sent == 8);
        CHECK(ns_list_get_first(&connection._linked_list_send_data) == NULL);
        for (unsigned i = 0; i < 8; ++i) {
            uint8_t packet[8] = {}; size_t received = 0;
            palStatus_t status = PAL_ERR_SOCKET_WOULD_BLOCK;
            for (unsigned attempt = 0; attempt < 1000 && status == PAL_ERR_SOCKET_WOULD_BLOCK; ++attempt) {
                status = pal_receiveFrom(receiver, packet, sizeof(packet), NULL, NULL, &received);
                if (status == PAL_ERR_SOCKET_WOULD_BLOCK) CHECK(pal_osDelay(1) == PAL_SUCCESS);
            }
            CHECK(status == PAL_SUCCESS);
            CHECK(received == sizeof(packet));
            CHECK(packet[1] == 0x84 && packet[7] == i);
        }
        CHECK(pal_close(&receiver) == PAL_SUCCESS);
    }
};

static void check_registry_lock(M2MNsdlInterface &registry, M2MBase *object, bool add)
{
    palSemaphoreID_t started = 0, finished = 0;
    CHECK(pal_osSemaphoreCreate(0, &started) == PAL_SUCCESS);
    CHECK(pal_osSemaphoreCreate(0, &finished) == PAL_SUCCESS);
    bool result = false;
    std::thread worker([&]() {
        CHECK(pal_osSemaphoreRelease(started) == PAL_SUCCESS);
        result = add ? Test_M2MNsdlInterface::add(registry, object) : registry.remove_object_from_list(object);
        CHECK(pal_osSemaphoreRelease(finished) == PAL_SUCCESS);
    });
    CHECK(pal_osSemaphoreWait(started, 3000, NULL) == PAL_SUCCESS);
    // The notification scan owns this mutex while traversing the same root list.
    CHECK(pal_osSemaphoreWait(finished, 200, NULL) == PAL_ERR_RTOS_TIMEOUT);
    eventOS_scheduler_mutex_release();
    CHECK(pal_osSemaphoreWait(finished, 3000, NULL) == PAL_SUCCESS);
    worker.join();
    eventOS_scheduler_mutex_wait();
    CHECK(result);
    CHECK(pal_osSemaphoreDelete(&started) == PAL_SUCCESS);
    CHECK(pal_osSemaphoreDelete(&finished) == PAL_SUCCESS);
}

static M2MResource *populate(M2MObject *object)
{
    CHECK(object != NULL);
    M2MObjectInstance *instance = object->create_object_instance(static_cast<uint16_t>(0));
    CHECK(instance != NULL);
    M2MResource *resource = instance->create_dynamic_resource("1", "Counter", M2MResourceInstance::INTEGER, true);
    CHECK(resource != NULL);
    CHECK(resource->set_value(static_cast<int64_t>(1500)));
    return resource;
}


static unsigned registration_acknowledgments = 0;
static uint8_t registration_ack(struct nsdl_s *, sn_coap_hdr_s *, sn_nsdl_addr_s *)
{
    ++registration_acknowledgments;
    return 0;
}

static std::string registration_body(nsdl_s *handle)
{
    sn_coap_hdr_s message;
    sn_coap_parser_init_message(&message);
    CHECK(sn_nsdl_build_registration_body(handle, &message, 1) == SN_NSDL_SUCCESS);
    std::string body;
    if (message.payload_len) body.assign(reinterpret_cast<char *>(message.payload_ptr), message.payload_len);
    handle->sn_nsdl_free(message.payload_ptr);
    return body;
}

static void check_registration_retry(M2MNsdlInterface &registry)
{
    nsdl_s *handle = registry.get_nsdl_handle();
    M2MObject *retained = M2MInterfaceFactory::create_object("13003");
    populate(retained);
    M2MBaseList existing;
    existing.push_back(retained);
    CHECK(registry.create_nsdl_list_structure(existing));
    for (sn_nsdl_dynamic_resource_parameters_s *item = sn_grs_get_first_resource(handle->grs); item;
         item = sn_grs_get_next_resource(handle->grs, item)) item->registered = SN_NDSL_RESOURCE_REGISTERED;

    M2MEndpoint *endpoint = M2MInterfaceFactory::create_endpoint(String("registration-retry"));
    CHECK(endpoint != NULL);
    M2MResource *resource = populate(endpoint->create_object(String("12005")));
    M2MBaseList added;
    added.push_back(endpoint);
    CHECK(registry.create_nsdl_list_structure(added));
    const std::string first = registration_body(handle);
    CHECK(first.find("registration-retry") != std::string::npos);
    CHECK(first.find("13003") == std::string::npos);
    // A failed send or full retransmission queue must not consume the delta.
    const std::string retry = registration_body(handle);
    CHECK(retry == first);
    CHECK(resource->get_nsdl_resource()->registered == SN_NDSL_RESOURCE_REGISTERING);

    M2MObject *late = M2MInterfaceFactory::create_object("13004");
    M2MResource *late_resource = populate(late);
    M2MBaseList next;
    next.push_back(late);
    CHECK(registry.create_nsdl_list_structure(next));
    auto previous_callback = handle->sn_nsdl_rx_callback;
    handle->sn_nsdl_rx_callback = registration_ack;
    handle->update_register_token = 0x12345678;
    sn_coap_hdr_s *ack = sn_coap_parser_alloc_message(handle->grs->coap);
    CHECK(ack != NULL);
    ack->msg_type = COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    ack->msg_code = COAP_MSG_CODE_RESPONSE_CHANGED;
    ack->token_len = static_cast<uint8_t>(sizeof(handle->update_register_token));
    ack->token_ptr = static_cast<uint8_t *>(handle->sn_nsdl_alloc(ack->token_len));
    CHECK(ack->token_ptr != NULL);
    memcpy(ack->token_ptr, &handle->update_register_token, ack->token_len);
    uint8_t address[] = {127, 0, 0, 1};
    sn_nsdl_addr_s source = {};
    source.addr_ptr = address;
    source.addr_len = static_cast<uint8_t>(sizeof(address));
    source.type = SN_NSDL_ADDRESS_TYPE_IPV4;
    source.port = 5683;
    CHECK(sn_nsdl_process_coap(handle, ack, &source) == SN_NSDL_SUCCESS);
    handle->sn_nsdl_rx_callback = previous_callback;
    CHECK(registration_acknowledgments == 1);
    CHECK(resource->get_nsdl_resource()->registered == SN_NDSL_RESOURCE_REGISTERED);
    CHECK(late_resource->get_nsdl_resource()->registered == SN_NDSL_RESOURCE_NOT_REGISTERED);
    const std::string remaining = registration_body(handle);
    CHECK(remaining.find("registration-retry") == std::string::npos);
    CHECK(remaining.find("13004") != std::string::npos);
    delete endpoint;
    delete retained;
    delete late;
}

static void check_observation_cancellation(M2MNsdlInterface &registry)
{
    M2MObject *object = M2MInterfaceFactory::create_object("13006");
    M2MResource *resource = populate(object);
    M2MBaseList list;
    list.push_back(object);
    CHECK(registry.create_nsdl_list_structure(list));
    nsdl_s *handle = registry.get_nsdl_handle();
    uint8_t token[] = {0xa1, 0xb2, 0xc3, 0xd4};
    for (unsigned round = 0; round < 3; ++round) {
        for (int observe = 0; observe <= 1; ++observe) {
            sn_coap_hdr_s request;
            sn_coap_parser_init_message(&request);
            sn_coap_options_list_s options = {};
            options.observe = observe;
            request.options_list_ptr = &options;
            request.msg_code = COAP_MSG_CODE_REQUEST_GET;
            request.msg_type = COAP_MSG_TYPE_CONFIRMABLE;
            request.token_ptr = token;
            request.token_len = static_cast<uint8_t>(sizeof(token));
            request.content_format = static_cast<sn_coap_content_format_e>(COAP_CONTENT_OMA_PLAIN_TEXT_TYPE);
            sn_coap_hdr_s *response = resource->handle_get_request(handle, &request, &registry);
            CHECK(response != NULL);
            CHECK(response->msg_code == COAP_MSG_CODE_RESPONSE_CONTENT);
            CHECK(response->options_list_ptr != NULL);
            CHECK(resource->is_under_observation() == (observe == 0));
            if (observe == 0) CHECK(response->options_list_ptr->observe >= 0);
            else CHECK(response->options_list_ptr->observe == -1);
            sn_nsdl_release_allocated_coap_msg_mem(handle, response);
        }
        ++token[0];
    }
    delete object;
}

int main(int argc, char **argv)
{
    const bool remove_only = argc == 2 && strcmp(argv[1], "--remove-lock-only") == 0;
    CHECK(argc == 1 || remove_only);
    const char *storage = "./endpoint-registry-storage";
    palStatus_t created = pal_fsMkDir(storage);
    CHECK(created == PAL_SUCCESS || created == PAL_ERR_FS_NAME_ALREADY_EXIST);
    CHECK(pal_fsSetMountPoint(PAL_FS_PARTITION_PRIMARY, storage) == PAL_SUCCESS);
    CHECK(pal_fsSetMountPoint(PAL_FS_PARTITION_SECONDARY, storage) == PAL_SUCCESS);
    CHECK(pal_init() == PAL_SUCCESS);
    ns_hal_init(NULL, 65536, NULL, NULL);
    {
        Observer observer;
        M2MConnectionHandler connection(observer, NULL, M2MInterface::TCP, M2MInterface::LwIP_IPv4);
        M2MNsdlInterface registry(observer, connection);
        eventOS_scheduler_mutex_wait();
        Test_M2MConnectionHandlerPimpl_classic::check_send_burst();
        check_registration_retry(registry);
        check_observation_cancellation(registry);
        M2MObject *concurrent = M2MInterfaceFactory::create_object("13002");
        CHECK(concurrent != NULL);
        if (remove_only) {
            CHECK(Test_M2MNsdlInterface::add(registry, concurrent));
        } else {
            check_registry_lock(registry, concurrent, true);
        }
        check_registry_lock(registry, concurrent, false);
        CHECK(!registry.remove_object_from_list(concurrent));
        delete concurrent;
        M2MObject *ordinary = M2MInterfaceFactory::create_object("13000");
        populate(ordinary);
        M2MBaseList ordinary_list;
        ordinary_list.push_back(ordinary);
        CHECK(registry.create_nsdl_list_structure(ordinary_list));
        static_cast<M2MObservationHandler &>(registry).remove_object(ordinary);
        CHECK(!registry.remove_object_from_list(ordinary));
        delete ordinary;
        M2MObject *retained = M2MInterfaceFactory::create_object("13001");
        populate(retained);
        M2MBaseList retained_list;
        retained_list.push_back(retained);
        CHECK(registry.create_nsdl_list_structure(retained_list));
        for (int round = 0; round < 64; ++round) {
            M2MEndpoint *endpoint = M2MInterfaceFactory::create_endpoint(String("registry-replacement"));
            CHECK(endpoint != NULL);
            populate(endpoint->create_object(String("12005")));
            M2MBaseList list;
            list.push_back(endpoint);
            CHECK(registry.create_nsdl_list_structure(list));
            if (round % 2 == 0) {
                static_cast<M2MObservationHandler &>(registry).remove_object(endpoint);
                CHECK(!registry.remove_object_from_list(endpoint));
                static_cast<M2MObservationHandler &>(registry).remove_object(endpoint);
                delete endpoint;
            } else {
                delete endpoint;
                CHECK(!registry.remove_object_from_list(endpoint));
            }
        }
        for (int round = 0; round < 64; ++round) {
            M2MEndpoint *endpoint = M2MInterfaceFactory::create_endpoint(String("observed-replacement"));
            CHECK(endpoint != NULL);
            M2MResource *resource = populate(endpoint->create_object(String("12005")));
            M2MBaseList list;
            list.push_back(endpoint);
            CHECK(registry.create_nsdl_list_structure(list));
            Test_M2MNsdlInterface::pending(registry, resource->uri_path(), 100 + round, M2MBase::NOTIFICATION);
            CHECK(Test_M2MNsdlInterface::has_response(registry, 100 + round));
            delete endpoint;
            CHECK(!Test_M2MNsdlInterface::has_response(registry, 100 + round));
            CHECK(!Test_M2MNsdlInterface::sending(registry));
            eventOS_scheduler_run_until_idle();
        }
        Test_M2MNsdlInterface::pending(registry, "13001/0/1", 300, M2MBase::NOTIFICATION);
        Test_M2MNsdlInterface::pending(registry, "unrelated", 301, M2MBase::DELAYED_POST_RESPONSE);
        Test_M2MNsdlInterface::remove(registry, "unrelated");
        CHECK(Test_M2MNsdlInterface::sending(registry));
        CHECK(Test_M2MNsdlInterface::has_response(registry, 300));
        CHECK(!Test_M2MNsdlInterface::has_response(registry, 301));
        Test_M2MNsdlInterface::remove(registry, "not-present");
        CHECK(Test_M2MNsdlInterface::sending(registry));
        CHECK(registry.remove_object_from_list(retained));
        delete retained;
        CHECK(!Test_M2MNsdlInterface::sending(registry));
        eventOS_scheduler_run_until_idle();
        M2MEndpoint *observed = M2MInterfaceFactory::create_endpoint(String("termination"));
        CHECK(observed != NULL);
        M2MResource *resource = populate(observed->create_object(String("12005")));
        M2MBaseList observed_list;
        observed_list.push_back(observed);
        CHECK(registry.create_nsdl_list_structure(observed_list));
        const uint8_t token[] = {0x12, 0x34, 0x56, 0x78};
        resource->set_under_observation(true, &registry);
        resource->report_handler()->set_observation_token(token, static_cast<uint8_t>(sizeof(token)));
        nsdl_s *handle = registry.get_nsdl_handle();
        handle->server_address.addr_ptr = static_cast<uint8_t *>(malloc(4));
        CHECK(handle->server_address.addr_ptr != NULL);
        const uint8_t address[] = {127, 0, 0, 1};
        memcpy(handle->server_address.addr_ptr, address, sizeof(address));
        handle->server_address.addr_len = static_cast<uint8_t>(sizeof(address));
        handle->server_address.port = 5683;
        handle->server_address.type = SN_NSDL_ADDRESS_TYPE_IPV4;
        registry.set_registration_status(true);
        delete observed;
        CHECK(observer.messages == 1);
        CHECK(observer.packet_length == static_cast<uint16_t>(4 + sizeof(token)));
        CHECK((observer.packet[0] & 0x0f) == static_cast<int>(sizeof(token)));
        CHECK(observer.packet[1] == COAP_MSG_CODE_RESPONSE_NOT_FOUND);
        CHECK(memcmp(observer.packet + 4, token, sizeof(token)) == 0);
        eventOS_scheduler_run_until_idle();
        CHECK(sn_nsdl_clear_coap_resending_queue(handle) == SN_NSDL_SUCCESS);
        M2MEndpoint *burst = M2MInterfaceFactory::create_endpoint(String("termination-burst"));
        for (unsigned i = 0; i < 8; ++i) {
            char name[8]; snprintf(name, sizeof(name), "%u", 13010 + i);
            M2MResource *leaf = populate(burst->create_object(String(name)));
            uint8_t key[] = {0x55, 0x66, 0x77, static_cast<uint8_t>(i)};
            leaf->set_under_observation(true, &registry);
            leaf->report_handler()->set_observation_token(key, static_cast<uint8_t>(sizeof(key)));
        }
        M2MBaseList burst_list; burst_list.push_back(burst);
        CHECK(registry.create_nsdl_list_structure(burst_list));
        observer.messages = 0;
        delete burst;
        CHECK(observer.messages == 8);
        registry.set_registration_status(false);
        eventOS_scheduler_mutex_release();
    }
    ns_event_loop_thread_stop();
    puts("PASS send queue bursts, observation cancellation, registration retry, endpoint replacement and termination");
    return 0;
}
