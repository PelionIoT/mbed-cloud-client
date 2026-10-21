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
    void data_sent() override {}
    void network_interface_status_change(NetworkInterfaceStatus) override {}
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
        check_registration_retry(registry);
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
        registry.set_registration_status(false);
        eventOS_scheduler_mutex_release();
    }
    ns_event_loop_thread_stop();
    puts("PASS registration retry, registry mutation locking, endpoint replacement, in-flight cleanup and terminal observation packet");
    return 0;
}
