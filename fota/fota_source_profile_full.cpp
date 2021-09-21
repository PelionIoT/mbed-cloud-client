// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE
#if (MBED_CLOUD_CLIENT_PROFILE == MBED_CLOUD_CLIENT_PROFILE_FULL) && !defined(FOTA_UNIT_TEST)

#define TRACE_GROUP "FOTA"

#include "fota/fota_source.h"
#include "fota/fota_source_defs.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_status.h"
#include "fota/fota_internal.h"
#include "fota/fota.h"
#include "fota/fota_event_handler.h"
#include "fota/fota_component_defs.h"
#include "fota/fota_component_internal.h"

#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobject.h"

#include <stdlib.h>

static M2MInterface *g_m2m = NULL;
static M2MResource *g_manifest_resource = NULL;  // /10252/0/1
static M2MResource *g_state_resource = NULL;  // /10252/0/2
static M2MResource *g_update_result_resource = NULL;  // /10252/0/3
static M2MResource *g_update_customer_result_resource = NULL;  // /10252/0/4
static M2MObject *g_lwm2m_manifest_object = NULL; //10252
static M2MObject *g_lwm2m_dev_metadata_object = NULL; //10255
#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 0)
static M2MObject *g_component_lwm2m_object = NULL;  // /14
#endif

static report_sent_callback_t g_on_sent_callback = NULL;
static report_sent_callback_t g_on_failure_callback = NULL;
static bool auto_observable_reporting_enabled;
static bool report_state_random_delay_enabled = false;

typedef struct {
    size_t max_frag_size;
    bool   allow_unaligned_fragments;
} fota_source_config_t;

fota_source_config_t fota_source_config = {
#ifdef SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE
    .max_frag_size = SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE,
    // COAP doesn't allow non aligned fragments.
    // TODO: Make sure it's true in all cases
    .allow_unaligned_fragments = false,
#else
    // This is true in tests only currently, so values will be set by test code.
    .max_frag_size = 0,
    .allow_unaligned_fragments = false,
#endif
};

static void got_manifest_callback(void *arguments)
{
    // recast parameter
    M2MResource::M2MExecuteParameter *parameters =
        static_cast<M2MResource::M2MExecuteParameter *>(arguments);

    /* read payload */
    uint8_t *buffer = (uint8_t *) parameters->get_argument_value();
    uint16_t length = parameters->get_argument_value_length();

    fota_state_e fota_state;

    int ret = fota_is_ready(buffer, length, &fota_state);

    if (ret == FOTA_STATUS_OUT_OF_MEMORY) {
        goto fail;
    }

    switch (fota_state) {
        case FOTA_STATE_IDLE: {

            // TODO: do we really need it?
            if (!g_state_resource->set_value(-1)) {
                FOTA_DBG_ASSERT(!"g_state_resource->set_value(int) failed");
            }

            if (!g_update_result_resource->set_value(-1)) {
                FOTA_DBG_ASSERT(!"g_update_result_resource->set_value(int) failed");
            }

#if 0
            fota_event_handler_defer_with_data(fota_on_manifest, buffer, length);
#endif
            // Call directly instead of deferring (like the commented out code above),
            // as manifest handling is short now
            fota_on_manifest(buffer, length);
            return;
        }
        case FOTA_STATE_INVALID:
            FOTA_TRACE_ERROR("FOTA cannot handle manifest - rejecting");
        // fallthrough
        default:
            break;
    }

fail:
    // Reset tainted buffer
    memset(buffer, 0, length);
    //TODO: report COAP_MSG_CODE_RESPONSE_PRECONDITION_FAILED
    g_manifest_resource->send_delayed_post_response();
    //parameters->get_resource()->send_delayed_post_response();
}


void fota_source_send_manifest_received_ack(void)
{
    FOTA_DBG_ASSERT(g_m2m);
    g_manifest_resource->send_delayed_post_response();
}

// static void notification_status(
//     const M2MBase& base,
//     const MessageDeliveryStatus status,
//     const MessageType type,
//     void *client_args
// )
static void notification_status(
    const M2MBase &base,
    const M2MBase::MessageDeliveryStatus delivery_status,
    const M2MBase::MessageType type,
    void *client_args
)
{
    (void)base;
    (void)client_args;

    FOTA_TRACE_DEBUG(
        "Callback for resource: /%s status: %d type: %d",
        base.uri_path(),
        (int)delivery_status,
        (int)type
    );

    if (M2MBase::NOTIFICATION != type) {
        return;
    }

    report_sent_callback_t callback = NULL;
    switch (delivery_status) {
        case M2MBase::MESSAGE_STATUS_DELIVERED:
            // Notification has been ACKed by server, complete to callback
            callback = g_on_sent_callback;
            break;
        case M2MBase::MESSAGE_STATUS_BUILD_ERROR:  // fall through
        case M2MBase::MESSAGE_STATUS_RESEND_QUEUE_FULL:  // fall through
        case M2MBase::MESSAGE_STATUS_SEND_FAILED:  // fall through
        case M2MBase::MESSAGE_STATUS_UNSUBSCRIBED:  // fall through
        case M2MBase::MESSAGE_STATUS_REJECTED:
            FOTA_TRACE_ERROR(
                "Received Notification delivery resource: /%s status: %d - ERROR!",
                base.uri_path(),
                delivery_status
            );
            callback = g_on_failure_callback;
            break;
        default:
            return;
    }


    g_on_sent_callback = NULL;
    g_on_failure_callback = NULL;
    if (callback) {
        callback();
    }
}

#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 1)
/*
 * Converting binary array to hex string
 *
 * /param in[in] binary array to convert
 * /param input_size[in] binary array size
 * /param out[out] buffer should be allocated in calling function doubled size plus one for null termination.
 * /param output_size[in] output hex string length
 *
 */

static void bin_to_hex_string(const uint8_t *in, size_t input_size, uint8_t *out, size_t output_size)
{
    FOTA_DBG_ASSERT(in && out && input_size != 0 && (input_size * 2 + 1) == output_size);

    const uint8_t *p_in = in;
    const char *hex_arr = "0123456789ABCDEF";

    uint8_t *p_out = out;

    for (; p_in < in + input_size; p_out += 2, p_in++) {
        p_out[0] = hex_arr[(*p_in >> 4) & 0xF];
        p_out[1] = hex_arr[*p_in & 0xF];
    }

    p_out[0] = 0;
}
#endif


void fota_source_set_config(size_t max_frag_size, bool allow_unaligned_fragments)
{
    fota_source_config.allow_unaligned_fragments = allow_unaligned_fragments;
    fota_source_config.max_frag_size = max_frag_size;
}

int fota_source_init(
    void *m2m_interface, void *resource_list,
    const uint8_t *vendor_id, uint32_t vendor_id_size,
    const uint8_t *class_id, uint32_t class_id_size,
    const uint8_t *curr_fw_digest, uint32_t curr_fw_digest_size,
    uint64_t curr_fw_version,
    fota_source_state_e source_state)
{
    if (g_m2m) {
        return FOTA_STATUS_SUCCESS;
    }
    FOTA_DBG_ASSERT(resource_list);

    FOTA_DBG_ASSERT(fota_source_config.max_frag_size);

#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 1)
    uint8_t str_digest[FOTA_CRYPTO_HASH_SIZE * 2 + 1];
#endif

    static M2MBaseList *m2m_object_list = (M2MBaseList *)resource_list;

    g_m2m = (M2MInterface *)m2m_interface;

    g_lwm2m_manifest_object = M2MInterfaceFactory::create_object("10252");//Manifest
    FOTA_ASSERT(g_lwm2m_manifest_object);

    // Create first (and only) instance /10252/0
    M2MObjectInstance *lwm2m_object_instance = g_lwm2m_manifest_object->create_object_instance();
    FOTA_ASSERT(lwm2m_object_instance);

    // Create package resource /10252/0/1
    g_manifest_resource = lwm2m_object_instance->create_dynamic_resource(
                              "1",
                              "Package",
                              M2MResourceInstance::OPAQUE,
                              false // observable
                          );
    FOTA_ASSERT(g_manifest_resource);
    g_manifest_resource->set_operation(M2MBase::POST_ALLOWED);
    g_manifest_resource->set_execute_function(got_manifest_callback);
    g_manifest_resource->set_delayed_response(true);  // The delayed response if for processing heavier loads

    // Create state resource /10252/0/2
    g_state_resource = lwm2m_object_instance->create_dynamic_resource(
                           "2",
                           "State",
                           M2MResourceInstance::INTEGER,
                           true // observable
                       );
    FOTA_ASSERT(g_state_resource);
    g_state_resource->set_operation(M2MBase::GET_ALLOWED);
    g_state_resource->set_message_delivery_status_cb(notification_status, NULL);
    FOTA_TRACE_DEBUG("Announcing FOTA state is %d", source_state);
    g_state_resource->set_value(source_state);
    g_state_resource->publish_value_in_registration_msg(true);
    g_state_resource->set_auto_observable(true);

    // Create update result resource /10252/0/3
    g_update_result_resource = lwm2m_object_instance->create_dynamic_resource(
                                   "3",
                                   "UpdateResult",
                                   M2MResourceInstance::INTEGER,
                                   true // observable
                               );
    FOTA_ASSERT(g_update_result_resource);
    g_update_result_resource->set_operation(M2MBase::GET_ALLOWED);
    g_update_result_resource->set_message_delivery_status_cb(notification_status, NULL);
    g_update_result_resource->set_value(-1);
    g_update_result_resource->publish_value_in_registration_msg(true);
    g_update_result_resource->set_auto_observable(true);

    // Create update customer result resource /10252/0/4
    g_update_customer_result_resource = lwm2m_object_instance->create_dynamic_resource(
                                   "4",
                                   "CustomerUpdateResult",
                                   M2MResourceInstance::INTEGER,
                                   true // observable
                               );
    FOTA_ASSERT(g_update_customer_result_resource);
    g_update_customer_result_resource->set_operation(M2MBase::GET_ALLOWED);
    g_update_customer_result_resource->set_message_delivery_status_cb(notification_status, NULL);
    g_update_customer_result_resource->publish_value_in_registration_msg(false);
    g_update_customer_result_resource->set_auto_observable(true);

#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 1)
    // Create package name resource /10252/0/5
    FOTA_DBG_ASSERT(curr_fw_digest_size == FOTA_CRYPTO_HASH_SIZE);

    bin_to_hex_string(curr_fw_digest, FOTA_CRYPTO_HASH_SIZE, str_digest, FOTA_CRYPTO_HASH_SIZE * 2 + 1);

    M2MResource *pkg_name_resource = lwm2m_object_instance->create_dynamic_resource(
                                         "5",
                                         "PkgName",
                                         M2MResourceInstance::STRING,
                                         false // observable
                                     );
    FOTA_ASSERT(pkg_name_resource);
    pkg_name_resource->set_operation(M2MBase::GET_ALLOWED);
    pkg_name_resource->set_value(str_digest, curr_fw_digest_size);
    pkg_name_resource->publish_value_in_registration_msg(true);
    pkg_name_resource->set_auto_observable(true):
#else
    // Create dummy resource for server
    M2MResource *pkg_name_resource = lwm2m_object_instance->create_dynamic_resource(
                                         "5",
                                         "PkgName",
                                         M2MResourceInstance::STRING,
                                         false // observable
                                     );
    FOTA_ASSERT(pkg_name_resource);
    pkg_name_resource->set_auto_observable(true);
#endif

#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 1 || MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION < 3)
    // Create package version resource /10252/0/6
    FOTA_TRACE_DEBUG("Announcing version is %" PRIu64, curr_fw_version);
    M2MResource *pkg_version_resource = lwm2m_object_instance->create_dynamic_resource(
                                            "6",
                                            "PkgVersion",
                                            M2MResourceInstance::INTEGER,
                                            false // observable
                                        );
    FOTA_ASSERT(pkg_version_resource);
    pkg_version_resource->set_operation(M2MBase::GET_ALLOWED);
    pkg_version_resource->set_value(curr_fw_version);
    pkg_version_resource->publish_value_in_registration_msg(true);
    pkg_version_resource->set_auto_observable(true);
#else
    // Create dummy resource for server
    M2MResource *pkg_version_resource = lwm2m_object_instance->create_dynamic_resource(
                                            "6",
                                            "PkgVersion",
                                            M2MResourceInstance::INTEGER,
                                            false // observable
                                        );
    FOTA_ASSERT(pkg_version_resource);
    pkg_version_resource->set_auto_observable(true);
#endif

    m2m_object_list->push_back(g_lwm2m_manifest_object);

    g_lwm2m_dev_metadata_object = M2MInterfaceFactory::create_object("10255");//Device Metadata
    FOTA_ASSERT(g_lwm2m_dev_metadata_object);

    // Create first (and only) instance /10255/0
    lwm2m_object_instance = g_lwm2m_dev_metadata_object->create_object_instance();
    FOTA_ASSERT(lwm2m_object_instance);

    // Create protocol supported resource  /10255/0/0
    M2MResource *resource = lwm2m_object_instance->create_dynamic_resource(
                                "0",
                                "ProtocolSupported",
                                M2MResourceInstance::INTEGER,
                                false // observable
                            );
    FOTA_ASSERT(resource);
    resource->set_operation(M2MBase::GET_ALLOWED);
    resource->set_value(FOTA_MCCP_PROTOCOL_VERSION);
    resource->publish_value_in_registration_msg(true);
    resource->set_auto_observable(true);


    // Create vendor resource /10255/0/2
    resource = lwm2m_object_instance->create_dynamic_resource(
                   "3",
                   "Vendor",
                   M2MResourceInstance::OPAQUE,
                   false // observable
               );
    resource->set_operation(M2MBase::GET_ALLOWED);
    resource->set_value(vendor_id, vendor_id_size);
    resource->publish_value_in_registration_msg(true);
    resource->set_auto_observable(true);

    // Create class resource  /10255/0/4
    resource = lwm2m_object_instance->create_dynamic_resource(
                   "4",
                   "Class",
                   M2MResourceInstance::OPAQUE,
                   false // observable
               );
    FOTA_ASSERT(resource);
    resource->set_operation(M2MBase::GET_ALLOWED);
    resource->set_value(class_id, class_id_size);
    resource->publish_value_in_registration_msg(true);
    resource->set_auto_observable(true);

    m2m_object_list->push_back(g_lwm2m_dev_metadata_object);

#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 0)
    // Create
    g_component_lwm2m_object = M2MInterfaceFactory::create_object("14");
    FOTA_ASSERT(g_component_lwm2m_object);

    m2m_object_list->push_back(g_component_lwm2m_object);
#endif

    fota_source_enable_auto_observable_resources_reporting(true);
    report_state_random_delay(false);
    return FOTA_STATUS_SUCCESS;
}

int fota_source_add_component(unsigned int comp_id, const char *name, const char *sem_ver)
{
#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 0)
    // Create first (and only) instance /14/<comp_id>
    M2MObjectInstance *lwm2m_object_instance = g_component_lwm2m_object->create_object_instance(comp_id);
    FOTA_ASSERT(lwm2m_object_instance);

    // Create Component Identity resource /14/<comp_id>/0
    M2MResource *resource = lwm2m_object_instance->create_dynamic_resource(
                                "0", "Component Identity", M2MResourceInstance::STRING, false
                            );
    FOTA_ASSERT(resource);
    resource->set_operation(M2MBase::GET_ALLOWED);
    resource->set_value((uint8_t *) name, strlen(name));
    resource->publish_value_in_registration_msg(true);

    // Create Component Version resource /14/<comp_id>/2
    resource = lwm2m_object_instance->create_dynamic_resource(
                   "2", "Component Version", M2MResourceInstance::STRING, false
               );
    FOTA_ASSERT(resource);
    resource->set_operation(M2MBase::GET_ALLOWED);
    resource->set_value((uint8_t *) sem_ver, strlen(sem_ver));
    resource->publish_value_in_registration_msg(true);
#endif

    return FOTA_STATUS_SUCCESS;
}

int fota_source_deinit(void)
{
    g_manifest_resource = NULL;
    g_state_resource = NULL;
    g_update_result_resource = NULL;
    delete g_lwm2m_manifest_object;
    delete g_lwm2m_dev_metadata_object;
    g_lwm2m_manifest_object = NULL;
    g_lwm2m_dev_metadata_object = NULL;
#if (FOTA_SOURCE_LEGACY_OBJECTS_REPORT == 0)
    delete g_component_lwm2m_object;
    g_component_lwm2m_object = NULL;
#endif
    g_on_sent_callback = NULL;
    g_on_failure_callback = NULL;
    g_m2m = NULL;

    return FOTA_STATUS_SUCCESS;
}

static int report_int(M2MResource *resource, int value, report_sent_callback_t on_sent, report_sent_callback_t on_failure)
{
    // Auto observable resources reporting not enabled - call the on sent callback ourselves here
    if (!auto_observable_reporting_enabled) {
        if (on_sent) {
            on_sent();
        }
        return FOTA_STATUS_SUCCESS;
    }

    FOTA_DBG_ASSERT(!(on_sent && g_on_sent_callback));
    FOTA_DBG_ASSERT(!(on_failure && g_on_failure_callback));

    // must assign values before calling registry_set_value_int because of special way unit-tests are implemented
    g_on_sent_callback = on_sent;
    g_on_failure_callback = on_failure;

    FOTA_TRACE_DEBUG(
        "Reporting resource: /%s: value: %d",
        resource->uri_path(),
        value
    );
    if (!resource->set_value(value)) {
        g_on_sent_callback = NULL;
        g_on_failure_callback = NULL;
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

static void on_random_state_report(void *data, size_t size)
{
    (void)size;  // unused param
    fota_random_state_report_params_t *params = (fota_random_state_report_params_t *)data;
    report_int(g_state_resource, (int)params->state, params->on_sent, params->on_failure);  // 10252/0/2
}

static size_t fota_get_random_delay_ms()
{
    return (rand() % RANDOM_DELAY_RANGE_IN_SEC) * 1000;
}

int fota_source_report_state_in_ms(fota_source_state_e state, report_sent_callback_t on_sent, report_sent_callback_t on_failure, size_t in_ms)
{
    if (in_ms) {
        fota_random_state_report_params_t params;
        params.state = state;
        params.on_sent = on_sent;
        params.on_failure = on_failure;
        FOTA_TRACE_DEBUG("fota_source_report_state_in_ms sent delayed state %d in_ms %zu", state, in_ms);
        return fota_event_handler_defer_with_data_in_ms(on_random_state_report, &params, sizeof(params), in_ms, EVENT_RANDOM_DELAY);
    }

    return report_int(g_state_resource, (int)state, on_sent, on_failure);  // 10252/0/2
}

void report_state_random_delay(bool enable)
{
    report_state_random_delay_enabled = enable;
}

int fota_source_report_state(fota_source_state_e state, report_sent_callback_t on_sent, report_sent_callback_t on_failure)
{
    if (report_state_random_delay_enabled) {
        return fota_source_report_state_in_ms(state, on_sent, on_failure, fota_get_random_delay_ms());
    }

    return fota_source_report_state_in_ms(state, on_sent, on_failure, 0);
}

int fota_source_report_update_customer_result(int result)
{
    return report_int(g_update_customer_result_resource, result, NULL, NULL);  // 10252/0/4
}

int fota_source_report_update_result(int result)
{
    return report_int(g_update_result_resource, result, NULL, NULL);  // 10252/0/3
}

static void data_req_callback(
    const uint8_t *buffer, size_t buffer_size,
    size_t total_size,
    bool last_block,
    void *context
)
{
    bool is_active = fota_is_active_update();
    if (is_active) {
        // Extract original offset from context
        size_t offset = (size_t) context;
        if (!fota_source_config.allow_unaligned_fragments) {
            size_t extra = offset % fota_source_config.max_frag_size;
            buffer_size -= extra;
            buffer += extra;
        }
        // removing const qualifier here allows FOTA the manipulation of fragment data in place (like encryption).
        // TODO: Need to decide whether this is legit. If so, all preceding LWM2M calls should also remove this qualifier.
        fota_on_fragment((uint8_t *)buffer, buffer_size);
    } else {
        FOTA_TRACE_ERROR("Fragment received ignored - FOTA not ready");
    }
}

static void data_req_error_callback(request_error_t error_code, void *context)
{
    bool is_active = fota_is_active_update();
    if (is_active) {
        fota_event_handler_defer_with_result(fota_on_fragment_failure, (int32_t)error_code);
    } else {
        FOTA_TRACE_ERROR("Fragment received error ignored - FOTA not ready");
    }
}

int fota_source_firmware_request_fragment(const char *uri, size_t offset)
{
    size_t extra = 0;
    if (!fota_source_config.allow_unaligned_fragments) {
        extra = offset % fota_source_config.max_frag_size;
    }

    // Make sure that offset is aligned to fragment size in case limited by platform (like currently in COAP)
    // Send original offset in context for callback
    g_m2m->get_data_request(
        FIRMWARE_DOWNLOAD,  // type
        uri,  // uri
        offset - extra,  // offset
        true,  //async
        data_req_callback,  // data_cb
        data_req_error_callback,  // error_cb
        (void *) offset  // context
    );

    return FOTA_STATUS_SUCCESS;
}

void fota_source_enable_auto_observable_resources_reporting(bool enable)
{
    auto_observable_reporting_enabled = enable;
}

#endif  // (MBED_CLOUD_CLIENT_PROFILE == MBED_CLOUD_CLIENT_PROFILE_FULL)
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
