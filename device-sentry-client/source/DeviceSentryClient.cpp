// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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
#include <stdio.h>
#include "DeviceSentryClient.h"
#include "MbedCloudClient.h"
#include "pv_error_handling.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2minterface.h"
#include "eventOS_scheduler.h"
#include "eventOS_event_timer.h"
#include "eventOS_event.h"
#include "ds_status.h"
#include "tinycbor.h"
#include "ds_plat_metrics_report.h"
#include "ds_internal.h"
#include "ds_plat_defs.h"
#include "key_config_manager.h"
#include "ds_custom_metrics_internal.h"
#include "ds_custom_metrics.h"

#ifdef DS_TEST_API
#include "ds_test_metrics_report.h"
#endif

//Configuration: 'Metrics Collection' (35012) over resource 'Configure' (27004)
//Observation: 'Metrics Collection' (35012) over resource 'Observation' (27005)
#define DEVICE_SENTRY_OBJECT "35012"
#define DEVICE_SENTRY_CONFIGURATION_RSC "27004"
#define DEVICE_SENTRY_OBSERVATION_RSC "27005"

#define MBED_OS_INVALID_HANDLER_ID (-1)

// Event type that is part of the arm_event_s structure.
enum event_type_e {
    EVENT_TYPE_INIT, // Init event id - will do nothing currently, initialization called by mbed cloud client.
    EVENT_TYPE_COLLECT_AND_SEND_METRICS, // Collect metrics and send to Pelion event id
    EVENT_TYPE_MAX = 0xff // Must fit in a uint8_t (field in the arm_event_s struct)
};

char active_conf_filename[] = "active.metrics.conf";

typedef struct {
    bool is_initialized;
    char policy_id[POLICY_ID_LEN];
    bool is_policy_id_initialized;
    M2MObject* resource_object;
    M2MResource* metrics_resource;
    M2MResource* config_resource;
    uint32_t device_metrics_report_intervals[DS_MAX_METRIC_NUMBER]; // metric is active when it's report interval != 0
                                                     // metric is inactive, when it's interval = 0

    ds_custom_metric_t custom_metrics[DS_MAX_NUMBER_OF_CUSTOM_METRICS];           // custom metric array
    ds_custom_metric_value_getter_t custom_metric_value_getter_cb;    // custom metric getter 
    void* user_context;                              // user context

    uint32_t min_report_interval_sec;   // minimal report interval for active configuration in seconds.
                                        // will be equal to the minimal report interval between metrics, 
                                        // or 0 when there is no active configuration.

    int8_t event_handler_id;            // ID of the handler we register to the MbedCloudClient event loop

    arm_event_storage_t* timer_event_handle; // handle to the timer event (when active)

} device_sentry_context_s;


static device_sentry_context_s ds_ctx = {
    .is_initialized = false,
    .policy_id = {0},
    .is_policy_id_initialized = false,
    .resource_object = NULL,
    .metrics_resource = NULL, 
    .config_resource = NULL, 
    .device_metrics_report_intervals = {}, 
    .custom_metrics = {}, 
    .custom_metric_value_getter_cb = NULL,
    .user_context = NULL,
    .min_report_interval_sec = 0,
    .event_handler_id = MBED_OS_INVALID_HANDLER_ID, 
    .timer_event_handle = NULL
};

/**
* \brief The function that handles all the DeviceInsigtsClient events.
* Create a report and sends to Pelion.
*
* \param event event that should be handled.
*/
static void event_handler(arm_event_s* event);

/**
* \brief 
* Create an arm_event_s object and requests new timer according to the minimal report interval. 
* The event object will have an application level priority
*
* \param event_type An event identifier
*/
static ds_status_e schedule_event(event_type_e event_type);

/**
* \brief Callback function that is called when we get a POST message to config_resource.
* Runs in network context of the event loop.
* This function extracts and handles network buffer which is metrics collection configuration message. 
*
* \param arg a M2MResource::M2MExecuteParameter argument.
*/
static void metrics_config_callback(void *arg);

/**
* \brief Parse received configurational message and initialize metrics collection intervals.
*
* \param metric_configuration_data metric configuration data in cbor format.
*/
static ds_status_e start_metrics_collection_config_message_handle(CborValue *metric_configuration_data);

/**
* \brief Stop sending all metrics
*/
static ds_status_e stop_metrics_collection_config_message_handle();

/**
* \brief Encode all NOT labeled metrics that should be reported into cbor buffer.
*
* \param main_array pointer to relevant main_array to which the metric should be encoded.
*/
static ds_status_e metrics_report_not_labeled_encode(CborEncoder *main_array);

/**
* \brief Encode all labeled metrics that should be reported into cbor buffer.
*
* \param main_array pointer to relevant main_array to which the metric should be encoded.
*/
static ds_status_e metrics_report_labeled_encode(CborEncoder *main_array);

/**
 * @brief Releases LWM2M objects
 */
static void release_objects();

/**
 * @brief Calculates and returns minimal report interval according to the Device Sentry
 * metric sending policy. 
 * 
 * @return uint32_t minimal report interval according to the Device Sentry metric sending policy. 
 */
static uint32_t min_report_interval_calculate();


/**
 * @brief Loads active metrics configuration from config file. 
 * 
 * The purpose of the active configuration file is to store the configuration over the resets. 
 * Config file contains start configuration message. 
 * 
 * If active metrics configuration was loaded successfuly from file, 
 * function schedules metric collection timer event.
 * 
 * @return DS_STATUS_SUCCESS in case of success, or ds_status_e error otherwise. 
 */
static ds_status_e load_active_config_from_file();

/**
 * @brief Saves start collection configuration message in cbor format to the persistant storage.
 * \param config_message start collection configuration message in cbor format (that should be saved to config file).
 * \param message_size start collection configuration message size in bytes.
 * @return DS_STATUS_SUCCESS in case of success, or ds_status_e error otherwise. 
 */
static ds_status_e save_active_config_to_file(const uint8_t *config_message, uint16_t message_size);

/**
 * @brief Retunrs true if metric identrified by index is active. 
 * 
 * @param index index in device sentry device_metrics_report_intervals array. 
 * @return true if metric's report interval identified by index > 0
 * @return false if metric's report interval identified by index = 0
 */
static inline bool is_metric_active_by_index(uint32_t index)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF(index >= DS_METRIC_GROUP_MAX, 
            false, "Invalid metric index = %" PRIu32, index);
    // if report interval > 0, then the metric is active, else the metric is inactive.
    return (ds_ctx.device_metrics_report_intervals[index] > 0);
}

/**
 * @brief Returns true if custom metric identrified by index is active. 
 * 
 * @param index index in device sentry custom metrics array. 
 * @return true if metric's report interval identified by index > 0
 * @return false if metric's report interval identified by index = 0
 */
static inline bool is_custom_metric_active_by_index(uint32_t index)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF(index >= DS_MAX_NUMBER_OF_CUSTOM_METRICS, 
            false, "Invalid custom metric index = %" PRIu32, index);
    // if report interval > 0, then the metric is active, else the metric is inactive.
    return (ds_ctx.custom_metrics[index].report_interval > 0);
}


/**
 * @brief Returns custom metric_id by index. 
 * 
 * @param index index in device sentry custom metrics array. 
 * @return custom metic_id
 */
static inline ds_custom_metric_id_t custom_metric_id_get_by_index(uint32_t index)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF(index >= DS_MAX_NUMBER_OF_CUSTOM_METRICS, 
            false, "Invalid custom metric index = %" PRIu32, index);

    return ds_ctx.custom_metrics[index].metric_id;
}


/**
 * @brief Returns true if metric identrified by group_id is active. 
 * 
 * @param group_id device sentry group id. 
 * @return true if metric's report interval identrified by group_id > 0
 * @return false if metric's report interval identrified by group_ids = 0
 */
static inline bool is_metric_active_by_group_id(ds_metric_group_id_e group_id)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((group_id <= DS_METRIC_GROUP_BASE || group_id >= DS_METRIC_GROUP_MAX), 
            false, "Invalid metric group id = %d", group_id);
    return is_metric_active_by_index(ds_array_index_by_metric_group_id_get(group_id));
}

/**
 * @brief Gets value of report interval of the metric identified by index.
 * 
 * @param index index in device sentry device_metrics_report_intervals array. 
 * @return uint32_t report interval of the metric if index is valid, and 0 if the index was not valid. 
 */
static inline uint32_t report_interval_get_by_index(uint32_t index)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF(index >= DS_METRIC_GROUP_MAX, 
            0, "Invalid metric index = %" PRIu32, index);
    return ds_ctx.device_metrics_report_intervals[index];
}

/**
 * @brief Gets value of custom report interval of the metric identified by index.
 * 
 * @param index index in device sentry custom metrics array. 
 * @return uint32_t report interval of the metric if index is valid, and 0 if the index was not valid. 
 */
static inline uint32_t custom_metric_report_interval_get_by_index(uint32_t index)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF(index >= DS_MAX_NUMBER_OF_CUSTOM_METRICS, 
            0, "Invalid custom metric index = %" PRIu32, index);
    return ds_ctx.custom_metrics[index].report_interval;
}

/**
 * @brief Retruns if the metric belongs to labeled metric group.
 * 
 * @param metric_id id of the metric.
 * @return true if the metric belongs to labeled metric group.
 * @return false the metric does not belong to labeled metric group.
 */
static inline bool is_labled_metric(ds_metric_group_id_e metric_id){
    return (metric_id == DS_METRIC_GROUP_NETWORK);
}

/**
 * @brief Resets policy id (only)
 * 
 */
static void ds_metrics_policy_id_reset()
{
    SA_PV_LOG_TRACE("Reset policy id");
    memset(&ds_ctx.policy_id, 0, sizeof(ds_ctx.policy_id));
    ds_ctx.is_policy_id_initialized = 0;
}


static uint32_t min_report_interval_calculate()
{
    uint32_t min_report_interval = 0xFFFFFFFF;
    // calculate min_report_interval, which is the minimal report interval in active metrics.

    // pass over standart metrics
    for (uint32_t metric_index = 0; metric_index < DS_MAX_METRIC_NUMBER; metric_index++) {
        if (is_metric_active_by_index(metric_index)) {
            uint32_t report_interval = report_interval_get_by_index(metric_index);
            if(report_interval < min_report_interval){
                // we found active metric with report interval that is smaller than current min_report_interval
                min_report_interval = report_interval;
            } 
        }
    }

    // pass over custom metrics
    for (uint32_t metric_index = 0; metric_index < DS_MAX_NUMBER_OF_CUSTOM_METRICS; metric_index++) {
        if (is_custom_metric_active_by_index(metric_index)) {
            uint32_t report_interval = custom_metric_report_interval_get_by_index(metric_index);
            if(report_interval < min_report_interval){
                // we found active metric with report interval that is smaller than current min_report_interval
                min_report_interval = report_interval;
            } 
        }
    }

    return (min_report_interval == 0xFFFFFFFF) ? 0 : min_report_interval;
}

static ds_status_e load_active_config_from_file()
{
    ds_status_e status = DS_STATUS_SUCCESS;
    uint8_t *config_filedata = NULL;
    size_t config_filesize = 0;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // check if we have active configuration file
    kcm_status_e kcm_status = kcm_item_get_size_and_data(
            (uint8_t*)active_conf_filename, 
            strlen(active_conf_filename),
            KCM_CONFIG_ITEM,
            &config_filedata,
            &config_filesize);

    if (KCM_STATUS_ITEM_NOT_FOUND == kcm_status){
        // if config file not found, it's not an error 
        SA_PV_LOG_INFO("no saved active metrics file found, continue");
        return DS_STATUS_SUCCESS;
    }
    
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status), DS_STATUS_ERROR, 
        "reading %s is failed with kcm error %d", active_conf_filename, kcm_status);

    // active metrics config file found

    // verify file size is not 0
    SA_PV_ERR_RECOVERABLE_GOTO_IF((0 == config_filesize), status = DS_STATUS_ERROR, 
        release_resources, "active config file format is invalid, filesize = %" PRIu32, (uint32_t)config_filesize);

    // load active metrics configuration from file
    SA_PV_LOG_INFO("loading config file, size %" PRIu32, (uint32_t)config_filesize);

    status = ds_metrics_config_message_handle(config_filedata, (uint16_t)config_filesize);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), 
        status = DS_STATUS_INVALID_CONFIG, 
        release_resources, 
        "configuration message loaded from config file parsing failed, error = %d", status);

    // Enqueue the event
    status = schedule_event(EVENT_TYPE_COLLECT_AND_SEND_METRICS);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), 
        status = DS_STATUS_ERROR, release_resources, "Failed to schedule event");

release_resources:

    free(config_filedata);

    if(status == DS_STATUS_SUCCESS){
        SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    } else {
        SA_PV_LOG_INFO_FUNC_EXIT("failed with error %d", status);
    }

    return status;
}


static ds_status_e save_active_config_to_file(const uint8_t *config_message, uint16_t message_size)
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // try delete possibly existing configuration file
    kcm_status_e kcm_status = kcm_item_delete((uint8_t*)active_conf_filename, strlen(active_conf_filename), KCM_CONFIG_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status) && (KCM_STATUS_ITEM_NOT_FOUND != kcm_status), DS_STATUS_ERROR, 
            "deleting %s is failed with kcm error %d", active_conf_filename, kcm_status);

    SA_PV_LOG_INFO("storing start message to file %s (size %" PRIu16 ") bytes", active_conf_filename, message_size); 

    kcm_status = kcm_item_store((uint8_t*)active_conf_filename, strlen(active_conf_filename),
                                KCM_CONFIG_ITEM, false,
                                config_message, message_size,
                                NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status), DS_STATUS_ERROR, 
            "storing %s (size %" PRIu16 ") bytes failed with kcm error %d", active_conf_filename, message_size, kcm_status);

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return DS_STATUS_SUCCESS;
}

ds_status_e DeviceSentryClient::init(M2MBaseList& registration_list)
{
    ds_status_e status = DS_STATUS_SUCCESS, load_status = DS_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (!ds_ctx.is_initialized){
        // Create the certificate device sentry resource
        ds_ctx.resource_object = M2MInterfaceFactory::create_object(DEVICE_SENTRY_OBJECT);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((NULL == ds_ctx.resource_object), DS_STATUS_INIT_FAILED, "Error creating LWM2M object");

        // Create the instance
        M2MObjectInstance *resource_object_instance = ds_ctx.resource_object->create_object_instance();
        SA_PV_ERR_RECOVERABLE_GOTO_IF((NULL == resource_object_instance), status = DS_STATUS_INIT_FAILED, Cleanup, "Error creating LWM2M object instance");

        // Create the metrics configuration sentry resource
        ds_ctx.config_resource = resource_object_instance->create_dynamic_resource(DEVICE_SENTRY_CONFIGURATION_RSC, "Metrics Collection Configure", M2MResourceInstance::INTEGER, false);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((NULL == ds_ctx.config_resource), status = DS_STATUS_INIT_FAILED, Cleanup, "Error creating Device Sentry configuration resource");

        // Allow POST operations
        ds_ctx.config_resource->set_operation(M2MBase::GET_POST_ALLOWED);

        // Set the resource callback
        SA_PV_ERR_RECOVERABLE_GOTO_IF((!ds_ctx.config_resource->set_execute_function(metrics_config_callback)),
                                    status = DS_STATUS_INIT_FAILED, Cleanup, "Error in setting resource callback");

        // Enable sending of delayed responses
        ds_ctx.config_resource->set_delayed_response(true);

        // Create observable metrics configuration sentry resource
        ds_ctx.metrics_resource = resource_object_instance->create_dynamic_resource(DEVICE_SENTRY_OBSERVATION_RSC, "Metrics Collection Observation", M2MResourceInstance::OPAQUE, true);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((!ds_ctx.metrics_resource), status = DS_STATUS_INIT_FAILED, Cleanup, "Error creating Device Sentry metrics observation resource");

        // Allow GET operation only
        ds_ctx.metrics_resource->set_operation(M2MBase::GET_ALLOWED);

        // Set auto-observalble mode for the resource
        ds_ctx.metrics_resource->set_auto_observable(true);

        // Put the handler creation in a critical code block for the case that this function is called after the start of the event loop
        eventOS_scheduler_mutex_wait();
        ds_ctx.event_handler_id = eventOS_event_handler_create(event_handler, EVENT_TYPE_INIT);
        // release mutex in any case
        eventOS_scheduler_mutex_release();

        SA_PV_ERR_RECOVERABLE_GOTO_IF((ds_ctx.event_handler_id < 0), status = DS_STATUS_INIT_FAILED, Cleanup, "Error creating event handler");

        // try read active metrics persistant configuration file
        load_status = load_active_config_from_file();
        if(DS_STATUS_SUCCESS != load_status){
            SA_PV_LOG_ERR("Error (%d) reading config file, continue init flow", load_status);
        }

        // if all was sucessfull, register created object in MCC
        registration_list.push_back(ds_ctx.resource_object);

        ds_ctx.is_initialized = true;
    }

#ifdef DS_TEST_API
    status = init_demo_objects(registration_list);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = DS_STATUS_ERROR, Cleanup, "Error creating test object");
#endif

Cleanup:
    if(DS_STATUS_SUCCESS != status) {
        // clean resources that where created
        release_objects();
    }

    SA_PV_LOG_INFO_FUNC_EXIT("status = %d", status);
    return status;
}


static void release_objects()
{

#ifdef DS_TEST_API
    release_demo_objects();
#endif

    // Deleting resource_object will release all the resources that were created under it.
    delete ds_ctx.resource_object;  // it is safe to delete null pointer

    ds_ctx.resource_object = NULL;

    // Resources were released during resource_object delete. Set the pointers to NULL
    ds_ctx.config_resource = NULL;
    ds_ctx.metrics_resource = NULL;

    // if timer is started, stop it
    if (ds_ctx.timer_event_handle != NULL) {
        eventOS_cancel(ds_ctx.timer_event_handle);
        ds_ctx.timer_event_handle = NULL;
    }

    // ds_ctx.event_handler_id does not require release
	
}


void DeviceSentryClient::finalize()
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();
    if (!ds_ctx.is_initialized){
        // was not initialized, so exit
        return;
    }

    ds_metrics_active_metric_config_reset();
    
    release_objects();

    ds_ctx.is_initialized = false;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}


static void metrics_config_callback(void *arg)
{
    ds_status_e config_status = DS_STATUS_SUCCESS;
    const uint8_t *metrics_config = NULL;
    uint16_t config_size = 0;

    M2MResource::M2MExecuteParameter *configure_args = (M2MResource::M2MExecuteParameter *)arg;

    //TODO: error handling and error/success response should be added
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((configure_args == NULL), config_status = DS_STATUS_INVALID_CONFIG, send_response, "Configuration message is null");

    //Parse configuration data
    config_size = configure_args->get_argument_value_length();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((config_size == 0), config_status = DS_STATUS_INVALID_CONFIG, send_response, "Configuration message size is 0");

    metrics_config = configure_args->get_argument_value();

    SA_PV_LOG_BYTE_BUFF_TRACE("Configuration data received", metrics_config, config_size);

    config_status = ds_metrics_config_message_handle(metrics_config, config_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((config_status != DS_STATUS_SUCCESS), config_status = DS_STATUS_INVALID_CONFIG, send_response, "Configuration message parsing failed");

    // Enqueue the event
    config_status = schedule_event(EVENT_TYPE_COLLECT_AND_SEND_METRICS);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((config_status != DS_STATUS_SUCCESS), config_status = DS_STATUS_ERROR, send_response, "Failed to schedule event");

send_response:

    bool set_status = ds_ctx.config_resource->set_value(config_status);
    if(!set_status) {
        SA_PV_LOG_ERR("Setting value (=%d) failed", config_status);
    }

    bool send_status = false;
    if (set_status) {
        send_status = ds_ctx.config_resource->send_delayed_post_response();
        if(!send_status) {
            SA_PV_LOG_ERR("Sending delayed response value (=%d) failed", config_status);
        }
    }

    if (set_status && send_status){
        SA_PV_LOG_INFO("config message response successfully sent to MCC, config_status = %d", config_status);
    }

    if (DS_STATUS_SUCCESS == config_status && set_status && send_status){
        SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    } else {
        SA_PV_LOG_INFO_FUNC_EXIT("config_status=%d, set_status=%d, send_status=%d", config_status, set_status, send_status);
    }
}


static void event_handler(arm_event_s* event)
{
    ds_status_e status = DS_STATUS_SUCCESS;

    // TODO: replace by dynamic alocation
    // the size of the buffer depends on platform. 
    uint8_t metrics_report[DS_PLAT_METRICS_REPORT_BUFFER];
    size_t metrics_report_size = sizeof(metrics_report);

    SA_PV_ERR_RECOVERABLE_GOTO_IF((event == NULL), status = DS_STATUS_INVALID_PARAMETER, send_response, "Invalid parameter: event is NULL");
    SA_PV_LOG_INFO_FUNC_ENTER("event = %d", event->event_type);

    if (event->event_type == EVENT_TYPE_INIT) {
        // nothing to do, init already is done and don't required periodic handling
        return;
    }

    // Currently only EVENT_TYPE_COLLECT_AND_SEND_METRICS is supported
    SA_PV_ERR_RECOVERABLE_GOTO_IF((event->event_type != EVENT_TYPE_COLLECT_AND_SEND_METRICS), status = DS_STATUS_INVALID_PARAMETER, 
        send_response, "Unsupported event = %d", event->event_type);

    //Create metrics report message
    status = ds_metrics_report_create(metrics_report, &metrics_report_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = status, send_response, "Failed to create report, error=%d", status);

send_response:

    const uint8_t *metrics_report_to_send = NULL;
    uint32_t metrics_report_size_to_send = 0;
    if (status == DS_STATUS_SUCCESS) {
        // send created report to the Pelion, otherwise send nulls
        metrics_report_to_send = metrics_report;
        metrics_report_size_to_send = (uint32_t)metrics_report_size;
    }

    bool set_status = ds_ctx.metrics_resource->set_value(metrics_report_to_send, metrics_report_size_to_send);
    if(!set_status){
        SA_PV_LOG_ERR("Failed to send data to Pelion");
        // if the status is already error, save it's value
        status = (status == DS_STATUS_SUCCESS) ? DS_STATUS_ERROR : status;
    } else {
        SA_PV_LOG_INFO("metrics report (size %" PRIu32 " bytes) was reported to MCC", metrics_report_size_to_send);
    }

    if (status == DS_STATUS_SUCCESS) {
        SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    } else {
        SA_PV_LOG_INFO_FUNC_EXIT("Report was not created, status = %d", status);
    }
}

static ds_status_e schedule_event(event_type_e event_type)
{
    arm_event_s event = {
        .receiver = ds_ctx.event_handler_id, // id that we got when created event handler
        .sender = 0, // Sender tasklet - not relevant
        .event_type = event_type, // indicate event type
        .event_id = 0, // not required, event type is enough
        .data_ptr = 0, // not required, data handled in internal structure ds_ctx
        .priority = ARM_LIB_LOW_PRIORITY_EVENT, // application level priority
        .event_data = 0, // not required
    };

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    //We already have metrics event let's stop it
    if (ds_ctx.timer_event_handle != NULL) {
        eventOS_cancel(ds_ctx.timer_event_handle);
    }

    uint32_t ticks = 0;
    if (ds_ctx.min_report_interval_sec > 0) {
        SA_PV_LOG_INFO("scheduling timer to %" PRIu32 " secs from now", ds_ctx.min_report_interval_sec);
        // convert from seconds to ticks
        ticks = eventOS_event_timer_ms_to_ticks(ds_ctx.min_report_interval_sec * 1000);
        ds_ctx.timer_event_handle = eventOS_event_timer_request_every(&event, ticks);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((ds_ctx.timer_event_handle == NULL), DS_STATUS_INIT_FAILED, 
                                        "Error scheduling timer %" PRIu32 " ticks from now", ticks);
    }

    if (ds_ctx.min_report_interval_sec > 0) {
        SA_PV_LOG_INFO_FUNC_EXIT("Timer set to %" PRIu32 " (%" PRIu32 " ticks) from now", ds_ctx.min_report_interval_sec, ticks);
    } else {
        SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    }

    return DS_STATUS_SUCCESS;
}

ds_status_e ds_metrics_config_message_handle(const uint8_t *message, uint16_t message_size)
{
    ds_status_e status = DS_STATUS_SUCCESS;
    CborParser parser;
    CborValue cbor_handle;
    CborValue msg_array;

    SA_PV_LOG_INFO_FUNC_ENTER("message_size = %" PRIu16, message_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((message == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: message is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((message_size == 0), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: message_size is 0");

    CborError cbor_err = cbor_parser_init(message, message_size, 0, &parser, &cbor_handle);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Cbor parser init failed");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&cbor_handle) != CborArrayType), DS_STATUS_INVALID_CONFIG, "Invalid config message format");

    //Start to iterate configuration array
    cbor_err = cbor_value_enter_container(&cbor_handle, &msg_array);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to enter config message cbor container");
    //Next value is a cbor version, should be integer
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&msg_array) != CborIntegerType), DS_STATUS_INVALID_CONFIG, "Wrong config message version data type");

    int value;
    cbor_err = cbor_value_get_int(&msg_array, &value);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to read config message version");

    //check version number
    SA_PV_ERR_RECOVERABLE_RETURN_IF((value != DS_METRIC_CURRENT_VERSION), DS_STATUS_INVALID_CONFIG, "Invalid config message version (=%d)", value);

    cbor_err = cbor_get_next_container_element(&msg_array);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to move to next element");

    //Check message type
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&msg_array) != CborIntegerType), DS_STATUS_INVALID_CONFIG, "Wrong config message type data type");

    cbor_err = cbor_value_get_int(&msg_array, &value);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to read config message type");

    // move container iterator to next element and pass the remaining part to further parsing
    cbor_err = cbor_get_next_container_element(&msg_array);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to move to next element");
    switch (value) {
        case DS_METRIC_START_COLLECT:
            status = start_metrics_collection_config_message_handle(&msg_array);
            SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = status, send_response, 
                "Handling start config message failed (error = %d)", status);

            // save configuration message to the config file
            status = save_active_config_to_file(message, message_size); 
            SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = status, send_response, 
                "Saving config file failed (error = %d)", status);

            break;
        case DS_METRIC_STOP_COLLECT:
            status = stop_metrics_collection_config_message_handle();
            SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = status, send_response, 
                "Stopping metrics failed (error = %d)", status);
            break;
        default:
            SA_PV_LOG_ERR("Wrong config message type (=%d)", value);
            status = DS_STATUS_INVALID_CONFIG;
    }

send_response:
    if(status != DS_STATUS_SUCCESS){
        SA_PV_LOG_INFO_FUNC_EXIT("Failed with error %d", status);
    }
    else {
        SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    }
    return status;
}


static ds_status_e set_policy_id(CborValue* config_map) 
{
    bool res = cbor_value_is_text_string(config_map);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!res), DS_STATUS_INVALID_CONFIG, "Unexpected CBOR type, expected string");

    const char* policy_id = NULL;
    size_t policy_id_len = 0;
    CborError cbor_err = cbor_value_get_text_string_chunk(config_map, &policy_id, &policy_id_len, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to read policy id");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((policy_id == NULL), DS_STATUS_ERROR, "CBOR parsing error: policy_id is null");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((policy_id_len != POLICY_ID_LEN), DS_STATUS_INVALID_CONFIG, "Policy id size differs from expected");

    memcpy(ds_ctx.policy_id, policy_id, POLICY_ID_LEN);
    ds_ctx.is_policy_id_initialized = true;

    SA_PV_LOG_BYTE_BUFF_INFO("updated policy id", (uint8_t*)ds_ctx.policy_id, POLICY_ID_LEN);

    return DS_STATUS_SUCCESS;
}

static ds_status_e encode_policy_id(CborEncoder* main_map)
{
    if(ds_ctx.is_policy_id_initialized) {
        CborError cbor_err = cbor_encode_uint(main_map, DS_METRIC_POLICY_ID);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode policy id label");

        cbor_err = cbor_encode_text_string(main_map, ds_ctx.policy_id, POLICY_ID_LEN);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode policy_id");
    }

    return DS_STATUS_SUCCESS;
}

/*
# Example of the start metrics collection configuration message:

[
    METRICS_VERSION_1,
    DS_METRIC_START_COLLECT,
    {
        METRIC_GROUP_CPU: [30],
        METRIC_GROUP_THREADS : [60],
        METRIC_GROUP_NETWORK : [30],
        METRIC_GROUP_MEMORY : [40],

        // custom metrics
        1018 : [80],
        8456 : [45],
    },
    POLICY_ID
]

*/

static ds_status_e start_metrics_collection_config_message_handle(CborValue *metric_configuration_data)
{
    size_t metrics_configs_num = 0;
    CborValue single_config;
    CborValue config_array;
    ds_status_e ds_status = DS_STATUS_ERROR;

    // array will store metric ids that were parsed out in the current config message. 
    // When we affirmed that the whole message was parsed successfully, we copy the values to the active metrics.
    uint32_t tmp_device_metrics_report_intervals[DS_MAX_METRIC_NUMBER] = {}; // temp device metric array
    ds_custom_metric_t tmp_custom_metrics[DS_MAX_NUMBER_OF_CUSTOM_METRICS] = {}; // temp custom metric array

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((metric_configuration_data == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: metric_configuration_data is NULL");

    //Continue config message parsing. First item should be map.
    bool is_map = cbor_value_is_map(metric_configuration_data);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!is_map), DS_STATUS_INVALID_CONFIG, "Start config message should contain map");

    //Start iterations on the configuration in the map
    CborError cbor_err = cbor_value_enter_container(metric_configuration_data, &single_config);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to parse config map container");

    // Index in the custom metrics array
    size_t custom_metrics_index = 0;

    //Go over parameter groups
    while (!cbor_value_at_end(&single_config)) {

        int metric_group_id = 0;
        //Get a key of the current map -  parameter type
        cbor_err = cbor_value_get_int(&single_config, &metric_group_id);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to read a key");

        //Move iterator to the value of the current key
        cbor_err = cbor_value_advance(&single_config);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to move to value in config map");
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&single_config) != CborArrayType), DS_STATUS_INVALID_CONFIG, "Wrong config map value data type");

        //TODO: Add check of array length and possible iteration of value's reading
        //Start to iterate configuration array
        cbor_err = cbor_value_enter_container(&single_config, &config_array);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to parse value container");

        //Next item is map value, should be integer
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_value_get_type(&config_array) != CborIntegerType), DS_STATUS_INVALID_CONFIG, "Wrong config map value data type");

        int report_interval_sec = 0;
        cbor_err = cbor_value_get_int(&config_array, &report_interval_sec);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to read metric interval");

        // Check to which range the metric_group_id belongs:
        // device "health" standard metrics: DS_METRIC_GROUP_BASE < metric_group_id < DS_METRIC_GROUP_MAX
        // custom metrics: DS_CUSTOM_METRIC_MIN_ID < metric_group_id < DS_CUSTOM_METRIC_MAX_ID
        if (DS_METRIC_GROUP_BASE < metric_group_id && metric_group_id < DS_METRIC_GROUP_MAX) {
    
            uint32_t metric_index = ds_array_index_by_metric_group_id_get((ds_metric_group_id_e)metric_group_id);

            // report interval can't be 0 for active metric
            SA_PV_ERR_RECOVERABLE_RETURN_IF((report_interval_sec == 0), 
                DS_STATUS_INVALID_CONFIG, 
                "received invalid report interval = 0 for metric id: %d", metric_group_id);

            // store parsed out metric's interval 
            tmp_device_metrics_report_intervals[metric_index] = report_interval_sec;

            SA_PV_LOG_INFO("metric id=%d, interval=%d sec", metric_group_id, report_interval_sec);
        } 
        else if (DS_CUSTOM_METRIC_MIN_ID < metric_group_id && metric_group_id < DS_CUSTOM_METRIC_MAX_ID) {

            // report interval can't be 0 for active metric
            SA_PV_ERR_RECOVERABLE_RETURN_IF((custom_metrics_index >= DS_MAX_NUMBER_OF_CUSTOM_METRICS), 
                DS_STATUS_INVALID_CONFIG, 
                "received too many custom metrics, only %d allowed", DS_MAX_NUMBER_OF_CUSTOM_METRICS);

            // report interval can't be 0 for active metric
            SA_PV_ERR_RECOVERABLE_RETURN_IF((report_interval_sec == 0), 
                DS_STATUS_INVALID_CONFIG, 
                "received invalid report interval = 0 for metric id: %d", metric_group_id);

            // store parsed out metric's interval 
            tmp_custom_metrics[custom_metrics_index].report_interval = report_interval_sec;
            tmp_custom_metrics[custom_metrics_index].metric_id = metric_group_id;

            custom_metrics_index++;

            SA_PV_LOG_INFO("custom metric id=%d, interval=%d sec", metric_group_id, report_interval_sec);
        } else {
            //We will not return error, may be current device does not support all metrics
            SA_PV_LOG_INFO("Unsupported metric id: %d", metric_group_id); 
        }

        metrics_configs_num++;

        //Move to next map's pair (key : value)
        cbor_err = cbor_value_advance(&single_config);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_INVALID_CONFIG, "Failed to move to next entry in config map");
    }

    SA_PV_ERR_RECOVERABLE_RETURN_IF((metrics_configs_num == 0), DS_STATUS_INVALID_CONFIG, "Failed on empty configuration map");

    // move container iterator to next element and pass the remaining part to further parsing
    cbor_err = cbor_get_next_container_element(metric_configuration_data);
    SA_PV_ERR_RECOVERABLE_RETURN_IF(((cbor_err != CborErrorAdvancePastEOF) && (cbor_err != CborNoError)), DS_STATUS_INVALID_CONFIG, "Failed to move to next element");	

    // read policy id if exists - FIXME this is for backward compatibility with Device Insights service that doesn't send policy id.
    // can be removed once Device Insights service is replaced by Device Sentry service.

    // if we have one more element, so it supposed to be policy id 
    if(cbor_err != CborErrorAdvancePastEOF) {
        ds_status = set_policy_id(metric_configuration_data);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((ds_status != DS_STATUS_SUCCESS), ds_status, "Failed to set policy id");
    } else {
        // reset policy id in case it was already set by the previous start config message
        ds_metrics_policy_id_reset();
    }

    // copy temporary arrays to the context 
    memcpy(ds_ctx.device_metrics_report_intervals, tmp_device_metrics_report_intervals, sizeof(tmp_device_metrics_report_intervals));
    memcpy(ds_ctx.custom_metrics, tmp_custom_metrics, sizeof(tmp_custom_metrics));

    //  set minimal report interval
    ds_ctx.min_report_interval_sec = min_report_interval_calculate();
    SA_PV_LOG_TRACE("min_report_interval_sec = %" PRIu32, ds_ctx.min_report_interval_sec);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return DS_STATUS_SUCCESS;
}

/*
# Example of the stop metrics collection configuration message:

[
    METRICS_VERSION_1,
    DS_METRIC_STOP_COLLECT
]

*/


static ds_status_e stop_metrics_collection_config_message_handle()
{
    // stop reporting of all metrics: we support only full stop when all metrics are stopped
    SA_PV_LOG_INFO("Stop reporting all metrics");
    ds_metrics_active_metric_config_reset();

    // stop metrics scheduler and reschedule if required
    if (ds_ctx.timer_event_handle != NULL) {
        eventOS_cancel(ds_ctx.timer_event_handle);
        ds_ctx.timer_event_handle = NULL;
    }

    // delete configuration file
    kcm_status_e kcm_status = kcm_item_delete((uint8_t*)active_conf_filename, strlen(active_conf_filename), KCM_CONFIG_ITEM);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((KCM_STATUS_SUCCESS != kcm_status) && (KCM_STATUS_ITEM_NOT_FOUND != kcm_status), DS_STATUS_ERROR, 
            "deleting %s is failed with kcm error %d", active_conf_filename, kcm_status);

    if (KCM_STATUS_ITEM_NOT_FOUND != kcm_status) {
        SA_PV_LOG_TRACE("WARNING: no config file %s during stop config message handling", active_conf_filename);
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return DS_STATUS_SUCCESS;
}


/* Example of cbor array for Linux platform:
{
    DS_METRIC_REPORT_V1: [ // main array
        {// not labeled metric map
            DS_METRIC_CPU_UP_TIME: 3478153, 
            DS_METRIC_CPU_IDLE_TIME: 3204508, 
            DS_METRIC_THREADS_COUNT: 31,
            DS_METRIC_MEMORY_TOTAL: 135068012544,
            DS_METRIC_MEMORY_USED: 126662152192,

            // custom metrics
            1018 : 80,
            8456 : 45,
        }, 
         
        // labeled metric maps
        {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_INTERFACE_NAME:  "vethf926846"}, DS_METRIC_BYTES_IN: 70196, DS_METRIC_BYTES_OUT: 100376}, 
        {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_INTERFACE_NAME:  "veth70ec8f2"}, DS_METRIC_BYTES_IN: 77846, DS_METRIC_BYTES_OUT: 453690}, 
        {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_INTERFACE_NAME:  "br-4802ffacedd8"}, DS_METRIC_BYTES_IN: 0, DS_METRIC_BYTES_OUT: 67436}, 
    ], 
    
    DS_METRIC_ACTIVE_DESTS: [// active destinations array
        {DS_METRIC_LABEL_DEST_IP: "10.50.21.31", DS_METRIC_LABEL_DEST_PORT: 2049}, 
        {DS_METRIC_LABEL_DEST_IP: "10.50.0.157", DS_METRIC_LABEL_DEST_PORT: 52887}, 
        {DS_METRIC_LABEL_DEST_IP: "10.50.0.38", DS_METRIC_LABEL_DEST_PORT: 61375}, 
    ],
    
    DS_METRIC_POLICY_ID: "0168c6ed50b40000000000010010016a"
}

Example of cbor array for MbedOS platform:
{
    DS_METRIC_REPORT_V1: [// main array
         {// not labeled metric map
            DS_METRIC_CPU_UP_TIME: 235, 
            DS_METRIC_CPU_IDLE_TIME: 159, 
            DS_METRIC_THREADS_COUNT: 8,
            DS_METRIC_HEAP_TOTAL: 127648,
            DS_METRIC_HEAP_USED: 42354

            // custom metrics
            1018 : 80,
            8456 : 45,
         }, 
        
         // labeled metric maps
         {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_DEST_IP: "8.8.8.8", DS_METRIC_LABEL_DEST_PORT: 53, DS_METRIC_LABEL_INTERFACE_NAME: "en0"}, DS_METRIC_BYTES_IN: 109, DS_METRIC_BYTES_OUT: 51}, 
         {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_DEST_IP: "35.172.202.42", DS_METRIC_LABEL_DEST_PORT: 5684, DS_METRIC_LABEL_INTERFACE_NAME: "en0"}, DS_METRIC_BYTES_IN: 4961, DS_METRIC_BYTES_OUT: 2420}, 
         {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_DEST_IP: "8.8.8.8", DS_METRIC_LABEL_DEST_PORT: 53, DS_METRIC_LABEL_INTERFACE_NAME: "en0"}, DS_METRIC_BYTES_IN: 106, DS_METRIC_BYTES_OUT: 47}, 
         {DS_METRIC_GROUP_LABELS: {DS_METRIC_LABEL_DEST_IP: "34.230.180.49", DS_METRIC_LABEL_DEST_PORT: 5684, DS_METRIC_LABEL_INTERFACE_NAME: "en0"}, DS_METRIC_BYTES_IN: 1543, DS_METRIC_BYTES_OUT: 4066}
       ],

       // on MbedOS there no special section of active destinations, active destinations are part of "labeled metric maps"

    DS_METRIC_POLICY_ID: "0168c6ed50b40000000000010010016a"
}
*/
ds_status_e ds_metrics_report_create(uint8_t *metrics_report, size_t *metrics_report_size)
{
    ds_status_e status = DS_STATUS_SUCCESS;
    CborEncoder cbor_report, main_map, main_array;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    
    SA_PV_ERR_RECOVERABLE_RETURN_IF((metrics_report == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: metrics_report is NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((metrics_report_size == 0), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: metrics_report_size is 0");
    cbor_encoder_init(&cbor_report, metrics_report, *metrics_report_size, 0);

    CborError cbor_err = cbor_encoder_create_map(&cbor_report, &main_map, CborIndefiniteLength);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to create cbor outer map");

    cbor_err = cbor_encode_uint(&main_map, DS_METRIC_REPORT_V1);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode version");

    // we don't know how much metrics will be, so put CborIndefiniteLength
    cbor_err = cbor_encoder_create_array(&main_map, &main_array, CborIndefiniteLength);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to create main array");

    // encode all NOT labeled metrics
    status = metrics_report_not_labeled_encode(&main_array);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to add not labeled metrics");

    // encode all labeled metrics
    status = metrics_report_labeled_encode(&main_array);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to add labeled metrics"); 

    cbor_err = cbor_encoder_close_container(&main_map, &main_array);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to close main array");

    if(is_metric_active_by_group_id(DS_METRIC_GROUP_NETWORK)) {
        // encode network active destivations - relevant only for Linux platform, on MbedOS will do nothing
        status = ds_active_dests_collect_and_encode(&main_map);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to encode active dests");
    }

    status = encode_policy_id(&main_map);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), status, "Failed to get policy id");	

    cbor_err = cbor_encoder_close_container(&cbor_report, &main_map);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to close outer map");

    *metrics_report_size = cbor_encoder_get_buffer_size(&cbor_report, metrics_report);

    // print buffer by lines
    const size_t LINE_SIZE = 32;
    for (size_t start_offset = 0; start_offset < *metrics_report_size;  start_offset += LINE_SIZE) {
        // print_size is the minimum between LINE_SIZE and the remainder (*metrics_report_size - start_offset)
        size_t print_size = (LINE_SIZE > (*metrics_report_size - start_offset)) ? 
                                (*metrics_report_size - start_offset) : 
                                LINE_SIZE;
        (void)print_size;
        SA_PV_LOG_BYTE_BUFF_TRACE("report buffer", metrics_report + start_offset, (uint16_t)print_size);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT("metric cbor report size %" PRIu32 " bytes", (uint32_t)(*metrics_report_size));
    return DS_STATUS_SUCCESS;
}


static ds_status_e metrics_report_not_labeled_encode(CborEncoder *main_array)
{
    CborError cbor_err;
    bool not_labeled_map_opened = false;	
    ds_status_e status = DS_STATUS_SUCCESS;
    CborEncoder not_labeled_map;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((main_array == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: main_array is NULL");

    // go over all possible NOT labeled metrics and check if should be reported
    for (uint32_t ind = 0; ind < DS_MAX_METRIC_NUMBER; ind++) {
        if (is_metric_active_by_index(ind) && (!is_labled_metric(ds_metric_group_id_by_array_index_get(ind)))) { 

            if (!not_labeled_map_opened) { 
                //first not_labeled metric, map should be created
                cbor_err = cbor_encoder_create_map(main_array, &not_labeled_map, CborIndefiniteLength);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to create not labeled map");
                not_labeled_map_opened = true;
            }
            
            ds_metric_group_id_e metric_id = ds_metric_group_id_by_array_index_get(ind);

            //Add metric value to map of all unlabeled values
            SA_PV_LOG_TRACE("encode not labeled metric_id = %" PRIu32, metric_id);

            switch (metric_id) {
                case DS_METRIC_GROUP_CPU: {
                    ds_stats_cpu_t cpu_stats;
                    status = ds_cpu_stats_get(&cpu_stats);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to get CPU metrics");

                    cbor_err = cbor_map_encode_uint_uint(&not_labeled_map, DS_METRIC_CPU_UP_TIME, cpu_stats.uptime);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode cpu uptime");

                    cbor_err = cbor_map_encode_uint_uint(&not_labeled_map, DS_METRIC_CPU_IDLE_TIME, cpu_stats.idle_time);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode cpu idle time");

                    SA_PV_LOG_INFO("cpu metric encoded: uptime=%" PRIu64 ", idle_time=%" PRIu64, cpu_stats.uptime, cpu_stats.idle_time); 
                }
                break;
                case DS_METRIC_GROUP_THREADS: {
                    uint32_t thread_count = 0;
                    status = ds_thread_stats_get(&thread_count);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to get thread metrics");

                    cbor_err = cbor_map_encode_uint_uint(&not_labeled_map, DS_METRIC_THREADS_COUNT, thread_count);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode thread count");

                    SA_PV_LOG_INFO("thread metric encoded: thread_count=%" PRIu32, thread_count); 
                }
                break;
                case DS_METRIC_GROUP_MEMORY: {
                    ds_stats_memory_t mem_stats;
                    status = ds_memory_stats_get(&mem_stats);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to get memory metrics");

                    cbor_err = cbor_map_encode_uint_uint(&not_labeled_map, mem_stats.mem_available_id, mem_stats.mem_available_bytes);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode mem available");

                    cbor_err = cbor_map_encode_uint_uint(&not_labeled_map, mem_stats.mem_used_id, mem_stats.mem_used_bytes);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode mem used");

                    SA_PV_LOG_INFO("mem metric encoded: available=%" PRIu64 ", used=%" PRIu64, mem_stats.mem_available_bytes, mem_stats.mem_used_bytes); 
                }

                case DS_METRIC_GROUP_NETWORK:
                // do nothing in nework metrics for not labled metrics
                break;
                default:
                    SA_PV_LOG_TRACE("unsupported metric error %" PRIu32, metric_id);
                    return DS_STATUS_UNSUPPORTED_METRIC;
            }
        }
    }

    // encode custom metrics : go over all possible NOT labeled metrics and check if should be reported
    for (uint32_t ind = 0; ind < DS_MAX_NUMBER_OF_CUSTOM_METRICS; ind++) {
        if (is_custom_metric_active_by_index(ind)) { 

            //Add metric value to map of all unlabeled values
            
            if (!not_labeled_map_opened) { 
                //first not_labeled metric, map should be created
                cbor_err = cbor_encoder_create_map(main_array, &not_labeled_map, CborIndefiniteLength);
                SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to create not labeled map");
                not_labeled_map_opened = true;
            }
            
            SA_PV_ERR_RECOVERABLE_RETURN_IF(NULL == ds_ctx.custom_metric_value_getter_cb, DS_STATUS_ENCODE_FAILED, "User custom metric callback is NULL!");

            ds_custom_metric_id_t custom_metric_id = custom_metric_id_get_by_index(ind);

            SA_PV_LOG_TRACE("encode not labeled custom metric_id = %" PRIu64, custom_metric_id);

            // get metric value from the user
            uint8_t *metric_value_out = NULL;
            ds_custom_metrics_value_type_t metric_value_type_out = DS_INVALID_TYPE;
            size_t metric_value_size_out = 0;
            status =  ds_ctx.custom_metric_value_getter_cb(
                    custom_metric_id,           // input value
                    ds_ctx.user_context,        // input value
                    &metric_value_out,          // ouput value
                    &metric_value_type_out,     // ouput value
                    &metric_value_size_out
                );    // ouput value
            SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), DS_STATUS_ENCODE_FAILED, "Failed to get custom metric, error = %d", status);

            // Currently we support only int64

            // verify that we got int 64 
            SA_PV_ERR_RECOVERABLE_RETURN_IF((metric_value_type_out != DS_INT64), DS_STATUS_ENCODE_FAILED, 
                "Failed on getting wrong type (= %d) of the metric value. Currently only DS_INT64 is supported!", metric_value_type_out);

            SA_PV_ERR_RECOVERABLE_RETURN_IF((metric_value_size_out != DS_SIZE_OF_INT64), DS_STATUS_ENCODE_FAILED, 
                "Failed on getting wrong size (= %" PRIu32 ") of the metric value. Currently Only int 64 bit is supported!", (uint32_t)metric_value_size_out);

            // cast the output value to int 64
            int64_t value = *(int64_t*) (metric_value_out); 

            // put metrice_id (as uint64) and the value (as int64) to the cbor buffer
            cbor_err = cbor_encode_uint(&not_labeled_map, custom_metric_id);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode custom metric_id=%" PRIu64, custom_metric_id);

            cbor_err = cbor_encode_int(&not_labeled_map, value);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to encode custom metric value (metric_id=%" PRIu64 ", value=%" PRId64 ")", custom_metric_id, value);

            SA_PV_LOG_INFO("custom metric encoded: metric_id=%" PRIu64 ", value=%" PRId64, custom_metric_id, value); 
        }
    }

    if (not_labeled_map_opened) {
        cbor_err = cbor_encoder_close_container(main_array, &not_labeled_map);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((cbor_err != CborNoError), DS_STATUS_ENCODE_FAILED, "Failed to close not labeled map");
        not_labeled_map_opened = false;
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return DS_STATUS_SUCCESS;
}


static ds_status_e metrics_report_labeled_encode(CborEncoder *main_array)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((main_array == NULL), DS_STATUS_INVALID_PARAMETER, "Invalid parameter: main_array is NULL");
        
    for (uint32_t ind = 0; ind < DS_MAX_METRIC_NUMBER; ind++) {
        if (is_metric_active_by_index(ind) && is_labled_metric(ds_metric_group_id_by_array_index_get(ind))) {
            
            //Add metric value to main map
            uint32_t metric_id = ds_metric_group_id_by_array_index_get(ind);
    
            ds_status_e status = DS_STATUS_SUCCESS;
            switch (metric_id) {
                case DS_METRIC_GROUP_CPU: 
                case DS_METRIC_GROUP_THREADS: 
                case DS_METRIC_GROUP_MEMORY: 
                // CPU/THREADS/MEMORY metrics are not labled metrics
                break;
                case DS_METRIC_GROUP_NETWORK: {
                    uint32_t network_stats_count = 0;
                    ds_stats_network_t *network_stats = NULL;
                    status = ds_network_stats_get(&network_stats, &network_stats_count);
                    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != DS_STATUS_SUCCESS), status, "Failed to get network stats");

                    for (uint32_t i = 0; i < network_stats_count; i++) {
                        CborEncoder report_labled_map;
                        CborError cbor_err = cbor_encoder_create_map(main_array, &report_labled_map, CborIndefiniteLength);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to create group map");

                        cbor_err = cbor_encode_uint(&report_labled_map, DS_METRIC_GROUP_LABELS);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode group label");

                        CborEncoder lable;
                        // open map for labeled metrics
                        cbor_err = cbor_encoder_create_map(&report_labled_map, &lable, CborIndefiniteLength);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to create lable map");

                        // encode network ip data - relevant only for Mbed OS platform, on Linux will do nothing
                        status = ds_plat_labeled_metric_ip_data_encode(&lable, &network_stats[i].ip_data);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != DS_STATUS_SUCCESS), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode dest ip at index %" PRIu32, i);

                        // add interface name to lable
                        cbor_err = cbor_encode_uint(&lable, DS_METRIC_LABEL_INTERFACE_NAME);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode if name key");

                        cbor_err = cbor_encode_text_stringz(&lable, network_stats[i].interface);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode if name");

                        // close map for labeled metrics
                        cbor_err = cbor_encoder_close_container(&report_labled_map, &lable);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to close label map");

                        // add received bytes
                        cbor_err = cbor_map_encode_uint_uint(&report_labled_map, DS_METRIC_BYTES_IN, network_stats[i].recv_bytes);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode tcp bytes in");

                        // add sent bytes
                        cbor_err = cbor_map_encode_uint_uint(&report_labled_map, DS_METRIC_BYTES_OUT, network_stats[i].sent_bytes);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to encode tcp bytes out");

                        SA_PV_LOG_INFO("net metric [%" PRIu32 "] if_name=%s, recv_bytes=%" PRIu64 " sent_bytes=%" PRIu64 " encoded", 
                            i, network_stats[i].interface, network_stats[i].recv_bytes, network_stats[i].sent_bytes);

                        // close current socket report map
                        cbor_err = cbor_encoder_close_container(main_array, &report_labled_map);
                        SA_PV_ERR_RECOVERABLE_GOTO_IF((cbor_err != CborNoError), status = DS_STATUS_ENCODE_FAILED, release_resources, "Failed to close group map");
                    }
            
                    release_resources:
                    free(network_stats);
                }
                break;
                    default:
                        SA_PV_LOG_INFO_FUNC_EXIT("unsupported metric error %" PRIu32, metric_id);
                        return DS_STATUS_UNSUPPORTED_METRIC;
            }
        }
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return DS_STATUS_SUCCESS;
}

uint32_t ds_metrics_ctx_min_report_interval_get()
{
    return ds_ctx.min_report_interval_sec;
}

const uint32_t* ds_metrics_ctx_device_metrics_report_intervals_get()
{
    return ds_ctx.device_metrics_report_intervals;
}

const ds_custom_metric_t* ds_custom_metrics_ctx_array_get()
{
    return ds_ctx.custom_metrics;
}

const char* ds_metrics_ctx_policy_id_get(bool *is_policy_initialized)
{
    SA_PV_ERR_RECOVERABLE_RETURN_IF((is_policy_initialized == NULL), NULL, "Invalid parameter: is_policy_initialized is NULL");
    *is_policy_initialized = ds_ctx.is_policy_id_initialized;

    if(*is_policy_initialized){
        return ds_ctx.policy_id;
    } else {
        return NULL;
    }
}

void ds_metrics_active_metric_config_reset()
{
    SA_PV_LOG_TRACE("Reset all active metrics");
    // reset standart metrics
    memset(&ds_ctx.device_metrics_report_intervals, 0, sizeof(ds_ctx.device_metrics_report_intervals));
    // reset custom metrics
    memset(&ds_ctx.custom_metrics, 0, sizeof(ds_ctx.custom_metrics));

    // reset report interval
    ds_ctx.min_report_interval_sec = 0;

    ds_metrics_policy_id_reset();
}

void ds_custom_metric_callback_set(ds_custom_metric_value_getter_t cb, void *user_context)
{
    ds_ctx.custom_metric_value_getter_cb = cb;
    ds_ctx.user_context = user_context;
}
