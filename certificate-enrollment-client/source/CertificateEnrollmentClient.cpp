// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
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

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT

#include "CertificateEnrollmentClient.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2minterface.h"
#include "pal.h"
#include "eventOS_scheduler.h"
#include "eventOS_event.h"
#include "ce_defs.h"
#include "ce_tlv.h"
#include "certificate_enrollment.h"
#include <stdio.h>
#include <string.h>
#include "CertificateEnrollmentClient.h"
#include "CertificateEnrollmentClientCommon.h"
#include "CertificateRenewalData.h"
#include "pv_error_handling.h"
#include "pv_macros.h"

#define RESOURCE_ID_CERTIFICATE_NAME "27002"
#define OBJECT_LWM2M_CERTIFICATE "35011"

#define NUMBER_OF_CONCURRENT_RENEWALS 1


/************************************************************************/
/* Different calls to update                                            */
/************************************************************************/

extern const char g_lwm2m_name[];

namespace CertificateEnrollmentClient {

    // Event type that is part of the arm_event_s structure.
    enum event_type_e {
        EVENT_TYPE_INIT, // Some initializer - nothing done currently, initialization called by the client
        EVENT_TYPE_RENEWAL_REQUEST, // Certificate renewal request. We can tell if it is initiated by the server or the device with the derived type of CertificateRenewalDataBase of the certificate descriptor / global variable
        EVENT_TYPE_EST_RESPONDED, // Certificate arrived from EST service, or EST failure
        EVENT_TYPE_MAX = 0xff // Must fit in a uint8_t (field in the arm_event_s struct)
    };

    // Pointer to the EST client object for dealing with the EST service.
    extern const CERT_ENROLLMENT_EST_CLIENT *g_est_client;

    // Data for certificate that is currently being renewed. Will change to list if we need to support multiple renewals
    static CertificateRenewalDataBase *current_cert = NULL;

    // ID of the handler we register to the MbedCloudClient event loop
    static int8_t handler_id = -1;

    // Flag that indicates whether the module is initialized
    static bool is_initialized = false;

    // Semaphore for enforcing that only NUMBER_OF_CONCURRENT_RENEWALS (currently 1) request at a time may update current_cert. Hold lock until process finished.
    // Important: When pal_osSemaphoreWait called from within event loop - do not block, must set timeout to 0, and fail if failed to acquire lock
    // Future: For supporting renewals of NUMBER_OF_CONCURRENT_RENEWALS certificates simultaneously - change to semaphore that counts to NUMBER_OF_CONCURRENT_RENEWALS
    //         and maintain a list of certificates of size NUMBER_OF_CONCURRENT_RENEWALS inside the event loop.
    static palSemaphoreID_t g_renewal_sem = 0;


    /**
    * \brief Finish the renewal process.
    * Zero current_cert pointer, then release the semaphore. Note that when the semaphore is released - new device renewals may be made.
    * Then call renewal_data->finish() and delete renewal_data.
    *
    * \param renewal_data the data of the certificate to be renewed.
    *        It is important that this is passed to the function because after releasing the semaphore - the global pointer may be replaced.
    * \param exit_status the status of the renewal process
    */
    static void certificate_renewal_finish(CertificateRenewalDataBase *renewal_data, ce_status_e exit_status);

    /**
    * \brief The function that handles all the CertificateEnrollmentClient events
    * Create an arm_event_s object and call eventOS_event_send()
    * The event will have an application level priority, and will be executed when in the head of the event queue.
    * In the future: an extra arg should be passed - some descriptor for the specific CertificateRenewalDataBase object.
    *
    * \param event_type An event identifier
    */
    static void event_handler(arm_event_s* event);

    /**
    * \brief Send a new event to the event loop queue.
    * Create an arm_event_s object and call eventOS_event_send()
    * The event will have an application level priority
    *
    * \param renewal_data A pointer to an object derived from CertificateRenewalDataBase
    * \param event_type An event identifier
    */
    static ce_status_e schedule_event(event_type_e event_type);

    /**
    * \brief Callback that will be executed when an EST service response is available
    * Event Context is probably network so this function will check if response is success, if so, allocate the data if needed in renewal_data->est_data. schedule a new event with type EVENT_TYPE_EST_RESPONDED.
    *
    * \param result Whether the EST client successfully received a certificate from the EST service
    * \param cert_chain structure containing the certificate/chain received from the EST service
    * \param Context passed when requesting a certificate via the EST client. Currently unused. In the future will be used to identify the relevant CertificateRenewalDataBase object.
    */
    static void est_cb(est_enrollment_result_e result,
                       cert_chain_context_s *cert_chain,
                       void *context);

    /**
    * \brief The function that handles the EST response.
    *
    * Called by event_handler(). renewal_data->est_data already exists and is valid.
    * Will perform a safe replacement of the certificate with the new certificate received from EST
    * Then it will free the EST chain and finish the renewal operation.
    * \param renewal_data A pointer to an object derived from CertificateRenewalDataBase
    */
    static void est_response_process(CertificateRenewalDataBase *renewal_data);

    /**
    * \brief Create g_cert_enroll_lwm2m_obj, from the object create an object resource, and create the resources. Then push the object to the MCC object list
    *
    * Note that the pointers to the objects created by this function is owned by the CertificateEnrollmentClient Module and must be released in by CertificateEnrollmentClient::finalize()
    * \param list A reference to the MbedCloudClient object list. MbedCloudClient will later set the resource
    */
    static ce_status_e init_objects(M2MBaseList& list);

    /**
    * \brief Release the objects created by init_objects()
    *
    */
    static void release_objects();

    // Callback is called when we get a POST message to g_cert_enroll_lwm2m_resource (runs in high priority context!)
    /**
    * \brief Callback is called when we get a POST message to g_cert_enroll_lwm2m_resource
    * Runs in network context of the event loop.
    * This function extracts the input data, creates a CertificateEnrollmentClient::CertificateRenewalDataFromServer object sets the global variable
    *
    * \param arg a M2MResource::M2MExecuteParameter argument.
    */
    static void certificate_renewal_post(void *arg);

    /**
    * \brief Start the renewal process.
    * Parse the certificate name, generate keys and CSR. Then call the EST client so the new certificate may be retrieved
    *
    * \param renewal_data the data of the certificate to be renewed
    */
    static void certificate_renewal_start(CertificateRenewalDataBase *renewal_data);

    /**
    * \brief Call the user callback and send a response to the server, when a CertificateRenewalDataFromServer object does not exist.
    * Use only for server initiated renewal, since this sends a response to the server.
    *
    * \param tlv the raw data from the server - should be in the form of TLV
    * \param tlv_size size of the TLV buffer
    * \param ret_status The return status to return to the user callback and the server
    */
    static void call_user_cb_send_response(const uint8_t *tlv, uint16_t tlv_size, ce_status_e ret_status);

#ifdef CERT_RENEWAL_TEST
    void testonly_certificate_renewal_post(void *arg);
#endif // CERT_RENEWAL_TEST

}

// FIXME: print error
void CertificateEnrollmentClient::call_user_cb_send_response(const uint8_t *tlv, uint16_t tlv_size, ce_status_e ret_status)
{
    CertificateEnrollmentClient::CertificateRenewalDataFromServer temp_obj(tlv, tlv_size);
    (void)temp_obj.parse();

    // Call user callback with appropriate error
    // In case of parsing error (malformed TLV), the provided ret_status will be returned and not 
    call_user_cert_renewal_cb(temp_obj.cert_name, ret_status, CE_INITIATOR_SERVER);

    // Send response to the server
    SA_PV_LOG_INFO("sending delayed response\n");
    g_cert_enroll_lwm2m_resource->set_value(ret_status);
    g_cert_enroll_lwm2m_resource->send_delayed_post_response();
}

void CertificateEnrollmentClient::certificate_renewal_post(void *arg)
{
    palStatus_t pal_status;
    ce_status_e status;
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    M2MResource::M2MExecuteParameter *args = (M2MResource::M2MExecuteParameter *)arg;
    const uint8_t *data = args->get_argument_value();
    const uint16_t data_size = args->get_argument_value_length();

    // If CEC module is not initialized - do not even take semaphore - exit with proper response
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!is_initialized), call_user_cb_send_response(data, data_size, CE_STATUS_NOT_INITIALIZED), "Certificate Renewal module not initialized");

    pal_status = pal_osSemaphoreWait(g_renewal_sem, 0, NULL);

    if (pal_status == PAL_SUCCESS) {
        CertificateEnrollmentClient::current_cert = new CertificateEnrollmentClient::CertificateRenewalDataFromServer(data, data_size);
        if (!CertificateEnrollmentClient::current_cert) {
            status = CE_STATUS_OUT_OF_MEMORY;
            pal_status = pal_osSemaphoreRelease(g_renewal_sem);
            if (PAL_SUCCESS != pal_status) { // Should never happen
                status = CE_STATUS_ERROR;
            }

            call_user_cb_send_response(data, data_size, status);
            return;
        }

        // Enqueue the event
        status = schedule_event(CertificateEnrollmentClient::EVENT_TYPE_RENEWAL_REQUEST);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((status != CE_STATUS_SUCCESS), certificate_renewal_finish(CertificateEnrollmentClient::current_cert, status), "Error scheduling event");

    } else {
        SA_PV_LOG_ERR("Failed to take semaphore- device busy\n");

        if (pal_status == PAL_ERR_RTOS_TIMEOUT) {
            status = CE_STATUS_DEVICE_BUSY;
        } else {
            status = CE_STATUS_ERROR;
        }

        call_user_cb_send_response(data, data_size, status);
        return;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

ce_status_e CertificateEnrollmentClient::certificate_renew(const char *cert_name)
{
    palStatus_t pal_status = PAL_SUCCESS;
    ce_status_e status = CE_STATUS_SUCCESS;

    SA_PV_ERR_RECOVERABLE_RETURN_IF((!cert_name), CE_STATUS_INVALID_PARAMETER, "Provided NULL certificate name");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!is_initialized), CE_STATUS_NOT_INITIALIZED, "Certificate Renewal module not initialized");

    SA_PV_LOG_INFO_FUNC_ENTER("cert_name = %s\n", cert_name);

    pal_status = pal_osSemaphoreWait(g_renewal_sem, 0, NULL);

    if (pal_status == PAL_SUCCESS) {
        CertificateEnrollmentClient::current_cert = new CertificateEnrollmentClient::CertificateRenewalDataFromDevice(cert_name);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((!CertificateEnrollmentClient::current_cert), status = CE_STATUS_OUT_OF_MEMORY, ReleseSemReturn, "Allocation error");

        // Enqueue the event
        status = schedule_event(CertificateEnrollmentClient::EVENT_TYPE_RENEWAL_REQUEST);
        SA_PV_ERR_RECOVERABLE_GOTO_IF((status != CE_STATUS_SUCCESS), status = status, ReleseSemReturn, "Error scheduling event");

        // If some error synchronous error has occurred before scheduling the event - release the semaphore we had just taken, 
        // and then return the error without calling the user callback 
ReleseSemReturn:
        if (status != CE_STATUS_SUCCESS) {
            pal_status = pal_osSemaphoreRelease(g_renewal_sem);
            if (PAL_SUCCESS != pal_status) { // Should never happen
                status = CE_STATUS_ERROR;
            }
        }

    } else {
        // return with appropriate error
        if (pal_status == PAL_ERR_RTOS_TIMEOUT) {
            status = CE_STATUS_DEVICE_BUSY;
        } else {
            status = CE_STATUS_ERROR;
        }

    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return status;
}


void CertificateEnrollmentClient::on_certificate_renewal(cert_renewal_cb_f user_cb)
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();
    CertificateEnrollmentClient::set_user_cert_renewal_cb(user_cb);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}


ce_status_e CertificateEnrollmentClient::init_objects(M2MBaseList& list)
{
    M2MObjectInstance *cert_enroll_lwm2m_obj_instance;

    ce_status_e ce_status = CE_STATUS_SUCCESS;
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Create the certificate enrollment resource
    g_cert_enroll_lwm2m_obj = M2MInterfaceFactory::create_object(OBJECT_LWM2M_CERTIFICATE);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!g_cert_enroll_lwm2m_obj), CE_STATUS_ERROR, "Error creating LWM2M object");

    // Create the instance
    cert_enroll_lwm2m_obj_instance = g_cert_enroll_lwm2m_obj->create_object_instance();
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!cert_enroll_lwm2m_obj_instance), ce_status = CE_STATUS_ERROR, Cleanup, "Error creating LWM2M object instance");

    // Create the resource
    g_cert_enroll_lwm2m_resource = cert_enroll_lwm2m_obj_instance->create_dynamic_resource(RESOURCE_ID_CERTIFICATE_NAME, "Enroll", M2MResourceInstance::INTEGER, false);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!g_cert_enroll_lwm2m_resource), ce_status = CE_STATUS_ERROR, Cleanup, "Error creating LWM2M resource");

    // Allow POST operations
    g_cert_enroll_lwm2m_resource->set_operation(M2MBase::POST_ALLOWED);

    // Set the resource callback
    SA_PV_ERR_RECOVERABLE_GOTO_IF((!g_cert_enroll_lwm2m_resource->set_execute_function(CertificateEnrollmentClient::certificate_renewal_post)),
                                  ce_status = CE_STATUS_ERROR, Cleanup, "Error resource callback");

    // Enable sending of delayed responses
    g_cert_enroll_lwm2m_resource->set_delayed_response(true);

    // Push the object to the list
    list.push_back(g_cert_enroll_lwm2m_obj);

Cleanup:
    if (ce_status != CE_STATUS_SUCCESS) {
        // Destroying the object will destroy all instances and resources associated with it
        delete g_cert_enroll_lwm2m_obj;
        g_cert_enroll_lwm2m_resource = NULL;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return ce_status;
}

void CertificateEnrollmentClient::release_objects()
{
    delete g_cert_enroll_lwm2m_obj;
    g_cert_enroll_lwm2m_obj = NULL;
}


ce_status_e CertificateEnrollmentClient::init(M2MBaseList& list, const EstClient *est_client)
{
    ce_status_e ce_status = CE_STATUS_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    if (!is_initialized) {

        // Init the LWM2M object and resource and push the object
        ce_status = init_objects(list);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((ce_status != CE_STATUS_SUCCESS), ce_status, "Error initializing LWM2M object and resource");

        // Put the handler creation in a critical code block for the case that this function is called after the start of the event loop
        eventOS_scheduler_mutex_wait();
        if (handler_id == -1) { // Register the handler only if it hadn't been registered before
            handler_id = eventOS_event_handler_create(CertificateEnrollmentClient::event_handler, EVENT_TYPE_INIT);
            SA_PV_ERR_RECOVERABLE_RETURN_IF((handler_id == -1), ce_status, "Error creating event handler");
        }
        eventOS_scheduler_mutex_release();

        // Initialize the CE module
        ce_status = ce_init();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((ce_status != CE_STATUS_SUCCESS), ce_status, "Error initializing CE module");

        // Create the certificate renewal mutex
        pal_status = pal_osSemaphoreCreate(NUMBER_OF_CONCURRENT_RENEWALS, &g_renewal_sem);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((pal_status != PAL_SUCCESS), CE_STATUS_ERROR, "Error creating semaphore");

#ifdef CERT_ENROLLMENT_EST_MOCK
        PV_UNUSED_PARAM(est_client);
        g_est_client = new EstClientMock();
        SA_PV_ERR_RECOVERABLE_RETURN_IF((!g_est_client), CE_STATUS_ERROR, "Error creating mock EST");
#else 
        g_est_client = est_client;
#endif

        is_initialized = true;
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return CE_STATUS_SUCCESS;
}

void CertificateEnrollmentClient::finalize()
{
    palStatus_t pal_status;
    // If module not initialized - do nothing
    if (is_initialized) {
        pal_status = pal_osSemaphoreDelete(&g_renewal_sem);
        if (pal_status != PAL_SUCCESS) {
            SA_PV_LOG_ERR("Error deleting semaphore");
        }

#ifdef CERT_ENROLLMENT_EST_MOCK
        delete g_est_client;
#endif
        is_initialized = false;

        // LWM2M objects, instances, and resources are deleted when MbedCloudClient is unregistered and ServiceClient::state_unregister() is called
        // Currently nothing to finalize for CE core module except for KCM. However we do not wish to finalize it it may be used by other resources

        // Release our resources
        release_objects();
    }
}

void CertificateEnrollmentClient::event_handler(arm_event_s* event)
{
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    switch (event->event_type) {
        case EVENT_TYPE_INIT:
            // Nothing to do - ce module already initialized
            break;
        case EVENT_TYPE_RENEWAL_REQUEST:
            certificate_renewal_start(current_cert);
            break;
        case EVENT_TYPE_EST_RESPONDED:
            est_response_process(current_cert);
            break;
        default:
            // Should never happen
            SA_PV_LOG_ERR("Unsuupported event\n");
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

// This is the entry point of the renewal request, inside the event loop
void CertificateEnrollmentClient::certificate_renewal_start(CertificateRenewalDataBase *renewal_data)
{
    ce_status_e ce_status;
    est_status_e est_status;
    const char *cert_name;
    size_t cert_name_size;
    kcm_status_e kcm_status;
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Parse the certificate name
    ce_status = renewal_data->parse();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ce_status != CE_STATUS_SUCCESS), certificate_renewal_finish(renewal_data, ce_status), "Parse error");

    // Create CSR's key handle
    kcm_status = cs_key_pair_new(&(renewal_data->key_handle), true);
    // translate error to some CE native error
    ce_status = ce_error_handler(kcm_status);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ce_status != CE_STATUS_SUCCESS), certificate_renewal_finish(renewal_data, ce_status), "Failed creating new key handle");

    // key handle is initialized in the base constructor
    ce_status = ce_generate_keys_and_create_csr_from_certificate(renewal_data->cert_name, &(renewal_data->renewal_items_names), renewal_data->key_handle, &renewal_data->csr, &renewal_data->csr_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((ce_status != CE_STATUS_SUCCESS), certificate_renewal_finish(renewal_data, ce_status), "Keys/CSR generation error");

    // Call the EST client

    // If lwm2m device certificate - set cert name to NULL and request EST enrollment
    if (pv_str_equals(g_lwm2m_name, renewal_data->cert_name, (uint32_t)(strlen(g_lwm2m_name) + 1))) {
        SA_PV_LOG_INFO("Attempting to renew LwM2M device certificate\n");
        cert_name = NULL;
        cert_name_size = 0;
    } else {
        SA_PV_LOG_INFO("Attempting to renew a custom certificate\n");
        cert_name = renewal_data->cert_name;
        cert_name_size = strlen(renewal_data->cert_name);
    }

    // Request a certificate from a CSR via the EST service
    est_status = g_est_client->est_request_enrollment(cert_name, cert_name_size, renewal_data->csr, renewal_data->csr_size, est_cb, NULL);
    // FIXME: Currently commented out. If we find that the CSR must be persistent only during est_request_enrollment call - uncomment, and this should be the only place we free the CSR
    //free(renewal_data->csr);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((est_status != EST_STATUS_SUCCESS), certificate_renewal_finish(renewal_data, CE_STATUS_EST_ERROR), "EST request failed");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

ce_status_e CertificateEnrollmentClient::schedule_event(event_type_e event_type)
{
    int8_t event_status;

    arm_event_s event = {
        .receiver = handler_id, // ID we got when creating our handler
        .sender = 0, // Which tasklet sent us the event is irrelevant to us 
        .event_type = event_type, // Indicate event type 
        .event_id = 0, // We currently do not need an ID for a specific event - event type is enough
        .data_ptr = 0, // Not needed, data handled in internal structure
        .priority = ARM_LIB_LOW_PRIORITY_EVENT, // Application level priority
        .event_data = 0, // With one certificate this is irrelevant. If allow multiple certificates, This will be a certificate descriptor (index in a CertificateRenewalDataBase list)
    };

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    event_status = eventOS_event_send(&event);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((event_status < 0), CE_STATUS_OUT_OF_MEMORY, "Error scheduling event");

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
    return CE_STATUS_SUCCESS;
}

void CertificateEnrollmentClient::est_cb(est_enrollment_result_e result,
                                         cert_chain_context_s *cert_chain,
                                         void *context)
{
    ce_status_e status;
    SA_PV_LOG_INFO_FUNC_ENTER("result = %d", result);

    PV_UNUSED_PARAM(context);
    if (result != EST_ENROLLMENT_SUCCESS || cert_chain == NULL) {
        return certificate_renewal_finish(current_cert, CE_STATUS_EST_ERROR);
    }

    // Cert chain remains persistent until g_est_client->free_cert_chain_context is called
    current_cert->est_data = cert_chain;

    status = schedule_event(CertificateEnrollmentClient::EVENT_TYPE_EST_RESPONDED);
    if (status != CE_STATUS_SUCCESS) { // If event scheduling fails - free the chain context and finish the process
        SA_PV_LOG_INFO("Error scheduling event");
        g_est_client->free_cert_chain_context(current_cert->est_data);

        // Make sure we do not keep an invalid pointer
        current_cert->est_data = NULL;
        certificate_renewal_finish(current_cert, status);
    }

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

void CertificateEnrollmentClient::est_response_process(CertificateRenewalDataBase *renewal_data)
{
    ce_status_e ce_status;
    ce_renewal_params_s params;
    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    // Fill params
    params.cert_data = renewal_data->est_data;
    params.crypto_handle = renewal_data->key_handle;

    // Perform a safe renewal
    ce_status = ce_safe_renewal(renewal_data->cert_name, &renewal_data->renewal_items_names, &params);

    // Free the est chain. Do not free in the destructor, we'd rather free it as soon as possible
    g_est_client->free_cert_chain_context(renewal_data->est_data);
    renewal_data->est_data = NULL;

    // Done!
    certificate_renewal_finish(renewal_data, ce_status);
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

void CertificateEnrollmentClient::certificate_renewal_finish(CertificateRenewalDataBase *renewal_data, ce_status_e exit_status)
{
    palStatus_t pal_status;
    SA_PV_LOG_INFO_FUNC_ENTER("exit_status = %d", exit_status);

    // Don't leave an invalid global pointer
    current_cert = NULL;

    // Note: release of the mutex is before the deletion of the object (which holds the allocated cert_name)
    // and before the user callback is invoked (so that the user may call the renewal API successfully from within his callback)
    pal_status = pal_osSemaphoreRelease(g_renewal_sem);
    if (PAL_SUCCESS != pal_status) { // 
        exit_status = CE_STATUS_ERROR;
    }

    // At this point, new device requests may be made and the global pointer CertificateEnrollmentClient::current_cert may be changed.
    // Therefore, we use the renewal_data pointer that was past as a parameter to this function
    // New server requests will not be made until after this function returns since the response to the server is enqueued into the event loop by renewal_data->finish()
    // and it is guaranteed that the server will not send another request until it receives a response.
    renewal_data->finish(exit_status);

    delete renewal_data;

    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();
}

#ifdef CERT_RENEWAL_TEST
void CertificateEnrollmentClient::testonly_certificate_renewal_post(void *arg)
{
    return certificate_renewal_post(arg);
}


#endif // CERT_RENEWAL_TEST

#endif // #ifndef MBED_CONF_MBED_CLOUD_CLIENT_DISABLE_CERTIFICATE_ENROLLMENT
