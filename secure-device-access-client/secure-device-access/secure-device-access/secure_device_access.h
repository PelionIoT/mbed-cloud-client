// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
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

#ifndef __SECURE_DEVICE_ACCESS_H__
#define __SECURE_DEVICE_ACCESS_H__

#include <stdlib.h>
#include <inttypes.h>
#include "sda_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file secure_device_access.h \brief Device-based authorization APIs.
 *
 * Secure Device Access enables policy-based access control for IoT
 * devices. It allows you to control who can access IoT devices, and what they
 * can change on that device. An Mbed device that supports Secure Device Access
 * can validate permissions even when it is offline (not connected to Device
 * Management).
 *
 * To give users, such as service technicians, permission to access IoT devices,
 * the device owner defines one or more policies on Device Management to control who
 * can access devices and what they can do.
 *
 * Once the policies are defined, you access the IoT device as
 * follows:
 *
 * 1. On a proxy device (tablet or smartphone), use
 *    the SDA app (which uses Secure Device Access Proxy APIs) to request access
 *    to the IoT device from Device Management. If you have permission, Device Management
 *    sends an access token, which must be presented to the IoT device with the
 *    requested actions. For this, you must be connected to the Device
 *    Management.
 * 2. When the Secure Device Access app on the proxy device presents the access
 *    token and a set of actions to the Secure Device Access client app on the
 *    IoT device, the client app verifies the validity of the access token and,
 *    if the token is accepted, performs the requested actions. **Note:** Neither
 *    the proxy nor the IoT device need to be online for this as long as they can
 *    connect to each other.
 *
 * The proxy interacts with the client using a platform-agnostic protocol;
 * therefore, you can use any medium to connect, such as Ethernet,
 * Bluetooth, UART, or USB.
 *
 * The applications on the IoT device and proxy device communicate using the
 * Secure Device Access APIs to proxy parse and handle the Secure Device access
 * messages.
 *
 */



typedef void *sda_operation_ctx_h;

//! User callback that defines and checks operation permissions and performs the operation.
typedef sda_status_e(*user_callback)(sda_operation_ctx_h, void *);

// Type of operation command.
typedef enum {
    SDA_OPERATION_NONE = 0,
    SDA_OPERATION_FUNC_CALL = 1,//Name or reference to operation function.
    SDA_OPERATION_LWM2M = 2     // Not supported.
} sda_command_type_e;

//! Minimum buffer size requested for response buffer for `sda_operation_process()`.
#define SDA_RESPONSE_HEADER_SIZE 24

/** Initializes the secure device access module.
 *
 * @return
 *       ::SDA_STATUS_SUCCESS in success. Otherwise, one of the `::sda_status_e`
 *       errors.
 */
sda_status_e sda_init(void);

/** Finalizes the secure device access module.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in success. Otherwise one of the `::sda_status_e`
 *       errors.
 */
sda_status_e sda_finalize(void);

/** Processes a single input message, performs all needed message verifications,
 * and fills the context with relevant data for the following call of the user application callback.
 * After message verification, the API calls the user callback and passes the operation handle and user context.
 * This function must only be called after `::sda_init()` has been called.
 *
 * The input message is parsed in-place.
 * As output, the function fills the response message, which includes the operation type and status, and specific message information.
 *
 * @param message[in] Message to process.
 * @param message_size[in] Message size.
 * @param callback[in] Pointer to the user callback.
 * @param callback_context[in] Pointer to the context to call the user callback with - optional, can be NULL.
 * @param response_buffer_out[out] Pointer to the response message buffer allocated by the user.
 * @param response_buffer_out_max_size[in] Maximum size allocated for the response message buffer. Must be at least 
 * `::SDA_RESPONSE_HEADER_SIZE` + the size of the application data that may be sent through the `sda_response_data_set()` function.
 * @param response_message_actual_size_out[out] Actual size of the response message. If the response message wasn't created, 
 * the actual size is 0.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in success.
 *       `::SDA_STATUS_NOT_INITIALIZED` if the SDA module wasn't initialized.
 *        Otherwise, one of the `::sda_status_e` errors.
 */
sda_status_e sda_operation_process(const uint8_t *message,
                                   size_t message_size,
                                   user_callback callback,
                                   void *callback_context,
                                   uint8_t *response_buffer_out,
                                   size_t response_buffer_out_max_size,
                                   size_t *response_message_actual_size_out);

/** Sets application-specific data to be sent to the proxy.
* The API copies the user buffer directly to the response buffer that the user provides to the `sda_operation_process()` API.
* The function must be called from the context of the user callback that the user provides to the `sda_operation_process()` API.
* This function must only be called after the `::sda_init()` function has been called.
*
* Currently, calling this function twice in the context of a user callback results in undefined behavior.

* @param handle[in] The handle is received as the input argument to the user callback.
* @param buffer[in] Pointer to the application-specific data to be copied to the `response_buffer_out` that the user provides to the `sda_operation_process()` API.
* @param buffer_size[in] Size of buffer in bytes. The maximum size is `response_buffer_out_max_size` that the user provides to the `sda_operation_process()` API, minus `::SDA_RESPONSE_HEADER_SIZE`.
*
* @return
*       `::SDA_STATUS_SUCCESS` in success.
*       `::SDA_STATUS_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR` if the response buffer size that the user provides to `sda_operation_process()` is insufficient.
*       `::SDA_STATUS_NOT_INITIALIZED` if the SDA module wasn't initialized.
*        Otherwise, one of the `::sda_status_e` errors.
*/
sda_status_e sda_response_data_set(sda_operation_ctx_h handle, uint8_t *buffer,
                                   size_t buffer_size);



/** Retrieves the next scope in the list of scopes of the currently
 *  processed message.
 *
 * Scope is a collection of bytes, which isn't '\0'-terminated. Its size is
 * also returned.
 * The output scope pointer points inside the message buffer; therefore, the pointer should
 * not be released manually.
 * This function must only be called after `::sda_init()` and '::sda_operation_process()' have been called.
 *
 * @param handle[in] Initialized context handle.
 * @param scope[out] Pointer to the scope of current command.
 * @param scope_size_out[out] Size of retrieved scope.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in case of success.
 *       `::SDA_STATUS_NOT_INITIALIZED` if the SDA module wasn't initialized.
 *        Otherwise, one of the `::sda_status_e` errors.
 */
sda_status_e sda_scope_get_next(sda_operation_ctx_h handle, const uint8_t **scope_out,
                                size_t *scope_size_out);

/** Retrieves the command type of the currently processed message.
 *
 * This function must only be called after `::sda_init()` and `::sda_operation_process()` have been called.
 *
 * @param handle[in] Initialized context handle.
 * @param command_type[out] Pointer to type out parameter.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in success.
 *       `::SDA_STATUS_NOT_INITIALIZED` if the SDA module wasn't initialized.
 *        Otherwise, one of the `::sda_status_e` errors.
 */
sda_status_e sda_command_type_get(sda_operation_ctx_h handle, sda_command_type_e *command_type);

/** Retrieves a pointer to the function name of the function call command.
 *
 * Function name is a collection of bytes, which isn't '\0'-terminated. Its size
 * is also returned.
 * The output function name pointer points inside the message buffer; therefore, the pointer
 * should not be released manually.
 * This function must only be called after `::sda_init()` and `::sda_operation_process()` have been called.
 *
 * @param handle[in] Initialized context handle.
 * @param func_call_name_out[out] Pointer to current function call name.
 * @param func_call_name_size_out[out] Size of current function call name.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in success.
 *       `::SDA_STATUS_NOT_INITIALIZED` if the SDA module wasn't initialized.
 *        Otherwise, one of the `::sda_status_e` errors.
 */
sda_status_e sda_func_call_name_get(sda_operation_ctx_h handle, const uint8_t **func_call_name_out,
                                    size_t *func_call_name_size_out);

/** Retrieves numeric parameter of function call command.
 *
 * If the requested parameter is not numeric, an error is returned.
 * This function must only be called after `::sda_init()` and `::sda_operation_process()` have been called.
 *
 * @param handle[in] Initialized context handle.
 * @param index[in] Index of needed parameter (zero based).
 * @param num_param_out[out] Output parameter value.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in success.
 *       `::SDA_STATUS_NOT_INITIALIZED` if the SDA module wasn't initialized.
 *        Otherwise, one of the `::sda_status_e` errors.
 */
sda_status_e sda_func_call_numeric_parameter_get(sda_operation_ctx_h handle, uint32_t index,
        int64_t *num_param_out);

/** Retrieves a pointer to a data parameter of a function call command.
 *
 * Data is a collection of bytes, which isn't '\0'-terminated. Its size is
 * also returned.
 * The output data pointer points inside the message buffer; therefore, the pointer
 * should not be released manually.
 * This function must only be called after `::sda_init()` and `::sda_operation_process()` have been called.
 *
 * @param handle[in] Initialized context handle.
 * @param index[in] Index of needed parameter (zero based).
 * @param data_param_out[out] Pointer to data parameter value.
 * @param data_param_size_out[out] Pointer to data parameter size.
 *
 * @return
 *       `::SDA_STATUS_SUCCESS` in success. Otherwise, one of the `::sda_status_e` errors.
 */
sda_status_e sda_func_call_data_parameter_get(sda_operation_ctx_h handle, uint32_t index,
        const uint8_t **data_param_out,
        size_t *data_param_size_out);


#ifdef __cplusplus
}
#endif

#endif //__SECURE_DEVICE_ACCESS_H__
