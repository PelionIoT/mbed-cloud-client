// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#include "lwm2m-source.h"

#ifdef LWM2M_SOURCE_USE_C_API

#include <inttypes.h>
#include <stdio.h>

#include "update-client-common/arm_uc_config.h"
#include "update-client-common/arm_uc_common.h"
#include "source/update_client_hub_state_machine.h"
#include "source/update_client_hub_error_handler.h"

#include "lwm2m_registry.h"
#include "lwm2m_registry_handler.h"

#include "firmware_update.h"

#define ARM_UCS_LWM2M_INTERNAL_ERROR (-1)
#define ARM_UCS_LWM2M_INTERNAL_SUCCESS (0)

/* send delayed response */
enum {
    ResourcePackage,
    ResourcePackageURI,
    ResourceUpdate
};

/* Default values are non-standard, but the standard has no
   values for indicating that the device is initializing.
   To address this, Service ignores -1 and/or 255 values coming through,
   so for our purposes this is the correct form of initialization.
*/
const int64_t default_value = -1;

/* function pointers to callback functions */
static void (*notification_callback)(void) = NULL;

static bool initialized = false;

static registry_status_t manifest_executed(registry_callback_type_t type,
                                           const registry_path_t *path,
                                           const registry_callback_token_t *token,
                                           const registry_object_value_t *value,
                                           const registry_notification_status_t status,
                                           registry_t *registry);

static registry_status_t notification_status(registry_callback_type_t type,
                                               const registry_path_t *path,
                                               const registry_callback_token_t *token,
                                               const registry_object_value_t *value,
                                               const registry_notification_status_t delivery_status,
                                               registry_t *registry);


bool firmware_update_initialize(registry_t *registry)
{
    registry_path_t path;


    static const char defaultVersion[] = "-1";

    if (initialized) {
        return true;
    }

    /* Create Package resource /10252/0/1 */
    registry_set_path(&path, 10252, 0, 1, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_empty(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_callback(registry, &path, &manifest_executed)) {

        firmware_update_destroy(registry);
        return false;
    }

    /* Create State resource /10252/0/2 */
    registry_set_path(&path, 10252, 0, 2, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, default_value) ||
        REGISTRY_STATUS_OK != registry_set_callback(registry, &path, notification_status) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        firmware_update_destroy(registry);
        return false;
    }

    /* Create Update Result resource /10252/0/3 */
    registry_set_path(&path, 10252, 0, 3, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, default_value) ||
        REGISTRY_STATUS_OK != registry_set_callback(registry, &path, notification_status) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        firmware_update_destroy(registry);
        return false;
    }


    /* Create PkgName resource /10252/0/5 */
    registry_set_path(&path, 10252, 0, 5, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_string(registry, &path, (char*)defaultVersion, false) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        firmware_update_destroy(registry);
        return false;
    }

    /* Create PkgVersion resource /10252/0/6 */
    registry_set_path(&path, 10252, 0, 6, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_string(registry, &path, (char*)defaultVersion, false) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        firmware_update_destroy(registry);
        return false;
    }

    initialized = true;

    return true;

}

static registry_status_t manifest_executed(registry_callback_type_t type,
                                           const registry_path_t *path,
                                           const registry_callback_token_t *token,
                                           const registry_object_value_t *value,
                                           const registry_notification_status_t status,
                                           registry_t *registry)

{

    registry_path_t temp_path;
    (void) status;

    if (type != REGISTRY_CALLBACK_EXECUTE) {
        return REGISTRY_STATUS_OK;
    }

    if (!value->generic_value.data.opaque_data->size) {
        UC_SRCE_ERR_MSG("received empty manifest");
        send_execute_response(path, registry->notifier->endpoint, token->token, token->token_size, COAP_MSG_CODE_RESPONSE_BAD_REQUEST);
        return REGISTRY_STATUS_OK;
    }

    UC_SRCE_TRACE("manifest_executed()");

    // Reset the resource values for every new Campaign
    // to make sure values of new Campaign get sent to service
    registry_set_path(&temp_path, 10252, 0, 2, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &temp_path, default_value)) {
        //TODO: Is handling needed here?
    }

    registry_set_path(&temp_path, 10252, 0, 3, 0, REGISTRY_PATH_RESOURCE);
    if (REGISTRY_STATUS_OK != registry_set_value_empty(registry, &temp_path, true)) {
        //TODO Is handling needed here?
    }

    /* invoke external callback function */
    if (ARM_UCS_LWM2M_SOURCE_manifast_received(value->generic_value.data.opaque_data->data, value->generic_value.data.opaque_data->size)) {
        send_execute_response(path, registry->notifier->endpoint, token->token, token->token_size, COAP_MSG_CODE_RESPONSE_CHANGED);
    } else {
        send_execute_response(path, registry->notifier->endpoint, token->token, token->token_size, COAP_MSG_CODE_RESPONSE_INTERNAL_SERVER_ERROR);
    }

    return REGISTRY_STATUS_OK;

}



static registry_status_t notification_status(registry_callback_type_t type,
                                               const registry_path_t *path,
                                               const registry_callback_token_t *token,
                                               const registry_object_value_t *value,
                                               const registry_notification_status_t delivery_status,
                                               registry_t *registry)

{

    (void)token;
    (void)value;
    (void)registry;

    if (REGISTRY_CALLBACK_NOTIFICATION_STATUS != type) {
        return REGISTRY_STATUS_OK;
    }

    UC_SRCE_TRACE("notification_status() status: %d", delivery_status);
    UC_SRCE_TRACE("Callback for resource: /%d/%d/%d", path->object_id, path->object_instance_id, path->resource_id);

    if (delivery_status == NOTIFICATION_STATUS_DELIVERED) {
        // Notification has been ACKed by server, complete to callback
        UC_SRCE_TRACE("NOTIFICATION_STATUS_DELIVERED");

        if (notification_callback) {
            notification_callback();
        }
    } else if (delivery_status == NOTIFICATION_STATUS_BUILD_ERROR ||
               delivery_status == NOTIFICATION_STATUS_RESEND_QUEUE_FULL ||
               delivery_status == NOTIFICATION_STATUS_SEND_FAILED ||
               delivery_status == NOTIFICATION_STATUS_UNSUBSCRIBED) {
        // Error case, notification not reaching service
        // We are sending out error because we cannot rely connection is
        // anymore up and the service and client are not in sync anymore.
        // Also sending new notifications after this might lock event
        // machine because comms cannot service us anymore.
        UC_SRCE_ERR_MSG("Received Notification delivery status: %d - ERROR!", delivery_status);
        ARM_UC_HUB_ErrorHandler(HUB_ERR_CONNECTION, ARM_UC_HUB_getState());
    } else {
        // NOTIFICATION_STATUS_INIT
        // NOTIFICATION_STATUS_SENT
        // NOTIFICATION_STATUS_SUBSCRIBED
        UC_SRCE_TRACE("FirmwareUpdateResource::notificationCallback Status ignored, waiting delivery...");
    }

    return REGISTRY_STATUS_OK;
}

/*****************************************************************************/
/* Update Client Source                                                      */
/*****************************************************************************/

/* Add callback for when send{State, UpdateResult} is done */
void firmware_update_add_notification_callback(void (*cb)(void))
{
    UC_SRCE_TRACE("firmware_update_add_notification_callback: %p", cb);

    notification_callback = cb;
}

/*****************************************************************************/
/* Update Client Status                                                      */
/*****************************************************************************/

/* Send state for resource /10252/0/2, State */
bool firmware_update_send_state(registry_t *registry, int64_t state)
{
    registry_path_t path;

    UC_SRCE_TRACE("firmware_update_send_state()");

    registry_set_path(&path, 10252, 0, 2, 0, REGISTRY_PATH_RESOURCE);

    return (REGISTRY_STATUS_OK == registry_set_value_int(registry, &path, state));
}

/* Send result for resource /10252/0/3, Update Result */
bool firmware_update_send_update_result(registry_t *registry, int64_t updateResult)
{
    registry_path_t path;

    UC_SRCE_TRACE("firmware_update_send_update_result()");

    registry_set_path(&path, 10252, 0, 3, 0, REGISTRY_PATH_RESOURCE);

    return (REGISTRY_STATUS_OK == registry_set_value_int(registry, &path, updateResult));
}

/* Send name for resource /10252/0/5 PkgName */

/* the maximum length is defined in the OMA LWM2M standard. */
#define MAX_PACKAGE_NAME_CHARS 32

bool firmware_update_send_pkg_name(registry_t *registry, const uint8_t *name, uint16_t length)
{
    registry_path_t path;
    uint8_t value[MAX_PACKAGE_NAME_CHARS * 2] = { 0 };
    uint8_t index = 0;

    UC_SRCE_TRACE("firmware_update_send_pkg_name()");

    /* convert to printable characters using lookup table */
    for (; (index < 32) && (index < length); index++) {
        value[2 * index    ] = arm_uc_hex_table[name[index] >> 4];
        value[2 * index + 1] = arm_uc_hex_table[name[index] & 0x0F];
    }

    registry_set_path(&path, 10252, 0, 3, 0, REGISTRY_PATH_RESOURCE);

    return (REGISTRY_STATUS_OK == registry_set_value_string_copy(registry, &path, value, 2 * index));
}

/* Send version for resource /10252/0/6, PkgVersion */
#define MAX_PACKAGE_VERSION_CHARS 21

bool firmware_update_send_pkg_version(registry_t *registry, uint64_t version)
{
    registry_path_t path;
    uint8_t value[MAX_PACKAGE_VERSION_CHARS + 1] = { 0 };
    int length;

    UC_SRCE_TRACE("firmware_update_send_pkg_version()");

    length = snprintf((char *)value, MAX_PACKAGE_VERSION_CHARS, "%" PRIu64, version);

    /* We are assuming that the MAX_PACKAGE_VERSION_CHARS is enough here,
     * and that encoding errors cannot happen . */

    registry_set_path(&path, 10252, 0, 6, 0, REGISTRY_PATH_RESOURCE);

    return (REGISTRY_STATUS_OK == registry_set_value_string_copy(registry, &path, value, length));
}

void firmware_update_destroy(registry_t *registry)
{
    registry_path_t path;
    UC_SRCE_TRACE("firmware_update_destroy()");

    registry_set_path(&path, 10252, 0, 0, 0, REGISTRY_PATH_OBJECT);

    registry_remove_object(registry, &path, REGISTRY_REMOVE);

    initialized = false;

}

#endif //LWM2M_SOURCE_USE_C_API
