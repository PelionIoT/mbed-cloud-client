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

#include "pal4life-device-identity/pal_device_identity.h"
#include "lwm2m_registry.h"
#include "device_metadata.h"

#define PROTOCOL_VERSION 2

static bool initialized = false;

bool device_metadata_create(registry_t *registry)
{
    arm_uc_guid_t guid;
    registry_path_t path;

    //TODO: Are these resources needed?
    if (initialized) {
        return true;
    }

    /* Create Update resource /10255/0/0 */
    registry_set_path(&path, 10255, 0, 0, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_int(registry, &path, PROTOCOL_VERSION)) {

        return false;
    }

    if (REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        device_metadata_destroy(registry);
        return false;
    }

    /* Create Update resource /10255/0/1 */
    registry_set_path(&path, 10255, 0, 1, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_empty(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        device_metadata_destroy(registry);
        return false;
    }

    /* Create Update resource /10255/0/2 */
    registry_set_path(&path, 10255, 0, 2, 0, REGISTRY_PATH_RESOURCE);

    if (REGISTRY_STATUS_OK != registry_set_value_empty(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        device_metadata_destroy(registry);
        return false;
    }

    /* Create Update resource /10255/0/3 */
    registry_set_path(&path, 10255, 0, 3, 0, REGISTRY_PATH_RESOURCE);

    if (ERR_NONE != pal_getVendorGuid(&guid).error ||
        REGISTRY_STATUS_OK != registry_set_value_opaque_copy(registry, &path, guid, sizeof(guid)) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        device_metadata_destroy(registry);
        return false;
    }

    /* Create Update resource /10255/0/4 */
    registry_set_path(&path, 10255, 0, 4, 0, REGISTRY_PATH_RESOURCE);

    if (ERR_NONE != pal_getClassGuid(&guid).error ||
        REGISTRY_STATUS_OK != registry_set_value_opaque_copy(registry, &path, guid, sizeof(guid)) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        device_metadata_destroy(registry);
        return false;
    }

    /* Create Update resource /10255/0/5 */
    registry_set_path(&path, 10255, 0, 5, 0, REGISTRY_PATH_RESOURCE);

    if (ERR_NONE != pal_getDeviceGuid(&guid).error ||
        REGISTRY_STATUS_OK != registry_set_value_opaque_copy(registry, &path, guid, sizeof(guid)) ||
        REGISTRY_STATUS_OK != registry_set_auto_observable_parameter(registry, &path, true) ||
        REGISTRY_STATUS_OK != registry_set_resource_value_to_reg_msg(registry, &path, true)) {

        //TODO: It seems like pal_getDeviceGuid may return error, do we need it?

    }

    initialized = true;

    return true;

}

bool device_metadata_set_bootloader_hash(registry_t *registry, arm_uc_buffer_t *hash)
{
    registry_path_t path;

    UC_SRCE_TRACE("device_metadata_set_bootloader_hash ptr %p size %" PRIu32, hash, hash->size);

    registry_set_path(&path, 10255, 0, 2, 0, REGISTRY_PATH_RESOURCE);

    return (REGISTRY_STATUS_OK == registry_set_value_opaque_copy(registry, &path, hash->ptr, hash->size));
}

bool device_metadata_set_oem_bootloader_hash(registry_t *registry, arm_uc_buffer_t *hash)
{
    registry_path_t path;

    UC_SRCE_TRACE("device_metadata_set_oem_bootloader_hash ptr %p size %" PRIu32, hash, hash->size);

    registry_set_path(&path, 10255, 0, 3, 0, REGISTRY_PATH_RESOURCE);

    return (REGISTRY_STATUS_OK == registry_set_value_opaque_copy(registry, &path, hash->ptr, hash->size));
}


void device_metadata_destroy(registry_t *registry)
{
    registry_path_t path;

    UC_SRCE_TRACE("device_metadata_destroy()");

    registry_set_path(&path, 10255, 0, 0, 0, REGISTRY_PATH_OBJECT);

    registry_remove_object(registry, &path, REGISTRY_REMOVE);

    initialized = false;
}

#endif //LWM2M_SOURCE_USE_C_API

