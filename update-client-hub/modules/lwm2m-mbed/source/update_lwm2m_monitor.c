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

#include "device_metadata.h"
#include "firmware_update.h"
#include "update_lwm2m_monitor.h"

static uint32_t get_version(void);
static ARM_MONITOR_CAPABILITIES get_capabilities(void);
static arm_uc_error_t initialize(void (*notification_handler)(void));
static arm_uc_error_t destroy(void);
static arm_uc_error_t send_state(arm_uc_monitor_state_t an_update_state);
static arm_uc_monitor_state_t get_state();
static arm_uc_error_t send_update_result(arm_uc_monitor_result_t an_update_result);
static arm_uc_error_t send_name(arm_uc_buffer_t *name);
static arm_uc_error_t send_version(uint64_t version);
static arm_uc_error_t set_bootloader_hash(arm_uc_buffer_t *hash);
static arm_uc_error_t set_oem_bootloader_hash(arm_uc_buffer_t *hash);

static const ARM_UPDATE_MONITOR lwm2m_monitor = {
    .GetVersion           = get_version,
    .GetCapabilities      = get_capabilities,
    .Initialize           = initialize,
    .Uninitialize         = destroy,

    .SendState            = send_state,
    .GetState             = get_state,
    .SendUpdateResult     = send_update_result,
    .SendName             = send_name,
    .SendVersion          = send_version,

    .SetBootloaderHash    = set_bootloader_hash,
    .SetOEMBootloaderHash = set_oem_bootloader_hash
};

const ARM_UPDATE_MONITOR *get_update_lwm2m_monitor(void)
{
    return &lwm2m_monitor;
}

/**
 * @brief Get driver version.
 * @return Driver version.
 */
static uint32_t get_version(void)
{
    return 0;
}

/**
 * @brief Get Source capabilities.
 * @return Struct containing capabilites. See definition above.
 */
static ARM_MONITOR_CAPABILITIES get_capabilities(void)
{
    ARM_MONITOR_CAPABILITIES result;
    result.state   = 1;
    result.result  = 1;
    result.version = 1;

    return result;
}

/**
 * @brief Initialize Monitor.
 * @return Error code.
 */
static arm_uc_error_t initialize(void (*notification_handler)(void))
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (!firmware_update_initialize(ARM_UCS_LWM2M_SOURCE_registry_get())) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
        return result;
    }

    firmware_update_add_notification_callback(notification_handler);

    if (!device_metadata_create(ARM_UCS_LWM2M_SOURCE_registry_get())) {
        firmware_update_destroy(ARM_UCS_LWM2M_SOURCE_registry_get());
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
        return result;
    }

    return result;
}

/**
 * @brief Uninitialized Monitor.
 * @return Error code.
 */
static arm_uc_error_t destroy(void)
{
    ARM_UC_INIT_ERROR(retval, ERR_NONE);
    return retval;
}

/**
 * @brief Send Update Client state.
 * @details From the OMA LWM2M Technical Specification:
 *
 *          Indicates current state with respect to this firmware update.
 *          This value is set by the LWM2M Client in accordance with state
 *          and arm_uc_monitor_state_t type.
 *
 * @return Error code.
 */
static arm_uc_error_t send_state(arm_uc_monitor_state_t an_update_state)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);


    if (!firmware_update_send_state(ARM_UCS_LWM2M_SOURCE_registry_get(), an_update_state)) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }

    return result;
}

static arm_uc_monitor_state_t get_state()
{
    return (arm_uc_monitor_state_t)firmware_update_get_state(ARM_UCS_LWM2M_SOURCE_registry_get());
}

/**
 * @brief Send update result.
 * @details From the OMA LWM2M Technical Specification:
 *          Contains the result of downloading or updating the firmware
 *          This Resource MAY be reported by sending Observe operation.
 *
 * @return Error code.
 */
static arm_uc_error_t send_update_result(arm_uc_monitor_result_t an_update_result)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);


    if (!firmware_update_send_update_result(ARM_UCS_LWM2M_SOURCE_registry_get(), an_update_result)) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }

    return result;
}

/**
 * @brief Send current firmware name.
 * @details The firmware name is the SHA256 hash.
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
static arm_uc_error_t send_name(arm_uc_buffer_t *name)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (!firmware_update_send_pkg_name(ARM_UCS_LWM2M_SOURCE_registry_get(), name->ptr, name->size)) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }

    return result;
}

/**
 * @brief Send current firmware version.
 * @details The firmware version is the timestamp from the manifest that
 *          authorized the firmware.
 * @param version Timestamp, 64 bit unsigned integer.
 * @return Error code.
 */
static arm_uc_error_t send_version(uint64_t version)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (!firmware_update_send_pkg_version(ARM_UCS_LWM2M_SOURCE_registry_get(), version)) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }

    return result;
}

/**
 * @brief Set the bootloader hash.
 * @details The bootloader hash is a hash of the bootloader. This is
 *          used for tracking the version of the bootloader used.
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
static arm_uc_error_t set_bootloader_hash(arm_uc_buffer_t *hash)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (!device_metadata_set_bootloader_hash(ARM_UCS_LWM2M_SOURCE_registry_get(), hash)) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }

    return result;
}

/**
 * @brief Set the OEM bootloader hash.
 * @details If the end-user has modified the bootloader the hash of the
 *          modified bootloader can be set here.
 * @param name Pointer to buffer struct. Hash is stored as byte array.
 * @return Error code.
 */
static arm_uc_error_t set_oem_bootloader_hash(arm_uc_buffer_t *hash)
{
    ARM_UC_INIT_ERROR(result, ERR_NONE);

    if (!device_metadata_set_oem_bootloader_hash(ARM_UCS_LWM2M_SOURCE_registry_get(), hash)) {
        ARM_UC_SET_ERROR(result, ERR_UNSPECIFIED);
    }

    return result;
}

#endif //LWM2M_SOURCE_USE_C_API

