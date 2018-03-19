// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#include <string.h>
#include "key_config_manager.h"
#include "CloudClientStorage.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "mClt"

ccs_status_e uninitialize_storage(void)
{
    tr_debug("CloudClientStorage::uninitialize_storage");

    kcm_status_e status = kcm_finalize();
    if(status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::uninitialize_storage - error %d", status);
        return CCS_STATUS_ERROR;
    }
    return CCS_STATUS_SUCCESS;
}

ccs_status_e initialize_storage(void)
{
    tr_debug("CloudClientStorage::initialize_storage");
    kcm_status_e status = kcm_init();
    if(status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::::initialize_storage - error %d", status);
        return CCS_STATUS_ERROR;
    }
    return CCS_STATUS_SUCCESS;
}

ccs_status_e get_config_parameter(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::get_config_parameter error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::get_config_parameter [%s]", key);

    // Get parameter value to buffer
    kcm_status_e kcm_status = kcm_item_get_data((const uint8_t*)key,
                                    strlen(key),
                                    KCM_CONFIG_ITEM,
                                    buffer,
                                    buffer_size,
                                    value_length);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::get_config_parameter [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e get_config_parameter_string(const char* key, uint8_t *buffer, const size_t buffer_size)
{
    size_t len = 0;
    ccs_status_e status = get_config_parameter(key, buffer, buffer_size - 1, &len);

    if (status == CCS_STATUS_SUCCESS) {
        // Null terminate after buffer value
        buffer[len] = 0;
    }

    return status;
}


ccs_status_e set_config_parameter(const char* key, const uint8_t *buffer, const size_t buffer_size)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::set_config_parameter error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::set_config_parameter [%s]", key);

    // Set parameter to storage
    kcm_status_e kcm_status = kcm_item_store((const uint8_t*)key,
                                 strlen(key),
                                 KCM_CONFIG_ITEM,
                                 false,
                                 buffer,
                                 buffer_size,
                                 NULL);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::set_config_parameter [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e delete_config_parameter(const char* key)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::delete_config_parameter error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::delete_config_parameter [%s]", key);

    // Delete parameter from storage
    kcm_status_e kcm_status = kcm_item_delete((const uint8_t*)key,
                                  strlen(key),
                                  KCM_CONFIG_ITEM);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::delete_config_parameter [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e size_config_parameter(const char* key, size_t* size_out)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::size_config_parameter error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::size_config_parameter [%s]", key);

    // Delete parameter from storage
    kcm_status_e kcm_status = kcm_item_get_data_size((const uint8_t*)key,
                                         strlen(key),
                                         KCM_CONFIG_ITEM,
                                         size_out);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::size_config_parameter [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e get_config_private_key(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::get_connector_private_key error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::get_connector_private_key [%s]", key);

    // Get private key from storage
    kcm_status_e kcm_status = kcm_item_get_data((const uint8_t*)key,
                                    strlen(key),
                                    KCM_PRIVATE_KEY_ITEM,
                                    buffer,
                                    buffer_size,
                                    value_length);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::get_connector_private_key [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e set_config_private_key(const char* key, const uint8_t *buffer, const size_t buffer_size)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::set_connector_private_key error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::set_connector_private_key kcm [%s]", key);

    // Set private key to storage
    kcm_status_e kcm_status = kcm_item_store((const uint8_t*)key,
                                 strlen(key),
                                 KCM_PRIVATE_KEY_ITEM,
                                 false,
                                 buffer,
                                 buffer_size,
                                 NULL);

    if (kcm_status == KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED) {
        tr_error("CloudClientStorage::set_connector_private_key kcm validation error");
        return CCS_STATUS_VALIDATION_FAIL;
    }
    else if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::set_connector_private_key kcm [%s] get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e delete_config_private_key(const char* key)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::delete_config_private_key error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::delete_config_private_key [%s]", key);

    // Delete private key from storage
    kcm_status_e kcm_status = kcm_item_delete((const uint8_t*)key,
                                  strlen(key),
                                  KCM_PRIVATE_KEY_ITEM);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::delete_config_private_key [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e get_config_public_key(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::get_config_public_key error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::get_config_public_key [%s]", key);

    // Get parameter value to buffer
    kcm_status_e kcm_status = kcm_item_get_data((const uint8_t*)key,
                                    strlen(key),
                                    KCM_PUBLIC_KEY_ITEM,
                                    buffer,
                                    buffer_size,
                                    value_length);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::get_config_public_key [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e set_config_public_key(const char* key, const uint8_t *buffer, const size_t buffer_size)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::set_config_public_key error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::set_config_public_key - kcm [%s]", key);

    // Set public key to storage
    kcm_status_e kcm_status = kcm_item_store((const uint8_t*)key,
                                 strlen(key),
                                 KCM_PUBLIC_KEY_ITEM,
                                 false,
                                 buffer,
                                 buffer_size,
                                 NULL);

    if (kcm_status == KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED) {
        tr_error("CloudClientStorage::set_config_public_key - kcm validation error");
        return CCS_STATUS_VALIDATION_FAIL;
    }
    else if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::set_config_public_key - kcm [%s] get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e delete_config_public_key(const char* key)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::delete_config_public_key error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::delete_config_public_key [%s]", key);

    // Delete the public key
    kcm_status_e kcm_status = kcm_item_delete((const uint8_t*)key,
                                  strlen(key),
                                  KCM_PUBLIC_KEY_ITEM);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::delete_config_public_key [%s] kcm get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e get_config_certificate(const char* key, uint8_t *buffer, const size_t buffer_size, size_t *value_length)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::get_config_certificate error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::get_config_certificate kcm [%s]", key);

    // Get parameter value to buffer
    kcm_status_e kcm_status = kcm_item_get_data((const uint8_t*)key,
                                    strlen(key),
                                    KCM_CERTIFICATE_ITEM,
                                    buffer,
                                    buffer_size,
                                    value_length);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::get_config_certificate kcm [%s] get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e set_config_certificate(const char* key, const uint8_t *buffer, const size_t buffer_size)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::set_config_certificate error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::set_config_certificate kcm [%s]", key);

    // Get parameter value to buffer
    kcm_status_e kcm_status = kcm_item_store((const uint8_t*)key,
                                 strlen(key),
                                 KCM_CERTIFICATE_ITEM,
                                 false,
                                 buffer,
                                 buffer_size,
                                 NULL);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::set_config_certificate kcm [%s] get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e delete_config_certificate(const char* key)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::delete_config_certificate error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::delete_config_certificate kcm [%s]", key);

    // Get parameter value to buffer
    kcm_status_e kcm_status = kcm_item_delete((const uint8_t*)key,
                                  strlen(key),
                                  KCM_CERTIFICATE_ITEM);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::delete_config_certificate kcm [%s] get error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}
