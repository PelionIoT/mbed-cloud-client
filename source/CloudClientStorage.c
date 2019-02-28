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
#include <assert.h>
#include "key_config_manager.h"
#include "CloudClientStorage.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client-libservice/common_functions.h"

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

ccs_status_e ccs_get_string_item(const char* key,
                                 uint8_t *buffer,
                                 const size_t buffer_size,
                                 ccs_item_type_e item_type)
{
    size_t len = 0;
    ccs_status_e status = ccs_get_item(key, buffer, buffer_size - 1, &len, item_type);

    if (status == CCS_STATUS_SUCCESS) {
        // Null terminate after buffer value
        buffer[len] = 0;
    }

    return status;
}

ccs_status_e ccs_check_item(const char* key, ccs_item_type_e item_type)
{
    if (key == NULL) {
        return CCS_STATUS_ERROR;
    }

    size_t real_size = 0;
    kcm_status_e kcm_status = kcm_item_get_data_size((const uint8_t*)key, strlen(key), (kcm_item_type_e)item_type, &real_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return CCS_STATUS_KEY_DOESNT_EXIST;
    }
    return CCS_STATUS_SUCCESS;
}

ccs_status_e ccs_delete_item(const char* key, ccs_item_type_e item_type)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::ccs_delete_item error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    ccs_status_e status = ccs_check_item(key, item_type);
    if (status == CCS_STATUS_KEY_DOESNT_EXIST) {
        // No need to call delete as item does not exist.
        tr_debug("CloudClientStorage::ccs_delete_item [%s], type [%d] does not exist. Not deleting anything.", key, item_type);
        return CCS_STATUS_SUCCESS;
    } else if (status == CCS_STATUS_ERROR) {
        return CCS_STATUS_ERROR;
    }

    // Delete parameter from storage
    tr_debug("CloudClientStorage::ccs_delete_item [%s], type [%d] ", key, item_type);
    kcm_status_e kcm_status = kcm_item_delete((const uint8_t*)key,
                                  strlen(key),
                                  (kcm_item_type_e)item_type);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::ccs_delete_item [%s] kcm error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e ccs_item_size(const char* key, size_t* size_out, ccs_item_type_e item_type)
{
    if (key == NULL) {
        tr_error("CloudClientStorage::ccs_item_size error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::ccs_item_size [%s], item [%d]", key, item_type);

    // Get kcm item size
    kcm_status_e kcm_status = kcm_item_get_data_size((const uint8_t*)key,
                                         strlen(key),
                                         (kcm_item_type_e)item_type,
                                         size_out);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::ccs_item_size [%s] kcm error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e ccs_get_item(const char* key,
                          uint8_t *buffer,
                          const size_t buffer_size,
                          size_t *value_length,
                          ccs_item_type_e item_type)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::ccs_get_item error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::ccs_get_item [%s], type [%d]", key, item_type);

    kcm_status_e kcm_status = kcm_item_get_data((const uint8_t*)key,
                                    strlen(key),
                                    (kcm_item_type_e)item_type,
                                    buffer,
                                    buffer_size,
                                    value_length);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::ccs_get_item [%s] kcm error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

ccs_status_e ccs_set_item(const char* key,
                          const uint8_t *buffer,
                          const size_t buffer_size,
                          ccs_item_type_e item_type)
{
    if (key == NULL || buffer == NULL || buffer_size == 0) {
        tr_error("CloudClientStorage::ccs_set_item error, invalid parameters");
        return CCS_STATUS_ERROR;
    }

    tr_debug("CloudClientStorage::ccs_set_item kcm [%s], type [%d]", key, item_type);

    kcm_status_e kcm_status = kcm_item_store((const uint8_t*)key,
                                 strlen(key),
                                 (kcm_item_type_e)item_type,
                                 false,
                                 buffer,
                                 buffer_size,
                                 NULL);

    if (kcm_status == KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED) {
        tr_error("CloudClientStorage::ccs_set_item kcm validation error");
        return CCS_STATUS_VALIDATION_FAIL;
    }
    else if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_debug("CloudClientStorage::ccs_set_item kcm [%s] error %d", key, kcm_status);
        return CCS_STATUS_ERROR;
    }

    return CCS_STATUS_SUCCESS;
}

void *ccs_create_certificate_chain(const char *chain_file_name, size_t chain_len)
{
    kcm_status_e kcm_status;
    kcm_cert_chain_handle chain_handle;

    kcm_status = kcm_cert_chain_create(&chain_handle,
                                       (uint8_t*)chain_file_name,
                                       strlen(chain_file_name),
                                       chain_len,
                                       false);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::ccs_create_certificate_chain - error %d", kcm_status);
        return NULL;
    } else {
        return (void*)chain_handle;
    }
}

void *ccs_open_certificate_chain(const char *chain_file_name, size_t *chain_size)
{
    kcm_status_e kcm_status;
    kcm_cert_chain_handle handle;

    kcm_status = kcm_cert_chain_open(&handle,
                                     (uint8_t*)chain_file_name,
                                     strlen(chain_file_name),
                                     chain_size);

    if (kcm_status == KCM_STATUS_SUCCESS) {
        return (void*)handle;
    } else {
        tr_error("CloudClientStorage::ccs_open_certificate_chain - error %d", kcm_status);
        return NULL;
    }
}

ccs_status_e ccs_get_next_cert_chain(void *chain_handle, void *cert_data, size_t *data_size)
{
    kcm_status_e kcm_status;
    size_t max_size = 1024;

    kcm_status = kcm_cert_chain_get_next_size((kcm_cert_chain_handle *) chain_handle, data_size);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::ccs_get_next_cert_chain - get_next_size error %d", kcm_status);
        return CCS_STATUS_ERROR;
    }


    kcm_status = kcm_cert_chain_get_next_data((kcm_cert_chain_handle *) chain_handle, (uint8_t*)cert_data, max_size, data_size);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::ccs_get_next_cert_chain - get_next_data error %d", kcm_status);
        return CCS_STATUS_ERROR;
    } else {
        return CCS_STATUS_SUCCESS;
    }
}

ccs_status_e ccs_close_certificate_chain(void *chain_handle)
{
    kcm_status_e kcm_status;
    kcm_cert_chain_handle *handle = (kcm_cert_chain_handle *) chain_handle;
    kcm_status = kcm_cert_chain_close(handle);
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::ccs_close_certificate_chain - error %d", kcm_status);
        return CCS_STATUS_ERROR;
    } else {
        return CCS_STATUS_SUCCESS;
    }
}

ccs_status_e ccs_add_next_cert_chain(void *chain_handle, const uint8_t *cert_data, size_t data_size)
{
    kcm_status_e kcm_status;
    kcm_status = kcm_cert_chain_add_next((kcm_cert_chain_handle *) chain_handle, cert_data, data_size);

    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_error("CloudClientStorage::ccs_add_next_cert_chain - error %d", kcm_status);
        return CCS_STATUS_ERROR;
    } else {
        return CCS_STATUS_SUCCESS;
    }
}

ccs_status_e ccs_parse_cert_chain_and_store(const uint8_t *cert_chain_name,
                                            const size_t cert_chain_name_len,
                                            const uint8_t *cert_chain_data,
                                            const uint16_t cert_chain_data_len)
{
    assert(cert_chain_data);
    assert(cert_chain_data_len > 0);

    const uint8_t *ptr = cert_chain_data;
    uint8_t version = *ptr++;
    uint8_t chain_length = *ptr++;
    ccs_status_e success = CCS_STATUS_SUCCESS;
    kcm_cert_chain_handle chain_handle;
    kcm_status_e status;

    // Check overflow
    if (ptr - cert_chain_data > cert_chain_data_len) {
        success = CCS_STATUS_VALIDATION_FAIL;
    }

    // Check version is correct and there are certs in the chain
    if (version != 1 || chain_length == 0) {
        success = CCS_STATUS_VALIDATION_FAIL;
    }

    // Create KCM cert chain
    if (success == CCS_STATUS_SUCCESS) {
        status = kcm_cert_chain_create(&chain_handle,
                                       cert_chain_name,
                                       cert_chain_name_len,
                                       chain_length,
                                       false);
        tr_debug("Cert chain create %d", status);
        if (status != KCM_STATUS_SUCCESS) {
            success = CCS_STATUS_ERROR;
        }
    }

    if (success == CCS_STATUS_SUCCESS) {
        for (uint8_t i = 0; i < chain_length; i++) {
            // Parse certificate length (2 bytes)
            uint16_t cert_len = common_read_16_bit(ptr);
            ptr += 2;
            // Check overflow
            if (ptr - cert_chain_data > cert_chain_data_len) {
                success = CCS_STATUS_VALIDATION_FAIL;
                break;
            }

            // Store certificate
            tr_debug("Storing cert\r\n%s", tr_array(ptr, cert_len));
            status = kcm_cert_chain_add_next(chain_handle, ptr, cert_len);
            if (status != KCM_STATUS_SUCCESS) {
                success = CCS_STATUS_ERROR;
                break;
            }

            ptr += cert_len;

            // Check overflow
            if (ptr - cert_chain_data > cert_chain_data_len) {
                success = CCS_STATUS_VALIDATION_FAIL;
                break;
            }
        }

        status = kcm_cert_chain_close(chain_handle);
        if (status != KCM_STATUS_SUCCESS) {
            success = CCS_STATUS_ERROR;
        }
    }

    if (success != CCS_STATUS_SUCCESS) {
        kcm_cert_chain_delete(cert_chain_name, cert_chain_name_len);
    }

    return success;
}
