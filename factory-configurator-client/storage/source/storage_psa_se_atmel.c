// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_ATCA_SUPPORT

#include "pv_error_handling.h"
#include "storage_internal.h"
#include "storage_se_atmel.h"
#include "kcm_defs.h"
#include "key_slot_allocator.h"
#include "pv_macros.h"
#include "psa_driver_se_atmel.h"
#include "fcc_defs.h"
#include "storage_kcm.h"
#include "fcc_malloc.h"


static kcm_status_e store_device_cert_cn(const uint8_t *device_cert, size_t device_cert_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t *device_cn = NULL;
    size_t device_cn_size = 0;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    kcm_status = psa_drv_atca_get_cn(device_cert, device_cert_size, &device_cn, &device_cn_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for ksa_load_external_key");

    // store the device certificate CN as a config param
    kcm_status = storage_item_store((const uint8_t *)g_fcc_endpoint_parameter_name, strlen(g_fcc_endpoint_parameter_name), KCM_CONFIG_ITEM, true, STORAGE_ITEM_PREFIX_KCM, device_cn, device_cn_size, NULL);

    fcc_free(device_cn); // caller must evacuate this buffer

    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for storage_item_store");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_psa_se_atmel_load_device_private_key(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    uint8_t privkey_kcm_name[STORAGE_COMPLETE_ITEM_NAME_SIZE] = { 0 };

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // build device private key name
    kcm_status = storage_build_item_name(
        (uint8_t *)g_fcc_bootstrap_device_private_key_name,
        strlen(g_fcc_bootstrap_device_private_key_name),
        KCM_PRIVATE_KEY_ITEM,
        STORAGE_ITEM_PREFIX_KCM,
        NULL, privkey_kcm_name);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to build device private key complete name");

    // add the device private key 
    kcm_status = ksa_load_key_to_entry_from_se((uint8_t *)privkey_kcm_name ,STORAGE_ATCA_DEVICE_PRIVATE_KEY_SLOT_ID, true);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for ksa_load_external_key");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return kcm_status;
}

kcm_status_e storage_psa_se_atmel_create_device_cert_chain(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS, close_chain_status = KCM_STATUS_SUCCESS;
    kcm_cert_chain_handle cert_chain_h = NULL;
    size_t device_cert_size = 0, signer_cert_size = 0;
    uint8_t *certs_buffer = NULL;

    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    // Create chain for device and signer certificate.
    kcm_status = storage_cert_chain_create(&cert_chain_h, (uint8_t *)g_fcc_bootstrap_device_certificate_name, strlen(g_fcc_bootstrap_device_certificate_name), STORAGE_ATCA_SIGNER_CHAIN_DEPTH, true, STORAGE_ITEM_PREFIX_KCM);
    if (kcm_status == KCM_STATUS_FILE_EXIST) {
        // Already exist. Skip read and store again.
        SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
        return KCM_STATUS_SUCCESS;
    }
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed for storage_cert_chain_create");

    // query device cert size
    kcm_status = psa_drv_atca_get_max_device_cert_size(&device_cert_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for psa_drv_atca_get_max_device_cert_size");

    // query signer cert size
    kcm_status = psa_drv_atca_get_max_signer_cert_size(&signer_cert_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed for psa_drv_atca_get_max_signer_cert_size");

    // allocate buffer to hold the device and signer certificates
    certs_buffer = fcc_malloc(device_cert_size + signer_cert_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((certs_buffer == NULL), KCM_STATUS_OUT_OF_MEMORY, "Failed allocating certificates buffer");

    // read the device certificate
    kcm_status = psa_drv_atca_read_device_cert(certs_buffer, &device_cert_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed for psa_drv_atca_read_signer_cert");

    // read and store the CN of the device X509 certificate
    kcm_status = store_device_cert_cn(certs_buffer, device_cert_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed for storage_psa_se_atmel_read_cn_from_device_cert");

    // read the signer certificate (signer certificate is the actual device certificate CA)
    kcm_status = psa_drv_atca_read_signer_cert(&(certs_buffer[device_cert_size]), &signer_cert_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed for psa_drv_atca_read_signer_cert");

    // Store the device and signer certificate as KCM chain

    // start with the leaf
    kcm_status = storage_cert_chain_add_next(cert_chain_h, &(certs_buffer[0]), device_cert_size, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to add Atmel's device certificate");

    kcm_status = storage_cert_chain_add_next(cert_chain_h, &(certs_buffer[device_cert_size]), signer_cert_size, STORAGE_ITEM_PREFIX_KCM);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to add Atmel's signer certificate");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    
Exit:
    fcc_free(certs_buffer);

    close_chain_status = storage_cert_chain_close(cert_chain_h, STORAGE_ITEM_PREFIX_KCM);
    if (close_chain_status != KCM_STATUS_SUCCESS) {
        SA_PV_LOG_ERR("Failed closing certificate chain error (%u)", close_chain_status);
        // modify return status only if function succeed but we failed for storage_cert_chain_close
        kcm_status = (kcm_status == KCM_STATUS_SUCCESS) ? close_chain_status : kcm_status;
    }

    return kcm_status;
}

kcm_status_e storage_psa_se_atmel_init(void)
{
    // Init Atmel's secure element
    kcm_status_e kcm_status = psa_drv_atca_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to initialize Atmel's secure element (%" PRIu32 ")", (uint32_t)kcm_status);

    return KCM_STATUS_SUCCESS;
}

void storage_psa_se_atmel_release(void)
{
    psa_drv_atca_release();
}

#endif // MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_ATCA_SUPPORT
