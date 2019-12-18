// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_ATCA_SUPPORT

#include "pal.h"
#include "kcm_status.h"
#include "cs_der_certs.h"
#include "pv_error_handling.h"
#include "pv_macros.h"
#include "fcc_malloc.h"
#include "psa_driver_se_atmel.h"
#include "psa_driver.h"

#include "atcacert.h"
#include "atca_status.h"
#include "tng_atcacert_client.h"
#include "atcacert_def.h"
#include "atca_basic.h"
#include "atca_helpers.h"

#include "tng22_cert_def_1_signer.h"
#include "tng22_cert_def_2_device.h"

#include "psa/crypto.h"
#include "psa_driver_se.h"


/** Translates Atmel's Secure Element error returned to KCM error.
*
*    @param[in] atca_status Secure Element error code.
*    @returns
*       KCM_STATUS_SUCCESS in case of PSA_SUCCESS, or one of the `::kcm_status_e` errors otherwise.
*/
static kcm_status_e translate_atca_to_kcm_error(int atca_status)
{
    kcm_status_e kcm_status;

    switch (atca_status) {
        case ATCACERT_E_SUCCESS:
            kcm_status = KCM_STATUS_SUCCESS;
            break;
        case ATCACERT_E_BAD_PARAMS:
        case ATCACERT_E_INVALID_DATE:
            kcm_status = KCM_STATUS_INVALID_PARAMETER;
            break;
        case ATCACERT_E_BUFFER_TOO_SMALL:
            kcm_status = KCM_STATUS_INSUFFICIENT_BUFFER;
            break;
        case ATCACERT_E_BAD_CERT:
            kcm_status = KCM_CRYPTO_STATUS_PARSING_DER_CERT;
            break;
        case ATCACERT_E_VERIFY_FAILED:
            kcm_status = KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED;
            break;
        case ATCACERT_E_INVALID_TRANSFORM:
        case ATCACERT_E_WRONG_CERT_DEF:
        case ATCACERT_E_ELEM_OUT_OF_BOUNDS:
        case ATCACERT_E_ELEM_MISSING:
        case ATCACERT_E_UNEXPECTED_ELEM_SIZE:
        case ATCACERT_E_DECODING_ERROR:
        case ATCACERT_E_UNIMPLEMENTED:
        case ATCACERT_E_ERROR:
        default:
            kcm_status = KCM_STATUS_ERROR;
    }

    return kcm_status;
}

kcm_status_e psa_drv_atca_get_max_signer_cert_size(size_t *max_cert_size_out)
{
    int atca_status = ATCACERT_E_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((max_cert_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid max_cert_size_out");

    // Get signer certificate
    atca_status = tng_atcacert_max_signer_cert_size(max_cert_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((atca_status != ATCACERT_E_SUCCESS), translate_atca_to_kcm_error(atca_status), "Failed to get ATCA signer certificate size");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_atca_get_max_device_cert_size(size_t *max_cert_size_out)
{
    int atca_status = ATCACERT_E_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((max_cert_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid max_cert_size_out");

    // Get signer certificate
    atca_status = tng_atcacert_max_device_cert_size(max_cert_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((atca_status != ATCACERT_E_SUCCESS), translate_atca_to_kcm_error(atca_status), "Failed to get ATCA signer certificate size");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_atca_read_signer_cert(uint8_t *cert, size_t *cert_size_out)
{
    int atca_status = ATCACERT_E_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*cert_size_out == 0), KCM_STATUS_INVALID_PARAMETER, "Got empty certificate");

    // read signer cert
    atca_status = tng_atcacert_read_signer_cert(cert, cert_size_out);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((atca_status != ATCACERT_E_SUCCESS), translate_atca_to_kcm_error(atca_status), "Failed reading ATCA signer certificate");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_atca_read_device_cert(uint8_t *cert, size_t *cert_size_out)
{
    int atca_status = ATCACERT_E_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert_size_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*cert_size_out == 0), KCM_STATUS_INVALID_PARAMETER, "Got empty certificate");

    // read signer cert, the last param is NULL, that means that the signer's public key will be fetched from Atmel's SE
    atca_status = tng_atcacert_read_device_cert(cert, cert_size_out, NULL);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((atca_status != ATCACERT_E_SUCCESS), translate_atca_to_kcm_error(atca_status), "Failed reading ATCA signer certificate");

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_atca_get_cn(const uint8_t *cert, size_t cert_size, uint8_t **cn_out, size_t *cn_size_out)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t cert_cn_max_size = 0, cert_cn_size = 0;
    uint8_t *cert_cn_data = NULL;
    palX509Handle_t device_cert_h = NULLPTR;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cert");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cert_size == 0), KCM_STATUS_INVALID_PARAMETER, "Got empty certificate");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cn_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cn_out");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((cn_size_out == NULL), KCM_STATUS_INVALID_PARAMETER, "Invalid cn_size_out");

    kcm_status = cs_create_handle_from_der_x509_cert(cert, cert_size, &device_cert_h);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), kcm_status, "Failed to get X509 handle");

    //Get attribute size
    kcm_status = cs_attr_get_data_size_x509_cert(device_cert_h, CS_CN_ATTRIBUTE_TYPE, &cert_cn_max_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), (kcm_status = kcm_status), Exit, "Failed to get device certificate CN");

    cert_cn_data = fcc_malloc(cert_cn_max_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((cert_cn_data == NULL), (kcm_status = KCM_STATUS_OUT_OF_MEMORY), Exit, "Failed to allocate memory to accommodate CN attribute");

    //Get data of "CN" attribute
    kcm_status = cs_attr_get_data_x509_cert(device_cert_h, CS_CN_ATTRIBUTE_TYPE, cert_cn_data, cert_cn_max_size, &cert_cn_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS || cert_cn_size == 0), (kcm_status = KCM_CRYPTO_STATUS_INVALID_X509_ATTR), Exit, "Failed getting device certificate CN data");

    *cn_out = cert_cn_data;
    *cn_size_out = (cert_cn_size - 1); // chop the null terminator "\0"

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

Exit:
    if (kcm_status != KCM_STATUS_SUCCESS) {
        fcc_free(cert_cn_data);
        cert_cn_data = NULL;
    }
    cs_close_handle_x509_cert(&device_cert_h);
    return kcm_status;
}



static ATCAIfaceCfg atca_iface_config = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC608A,
    .atcai2c.slave_address = 0x6A,
    .atcai2c.bus = 2,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20,
};

kcm_status_e psa_drv_atca_register(void)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();
    psa_status_t psa_status = PSA_SUCCESS;

    //Register atmel driver
    psa_status = psa_register_se_driver(PSA_DRIVER_SE_DRIVER_LIFETIME_VALUE, &atecc608a_drv_info);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((psa_status != psa_status), psa_drv_translate_to_kcm_error(psa_status), "Failed psa_register_se_driver (%" PRIu32 ")", (uint32_t)psa_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;
}

kcm_status_e psa_drv_atca_init(void)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    ATCA_STATUS atca_status = atcab_init(&atca_iface_config);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((atca_status != ATCA_SUCCESS), translate_atca_to_kcm_error(atca_status), "Failed initializing Atmel's Secure Element peripheral (%" PRIu32 ")", (uint32_t)atca_status);

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();

    return KCM_STATUS_SUCCESS;;
}


void psa_drv_atca_release(void)
{
    SA_PV_LOG_TRACE_FUNC_ENTER_NO_ARGS();

    ATCA_STATUS atca_status = atcab_release();
    if (atca_status != ATCA_SUCCESS) {
        SA_PV_LOG_ERR("Failed to releasing Atmel's secure element (%" PRIu32 ")", (uint32_t)atca_status);
    }

    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
}

#endif //#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_ATCA_SUPPORT
