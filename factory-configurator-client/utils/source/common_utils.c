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

#include "factory_configurator_client.h"
#include "fcc_status.h"
#include "fcc_verification.h"
#include "key_config_manager.h"
#include "pv_error_handling.h"
#include "cs_der_certs.h"
#include "cs_utils.h"
#include "fcc_output_info_handler.h"
#include "fcc_malloc.h"
#include "time.h"
#include "cs_utils.h"


fcc_status_e fcc_get_kcm_data(const uint8_t *parameter_name, size_t size_of_parameter_name, kcm_item_type_e kcm_type, uint8_t **kcm_data, size_t *kcm_data_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((parameter_name == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong parameter_name pointer");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((size_of_parameter_name == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong parameter_name size.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data != NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong *kcm_data pointer, should be NULL");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_data_size == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong kcm_data_size pointer.");

    //Get size of kcm data
    kcm_status = kcm_item_get_data_size(parameter_name,
        size_of_parameter_name,
        kcm_type,
        kcm_data_size);
    if (kcm_status == KCM_STATUS_ITEM_NOT_FOUND) {
        return FCC_STATUS_ITEM_NOT_EXIST;
    }
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_KCM_STORAGE_ERROR, "Failed to get kcm data size");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data_size == 0), fcc_status = FCC_STATUS_EMPTY_ITEM, "KCM item is empty");

    //Alocate memory and get device certificate data
    *kcm_data = fcc_malloc(*kcm_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*kcm_data == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, "Failed to allocate buffer for kcm data");

    kcm_status = kcm_item_get_data(parameter_name,
        size_of_parameter_name,
        kcm_type,
        *kcm_data, *kcm_data_size, kcm_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status == KCM_STATUS_ITEM_NOT_FOUND), fcc_status = FCC_STATUS_ITEM_NOT_EXIST, exit, "KCM is not found");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_KCM_STORAGE_ERROR, exit, "Failed to get device certificate data");

exit:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        fcc_free(*kcm_data);
        *kcm_data = NULL;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}

fcc_status_e fcc_get_certificate_attribute(palX509Handle_t x509_cert, cs_certificate_attribute_type_e attribute_type, uint8_t **attribute_data, size_t *attribute_act_data_size)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_RETURN_IF((x509_cert == NULLPTR), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong x509 handle.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*attribute_data != NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "Wrong attribute_data pointer.");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((attribute_act_data_size == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, "attribute_act_data_size pointer is NULL.");

    //Get attribute size
    kcm_status = cs_attr_get_data_size_x509_cert(x509_cert, attribute_type, attribute_act_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_INVALID_CERT_ATTRIBUTE, "Failed to get size of attribute");

    *attribute_data = fcc_malloc(*attribute_act_data_size);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((*attribute_data == NULL), fcc_status = FCC_STATUS_MEMORY_OUT, "Failed to allocate memory for attribute");

    //Get data of "CN" attribute
    kcm_status = cs_attr_get_data_x509_cert(x509_cert,
        attribute_type,
        *attribute_data,
        *attribute_act_data_size,
        attribute_act_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS || *attribute_act_data_size == 0), fcc_status = FCC_STATUS_INVALID_CERT_ATTRIBUTE, exit, "Failed to get attribute data");


exit:
    if (fcc_status != FCC_STATUS_SUCCESS) {
        fcc_free(*attribute_data);
        *attribute_data = NULL;
    }
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}

fcc_status_e fcc_get_certificate_attribute_by_name(const uint8_t *cert_name, size_t size_of_cert_name, cs_certificate_attribute_type_e attribute_type, uint8_t *attribute_data,size_t attribute_data_size, size_t *attribute_act_data_size)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    uint8_t *kcm_data = NULL;
    size_t kcm_data_size = 0;
    palX509Handle_t x509_cert = NULLPTR;

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();

    SA_PV_ERR_RECOVERABLE_GOTO_IF((cert_name == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Wrong cert name");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((size_of_cert_name == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Wrong cert name size");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((attribute_data == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Wrong attribute data buffer pointer");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((attribute_data_size == 0), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Wrong attribute data buffer size");
    SA_PV_ERR_RECOVERABLE_GOTO_IF((attribute_act_data_size == NULL), fcc_status = FCC_STATUS_INVALID_PARAMETER, exit, "Wrong attribute_act_data_size pointer");

    //For now we save ca id only for bootstrap server
    fcc_status = fcc_get_kcm_data((const uint8_t*)cert_name, size_of_cert_name, KCM_CERTIFICATE_ITEM, &kcm_data, &kcm_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status = fcc_status, exit, "Failed to read cert data");

    //Create device certificate handle
    kcm_status = cs_create_handle_from_der_x509_cert(kcm_data, kcm_data_size, &x509_cert);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_INVALID_CERTIFICATE, exit, "Failed to get device certificate descriptor");

    //Get certificate attribute data
    kcm_status = cs_attr_get_data_x509_cert(x509_cert,
        attribute_type,
        attribute_data,
        attribute_data_size,
        attribute_act_data_size);
    SA_PV_ERR_RECOVERABLE_GOTO_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_status = FCC_STATUS_INVALID_CERT_ATTRIBUTE, exit, "Failed to get attribute data");


exit:
    fcc_free(kcm_data);
    cs_close_handle_x509_cert(&x509_cert);
    SA_PV_LOG_TRACE_FUNC_EXIT_NO_ARGS();
    return fcc_status;
}
