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
#include "key_config_manager.h"
#include "fcc_defs.h"
#include "pv_error_handling.h"
#include "fcc_utils.h"

typedef struct fcc_deloveper_mode_item_params {
    const char *item_name;
    kcm_item_type_e item_kcm_type;
    const uint8_t *item_data;
    const uint32_t item_data_size;
} fcc_deloveper_mode_item_params_s;

//bootstrap endpoint name
extern const char MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME[];
//bootstrap server uri
extern const char MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI[];
//bootstrap device certificate
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE[];
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE_SIZE;
//bootstrap server root ca certificate
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE[];
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE_SIZE;
//bootstrap device private key
extern const uint8_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY[];
extern const uint32_t MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY_SIZE;
//device manufacturer
extern const char MBED_CLOUD_DEV_MANUFACTURER[];
//device  model number
extern const char MBED_CLOUD_DEV_MODEL_NUMBER[];
//device serial number
extern const char MBED_CLOUD_DEV_SERIAL_NUMBER[];
//device type
extern const char MBED_CLOUD_DEV_DEVICE_TYPE[];
//device hw version
extern const char MBED_CLOUD_DEV_HARDWARE_VERSION[];
//device total memory
extern const uint32_t MBED_CLOUD_DEV_MEMORY_TOTAL_KB;

#ifdef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
extern const char MBED_CLOUD_DEV_ACCOUNT_ID[];
#endif


fcc_status_e fcc_developer_flow(void)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    fcc_status_e  fcc_status =  FCC_STATUS_SUCCESS;
    const bool is_factory_item = true;
#ifdef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
    static const uint32_t is_bootstrap_mode = 0;
#else
    static const uint32_t is_bootstrap_mode = 1;
#endif
    const fcc_deloveper_mode_item_params_s fcc_deloveper_mode_item_params_table[] = {

        //param name                                //param kcm type        //param data                                              //param data_size
        //Device general info
        { g_fcc_use_bootstrap_parameter_name,          KCM_CONFIG_ITEM,      (const uint8_t*)&is_bootstrap_mode,                       sizeof(uint32_t) },
#if  !defined(MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT) || (defined(MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT) && defined(MBED_CONF_MBED_CLOUD_CLIENT_CLEAN_CREDENTIALS_SE))
        { g_fcc_endpoint_parameter_name,               KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME,   (uint32_t)strlen((char*)MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME) },
        //Bootstrap configuration
#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        { g_fcc_bootstrap_device_certificate_name,     KCM_CERTIFICATE_ITEM,  MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE,             MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE_SIZE },
        { g_fcc_bootstrap_device_private_key_name,     KCM_PRIVATE_KEY_ITEM,  MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY,             MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY_SIZE },
#else
        { g_fcc_lwm2m_device_certificate_name,         KCM_CERTIFICATE_ITEM,  MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE,             MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_CERTIFICATE_SIZE },
        { g_fcc_lwm2m_device_private_key_name,         KCM_PRIVATE_KEY_ITEM,  MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY,             MBED_CLOUD_DEV_BOOTSTRAP_DEVICE_PRIVATE_KEY_SIZE },
        { g_fcc_mbed_internal_endpoint,                KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME,   (uint32_t)strlen((char*)MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME) },
        // The account id is not really needed, but the MCC requires it.
        { g_fcc_account_id,                            KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_ACCOUNT_ID,                (uint32_t)strlen((char*)MBED_CLOUD_DEV_ACCOUNT_ID) },
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
#endif //!defined(MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT) || (defined(MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT) && defined(MBED_CONF_MBED_CLOUD_CLIENT_CLEAN_CREDENTIALS_SE))

#ifndef MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        { g_fcc_bootstrap_server_ca_certificate_name,  KCM_CERTIFICATE_ITEM,  MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE,     MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE_SIZE },
        { g_fcc_bootstrap_server_uri_name,             KCM_CONFIG_ITEM,       (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI,     (uint32_t)strlen((char*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI) },
#else
        { g_fcc_lwm2m_server_ca_certificate_name,      KCM_CERTIFICATE_ITEM,  MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE,     MBED_CLOUD_DEV_BOOTSTRAP_SERVER_ROOT_CA_CERTIFICATE_SIZE },
        { g_fcc_lwm2m_server_uri_name,                 KCM_CONFIG_ITEM,       (const uint8_t*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI,     (uint32_t)strlen((char*)MBED_CLOUD_DEV_BOOTSTRAP_SERVER_URI) },
#endif //MBED_CONF_MBED_CLIENT_DISABLE_BOOTSTRAP_FEATURE
        //device meta data
        { g_fcc_manufacturer_parameter_name,           KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_MANUFACTURER,              (uint32_t)strlen((char*)MBED_CLOUD_DEV_MANUFACTURER) },
        { g_fcc_model_number_parameter_name,           KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_MODEL_NUMBER,              (uint32_t)strlen((char*)MBED_CLOUD_DEV_MODEL_NUMBER) },
        { g_fcc_device_serial_number_parameter_name,   KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_SERIAL_NUMBER,             (uint32_t)strlen((char*)MBED_CLOUD_DEV_SERIAL_NUMBER) },
        { g_fcc_device_type_parameter_name,            KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_DEVICE_TYPE,               (uint32_t)strlen((char*)MBED_CLOUD_DEV_DEVICE_TYPE) },
        { g_fcc_hardware_version_parameter_name,       KCM_CONFIG_ITEM,      (const uint8_t*)MBED_CLOUD_DEV_HARDWARE_VERSION,          (uint32_t)strlen((char*)MBED_CLOUD_DEV_HARDWARE_VERSION) },
        { g_fcc_memory_size_parameter_name,            KCM_CONFIG_ITEM,      (const uint8_t*)&MBED_CLOUD_DEV_MEMORY_TOTAL_KB,          sizeof(uint32_t) },

        //last item
        { NULL,                                       KCM_LAST_ITEM,         NULL,                                                    0},
    };

    const fcc_deloveper_mode_item_params_s* mandatory_items_iter = &fcc_deloveper_mode_item_params_table[0];

    SA_PV_LOG_INFO_FUNC_ENTER_NO_ARGS();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((!fcc_is_initialized()), FCC_STATUS_NOT_INITIALIZED, "FCC not initialized");

    // verify if an arbitrary item from the array is already existing on the storage (check with "mbed.UseBootstrap")  
    
    size_t UseBootstrap_size = 0;                    // mandatory_items_iter points on mbed.UseBootstrap  
    kcm_status = kcm_item_get_data_size((const uint8_t*)mandatory_items_iter->item_name,
                                        strlen(mandatory_items_iter->item_name), 
                                        mandatory_items_iter->item_kcm_type,
                                        &UseBootstrap_size);
    if(kcm_status == KCM_STATUS_SUCCESS){
        // item already exists - this means that storage already contains developer mode prov items.
        // we don't need to override the items, we just exit from the function with "an item exists" status.
        SA_PV_LOG_INFO("Developer mode prov items already exist on the storage.");
        return FCC_STATUS_KCM_FILE_EXIST_ERROR;
    }

    // developer mode prov items do not exist on the storage. Flash them.
    for (; mandatory_items_iter->item_name!= NULL; mandatory_items_iter++) {

        kcm_status = kcm_item_store((const uint8_t*)(mandatory_items_iter->item_name), strlen(mandatory_items_iter->item_name), mandatory_items_iter->item_kcm_type, is_factory_item,
                                    (const uint8_t*)(mandatory_items_iter->item_data), mandatory_items_iter->item_data_size, NULL);
        SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), fcc_convert_kcm_to_fcc_status(kcm_status), "Store status: %d, Failed to store %s", kcm_status, mandatory_items_iter->item_name);
    }

#if defined (PAL_USE_SECURE_TIME) && (PAL_USE_SECURE_TIME == 1)
    fcc_status = fcc_trust_ca_cert_id_set();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((fcc_status != FCC_STATUS_SUCCESS), fcc_status, "Failed to set ca certificate identifier");
#endif
    SA_PV_LOG_INFO_FUNC_EXIT_NO_ARGS();

    return fcc_status;
}
