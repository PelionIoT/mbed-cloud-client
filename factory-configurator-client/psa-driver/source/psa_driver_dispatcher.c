// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "key_slot_allocator.h"
#include "psa_driver_dispatcher.h"
#include "psa_driver.h"
#include "kcm_defs.h"
#include "pv_macros.h"


//functions declarations 
/**
* Imports item data to PSA crypto module.
*    @param[in] data  Pointer to the buffer of imported data.
*    @param[in] data_size  Size of the imported data.
*    @param[in] extra_flags  Extra flags of the data.
*    @param[out] ksa_id  KSA PSA id number that used by import operation.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_import(const void* data, size_t data_size, uint32_t extra_flags, uint16_t *ksa_id);



/**
* Gets a data size from PSA crypto module according to its PSA id.
* If key that associated with ksa_id is private key, the function exports from the private key its public key and returns its size.
*
*    @param[in] ksa_id  KSA PSA id number of the exported data.
*    @param[in] extra_flags  Extra flags of the data.
*    @param[out] actual_data_size  The actual data size.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_export_data_size(const uint16_t ksa_id, size_t* actual_data_size);

/**
* Destroys a data associated with PSA id.
*
*    @param[in] ksa_id  KSA PSA id number of the exported data.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_crypto_destroy(const uint16_t ksa_id);

/**
* Destroys a data associated with PS id.
*
*    @param[in] ksa_id  KSA PS id number of the exported data.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_ps_remove(const uint16_t ksa_id);

/**
* Sets the data to PS module.
*    @param[in] data  Pointer to the buffer of imported data.
*    @param[in] data_size  Size of the imported data.
*    @param[in] extra_flags  Extra flags of the data.
*    @param[out] ksa_id  KSA PS id number that used for the data.
*    @returns
*       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
*/
kcm_status_e psa_drv_ps_set(void* data, size_t data_size, uint32_t extra_flags, uint16_t *ksa_id);

// PSA driver operations function table
static void *g_psa_drv_operation_functions[PSA_DRV_FUNC_LAST][PSA_DRV_TYPE_LAST] = {
    { (void *)psa_drv_crypto_export_data,              (void *)psa_drv_ps_get_data },
    { (void *)psa_drv_crypto_export_data_size,         (void *)psa_drv_ps_get_data_size },
    { (void *)psa_drv_crypto_import,                   (void *)psa_drv_ps_set },
    { (void *)psa_drv_crypto_destroy,                  (void *)psa_drv_ps_remove }
};

void *psa_drv_func_dispatch_operation(psa_drv_func_e caller, ksa_item_type_e item_type, ksa_type_location_e item_location)
{
    uint32_t function_index = 0;


    if (item_type == KSA_KEY_ITEM && item_location != KSA_SECURE_ELEMENT_TYPE_LOCATION) {//PSA CRYPTO non secure element key
        function_index = PSA_DRV_TYPE_CRYPTO;
    } else {
        if (item_location == KSA_SECURE_ELEMENT_TYPE_LOCATION) { //Secure element item
            //TODO: When SE will be integrated redirect it to SE driver
            function_index = PSA_DRV_TYPE_CRYPTO;
        } else { //PSA PS item
            function_index = PSA_DRV_TYPE_PS;
        }
    }

    return g_psa_drv_operation_functions[caller][function_index];
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
