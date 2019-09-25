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

#ifndef __PSA_DRIVER_DISPATCHER_H__
#define __PSA_DRIVER_DISPATCHER_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <inttypes.h>
#include "kcm_status.h"
#include "kcm_defs.h"
#include "psa/crypto.h"
#include "psa/crypto_extra.h"
#include "psa/crypto_types.h"
#include "key_config_manager.h"
#include "storage_items.h"
#include "storage_keys.h"

    typedef enum {
        PSA_DRV_FUNC_READ = 0,
        PSA_DRV_FUNC_READ_SIZE = 1,
        PSA_DRV_FUNC_WRITE = 2,
        PSA_DRV_FUNC_DELETE = 3,
        PSA_DRV_FUNC_LAST
    }psa_drv_func_e;

    typedef enum {
        PSA_DRV_TYPE_CRYPTO = 0,
        PSA_DRV_TYPE_PS = 1,
        PSA_DRV_TYPE_LAST
    }psa_drv_element_type_e;


    void *psa_drv_func_dispatch_operation(psa_drv_func_e caller, ksa_item_type_e item_type, ksa_type_location_e item_location);


    
    // Prototypes of the 4 storage functions
    typedef kcm_status_e(*psa_drv_store_f)( const void* data, size_t data_size, uint32_t extra_flags, uint16_t *ksa_id);
    typedef kcm_status_e(*psa_drv_get_data_f)(const uint16_t ksa_id, const void* data_buffer_size, size_t data_length, size_t* actual_data_size);
    typedef kcm_status_e(*psa_drv_get_data_size_f)(const uint16_t ksa_id, size_t* actual_data_size);
    typedef kcm_status_e(*psa_drv_delete_f)(const uint16_t ksa_id);

#ifdef __cplusplus
}
#endif

#endif //__PSA_DRIVER_DISPATCHER_H__
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
