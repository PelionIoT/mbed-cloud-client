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

#ifndef __STORAGE_DISPATCHER_H__
#define __STORAGE_DISPATCHER_H__

#include "key_config_manager.h"
#include "storage_items.h"
#include "storage_keys.h"

typedef enum {
    STORAGE_FUNC_GET = 0,
    STORAGE_FUNC_GET_SIZE = 1,
    STORAGE_FUNC_STORE = 2,
    STORAGE_FUNC_DELETE = 3,
    STORAGE_FUNC_NUM
} storage_func_e;

typedef enum {
    STORAGE_TYPE_KEY = 0,
    STORAGE_TYPE_DATA = 1,
    STORAGE_TYPE_DATA_NUM
} storage_element_type_e;

void *storage_func_dispatch(storage_func_e caller, kcm_item_type_e kcm_item_type);

// Prototypes of the 4 storage functions
typedef kcm_status_e (*storage_store_f)(const uint8_t *key_name, size_t key_name_len, kcm_item_type_e key_type, bool kcm_item_is_factory, storage_item_prefix_type_e item_prefix_type, const uint8_t * kcm_item_data, size_t kcm_item_data_size, const kcm_security_desc_s kcm_item_info);
typedef kcm_status_e (*storage_get_data_f)(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e key_type, storage_item_prefix_type_e item_prefix_type, uint8_t *key_data_out, size_t key_data_max_size, size_t *key_data_act_size_out);
typedef kcm_status_e (*storage_get_data_size_f)(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e key_type, storage_item_prefix_type_e item_prefix_type, size_t *key_data_act_size_out);
typedef kcm_status_e (*storage_delete_f)(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, storage_item_prefix_type_e item_prefix_type);

#endif // __STORAGE_DISPATCHER_H__
