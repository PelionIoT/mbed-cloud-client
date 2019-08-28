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
#ifndef __FCC_BUNDLE_UTILS_H__
#define __FCC_BUNDLE_UTILS_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "fcc_status.h"
#include "key_config_manager.h"
#include "tinycbor.h"
#include "fcc_bundle_fields.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CSR_MAX_NUMBER_OF_CSRS 5

typedef fcc_status_e (*fcc_bundle_process_map_cb)(CborValue *tcbor_map_val, void *extra_cb_info);

fcc_status_e fcc_bundle_process_maps_in_arr(const CborValue *tcbor_arr_val, fcc_bundle_process_map_cb process_map_cb, void *extra_cb_info);

fcc_status_e fcc_bundle_process_certificates_cb(CborValue *tcbor_val, void *extra_info);

fcc_status_e fcc_bundle_process_keys_cb(CborValue *tcbor_val, void *extra_info);

fcc_status_e fcc_bundle_process_config_param_cb(CborValue *tcbor_val, void *extra_info);

fcc_status_e fcc_bundle_process_csr_reqs(const CborValue *tcbor_csr_reqs_val, CborEncoder *tcbor_top_map_encoder);

/** Get pointer to the start of string value in the cbor blob and its length
 *  Note, valid until blob memory is freed */
bool fcc_bundle_get_text_string(const CborValue *tcbor_val, const char **str, size_t *str_len, const char *err_field_name, size_t err_field_name_len);

/** Get pointer to the start of string value in the cbor blob and its length
 *  Note, valid until blob memory is freed */
bool fcc_bundle_get_byte_string(const CborValue *tcbor_val, const uint8_t **bytes, size_t *bytes_len, const char *err_field_name, size_t err_field_name_len);

bool fcc_bundle_get_uint64(const CborValue *tcbor_val, uint64_t *value_out, const char *err_field_name, size_t err_field_name_len);

bool fcc_bundle_get_bool(const CborValue *tcbor_val, bool *value_out, const char *err_field_name, size_t err_field_name_len);

/** Get pointer to the start of the data. 
 *  In case of fixed type, get the value to data64_val and set data_ptr to it's address */
bool fcc_bundle_get_variant(CborValue *tcbor_val, const uint8_t **data_ptr, size_t *data_ptr_size, uint64_t *data64_val, const char *err_field_name, size_t err_field_name_len);

fcc_status_e fcc_bundle_process_rbp_buffer(CborValue *tcbor_top_map, const char *map_key_name, const char *rbp_item_name);

fcc_status_e fcc_bundle_factory_disable( void );

#ifdef __cplusplus
}
#endif

#endif //__FCC_BUNDLE_UTILS_H__
