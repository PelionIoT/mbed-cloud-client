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

#ifndef __FCC_OUTPUT_INFO_HANDLER_DEFINES_H__
#define __FCC_OUTPUT_INFO_HANDLER_DEFINES_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include  "kcm_status.h"

#ifdef __cplusplus
extern "C" {
#endif

//General error string
extern const char g_fcc_general_status_error_str[];

//fcc error strings
extern const char g_fcc_ca_error_str[];
extern const char g_fcc_rot_error_str[];
extern const char g_fcc_entropy_error_str[];
extern const char g_fcc_disabled_error_str[];
extern const char g_fcc_invalid_certificate_error_str[];
extern const char g_fcc_item_not_exists_error_str[];
extern const char g_fcc_meta_data_not_exists_error_str[];
extern const char g_fcc_meta_data_size_error_str[];
extern const char g_fcc_wrong_item_size_error_str[];
extern const char g_fcc_empty_item_error_str[];
extern const char g_fcc_uri_wrong_format_error_str[];
extern const char g_fcc_first_to_claim_not_allowed_error_str[];
extern const char g_fcc_wrong_utc_offset_value_error_str[];
extern const char g_fcc_wrong_ca_certificate_error_str[];
extern const char g_fcc_invalid_cn_certificate_error_str[];
extern const char g_fcc_crypto_public_key_correlation_error_str[];
extern const char g_fcc_internal_storage_error_str[];

//kcm crypto error strings
extern const char g_fcc_kcm_file_exist_error_str[];
extern const char g_fcc_kcm_invalid_num_of_cert_in_chain_str[];
extern const char g_fcc_crypto_empty_item_error_str[];
extern const char g_fcc_crypto_unsupported_hash_mode_error_str[];
extern const char g_fcc_crypto_parsing_der_pivate_key_error_str[];
extern const char g_fcc_crypto_parsing_der_public_key_error_str[];
extern const char g_fcc_crypto_verify_private_key_error_str[];
extern const char g_fcc_crypto_verify_public_key_error_str[];
extern const char g_fcc_crypto_unsupported_curve_error_str[];
extern const char g_fcc_crypto_parsing_der_cert_error_str[];
extern const char g_fcc_crypto_cert_expired_error_str[];
extern const char g_fcc_crypto_cert_future_error_str[];
extern const char g_fcc_crypto_cert_md_alg_error_str[];
extern const char g_fcc_crypto_cert_public_key_type_error_str[];
extern const char g_fcc_crypto_cert_public_key_error_str[];
extern const char g_fcc_crypto_cert_not_trusted_error_str[];
extern const char g_fcc_crypto_invalid_x509_attr_error_str[];
extern const char g_fcc_wrong_bootstrap_use_value_error_str[];
extern const char g_fcc_crypto_invalid_pk_key_format_error_str[];
extern const char g_fcc_crypto_invalid_public_key_error_str[];
extern const char g_fcc_crypto_ecp_invalid_key_error_str[];
extern const char g_fcc_crypto_pk_key_invalid_version_error_str[];
extern const char g_fcc_crypto_pk_password_requerd_error_str[];
extern const char g_fcc_crypto_unknown_pk_algorithm_error_str[];

//warning strings
extern const char g_fcc_item_not_set_warning_str[];
extern const char g_fcc_bootstrap_mode_false_warning_str[];
extern const char g_fcc_time_is_not_set_warning_str[];
extern const char g_fcc_self_signed_warning_str[];
extern const char g_fcc_item_is_empty_warning_str[];
extern const char g_fcc_redundant_item_warning_str[];
extern const char g_fcc_cert_time_validity_warning_str[];
extern const char g_fcc_cert_validity_less_10_years_warning_str[];
extern const char g_fcc_ca_identifier_warning_str[];
#ifdef __cplusplus
}
#endif

#endif //__FCC_OUTPUT_INFO_HANDLER_DEFINES_H__
