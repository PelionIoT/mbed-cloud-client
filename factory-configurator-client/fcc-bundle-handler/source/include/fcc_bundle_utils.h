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
#include "fcc_sotp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FCC_CBOR_MAP_LENGTH 2

/**
* Names of key parameters
*/
#define FCC_BUNDLE_DATA_PARAMETER_NAME                  "Name"
#define FCC_BUNDLE_DATA_PARAMETER_SCHEME                "Type"
#define FCC_BUNDLE_DATA_PARAMETER_FORMAT                "Format"
#define FCC_BUNDLE_DATA_PARAMETER_DATA                  "Data"
#define FCC_BUNDLE_DATA_PARAMETER_ACL                   "ACL"
#define FCC_BUNDLE_DATA_PARAMETER_ARRAY                 "DataArray"

/**
* Types of key parameters
*/
typedef enum {
    FCC_BUNDLE_DATA_PARAM_NAME_TYPE,
    FCC_BUNDLE_DATA_PARAM_SCHEME_TYPE,
    FCC_BUNDLE_DATA_PARAM_FORMAT_TYPE,
    FCC_BUNDLE_DATA_PARAM_DATA_TYPE,
    FCC_BUNDLE_DATA_PARAM_ACL_TYPE,
    FCC_BUNDLE_DATA_PARAM_ARRAY_TYPE,
    FCC_BUNDLE_DATA_PARAM_MAX_TYPE
} fcc_bundle_data_param_type_e;

/**
* Key lookup record, correlating key's param type and name
*/
typedef struct fcc_bundle_data_param_lookup_record_ {
    fcc_bundle_data_param_type_e data_param_type;
    const char *data_param_name;
} fcc_bundle_data_param_lookup_record_s;

/**
* Key lookup table, correlating for each key its param type and param name
*/
static const fcc_bundle_data_param_lookup_record_s fcc_bundle_data_param_lookup_table[FCC_BUNDLE_DATA_PARAM_MAX_TYPE] = {
    { FCC_BUNDLE_DATA_PARAM_NAME_TYPE,          FCC_BUNDLE_DATA_PARAMETER_NAME },
    { FCC_BUNDLE_DATA_PARAM_SCHEME_TYPE,        FCC_BUNDLE_DATA_PARAMETER_SCHEME },
    { FCC_BUNDLE_DATA_PARAM_FORMAT_TYPE,        FCC_BUNDLE_DATA_PARAMETER_FORMAT },
    { FCC_BUNDLE_DATA_PARAM_DATA_TYPE,          FCC_BUNDLE_DATA_PARAMETER_DATA },
    { FCC_BUNDLE_DATA_PARAM_ACL_TYPE,           FCC_BUNDLE_DATA_PARAMETER_ACL },
    { FCC_BUNDLE_DATA_PARAM_ARRAY_TYPE,         FCC_BUNDLE_DATA_PARAMETER_ARRAY }
};

/**
* Source type of buffer
*/
typedef enum {
    FCC_EXTERNAL_BUFFER_TYPE,
    FCC_INTERNAL_BUFFER_TYPE,
    FCC_MAX_BUFFER_TYPE
} fcc_bundle_buffer_type_e;

/**
* Data formats supported by FC
*/
typedef enum {
    FCC_INVALID_DATA_FORMAT,
    FCC_DER_DATA_FORMAT,
    FCC_PEM_DATA_FORMAT,
    FCC_MAX_DATA_FORMAT
} fcc_bundle_data_format_e;

/**
* Names of data formats
*/
#define FCC_BUNDLE_DER_DATA_FORMAT_NAME  "der"
#define FCC_BUNDLE_PEM_DATA_FORMAT_NAME   "pem"

/**
* Group lookup record, correlating group's type and name
*/
typedef struct fcc_bundle_data_format_lookup_record_ {
    fcc_bundle_data_format_e data_format_type;
    const char *data_format_name;
} fcc_bundle_data_format_lookup_record_s;

/**
* Group lookup table, correlating for each group its type and name
*/
static const fcc_bundle_data_format_lookup_record_s fcc_bundle_data_format_lookup_table[FCC_MAX_DATA_FORMAT] = {
    { FCC_DER_DATA_FORMAT,          FCC_BUNDLE_DER_DATA_FORMAT_NAME },
    { FCC_PEM_DATA_FORMAT,          FCC_BUNDLE_PEM_DATA_FORMAT_NAME },
};

/**
* Key types supported by FC
*/
typedef enum {
    FCC_INVALID_KEY_TYPE,
    FCC_ECC_PRIVATE_KEY_TYPE,//do not change this type's place.FCC_ECC_PRIVATE_KEY_TYPE should be at first place.
    FCC_ECC_PUBLIC_KEY_TYPE,
    FCC_RSA_PRIVATE_KEY_TYPE,
    FCC_RSA_PUBLIC_KEY_TYPE,
    FCC_SYM_KEY_TYPE,
    FCC_MAX_KEY_TYPE
} fcc_bundle_key_type_e;

typedef struct fcc_bundle_data_param_ {
    uint8_t                          *name;
    size_t                           name_len;
    fcc_bundle_data_format_e         format;
    fcc_bundle_key_type_e            type;
    uint8_t                          *data;
    size_t                           data_size;
    uint8_t                          *data_der;
    size_t                           data_der_size;
    fcc_bundle_buffer_type_e         data_type;
    uint8_t                          *acl;
    size_t                           acl_size;
    cn_cbor                          *array_cn;
} fcc_bundle_data_param_s;


/** Frees all allocated memory of data parameter struct and sets initial values.
*
* @param data_param[in/out]    The data parameter structure
*/
void fcc_bundle_clean_and_free_data_param(fcc_bundle_data_param_s *data_param);

/** Gets data buffer from cbor struct.
*
* @param data_cb[in]          The cbor text structure
* @param out_data_buffer[out] The out buffer for string data
* @param out_size[out]        The actual size of output buffer
*
* @return
*     true for success, false otherwise.
*/
bool get_data_buffer_from_cbor(const cn_cbor *data_cb, uint8_t **out_data_buffer, size_t *out_size);

/** Processes  keys list.
* The function extracts data parameters for each key and stores its according to it type.
*
* @param keys_list_cb[in]   The cbor structure with keys list.
*
* @return
*     fcc_status_e status.
*/
fcc_status_e fcc_bundle_process_keys(const cn_cbor *keys_list_cb);

/** Processes  certificate list.
* The function extracts data parameters for each certificate and stores it.
*
* @param certs_list_cb[in]   The cbor structure with certificate list.
*
* @return
*      fcc_status_e status.
*/
fcc_status_e fcc_bundle_process_certificates(const cn_cbor *certs_list_cb);
/** Processes  certificate chain list.
* The function extracts data parameters for each certificate chain and stores it.
*
* @param certs_list_cb[in]   The cbor structure with certificate chain list.
*
* @return
*      fcc_status_e status.
*/
fcc_status_e fcc_bundle_process_certificate_chains(const cn_cbor *cert_chains_list_cb);

/** Processes  configuration parameters list.
* The function extracts data parameters for each config param and stores it.
*
* @param config_params_list_cb[in]   The cbor structure with config param list.
*
* @return
*      fcc_status_e status.
*/
fcc_status_e fcc_bundle_process_config_params(const cn_cbor *config_params_list_cb);

/** Gets data parameters.
*
* The function goes over all existing parameters (name,type,format,data,acl and etc) and
* tries to find correlating parameter in cbor structure and saves it to data parameter structure.
*
* @param data_param_cb[in]   The cbor structure with relevant data parameters.
* @param data_param[out]     The data parameter structure
*
* @return
*     true for success, false otherwise.
*/
bool fcc_bundle_get_data_param(const cn_cbor *data_param_list_cb, fcc_bundle_data_param_s *data_param);

/**  Gets type of key form cbor structure
*
* The function goes over all key types and compares it with type inside cbor structure.
*
* @param key_type_cb[in]   The cbor structure with key type data.
* @param key_type[out]     The key type
*
* @return
*     true for success, false otherwise.
*/
bool fcc_bundle_get_key_type(const cn_cbor *key_type_cb, fcc_bundle_key_type_e *key_type);

/** Writes buffer to SOTP
*
* @param cbor_bytes[in]   The pointer to a cn_cbor object of type CN_CBOR_BYTES.
* @param sotp_type[in]    enum representing the type of the item to be stored in SOTP.
* @return
*     true for success, false otherwise.
*/

fcc_status_e fcc_bundle_process_sotp_buffer(cn_cbor *cbor_bytes, sotp_type_e sotp_type);

/** Gets the status groups value
*
* - if value is '0' - set status to false
* - if value is '1' - set status to true
*
* @param cbor_blob[in]             The pointer to main CBOR blob.
* @param cbor_group_name[in]       CBOT group name.
* @param cbor_group_name_size[in]  CBOR group name size .
* @param fcc_field_status[out]     Status of the field.
*
* @return
*     One of FCC_STATUS_* error codes
*/
fcc_status_e bundle_process_status_field(const cn_cbor *cbor_blob, char *cbor_group_name, size_t cbor_group_name_size, bool *fcc_field_status);

/** The function sets factory disable flag to sotp.
*
* @return
*     One of FCC_STATUS_* error codes
*/
fcc_status_e fcc_bundle_factory_disable(void);
#ifdef __cplusplus
}
#endif

#endif //__FCC_BUNDLE_UTILS_H__
