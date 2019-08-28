// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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

#ifndef __CERTIFICATE_ENROLLMENT_H__
#define __CERTIFICATE_ENROLLMENT_H__

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "ce_status.h"
#include "cs_der_keys_and_csrs.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct ce_renewal_params_ {
    struct cert_chain_context_s *cert_data;// Not owner
    cs_key_handle_t crypto_handle;//This should include pointer to private key/private  and public key object optional - Not owner 
} ce_renewal_params_s;

ce_status_e ce_init(void);


/** Translates key-configurator-manager (KCM) statuses into certificate enrollment statuses.
*
* @param kcm_status[in] The KCM status to translate
*
* @returns
*       one of the `::ce_status_e` statuses listed in ce_status.h.
*/
ce_status_e ce_error_handler(kcm_status_e kcm_status);

/** Generates key pair and a CSR from a given certificate name.
* Calling to cs_key_pair_new(..) prior calling this function is mandatory in order to achieve the handle to the key object in store.
* Calling to cs_key_pair_free(..) prior calling this function is mandatory in order to evacuate the handle resources.
* Please refer cs_der_keys_and_csr.h for specific API details.
*
* @param certifcate_name[in] Certificate name to search in store, the certificate
*                            name must be NULL terminated string
* @param key_h[in] A handle to a key object that obtained by calling to cs_key_pair_new(..)
* @param csr_out[out] A pointer to a newly allocated buffer that accommodate the CSR.
*                     It is the user responsibility to evacuate this buffer.
* @param csr_size_out[out] The size in bytes of the newly created CSR
* @returns
*       CE_STATUS_SUCCESS in case of success or one of the `::ce_status_e` errors otherwise.
*/
ce_status_e ce_generate_keys_and_create_csr_from_certificate(
    const char *certificate_name, cs_renewal_names_s *renewal_items_names, const cs_key_handle_t key_h,
    uint8_t **csr_out, size_t *csr_size_out);

/*! The API updates certificate/certificate chain and correlated key/key pair.
*
*    @param[in] item_name              item name.
*    @param[in] item_name_len          item name length.
*    @param[in] renewal_data           pointer to renewal data structure.
*
*    @returns
*        CE_STATUS_SUCCESS in case of success or one of the `::ce_status_e` errors otherwise.
*/
ce_status_e ce_safe_renewal(const char *item_name, cs_renewal_names_s *renewal_items_names, ce_renewal_params_s *renewal_data);

/*! The API called during kcm_init() in case of error during renewal_certificate API.
* The functions checks status of the renewal process, restores original data and deletes redundant files.
* The APIs checks the status based on renewal file and its data.
*    @void
*/
void ce_check_and_restore_backup_status(void);

#ifdef __cplusplus
}
#endif

#endif  //__CERTIFICATE_ENROLLMENT_H__
