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

#ifndef __KEYS_CONFIG_MANAGER_H__
#define __KEYS_CONFIG_MANAGER_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "kcm_status.h"
#include "kcm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
    * @file key_config_manager.h
    *  \brief Keys and Configuration Manager (KCM) APIs.
    */

    /* === Initialization and Finalization === */

    /**
    *   Initiate the KCM module.
    *   Allocates and initializes file storage resources.
    *
    *    @returns
    *       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_init(void);

    /**
    *   Finalize the KCM module.
    *   Finalizes and frees file storage resources.
    *
    *    @returns
    *       KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_finalize(void);

    /* === Keys, Certificates and Configuration data storage === */

    /** Store the KCM item into a secure storage.
    * Item name restrictions (the kcm_item_name argument):
    * If you are using Mbed OS 5.11 or higher with the built-in secure storage (KVStore), or your own secure storage (ported to the Pelion client), kcm_item_name must only include the following characters: 'a'-'z', 'A'-'Z', '0'-'9', '_', '-', '.'.
    * If you are using the Pelion client secure storage (SOTP and ESFS), KCM file names have no character restrictions. Note that this feature will be deprecated in the future and the same character restriction will apply ('a'-'z', 'A'-'Z', '0'-'9', '_', '-', '.').
    * 
    *
    *    @param[in] kcm_item_name KCM item name. See comment above.
    *    @param[in] kcm_item_name_len KCM item name length. kcm_item_name_len must be at most ::KCM_MAX_FILENAME_SIZE bytes.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[in] kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *    @param[in] kcm_item_data KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in] kcm_item_data_size KCM item data buffer size in bytes. Can be 0 if you wish to store an empty file.
    *    @param[in] security_desc Security descriptor.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in success.
    *        KCM_STATUS_FILE_EXIST if trying to store an item that already exists.
    *        KCM_STATUS_FILE_NAME_TOO_LONG if kcm_item_name_len is too long.
    *        KCM_STATUS_FILE_NAME_INVALID if kcm_item_name contains illegal characters.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_store(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, bool kcm_item_is_factory, const uint8_t *kcm_item_data, size_t kcm_item_data_size, const kcm_security_desc_s security_desc);

    /* === Keys, Certificates and Configuration data retrieval === */

    /** Retrieve the KCM item data size from a secure storage.
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[out] kcm_item_data_size_out KCM item data size in bytes.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_data_size(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, size_t *kcm_item_data_size_out);

    /** Retrieve KCM item data from a secure storage.
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[out] kcm_item_data_out KCM item data output buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in] kcm_item_data_max_size The maximum size of the KCM item data output buffer in bytes.
    *    @param[out] kcm_item_data_act_size_out Actual KCM item data output buffer size in bytes.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_data(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, uint8_t *kcm_item_data_out, size_t kcm_item_data_max_size, size_t * kcm_item_data_act_size_out);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    /* === Key Configuration Manager with PSA support uses PSA key IDs from 0x1 up to  0x2800 === */


    /** Retrieves a PSA handle that refers to a valid existing private/public key in storage.
    *   The handle remains valid until the application calls kcm_item_close_handle().
    *   You can use the handle for the PSA key layer in mbed-crypto/include/psa/crypto.h.
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`.
    *    @param[out] A handle value that refers to the target KCM item in storage.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_handle(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type, kcm_key_handle_t *key_handle_out);

    /** Frees all resources associated with the PSA private/public key.
    *
    *    @param[in] item_h key handle.
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_close_handle(kcm_key_handle_t key_handle);
#endif

    /* === Keys, Certificates and Configuration delete === */

    /** Delete a KCM item from a secure storage.
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *
    *    @returns
    *        KCM_STATUS_SUCCESS status in case of success or one of ::kcm_status_e errors otherwise.
    */
    kcm_status_e kcm_item_delete(const uint8_t *kcm_item_name, size_t kcm_item_name_len, kcm_item_type_e kcm_item_type);

    /* === Certificates chain APIs === */

    /** The API initializes the chain context for the write chain operation.
    *   It should be called before `::kcm_cert_chain_add_next` API.
    *
    *    @param[out] kcm_chain_handle                 A pointer to the certificate chain handle.
    *    @param[in]  kcm_chain_name                   A pointer to the certificate chain name.
    *    @param[in]  kcm_chain_name_len               The length of the certificate name buffer.
    *    @param[in]  kcm_chain_len                    The number of certificates in the chain.
    *    @param[in]  kcm_chain_is_factory             True if the KCM chain is a factory item, otherwise false.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle,
                                       const uint8_t *kcm_chain_name,
                                       size_t kcm_chain_name_len,
                                       size_t kcm_chain_len,
                                       bool kcm_chain_is_factory);

    /** The API initializes the chain context for the read chain operation.
    *   This API should be called before `::kcm_cert_chain_get_next_size` and `::kcm_cert_chain_get_next_data` APIs.
    *
    *    @param[out] kcm_chain_handle                  A pointer to the certificate chain handle.
    *    @param[in]  kcm_chain_name                    A pointer to the certificate chain name.
    *    @param[in]  kcm_chain_name_len                The size of the certificate name buffer.
    *    @param[out] kcm_chain_len                     The length of the certificate chain.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle,
                                     const uint8_t *kcm_chain_name,
                                     size_t kcm_chain_name_len,
                                     size_t *kcm_chain_len_out);

    /** This API adds the next chain of certificates to the storage. 
    *
    *  It also validates the previous certificate (unless it is the first certificate) with the public key from `kcm_cert_data`.
    *  The certificates should be added in the order from lowest child, followed by the certificate that signs it and so on, all the way to the root of the chain.
    *
    *    @param[in] kcm_chain_handle                 The certificate chain handle.
    *    @param[in] kcm_cert_data                    A pointer to the certificate data in DER format.
    *    @param[in] kcm_cert_data_size               The size of the certificate data buffer.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success. 
    *        KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED if one of the certificates in the chain failed to verify its predecessor.
    *        In other cases, one of the `::kcm_status_e` errors.
    *       
    */
    kcm_status_e kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
                                         const uint8_t *kcm_cert_data,
                                         size_t kcm_cert_data_size);

    /** The API deletes all certificates of the chain from the storage.
    *  In case of invalid chain the API deletes all reachable certificates and return relevant error for indication.
    *
    *    @param[in] kcm_chain_name                A pointer to certificate chain name.
    *    @param[in] kcm_chain_name_len            The length of certificate chain name.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_delete(const uint8_t *kcm_chain_name,
                                       size_t kcm_chain_name_len);

    /** This API returns the size of the next certificate in the chain.
    *  It should be called before `::kcm_cert_chain_get_next_data`.
    *  This operation does not increase the chain's context iterator.
    *
    *    @param[in]  kcm_chain_handle        The certificate chain handle.
    *    @param[out] kcm_cert_data_size      The pointer size of the next certificate.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in success.
    *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN if the end of the chain was reached.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_get_next_size(kcm_cert_chain_handle kcm_chain_handle,
                                              size_t *kcm_cert_data_size);

    /** This API returns the data of the next certificate in the chain.
    *   To get the exact size of the next certificate, use `::kcm_cert_chain_get_next_size`.
    *   In the end of the get data operation, the chain context points to the next certificate of the current chain.
    *
    *    @param[in] kcm_chain_handle                    The certificate chain handle.
    *    @param[in/out] kcm_cert_data                   A pointer to the certificate data in DER format.
    *    @param[in] kcm_max_cert_data_size              The max size of the certificate data buffer.
    *    @param[out] kcm_actual_cert_data_size          The actual size of the certificate data.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in success.
    *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN if the end of the chain was reached.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_get_next_data(kcm_cert_chain_handle kcm_chain_handle,
                                              uint8_t *kcm_cert_data,
                                              size_t kcm_max_cert_data_size,
                                              size_t *kcm_actual_cert_data_size);


    /** The API releases the context and frees allocated resources.
    *   When the operation type is creation and if the total number of added/stored certificates is not equal to the number
    *   of certificates in the chain, the API returns an error.
    *
    *    @param[in] kcm_chain_handle                    The certificate chain handle.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in success.
    *        ::KCM_STATUS_CLOSE_INCOMPLETE_CHAIN if all certificates were not saved. In this case the chain will be deleted.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle);


    /* === Factory Reset === */

    /**  Reset the KCM secure storage to factory state.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in success.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_factory_reset(void);


    /** Generate a key pair complying the given cryptographic scheme in DER format.
    *    Saves the private and public key if provided.
    *
    *      @param key_scheme The cryptographic scheme.
    *      @param private_key_name The private key name for which a key pair is generated.
    *      @param private_key_name_len The length of the private key name.
    *      @param public_key_name The public key name for which a key pair is generated.
    *      This parameter is optional. If not provided, the key will be generated, but not stored.
    *      @param public_key_name_len The length of the public key name.
    *      Must be 0, if `::public_key_name` not provided.
    *      @param kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *      @param kcm_params Additional `kcm_params`. Currently void.
    *
    *      @returns
    *         KCM_STATUS_SUCCESS in success.
    *         Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_key_pair_generate_and_store(
        const kcm_crypto_key_scheme_e     key_scheme,
        const uint8_t                     *private_key_name,
        size_t                            private_key_name_len,
        const uint8_t                     *public_key_name,
        size_t                            public_key_name_len,
        bool                              kcm_item_is_factory,
        const kcm_security_desc_s         *kcm_params
    );


    /** Generate a general CSR from the given private key.
   *
   *     @param private_key_name The private key name to fetch from storage.
   *     @param private_key_name_len The length of the private key name.
   *     @param csr_params CSR parameters.
   *     @param csr_buff_out A pointer to the generated CSR buffer to fill.
   *     @param csr_buff_max_size The size of the supplied CSR buffer.
   *     @param csr_buff_act_size The actual size of the filled CSR buffer.
   *
   *     @returns
   *         KCM_STATUS_SUCCESS in success.
   *         Otherwise, one of the `::kcm_status_e` errors.
   */
    kcm_status_e kcm_csr_generate(
        const uint8_t              *private_key_name,
        size_t                     private_key_name_len,
        const kcm_csr_params_s     *csr_params,
        uint8_t                    *csr_buff_out,
        size_t                     csr_buff_max_size,
        size_t                     *csr_buff_act_size
    );


    /** Generate private and public key and CSR from the generated keys.
    *
    *     @param key_scheme The cryptographic scheme.
    *     @param private_key_name The private key name to generate.
    *     @param private_key_name_len The length of the private key name.
    *     @param public_key_name The public key name for which a key pair is generated.
    *     This parameter is optional. If not provided, the key will be generated, but not stored.
    *     @param public_key_name_len The length of the public key name.
    *     Must be 0, if `::public_key_name` is not provided.
    *     @param kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *     @param csr_params CSR parameters.
    *     @param csr_buff_out A pointer to the generated CSR buffer to fill.
    *     @param csr_buff_max_size The size of the supplied CSR buffer.
    *     @param csr_buff_act_size The actual size of the filled CSR buffer.
    *     @param kcm_data_pkcm_params Additional `kcm_params`. Currently void.
    *
    *     @returns
    *         KCM_STATUS_SUCCESS in success.
    *         Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_generate_keys_and_csr(
        kcm_crypto_key_scheme_e     key_scheme,
        const uint8_t               *private_key_name,
        size_t                      private_key_name_len,
        const uint8_t               *public_key_name,
        size_t                      public_key_name_len,
        bool                        kcm_item_is_factory,
        const kcm_csr_params_s      *csr_params,
        uint8_t                     *csr_buff_out,
        size_t                      csr_buff_max_size,
        size_t                      *csr_buff_act_size_out,
        const kcm_security_desc_s   *kcm_params
    );

    /** Verify the device-generated certificate against the given private key name from storage.
    * This function can be called when the certificate creation is initiated by the device using `kcm_generate_keys_and_csr` or `kcm_csr_generate` functions.
    * In this case, the function checks the correlation between certificate's public key and given private key generated by the device and saved in device storage.
    *
    *    @param[in] kcm_cert_data The DER certificate data buffer.
    *    @param[in] kcm_cert_data_size The size of the DER certificate data buffer in bytes.
    *    @param[in] kcm_priv_key_name The private key name of the certificate. The function assumes that the key was generated by the device and saved in the storage.
    *    @param[in] kcm_priv_key_name_len The length of the private key name of the certificate.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_ITEM_NOT_FOUND if the private key was not found in the storage.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_certificate_verify_with_private_key(
        const uint8_t * kcm_cert_data,
        size_t kcm_cert_data_size,
        const uint8_t * kcm_priv_key_name,
        size_t kcm_priv_key_name_len);



#ifdef __cplusplus
}
#endif

#endif //__KEYS_CONFIG_MANAGER_H__

