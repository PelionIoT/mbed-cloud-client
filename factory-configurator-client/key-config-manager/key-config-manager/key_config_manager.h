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
    *
    *    @param[in] kcm_item_name KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type KCM item type as defined in `::kcm_item_type_e`
    *    @param[in] kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *    @param[in] kcm_item_data KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in] kcm_item_data_size KCM item data buffer size in bytes. Can be 0 if you wish to store an empty file.
    *    @param[in] security_desc Security descriptor.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
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

    /** The API initializes chain context for write chain operation,
    *   This API should be called prior to ::kcm_cert_chain_add_next API.
    *
    *    @param[out] kcm_chain_handle                 pointer to certificate chain handle.
    *    @param[in]  kcm_chain_name                   pointer to certificate chain name.
    *    @param[in]  kcm_chain_name_len               length of certificate name buffer.
    *    @param[in]  kcm_chain_len                    number of certificates in the chain.
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

    /** The API initializes chain context for read chain operation.
    *   This API should be called prior to ::kcm_cert_chain_get_next_size and ::kcm_cert_chain_get_next_data APIs
    *
    *    @param[out] kcm_chain_handle                  pointer to certificate chain handle.
    *    @param[in]  kcm_chain_name                    pointer to certificate chain name.
    *    @param[in]  kcm_chain_name_len                size of certificate name buffer.
    *    @param[out] kcm_chain_len                     length of certificate chain.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle,
                                     const uint8_t *kcm_chain_name,
                                     size_t kcm_chain_name_len,
                                     size_t *kcm_chain_len_out);

    /** This API adds next certificate of chain to the storage. 
    *
    *  It also validates the previous certificate (unless it is the first certificate) with the public key from kcm_cert_data.
    *  The certificates should be added in the order from lowest child, followed by the certificate that signs it and so on, all the way to the root of the chain.
    *
    *    @param[in] kcm_chain_handle                 certificate chain handle.
    *    @param[in] kcm_cert_data                    pointer to certificate data in DER format.
    *    @param[in] kcm_cert_data_size               size of certificate data buffer.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
                                         const uint8_t *kcm_cert_data,
                                         size_t kcm_cert_data_size);

    /** The API deletes all certificates of the chain from the storage.
    *
    *    @param[in] kcm_chain_name                pointer to certificate chain name.
    *    @param[in] kcm_chain_name_len            length of certificate chain name.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_delete(const uint8_t *kcm_chain_name,
                                       size_t kcm_chain_name_len);

    /** The API returns size of the next certificate in the chain.
    *  This API should be called prior to ::kcm_cert_chain_get_next_data.
    *  This operation does not increase chain's context iterator.
    *
    *    @param[in]  kcm_chain_handle        certificate chain handle.
    *    @param[out] kcm_cert_data_size      pointer size of next certificate.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN in case we reached the end of the chain
    *        Otherwise one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_get_next_size(kcm_cert_chain_handle kcm_chain_handle,
                                              size_t *kcm_cert_data_size);

    /** The API returns data of the next certificate in the chain.
    *   To get exact size of a next certificate use ::kcm_cert_chain_get_next_size.
    *   In the end of get data operation, chain context points to the next certificate of current chain.
    *
    *    @param[in] kcm_chain_handle                    certificate chain handle.
    *    @param[in/out] kcm_cert_data                   pointer to certificate data in DER format.
    *    @param[in] kcm_max_cert_data_size              max size of certificate data buffer.
    *    @param[out] kcm_actual_cert_data_size          actual size of certificate data.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN in case we reached the end of the chain
    *        Otherwise one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_get_next_data(kcm_cert_chain_handle kcm_chain_handle,
                                              uint8_t *kcm_cert_data,
                                              size_t kcm_max_cert_data_size,
                                              size_t *kcm_actual_cert_data_size);


    /** The API releases the context and frees allocated resources.
    *   When operation type is creation--> if total number of added/stored certificates is not equal to number
    *   of certificates in the chain, the API will return an error.
    *
    *    @param[in] kcm_chain_handle                    certificate chain handle.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_CLOSE_INCOMPLETE_CHAIN in case of not all certificates were saved. In this case the chain will be deleted.
    *        Otherwise one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle);


    /* === Factory Reset === */

    /**  Reset the KCM secure storage to factory state.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_factory_reset(void);


    /** Generate a key pair complying the given cryptographic scheme in DER format.
    *    Saves private key and public key if provided.
    *
    *      @param key_scheme The cryptographic scheme.
    *      @param private_key_name The private key name for which a key pair is generated.
    *      @param private_key_name_len Private key name length
    *      @param public_key_name The public key name for which a key pair is generated.
    *      This parameter is optional. If not provided, the key will be generated, but not stored.
    *      @param public_key_name_len Public key name length.
    *      Must be 0, if ::public_key_name not provided.
    *      @param kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *      @param kcm_params Additional kcm_params. Currently void.
    *
    *      @returns
    *         KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
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
   *     @param private_key_name_len The private key name len.
   *     @param csr_params CSR parameters.
   *     @param csr_buff_out Pointer to generated CSR buffer to fill.
   *     @param csr_buff_max_size Size of the supplied CSR buffer.
   *     @param csr_buff_act_size Actual size of the filled CSR buffer.
   *
   *     @returns
   *         KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
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
    *     @param private_key_name_len The private key name len.
    *     @param public_key_name The public key name for which a key pair is generated.
    *     This parameter is optional. If not provided, the key will be generated, but not stored.
    *     @param public_key_name_len Public key name length.
    *     Must be 0, if ::public_key_name not provided.
    *     @param kcm_item_is_factory True if the KCM item is a factory item, otherwise false.
    *     @param csr_params CSR parameters.
    *     @param csr_buff_out Pointer to generated CSR buffer to fill.
    *     @param csr_buff_max_size Size of the supplied CSR buffer.
    *     @param csr_buff_act_size Actual size of the filled CSR buffer.
    *     @param kcm_data_pkcm_params Additional kcm_params. Currently void.
    *
    *     @returns
    *         KCM_STATUS_SUCCESS in case of success or one of the `::kcm_status_e` errors otherwise.
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

    /** Verify the self-generated certificate against given private key name from storage.
    * This function can be called when certificate creation is initiated by device using `kcm_generate_keys_and_csr` or `kcm_csr_generate` functions.
    * In this case, the function checks correlation between certificate's public key and given private key generated by the device and saved in device storage.
    *
    *    @param[in] kcm_cert_data DER certificate data buffer.
    *    @param[in] kcm_cert_data_size DER certificate data buffer size in bytes.
    *    @param[in] kcm_priv_key_name Private key name of the certificate, the function assumes that the key was generated by the device and saved in the storage.
    *    @param[in] kcm_priv_key_name_len Private key name length of the certificate.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS in case of success.
    *        KCM_STATUS_ITEM_NOT_FOUND  in case private key wasn't found in the storage,
    *            otherwise one of the `::kcm_status_e` errors.
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

