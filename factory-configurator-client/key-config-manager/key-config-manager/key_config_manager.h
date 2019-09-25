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
    *  \brief Key and Configuration Manager (KCM) APIs.
    */

    /* === Initialization and Finalization === */

    /**
    * Initiates the KCM module.
    * Allocates and initializes file storage resources.
    *
    *    @returns
    *       KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_init(void);

    /**
    * Finalizes the KCM module.
    * Finalizes and frees file storage resources.
    *
    *    @returns
    *       ::KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_finalize(void);

    /* === Key, certificate, and configuration data storage === */

    /**
    * Stores a KCM item in secure storage.
    *
    * When `MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT` is on,
    * the ``::KCM_PRIVATE_KEY_ITEM and ::KCM_PUBLIC_KEY_ITEM` types are stored in PSA storage.
    *
    * Item name restrictions (the kcm_item_name argument):
    * kcm_item_name must only include the following characters: `a`-`z`, `A`-`Z`, `0`-`9`, `_`, `-`, `.`.
    *
    *    @param[in] kcm_item_name       KCM item name. See comment above.
    *    @param[in] kcm_item_name_len   KCM item name length. kcm_item_name_len must be at most ::KCM_MAX_FILENAME_SIZE bytes.
    *    @param[in] kcm_item_type       KCM item type as defined in `::kcm_item_type_e`.
    *    @param[in] kcm_item_is_factory True if the KCM item is a factory item; otherwise, false.
    *    @param[in] kcm_item_data       KCM item data buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in] kcm_item_data_size  KCM item data buffer size in bytes. Can be 0 if you want to store an empty file.
    *    @param[in] kcm_item_info       Security descriptor, caller must set this to NULL.
    *    @returns
    *        ::KCM_STATUS_SUCCESS            in case of success.
    *        ::KCM_STATUS_FILE_EXIST         when trying to store an item that already exists.
    *        ::KCM_STATUS_FILE_NAME_TOO_LONG if kcm_item_name_len is too long.
    *        ::KCM_STATUS_FILE_NAME_INVALID  if kcm_item_name contains illegal characters.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_store(const uint8_t            *kcm_item_name,
                                size_t                    kcm_item_name_len,
                                kcm_item_type_e           kcm_item_type,
                                bool                      kcm_item_is_factory,
                                const uint8_t            *kcm_item_data,
                                size_t                    kcm_item_data_size,
                                const kcm_security_desc_s kcm_item_info);

    /* === Key, certificate, and configuration data retrieval === */

    /**
    * Retrieves the KCM item data size from secure storage.
    * In PSA mode (MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is on), ::KCM_PRIVATE_KEY_ITEM type is not supported.   
    *
    *    @param[in]  kcm_item_name          KCM item name.
    *    @param[in]  kcm_item_name_len      KCM item name length.
    *    @param[in]  kcm_item_type          KCM item type as defined in `::kcm_item_type_e`.
    *    @param[out] kcm_item_data_size_out KCM item data size in bytes.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS            in case of success.
    *        ::KCM_STATUS_ITEM_NOT_FOUND     if kcm_item_name isn't found in the secure storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_data_size(const uint8_t  *kcm_item_name,
                                        size_t          kcm_item_name_len,
                                        kcm_item_type_e kcm_item_type,
                                        size_t         *kcm_item_data_size_out);

    /**
    * Retrieves KCM item data from secure storage.
    * In PSA mode (MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is on), ::KCM_PRIVATE_KEY_ITEM type is not supported.
    *
    *    @param[in]  kcm_item_name              KCM item name.
    *    @param[in]  kcm_item_name_len          KCM item name length.
    *    @param[in]  kcm_item_type              KCM item type as defined in `::kcm_item_type_e`.
    *    @param[out] kcm_item_data_out          KCM item data output buffer. Can be NULL if `kcm_item_data_size` is 0.
    *    @param[in]  kcm_item_data_max_size     The maximum size of the KCM item data output buffer in bytes.
    *    @param[out] kcm_item_data_act_size_out Actual KCM item data output buffer size in bytes.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS            in case of success.
    *        ::KCM_STATUS_ITEM_NOT_FOUND     if kcm_item_name isn't found in the secure storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_data(const uint8_t  *kcm_item_name,
                                   size_t          kcm_item_name_len,
                                   kcm_item_type_e kcm_item_type,
                                   uint8_t        *kcm_item_data_out,
                                   size_t          kcm_item_data_max_size,
                                   size_t         *kcm_item_data_act_size_out);

    /**
    * Retrieves KCM item data and its size from secure storage.
    * The buffer for the data is allocated internally and the caller is responsible to free it.
    * If kcm_status_e` error returned, no need to free the buffer
    * In PSA mode (MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT is on), ::KCM_PRIVATE_KEY_ITEM type is not supported.
    *
    *    @param[in]  kcm_item_name              KCM item name.
    *    @param[in]  kcm_item_name_len          KCM item name length.
    *    @param[in]  kcm_item_type              KCM item type as defined in `::kcm_item_type_e`.
    *    @param[out] kcm_item_data_out          KCM item data output buffer. The buffer allocated internally. 
    *    @param[out] kcm_item_data_size_out     KCM item data output buffer size in bytes.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS            in case of success.
    *        ::KCM_STATUS_ITEM_NOT_FOUND     if kcm_item_name isn't found in the secure storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_size_and_data(const uint8_t * kcm_item_name,
                                            size_t kcm_item_name_len,
                                            kcm_item_type_e kcm_item_type,
                                            uint8_t ** kcm_item_data_out,
                                            size_t * kcm_item_data_size_out);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    /* === Key and Configuration Manager with Platform Secure Architecture (PSA) support uses PSA key IDs from 0x1 up to 0x2800 === */


    /**
    * Retrieves a PSA handle that refers to a valid existing private/public key in storage.
    * The handle remains valid until the application calls ::kcm_item_close_handle().
    * You can use the handle for the PSA key layer in mbed-crypto/inc/psa/crypto.h.
    *
    *    @param[in]  kcm_item_name     KCM item name.
    *    @param[in]  kcm_item_name_len KCM item name length.
    *    @param[in]  kcm_item_type     KCM item type as defined in `::kcm_item_type_e`.
    *                                  Only ::KCM_PRIVATE_KEY_ITEM and ::KCM_PUBLIC_KEY_ITEM are valid.
    *                                  Other types result in a ::KCM_STATUS_INVALID_PARAMETER error.
    *    @param[out] key_handle_out    Pointer to handle for the PSA key.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS            in case of success.
    *        ::KCM_STATUS_ITEM_NOT_FOUND     if the item isn't found in the PSA storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_handle(const uint8_t    *kcm_item_name,
                                     size_t            kcm_item_name_len,
                                     kcm_item_type_e   kcm_item_type,
                                     kcm_key_handle_t *key_handle_out);

    /**
    * Frees all resources associated with the PSA private/public key and sets the handle value to zero.
    * This API must be called after ::kcm_item_get_handle().
    *
    *    @param[in] key_handle Pointer to the handle of the PSA key.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_close_handle(kcm_key_handle_t *key_handle);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

    /** Return an initial value of an item extra info.
    * Caller must set item extra info relevant members before calling any other KCM API otherwise default will be used (default: KCM_LOCATION_PSA).
    */
#define KCM_ITEM_EXTRA_INFO_INIT {KCM_LOCATION_PSA, KCM_LOCATION_PSA}
    static inline kcm_item_extra_info_s kcm_item_extra_info_init(void)
    {
        const kcm_item_extra_info_s extra_info = KCM_ITEM_EXTRA_INFO_INIT;
        return (extra_info);
    }

    /**
    * Gets the location of a certain item.
    * The location is the actual storage meduim as defined by ::kcm_item_location_e
    *
    *    @param[in]  kcm_item_name     KCM item name.
    *    @param[in]  kcm_item_name_len KCM item name length.
    *    @param[in]  kcm_item_type     KCM item type as defined in `::kcm_item_type_e`.
    *                                  Only ::KCM_PRIVATE_KEY_ITEM and ::KCM_PUBLIC_KEY_ITEM are valid.
    *                                  Other types result in a ::KCM_STATUS_INVALID_PARAMETER error.
    *    @param[out] item_location_out A pointer to the location on which the item resides.
    *                                  This out variable will be set to the corresponding storage location as defined in `::kcm_item_location_e`
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS            in case of success.
    *        ::KCM_STATUS_ITEM_NOT_FOUND     if the item isn't found in the PSA storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_item_get_location(const uint8_t *item_name,
                                       size_t item_name_len,
                                       kcm_item_type_e kcm_item_type,
                                       kcm_item_location_e *item_location_out);

#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT
#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    /* === Key, certificate, and configuration delete === */

    /**
    * Deletes a KCM item from a secure storage.
    *
    *    @param[in] kcm_item_name     KCM item name.
    *    @param[in] kcm_item_name_len KCM item name length.
    *    @param[in] kcm_item_type     KCM item type as defined in `::kcm_item_type_e`.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS status in case of success, or one of the ::kcm_status_e errors otherwise.
    */
    kcm_status_e kcm_item_delete(const uint8_t  *kcm_item_name,
                                 size_t          kcm_item_name_len,
                                 kcm_item_type_e kcm_item_type);

    /* === Certificate chain APIs === */

    /**
    * Initializes the chain context for the write chain operation.
    * This API must be called before the `::kcm_cert_chain_add_next` API.
    *
    *    @param[out] kcm_chain_handle                 A pointer to the certificate chain handle.
    *    @param[in]  kcm_chain_name                   Certificate chain name.
    *    @param[in]  kcm_chain_name_len               Certificate chain name length.
    *    @param[in]  kcm_chain_len                    The number of certificates in the chain.
    *    @param[in]  kcm_chain_is_factory             True if the KCM chain is a factory item; otherwise, false.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in case of success, or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_create(kcm_cert_chain_handle *kcm_chain_handle,
                                       const uint8_t         *kcm_chain_name,
                                       size_t                 kcm_chain_name_len,
                                       size_t                 kcm_chain_len,
                                       bool                   kcm_chain_is_factory);

    /**
    * Initializes the chain context for the read chain operation.
    * This API must be called before the `::kcm_cert_chain_get_next_size` and `::kcm_cert_chain_get_next_data` APIs.
    *
    *    @param[out] kcm_chain_handle                  A pointer to the certificate chain handle.
    *    @param[in]  kcm_chain_name                    Certificate chain name.
    *    @param[in]  kcm_chain_name_len                Certificate chain name length.
    *    @param[out] kcm_chain_len                     The length of the certificate chain.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in case of success
    *      If the first certificate of the chain is missing, the function returns a
    *        ::KCM_STATUS_ITEM_NOT_FOUND error.
    *      If one of the next certificates is missing, the function returns:
    *        ::KCM_STATUS_ITEM_NOT_FOUND for SST storage configuration.
    *        ::KCM_STATUS_SUCCESS for Device Management Client secure storage configuration.
    *                  If there is an attempt to read the missing certificate using the opened chain handle, through the `::kcm_cert_chain_get_next_size`
    *                  or `::kcm_cert_chain_get_next_data` APIs, the called API then returns a ::KCM_STATUS_ITEM_NOT_FOUND error.
    *      One of the `::kcm_status_e` errors otherwise.
    */

    kcm_status_e kcm_cert_chain_open(kcm_cert_chain_handle *kcm_chain_handle,
                                     const uint8_t         *kcm_chain_name,
                                     size_t                 kcm_chain_name_len,
                                     size_t                *kcm_chain_len_out);

    /**
    * Adds the next chain of certificates to storage.
    *
    * It also validates the previous certificate (unless it is the first certificate) with the public key from `kcm_cert_data`.
    * The certificates must be added in order - starting with the leaf, followed by the certificate that signs it, and so on - all the way to the root of the chain.
    *
    *    @param[in] kcm_chain_handle                 The certificate chain handle.
    *    @param[in] kcm_cert_data                    A pointer to the certificate data in DER format.
    *    @param[in] kcm_cert_data_size               The size of the certificate data buffer.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS                               in case of success.
    *        ::KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED if one of the certificates in the chain failed to verify its predecessor.
    *        One of the `::kcm_status_e` errors otherwise.
    *
    */
    kcm_status_e kcm_cert_chain_add_next(kcm_cert_chain_handle kcm_chain_handle,
                                         const uint8_t        *kcm_cert_data,
                                         size_t                kcm_cert_data_size);

    /**
    * Deletes all certificates of the chain from storage.
    * For an invalid chain, the API deletes all reachable certificates and returns a relevant error.
    *
    *    @param[in] kcm_chain_name                Certificate chain name.
    *    @param[in] kcm_chain_name_len            Certificate chain name length.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in the event of success, or one of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_cert_chain_delete(const uint8_t *kcm_chain_name,
                                       size_t         kcm_chain_name_len);

    /**
    * Returns the size of the next certificate in the chain.
    * This API must be called before `::kcm_cert_chain_get_next_data`.
    * This operation does not increase the chain's context iterator.
    *
    *    @param[in]  kcm_chain_handle        The certificate chain handle.
    *    @param[out] kcm_cert_data_size      The pointer size of the next certificate.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS                      in the event of success.
    *        ::KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN if the end of the chain is reached.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_get_next_size(kcm_cert_chain_handle kcm_chain_handle,
                                              size_t               *kcm_cert_data_size);

    /**
    * Returns the data of the next certificate in the chain.
    * To get the exact size of the next certificate, use `::kcm_cert_chain_get_next_size`.
    * In the end of the get data operation, the chain context points to the next certificate of the current chain.
    *
    *    @param[in]  kcm_chain_handle                The certificate chain handle.
    *    @param[out] kcm_cert_data                   A pointer to the certificate data in DER format.
    *    @param[in]  kcm_max_cert_data_size          The maximum size of the certificate data buffer.
    *    @param[out] kcm_actual_cert_data_size       The actual size of the certificate data.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS                      in the event of success.
    *        ::KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN if the end of the chain is reached.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_get_next_data(kcm_cert_chain_handle kcm_chain_handle,
                                              uint8_t              *kcm_cert_data,
                                              size_t                kcm_max_cert_data_size,
                                              size_t               *kcm_actual_cert_data_size);


    /**
    * Releases the context and frees allocated resources.
    * When the operation type is creation, if the total number of added or stored certificates is not equal to the number
    * of certificates in the chain, the API returns an error.
    *
    *    @param[in] kcm_chain_handle                    The certificate chain handle.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS                In the event of success.
    *        ::KCM_STATUS_CLOSE_INCOMPLETE_CHAIN If all certificates were not saved. In this case, the chain is deleted.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_cert_chain_close(kcm_cert_chain_handle kcm_chain_handle);


    /* === Factory Reset === */

    /**
    * Resets the KCM secure storage to factory state.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS in success.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_factory_reset(void);


    /**
    * Generates a key pair that complies with the given cryptographic scheme in DER format.
    * Saves the private and public key, if provided.
    *
    *      @param[in] key_scheme           The cryptographic scheme.
    *      @param[in] private_key_name     The private key name for which a key pair is generated.
    *      @param[in] private_key_name_len The length of the private key name.
    *      @param[in] public_key_name      The public key name for which a key pair is generated.
    *                                      This parameter is optional.
    *                                      If not provided, the key is generated, but not stored.
    *      @param[in] public_key_name_len  The length of the public key name.
    *                                      Must be 0, if `::public_key_name` is not provided.
    *      @param[in] kcm_item_is_factory  True if the KCM item is a factory item; otherwise, it is false.
    *      @param[in] kcm_item_info        Additional item data.
    *                                      if Non-PSA: this parameter must be set to NULL
    *                                      if PSA:
    *                                      (1) if NULL: the private/public keys will be generated and stored in the default key resident set in pre-build time.
    *                                      (2) if `kcm_item_extra_info_s`: the private/public keys will be generated and stored in the selected resident defined in `::kcm_item_extra_info_s`.
    *
    *      @returns
    *         ::KCM_STATUS_SUCCESS in the event of success.
    *         Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_key_pair_generate_and_store(const kcm_crypto_key_scheme_e key_scheme,
                                                 const uint8_t                *private_key_name,
                                                 size_t                        private_key_name_len,
                                                 const uint8_t                *public_key_name,
                                                 size_t                        public_key_name_len,
                                                 bool                          kcm_item_is_factory,
                                                 const kcm_security_desc_s     kcm_item_info);


   /**
   * Generates a general CSR from the given private key.
   *
   *     @param[in]  private_key_name     The private key name to fetch from storage.
   *     @param[in]  private_key_name_len The length of the private key name.
   *     @param[in]  csr_params           CSR parameters.
   *     @param[out] csr_buff_out         A pointer to the generated CSR buffer to fill.
   *     @param[in]  csr_buff_max_size    The size of the supplied CSR buffer.
   *     @param[out] csr_buff_act_size    The actual size of the filled CSR buffer.
   *
   *     @returns
   *         ::KCM_STATUS_SUCCESS in the event of success.
   *         Otherwise, one of the `::kcm_status_e` errors.
   */
    kcm_status_e kcm_csr_generate(const uint8_t             *private_key_name,
                                  size_t                     private_key_name_len,
                                  const kcm_csr_params_s    *csr_params,
                                  uint8_t                   *csr_buff_out,
                                  size_t                     csr_buff_max_size,
                                  size_t                    *csr_buff_act_size);


    /**
    * Generates a private and public key and CSR from the generated keys.
    *
    *     @param[in]  key_scheme           The cryptographic scheme.
    *     @param[in]  private_key_name     The private key name to generate.
    *     @param[in]  private_key_name_len The length of the private key name.
    *     @param[in]  public_key_name      The public key name for which a key pair is generated.
    *                                      This parameter is optional.
    *                                      If not provided, the key is generated, but not stored.
    *     @param public_key_name_len       The length of the public key name.
    *                                      Must be 0, if `::public_key_name` is not provided.
    *     @param[in]  kcm_item_is_factory  True if the KCM item is a factory item; otherwise, it is false.
    *     @param[in]  csr_params           CSR parameters.
    *     @param[out] csr_buff_out         A pointer to the generated CSR buffer to fill.
    *     @param[in]  csr_buff_max_size    The size of the supplied CSR buffer.
    *     @param[out] csr_buff_act_size    The actual size of the filled CSR buffer.
    *     @param[in]  kcm_item_info        Additional item data.
    *                                      if Non-PSA: this parameter must be set to NULL
    *                                      if PSA:
    *                                      (1) if NULL: the private/public keys will be generated and stored in the default key resident set in pre-build.
    *                                      (2) if `kcm_item_extra_info_s`: the private/public keys will be generated and stored in the selected resident defined in `::kcm_item_extra_info_s`.
    *
    *     @returns
    *         ::KCM_STATUS_SUCCESS in case of success.
    *         Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_generate_keys_and_csr(kcm_crypto_key_scheme_e     key_scheme,
                                           const uint8_t              *private_key_name,
                                           size_t                      private_key_name_len,
                                           const uint8_t              *public_key_name,
                                           size_t                      public_key_name_len,
                                           bool                        kcm_item_is_factory,
                                           const kcm_csr_params_s     *csr_params,
                                           uint8_t                    *csr_buff_out,
                                           size_t                      csr_buff_max_size,
                                           size_t                     *csr_buff_act_size_out,
                                           const kcm_security_desc_s   kcm_item_info);

    /**
    * Verifies the device-generated certificate against the given private key name from storage.
    * This function can be called when the certificate creation is initiated by the device using the `kcm_generate_keys_and_csr` or `kcm_csr_generate` functions.
    * In this case, the function checks the correlation between the certificate's public key and the given private key generated by the device and saved in device storage.
    *
    *    @param[in] kcm_cert_data         The DER certificate data buffer.
    *    @param[in] kcm_cert_data_size    The size of the DER certificate data buffer in bytes.
    *    @param[in] kcm_priv_key_name     The private key name of the certificate.
    *                                     The function assumes that the key was generated by the device and saved in the storage.
    *    @param[in] kcm_priv_key_name_len The length of the private key name of the certificate.
    *
    *    @returns
    *        ::KCM_STATUS_SUCCESS        in case of success.
    *        ::KCM_STATUS_ITEM_NOT_FOUND if the private key was not found in storage.
    *        Otherwise, one of the `::kcm_status_e` errors.
    */
    kcm_status_e kcm_certificate_verify_with_private_key(const uint8_t *kcm_cert_data,
                                                         size_t         kcm_cert_data_size,
                                                         const uint8_t *kcm_priv_key_name,
                                                         size_t         kcm_priv_key_name_len);


    /** Calculates asymmetric signature on hash digest using associated private key.
    *
    *   The function retrieves a key data/handle according to the private key unique name,
    *   calls an asymmetric EC SECP256R1 sign function, and returns the calculated signature.
    *
    *    @param[in] private_key_name                                   The private key name to fetch from storage.
    *    @param[in] private_key_name_len                               The length of the private key name.
    *    @param[in] hash_digest                                        A pointer to a SHA256 hash digest buffer.
    *    @param[in] hash_digest_size                                   The size of the hash digest buffer. Must be exactly ::KCM_SHA256_SIZE bytes.
    *    @param[out] signature_data_out                                A pointer to the output buffer for the calculated signature in raw format.
    *    @param[in] signature_data_max_size                            The size of the signature buffer. Must be at least ::KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE bytes.
    *    @param[out] signature_data_act_size_out                       The actual size of the output signature buffer.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS on success.
    *        KCM_STATUS_INVALID_PARAMETER if one of the parameters is illegal.
    *        KCM_STATUS_FILE_NAME_TOO_LONG if private_key_name_len is too long.
    *        KCM_STATUS_FILE_NAME_INVALID if private_key_name contains illegal characters.
    *        KCM_STATUS_INSUFFICIENT_BUFFER if signature_data_max_size is too small.
    *        KCM_STATUS_ITEM_NOT_FOUND if the key is not found in the storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_asymmetric_sign(
        const uint8_t              *private_key_name,
        size_t                      private_key_name_len,
        const uint8_t               *hash_digest,
        size_t                      hash_digest_size,
        uint8_t                     *signature_data_out,
        size_t                      signature_data_max_size,
        size_t                      *signature_data_act_size_out);


    /** Verifies the signature of a previously hashed message using the associated public key.
    *
    *   The function retrieves a key data/handle according to the public key unique name,
    *   calls an asymmetric EC SECP256R1 verify function, and returns the result.
    *
    *    @param[in] public_key_name                             The public key name to fetch from storage.
    *    @param[in] public_key_name_len                         The length of the public key name.
    *    @param[in] hash_digest                                 A pointer to a SHA256 hash digest buffer.
    *    @param[in] hash_digest_size                            The size of the hash digest buffer. Must be exactly ::KCM_SHA256_SIZE bytes.
    *    @param[in] signature                                   The signature buffer in raw format.
    *    @param[in] signature_size                              The size of the signature buffer. Must be at most ::KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE bytes.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS on success.
    *        KCM_STATUS_INVALID_PARAMETER if one of the parameters is illegal.
    *        KCM_STATUS_FILE_NAME_TOO_LONG if public_key_name_len is too long.
    *        KCM_STATUS_FILE_NAME_INVALID if public_key_name contains illegal characters.
    *        KCM_STATUS_INSUFFICIENT_BUFFER if signature_data_max_size is too small.
    *        KCM_STATUS_ITEM_NOT_FOUND if the key is not found in the storage.
    *        One of the `::kcm_status_e` errors otherwise.
    */

    kcm_status_e kcm_asymmetric_verify(
        const uint8_t              *public_key_name,
        size_t                      public_key_name_len,
        const uint8_t               *hash_digest,
        size_t                      hash_digest_size,
        const uint8_t               *signature,
        size_t                      signature_size);

    /** Generates a random number into a given buffer of a given size in bytes.
    * 
    *    The function returns an error if entropy is expected and the function is called before entropy was injected.
    *
    *    @param[out] buffer                          A pointer to a buffer that holds the generated number.
    *    @param[in] buffer_size                      The size of the buffer and the size of the required random number to generate.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS on success.
    *        KCM_STATUS_INVALID_PARAMETER if one of the parameters is illegal.
    *        KCM_CRYPTO_STATUS_ENTROPY_MISSING if entropy is expected and wasn't injected.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_generate_random(uint8_t *buffer, size_t buffer_size);

    /* Computes a shared secret using the elliptic curve Diffie Hellman algorithm.
    *
    * A few limitations that should be considered:
    * (1) If Secure Element exist, this function enable only a single key usage ALG_ECDSA(ALG_SHA_256).
    * (2) If PSA and Secure Element does not exist, this function enable multiple key usage except LPC55S69_NS and CY8CKIT_062_WIFI_BT_PSA targets.
    *
    *    @param[in] private_key_name                            The private key name to fetch from storage.
    *    @param[in] private_key_name_len                        The length of the private key name.
    *    @param[in] peer_public_key                             The public key from a peer in DER format.
    *    @param[in] peer_public_key_size                        The length of the public key from a peer.
    *    @param[out] shared_secret                              A pointer to the output shared secret buffer.
    *    @param[in] shared_secret_max_size                      The size of the shared secret buffer. Must be at least ::KCM_EC_SECP256R1_SHARED_SECRET_SIZE bytes.
    *    @param[out] shared_secret_act_size_out                 The actual size of the shared secret buffer.
    *
    *    @returns
    *        KCM_STATUS_SUCCESS on success.
    *        KCM_STATUS_INVALID_PARAMETER if one of the parameters is illegal.
    *        One of the `::kcm_status_e` errors otherwise.
    */
    kcm_status_e kcm_ecdh_key_agreement(
        const uint8_t              *private_key_name,
        size_t                      private_key_name_len,
        const uint8_t               *peer_public_key, 
        size_t                      peer_public_key_size,
        uint8_t                     *shared_secret, 
        size_t                      shared_secret_max_size,
        size_t                      *shared_secret_act_size_out);

#ifdef __cplusplus
}
#endif

#endif //__KEYS_CONFIG_MANAGER_H__
