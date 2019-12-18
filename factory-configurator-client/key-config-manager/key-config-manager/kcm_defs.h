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

#ifndef __KCM_DEFS_H__
#define __KCM_DEFS_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
    * @file kcm_defs.h
    *  \brief Keys and configuration manager (KCM) definitions.
    */

    /**
    * KCM item types
    */
    typedef enum {
        KCM_PRIVATE_KEY_ITEM,          //!< KCM private key item type. KCM Supports ECC keys with curves defined in palGroupIndex_t(pal_Crypto.h)
        KCM_PUBLIC_KEY_ITEM,           //!< KCM public key item type.  KCM Supports ECC keys with curves defined in palGroupIndex_t(pal_Crypto.h)
        KCM_SYMMETRIC_KEY_ITEM,        //!< KCM symmetric key item type.
        KCM_CERTIFICATE_ITEM,          //!< KCM certificate item type. Supported x509 certificates in der format.
        KCM_CONFIG_ITEM,               //!< KCM configuration parameter item type.
        KCM_LAST_ITEM                  //!< KCM not defined item type.
    } kcm_item_type_e;

    /** supported message digests */
    typedef enum {
        KCM_MD_NONE = 0x0,
        KCM_MD_SHA256 = 0x1               //!< KCM SHA256 message digest.
    } kcm_md_type_e;

    /** X.509 v3 Key Usage Extension bit-mask options */
    typedef enum {
        KCM_CSR_KU_NONE = 0x0,
        KCM_CSR_KU_DIGITAL_SIGNATURE = 0x1, //!< Digital signature key usage extension bit.
        KCM_CSR_KU_NON_REPUDIATION = 0x2,   //!< Non repudiation key usage extension bit.
        KCM_CSR_KU_KEY_CERT_SIGN = 0x4,     //!< Certificate signing key usage extension bit.
        KCM_CSR_KU_KEY_AGREEMENT = 0x8      //!< Key agreement key usage extension bit.
    } kcm_csr_key_usage_e;

    /** X.509 v3 Extended Key Usage Extension bit-mask options */
    typedef enum {
        KCM_CSR_EXT_KU_NONE =             0,
        KCM_CSR_EXT_KU_ANY =              (1 << 0),
        KCM_CSR_EXT_KU_SERVER_AUTH =      (1 << 1), //!< SSL / TLS Web Server Authentication.
        KCM_CSR_EXT_KU_CLIENT_AUTH =      (1 << 2), //!< SSL / TLS Web Client Authentication.
        KCM_CSR_EXT_KU_CODE_SIGNING =     (1 << 3), //!< Code signing.
        KCM_CSR_EXT_KU_EMAIL_PROTECTION = (1 << 4), //!< E - mail Protection(S / MIME).
        KCM_CSR_EXT_KU_TIME_STAMPING =    (1 << 8), //!< Trusted Time stamping.
        KCM_CSR_EXT_KU_OCSP_SIGNING =     (1 << 9)  //!< OCSP Signing.
    } kcm_csr_ext_key_usage_e;

    /** Cryptographic scheme types
    *   Currently only ECC-256 curve is supported.
    *   More schemes can be added later on.
    */
    typedef enum {
        KCM_SCHEME_NONE,
        KCM_SCHEME_EC_SECP256R1,       //!< KCM ECC cryptographic scheme, 256-bits NIST curve.
    } kcm_crypto_key_scheme_e;

    /*
    * Certificate chain handle
    */
    typedef void* kcm_cert_chain_handle;

    /**
    * KCM key handle type
    * Represents a reference to internal kcm key handler
    */
    typedef uintptr_t kcm_key_handle_t;

    /**
    * Optional item info.
    * Currently used only for PSA configuration for PSA key policy transfer.
    */
    typedef void* kcm_security_desc_s;

    /** This struct contains CSR parameters for future generated CSR
    *
    *      @param subject String that contains the subject (distinguished name) of the certificate in predefined format.
    *                     The format should be as the following example: "C=US,ST=California,L=San Francisco,O=Wikimedia Foundation,Inc.,CN=*.wikipedia.org".
    *      @param md_type Message digest selected from `::kcm_md_type_e`.
    *      @param key_usage Key usage extension bit-mask selected from `::kcm_csr_key_usage_e`. If the requested CSR does not contain any key usage extension, it needs to be set to `::KCM_CSR_KU_NONE`.
    *      @param ext_key_usage Extended key usage extensions bit-mask selected from `::kcm_csr_ext_key_usage_e`. If the requested CSR does not contain any extended key usage extension, it needs to be set to `::KCM_CSR_EXT_KU_NONE`.
    */
    typedef struct kcm_csr_params_ {
        char *subject;
        kcm_md_type_e md_type;
        uint32_t key_usage;
        uint32_t ext_key_usage;
    } kcm_csr_params_s;


#ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

    /**
    * Item residency.
    */
    typedef enum {
        KCM_LOCATION_PSA = 1,             //!< PSA default store as set pre-build.
        KCM_LOCATION_SECURE_ELEMENT = 2,  //!< Secure element store.
    } kcm_item_location_e;

    /** The item extra info structure.
    *
    * Before using the structure, the application must initialize
    * it by calling `kcm_item_extra_info_init()`.
    *
    * @param priv_key_location The location of the private key selected from `::kcm_item_location_e`.
    * @param pub_key_location The location of the public key selected from `::kcm_item_location_e`.
    */
    typedef struct kcm_item_extra_info {
        kcm_item_location_e priv_key_location;
        kcm_item_location_e pub_key_location;
    } kcm_item_extra_info_s;

#endif // #ifdef MBED_CONF_MBED_CLOUD_CLIENT_SECURE_ELEMENT_SUPPORT

    /**
    * Maximum KCM file name length.
    */
    #define KCM_MAX_FILENAME_SIZE  100

    /**
    * Maximum length of the certificate chain on the device.
    */
    #define KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN 5

    /**
    * Size in bytes of the EC SECP256R1 hash digest.
    */
    #define KCM_SHA256_SIZE                         32

    /**
    * Size in bytes of the EC SECP256R1 signature in raw format.
    */
    #define KCM_EC_SECP256R1_SIGNATURE_RAW_SIZE     64

    /**
    * Size in bytes of the EC SECP256R1 shared secret.
    */
    #define KCM_EC_SECP256R1_SHARED_SECRET_SIZE     32

#ifdef __cplusplus
}
#endif

#endif //__KCM_DEFS_H__
