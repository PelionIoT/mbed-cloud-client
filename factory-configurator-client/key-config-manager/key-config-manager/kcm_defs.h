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

/**
* Security descriptor - contains different ACLs such as remote ACL, local ACL and audit.
* Currently defined to `void*.`
* May be changed in the future.
*/
typedef void* kcm_security_desc_s;

#ifndef __DOXYGEN__
/**
* CryptoKeyScheme structure.
* Currently defined to void*.
* May be changed in the future.
*/
typedef void* kcm_crypto_key_scheme_s;

#endif //#ifndef __DOXYGEN__


#define KCM_MAX_FILENAME_SIZE  1012

#define KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN 5

typedef void* kcm_cert_chain_handle;


#ifdef __cplusplus
}
#endif

#endif //__KCM_DEFS_H__
