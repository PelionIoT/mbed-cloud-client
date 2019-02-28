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

#ifndef __FCC_STATUS_H__
#define __FCC_STATUS_H__

#ifdef __cplusplus
extern "C" {
#endif
/**
* @file fcc_status.h
*  \brief factory configurator client status/error codes.
* This list may grow as needed.
*/
    typedef enum {
        FCC_STATUS_SUCCESS  = 0,                    //!< Operation completed successfully.
        FCC_STATUS_ERROR,                      //!< Operation ended with an unspecified error.
        FCC_STATUS_MEMORY_OUT,                 //!< An out-of-memory condition occurred.
        FCC_STATUS_INVALID_PARAMETER,          //!< A parameter provided to the function was invalid.
        FCC_STATUS_STORE_ERROR,                //!< Internal storage error.
        FCC_STATUS_INTERNAL_ITEM_ALREADY_EXIST,//!< Current item already exists in storage.
        FCC_STATUS_CA_ERROR,                   //!< CA Certificate already exist in storage (currently only bootstrap CA)
        FCC_STATUS_ROT_ERROR,                  //!< ROT already exist in storage
        FCC_STATUS_ENTROPY_ERROR,              //!< Entropy already exist in storage
        FCC_STATUS_FACTORY_DISABLED_ERROR,     //!< FCC flow was disabled - denial of service error.
        FCC_STATUS_INVALID_CERTIFICATE,        //!< Invalid certificate found.
        FCC_STATUS_INVALID_CERT_ATTRIBUTE,     //!< Operation failed to get an attribute.
        FCC_STATUS_INVALID_CA_CERT_SIGNATURE,  //!< Invalid ca signature.
        FCC_STATUS_EXPIRED_CERTIFICATE,        //!< Certificate is expired.
        FCC_STATUS_INVALID_LWM2M_CN_ATTR,      //!< Invalid CN field of certificate.
        FCC_STATUS_KCM_ERROR,                  //!< KCM basic functionality failed.
        FCC_STATUS_KCM_STORAGE_ERROR,          //!< KCM failed to read, write or get size of item from/to storage.
        FCC_STATUS_KCM_FILE_EXIST_ERROR,       //!< KCM tried to create existing storage item.
        FCC_STATUS_KCM_CRYPTO_ERROR,           //!< KCM returned error upon cryptographic check of an certificate or key.
        FCC_STATUS_NOT_INITIALIZED,            //!< FCC failed or did not initialized.
        FCC_STATUS_BUNDLE_ERROR,               //!< Protocol layer general error.
        FCC_STATUS_BUNDLE_RESPONSE_ERROR,      //!< Protocol layer failed to create response buffer.
        FCC_STATUS_BUNDLE_UNSUPPORTED_GROUP,   //!< Protocol layer detected unsupported group was found in a message.
        FCC_STATUS_BUNDLE_INVALID_GROUP,       //!< Protocol layer detected invalid group in a message.
        FCC_STATUS_BUNDLE_INVALID_SCHEME,      //!< The scheme version of a message in the protocol layer is wrong.
        FCC_STATUS_ITEM_NOT_EXIST,             //!< Current item wasn't found in the storage
        FCC_STATUS_EMPTY_ITEM,                 //!< Current item's size is 0
        FCC_STATUS_WRONG_ITEM_DATA_SIZE,       //!< Current item's size is different then expected
        FCC_STATUS_URI_WRONG_FORMAT,           //!< Current URI is different than expected.
        FCC_STATUS_FIRST_TO_CLAIM_NOT_ALLOWED, //!< Can't use first to claim without bootstrap or with account ID
        FCC_STATUS_BOOTSTRAP_MODE_ERROR,       //!< Wrong value of bootstrapUse mode.
        FCC_STATUS_OUTPUT_INFO_ERROR,          //!< The process failed in output info creation.
        FCC_STATUS_WARNING_CREATE_ERROR,       //!< The process failed in output info creation.
        FCC_STATUS_UTC_OFFSET_WRONG_FORMAT,    //!< Current UTC is wrong.
        FCC_STATUS_CERTIFICATE_PUBLIC_KEY_CORRELATION_ERROR, //!< Certificate's public key failed do not matches to corresponding private key        
        FCC_STATUS_BUNDLE_INVALID_KEEP_ALIVE_SESSION_STATUS,//!< The message status is invalid.
        FCC_STATUS_TOO_MANY_CSR_REQUESTS,     //!< The message contained more than CSR_MAX_NUMBER_OF_CSRS CSR requests
        FCC_STATUS_NOT_SUPPORTED,             //!< Unsupported feature for current configuration
        FCC_MAX_STATUS = 0x7fffffff
} fcc_status_e;

#ifdef __cplusplus
}
#endif

#endif //__FCC_STATUS_H__
