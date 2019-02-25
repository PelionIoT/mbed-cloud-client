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

#ifndef __KCM_STATUS_H__
#define __KCM_STATUS_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
* @file kcm_status.h
*  \brief Keys and configuration manager (KCM) status/error codes.
* This list may grow as needed.
*/

typedef enum {
    KCM_STATUS_SUCCESS,                                       //!< Operation completed successfully.
    KCM_STATUS_ERROR,                                         //!< Operation ended with an unspecified error.
    KCM_STATUS_INVALID_PARAMETER,                             //!< A parameter provided to the function was invalid.
    KCM_STATUS_INSUFFICIENT_BUFFER,                           //!< The provided buffer size was insufficient for the required output.
    KCM_STATUS_OUT_OF_MEMORY,                                 //!< An out-of-memory condition occurred.
    KCM_STATUS_ITEM_NOT_FOUND,                                //!< The item was not found in the storage.
    KCM_STATUS_META_DATA_NOT_FOUND,                           //!< The meta data was not found in the file.
    KCM_STATUS_META_DATA_SIZE_ERROR,                          //!< The meta data found but the size is different then expected.
    KCM_STATUS_FILE_EXIST,                                    //!< Trying to store an item that is already in the storage.
    KCM_STATUS_KEY_EXIST,                                     //!< Trying to generate a key for a CSR, but the requesested output key name already exists in the storage.
    KCM_STATUS_NOT_PERMITTED,                                 //!< Trying to access an item without proper permissions.
    KCM_STATUS_STORAGE_ERROR,                                 //!< File error occurred.
    KCM_STATUS_ITEM_IS_EMPTY,                                 //!< The data of current item is empty.
    KCM_STATUS_INVALID_FILE_VERSION,                          //!< Invalid file version, the file can not be read
    KCM_STATUS_FILE_CORRUPTED,                                //!< File data corrupted, the file can not be read
    KCM_STATUS_FILE_NAME_CORRUPTED,                           //!< File name corrupted, the file can not be read
    KCM_STATUS_INVALID_FILE_ACCESS_MODE,                      //!< Invalid file access mode
    KCM_STATUS_UNKNOWN_STORAGE_ERROR,                         //!< KCM can not translate current storage error
    KCM_STATUS_NOT_INITIALIZED,                               //!< KCM did not initialized.
    KCM_STATUS_CLOSE_INCOMPLETE_CHAIN,                        //!< Closing KCM chain with less certificates than declared in create
    KCM_STATUS_CORRUPTED_CHAIN_FILE,                          //!< KCM attempted to open an invalid chain file
    KCM_STATUS_INVALID_NUM_OF_CERT_IN_CHAIN,                  //!< Operation failed due to invalid number of certificates.
    KCM_STATUS_CERTIFICATE_CHAIN_VERIFICATION_FAILED,         //!< At least one of the certificates fails to verify its predecessor.
    KCM_STATUS_FILE_NAME_TOO_LONG,                            //!< Provided a file name that is longer than permitted. 
    KCM_CRYPTO_STATUS_UNSUPPORTED_HASH_MODE,                  //!< Operation was called with unsupported hash mode.
    KCM_CRYPTO_STATUS_PARSING_DER_PRIVATE_KEY,                //!< Operation failed to parse private der key.
    KCM_CRYPTO_STATUS_PARSING_DER_PUBLIC_KEY,                 //!< Operation failed to parse public der key.
    KCM_CRYPTO_STATUS_PK_KEY_INVALID_FORMAT,                  //!< Operation failed due to invalid pk key format.
    KCM_CRYPTO_STATUS_INVALID_PK_PUBKEY,                      //!< Operation failed due to invalid pk public key.
    KCM_CRYPTO_STATUS_ECP_INVALID_KEY,                        //!< Operation failed due to invalid ECP key.
    KCM_CRYPTO_STATUS_PK_KEY_INVALID_VERSION,                 //!< Operation failed due to invalid pk version of key.
    KCM_CRYPTO_STATUS_PK_PASSWORD_REQUIRED,                   //!< Operation failed due to missing password.
    KCM_CRYPTO_STATUS_PRIVATE_KEY_VERIFICATION_FAILED,        //!< Operation failed to verify private key.
    KCM_CRYPTO_STATUS_PUBLIC_KEY_VERIFICATION_FAILED,         //!< Operation failed to verify public key.
    KCM_CRYPTO_STATUS_PK_UNKNOWN_PK_ALG,                      //!< Operation failed due to unknown pk algorithm,
    KCM_CRYPTO_STATUS_UNSUPPORTED_CURVE,                      //!< Unsupported curve.
    KCM_CRYPTO_STATUS_PARSING_DER_CERT,                       //!< Operation failed to parse der certificate.
    KCM_CRYPTO_STATUS_CERT_EXPIRED,                           //!< Certificate validity is expired.
    KCM_CRYPTO_STATUS_CERT_FUTURE,                            //!< Certificate validity starts in future.
    KCM_CRYPTO_STATUS_CERT_MD_ALG,                            //!< Certificate with bad MD algorithm.
    KCM_CRYPTO_STATUS_CERT_PUB_KEY_TYPE,                      //!< Certificate with unsupported public key PK type.
    KCM_CRYPTO_STATUS_CERT_PUB_KEY,                           //!< Certificate with bad public key data (size or curve).
    KCM_CRYPTO_STATUS_CERT_NOT_TRUSTED,                       //!< Certificate is not trusted.
    KCM_CRYPTO_STATUS_INVALID_X509_ATTR,                      //!< Certificate with bad x509 attribute
    KCM_CRYPTO_STATUS_VERIFY_SIGNATURE_FAILED,                //!< Operation failed to check the signature.
    KCM_CRYPTO_STATUS_INVALID_MD_TYPE,                        //!< Operation failed in check of ecc md type.
    KCM_CRYPTO_STATUS_FAILED_TO_WRITE_SIGNATURE,              //!< Operation failed to calculate signature.
    KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PRIVATE_KEY,            //!< Operation failed to write private key to DER buffer.
    KCM_CRYPTO_STATUS_FAILED_TO_WRITE_PUBLIC_KEY,             //!< Operation failed to write public key to DER buffer.
    KCM_CRYPTO_STATUS_FAILED_TO_WRITE_CSR,                    //!< Operation failed to write CSR to DER buffer.
    KCM_CRYPTO_STATUS_INVALID_OID,                            //!< Operation failed due to invalid OID.
    KCM_CRYPTO_STATUS_INVALID_NAME_FORMAT,                    //!< Operation failed due to invalid name format.
    KCM_STATUS_SELF_GENERATED_CERTIFICATE_VERIFICATION_ERROR, //!< Verification of self-generated certificate against stored private key failed.
    KCM_CRYPTO_STATUS_SET_EXTENSION_FAILED,                   //!< Copying the extension from certificate to CSR failed.
    KCM_STATUS_RBP_ERROR,                                     //!< Roll back protected data operation failed.
    KCM_STATUS_FILE_NAME_INVALID,                             //!< File name contains an invalid character (Must only include the following characters: '0-9', 'A'-'Z','a'-'z', '.', '-', '_').
    KCM_MAX_STATUS,
} kcm_status_e;

//The macro defined for backward compatibility. Will be deprecated.
#define KCM_STATUS_ESFS_ERROR KCM_STATUS_STORAGE_ERROR

#ifdef __cplusplus
}
#endif

#endif //__KCM_STATUS_H__
