/*******************************************************************************
 * Copyright 2016-2018 ARM Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/


#ifndef _PAL_ROT_H
#define _PAL_ROT_H

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/*! \file pal_rot.h
*  \brief PAL ROT.
*   This file contains the ROT (root of trust) API.
*/


//! Device key types supported in PAL.
typedef enum  palDeviceKeyType {
    palOsStorageEncryptionKey128Bit = 0, /*! 128bit storage encryption key derived from RoT. */
    palOsStorageSignatureKey128Bit = 1, /*! 128bit storage signature key derived from RoT. */
    palOsStorageHmacSha256 = 2
} palDevKeyType_t;


/*! Return a device unique key derived from the root of trust.
*
* @param[in] keyType The type of key to derive.
* @param[in,out] key A 128-bit OR 256-bit buffer to hold the derived key, size is defined according to the `keyType`.
* @param[in] keyLenBytes The size of buffer to hold the 128-bit OR 256-bit key.
* \return PAL_SUCCESS in case of success and one of the following error codes in case of failure: \n
* PAL_ERR_GET_DEV_KEY - an error in key derivation.\n
* PAL_ERR_INVALID_ARGUMENT - invalid parameter.
*/
palStatus_t pal_osGetDeviceKey(palDevKeyType_t keyType, uint8_t *key, size_t keyLenBytes);


#ifdef __cplusplus
}
#endif
#endif //_PAL_ROT_H
