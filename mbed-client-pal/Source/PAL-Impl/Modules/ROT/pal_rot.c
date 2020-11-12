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


#include "pal.h"
#include "pal_Crypto.h"
#include "pal_plat_rot.h"
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "sotp.h"
#endif
#define TRACE_GROUP "PAL"

/*
 * Here we define const keys for RoT derivation algorithm.
 * Must be 16 characters or less
 */
#define PAL_STORAGE_SIGNATURE_128_BIT_KEY  "RoTStorageSgn128"
#define PAL_STORAGE_ENCRYPTION_128_BIT_KEY "RoTStorageEnc128"
#define PAL_STORAGE_ENCRYPTION_256_BIT_KEY "StorageEnc256HMACSHA256SIGNATURE"

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

palStatus_t pal_osGetDeviceKey(palDevKeyType_t keyType, uint8_t *key, size_t keyLenBytes)
{
    palStatus_t status = PAL_SUCCESS;
    sotp_result_e sotpStatus;
    uint8_t rotBuffer[PAL_DEVICE_KEY_SIZE_IN_BYTES] __attribute__ ((aligned(4))) = {0};

    PAL_VALIDATE_CONDITION_WITH_ERROR(((keyLenBytes < PAL_DEVICE_KEY_SIZE_IN_BYTES) || ((palOsStorageHmacSha256 == keyType) && (keyLenBytes < PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES))), PAL_ERR_BUFFER_TOO_SMALL)
    PAL_VALIDATE_CONDITION_WITH_ERROR((NULL == key), PAL_ERR_NULL_POINTER)

    status = pal_plat_osGetRoT(rotBuffer, keyLenBytes);

#if (PAL_USE_HW_ROT == 0)

    //If Rot not exists,try to generate random buffer and set as RoT
    if (status == PAL_ERR_ITEM_NOT_EXIST) {
        status = pal_osRandomBuffer(rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES);
        if (PAL_SUCCESS == status)
        {
            sotpStatus = sotp_set(SOTP_TYPE_ROT, PAL_DEVICE_KEY_SIZE_IN_BYTES, (uint32_t *)rotBuffer);
            if (SOTP_SUCCESS != sotpStatus) {
                status = PAL_ERR_GENERIC_FAILURE;
            }
        }
    }
#endif

    if (PAL_SUCCESS == status)
    {   // Logic of RoT according to key type using 128 bit strong Key Derivation Algorithm

#if (PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC == 1) //calculate the key derivation in an old way
        switch(keyType)
        {
            case palOsStorageEncryptionKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char*)PAL_STORAGE_ENCRYPTION_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageSignatureKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char *)PAL_STORAGE_SIGNATURE_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageHmacSha256:
            {
                size_t outputLenInBytes = 0;
                status = pal_mdHmacSha256((const unsigned char *)PAL_STORAGE_ENCRYPTION_256_BIT_KEY, PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES, (const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, key, &outputLenInBytes);
                break;
            }
            default:
                status = PAL_ERR_INVALID_ARGUMENT;
        } //switch end
#else //calculate the key derivation in a new way
        switch(keyType)
        {
            case palOsStorageEncryptionKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)PAL_STORAGE_ENCRYPTION_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageSignatureKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)PAL_STORAGE_SIGNATURE_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageHmacSha256:
            {
                size_t outputLenInBytes = 0;
                status = pal_mdHmacSha256((const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, (const unsigned char *)PAL_STORAGE_ENCRYPTION_256_BIT_KEY, PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES, key, &outputLenInBytes);
                break;
            }
            default:
                status = PAL_ERR_INVALID_ARGUMENT;
        } //switch end
#endif

    } // outer if
    else
    {
        status = PAL_ERR_GET_DEV_KEY;
    }

    return status;

}
#endif

palStatus_t pal_osSetRoT(uint8_t *key, size_t keyLenBytes) {

    palStatus_t status = PAL_SUCCESS;

    PAL_VALIDATE_CONDITION_WITH_ERROR(((keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES)), PAL_ERR_INVALID_ARGUMENT)
    PAL_VALIDATE_CONDITION_WITH_ERROR((NULL == key), PAL_ERR_NULL_POINTER)

#if (PAL_USE_HW_ROT == 0)
        status = pal_plat_osSetRoT(key, keyLenBytes);
#else
        return PAL_ERR_NOT_IMPLEMENTED;
#endif
    return status;
}
