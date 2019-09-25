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

#if !defined  MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "pal.h"
#include "pal_plat_rot.h"

// If there is no "HW ROT", this code is enabled. It will in practice either use a pre-generated
// ROT in SOTP or generate it once on the fly.
#if (PAL_USE_HW_ROT == 0)

#include "sotp.h"

#define TRACE_GROUP "PAL"

//Error Translation from SOTP module to PAL
PAL_PRIVATE palStatus_t pal_osSotpErrorTranslation(sotp_result_e err)
{
    palStatus_t ret;
    switch(err)
    {
        case SOTP_SUCCESS:
            ret = PAL_SUCCESS;
            break;
        case SOTP_BAD_VALUE:
            ret = PAL_ERR_INVALID_ARGUMENT;
            break;

        case SOTP_BUFF_TOO_SMALL:
            ret = PAL_ERR_BUFFER_TOO_SMALL;
            break;

        case SOTP_BUFF_NOT_ALIGNED:
            ret = PAL_ERR_RTOS_BUFFER_NOT_ALIGNED;
            break;

        case SOTP_NOT_FOUND:
            ret = PAL_ERR_ITEM_NOT_EXIST;
            break;

        case SOTP_READ_ERROR:
        case SOTP_DATA_CORRUPT:
        case SOTP_OS_ERROR:
        default:
            ret = PAL_ERR_GENERIC_FAILURE;
            break;
    }
    return ret;
}

palStatus_t pal_plat_osGetRoT(uint8_t * key, size_t keyLenBytes)
{
    sotp_result_e sotpStatus;
    uint16_t actual_size;

    sotpStatus = sotp_get(SOTP_TYPE_ROT, keyLenBytes, (uint32_t *)key, &actual_size);
    return pal_osSotpErrorTranslation(sotpStatus);

}

palStatus_t pal_plat_osSetRoT(uint8_t * key, size_t keyLenBytes)
{
    sotp_result_e sotpStatus;
    uint16_t actual_size;
    uint8_t rotBuffer[PAL_DEVICE_KEY_SIZE_IN_BYTES] __attribute__((aligned(4))) = { 0 };

    if (keyLenBytes != PAL_DEVICE_KEY_SIZE_IN_BYTES || key == NULL) {
        return PAL_ERR_INVALID_ARGUMENT;
    }

    //Check if Rot already exists
    sotpStatus = sotp_get(SOTP_TYPE_ROT, keyLenBytes, (uint32_t *)rotBuffer, &actual_size);
    if (sotpStatus == SOTP_SUCCESS) {
        return PAL_ERR_ITEM_EXIST;
    }

    //Copy RoT to aligned buffer
    memcpy(rotBuffer, key, PAL_DEVICE_KEY_SIZE_IN_BYTES);

    //Set RoT
    sotpStatus = sotp_set(SOTP_TYPE_ROT, PAL_DEVICE_KEY_SIZE_IN_BYTES, (uint32_t *)rotBuffer);
    return pal_osSotpErrorTranslation(sotpStatus);

}
#endif // (PAL_USE_HW_ROT == 0)
#endif //#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT