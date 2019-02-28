/*******************************************************************************
* Copyright 2018 ARM Ltd.
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

#if !defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) 
#include "pal.h"
#include "sotp.h"
#include "pal_plat_entropy.h"

#define SOTP_ENTROPY_BUFF_SIZE (PAL_PLAT_MAX_ENTROPY_SIZE % 4 == 0 ? PAL_PLAT_MAX_ENTROPY_SIZE / 4 : PAL_PLAT_MAX_ENTROPY_SIZE / 4 + 1)

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

// Merge pal_plat_osEntropyInject and pal_plat_mbedtls_nv_seed_write
palStatus_t pal_plat_osEntropyInject(const uint8_t *entropyBuf, size_t bufSizeBytes)
{
    sotp_result_e sotp_result;
    uint16_t len; // Not used, just placeholder

    sotp_result = sotp_get_item_size(SOTP_TYPE_RANDOM_SEED, &len);
    if (sotp_result == SOTP_SUCCESS)
    {
        return PAL_ERR_ENTROPY_EXISTS;
    }
    else
    {
        if (bufSizeBytes > PAL_PLAT_MAX_ENTROPY_SIZE)
        {
            return PAL_ERR_ENTROPY_TOO_LARGE;
        }

        // copy to an aligned buffer and store in SOTP
        uint32_t sotpBuf[SOTP_ENTROPY_BUFF_SIZE];
        memcpy(sotpBuf, entropyBuf, bufSizeBytes);
        return pal_osSotpErrorTranslation(sotp_set(SOTP_TYPE_RANDOM_SEED, bufSizeBytes, sotpBuf));
    }
    
}


#endif

