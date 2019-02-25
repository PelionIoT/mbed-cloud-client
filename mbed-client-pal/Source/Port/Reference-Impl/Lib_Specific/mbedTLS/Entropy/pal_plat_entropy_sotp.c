/*******************************************************************************
* Copyright 2016, 2017 ARM Ltd.
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
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

// This file implements pal_plat_entropy.h for non kvstore users

#include "pal.h"
#include "pal_plat_entropy.h"
#include "sotp.h"

//Error Translation from SOTP module to PAL
PAL_PRIVATE palStatus_t pal_osSotpErrorTranslation(sotp_result_e err)
{
    palStatus_t ret;
    switch(err)
    {
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

palStatus_t pal_plat_set_nv_entropy(uint32_t *entropyBuf, uint16_t bufSizeBytes)
{
    palStatus_t palStatus = PAL_SUCCESS;

    sotp_result_e sotpResult = sotp_set(SOTP_TYPE_RANDOM_SEED, bufSizeBytes, entropyBuf);
    if (sotpResult != SOTP_SUCCESS)
    {
        palStatus = pal_osSotpErrorTranslation(sotpResult);
    }

    return palStatus;
}
palStatus_t pal_plat_get_nv_entropy(uint32_t *entropyBuf, size_t bufSizeBytes, uint16_t *bytesRead)

{
    palStatus_t palStatus = PAL_SUCCESS;

    sotp_result_e sotpResult = sotp_get(SOTP_TYPE_RANDOM_SEED, bufSizeBytes, entropyBuf, bytesRead);
    if (sotpResult != SOTP_SUCCESS)
    {
        palStatus = pal_osSotpErrorTranslation(sotpResult);
    }

    return palStatus;
}

#endif
