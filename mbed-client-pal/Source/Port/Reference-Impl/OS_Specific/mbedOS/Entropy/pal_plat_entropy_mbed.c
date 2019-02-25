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
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

#include "pal_plat_entropy.h"

// FIXME: This is temporary until entropy is supported for kv-store world 

palStatus_t pal_plat_set_nv_entropy(uint32_t *entropyBuf, uint16_t bufSizeBytes)
{
    return PAL_ERR_ITEM_NOT_EXIST;
}
palStatus_t pal_plat_get_nv_entropy(uint32_t *entropyBuf, size_t bufSizeBytes, uint16_t *bytesRead)
{
    return PAL_ERR_ITEM_NOT_EXIST;
}

#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
