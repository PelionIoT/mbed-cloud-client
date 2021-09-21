// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#include "pal.h"
#include "pal_plat_drbg.h"
#include "psa/crypto.h"

#define TRACE_GROUP "PAL"

PAL_PRIVATE bool g_palDRBGPSAInitialized = false;


palStatus_t pal_plat_DRBGInit(void)
{
    g_palDRBGPSAInitialized = true;

    return PAL_SUCCESS;
}


palStatus_t pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes)
{
    palStatus_t status = PAL_SUCCESS;
    psa_status_t psa_status;

    PAL_VALIDATE_ARGUMENTS (NULL == randomBuf);

    if (!g_palDRBGPSAInitialized) {
        return PAL_ERR_NOT_INITIALIZED;
    }

    // call psa_generate_random
    psa_status = psa_generate_random(randomBuf, bufSizeBytes);
    if (psa_status != PSA_SUCCESS) {
        status = PAL_ERR_GENERIC_FAILURE; 
    }

    return status;
}


palStatus_t pal_plat_DRBGDestroy(void)
{
    g_palDRBGPSAInitialized = false;

    return PAL_SUCCESS;
}

#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

