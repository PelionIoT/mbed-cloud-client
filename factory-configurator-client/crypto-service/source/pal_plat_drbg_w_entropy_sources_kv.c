// ----------------------------------------------------------------------------
// Copyright 2019-2020 ARM Ltd.
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

// This file is compiled if we wish to use mbedtls entropy sources for collecting entropy and updating the non-volatile entropy
// There is currently an open issue https://jira.arm.com/browse/IOTCRYPT-180 (ability to accumulate sufficiently large entropy)
// So, meanwhile use this module only with PSA build since we must use the mbedtls entropy sourcing method. 
// When this issue is resolved - SOTP builds may also use this module, which will deprecate pal_plat_drbg_sotp.c

// This file implements pal_plat_drbg.h for mbedtls properly

#if defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) &&  !defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/config.h"
#include "pal_plat_Crypto.h"
#ifndef FCC_NANOCLIENT_ENABLED
#if PAL_USE_HW_TRNG
#include "pal_plat_drbg_noise.h"
#endif
#endif
#include "mbed_trace.h"
#include <stdlib.h>
#include "pal_Crypto.h"
#include "pal_plat_Crypto.h"


#define TRACE_GROUP "DRBG"

// Forward declaration to use non-public function from pal_plat_Crypto.c
palStatus_t pal_plat_CtrDRBGSeedFromEntropySources(palCtrDrbgCtxHandle_t ctx, int (*f_entropy)(void *, unsigned char *, size_t), const void* additionalData, size_t additionalDataLen);

static palCtrDrbgCtxHandle_t g_palCtrDrbgCtx = NULLPTR;

// Forward declaration
palStatus_t pal_plat_DRBGSeed(void);


/**
 * 1. init CTR DRBG context (entropy and DRBG mbedtls contexts) and noise
 * 2. If not expecting entropy (MBEDTLS_ENTROPY_NV_SEED not defined):
 *   2.a Seed the DRBG
 * 3. If expecting entropy (MBEDTLS_ENTROPY_NV_SEED defined):
 *    Do nothing (DRBG will be initialized by pal_plat_osEntropyInject()
 */
palStatus_t pal_plat_DRBGInit(void)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    if (g_palCtrDrbgCtx) {
        return status;
    }
#ifndef FCC_NANOCLIENT_ENABLED
#if PAL_USE_HW_TRNG
    status = pal_plat_noiseInit();
    if (status != FCC_PAL_SUCCESS)
    {
        goto Exit;
    }
#endif 
#endif
    // Notice that pal_plat_CtrDRBGInit is used and NOT pal_CtrDRBGInit, because the latter also tries to seed the DRBG
    status = pal_plat_CtrDRBGInit(&g_palCtrDrbgCtx);
    if (status != FCC_PAL_SUCCESS)
    {
        goto Exit;
    }

    /*
     * Seed the DRBG only if we do not expect a non-volatile entropy to be injected.
     * If we expect an NV seed, mbedtls_ctr_drbg_seed will fail trying to read the seed 
     * since the entropy was not injected yet.
     */

#ifndef MBEDTLS_ENTROPY_NV_SEED
    status = pal_plat_DRBGSeed();
    if (status != FCC_PAL_SUCCESS) {
        goto Exit;
    }
#else

#ifndef FCC_NANOCLIENT_ENABLED
#if PAL_USE_HW_TRNG
    status = pal_plat_noiseCreateThread();
    if (status != FCC_PAL_SUCCESS)
    {
        PAL_LOG_ERR("Error creating noise thread.");
        goto Exit;
    }
#endif // PAL_USE_HW_TRNG
#endif // MBEDTLS_ENTROPY_NV_SEED
#endif // FCC_NANOCLIENT_ENABLED

    /*
     * At this point the DRBG has the following state:
     * * If defined(MBEDTLS_ENTROPY_NV_SEED): initialized but not seeded - will be seeded when pal_plat_osEntropyInject() is called. pal_plat_osRandomBuffer_blocking() 
     *   will fail until entropy is injected.
     * * If not defined(MBEDTLS_ENTROPY_NV_SEED): initialized and seeded. pal_plat_osRandomBuffer_blocking() call should succeed.
     */
    
Exit:
    if (status != FCC_PAL_SUCCESS && g_palCtrDrbgCtx != NULLPTR) {
        (void)pal_CtrDRBGFree(&g_palCtrDrbgCtx);
        // No need to set g_palCtrDrbgCtx = NULLPTR, the pal_plat_CtrDRBGFree function already does so
    }
    return status;
}


palStatus_t pal_plat_DRBGDestroy(void)
{
    palStatus_t status = FCC_PAL_SUCCESS;
    if (!g_palCtrDrbgCtx) {
        return FCC_PAL_ERR_NOT_INITIALIZED;
    } else {
        (void)pal_CtrDRBGFree(&g_palCtrDrbgCtx);

#ifndef FCC_NANOCLIENT_ENABLED
#if PAL_USE_HW_TRNG
        status = pal_plat_noiseDestroy();
#endif
#endif
    }
    return status;
}

//! This function must not be static as it is also called from pal_plat_osEntropyInject() which declares it explicitly
// FIXME: move to pal_plat_Crypto (mbedtls) ? then pal_plat_CtrDRBGSeedFromEntropySources is a static function within
// This function seeds the DRBG based on internal sources (i.e entropy that is already injected, trng, etc.)
// Should be fcc_pal_plat_DRBGSeed(palCtrDrbgCtxHandle_t handle) and we can move
palStatus_t pal_plat_DRBGSeed()
{
    palStatus_t status = FCC_PAL_SUCCESS;

    if (!g_palCtrDrbgCtx) 
    {
        return FCC_PAL_ERR_NOT_INITIALIZED;
    }

    // Seed the DRBG if not seeded. If it is - reseed it.
    status = pal_plat_CtrDRBGSeedFromEntropySources(g_palCtrDrbgCtx, mbedtls_entropy_func, NULL, 0);

    return status;
}

palStatus_t pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes)
{
    palStatus_t status = FCC_PAL_SUCCESS;

    if (!g_palCtrDrbgCtx) 
    {
        return FCC_PAL_ERR_NOT_INITIALIZED;
    }
    /*
     * If the DRBG is not yet seeded, try to seed it.
     * This check is important for the production flow where NV entropy is expected (MBEDTLS_ENTROPY_NV_SEED defined):
     * First run factory app:
     *  - Entropy is injected and DRBG is seeded
     * Then run Pelion client app (entropy exists in storage):
     *  - call pal_plat_osRandomBuffer_blocking(). DRBG is not seeded during pal_plat_DRBGInit() and pal_plat_osEntropyInject() 
     *    will not be called so we should seed the DRBG with the entropy already in storage.
     */
    if (pal_CtrDRBGIsSeeded(g_palCtrDrbgCtx) == FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED)
    {
        status = pal_plat_DRBGSeed();
        // If seeding failed with source error, we assume that the NV source did not exist, and return a FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED error
        if (status == FCC_PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED)
        {
            return FCC_PAL_ERR_CTR_DRBG_NOT_SEEDED;
        } else if (status != FCC_PAL_SUCCESS) {
            return status;
        }
    }

#if PAL_USE_HW_TRNG && defined(MBED_NOT_NANOCLIENT)
    return plat_generateDrbgWithNoiseAttempt(g_palCtrDrbgCtx, randomBuf, false, bufSizeBytes);
#else 
    // Note that calling pal_plat_generateDrbgWithNoiseAttempt here will also work
    // but that will add some unnecessary code to the image. Besides, it is more clear
    // this way.
    return pal_CtrDRBGGenerate(g_palCtrDrbgCtx, randomBuf, bufSizeBytes);
#endif
}
#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
