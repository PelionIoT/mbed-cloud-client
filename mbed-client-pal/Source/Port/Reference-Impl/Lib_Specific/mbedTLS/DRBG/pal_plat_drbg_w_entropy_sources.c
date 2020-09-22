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

#include "pal.h"
#include "pal_plat_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/config.h"
#include "pal_plat_Crypto.h"
#if PAL_USE_HW_TRNG
#include "pal_plat_drbg_noise.h"
#endif
#include "mbed_trace.h"
#include <stdlib.h>

#define TRACE_GROUP "PAL"

// Forward declaration to use non-public function from pal_plat_Crypto.c
palStatus_t pal_plat_CtrDRBGSeedFromEntropySources(palCtrDrbgCtxHandle_t ctx, int (*f_entropy)(void *, unsigned char *, size_t), const void* additionalData, size_t additionalDataLen);

PAL_PRIVATE palCtrDrbgCtxHandle_t g_palCtrDrbgCtx = NULLPTR;

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
    palStatus_t status = PAL_SUCCESS;
    if (g_palCtrDrbgCtx) {
        return status;
    }

#if PAL_USE_HW_TRNG
    status = pal_plat_noiseInit();
    if (status != PAL_SUCCESS)
    {
        goto Exit;
    }
#endif 

    // Notice that pal_plat_CtrDRBGInit is used and NOT pal_CtrDRBGInit, because the latter also tries to seed the DRBG
    status = pal_plat_CtrDRBGInit(&g_palCtrDrbgCtx);
    if (status != PAL_SUCCESS)
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
    if (status != PAL_SUCCESS) {
        goto Exit;
    }    
#else

#if PAL_USE_HW_TRNG
    status = pal_plat_noiseCreateThread();
    if (status != PAL_SUCCESS)
    {
        PAL_LOG_ERR("Error creating noise thread.");
        goto Exit;
    }
#endif // PAL_USE_HW_TRNG
#endif // MBEDTLS_ENTROPY_NV_SEED

    /*
     * At this point the DRBG has the following state:
     * * If defined(MBEDTLS_ENTROPY_NV_SEED): initialized but not seeded - will be seeded when pal_plat_osEntropyInject() is called. pal_plat_osRandomBuffer_blocking() 
     *   will fail until entropy is injected.
     * * If not defined(MBEDTLS_ENTROPY_NV_SEED): initialized and seeded. pal_plat_osRandomBuffer_blocking() call should succeed.
     */
    
Exit:
    if (status != PAL_SUCCESS && g_palCtrDrbgCtx != NULLPTR) {
        (void)pal_CtrDRBGFree(&g_palCtrDrbgCtx);
        // No need to set g_palCtrDrbgCtx = NULLPTR, the pal_plat_CtrDRBGFree function already does so
    }
    return status;
}

palStatus_t pal_plat_DRBGDestroy(void)
{
    palStatus_t status = PAL_SUCCESS;
    if (!g_palCtrDrbgCtx) {
        return PAL_ERR_NOT_INITIALIZED;
    } else {
        (void)pal_CtrDRBGFree(&g_palCtrDrbgCtx);
#if PAL_USE_HW_TRNG
        status = pal_plat_noiseDestroy();
#endif
    }
    return status;
}

//! This function must not be static as it is also called from pal_plat_osEntropyInject() which declares it explicitly
// FIXME: move to pal_plat_Crypto (mbedtls) ? then pal_plat_CtrDRBGSeedFromEntropySources is a static function within
// This function seeds the DRBG based on internal sources (i.e entropy that is already injected, trng, etc.)
// Should be pal_plat_DRBGSeed(palCtrDrbgCtxHandle_t handle) and we can move
palStatus_t pal_plat_DRBGSeed()
{
    palStatus_t status = PAL_SUCCESS;

    if (!g_palCtrDrbgCtx) 
    {
        return PAL_ERR_NOT_INITIALIZED;
    }

    // Seed the DRBG if not seeded. If it is - reseed it.
    status = pal_plat_CtrDRBGSeedFromEntropySources(g_palCtrDrbgCtx, mbedtls_entropy_func, NULL, 0);

    return status;
}

palStatus_t pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes)
{
    palStatus_t status = PAL_SUCCESS;

    if (!g_palCtrDrbgCtx) 
    {
        return PAL_ERR_NOT_INITIALIZED;
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
    if (pal_CtrDRBGIsSeeded(g_palCtrDrbgCtx) == PAL_ERR_CTR_DRBG_NOT_SEEDED)
    {
        status = pal_plat_DRBGSeed();
        // If seeding failed with source error, we assume that the NV source did not exist, and return a PAL_ERR_CTR_DRBG_NOT_SEEDED error
        if (status == PAL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED)
        {
            return PAL_ERR_CTR_DRBG_NOT_SEEDED;
        } else if (status != PAL_SUCCESS) {
            return status;
        }
    }

#if PAL_USE_HW_TRNG
    return pal_plat_generateDrbgWithNoiseAttempt(g_palCtrDrbgCtx, randomBuf, false, bufSizeBytes);
#else 
    // Note that calling pal_plat_generateDrbgWithNoiseAttempt here will also work
    // but that will add some unnecessary code to the image. Besides, it is more clear
    // this way.
    return pal_CtrDRBGGenerate(g_palCtrDrbgCtx, randomBuf, bufSizeBytes);
#endif
}

palStatus_t pal_plat_DRBGEntropyInject(const uint8_t *entropyBuf, size_t bufSizeBytes)
{
    PAL_LOG_DBG("Entropy: entered into pal_plat_DRBGEntropyInject().");

    palStatus_t pal_status = PAL_SUCCESS;

    // Creating a temporary buffer for checking if the entropy is existing
    uint8_t entropy_temp_buf[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t data_actual_size_out;

    pal_status = storage_kvstore_read(ENTROPY_RANDOM_SEED, entropy_temp_buf, MBEDTLS_ENTROPY_BLOCK_SIZE, &data_actual_size_out);
    PAL_LOG_DBG("ENTROPY_RANDOM_SEED %s; entropyBuf addr 0x%08x; bufSizeBytes %i; data_actual_size_out %i; "
                "PAL status: 0x%08x.",
                ENTROPY_RANDOM_SEED, entropy_temp_buf, MBEDTLS_ENTROPY_BLOCK_SIZE, data_actual_size_out, pal_status);
    (void) data_actual_size_out;

    // Do nothing if the entropy is saved in memory
    if (PAL_ERR_ITEM_NOT_EXIST == pal_status)       /* No seed exists */
    {
        PAL_LOG_DBG("Entropy: The entropy not exist. Will write new entropy.");

        // entropy does not exist - inject it
        // Note. is_write_once = FALSE, value can be updated

        pal_status = storage_kvstore_write(ENTROPY_RANDOM_SEED, (uint8_t *) entropyBuf, bufSizeBytes);
        PAL_LOG_DBG("ENTROPY_RANDOM_SEED %s; entropyBuf addr 0x%08x; bufSizeBytes %i; PAL status: 0x%08x %i.",
                    ENTROPY_RANDOM_SEED, entropyBuf, bufSizeBytes, pal_status);

        if (PAL_SUCCESS != pal_status) 
        PAL_LOG_ERR("Entropy: Failed to inject/write an entropy!");
    }
    else if (PAL_SUCCESS == pal_status)
    {
        PAL_LOG_DBG("Entropy: The entropy is already seeded!");
        pal_status = PAL_ERR_ENTROPY_EXISTS;
    }
    else if (PAL_SUCCESS != pal_status) 
    {   // Checking pal_status after read/write the entropy
        PAL_LOG_ERR("Entropy: Failed to inject an entropy!");
    }
    return pal_status;
}

int seed_read_from_kvs( unsigned char *buf, size_t buf_len )
{
    size_t actual_size_out;
    return storage_kvstore_read(ENTROPY_RANDOM_SEED, buf, buf_len, &actual_size_out);
}

int seed_write_to_kvs( unsigned char *buf, size_t buf_len )
{
    return storage_kvstore_write(ENTROPY_RANDOM_SEED, (uint8_t *) buf, buf_len);
}

#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
