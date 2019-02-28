// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
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

// MBEDTLS_PSA_HAS_ITS_IO is defined by default in mbed_lib.json of mbedcrypto (part of mbed-os)
// and therefore is visible througout the entire code
#if defined(MBEDTLS_PSA_HAS_ITS_IO) && defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT)

#include "pal.h"
#include "pal_plat_entropy.h"
#include "crypto.h"
#include "config.h" // Include mbedtls config file explicitly for MBEDTLS_ENTROPY_NV_SEED flag

/*
 * Declaration of the function that seeds the DRBG. It is implemented in pal_plat_drbg_w_entropy_sources.c
 * This is not part of the pal_plat_drbg.h interface and therefore we declare it here manually
 */

palStatus_t pal_plat_DRBGSeed();

//Error Translation from PSA module to PAL
PAL_PRIVATE palStatus_t pal_osPsaErrorTranslation(psa_status_t err)
{
    palStatus_t ret;
    switch (err) {
        case PSA_SUCCESS:
            ret = PAL_SUCCESS;
            break;
        case PSA_ERROR_NOT_PERMITTED:
            ret = PAL_ERR_ENTROPY_EXISTS;
            break;
        default:
            ret = PAL_ERR_GENERIC_FAILURE;
            break;
    }
    return ret;
}

/*
 * If entropy not in storage - store the entropy and seed the DRBG for future use
 * If entropy already in storage - do nothing return FCC_STATUS_ENTROPY_ERROR
 * If entropy not in storage, but DRBG is already seeded - store the entropy and reseed the DRBG
 */

/**
 * Inject entropy to non-volatile memory via mbedtls PSA API
 * 
 * * If bufSizeBytes larger than 32, hash (SHA256) and inject the message digest (32 bytes)
 * * If it is exactly 32 inject the buffer
 * * If it is less than 32, return an error
 * 
 * After injecting, this API will seed the DRBG instance in pal_plat_drbg.
 * FIXME: When https://jira.arm.com/browse/IOTCRYPT-180 is resolved - no need to hash, just inject 48 bytes
 *
 * @param entropyBuf - pointer to buffer containing the entropy
 * @param bufSizeBytes - size of entropyBuf in bytes
 * 
 * @return PAL_SUCCESS - if operation is successful
 *         PAL_ERR_NOT_SUPPORTED - if code compiled in a way that does not expect an entropy to be injected (TRNG must be available)
 *         PAL_ERR_INVALID_ARGUMENT - bufSizeBytes too small
 *         PAL_ERR_ENTROPY_EXISTS - Entropy already injected
 *         PAL_ERR_GENERIC_FAILURE - any other case
 */
palStatus_t pal_plat_osEntropyInject(const uint8_t *entropyBuf, size_t bufSizeBytes)
{
#ifdef MBEDTLS_ENTROPY_NV_SEED
    palStatus_t status = PAL_SUCCESS;
    bool entropyExists = false;
    uint8_t buf[PAL_SHA256_SIZE];

    if (bufSizeBytes < PAL_SHA256_SIZE) {
        return PAL_ERR_INVALID_ARGUMENT;
    } else if (bufSizeBytes > PAL_SHA256_SIZE) { 
        if (pal_sha256(entropyBuf, bufSizeBytes, buf) != PAL_SUCCESS) {
            return PAL_ERR_GENERIC_FAILURE;
        }
        // Point to the message digest instead of the actual message
        entropyBuf = buf;
        bufSizeBytes = PAL_SHA256_SIZE;
    }

    
    // Inject the entropy
    status = pal_osPsaErrorTranslation(mbedtls_psa_inject_entropy(entropyBuf, bufSizeBytes));
    if (status != PAL_SUCCESS && status != PAL_ERR_ENTROPY_EXISTS) {
        goto Exit;
    }
    // If entropy in storage - do nothing
    if (status == PAL_ERR_ENTROPY_EXISTS) {
        entropyExists = true;
    }

    /*
     * If status == PAL_ERR_ENTROPY_EXISTS, entropy is somehow already injected, yet the DRBG may not be seeded
     * This may happen if an injected device runs a new factory flow. We will return a PAL_ERR_ENTROPY_EXISTS
     * but we would still like for the DRBG to be initialized. Caller will still catch the error but will be able
     * to call pal_plat_osRandomBuffer_blocking() successfully.
     */

    // Only now that the entropy is injected, we may seed the DRBG, and make calls to pal_plat_osRandomBuffer_blocking()
    // FIXME: When the DRBG module moves to the client, it will provide a seeding API and fcc_entropy_set() will call 
    // the DRBG seeding function. Then pal_plat_osEntropyInject will not have to do so. Note that we seed the DRBG even
    // though pal_plat_osRandomBuffer_blocking() tries to seed it because we would like to know of failures as soon as
    // possible (already in the factory, were this API is invoked, as pal_plat_osRandomBuffer_blocking() may not be invoked
    // in the factory)
    status = pal_plat_DRBGSeed();
Exit:
    if (entropyExists) {
        return PAL_ERR_ENTROPY_EXISTS;
    }
    return status;
#else
    return PAL_ERR_NOT_SUPPORTED;
#endif
}
#endif
