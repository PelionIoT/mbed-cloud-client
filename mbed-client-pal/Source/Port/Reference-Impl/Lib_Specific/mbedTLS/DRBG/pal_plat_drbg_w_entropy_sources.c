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
