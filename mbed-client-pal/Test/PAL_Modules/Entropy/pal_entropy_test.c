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

#include "pal.h"
#include "unity.h"
#include "unity_fixture.h"
#include "pal_plat_entropy.h"
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
#include "sotp.h"
#endif
#include <stdlib.h>


TEST_GROUP(pal_entropy);


TEST_SETUP(pal_entropy)
{
    palStatus_t status = PAL_SUCCESS;

    //init pal
    status = pal_init();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
// reset storage before each tests to avoid possible RoT leftovers
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    pal_SSTReset();
#else
    sotp_reset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
}

TEST_TEAR_DOWN(pal_entropy)
{

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    pal_SSTReset();
#else
    sotp_reset();
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    pal_destroy();
}

/*! \brief Entropy and DRBG test when entropy is not needed for random number generation (TRNG exists)
 *
 * 
 *
* | # |    Step                                                                        |   Expected  |
* |---|--------------------------------------------------------------------------------|-------------|
* | 1 | Inject entropy.                                                                | PAL_SUCCESS or PAL_ERR_NOT_SUPPORTED if compiled out |
* | 2 | Generate a random buffer using `pal_osRandomBuffer`.                           | PAL_SUCCESS |
*/

#if PAL_USE_HW_TRNG
TEST(pal_entropy, inject)
{
    palStatus_t status = PAL_SUCCESS;
    uint8_t entropy[PAL_PLAT_MAX_ENTROPY_SIZE + 1] = { 2 };
    uint8_t out_buf[64] = { 0 };

    /*#1*/
    status = pal_osEntropyInject(entropy, PAL_PLAT_MAX_ENTROPY_SIZE); 
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_NOT_SUPPORTED, status);
#else 
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif
    /*#2*/
    status = pal_osRandomBuffer(out_buf, sizeof(out_buf));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

#else // PAL_USE_HW_TRNG

/*! \brief Entropy and DRBG test when entropy is needed for random number generation (no TRNG)
 *
 * 
 *
* | # |    Step                                                                        |   Expected  |
* |---|--------------------------------------------------------------------------------|-------------|
* | 1 | No entropy, attempt to generate a random buffer and fail.                      | PAL_ERR_CTR_DRBG_NOT_SEEDED |
* | 2 | Set an entropy that is too large and fail.                                     | PAL_ERR_ENTROPY_TOO_LARGE |
* | 3 | Again - try to generate a random buffer and fail.                              | PAL_ERR_CTR_DRBG_NOT_SEEDED |
* | 4 | Successfully inject the entropy.                                               | PAL_SUCCESS |
* | 5 | Now that entropy exists, we may successfully generate a random buffer.         | PAL_SUCCESS |
* | 6 | Fail to set the entropy a second time.                                         | PAL_ERR_ENTROPY_EXISTS |
* | 7 | Delete the entropy by force, by resetting the storage.                         | PAL_SUCCESS |
* | 8 | Set entropy again - will also reseed the DRBG since no entropy in storage.     | PAL_SUCCESS |
* | 9 | Successfully generate a random buffer.                                         | PAL_SUCCESS |
 */
TEST(pal_entropy, inject)
{
    palStatus_t status = PAL_SUCCESS;
    uint8_t entropy[PAL_PLAT_MAX_ENTROPY_SIZE + 1] = { 2 };
    uint8_t out_buf[64] = { 0 };

    // No entropy, attempt to generate a random buffer and fail if no trng
    /*#1*/
    status = pal_osRandomBuffer(out_buf, sizeof(out_buf));
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_CTR_DRBG_NOT_SEEDED, status);

    // Set an entropy that is too large and fail
    /*#2*/
    status = pal_osEntropyInject(entropy, PAL_PLAT_MAX_ENTROPY_SIZE + 1); 
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_ENTROPY_TOO_LARGE, status);

    // Again - try to generate a random buffer and fail
    /*#3*/
    status = pal_osRandomBuffer(out_buf, sizeof(out_buf));
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_CTR_DRBG_NOT_SEEDED, status);

    // Successfully inject the entropy
    /*#4*/
    status = pal_osEntropyInject(entropy, PAL_PLAT_MAX_ENTROPY_SIZE); 
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // Now that entropy exists, we may successfully generate a random buffer
    /*#5*/
    status = pal_osRandomBuffer(out_buf, sizeof(out_buf));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // Fail to set the entropy a second time
    /*#6*/
    status = pal_osEntropyInject(entropy, PAL_PLAT_MAX_ENTROPY_SIZE); 
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_ENTROPY_EXISTS, status);

    // Delete the entropy by force, now entropy will not exist anymore, yet DRBG will still be initialized and seeded
    /*#7*/
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    status = pal_SSTReset();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#else
    sotp_result_e sotpResult = sotp_reset();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#endif //MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT

    // Generating a random buffer should still succeed assuming it the reseeding interval has not been exceeded yet.
    // However we do not test this as it isn't really a well defined behavior
    // pal_status = pal_osRandomBuffer(out_buf, sizeof(out_buf));
    // TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);

    // Set entropy again, this will also reseed the DRBG since there is no entropy in the storage
    /*#8*/
    status = pal_osEntropyInject(entropy, PAL_PLAT_MAX_ENTROPY_SIZE); 
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    // Successfully generate a random buffer
    /*#9*/
    status = pal_osRandomBuffer(out_buf, sizeof(out_buf));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}
#endif // PAL_USE_HW_TRNG
