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

#include "pal.h"
#include "unity.h"
#include "unity_fixture.h"
#include "pal_crypto_test_data.h"
#include "ssl.h"
#include <string.h>
#include <time.h>
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
#include "crypto.h"
#endif

TEST_GROUP(pal_crypto);

TEST_SETUP(pal_crypto)
{
    pal_init();
    palStatus_t status = PAL_SUCCESS;
    uint64_t currentTime = 1512572014; //GMT: Wed, 06 Dec 2017 14:53:33 GMT

#if !PAL_USE_HW_TRNG
    // If no hardware trng - entropy must be injected for random to work
    uint8_t entropy_buf[48] = { 0 };
    status = pal_osEntropyInject(entropy_buf, sizeof(entropy_buf));
    TEST_ASSERT(status == PAL_SUCCESS || status == PAL_ERR_ENTROPY_EXISTS);

#endif

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    // After entropy is injected, it is safe to initialize PSA
    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);
#endif
    // Initialize the time module
    status = pal_initTime();
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_osSetTime(currentTime);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
}

TEST_TEAR_DOWN(pal_crypto)
{
    pal_destroy();
}

/**
 * @brief Testing AES encryption and decryption of buffers in CTR mode.
 * 
 * The test encrypts a buffer, compares it against a desired result and then decrypts it back and compares with the original buffer.
 *
 * Uses CtrVector.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize an AES context.                                                              | PAL_SUCCESS |
 * | 2 | Set an AES 128bit key for encryption.                                                   | PAL_SUCCESS |
 * | 3 | Perform AES CTR encryption on an input vector and check that the result is as expected. | PAL_SUCCESS |
 * | 4 | Release AES context.                                                                    | PAL_SUCCESS |
 * | 5 | Initialize an AES context.                                                              | PAL_SUCCESS |
 * | 6 | Set an AES 128bit key for encryption (used for decryption, see AES CTR docs)            | PAL_SUCCESS |
 * | 7 | Perform AES CTR decryption on an input vector and check that the result is as expected. | PAL_SUCCESS |
 * | 8 | Release AES context.                                                                    | PAL_SUCCESS |
 */
TEST(pal_crypto, AES_CTR)
{
    palStatus_t result;
    palAesHandle_t ctx_enc = NULLPTR, ctx_dec = NULLPTR;
    unsigned char out[16] = {0};
    unsigned char iv[16] = {0};

    memcpy(iv, CtrVector.nonce, sizeof(CtrVector.nonce));

    /*#1*/
    result = pal_initAes(&ctx_enc);
    TEST_ASSERT_NOT_EQUAL(ctx_enc, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_setAesKey(ctx_enc, CtrVector.key, 128, PAL_KEY_TARGET_ENCRYPTION);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_aesCTR(ctx_enc, CtrVector.input, out, sizeof(CtrVector.input), iv);
    TEST_ASSERT_EQUAL_MEMORY(CtrVector.output, out, sizeof(CtrVector.output));

    /*#4*/
    result = pal_freeAes(&ctx_enc);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    memcpy(iv, CtrVector.nonce, sizeof(CtrVector.nonce));
    memset(out, 0, sizeof(out));

    /*#5*/
    result = pal_initAes(&ctx_dec);
    TEST_ASSERT_NOT_EQUAL(ctx_dec, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_setAesKey(ctx_dec, CtrVector.key, 128, PAL_KEY_TARGET_ENCRYPTION);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    result = pal_aesCTR(ctx_dec, CtrVector.output, out, sizeof(CtrVector.output), iv);
    TEST_ASSERT_EQUAL_MEMORY(CtrVector.input, out, sizeof(CtrVector.output));

    /*#8*/
    result = pal_freeAes(&ctx_dec);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
}

/**
 * @brief Testing AES encryption and decryption of buffers in CTR mode.
 *
 * The test encrypts a buffer, compares it against the desired result and then decrypts it back and compares with the original buffer.
 *
 * Uses CtrVector.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize an AES context.                                                             | PAL_SUCCESS |
 * | 2 | Set an AES 128bit key for encryption.                                                  | PAL_SUCCESS |
 * | 3 | Perform AES CTR encryption on input vector and check the encryption output.            | PAL_SUCCESS |
 * | 4 | Release AES context.                                                                   | PAL_SUCCESS |
 * | 5 | Initialize an AES context.                                                             | PAL_SUCCESS |
 * | 6 | Set an AES 128bit key for encryption (used for decryption, see AES CTR docs).          | PAL_SUCCESS |
 * | 7 | Perform AES CTR decryption on an input vector and check that the result is as expected.| PAL_SUCCESS |
 * | 8 | Release AES context.                                                                   | PAL_SUCCESS |
 */
TEST(pal_crypto, AES_CTR_ZeroOffset)
{
    palStatus_t result;
    palAesHandle_t ctx_enc = NULLPTR, ctx_dec = NULLPTR;
    unsigned char out[16] = {0};
    unsigned char iv[16] = {0};

    memcpy(iv, CtrVector.nonce, sizeof(CtrVector.nonce));

    /*#1*/
    result = pal_initAes(&ctx_enc);
    TEST_ASSERT_NOT_EQUAL(ctx_enc, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_setAesKey(ctx_enc, CtrVector.key, 128, PAL_KEY_TARGET_ENCRYPTION);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_aesCTRWithZeroOffset(ctx_enc, CtrVector.input, out, sizeof(CtrVector.input), iv);
    TEST_ASSERT_EQUAL_MEMORY(CtrVector.output, out, sizeof(CtrVector.output));

    /*#4*/
    result = pal_freeAes(&ctx_enc);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    memcpy(iv, CtrVector.nonce, sizeof(CtrVector.nonce));
    memset(out, 0, sizeof(out));

    /*#5*/
    result = pal_initAes(&ctx_dec);
    TEST_ASSERT_NOT_EQUAL(ctx_dec, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_setAesKey(ctx_dec, CtrVector.key, 128, PAL_KEY_TARGET_ENCRYPTION);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    result = pal_aesCTRWithZeroOffset(ctx_dec, CtrVector.output, out, sizeof(CtrVector.output), iv);
    TEST_ASSERT_EQUAL_MEMORY(CtrVector.input, out, sizeof(CtrVector.output));

    /*#8*/
    result = pal_freeAes(&ctx_dec);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
}


/**
 * @brief Testing AES encryption and decryption of buffers in ECB mode.
 *
 * The test encrypts a buffer, compares it against the desired result and then decrypts it back and compares with the original buffer.
 *
 * Uses EcbVector.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize an AES context.                                                             | PAL_SUCCESS |
 * | 2 | Set an AES 128bit key for encryption.                                                  | PAL_SUCCESS |
 * | 3 | Perform AES ECB encryption on input vector and check the encryption output.            | PAL_SUCCESS |
 * | 4 | Release AES context.                                                                   | PAL_SUCCESS |
 * | 5 | Initialize an AES context.                                                             | PAL_SUCCESS |
 * | 6 | Set an AES 128bit key for decryption.                                                  | PAL_SUCCESS |
 * | 7 | Perform AES ECB decryption on an input vector and check that the result is as expected.| PAL_SUCCESS |
 * | 8 | Release AES context.                                                                   | PAL_SUCCESS |
 */
TEST(pal_crypto, AES_ECB)
{
    palStatus_t result;
    palAesHandle_t ctx_enc = NULLPTR, ctx_dec = NULLPTR;
    unsigned char out[16] = {0};
    unsigned char iv[16] = {0};

    memcpy(iv, EcbVector.nonce, sizeof(EcbVector.nonce));

    /*#1*/
    result = pal_initAes(&ctx_enc);
    TEST_ASSERT_NOT_EQUAL(ctx_enc, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_setAesKey(ctx_enc, EcbVector.key, 128, PAL_KEY_TARGET_ENCRYPTION);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_aesECB(ctx_enc, EcbVector.input, out, PAL_AES_ENCRYPT);
    TEST_ASSERT_EQUAL_MEMORY(EcbVector.output, out, sizeof(EcbVector.output));

    /*#4*/
    result = pal_freeAes(&ctx_enc);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    memcpy(iv, EcbVector.nonce, sizeof(EcbVector.nonce));
    memset(out, 0, sizeof(out));

    /*#5*/
    result = pal_initAes(&ctx_dec);
    TEST_ASSERT_NOT_EQUAL(ctx_dec, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_setAesKey(ctx_dec, EcbVector.key, 128, PAL_KEY_TARGET_DECRYPTION);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    result = pal_aesECB(ctx_dec, EcbVector.output, out, PAL_AES_DECRYPT);
    TEST_ASSERT_EQUAL_MEMORY(EcbVector.input, out, sizeof(EcbVector.output));

    /*#8*/
    result = pal_freeAes(&ctx_dec);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
}


/**
 * @brief Testing AES encryption and decryption of buffers in CCM mode.
 *
 * The test encrypts a buffer, compares it against the desired result and then decrypts it back and compares with the original buffer.
 *
 * Uses aesCcmVectors.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize an AES CCM context.                                                         | PAL_SUCCESS |
 * | 2 | Set an AES 128bit key for this particular vector.                                      | PAL_SUCCESS |
 * | 3 | Perform AES CCM encryption on input vector and check the encryption output.            | PAL_SUCCESS |
 * | 4 | Perform AES CCM decryption on an input vector and check that the result is as expected.| PAL_SUCCESS |
 * | 5 | Release AES CCM context.                                                               | PAL_SUCCESS |
 */
TEST(pal_crypto, AES_CCM)
{
    palStatus_t result;
    palCCMHandle_t ctx = NULLPTR;

    unsigned char iv[16] = {0};
    unsigned char encryptBuffer[32] = {0};
    unsigned char decryptBuffer[32] = {0};


    for (size_t i = 0; i < sizeof(aesCcmVectors) / sizeof(palAesCcmVector_t); ++i)
    {
        memset(encryptBuffer, 0, sizeof(encryptBuffer));
        memset(decryptBuffer, 0, sizeof(decryptBuffer));
        memset(iv, 0, sizeof(iv));
        memcpy(iv, aesCcmVectors[i].iv, aesCcmVectors[i].ivLen);

        /*#1*/
        result = pal_CCMInit(&ctx);
        TEST_ASSERT_NOT_EQUAL(ctx, NULLPTR);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

        /*#2*/
        result = pal_CCMSetKey(ctx, aesCcmVectors[i].key, 128, PAL_CIPHER_ID_AES);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

        /*#3*/
        result = pal_CCMEncrypt(ctx, (unsigned char*)aesCcmVectors[i].in, aesCcmVectors[i].inLen,
                iv, aesCcmVectors[i].ivLen, (unsigned char*)aesCcmVectors[i].ad, aesCcmVectors[i].adLen,
                encryptBuffer, encryptBuffer + aesCcmVectors[i].inLen, aesCcmVectors[i].tagLen);

        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL_MEMORY(aesCcmVectors[i].out, encryptBuffer, aesCcmVectors[i].inLen + aesCcmVectors[i].tagLen);

        /*#4*/
        result = pal_CCMDecrypt(ctx, encryptBuffer, aesCcmVectors[i].inLen,
                iv, aesCcmVectors[i].ivLen, (unsigned char*)aesCcmVectors[i].ad, aesCcmVectors[i].adLen,
                encryptBuffer + aesCcmVectors[i].inLen,    aesCcmVectors[i].tagLen, decryptBuffer);

        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL_MEMORY(aesCcmVectors[i].in, decryptBuffer, aesCcmVectors[i].inLen);

        /*#5*/
        result = pal_CCMFree(&ctx);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }
}


/**
 * @brief Testing SHA256 hash algorithm.
 *
 * The test hashes a few buffers and compares them with a well known result using SHA256.
 *
 * Uses sha256Vectors.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Perform SHA256 hash on the input vector and check the resulting digest Small input Buffers.     | PAL_SUCCESS |
 * | 2 | Perform SHA256 hash on the input vector and check the resulting digest BIG input buffer.     | PAL_SUCCESS |
 */
TEST(pal_crypto, SHA256)
{
    palStatus_t result;
    unsigned char output[32];

    for (size_t i = 0; i < sizeof(sha256Vectors) / sizeof(palSha256Vector_t); ++i)
    {
        memset(output, 0x0, sizeof(output));
        /*#1*/
        result = pal_sha256(sha256Vectors[i].input, sha256Vectors[i].inLenInBytes, output);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

        TEST_ASSERT_EQUAL_MEMORY(sha256Vectors[i].output, output, sizeof(sha256Vectors[i].output));
    }

    	memset(output, 0x0, sizeof(output));
	/*#2*/
	result = pal_sha256(sha256Vectors_2nd.input, sha256Vectors_2nd.inLenInBytes, output);
	TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
	TEST_ASSERT_EQUAL_MEMORY(sha256Vectors_2nd.output, output, sizeof(sha256Vectors_2nd.output));

}


/**
 * @brief Testing message digest using SHA256 hash algorithm.
 *
 * The test calculates a message digest of the buffers and compares them against the expected results.
 *
 * Uses sha256Vectors.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize a message digest context.                                                       | PAL_SUCCESS |
 * | 2 | Perform `pal_mdUpdate` on vector input data and check the status.                          | PAL_SUCCESS |
 * | 3 | Get the output size using `pal_mdGetOutputSize` and check the result.                      | PAL_SUCCESS |
 * | 4 | Get the digest result using `pal_mdFinal` and check its value.                             | PAL_SUCCESS |
 * | 5 | Release message digest context.                                                            | PAL_SUCCESS |
 * | 6 | Initialize a message digest context. with Big input buffer                                 | PAL_SUCCESS |
 * | 7 | Perform `pal_mdUpdate` on vector input data and check the status.  with Big input buffer   | PAL_SUCCESS |
 * | 8 | Get the output size using `pal_mdGetOutputSize` and check the result. with Big input buffer| PAL_SUCCESS |
 * | 9 | Get the digest result using `pal_mdFinal` and check its value. with Big input buffer 		| PAL_SUCCESS |
 * | 10 | Release message digest context. with Big input buffer                                     | PAL_SUCCESS |
 */
TEST(pal_crypto, md)
{
    palStatus_t result;
    palMDHandle_t handle = NULLPTR;
    size_t bufferSize = 0;
    uint8_t output[32] = {0};

    for (size_t i = 0; i < sizeof(sha256Vectors) / sizeof(palSha256Vector_t); ++i)
    {
    	memset(output, 0x0, sizeof(output));
        /*#1*/
        result = pal_mdInit(&handle, PAL_SHA256);
        TEST_ASSERT_NOT_EQUAL(handle, NULLPTR);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

        /*#2*/
        result = pal_mdUpdate(handle, sha256Vectors[i].input, sha256Vectors[i].inLenInBytes);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

        /*#3*/
        result = pal_mdGetOutputSize(handle, &bufferSize);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL_HEX(sha256Vectors[i].outLenInBytes, bufferSize);

        /*#4*/
        result = pal_mdFinal(handle, output);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL_MEMORY(sha256Vectors[i].output, output, sizeof(sha256Vectors[i].output));

        /*#5*/
        result = pal_mdFree(&handle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }

    memset(output, 0x0, sizeof(output));
    /*#6*/
    result = pal_mdInit(&handle, PAL_SHA256);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    result = pal_mdUpdate(handle, sha256Vectors_2nd.input, sha256Vectors_2nd.inLenInBytes);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#8*/
    result = pal_mdGetOutputSize(handle, &bufferSize);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(sha256Vectors_2nd.outLenInBytes, bufferSize);

    /*#9*/
    result = pal_mdFinal(handle, output);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_MEMORY(sha256Vectors_2nd.output, output, sizeof(sha256Vectors_2nd.output));

    /*#10*/
    result = pal_mdFree(&handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
}


/**
 * @brief Testing random number generation using deterministic random bit generators.
 *
 * The test generates a 128 bit number for 100 times and checks that there are no similar keys.
 *
 * Uses `ctr_drbg_buf` and `ctr_drbg_nonce_pers`.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize a CTR DRBG context.                                                          | PAL_SUCCESS |
 * | 2 | Generate 100 128bit random values using `pal_CtrDRBGGenerate`.                          | PAL_SUCCESS |
 * | 3 | Release message CTR DRBG context.                                                       | PAL_SUCCESS |
 * | 4 | Check that all generated numbers are different.                                         | PAL_SUCCESS |
 */
TEST(pal_crypto, CTR_DRBG)
{
    palStatus_t result;
    palCtrDrbgCtxHandle_t ctx = NULLPTR;

    memset(ctr_drbg_buf, 0x0, sizeof(ctr_drbg_buf));

    /*#1*/
    result = pal_CtrDRBGInit(&ctx,ctr_drbg_nonce_pers, sizeof(ctr_drbg_nonce_pers));
    TEST_ASSERT_NOT_EQUAL(ctx, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    for (int i = 0; i < 100; ++i) {
        result = pal_CtrDRBGGenerate(ctx, ctr_drbg_buf[i], sizeof(ctr_drbg_buf[i]));
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }

    /*#3*/
    result = pal_CtrDRBGFree(&ctx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#4*/
    for (int i = 0; i < 99; ++i) {
        for (int j = i + 1; j < 100; ++j) {
            TEST_ASSERT_NOT_EQUAL(0, memcmp(ctr_drbg_buf[i], ctr_drbg_buf[j], sizeof(ctr_drbg_buf[i])));
        }
    }
}


/**
 * @brief Testing CMAC operation on a buffer with one operation.
 *
 * The test signs a buffer using CMAC and compares with the expected result buffer.
 *
 * Uses cmacSingleUseVector.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Perform CMAC using `pal_cipherCMAC` and check the result.                                    | PAL_SUCCESS |
 * | 2 | Check the CMAC output against the test vector.                                               | PAL_SUCCESS |
 */
TEST(pal_crypto, CMAC_one_shot)
{
    palStatus_t result;
    unsigned char output[16] = {0};

    for (size_t i = 0; i < sizeof(cmacSingleUseVector) / sizeof(palAesCMACVector_t); ++i){
        memset(output, 0x0, sizeof(output));
        /*#1*/
        result = pal_cipherCMAC(cmacSingleUseVector[i].key, 128, cmacSingleUseVector[i].in, cmacSingleUseVector[i].inLen, output);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#2*/
        TEST_ASSERT_EQUAL_MEMORY(cmacSingleUseVector[i].out, output, sizeof(cmacSingleUseVector[i].out));
    }
}

/**
 * @brief Testing CMAC operation on a buffer with multiple operations and blocks.
 *
 * The test signs a buffer using CMAC multiple times and compares with the expected result buffer.
 *
 * Uses cmacIterativeUseVector.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize CMAC context using `pal_CMACStart`.                                           | PAL_SUCCESS |
 * | 2 | Add a block of data from test vector for CMAC processing using `pal_CMACFinish`.         | PAL_SUCCESS |
 * | 3 | Add a block of data from test vector for CMAC processing using `pal_CMACFinish`.         | PAL_SUCCESS |
 * | 4 | Add a block of data from test vector for CMAC processing using `pal_CMACFinish`.         | PAL_SUCCESS |
 * | 5 | Add a block of data from test vector for CMAC processing using `pal_CMACFinish`.         | PAL_SUCCESS |
 * | 6 | Get CMAC output using `pal_CMACFinish` and check the result.                             | PAL_SUCCESS |
 */
TEST(pal_crypto, CMAC_Iterative)
{
    palStatus_t result;
    palCMACHandle_t ctx = NULLPTR;
    unsigned char output[64] = {0};
    size_t resultLen = 0;

    for (size_t i = 0; i < sizeof(cmacIterativeUseVector) / sizeof(palCMACMultipleBlockVector_t); ++i)
    {
        memset(output, 0x0, sizeof(output));
        /*#1*/
        result = pal_CMACStart(&ctx,cmacIterativeUseVector[i].key_string, cmacIterativeUseVector[i].keybits, cmacIterativeUseVector[i].cipher_type);
        TEST_ASSERT_NOT_EQUAL(ctx, NULLPTR);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#2*/
        if (cmacIterativeUseVector[i].block1_len >= 0) {
            result = pal_CMACUpdate(ctx, cmacIterativeUseVector[i].block1_string, cmacIterativeUseVector[i].block1_len);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
        /*#3*/
        if (cmacIterativeUseVector[i].block2_len >= 0) {
            result = pal_CMACUpdate(ctx, cmacIterativeUseVector[i].block2_string, cmacIterativeUseVector[i].block2_len);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
        /*#4*/
        if (cmacIterativeUseVector[i].block3_len >= 0) {
            result = pal_CMACUpdate(ctx, cmacIterativeUseVector[i].block3_string, cmacIterativeUseVector[i].block3_len);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
        /*#5*/
        if (cmacIterativeUseVector[i].block4_len >= 0) {
            result = pal_CMACUpdate(ctx, cmacIterativeUseVector[i].block4_string, cmacIterativeUseVector[i].block4_len);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
        /*#6*/
        result = pal_CMACFinish(&ctx, output, &resultLen);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL_HEX(cmacIterativeUseVector[i].block_size, resultLen);
        TEST_ASSERT_EQUAL_MEMORY(cmacIterativeUseVector[i].expected_result_string, output, cmacIterativeUseVector[i].block_size);
    } // for ends
}

/**
 * @brief Testing HMAC operation on a buffer with one operation.
 *
 * The test signs a buffer using HMAC and compares with the expected result buffer.
 *
 * Uses mdHMACVector.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Perform one shot SHA256 HMAC on input vector using `pal_mdHmacSha256` and check the result. | PAL_SUCCESS |
 */
TEST(pal_crypto, HMAC_SHA256_one_shot)
{
    palStatus_t result;
    unsigned char output[32] = {0};

    for (size_t i = 0; i < sizeof(mdHMACVector) / sizeof(palMdHMACTestVector_t); ++i){
        memset(output, 0x0, sizeof(output));
        /*#1*/
        result = pal_mdHmacSha256(mdHMACVector[i].key, mdHMACVector[i].keyLen, mdHMACVector[i].input,    mdHMACVector[i].inputLen, output, NULL);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL_MEMORY(mdHMACVector[i].output, output, mdHMACVector[i].outputLen);
    }
}

/**
 * @brief Searching for ASN1 patterns in a DER certificate.
 *
 * The test extracts ASN1 tags from an existing DER format certificate and validates their types.
 *
 * Uses ASN1TestVector for coordinates and `asn1_data` as the dummy certificate buffer.
 *
 * For each vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Get data for an ASN tag using `pal_ASN1GetTag`.                                              | PAL_SUCCESS |
 * | 2 | Check if the result is success and the size tag size is correct.                             | PAL_SUCCESS |
 */
TEST(pal_crypto, ASN1)
{
    palStatus_t result;
    size_t s = 0;
    unsigned char* start = NULL;
    const unsigned char* end = NULL;

    for (size_t i = 0; i < sizeof(ASN1TestVector) / sizeof(palASN1TestVector_t); ++i) {
        start = (unsigned char*)(asn1_data + ASN1TestVector[i].start);
        end = asn1_data + ASN1TestVector[i].end;
        /*#1*/
        result = pal_ASN1GetTag(&start, end, &s, ASN1TestVector[i].type);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#2*/
        TEST_ASSERT_EQUAL(ASN1TestVector[i].dataLen, s);
    }
}

/**
 * @brief Test the parsing of a dummy X509 certificate.
 *
 * uses x509_cert
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize the X509 ceritifcate context using `pal_x509Initiate`.                            | PAL_SUCCESS |
 * | 2 | Parse a valid x509 certificate using `pal_x509CertParse`.                                    | PAL_SUCCESS |
 * | 3 | Parse an invalid x509 certificate using `pal_x509CertParse`.                                 | PAL_ERR_CERT_PARSING_FAILED |
 * | 4 | Parse an invalid x509 certificate using `pal_x509CertParse`.                                 | PAL_ERR_INVALID_MD_TYPE |
 * | 5 | Parse an invalid x509 certificate using `pal_x509CertParse`.                                 | PAL_ERR_NOT_SUPPORTED_CURVE |
 * | 6 | Release x509 certificate context.                                                            | PAL_SUCCESS |
 */
TEST(pal_crypto, X509_Parse)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t result;
    palX509Handle_t ctx = NULLPTR;
    /*#1*/
    result = pal_x509Initiate(&ctx);
    TEST_ASSERT_NOT_EQUAL(ctx, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#2*/
    result = pal_x509CertParse(ctx, x509_TI, sizeof(x509_TI));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#3*/
    result = pal_x509CertParse(ctx, x509_TI_PEM, sizeof(x509_TI_PEM));
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_CERT_PARSING_FAILED, result);
    /*#4*/
    result = pal_x509CertParse(ctx, (unsigned char*)testdata_x509_Sha512, sizeof(testdata_x509_Sha512));
    // If SHA512 is supported by the application/platform, we don't want tests (#4 and #5) to fail because of that.
    // Perhaps the test material should be changed to use less recent/used algorithm to get the PAL_ERR_INVALID_MD_TYPE
    // path executed.
#if defined (MBEDTLS_SHA512_C)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
#else
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_MD_TYPE, result);
#endif
    /*#5*/
    result = pal_x509CertParse(ctx, (unsigned char*)testdata_x509_Curve512r1, sizeof(testdata_x509_Curve512r1));
#if defined (MBEDTLS_SHA512_C)
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
#else
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_NOT_SUPPORTED_CURVE, result);
#endif
    /*#6*/
    result = pal_x509Free(&ctx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
#endif
}

/**
 * @brief Test the reading of specific attributes in an X509 certificate.
 *
 * The test parses a X509 certificate and extracts specific attributes and compare them against the expected result.
 *
 * Uses `x509_cert` and `cert_not_self_signed`.
 *
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize the X509 ceritifcate context using `pal_x509Initiate`.                            | PAL_SUCCESS |
 * | 2 | Parse a valid x509 certificate using `pal_x509CertParse`.                                    | PAL_SUCCESS |
 * | 3 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 4 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 5 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 6 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 7 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 8 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 9 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.           | PAL_SUCCESS |
 * | 10 | Release x509 certificate context using `pal_x509Free`.                                       | PAL_SUCCESS |
 * | 11 | Initialize X509 ceritifcate context using `pal_x509Initiate`.                                | PAL_SUCCESS |
 * | 12 | Parse a valid x509 certificate using `pal_x509CertParse`.                                   | PAL_SUCCESS |
 * | 13 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.          | PAL_SUCCESS |
 * | 14 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.          | PAL_SUCCESS |
 * | 15 | Get the certificate attribute value using `pal_x509CertGetAttribute `and check it.          | PAL_SUCCESS |
 * | 16 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.          | PAL_SUCCESS |
 * | 17 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.          | PAL_SUCCESS |
 * | 18 | Get the certificate attribute value with a too small buffer.                                | PAL_ERR_BUFFER_TOO_SMALL |
 * | 19 | Get the certificate attribute value using `pal_x509CertGetAttribute` and check it.          | PAL_SUCCESS |
 * | 20 | Release x509 certificate context using `pal_x509Free`.                                      | PAL_SUCCESS |
 */
TEST(pal_crypto, X509_ReadAttributes)
{

#if (PAL_ENABLE_X509 == 1)
    palStatus_t result;
    palX509Handle_t ctx = NULLPTR;
    char buffer1[512] = {0};
    char validationBuf[12] = {0};
    uint8_t certID1[PAL_CERT_ID_SIZE] = {0};
    uint8_t certID2[PAL_CERT_ID_SIZE] = {0};
    time_t validFrom = 0;
    time_t validTo = 0;
    time_t tmpTime;
    size_t actualOutLen = 0;

    /*#1*/
    result = pal_x509Initiate(&ctx);
    TEST_ASSERT_NOT_EQUAL(ctx, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#2*/
    result = pal_x509CertParse(ctx, x509_TI, sizeof(x509_TI));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#3*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_ISSUER_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memset(buffer1, 0, sizeof(buffer1));
    /*#4*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_SUBJECT_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memset(buffer1, 0, sizeof(buffer1));
    /*#5*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_VALID_FROM, validationBuf, sizeof(validationBuf), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memcpy(&tmpTime, validationBuf, sizeof(tmpTime));
    memset(validationBuf, 0, sizeof(validationBuf));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#6*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_CN_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_STRING("IOT_PAL", buffer1);
    memset(buffer1, 0, sizeof(buffer1));
    /*#7*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_L_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memset(buffer1, 0, sizeof(buffer1));
    /*#8*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_OU_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_STRING("IOTBU", buffer1);
    memset(buffer1, 0, sizeof(buffer1));
    /*#9*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_CERT_ID_ATTR, certID1, sizeof(certID1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    result = pal_x509CertGetAttribute(ctx, PAL_X509_CERT_ID_ATTR, certID2, sizeof(certID2), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_MEMORY(certID1, certID2, sizeof(certID1));
    memset(certID1, 0, sizeof(certID1));
    memset(certID2, 0, sizeof(certID2));
    /*#10*/
    result = pal_x509Free(&ctx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#11*/
    result = pal_x509Initiate(&ctx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#12*/
    result = pal_x509CertParse(ctx, cert_not_self_signed, sizeof(cert_not_self_signed));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#13*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_ISSUER_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memset(buffer1, 0, sizeof(buffer1));
    /*#14*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_SUBJECT_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memset(buffer1, 0, sizeof(buffer1));
    /*#15*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_CN_ATTR, buffer1, sizeof(buffer1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_STRING("IOT_TEST", buffer1);
    memset(buffer1, 0, sizeof(buffer1));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#16*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_VALID_FROM, validationBuf, sizeof(validationBuf), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memcpy(&validFrom, validationBuf, sizeof(tmpTime));
    memset(validationBuf, 0, sizeof(validationBuf));
    /*#17*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_VALID_TO, validationBuf, sizeof(validationBuf), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    memcpy(&validTo, validationBuf, sizeof(tmpTime));
    memset(validationBuf, 0, sizeof(validationBuf));
    
    //Check exact time period
    TEST_ASSERT_EQUAL_HEX(0x05a39a7f, validTo - validFrom);
    /*#18*/
    //! sending small buffer size to check error value scenario
    result = pal_x509CertGetAttribute(ctx, PAL_X509_VALID_TO, validationBuf, 1, &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_BUFFER_TOO_SMALL, result);
    TEST_ASSERT_EQUAL(sizeof(uint64_t), actualOutLen);
    /*#19*/
    result = pal_x509CertGetAttribute(ctx, PAL_X509_CERT_ID_ATTR, certID1, sizeof(certID1), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    result = pal_x509CertGetAttribute(ctx, PAL_X509_CERT_ID_ATTR, certID2, sizeof(certID2), &actualOutLen);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_MEMORY(certID1, certID2, sizeof(certID1));
    memset(certID1, 0, sizeof(certID1));
    memset(certID2, 0, sizeof(certID2));

    /*#20*/
    result = pal_x509Free(&ctx);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
#endif
}
    
/**
 * @brief Test the validity of a X509 certificate.
 *
 * Reads a X509 certificate, specific attributes such as `PAL_X509_VALID_FROM` and `PAL_X509_VALID_TO`
 * and validates with `pal_x509CertVerify`.
 *
 * Uses `x509_verify_data`.
 *
 For each test vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | If the CA cert is part of vector, initialize X509 certificate context using `pal_x509Initiate`. | PAL_SUCCESS |
 * | 2 | If the CA cert is part of vector, parse a valid x509 certificate using `pal_x509CertParse`.     | PAL_SUCCESS |
 * | 3 | Initialize X509 certificate context using `pal_x509Initiate`.                                   | PAL_SUCCESS |
 * | 4 | Parse a valid x509 certificate using `pal_x509CertParse`.                                       | PAL_SUCCESS |
 * | 5 | Verify the certificate using `pal_x509CertVerify`.                                              | PAL_SUCCESS |
 * | 6 | Release X509 certificate context.                                                               | PAL_SUCCESS |
 * | 7 | If the CA cert is part of vector, release X509 certificate context.                             | PAL_SUCCESS |
 */
TEST(pal_crypto, X509_Verify)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t result = PAL_SUCCESS;
    palX509Handle_t cert = NULLPTR;
    palX509Handle_t caCert = NULLPTR;
    int32_t verifyResult = 0;

    for (size_t i = 0; i < sizeof(x509_verify_data) / sizeof(palX509VertifyTestVector_t); ++i) 
    {
        if (x509_verify_data[i].ca != NULL)
        {
            /*#1*/
            result = pal_x509Initiate(&caCert);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
            TEST_ASSERT_NOT_EQUAL(caCert, NULLPTR);
            /*#2*/
            result = pal_x509CertParse(caCert, x509_verify_data[i].ca, x509_verify_data[i].ca_size);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }

        /*#3*/
        result = pal_x509Initiate(&cert);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#4*/
        result = pal_x509CertParse(cert, x509_verify_data[i].crt, x509_verify_data[i].crt_size);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#5*/
        result = pal_x509CertVerifyExtended(cert, caCert, &verifyResult);
        if (PAL_ERR_X509_CERT_VERIFY_FAILED == result)
        {
            TEST_ASSERT_TRUE((x509_verify_data[i].result & verifyResult));
        }
        else
        {
            TEST_ASSERT_EQUAL_HEX(x509_verify_data[i].result, result);   
        }
        /*#6*/
        result = pal_x509Free(&cert);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        if (x509_verify_data[i].ca != NULL)
        {
            /*#7*/
            result = pal_x509Free(&caCert);
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
    }
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
#endif
}

/**
* @brief Test the validity of a certain usage against the extended-key-usage V3 extension of a given X509 certificate.
*
* Reads a X509 certificate, specific usage such as `PAL_X509_EXT_KU_CLIENT_AUTH` and `PAL_X509_EXT_KU_OCSP_SIGNING`
* and validates with `pal_x509CertCheckExtendedKeyUsage`.
*
* Uses `x509_ca_with_extended_key_usage`.
*
For each test vector:
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize X509 certificate context using `pal_x509Initiate`.                                               | PAL_SUCCESS |
* | 2 | Parse a valid x509 certificate using `pal_x509CertParse`.                                                   | PAL_SUCCESS |
* | 3 | Check the usage against the extended-key-usage V3 extension using `pal_x509CertCheckExtendedKeyUsage`.      | PAL_SUCCESS |
* | 4 | Release X509 certificate context.                                                                           | PAL_SUCCESS |
*/
TEST(pal_crypto, X509_VerifyExtendedKeyUsage)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t result = PAL_SUCCESS;
    palX509Handle_t caCert = NULLPTR;

    /*#1*/
    result = pal_x509Initiate(&caCert);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_NOT_EQUAL(caCert, NULLPTR);
    /*#2*/
    result = pal_x509CertParse(caCert, x509_ca_with_extended_key_usage, sizeof(x509_ca_with_extended_key_usage));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    /*#3*/
    result = pal_x509CertCheckExtendedKeyUsage(caCert, PAL_X509_EXT_KU_CLIENT_AUTH);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    result = pal_x509CertCheckExtendedKeyUsage(caCert, PAL_X509_EXT_KU_OCSP_SIGNING);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_CERT_CHECK_EXTENDED_KEY_USAGE_FAILED, result);
    /*#4*/
    result = pal_x509Free(&caCert);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
#endif
}

/**
 * @brief Test the parsing of elliptic-curves keys (public and private).
 *
 * Uses `parse_ec_key_data`.
 *
 * For each test vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize a new ECC key using `pal_ECKeyNew`.                                                                      | PAL_SUCCESS |
 * | 2 | If private key, parse using `pal_parseECPrivateKeyFromDER`, otherwise parse using `pal_parseECPublicKeyFromDER`.    | PAL_SUCCESS |
 * | 3 | Check the parsing status according to the test vector.                                                              | PAL_SUCCESS |
 * | 4 | Release the ECC key using `pal_ECKeyFree`.                                                                          | PAL_SUCCESS |
 */
TEST(pal_crypto, ECKey_parseKey)
{
    palStatus_t result;
    palECKeyHandle_t handle = NULLPTR;

    for (uint32_t i = 0; i < sizeof(parse_ec_key_data) / sizeof(palParseECKeyTestVector_t) ; ++i) {
        /*#1*/
        result = pal_ECKeyNew(&handle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#2*/
        switch (parse_ec_key_data[i].type) {
            case PAL_CHECK_PRIVATE_KEY:
                result = pal_parseECPrivateKeyFromDER(parse_ec_key_data[i].key, parse_ec_key_data[i].len, handle);
                break;
            case PAL_CHECK_PUBLIC_KEY:
                result = pal_parseECPublicKeyFromDER(parse_ec_key_data[i].key, parse_ec_key_data[i].len, handle);
                break;
            default:
                TEST_FAIL();
        }
        /*#3*/
        if (parse_ec_key_data[i].shouldSucceed)
        {
            TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        }
        else
        {
            TEST_ASSERT_NOT_EQUAL(PAL_SUCCESS, result);
        }
        /*#4*/
        result = pal_ECKeyFree(&handle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }
}

/**
 * @brief Test the validity of elliptic-curves keys (public and private).
 *
 * Uses `check_ec_key_data`.
 *
 * For each test vector:
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize and load EC curve using `pal_ECGroupInitAndLoad`.                                                         | PAL_SUCCESS |
 * | 2 | Initialize a new ECC key using `pal_ECKeyNew`.                                                                       | PAL_SUCCESS |
 * | 3 | If private key, parse using `pal_parseECPrivateKeyFromDER` and check the parsing status according to the test vector.| PAL_SUCCESS |
 * | 4 | If successfully parsed, check the key using `pal_ECCheckKey`.                                                        | PAL_SUCCESS |
 * | 5 | Release the ECC key using `pal_ECKeyFree`.                                                                           | PAL_SUCCESS |
 * | 6 | Initialize a new ECC key using `pal_ECKeyNew`.                                                                       | PAL_SUCCESS |
 * | 7 | If public key, parse using `pal_parseECPublicKeyFromDER` and check the parsing status according to test the vector.  | PAL_SUCCESS |
 * | 8 | If successfully parsed, check the key using `pal_ECCheckKey`.                                                        | PAL_SUCCESS |
 * | 9 | Release the ECC key using `pal_ECKeyFree`.                                                                           | PAL_SUCCESS |
 * | 10 | Release the EC curve using `pal_ECGroupFree`.                                                                       | PAL_SUCCESS |
 */
TEST(pal_crypto, ECKey_checkKey)
{
    palStatus_t result;
    palCurveHandle_t grp = NULLPTR;
    bool verified = false;
    palECKeyHandle_t key = NULLPTR;

    for (uint32_t i = 0; i < sizeof(check_ec_key_data) / sizeof(palCheckEcKeyTestVector_t); ++i)
    {
        /*#1*/
        result = pal_ECGroupInitAndLoad(&grp, check_ec_key_data[i].index);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#2*/
        result = pal_ECKeyNew(&key);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#3*/
        result = pal_parseECPrivateKeyFromDER(check_ec_key_data[i].key, check_ec_key_data[i].keyLen, key);
        TEST_ASSERT_EQUAL_HEX(check_ec_key_data[i].parsePrvRes, result);
        if (PAL_SUCCESS == result)
        {
            /*#4*/
            result = pal_ECCheckKey(grp, key, PAL_CHECK_PRIVATE_KEY, &verified);
            TEST_ASSERT_EQUAL(check_ec_key_data[i].checkPrvRes, result);
            TEST_ASSERT_EQUAL(check_ec_key_data[i].verifed, verified);
        }

        /*#5*/
        result = pal_ECKeyFree(&key);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#6*/
        result = pal_ECKeyNew(&key);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#7*/
        result = pal_parseECPublicKeyFromDER(check_ec_key_data[i].key, check_ec_key_data[i].keyLen, key);
        TEST_ASSERT_EQUAL_HEX(check_ec_key_data[i].parsePubRes, result);
        if (PAL_SUCCESS == result)
        {
            /*#8*/
            result = pal_ECCheckKey(grp, key, PAL_CHECK_PUBLIC_KEY, &verified);
            TEST_ASSERT_EQUAL(check_ec_key_data[i].checkPubRes, result);
            TEST_ASSERT_EQUAL(check_ec_key_data[i].verifed, verified);
        }
        /*#9*/
        result = pal_ECKeyFree(&key);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#10*/
        result = pal_ECGroupFree(&grp);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }
}

/**
 * @brief Create a CSR from an elliptic-curve key and assure its validity.
 *
 * Uses CsrTests.
 *
 * For each test vector (steps 1A-1O are run for each tect vector):
 * | # |    Step                        |   Expected  |
 * |---|--------------------------------|-------------|
 * | 1 | Initialize and load the EC curve using `pal_ECGroupInitAndLoad`.                                                     | PAL_SUCCESS |
 * | 1A | Initialize a new ECC key using `pal_ECKeyNew`.                                                                      | PAL_SUCCESS |
 * | 1B | Parse using `pal_parseECPrivateKeyFromDER` and check the parsing status according to the test vector.               | PAL_SUCCESS |
 * | 1C | Check the key using `pal_ECCheckKey`.                                                                               | PAL_SUCCESS |
 * | 1D | Initialize a new ECC key using `pal_ECKeyNew`.                                                                      | PAL_SUCCESS |
 * | 1E | Parse using `pal_parseECPublicKeyFromDER` and check the parsing status according to the test vector.                | PAL_SUCCESS |
 * | 1F | Check the key using `pal_ECCheckKey`.                                                                               | PAL_SUCCESS |
 * | 1G | Initialize the x509 certificate context using `pal_x509CSRInit`.                                                    | PAL_SUCCESS |
 * | 1H  | Set the cert subject using `pal_x509CSRSetSubject`.                                                                | PAL_SUCCESS |
 * | 1I  | Set the cert MD using `pal_x509CSRSetMD`.                                                                          | PAL_SUCCESS |
 * | 1J  | Set the cert keys using `pal_x509CSRSetKey`.                                                                       | PAL_SUCCESS |
 * | 1K  | Set the cert key usage using `pal_x509CSRSetKey`.                                                                  | PAL_SUCCESS |
 * | 1L  | Write the certificate to DER file using `pal_x509CSRWriteDER`.                                                     | PAL_SUCCESS |
 * | 1M  | Release the x509 ceritifcate context using `pal_x509CSRFree`.                                                      | PAL_SUCCESS |
 * | 1N  | Release the ECC key using `pal_ECKeyFree`.                                                                         | PAL_SUCCESS |
 * | 1O  | Release the ECC key using `pal_ECKeyFree`.                                                                         | PAL_SUCCESS |
 * | 2 | Release the EC curve using `pal_ECGroupFree`.                                                                        | PAL_SUCCESS |
 */
TEST(pal_crypto, CSR)
{

#if (PAL_ENABLE_X509 == 1)
    palStatus_t result;
    palECKeyHandle_t prvKeyHandle = NULLPTR, pubKeyHandle = NULLPTR;
    unsigned char outDer[1000] = {0};
    size_t reqLen;
    palx509CSRHandle_t CSRHandle = NULLPTR;

    bool goodKey = false;
    palCurveHandle_t grp = NULLPTR;
    palGroupIndex_t index = PAL_ECP_DP_SECP256R1;
    /*#1*/
    result = pal_ECGroupInitAndLoad(&grp, index);
    TEST_ASSERT_NOT_EQUAL(grp, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    for (uint32_t i = 0; i < sizeof(CsrTests) / sizeof(palX509CSRTestVector_t); ++i)
    {
        memset(outDer,0, sizeof(outDer));

        goodKey = false;
        /*#1A*/
        result = pal_ECKeyNew(&prvKeyHandle);
        TEST_ASSERT_NOT_EQUAL(prvKeyHandle, NULLPTR);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1B*/
        result = pal_parseECPrivateKeyFromDER(CsrTests[i].prvkey, CsrTests[i].prvkeyLen, prvKeyHandle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1C*/
        result = pal_ECCheckKey(grp, prvKeyHandle, PAL_CHECK_PRIVATE_KEY, &goodKey);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL(true, goodKey);

        goodKey = false;
        /*#1D*/
        result = pal_ECKeyNew(&pubKeyHandle);
        TEST_ASSERT_NOT_EQUAL(pubKeyHandle, NULLPTR);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1E*/
        result = pal_parseECPublicKeyFromDER(CsrTests[i].pubkey, CsrTests[i].pubkeyLen, pubKeyHandle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1F*/
        result = pal_ECCheckKey(grp, pubKeyHandle, PAL_CHECK_PUBLIC_KEY, &goodKey);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        TEST_ASSERT_EQUAL(true, goodKey);
        /*#1G*/
        result = pal_x509CSRInit(&CSRHandle);
        TEST_ASSERT_NOT_EQUAL(CSRHandle, NULLPTR);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1H*/
        result = pal_x509CSRSetSubject(CSRHandle, CsrTests[i].subject_name);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1I*/
        result = pal_x509CSRSetMD(CSRHandle, CsrTests[i].mdType);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1J*/
        result = pal_x509CSRSetKey(CSRHandle, pubKeyHandle, prvKeyHandle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1K*/
        result = pal_x509CSRSetKeyUsage(CSRHandle, CsrTests[i].keyUsage);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1L*/
        //pal_x509CSRSetExtension - need input from provisioning
        reqLen = 0;
        result = pal_x509CSRWriteDER(CSRHandle, outDer, sizeof(outDer), &reqLen);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

        TEST_ASSERT_EQUAL(CsrTests[i].derOutLen, reqLen);
        TEST_ASSERT_EQUAL_MEMORY(CsrTests[i].derOut, outDer, reqLen);
        /*#1M*/
        result = pal_x509CSRFree(&CSRHandle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1N*/
        result = pal_ECKeyFree(&prvKeyHandle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
        /*#1O*/
        result = pal_ECKeyFree(&pubKeyHandle);
        TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    }
    /*#2*/
    result = pal_ECGroupFree(&grp);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
#endif
}

#define PAL_CRYPTO_TEST_MAX_ECDSA_LEN 74

/**
* @brief Test hash function of the TBS of an X509 and its verification
*
* Uses `x509_verify_ca` and `x509_verify_cert`.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Instantiate X509 handles using `pal_x509Initiate`.                                                                   | PAL_SUCCESS |
* | 2 | Parse signer and signee X509 certificates into handles using `pal_x509CertParse`.                                    | PAL_SUCCESS |
* | 3 | Hash the TBS of the signee using `pal_x509CertGetHTBS`.                                                              | PAL_SUCCESS |
* | 4 | Acquire the signature from the signee using `pal_x509CertGetAttribute` with PAL_X509_SIGNATUR_ATTR flag.             | PAL_SUCCESS |
* | 5 | Verify the hash signed by the CA in the signature of signee equals the hash of the TBS using `pal_verifySignature`.  | PAL_SUCCESS |
* | 6 | Verify the signature with the public key of the signee instead of the signer, using `pal_verifySignature` and fail.  | PAL_ERR_PK_SIG_VERIFY_FAILED |
* | 7 | Release the two X509 handles using `pal_x509Free`.                                                                   | PAL_SUCCESS |
*/
TEST(pal_crypto, X509_tbs_hash)
{
#if (PAL_ENABLE_X509 == 1)
    palStatus_t status;
    unsigned char digest[PAL_SHA256_SIZE] = { 0 };
    unsigned char sig[PAL_CRYPTO_TEST_MAX_ECDSA_LEN] = { 0 };
    size_t sig_len;
    size_t digest_len;
    palX509Handle_t signee = NULLPTR;
    palX509Handle_t signer = NULLPTR;

    /*#1*/
    status = pal_x509Initiate(&signee);
    TEST_ASSERT_NOT_EQUAL(signee, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_x509Initiate(&signer);
    TEST_ASSERT_NOT_EQUAL(signer, NULLPTR);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#2*/
    status = pal_x509CertParse(signee, x509_verify_cert, sizeof(x509_verify_cert));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    status = pal_x509CertParse(signer, x509_verify_ca, sizeof(x509_verify_ca));
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#3*/
#ifdef DEBUG
    // Check invalid arguments
    status = pal_x509CertGetHTBS(NULLPTR, PAL_SHA256, digest, sizeof(digest), &digest_len);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_x509CertGetHTBS(signee, PAL_SHA256, NULL, sizeof(digest), &digest_len);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
    status = pal_x509CertGetHTBS(signee, PAL_SHA256, digest, sizeof(digest), NULL);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, status);
#endif
    // Check with small buffer
    status = pal_x509CertGetHTBS(signee, PAL_SHA256, digest, sizeof(digest) - 1, &digest_len);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_BUFFER_TOO_SMALL, status);

    status = pal_x509CertGetHTBS(signee, PAL_SHA256, digest, sizeof(digest), &digest_len);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
    TEST_ASSERT_EQUAL_HEX(PAL_SHA256_SIZE, digest_len);
    
    /*#4*/
    status = pal_x509CertGetAttribute(signee, PAL_X509_SIGNATUR_ATTR, sig, sizeof(sig), &sig_len);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#5*/
    status = pal_verifySignature(signer, PAL_SHA256, digest, digest_len, sig, sig_len);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    /*#6*/
    status = pal_verifySignature(signee, PAL_SHA256, digest, PAL_SHA256_SIZE, sig, sig_len);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_PK_SIG_VERIFY_FAILED, status);

    /*#7*/
    status = pal_x509Free(&signee);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);

    status = pal_x509Free(&signer);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, status);
#else
    TEST_IGNORE_MESSAGE("Ignored, PAL_ENABLE_X509 not set");
#endif
}

/**
* @brief Test the generation of elliptic-curves keys (public and private).
*
* Uses `pal_ECKeyGenerateKey`.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Initialize a new EC key using `pal_ECKeyNew`.                                                                      | PAL_SUCCESS |
* | 2 | Generate EC keys using `pal_ECKeyGenerateKey`.                                                                     | PAL_SUCCESS |
* | 3 | Initialize and load EC group using `pal_ECGroupInitAndLoad`.                                                       | PAL_SUCCESS |
* | 4 | Check both generated keys using `pal_ECCheckKey`.                                                                  | PAL_SUCCESS |
* | 5 | Compute signature for digest with private key using `pal_ECDSASign`.                                               | PAL_SUCCESS |
* | 6 | Verify signature with public key using `pal_ECDSAVerify`.                                                          | PAL_SUCCESS |
* | 7 | Release the EC group using `pal_ECGroupFree`.                                                                      | PAL_SUCCESS |
* | 8 | Release the EC key using `pal_ECKeyFree`.                                                                          | PAL_SUCCESS |
*/
TEST(pal_crypto, ECKey_GenerateKeys)
{
    palStatus_t result;
    palECKeyHandle_t key_handle = NULLPTR;
    palGroupIndex_t grpID = PAL_ECP_DP_SECP256R1;
    palCurveHandle_t grp_handle = NULLPTR;
    bool verified = false;
    unsigned char hash_digest[] =
    { 0x34, 0x70, 0xCD, 0x54, 0x7B, 0x0A, 0x11, 0x5F, 0xE0, 0x5C, 0xEB, 0xBC, 0x07, 0xBA, 0x91, 0x88,
        0x27, 0x20, 0x25, 0x6B, 0xB2, 0x7A, 0x66, 0x89, 0x1A, 0x4B, 0xB7, 0x17, 0x11, 0x04, 0x86, 0x6F };
    unsigned char signature[74] = { 0 };
    size_t act_size_of_sign = sizeof(signature);

    /*#1*/
    result = pal_ECKeyNew(&key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_ECKeyGenerateKey(grpID, key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_ECGroupInitAndLoad(&grp_handle, grpID);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#4*/
    result = pal_ECCheckKey(grp_handle,key_handle, PAL_CHECK_BOTH_KEYS,&verified);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(true, verified);

    /*#5*/
    result = pal_ECDSASign(grp_handle, PAL_SHA256, key_handle, hash_digest, sizeof(hash_digest), signature, &act_size_of_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    verified = false;
    result = pal_ECDSAVerify(key_handle, hash_digest, sizeof(hash_digest), signature, act_size_of_sign, &verified);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(true, verified);

    /*#7*/
    result = pal_ECGroupFree(&grp_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#8*/
    result = pal_ECKeyFree(&key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
}


/**
* @brief Test the convertion of RAW signature to DER signature
*
* Uses `pal_convertRawSignatureToDer`.
*
* | # |    Step                        |   Expected  |
* |---|--------------------------------|-------------|
* | 1 | Convert fixed RAW signature to DER format.                                                 | PAL_SUCCESS |
* | 2 | Verify out DER signature equal expected signature.                                         | PAL_SUCCESS |
* | On debug only                                                                                  |
* | 3 | Test invalid RAW signature size.                                                           | PAL_ERR_INVALID_ARGUMENT |
* | 4 | Test invalid DER signature buffer.                                                         | PAL_ERR_INVALID_ARGUMENT |
* | 5 | Test invalid DER signature size.                                                           | PAL_ERR_INVALID_ARGUMENT |
*/
TEST(pal_crypto, ECSig_RawToDER)
{
    palStatus_t result;
    unsigned char raw_signature[PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE] = { 0x98, 0xB1, 0x4B, 0xEB, 0xF6, 0xDB, 0x8A, 0xFB, 0x5F, 0xF5, 0x72, 0x35, 0xBA, 0x15, 0x5B, 0x3A, 0xC7, 0xD4, 0x87, 0xA8, 0xE0, 0x4F, 0xE4, 0x2F, 0xFF, 0x3C, 0x51, 0x0D, 0xB9, 0xD5, 0x2E, 0xA6, 0x3B, 0x06, 0x17, 0x5E, 0x30, 0x07, 0x75, 0x33, 0x01, 0xFD, 0xBC, 0x62, 0x9F, 0xCE, 0x99, 0xA7, 0xD3, 0xBD, 0x0A, 0x39, 0xB3, 0xE0, 0xCF, 0x3A, 0x34, 0x1E, 0x1A, 0xF6, 0x0F, 0xB7, 0x6B, 0x83 };
    unsigned char der_signature[PAL_ECDSA_SECP256R1_SIGNATURE_DER_SIZE] = { 0 };
    unsigned char exepected_der_sig[] = { 0x30, 0x45, 0x02, 0x21, 0x00, 0x98, 0xB1, 0x4B, 0xEB, 0xF6, 0xDB, 0x8A, 0xFB, 0x5F, 0xF5, 0x72, 0x35, 0xBA, 0x15, 0x5B, 0x3A, 0xC7, 0xD4, 0x87, 0xA8, 0xE0, 0x4F, 0xE4, 0x2F, 0xFF, 0x3C, 0x51, 0x0D, 0xB9, 0xD5, 0x2E, 0xA6, 0x02, 0x20, 0x3B, 0x06, 0x17, 0x5E, 0x30, 0x07, 0x75, 0x33, 0x01, 0xFD, 0xBC, 0x62, 0x9F, 0xCE, 0x99, 0xA7, 0xD3, 0xBD, 0x0A, 0x39, 0xB3, 0xE0, 0xCF, 0x3A, 0x34, 0x1E, 0x1A, 0xF6, 0x0F, 0xB7, 0x6B, 0x83 };
    size_t act_size_of_der_sign = 0;

    /*#1*/
    result = pal_convertRawSignatureToDer(raw_signature,sizeof(raw_signature),der_signature,sizeof(der_signature),&act_size_of_der_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    TEST_ASSERT_EQUAL_HEX(sizeof(exepected_der_sig), act_size_of_der_sign);
    TEST_ASSERT_EQUAL_MEMORY(exepected_der_sig, der_signature, act_size_of_der_sign);

#ifdef DEBUG
    /*#3*/
    result = pal_convertRawSignatureToDer(raw_signature,PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE-1,der_signature,sizeof(der_signature),&act_size_of_der_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, result);

    /*#4*/
    result = pal_convertRawSignatureToDer(raw_signature,sizeof(raw_signature),NULL,sizeof(der_signature),&act_size_of_der_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, result);

    /*#5*/
    result = pal_convertRawSignatureToDer(raw_signature,sizeof(raw_signature),der_signature,PAL_ECDSA_SECP256R1_SIGNATURE_RAW_SIZE,&act_size_of_der_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_INVALID_ARGUMENT, result);
#endif
}

/**
* @brief Test the sign and verify functions of elliptic-curves keys.
*
* Uses `pal_asymmetricSign` and `pal_asymmetricVerify`.
*
* | #  |    Step                                                                                                            |   Expected                   |
* |----|--------------------------------------------------------------------------------------------------------------------|------------------------------|
* PSA ONLY INITIALIZAITON
* | 1  | Allocate PSA volatile key for private key using `psa_allocate_key`.                                                | PAL_SUCCESS                  | 
* | 2  | Set policy using `psa_key_policy_set_usage` and `psa_set_key_policy`.                                              | PAL_SUCCESS                  |
* | 3  | Import the private key using `psa_import_key`.                                                                     | PAL_SUCCESS                  |
* | 4  | Allocate PSA volatile key for public key using `psa_allocate_key`.                                                 | PAL_SUCCESS                  |
* | 5  | Set policy using `psa_key_policy_set_usage` and `psa_set_key_policy`.                                              | PAL_SUCCESS                  |
* | 6  | Import the public key using `psa_import_key`.                                                                      | PAL_SUCCESS                  |
* | 7  | Allocate PSA volatile key for wrong public key using `psa_allocate_key`.                                           | PAL_SUCCESS                  |
* | 8  | Set policy using `psa_key_policy_set_usage` and `psa_set_key_policy`.                                              | PAL_SUCCESS                  |
* | 9  | Import the wrong public key using `psa_import_key`.                                                                | PAL_SUCCESS                  |
* TEST FLOW
* | 1  | Initialize a new EC key using `pal_ECKeyNew`.                                                                      | PAL_SUCCESS                  |
* | 2  | Parse private key data using `pal_parseECPrivateKeyFromHandle`.                                                    | PAL_SUCCESS                  |
* | 3  | Compute signature for digest with private key using `pal_asymmetricSign`.                                          | PAL_SUCCESS                  |
* | 4  | Release the EC key using `pal_ECKeyFree`.                                                                          | PAL_SUCCESS                  |
* | 5  | Initialize a new EC key using `pal_ECKeyNew` for pairs's public key.                                               | PAL_SUCCESS                  |
* | 6  | Parse public  key data using `pal_parseECPrivateKeyFromHandle`.                                                    | PAL_SUCCESS                  |
* | 7  | Initialize a new EC key using `pal_ECKeyNew` to generate additional key pair.                                      | PAL_SUCCESS                  |
* | 8  | Parse additional public key data using `pal_parseECPrivateKeyFromHandle`.                                          | PAL_SUCCESS                  |
* | 9  | Verify signature with additional public key using `pal_asymmetricVerify`                                           | PAL_ERR_PK_SIG_VERIFY_FAILED |
* | 10 | Verify signature with original public key using `pal_asymmetricVerify`                                             | PAL_SUCCESS                  |
* | 11 | Release the EC original public key using `pal_ECKeyFree`.                                                          | PAL_SUCCESS                  |
* | 12 | Release the EC additional public key using `pal_ECKeyFree`.                                                        | PAL_SUCCESS                  |
* PSA ONLY FINALIZATION
* | 1  | Destroy private volatile key using `psa_close_key`                                                                 | PAL_SUCCESS                  |
* | 2  | Destroy public volatile key using `psa_close_key`                                                                  | PAL_SUCCESS                  |
* | 3  | Destroy wrong public volatile key using `psa_close_key`                                                            | PAL_SUCCESS                  |
*/
TEST(pal_crypto, ECKey_SignVerify)
{

    palStatus_t result;
    palECKeyHandle_t key_handle = NULLPTR;
    palECKeyHandle_t wrong_pub_key_handle = NULLPTR;
    palKeyHandle_t prvDERKey;
    palKeyHandle_t pubDERKey;
    palKeyHandle_t pubDERKeyWrong;
    size_t act_size_of_sign;
    unsigned char hash_digest[] =
    { 0x34, 0x70, 0xCD, 0x54, 0x7B, 0x0A, 0x11, 0x5F, 0xE0, 0x5C, 0xEB, 0xBC, 0x07, 0xBA, 0x91, 0x88,
        0x27, 0x20, 0x25, 0x6B, 0xB2, 0x7A, 0x66, 0x89, 0x1A, 0x4B, 0xB7, 0x17, 0x11, 0x04, 0x86, 0x6F };
    unsigned char signature[64] = { 0 };

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

    palCryptoBuffer_t prvKey_ctx, pubKey_ctx,wrongKey_ctx;
    const uint8_t wrong_ecc_public_key[91] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6c, 0x44, 0xee, 0x60, 0x46,
        0x3e, 0x14, 0x52, 0xd0, 0x7e, 0xb1, 0xd5, 0xe6, 0xc0, 0x1c, 0xcb, 0xd3, 0x20, 0x7e, 0xcb, 0x1f, 0xb0, 0x75, 0x3c, 0xca,
        0xff, 0xd4, 0x8a, 0xc2, 0xb8, 0xe0, 0xfd, 0x0d, 0xc2, 0x41, 0xc7, 0x52, 0xc7, 0x0e, 0x3b, 0x53, 0x25, 0xc1, 0x7e, 0x38,
        0xa0, 0x49, 0x56, 0x34, 0x27, 0x4e, 0xdd, 0x4c, 0xa8, 0x5a, 0x2a, 0xfa, 0xca, 0x66, 0x77, 0x8b, 0xd8, 0x8d, 0x3e, };


    prvKey_ctx.buffer = (uint8_t*)parse_ec_key_data[2].key;
    prvKey_ctx.size = parse_ec_key_data[2].len;
    pubKey_ctx.buffer = (uint8_t*)parse_ec_key_data[3].key;
    pubKey_ctx.size = parse_ec_key_data[3].len;
    wrongKey_ctx.buffer = (uint8_t*)wrong_ecc_public_key;
    wrongKey_ctx.size = sizeof(wrong_ecc_public_key);

    //set handles
    prvDERKey = (uintptr_t)&prvKey_ctx;
    pubDERKey = (uintptr_t)&pubKey_ctx;
    pubDERKeyWrong = (uintptr_t)&wrongKey_ctx;

#else

    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    uint8_t* rawPrvKeyData = (uint8_t*)parse_ec_key_data[2].raw_key;
    size_t rawPrvKeySize = parse_ec_key_data[2].raw_key_length;
    uint8_t* rawPubKeyData = (uint8_t*)parse_ec_key_data[3].raw_key;
    size_t rawPubKeySize = parse_ec_key_data[3].raw_key_length;

    unsigned char rawPubKeyDataWrong[65] = {0x4, 0x6C, 0x44, 0xEE, 0x60, 0x46, 0x3E, 0x14, 0x52, 0xD0, 0x7E, 0xB1, 0xD5, 0xE6, 0xC0, 0x1C,
    0xCB, 0xD3, 0x20, 0x7E, 0xCB, 0x1F, 0xB0, 0x75, 0x3C, 0xCA, 0xFF, 0xD4, 0x8A, 0xC2, 0xB8, 0xE0, 0xFD, 0xD, 0xC2, 0x41, 0xC7, 0x52,
    0xC7, 0xE, 0x3B, 0x53, 0x25, 0xC1, 0x7E, 0x38, 0xA0, 0x49, 0x56, 0x34, 0x27, 0x4E, 0xDD, 0x4C, 0xA8, 0x5A, 0x2A, 0xFA, 0xCA, 0x66,
    0x77, 0x8B, 0xD8, 0x8D, 0x3E,};

    /*1*/
    psa_status = psa_allocate_key((psa_key_handle_t*)&prvDERKey);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*2*/
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_status = psa_set_key_policy((psa_key_handle_t)prvDERKey, &policy);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*3*/
    psa_status = psa_import_key((psa_key_handle_t)prvDERKey, PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1), rawPrvKeyData, rawPrvKeySize);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*4*/
    psa_status = psa_allocate_key((psa_key_handle_t*)&pubDERKey);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*5*/
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_VERIFY, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_status = psa_set_key_policy((psa_key_handle_t)pubDERKey, &policy);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*6*/
    psa_status = psa_import_key((psa_key_handle_t)pubDERKey, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1), rawPubKeyData, rawPubKeySize);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*7*/
    psa_status = psa_allocate_key((psa_key_handle_t*)&pubDERKeyWrong);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*8*/
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_VERIFY, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_status = psa_set_key_policy((psa_key_handle_t)pubDERKeyWrong, &policy);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*9*/
    psa_status = psa_import_key((psa_key_handle_t)pubDERKeyWrong, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1), rawPubKeyDataWrong, sizeof(rawPubKeyDataWrong));
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

#endif

    /*#1*/
    result = pal_ECKeyNew(&key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_parseECPrivateKeyFromHandle(prvDERKey, key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_asymmetricSign(key_handle, PAL_SHA256, hash_digest, sizeof(hash_digest), signature, sizeof(signature), &act_size_of_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#4*/
     result = pal_ECKeyFree(&key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#5*/
    result = pal_ECKeyNew(&key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_parseECPublicKeyFromHandle(pubDERKey, key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#7*/
    result = pal_ECKeyNew(&wrong_pub_key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    
    /*#8*/
    result = pal_parseECPublicKeyFromHandle(pubDERKeyWrong, wrong_pub_key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#9*/
    result = pal_asymmetricVerify(wrong_pub_key_handle, PAL_SHA256,hash_digest, sizeof(hash_digest), signature, act_size_of_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_ERR_PK_SIG_VERIFY_FAILED, result);

    /*#10*/
    result = pal_asymmetricVerify(key_handle, PAL_SHA256, hash_digest, sizeof(hash_digest), signature, act_size_of_sign);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);


    /*#11*/
    result = pal_ECKeyFree(&key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#12*/
    result = pal_ECKeyFree(&wrong_pub_key_handle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);


#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    /*1*/
    psa_status = psa_close_key((psa_key_handle_t)prvDERKey);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*2*/
    psa_status = psa_close_key((psa_key_handle_t)pubDERKey);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    /*3*/
    psa_status = psa_close_key((psa_key_handle_t)pubDERKeyWrong);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);
#endif

}



/**
* @brief Test the ECDH key agreement functions of elliptic-curves keys.
*
* Uses `pal_ECDHKeyAgreement` 
*
* | #  |    Step                                                                                                            |   Expected                   |
* |----|--------------------------------------------------------------------------------------------------------------------|------------------------------|
* | 1  | Initialize a new EC key using `pal_ECKeyNew` for our private key.                                                  | PAL_SUCCESS                  |
* | 2  | Parse our private key data using `pal_parseECPrivateKeyFromHandle`.                                                | PAL_SUCCESS                  |
* | 3  | Compute our shared secret using `pal_ECDHKeyAgreement`.                                                            | PAL_SUCCESS                  |
* | 4  | Initialize a new EC key using `pal_ECKeyNew` for their private key.                                                | PAL_SUCCESS                  |
* | 5  | Parse their private key data using `pal_parseECPrivateKeyFromHandle`.                                              | PAL_SUCCESS                  |
* | 6  | Compute their shared secret using `pal_ECDHKeyAgreement`.                                                          | PAL_SUCCESS                  |
* | 7  | Check size of output secrets.                                                                                      | PAL_SUCCESS                  |
* | 8  | Compare the data of the both secrets.                                                                              | PAL_SUCCESS                  |
* | 9  | Release the EC our private key using `pal_ECKeyFree`.                                                              | PAL_SUCCESS                  |
* | 10 | Release the EC their private key using `pal_ECKeyFree`.                                                            | PAL_SUCCESS                  |
*/
TEST(pal_crypto, ECKey_Agreement)
{
    palStatus_t result;
    palECKeyHandle_t ourPrivKeyHandle = NULLPTR;
    palECKeyHandle_t theirPrivKeyHandle = NULLPTR;
    unsigned char ourSharedSecret[PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE] = { 0 };
    unsigned char theirSharedSecret[PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE] = { 0 };
    size_t actSizeOfOurSharedSecret = 0;
    size_t actSizeOfTheirSharedSecret = 0;
    palKeyHandle_t ourPrvPalKey;
    palKeyHandle_t ourPubPalKey;
    palKeyHandle_t theirPrvPalKey;
    palKeyHandle_t theirPubPalKey;
    uint8_t *theirPubKey = NULL;
    uint8_t theirPubKeySize = 0;
    uint8_t *ourPubKey = NULL;
    uint8_t ourPubKeySize = 0;


    //setup keys

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    palCryptoBuffer_t ourPrvKey_ctx, ourPubKey_ctx, theirPrvKey_ctx, theirPubKey_ctx;

    //Set our pal crypto buffers
    ourPrvKey_ctx.buffer = key_agreement_private_key;
    ourPrvKey_ctx.size = sizeof(key_agreement_private_key);
    ourPubKey_ctx.buffer = key_agreement_public_key;
    ourPubKey_ctx.size = sizeof(key_agreement_public_key);

    //Set their crypto buffers
    theirPrvKey_ctx.buffer = (uint8_t*)parse_ec_key_data[2].key;
    theirPrvKey_ctx.size = parse_ec_key_data[2].len;
    theirPubKey_ctx.buffer = (uint8_t*)parse_ec_key_data[3].key;
    theirPubKey_ctx.size = parse_ec_key_data[3].len;

    //set pal key handles
    ourPrvPalKey = (uintptr_t)&ourPrvKey_ctx;
    ourPubPalKey = (uintptr_t)&ourPubKey_ctx;
    theirPrvPalKey = (uintptr_t)&theirPrvKey_ctx;
    theirPubPalKey = (uintptr_t)&theirPubKey_ctx;
#else

    psa_status_t psa_status = PSA_SUCCESS;
    psa_key_handle_t ourPrvKeyPsaHandle = 0;
    psa_key_handle_t theirPrvKeyPsaHandle = 0;
    psa_key_policy_t policy ;
    unsigned char rawKeyDataOur[32] = { 0x16, 0xec, 0xed, 0x76, 0x21, 0xe4, 0x67, 0x06, 0x81, 0x6b, 0xfd, 0x93, 0x54, 0x67, 0xdb, 0x2a, 0x23, 0x03, 0x49, 0x38, 0xb0, 0xe2, 0x3d, 0xfa, 0x0b, 0x22, 0xb8, 0x07, 0xaf, 0xab, 0x43, 0xa4 };
    unsigned char rawKeyDataTheir[32] = { 0xbd, 0x42, 0xd6, 0x36, 0x31, 0x2d, 0xf3, 0x2b, 0x31, 0xeb, 0xe6, 0xe3, 0xc8, 0x63, 0x61, 0xa8, 0x45, 0x92, 0x2c, 0x70, 0xab, 0x02, 0xc7, 0x45, 0xa7, 0xba, 0x7f, 0x39, 0xd3, 0xfd, 0xf0, 0x07 };

    //Allocate our private key
    psa_status = psa_allocate_key(&ourPrvKeyPsaHandle);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    //Set usage and algorithm
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH(PSA_ALG_SELECT_RAW));
    psa_status = psa_set_key_policy(ourPrvKeyPsaHandle, &policy);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    //Import the key
    psa_status = psa_import_key(ourPrvKeyPsaHandle, PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1), rawKeyDataOur, sizeof(rawKeyDataOur));
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    ourPrvPalKey = (palKeyHandle_t)ourPrvKeyPsaHandle;

    //Allocate our their key
    psa_status = psa_allocate_key(&theirPrvKeyPsaHandle);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);
    //Set usage and algorithm
    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH(PSA_ALG_SELECT_RAW));
    psa_status = psa_set_key_policy(theirPrvKeyPsaHandle, &policy);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    //Import the key
    psa_status = psa_import_key(theirPrvKeyPsaHandle, PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1), rawKeyDataTheir, sizeof(rawKeyDataTheir));
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

    theirPrvPalKey = (palKeyHandle_t)theirPrvKeyPsaHandle;

#endif

    ourPubKey = key_agreement_public_key;
    ourPubKeySize = sizeof(key_agreement_private_key);
    theirPubKey = (uint8_t*)parse_ec_key_data[3].key;
    theirPubKeySize = parse_ec_key_data[3].len;

    /*#1*/
    result = pal_ECKeyNew(&ourPrivKeyHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#2*/
    result = pal_parseECPrivateKeyFromHandle(ourPrvPalKey, ourPrivKeyHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#3*/
    result = pal_ECDHKeyAgreement(theirPubKey, theirPubKeySize, ourPrivKeyHandle, ourSharedSecret, sizeof(ourSharedSecret), &actSizeOfOurSharedSecret);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE, actSizeOfOurSharedSecret);

    /*#4*/
    result = pal_ECKeyNew(&theirPrivKeyHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#5*/
    result = pal_parseECPrivateKeyFromHandle(theirPrvPalKey, theirPrivKeyHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#6*/
    result = pal_ECDHKeyAgreement(ourPubKey, ourPubKeySize, theirPrivKeyHandle, theirSharedSecret, sizeof(theirSharedSecret), &actSizeOfTheirSharedSecret);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);
    TEST_ASSERT_EQUAL_HEX(PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE, actSizeOfTheirSharedSecret);

    /*#7*/
    TEST_ASSERT_EQUAL_HEX(actSizeOfTheirSharedSecret, actSizeOfOurSharedSecret);

    /*#8*/
    TEST_ASSERT_EQUAL_MEMORY(theirSharedSecret, ourSharedSecret, PAL_SECP256R1_RAW_KEY_AGREEMENT_SIZE);

    /*#9*/
    result = pal_ECKeyFree(&ourPrivKeyHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

    /*#10*/
    result = pal_ECKeyFree(&theirPrivKeyHandle);
    TEST_ASSERT_EQUAL_HEX(PAL_SUCCESS, result);

#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    //free allocated resources
    psa_status = psa_close_key(theirPrvKeyPsaHandle);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);


    psa_status = psa_close_key(ourPrvKeyPsaHandle);
    TEST_ASSERT_EQUAL_HEX(PSA_SUCCESS, psa_status);

#endif

}
