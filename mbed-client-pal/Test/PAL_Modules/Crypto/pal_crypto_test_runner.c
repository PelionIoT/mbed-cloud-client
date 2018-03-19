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

#include "unity.h"
#include "unity_fixture.h"


// PAL Socket API tests
TEST_GROUP_RUNNER(pal_crypto)
{
	// AES cryptography
    RUN_TEST_CASE(pal_crypto, AES_CTR);
    RUN_TEST_CASE(pal_crypto, AES_ECB);
    RUN_TEST_CASE(pal_crypto, AES_CCM);

    //Hashing using SHA256
    RUN_TEST_CASE(pal_crypto, SHA256);
    RUN_TEST_CASE(pal_crypto, md);

    //Random Number Generation
    RUN_TEST_CASE(pal_crypto, CTR_DRBG);

    //CMAC
    RUN_TEST_CASE(pal_crypto, CMAC_one_shot);
    RUN_TEST_CASE(pal_crypto, CMAC_Iterative);

    //MD HMAC SHA256
    RUN_TEST_CASE(pal_crypto, HMAC_SHA256_one_shot);

    //Certificate
    RUN_TEST_CASE(pal_crypto, ASN1);
    RUN_TEST_CASE(pal_crypto, X509_Parse);
    RUN_TEST_CASE(pal_crypto, X509_ReadAttributes);
    RUN_TEST_CASE(pal_crypto, X509_Verify);

    //Elliptic Curves
    RUN_TEST_CASE(pal_crypto, ECKey_checkKey);
    RUN_TEST_CASE(pal_crypto, ECKey_parseKey);
#if 0
    //Not required for R1.2
    RUN_TEST_CASE(pal_crypto, CSR);
#endif //0

}
