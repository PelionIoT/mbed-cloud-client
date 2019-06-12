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
#include "pal.h"


TEST_GROUP_RUNNER(pal_tls)
{
    RUN_TEST_CASE(pal_tls, tlsConfiguration);
    RUN_TEST_CASE(pal_tls, tlsInitTLS);
    RUN_TEST_CASE(pal_tls, tlsPrivateAndPublicKeys);
    RUN_TEST_CASE(pal_tls, tlsCACertandPSK);
    RUN_TEST_CASE(pal_tls, tlsHandshakeUDPTimeOut);
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP);
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP_FutureLWM2M); //Far future LWM2M - should update the time in SOTP
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP_FutureLWM2M_NoTimeUpdate); // Near future LWM2M - No SOTP time update
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP_ExpiredLWM2MCert);   // Expired LWM2M - Certificate verification MUST fail
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP_ExpiredServerCert_Trusted); // Expired BootStrap - should update the times in SOTP
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP_FutureTrustedServer_NoTimeUpdate); // Near future BootStrap - No SOTP time update
    RUN_TEST_CASE(pal_tls, tlsHandshakeTCP_NearPastTrustedServer_NoTimeUpdate); // Near past BootStrap - No SOTP time update
    RUN_TEST_CASE(pal_tls, TCPHandshakeWhileCertVerify_threads);
    RUN_TEST_CASE(pal_tls, tlsHandshakeUDP);
    RUN_TEST_CASE(pal_tls, tlsHandshake_SessionResume);

}
