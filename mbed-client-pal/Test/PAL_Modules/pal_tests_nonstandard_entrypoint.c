/*******************************************************************************
 * Copyright 2018 ARM Ltd.
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


#if (PAL_UNIT_TESTING_NONSTANDARD_ENTRYPOINT)

#include "test_runners.h"

// Entry point for the module specific test suites. This code is executed from
// a OS which does not support calling main(), but has hook for
// mbed_cloud_application_entrypoint(). This requires one to build the whole system
// binary again for each test, but what can you do, without dynamic loader support.
int mbed_cloud_application_entrypoint(void)
{
    int status;

#if defined(PAL_UNIT_TEST_FILESYSTEM)
    status = palFileSystemTestMain();
#elif defined(PAL_UNIT_TEST_NETWORK)
    status = palNetworkTestMain();
#elif defined(PAL_UNIT_TEST_DRBG)
    status = palDRBGTestMain();
#elif defined(PAL_UNIT_TEST_ROT)
    status = palROTTestMain();
#elif defined(PAL_UNIT_TEST_RTOS)
    status = palRTOSTestMain();
#elif defined(PAL_UNIT_TEST_STORAGE)
    status = palStorageTestMain();
#elif defined(PAL_UNIT_TEST_TIME)
    status = palTimeTestMain();
#elif defined(PAL_UNIT_TEST_TLS)
    status = palTLSTestMain();
#elif defined(PAL_UNIT_TEST_UPDATE)
    status = palUpdateTestMain();
#elif defined(PAL_UNIT_TEST_SOTP)
    status = palSOTPTestMain();
#elif defined(PAL_UNIT_TEST_SANITY)
    status = palSanityTestMain();
#elif defined(PAL_UNIT_TEST_REFORMAT)
    status = palReformatTestMain();
#else 
    // No need for defined(PAL_UNIT_TEST_ALL), this is likely the most needed one
    status = palAllTestMain(); // this will execute tests for all the other modules above
#endif

    return status;
}
#endif
