/*******************************************************************************
 * Copyright 2016-2018 ARM Ltd.
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
#ifndef MBED_CLIENT_PAL_TEST_RUNNERS_H_
#define MBED_CLIENT_PAL_TEST_RUNNERS_H_
#include "pal.h"

#ifndef PAL_TEST_RTOS
#define PAL_TEST_RTOS 0
#endif // PAL_TEST_RTOS

#ifndef PAL_TEST_ROT
#define PAL_TEST_ROT 0
#endif // PAL_TEST_ROT

#ifndef PAL_TEST_NETWORK
#define PAL_TEST_NETWORK 0
#endif // PAL_TEST_NETWORK

#ifndef PAL_TEST_TIME
#define PAL_TEST_TIME 0
#endif // PAL_TEST_TIME

#ifndef PAL_TEST_TLS
#define PAL_TEST_TLS 0
#endif // PAL_TEST_TLS

#ifndef PAL_TEST_CRYPTO
#define PAL_TEST_CRYPTO 0
#endif // PAL_TEST_CRYPTO

#ifndef PAL_TEST_DRBG
#define PAL_TEST_DRBG 0
#endif // PAL_TEST_DRBG

#ifndef PAL_TEST_FS
#define PAL_TEST_FS 0
#endif // PAL_TEST_FS

#ifndef PAL_TEST_UPDATE
#define PAL_TEST_UPDATE 0
#endif // PAL_TEST_UPDATE

#ifndef PAL_TEST_FLASH
#define PAL_TEST_FLASH 1
#endif // PAL_TEST_FLASH

#ifndef TEST_PRINTF
    #define TEST_PRINTF(ARGS...) PAL_PRINTF(ARGS)
#endif //TEST_PRINTF

#ifdef PAL_LINUX
#define PAL_TEST_THREAD_STACK_SIZE 16*1024*sizeof(uint32_t)
#else
#define PAL_TEST_THREAD_STACK_SIZE 512*sizeof(uint32_t)
#endif


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int argc;
    char **argv;
} pal_args_t;


typedef void (*testMain_t)(pal_args_t *);
int test_main(int argc, char * argv[], testMain_t func);

#ifdef PAL_MEMORY_STATISTICS
void printMemoryStats(void);
#define PRINT_MEMORY_STATS  printMemoryStats();
#else //PAL_MEMORY_STATISTICS
#define PRINT_MEMORY_STATS
#endif


void TEST_pal_rtos_GROUP_RUNNER(void);

void TEST_pal_rot_GROUP_RUNNER(void);

void TEST_pal_entropy_GROUP_RUNNER(void);

void TEST_pal_socket_GROUP_RUNNER(void);

void TEST_pal_time_GROUP_RUNNER(void);

void TEST_pal_tls_GROUP_RUNNER(void);

void TEST_pal_crypto_GROUP_RUNNER(void);

void TEST_pal_drbg_GROUP_RUNNER(void);

void TEST_pal_fileSystem_GROUP_RUNNER(void);

void TEST_pal_update_GROUP_RUNNER(void);

void TEST_pal_internalFlash_GROUP_RUNNER(void);

void TEST_pal_sst_GROUP_RUNNER(void);

void TEST_pal_SOTP_GROUP_RUNNER(void);

void TEST_pal_sanity_GROUP_RUNNER(void);


typedef struct _palTestsStatusData_t
{
    int module;
    int test;
    int inner;
    unsigned long long  numberOfTests;
    unsigned long long  numOfTestsFailures;
    unsigned long long  numberOfIgnoredTests;
}palTestsStatusData_t;


typedef enum _palTestModules_t
{
    PAL_TEST_MODULE_START,
    PAL_TEST_MODULE_RTOS = PAL_TEST_MODULE_START,
    PAL_TEST_MODULE_ROT,
    PAL_TEST_MODULE_ENTROPY,
    PAL_TEST_MODULE_SOCKET,
    PAL_TEST_MODULE_TIME,
    PAL_TEST_MODULE_TLS,
    PAL_TEST_MODULE_CRYPTO,
    PAL_TEST_MODULE_DRBG,
    PAL_TEST_MODULE_FILESYSTEM,
    PAL_TEST_MODULE_UPDATE,
    PAL_TEST_MODULE_INTERNALFLASH,
    PAL_TEST_MODULE_SST,
    PAL_TEST_MODULE_SOTP,
    PAL_TEST_MODULE_SANITY,
    PAL_TEST_MODULE_ALL,
    PAL_TEST_MODULE_END
}palTestModules_t;

// bitmask of prequisite platform component initializations needed for test.
typedef enum _palTestPlatformInit_t
{
    // mcc_platform_init
    PAL_TEST_PLATFORM_INIT_BASE = 1,

    // mcc_platform_init_connection
    PAL_TEST_PLATFORM_INIT_CONNECTION = (1<<1),

    // mcc_platform_storage_init
    PAL_TEST_PLATFORM_INIT_STORAGE = (1<<2),

    // mcc_platform_reformat_storage
    PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE =  (1<<3)
} palTestPlatformInit_t;


// Entry points for the module specific test suites. This code is executed either from
// module-specific runner executables (eg. Test/TESTS/Unitest/RTOS/pal_rtos_test_main.c), which
// contain the main() function or directly from some other executable.
// Not all OS's even support main(), or it may already be in use by OS itself,
// so a platform specific runner may be needed for each test.
// Especially during the porting phase, it may be also convenient to call these from
// the test application itself so only the currently ported component is tested.
int palAllTestMain(void); // this will execute tests for all the other modules below
int palFileSystemTestMain(void);
int palNetworkTestMain(void);
int palCryptoTestMain(void);
int palDRBGTestMain(void);
int palROTTestMain(void);
int palEntropyTestMain(void);
int palRTOSTestMain(void);
int palStorageTestMain(void);
int palTimeTestMain(void);
int palSSTTestMain(void);
int palTLSTestMain(void);
int palUpdateTestMain(void);
int palSOTPTestMain(void);
int palSanityTestMain(void);
int palReformatTestMain(void);

typedef enum _palTestSOTPTests_t
{
    PAL_TEST_SOTP_TEST_START,
    PAL_TEST_SOTP_TEST_SW_HW_ROT = PAL_TEST_SOTP_TEST_START,
    PAL_TEST_SOTP_TEST_TIME_INIT,
    PAL_TEST_SOTP_TEST_RANDOM,
    PAL_TEST_SOTP_TEST_END
}palTestSOTPTests_t;

palStatus_t setPalTestStatus(palTestsStatusData_t palRebootTestStatus);

palStatus_t getPalTestStatus(void);

palStatus_t palTestReboot(palTestModules_t module ,palTestSOTPTests_t test );

void updatePalTestStatusAfterReboot(void);

#ifdef __cplusplus
}
#endif

#endif /* MBED_CLIENT_PAL_TEST_RUNNERS_H_ */
