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

#include "test_runners.h"

#include "mbed_trace.h"

#include "mcc_common_setup.h"

#include "unity.h"
#include "unity_fixture.h"

#include <stdio.h>

#define TRACE_GROUP "PAL"

extern struct _Unity Unity;

#define PAL_TEST_STATUS_FILE_LOCATION "/tstSts"
#define PAL_TEST_STATUS_FILE_DATA_MAX_SIZE 128

void * g_palTestNetworkInterface = NULL;
void * g_palTestTLSInterfaceCTX = NULL;

static volatile main_t main_test_function;
static volatile int main_init_flags;

static int palTestMainRunner(void);


pal_args_t g_args; // defiend as global so it could persist 
                   // during task execution on FreeRTOS

#ifdef DEBUG
#define	PAL_TESTS_LOG_LEVEL ((uint8_t)((TRACE_MASK_LEVEL & TRACE_ACTIVE_LEVEL_ALL) | (TRACE_MASK_CONFIG & TRACE_CARRIAGE_RETURN)))
#else
#define	PAL_TESTS_LOG_LEVEL ((uint8_t)((TRACE_MASK_LEVEL & TRACE_ACTIVE_LEVEL_ERROR) | (TRACE_MASK_CONFIG & TRACE_CARRIAGE_RETURN)))
#endif


palTestsStatusData_t palTestStatus = {-1,-1,-1,0,0,0};


palStatus_t getPalTestStatus(void)
{
    palStatus_t status = PAL_SUCCESS, status2 = PAL_SUCCESS;
    char filePath[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palFileDescriptor_t fd = 0;
    size_t dataSizeWritten = 0;
    char data[128] = {0};
  

    status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, filePath);
    if (PAL_SUCCESS == status) 
    {
        strncat(filePath,PAL_TEST_STATUS_FILE_LOCATION,PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
        status = pal_fsFopen(filePath, PAL_FS_FLAG_READONLY, &fd);
         if (PAL_SUCCESS == status)
         {

             status =  pal_fsFread(&fd, (void *)data, PAL_TEST_STATUS_FILE_DATA_MAX_SIZE, &dataSizeWritten);
             if ((PAL_SUCCESS == status) && (dataSizeWritten > 0))
             {
                 printf("reading DATA into test\r\n");
                 sscanf(data,"%i %i %i %llu %llu %llu", &palTestStatus.module, &palTestStatus.test, &palTestStatus.inner, &palTestStatus.numOfTestsFailures, &palTestStatus.numberOfTests, &palTestStatus.numberOfIgnoredTests);
             }
             status2 = pal_fsFclose(&fd);
             if (PAL_SUCCESS != status2) 
             {
                 PAL_LOG_ERR("Failed to close data file of test status after read");
             }
             status2 = pal_fsUnlink(filePath);
             if (PAL_SUCCESS != status2) 
             {
                 PAL_LOG_ERR("Failed to delete data file of test status after read");
             }
         }
        else if (PAL_ERR_FS_NO_FILE == status) {
            //this is not an error... in most times there will be no file
            status = PAL_SUCCESS;
        }
    }

    PAL_LOG_DBG("*********************************\n"
    		"** Test status: 				**\n"
    		"** Module %d    				**\n"
    		"** Test %d      				**\n"
    		"** Inner %d     				**\n"
    		"** num of tests failures %llu	**\n"
    		"** num of tests %llu     		**\n"
    		"** num of ignored tests %llu   **\n"
    		"*********************************\n",
			palTestStatus.module, palTestStatus.test, palTestStatus.inner,
			palTestStatus.numOfTestsFailures, palTestStatus.numberOfTests,
			palTestStatus.numberOfIgnoredTests);

    return status;
}

void updatePalTestStatusAfterReboot(void)
{
	if (palTestStatus.numberOfTests > 0)
	{
		Unity.TestFailures = palTestStatus.numOfTestsFailures;
		Unity.NumberOfTests = palTestStatus.numberOfTests;
		Unity.CurrentTestIgnored =palTestStatus.numberOfIgnoredTests;
        PAL_LOG_DBG("Unity number of tests was updated\r\n");
	}

	palTestStatus.inner = -1;
}


palStatus_t setPalTestStatus(palTestsStatusData_t palRebootTestStatus)
{
    palStatus_t status = PAL_SUCCESS, status2 = PAL_SUCCESS;;
    char filePath[PAL_MAX_FILE_AND_FOLDER_LENGTH] = {0};
    palFileDescriptor_t fd = 0;
    size_t dataSizeWritten = 0;
    char data[PAL_TEST_STATUS_FILE_DATA_MAX_SIZE] = {0};
    

    status = pal_fsGetMountPoint(PAL_FS_PARTITION_PRIMARY, PAL_MAX_FILE_AND_FOLDER_LENGTH, filePath);
    if (PAL_SUCCESS == status) 
    {
        strncat(filePath,PAL_TEST_STATUS_FILE_LOCATION,PAL_MAX_FILE_AND_FOLDER_LENGTH - strlen(filePath));
        status = pal_fsFopen(filePath, PAL_FS_FLAG_READWRITETRUNC, &fd);
         if (PAL_SUCCESS == status)
         {
        	 snprintf((char *)data,PAL_TEST_STATUS_FILE_DATA_MAX_SIZE, "%d %d %d %llu %llu %llu ", palRebootTestStatus.module, palRebootTestStatus.test, palRebootTestStatus.inner, palRebootTestStatus.numOfTestsFailures, palRebootTestStatus.numberOfTests, palRebootTestStatus.numberOfIgnoredTests);
        	 status =  pal_fsFwrite(&fd, (void *)data, PAL_TEST_STATUS_FILE_DATA_MAX_SIZE, &dataSizeWritten);
             pal_fsFclose(&fd);
             if (PAL_SUCCESS != status2) 
             {
                 PAL_LOG_ERR("Failed to close data file of test status after write");
             }
         }
    }
    return status;
}


palStatus_t palTestReboot(palTestModules_t module ,palTestSOTPTests_t test )
{
    palStatus_t status = PAL_SUCCESS;
	palTestsStatusData_t palRebootTestStatus;
	palRebootTestStatus.module = module;
    palRebootTestStatus.test = test;
    palRebootTestStatus.inner = 1;
    palRebootTestStatus.numberOfTests = Unity.NumberOfTests;
    palRebootTestStatus.numOfTestsFailures = Unity.TestFailures;
    palRebootTestStatus.numberOfIgnoredTests = Unity.CurrentTestIgnored;

    status = setPalTestStatus(palRebootTestStatus);
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("Failed to set test status before reboot");
    }
    else
    {
		pal_osReboot();
    }
    return status;
}


void TEST_pal_all_GROUPS_RUNNER(void)
{
    PRINT_MEMORY_STATS;
    switch (palTestStatus.module) // fall through is in design
    {
        case -1:
            //TEST_pal_sanity_GROUP_RUNNER(); // always run this at least once
        case PAL_TEST_MODULE_SOTP:
            PRINT_MEMORY_STATS;
            /**
             *  CAUTION:THIS TEST MUDOLE REBOOTS THE SYSTEM
             *  THIS TEST MUST BE 1ST!!!!!
             *  DO NOT MOVE THIS TEST!!!!!
            */
            #ifndef PAL_SKIP_TEST_MODULE_SOTP
                TEST_pal_SOTP_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_RTOS:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_RTOS
                TEST_pal_rtos_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_SOCKET:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_NETWORK
                TEST_pal_socket_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_TIME:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_TIME
                TEST_pal_time_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_CRYPTO:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_CRYPTO
                TEST_pal_crypto_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_DRBG:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_DRBG
                TEST_pal_drbg_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_FILESYSTEM:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_FILESYSTEM
                TEST_pal_fileSystem_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_SST:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_SST
                TEST_pal_sst_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_ROT:
            // if the implementation is using SOTP, it may be better to test storage and SOTP before it
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_ROT
                TEST_pal_rot_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_UPDATE:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_UPDATE
                TEST_pal_update_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_INTERNALFLASH:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_INTERNALFLASH
                TEST_pal_internalFlash_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_TLS:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_TLS
                TEST_pal_tls_GROUP_RUNNER();
            #endif
            PRINT_MEMORY_STATS;
            break;
        default:
            PAL_PRINTF("this should not happen!!! Error Error Error");
    }
}

// Wrapper for running the palTestMainRunner in platform specific way.
int palTestMain(void (*runAllTests)(void), int init_flags)
{
    // As the mcc_platform_run_program() misses a way to pass data, the arguments
    // for palTestMainRunner() need to be stored into static variables.
    main_test_function = runAllTests;
    main_init_flags = init_flags;

    // On FreeRTOS the test needs to be started via the platform API, which will
    // create a task out of it and run the scheduler. Without this, the many of
    // the FreeRTOS API's are not usable.
    return mcc_platform_run_program((main_t)palTestMainRunner);
}

// XXX: when this is ran by mcc_platform_run_program(), the return value is not
// actually passed on out of main(). This needs to be fixed in mcc_platform_run_program().
static int palTestMainRunner(void)
{
    const char * myargv[] = {"app","-v"};

    int status = 0;

    // copy back the arguments given to palTestMain.
    int init_flags = main_init_flags;
    void (*runAllTests)(void) = main_test_function;

    // this might be even a default as most tests need some kind of platform. But the
    // platfrom tests themselves might do some special stuff, so let's make mcc_platfrom_init()
    // call optional too.
    if (init_flags & PAL_TEST_PLATFORM_INIT_BASE) {
        status = mcc_platform_init();

        // The TEST_ASSERT can not be used yet, as it will cause a segfault on Unity, as
        // it has not yet performed its own setup for Unity.AbortFrame.
        // In any case, we will stop the test run as there is no point to continue tests
        // with half initialized platform.
        if (status) {
            PAL_LOG_ERR("failed to initialize platform: %d", status);
            return EXIT_FAILURE;
        }
    }

    // initialize the tracing as soon as possible so it can be used to debug the
    // more complex and fragile parts, such as storage and network driver initializations.
    mbed_trace_init();
    mbed_trace_config_set(PAL_TESTS_LOG_LEVEL);

    if (init_flags & PAL_TEST_PLATFORM_INIT_CONNECTION) {
        status = mcc_platform_init_connection();

        if (status) {
            PAL_LOG_ERR("failed to initialize connection: %d", status);
            return EXIT_FAILURE;
        }

        void* network;

#if defined(PAL_LINUX_ETH)
        // On Linux side there is CMake magic to find out a interface name, which will fill
        // the PAL_LINUX_ETH macro.
        network = (char*)PAL_LINUX_ETH;
#else
        network = mcc_platform_get_network_interface();
#endif

        g_palTestNetworkInterface = network;
        g_palTestTLSInterfaceCTX = network;
    }

    if (init_flags & PAL_TEST_PLATFORM_INIT_STORAGE) {
        status = mcc_platform_storage_init();

        if (status) {
            PAL_LOG_ERR("failed to initialize storage: %d", status);
            return EXIT_FAILURE;
        }
    }

// Format call is not needed with SST implementation
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    if (init_flags & PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE) {
        status = mcc_platform_reformat_storage();

        if (status) {
            PAL_LOG_ERR("failed to reformat storage: %d", status);
            return EXIT_FAILURE;
        }
    }
#endif

    // XXX: this function uses the filesystem and it will typically fail if the storage is not initialized.
    palStatus_t getTestStatusReturnValue = getPalTestStatus();
    if (PAL_SUCCESS != getTestStatusReturnValue) 
    {
        PAL_LOG_ERR("%s: Failed to get current status of tests 0x%" PRIX32 "\r\n",__FUNCTION__,getTestStatusReturnValue);
    }

    UnityPrint("*****PAL_TEST_START*****");
    UNITY_PRINT_EOL();

    UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, runAllTests);

    UnityPrint("*****PAL_TEST_END*****");
    UNITY_PRINT_EOL();

    mbed_trace_free();

    // TODO: should this actually return exit_failure if some of the tests failed?!
    return EXIT_SUCCESS;
}

int palAllTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_CONNECTION|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_all_GROUPS_RUNNER, init_flags);
}

int palFileSystemTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_fileSystem_GROUP_RUNNER, init_flags);
}

int palNetworkTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_CONNECTION;
    return palTestMain(TEST_pal_socket_GROUP_RUNNER, init_flags);
}

int palCryptoTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_crypto_GROUP_RUNNER, init_flags);
}

int palDRBGTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE;
    return palTestMain(TEST_pal_drbg_GROUP_RUNNER, init_flags);
}

int palRTOSTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE;
    return palTestMain(TEST_pal_rtos_GROUP_RUNNER, init_flags);
}

int palROTTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE;
    return palTestMain(TEST_pal_rot_GROUP_RUNNER, init_flags);
}

int palEntropyTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE;
    return palTestMain(TEST_pal_entropy_GROUP_RUNNER, init_flags);
}

int palStorageTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE;
    return palTestMain(TEST_pal_internalFlash_GROUP_RUNNER, init_flags);
}

int palSSTTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE | PAL_TEST_PLATFORM_INIT_STORAGE;
    return palTestMain(TEST_pal_sst_GROUP_RUNNER, init_flags);
}

int palTimeTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_time_GROUP_RUNNER, init_flags);
}

int palTLSTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_CONNECTION|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_tls_GROUP_RUNNER, init_flags);
}

int palUpdateTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_update_GROUP_RUNNER, init_flags);
}

int palSOTPTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_SOTP_GROUP_RUNNER, init_flags);
}

int palSanityTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE;
    return palTestMain(TEST_pal_sanity_GROUP_RUNNER, init_flags);
}

int palReformatTestMain(void)
{
    int init_flags = PAL_TEST_PLATFORM_INIT_BASE|PAL_TEST_PLATFORM_INIT_STORAGE|PAL_TEST_PLATFORM_INIT_REFORMAT_STORAGE;
    return palTestMain(TEST_pal_sanity_GROUP_RUNNER, init_flags);
}


