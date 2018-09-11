
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

#include "stdio.h"

#include "PlatIncludes.h"
#include "test_runners.h"
#include "pal_BSP.h"
#include "pal.h"
#include "mbed_trace.h"
#include "unity.h"
#include "unity_fixture.h"

#define TRACE_GROUP "PAL"

extern struct _Unity Unity;

#define PAL_TEST_STATUS_FILE_LOCATION "/tstSts"
#define PAL_TEST_STATUS_FILE_DATA_MAX_SIZE 128

void * g_palTestNetworkInterface = NULL;
void * g_palTestTLSInterfaceCTX = NULL;


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
        case PAL_TEST_MODULE_CRYPTO:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_CRYPTO
                TEST_pal_crypto_GROUP_RUNNER();
            #endif
        case PAL_TEST_MODULE_FILESYSTEM:
            PRINT_MEMORY_STATS;
            #ifndef PAL_SKIP_TEST_MODULE_FILESYSTEM
                TEST_pal_fileSystem_GROUP_RUNNER();
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



void palTestMain(palTestModules_t modules,void* network)
{
	const char * myargv[] = {"app","-v"};
    g_palTestNetworkInterface = network; 
    g_palTestTLSInterfaceCTX = network;
	mbed_trace_init();
	mbed_trace_config_set(PAL_TESTS_LOG_LEVEL);
    palStatus_t getTestStatusReturnValue = getPalTestStatus();
    if (PAL_SUCCESS != getTestStatusReturnValue) 
    {
        PAL_LOG_ERR("%s: Failed to get current status of tests 0x%" PRIu32 "\r\n",__FUNCTION__,getTestStatusReturnValue);
    }

    UnityPrint("*****PAL_TEST_START*****");
    UNITY_PRINT_EOL();
    switch (modules) 
    {
        case PAL_TEST_MODULE_ALL:
        {
	        UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_all_GROUPS_RUNNER);
			break;
        }
        case PAL_TEST_MODULE_SOTP:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_SOTP_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_RTOS:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_rtos_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_SOCKET:
        {
            UnityMain(sizeof(myargv)/ sizeof(myargv[0]), myargv, TEST_pal_socket_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_CRYPTO:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_crypto_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_FILESYSTEM:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_fileSystem_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_UPDATE:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_update_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_INTERNALFLASH:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_internalFlash_GROUP_RUNNER);
            break;
        }

        case PAL_TEST_MODULE_TLS:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_tls_GROUP_RUNNER);
            break;
        }
        
        case PAL_TEST_MODULE_SANITY:
        {
            UnityMain(sizeof(myargv) / sizeof(myargv[0]), myargv, TEST_pal_sanity_GROUP_RUNNER);
            break;
        }

        default:
        {
            UnityPrint("*****ERROR WRONG TEST SUITE WAS CHOOSEN*****");                
            break;
        }

    }
    UnityPrint("*****PAL_TEST_END*****");
    UNITY_PRINT_EOL();

    mbed_trace_free();

}

void palAllTestMain(void* network)
{
    palTestMain(PAL_TEST_MODULE_ALL, network);
}

void palFileSystemTestMain(void* network)
{
    palTestMain(PAL_TEST_MODULE_FILESYSTEM, network);
}

void palNetworkTestMain(void* network)
{
   palTestMain(PAL_TEST_MODULE_SOCKET, network); 
}

void palCryptoTestMain(void* network)
{
   palTestMain(PAL_TEST_MODULE_CRYPTO, network); 
}

void palRTOSTestMain(void* network)
{
   palTestMain(PAL_TEST_MODULE_RTOS, network); 
}

void palStorageTestMain(void* network)
{
   palTestMain(PAL_TEST_MODULE_INTERNALFLASH, network); 
}

void palTLSTestMain(void* network)
{
   palTestMain(PAL_TEST_MODULE_TLS, network); 
}

void palUpdateTestMain(void* network)
{
   palTestMain(PAL_TEST_MODULE_UPDATE, network); 
}

void palSOTPTestMain(void* network)
{
    palTestMain(PAL_TEST_MODULE_SOTP, network); 
}

void palSanityTestMain(void* network)
{
     palTestMain(PAL_TEST_MODULE_SANITY, network); 
}




