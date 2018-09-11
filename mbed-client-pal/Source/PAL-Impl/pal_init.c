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


#include "pal.h"
#include "pal_plat_network.h"
#include "pal_plat_TLS.h"
#include "pal_plat_Crypto.h"
#include "pal_macros.h"
#include "sotp.h"

#define TRACE_GROUP "PAL"

//this variable must be a int32_t for using atomic increment
PAL_PRIVATE int32_t g_palIntialized = 0;


PAL_PRIVATE void pal_modulesCleanup(void)
{
    DEBUG_PRINT("Destroying modules\r\n");
    pal_plat_socketsTerminate(NULL);
    sotp_deinit();
    pal_plat_cleanupCrypto();
    pal_cleanupTLS();
    pal_fsCleanup();
    #if PAL_USE_INTERNAL_FLASH
        pal_internalFlashDeInit();
    #endif
    pal_RTOSDestroy();
}



palStatus_t pal_init(void)
{

    palStatus_t status = PAL_SUCCESS;
    sotp_result_e sotpStatus = SOTP_SUCCESS;
    int32_t currentInitValue;
    //  get the return value of g_palIntialized+1 to save it locally
    currentInitValue = pal_osAtomicIncrement(&g_palIntialized,1);
    // if increased for the 1st time
    if (1 == currentInitValue)
    {
        DEBUG_PRINT("\nInit for the 1st time, initializing the modules\r\n");
        status = pal_RTOSInitialize(NULL);
        if (PAL_SUCCESS == status)
        {
            DEBUG_PRINT("Network init\r\n");
            status = pal_plat_socketsInit(NULL);
            if (PAL_SUCCESS != status)
            {
                DEBUG_PRINT("init of network module has failed with status %" PRIx32 "\r\n",status);
            }
            else //socket init succeeded
            {
                DEBUG_PRINT("TLS init\r\n");
                status = pal_initTLSLibrary();
                if (PAL_SUCCESS != status)
                {
                    DEBUG_PRINT("init of tls module has failed with status %" PRIx32 "\r\n",status);
                }
                else
                {
                    DEBUG_PRINT("Crypto init\r\n");
                    status = pal_plat_initCrypto();
                    if (PAL_SUCCESS != status)
                    {
                        DEBUG_PRINT("init of crypto module has failed with status %" PRIx32 "\r\n",status);
                    }
                    else
                    {
                        DEBUG_PRINT("Internal Flash init\r\n");
                        #if PAL_USE_INTERNAL_FLASH
                            status = pal_internalFlashInit();
                        #endif
                        if (PAL_SUCCESS != status)
                        {
                            DEBUG_PRINT("init of Internal Flash module has failed with status %" PRIx32 "\r\n",status);
                        }

                        else
                        {
                            DEBUG_PRINT("SOTP init\r\n");
                            sotpStatus = sotp_init();
                            if (SOTP_SUCCESS != sotpStatus)
                            {
                                DEBUG_PRINT("init of SOTP module has failed with status %" PRIx32 "\r\n", (int32_t)sotpStatus);
                                status = PAL_ERR_INIT_SOTP_FAILED;
                            }
                            if (PAL_SUCCESS == status)
                            {
                                status = pal_initTime();
                                if (PAL_SUCCESS != status)
                                {
                                    DEBUG_PRINT("init of Time module has failed with status %" PRIx32 "\r\n",status);
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            DEBUG_PRINT("init of RTOS module has failed with status %" PRIx32 "\r\n",status);
        }

        // if failed decrease the value of g_palIntialized
        if (PAL_SUCCESS != status)
        {
#if PAL_CLEANUP_ON_INIT_FAILURE           
            pal_modulesCleanup();
            pal_osAtomicIncrement(&g_palIntialized, -1);
#endif
            PAL_LOG_ERR("\nInit failed\r\n");
        }
    }

    DEBUG_PRINT("FINISH PAL INIT\r\n");
    return status;
}


int32_t  pal_destroy(void)
{
    int32_t currentInitValue;
    // get the current value of g_palIntialized locally
    currentInitValue = pal_osAtomicIncrement(&g_palIntialized, 0);
    if(currentInitValue != 0)
    {
        currentInitValue = pal_osAtomicIncrement(&g_palIntialized, -1);
        if (0 == currentInitValue)
        {
            pal_modulesCleanup();
        }
    }
    return currentInitValue;
}


