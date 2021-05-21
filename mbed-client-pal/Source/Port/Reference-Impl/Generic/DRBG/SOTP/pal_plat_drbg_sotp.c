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

// This file is compiled when using ESFS and SOTP
#if !defined(MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT) &&  !defined(MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT)


#include "pal.h"
#include "cs_pal_crypto.h"
#include "pal_plat_drbg.h"
#include "pal_plat_drbg_noise.h"
#include "sotp.h"

#include <stdlib.h>

#define TRACE_GROUP "PAL"


//! static variables for Random functionality.
//! CTR-DRBG context to be used for generating random numbers from given seed
static palCtrDrbgCtxHandle_t s_ctrDRBGCtx = NULLPTR;

PAL_PRIVATE bool g_palDRBGInitialized = false;

palStatus_t pal_plat_DRBGInit(void)
{
    palStatus_t status = PAL_SUCCESS;
    if (g_palDRBGInitialized)
    {
        return status;
    }
    status = pal_plat_noiseInit();
    if (PAL_SUCCESS != status)
    {
        PAL_LOG_ERR("pal_plat_DRBGInit: pal_plat_NoiseInit failed, status=%" PRIx32 "\n", status);
    }

    g_palDRBGInitialized = true;

    return status;
}

palStatus_t pal_plat_DRBGDestroy(void)
{
    palStatus_t status = PAL_ERR_NOT_INITIALIZED;
    if (!g_palDRBGInitialized)
    {
        return status;
    }

#if PAL_USE_HW_TRNG
    if (PAL_SUCCESS != pal_plat_noiseDestroy())
    {
        PAL_LOG_ERR("pal_DRBGDestroy: failed to terminate trng noise thread\n");
        // FIXME: return error status?
    }
#endif 
    if (NULLPTR != s_ctrDRBGCtx)
    {
        status = pal_CtrDRBGFree(&s_ctrDRBGCtx);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_ERR("pal_DRBGDestroy: pal_CtrDRBGFree failed, status=%" PRIx32 "\n", status);
        }
    }

    g_palDRBGInitialized = false;
    return status;
}


palStatus_t pal_plat_osRandomBuffer_blocking(uint8_t *randomBuf, size_t bufSizeBytes)
{
    PAL_VALIDATE_ARGUMENTS (NULL == randomBuf);

    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    if (g_palDRBGInitialized == true)
    {
        if (NULLPTR == s_ctrDRBGCtx)
        {
            // XXX: move this to pal_plat_DRBGInit(), no point to do lazy initializations as it is
            // better to fail early on init phase than unexpectedly on a call to pal_osRandomBuffer().
            uint32_t sotpCounter = 0;
            uint8_t buf[(PAL_INITIAL_RANDOM_SIZE * 2 + sizeof(sotpCounter))] PAL_PTR_ADDR_ALIGN_UINT8_TO_UINT32 = { 0 }; // space for 48 bytes short term + 48 bytes long term + 4 counter bytes (note this buffer will also be used to collect TRNG noise)
            const uint16_t sotpLenBytes = PAL_INITIAL_RANDOM_SIZE + sizeof(sotpCounter); // the max number of bytes expected to be read/written form/to sotp, note that sotpCounter will probably be empty the 1st time data is read from sotp
            uint32_t* ptrSotpRead = (uint32_t*)&buf; // pointer to the memory address in buf which will point to the data that will be read from sotp
            uint32_t* ptrSotpWrite = (uint32_t*)&buf[PAL_INITIAL_RANDOM_SIZE]; // pointer to the memory address in buf which will point to the data which needs to be written back to sotp
            uint32_t* ptrSotpCounterRead = ptrSotpWrite; // pointer to the memory address in buf which will point to the counter read from sotp
            uint32_t* ptrSotpCounterWrite = (uint32_t*)&buf[PAL_INITIAL_RANDOM_SIZE * 2]; // pointer to the memory address in buf which will point to the incremented counter which will be written back to sotp
            uint16_t sotpBytesRead = 0, noiseBitsWrittern = 0;
            size_t trngBytesRead = 0;
            palCtrDrbgCtxHandle_t longCtrDRBGCtx = NULLPTR; // long term drbg context            
            palStatus_t tmpStatus;
            sotp_result_e sotpResult = sotp_get(SOTP_TYPE_RANDOM_SEED, sotpLenBytes, ptrSotpRead, &sotpBytesRead); // read 48 drbg bytes + 4 counter bytes
            if (SOTP_SUCCESS == sotpResult)
            {
                if ((PAL_INITIAL_RANDOM_SIZE != sotpBytesRead) && (sotpLenBytes != sotpBytesRead))
                {
                    status = PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT;
                    PAL_LOG_ERR("Invalid number of bytes read from SOTP, bytes read=%" PRIu16, sotpBytesRead);
                    goto finish;
                }
                status = pal_CtrDRBGInit(&longCtrDRBGCtx, ptrSotpRead, PAL_INITIAL_RANDOM_SIZE); // initialize long term drbg with the seed that was read from sotp
                if (PAL_SUCCESS != status)
                {
                    PAL_LOG_ERR("Failed to initialize long term DRBG context, status=%" PRIx32 "\n", status);
                    goto finish;
                }
                memcpy((void*)&sotpCounter, (void*)ptrSotpCounterRead, sizeof(sotpCounter)); // read the counter from the buffer (sotp data) to local var
#if PAL_USE_HW_TRNG
                memset((void*)buf, 0, sizeof(buf));                
                status = pal_plat_osRandomBuffer(buf, PAL_NOISE_SIZE_BYTES, &trngBytesRead);
                if ((PAL_SUCCESS == status) || (PAL_ERR_RTOS_TRNG_PARTIAL_DATA == status))
                {
                    if (0 < trngBytesRead)
                    {
                        tmpStatus = pal_plat_noiseWriteBuffer((int32_t*)buf, (trngBytesRead * CHAR_BIT), &noiseBitsWrittern); // write whatever was collected from trng to the noise buffer
                        PAL_LOG_DBG( "Write TRNG to noise buffer, status=%" PRIx32 ", bits writtern=%" PRIu16 "\n", tmpStatus, noiseBitsWrittern);
                    }
                }
                else
                {
                    PAL_LOG_ERR("Read from TRNG failed, status=%" PRIx32 "\n", status);
                }                
#endif // PAL_USE_HW_TRNG
                memset((void*)buf, 0, sizeof(buf));
                status = pal_plat_generateDrbgWithNoiseAttempt(longCtrDRBGCtx, buf, true, (PAL_INITIAL_RANDOM_SIZE * 2)); // generate 96 bytes, the 1st 48 bytes will be used for short term drbg and the other 48 bytes will be used for long term drbg
                if (PAL_SUCCESS != status)
                {
                    PAL_LOG_ERR("Failed to gererate DRBG long term and short term seeds, status=%" PRIx32 "\n", status);
                    goto drbg_cleanup;
                }
                sotpCounter++; // increment counter before writting it back to sotp
                memcpy((void*)ptrSotpCounterWrite, (void*)&sotpCounter, sizeof(sotpCounter)); // copy the incremented counter to the last 4 bytes of the buffer
                sotpResult = sotp_set(SOTP_TYPE_RANDOM_SEED, sotpLenBytes, ptrSotpWrite); // write 48 long term drbg bytes + 4 counter bytes
                if (SOTP_SUCCESS != sotpResult)
                {
                    PAL_LOG_ERR("Failed to write to SOTP, sotp result=%d", sotpResult);
                    status = PAL_ERR_GENERIC_FAILURE;
                }                
drbg_cleanup:
                {
                    tmpStatus = pal_CtrDRBGFree(&longCtrDRBGCtx);
                    if (PAL_SUCCESS != tmpStatus)
                    {
                        PAL_LOG_ERR("Failed to free long term DRBG context, status=%" PRIx32 "\n", tmpStatus);
                    }
                    longCtrDRBGCtx = NULLPTR;                    
                    if (PAL_SUCCESS != status)
                    {
                        goto finish;
                    }
#if PAL_USE_HW_TRNG
                    status = pal_plat_noiseCreateThread();
                    if (PAL_SUCCESS != status)
                    {
                        PAL_LOG_ERR("Failed to create noise TRNG thread, status=%" PRIx32 "\n", tmpStatus);
                    }
#endif // PAL_USE_HW_TRNG
                }
            }
            else if (SOTP_NOT_FOUND == sotpResult)
            {
#if PAL_USE_HW_TRNG
                memset((void*)buf, 0, sizeof(buf));
                uint8_t* seedPtr = buf;
                size_t randomCounterBytes = 0;
                do
                {
                    status = pal_plat_osRandomBuffer(seedPtr, PAL_INITIAL_RANDOM_SIZE - randomCounterBytes, &trngBytesRead);
                    if (PAL_ERR_RTOS_TRNG_PARTIAL_DATA == status)
                    {
                        pal_osDelay(PAL_TRNG_COLLECT_DELAY_MILLI_SEC); // sleep to let the device to collect random data.
                        randomCounterBytes += trngBytesRead;
                        seedPtr += trngBytesRead;
                    }
                } while (PAL_ERR_RTOS_TRNG_PARTIAL_DATA == status);
#else
                status = PAL_ERR_CTR_DRBG_NOT_SEEDED; // No entropy in SOTP and no TRNG = DRBG not seeded
#endif // PAL_USE_HW_TRNG
            }
            if (PAL_SUCCESS != status)
            {
                goto finish;
            }
            status = pal_CtrDRBGInit(&s_ctrDRBGCtx, (void*)buf, PAL_INITIAL_RANDOM_SIZE);
            if (PAL_SUCCESS != status)
            {
                PAL_LOG_ERR("Failed to initialize short term DRBG context, status=%" PRIx32 "\n", status);
                goto finish;
            }
        }
        status = pal_plat_generateDrbgWithNoiseAttempt(s_ctrDRBGCtx, randomBuf, false, bufSizeBytes);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG_ERR("Failed to generate random, status=%" PRIx32 "\n", status);
        }
    }
    else
    {
        return PAL_ERR_NOT_INITIALIZED;
    }
finish:
    return status;
}



#endif // !MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
