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

#include <stdio.h>
#include "pal.h"
#include "pal_plat_rtos.h"
#include "sotp.h"

//! Store the last saved time in SOTP (ram) for quick access
PAL_PRIVATE uint64_t g_lastSavedTimeInSec = 0;

//! static variables for Random functionality.
//! CTR-DRBG context to be used for generating random numbers from given seed
static palCtrDrbgCtxHandle_t s_ctrDRBGCtx = NULLPTR;

PAL_PRIVATE palStatus_t pal_setWeakTimeForward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime);
PAL_PRIVATE palStatus_t pal_setWeakTimeBackward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime);

static uint64_t g_palDeviceBootTimeInSec = 0;

/*
 * Here we define const keys for RoT derivation algorithm.
 * Must be 16 characters or less
 */
#define PAL_STORAGE_SIGNATURE_128_BIT_KEY  "RoTStorageSgn128"
#define PAL_STORAGE_ENCRYPTION_128_BIT_KEY "RoTStorageEnc128"
#define PAL_STORAGE_ENCRYPTION_256_BIT_KEY "StorageEnc256HMACSHA256SIGNATURE"

PAL_PRIVATE bool palRTOSInitialized = false;

#if (PAL_SIMULATE_RTOS_REBOOT == 1)
    #include <unistd.h>
    extern char *program_invocation_name;
#endif

#define PAL_NOISE_WAIT_FOR_WRITERS_DELAY_MILLI_SEC 1
#define PAL_NOISE_BITS_TO_BYTES(x) (x / CHAR_BIT)

typedef struct palNoise
{
    int32_t buffer[PAL_NOISE_BUFFER_LEN];
    volatile uint32_t bitCountAllocated;
    volatile uint32_t bitCountActual;
    volatile uint32_t numWriters;
    volatile bool isReading;
} palNoise_t;

PAL_PRIVATE palNoise_t g_noise;

palStatus_t pal_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten); // forward declaration
palStatus_t pal_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead); // forward declaration

#if PAL_USE_HW_TRNG
    PAL_PRIVATE palThreadID_t g_trngThreadID = NULLPTR;
#endif

extern palStatus_t pal_plat_CtrDRBGGenerateWithAdditional(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len, unsigned char* additional, size_t additionalLen);

//Error Translation from SOTP module to PAL
PAL_PRIVATE palStatus_t pal_osSotpErrorTranslation(sotp_result_e err)
{
    palStatus_t ret;
    switch(err)
    {
        case SOTP_BAD_VALUE:
            ret = PAL_ERR_INVALID_ARGUMENT;
            break;

        case SOTP_BUFF_TOO_SMALL:
            ret = PAL_ERR_BUFFER_TOO_SMALL;
            break;

        case SOTP_BUFF_NOT_ALIGNED:
            ret = PAL_ERR_RTOS_BUFFER_NOT_ALIGNED;
            break;

        case SOTP_READ_ERROR:
        case SOTP_DATA_CORRUPT:
        case SOTP_OS_ERROR:
        default:
            ret = PAL_ERR_GENERIC_FAILURE;
            break;
    }
    return ret;
}

palStatus_t pal_RTOSInitialize(void* opaqueContext)
{
    palStatus_t status = PAL_SUCCESS;
    if (palRTOSInitialized)
    {
        return status;
    }

    status = pal_plat_RTOSInitialize(opaqueContext);
    if (PAL_SUCCESS == status)
    {
        memset(g_noise.buffer, 0, PAL_NOISE_SIZE_BYTES);
        g_noise.bitCountActual = g_noise.bitCountAllocated = 0;
        g_noise.numWriters = 0;
        g_noise.isReading = false;
#if PAL_USE_HW_TRNG
        g_trngThreadID = NULLPTR;
#endif
        palRTOSInitialized = true;
    }
    else
    {
        PAL_LOG(ERR, "pal_RTOSInitialize: pal_plat_RTOSInitialize failed, status=%" PRIx32 "\n", status);
    }
    return status;
}

palStatus_t pal_RTOSDestroy(void)
{
    palStatus_t status = PAL_ERR_NOT_INITIALIZED;
    if (!palRTOSInitialized)
    {
        return status;
    }

#if PAL_USE_HW_TRNG
    if (NULLPTR != g_trngThreadID)
    {
        if (PAL_SUCCESS != pal_osThreadTerminate(&g_trngThreadID))
        {
            PAL_LOG(ERR, "pal_RTOSDestroy: failed to terminate trng noise thread\n");
        }
    }
#endif

    if (NULLPTR != s_ctrDRBGCtx)
    {
        status = pal_CtrDRBGFree(&s_ctrDRBGCtx);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG(ERR, "pal_RTOSDestroy: pal_CtrDRBGFree failed, status=%" PRIx32 "\n", status);
        }
    }

    status = pal_plat_RTOSDestroy();
    if (PAL_SUCCESS != status)
    {
        PAL_LOG(ERR, "pal_RTOSDestroy: pal_plat_RTOSDestroy failed, status=%" PRIx32 "\n", status);
    }
    palRTOSInitialized = false;
    return status;
}

void pal_osReboot(void)
{
    PAL_LOG(INFO, "pal_osReboot\r\n");
#if (PAL_USE_APPLICATION_REBOOT)
    pal_plat_osApplicationReboot();
#else
    //Simulator is currently for Linux only
    #if (PAL_SIMULATE_RTOS_REBOOT == 1)
        const char *argv[] = {"0" , 0};
        char *const envp[] = { 0 };
        argv[0] = program_invocation_name;

        PAL_LOG(INFO, "pal_osReboot -> simulated reboot with execve(%s).\r\n", argv[0]);
  
        if (-1 == execve(argv[0], (char **)argv , envp))
        {
            PAL_LOG(ERR,"child process execve failed [%s]",argv[0]);
        }
    #else
        PAL_LOG(INFO, "Rebooting the system\r\n");
        pal_plat_osReboot();
    #endif
#endif
}

uint64_t pal_osKernelSysTick(void)
{
    static uint64_t lastValue = 0;
    static uint64_t wraparoundsDetected = 0;
    const uint64_t one = 1;
    uint64_t tics = pal_plat_osKernelSysTick();
    uint64_t tmp = tics + (wraparoundsDetected << 32);

    if (tmp < lastValue) //erez's "wraparound algorithm" if we detect a wrap around add 1 to the higher 32 bits
    {
        tmp = tmp + (one << 32);
        wraparoundsDetected++;
    }
    lastValue = tmp;
    return (uint64_t)tmp;
}

uint64_t pal_osKernelSysTickMicroSec(uint64_t microseconds)
{
    uint64_t result;
    result = pal_plat_osKernelSysTickMicroSec(microseconds);
    return result;
}

uint64_t pal_osKernelSysMilliSecTick(uint64_t sysTicks)
{
    uint64_t result = 0;
    uint64_t osTickFreq = pal_plat_osKernelSysTickFrequency();
    if ((sysTicks) && (osTickFreq)) // > 0
    {
        result = (uint64_t)((sysTicks) * PAL_TICK_TO_MILLI_FACTOR / osTickFreq); //convert ticks per second to milliseconds
    }

    return result;
}

uint64_t pal_osKernelSysTickFrequency(void)
{
    uint64_t result;
    result = pal_plat_osKernelSysTickFrequency();
    return result;
}

palStatus_t pal_osThreadCreateWithAlloc(palThreadFuncPtr function, void* funcArgument, palThreadPriority_t priority, uint32_t stackSize, palThreadLocalStore_t* store, palThreadID_t* threadID)
{
    PAL_VALIDATE_ARGUMENTS((NULL == function) || (PAL_osPrioritylast < priority) || (PAL_osPriorityError == priority) || (0 == stackSize) || (NULL == threadID));
    if (store)
    {
        PAL_LOG(ERR, "thread storage in not supported\n");
        return PAL_ERR_NOT_SUPPORTED;
    }
    palStatus_t status = pal_plat_osThreadCreate(function, funcArgument, priority, stackSize, threadID);
    return status;
}

palStatus_t pal_osThreadTerminate(palThreadID_t* threadID)
{
    PAL_VALIDATE_ARGUMENTS ((NULL == threadID) || (PAL_INVALID_THREAD == *threadID));
    palStatus_t status = pal_plat_osThreadTerminate(threadID);
    return status;
}

palThreadID_t pal_osThreadGetId(void)
{
    palThreadID_t threadID = pal_plat_osThreadGetId();
    return threadID;
}

palStatus_t pal_osDelay(uint32_t milliseconds)
{
    palStatus_t status;
    status = pal_plat_osDelay(milliseconds);
    return status;
}

palStatus_t pal_osTimerCreate(palTimerFuncPtr function, void* funcArgument, palTimerType_t timerType, palTimerID_t* timerID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == timerID || NULL == function);
    palStatus_t status;
    status = pal_plat_osTimerCreate(function, funcArgument, timerType, timerID);
    return status;
}

palStatus_t pal_osTimerStart(palTimerID_t timerID, uint32_t millisec)
{
    PAL_VALIDATE_ARGUMENTS (NULLPTR == timerID);
    palStatus_t status;
    if (0 == millisec)
    {
        return PAL_ERR_RTOS_VALUE;
    }
    status = pal_plat_osTimerStart(timerID, millisec);
    return status;
}

palStatus_t pal_osTimerStop(palTimerID_t timerID)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == timerID);
    palStatus_t status;
    status = pal_plat_osTimerStop(timerID);
    return status;
}

palStatus_t pal_osTimerDelete(palTimerID_t* timerID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == timerID || NULLPTR == *timerID);
    palStatus_t status;
    status = pal_plat_osTimerDelete(timerID);
    return status;
}

palStatus_t pal_osMutexCreate(palMutexID_t* mutexID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == mutexID);
    palStatus_t status;
    status = pal_plat_osMutexCreate(mutexID);
    return status;
}

palStatus_t pal_osMutexWait(palMutexID_t mutexID, uint32_t millisec)
{
    PAL_VALIDATE_ARGUMENTS((NULLPTR == mutexID));
    palStatus_t status;
    status = pal_plat_osMutexWait(mutexID, millisec);
    return status;
}

palStatus_t pal_osMutexRelease(palMutexID_t mutexID)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == mutexID);
    palStatus_t status;
    status = pal_plat_osMutexRelease(mutexID);
    return status;
}

palStatus_t pal_osMutexDelete(palMutexID_t* mutexID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == mutexID || NULLPTR == *mutexID);
    palStatus_t status;
    status = pal_plat_osMutexDelete(mutexID);
    return status;
}

palStatus_t pal_osSemaphoreCreate(uint32_t count, palSemaphoreID_t* semaphoreID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreCreate(count, semaphoreID);
    return status;
}

palStatus_t pal_osSemaphoreWait(palSemaphoreID_t semaphoreID, uint32_t millisec,  int32_t* countersAvailable)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreWait(semaphoreID, millisec, countersAvailable);
    return status;
}

palStatus_t pal_osSemaphoreRelease(palSemaphoreID_t semaphoreID)
{
    PAL_VALIDATE_ARGUMENTS(NULLPTR == semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreRelease(semaphoreID);
    return status;
}

palStatus_t pal_osSemaphoreDelete(palSemaphoreID_t* semaphoreID)
{
    PAL_VALIDATE_ARGUMENTS(NULL == semaphoreID || NULLPTR == *semaphoreID);
    palStatus_t status;
    status = pal_plat_osSemaphoreDelete(semaphoreID);
    return status;
}


int32_t pal_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
    PAL_VALIDATE_ARGUMENTS(NULL == valuePtr);
    int32_t result;
    result = pal_plat_osAtomicIncrement(valuePtr, increment);
    return result;
}


PAL_PRIVATE uint64_t pal_sysTickTimeToSec()
{
	uint64_t sysTicksFromBoot = pal_osKernelSysTick();
	uint64_t secFromBoot = pal_osKernelSysMilliSecTick(sysTicksFromBoot) / PAL_MILLI_PER_SECOND;

	return secFromBoot;
}

uint64_t pal_osGetTime(void)
{
    uint64_t curSysTimeInSec = 0;
	if (0 < g_palDeviceBootTimeInSec) //time was previously set
	{
		uint64_t secFromBoot = pal_sysTickTimeToSec();
		curSysTimeInSec = g_palDeviceBootTimeInSec + secFromBoot; //boot time in sec + sec passed since boot

		if((curSysTimeInSec > g_lastSavedTimeInSec) && (curSysTimeInSec - g_lastSavedTimeInSec > PAL_LAST_SAVED_TIME_LATENCY_SEC))
		{
            sotp_result_e status = SOTP_SUCCESS;
            status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&curSysTimeInSec);
            if (SOTP_SUCCESS != status)
            {
                PAL_LOG(ERR,"SOTP set time failed \n");  
            }
            else
            {
                g_lastSavedTimeInSec = curSysTimeInSec;
            }
                     
		}
	}

	return curSysTimeInSec;
}

palStatus_t pal_osSetTime(uint64_t seconds)
{
	palStatus_t status = PAL_SUCCESS;
	if(0 == seconds)
	{
	    g_palDeviceBootTimeInSec = 0;
	}
	else if (seconds < (uint64_t)PAL_MIN_SEC_FROM_EPOCH)
	{
		status = PAL_ERR_INVALID_TIME;
	}
	else
	{
		uint64_t secFromBoot = pal_sysTickTimeToSec();
		g_palDeviceBootTimeInSec = seconds - secFromBoot; //update device boot time
	}

	return status;
}



#if PAL_USE_HW_TRNG
PAL_PRIVATE void pal_trngNoiseThreadFunc(void const* arg)
{
    uint8_t buf[PAL_NOISE_SIZE_BYTES] PAL_PTR_ADDR_ALIGN_UINT8_TO_UINT32 = { 0 };
    size_t trngBytesRead = 0;
    uint16_t noiseBitsWritten = 0;
    palStatus_t status;
    while (true)
    {
        status = pal_plat_osRandomBuffer(buf, PAL_NOISE_SIZE_BYTES, &trngBytesRead);
        if ((0 < trngBytesRead) && ((PAL_SUCCESS == status) || (PAL_ERR_RTOS_TRNG_PARTIAL_DATA == status)))
        {
            noiseBitsWritten = 0;
            status = pal_noiseWriteBuffer((int32_t*)buf, (trngBytesRead * CHAR_BIT), &noiseBitsWritten);            
        }
        pal_osDelay(PAL_NOISE_TRNG_THREAD_DELAY_MILLI_SEC);
    }
}
#endif // PAL_USE_HW_TRNG


// this function generates drbg with the possibility of adding noise as additional input to the drbg function.
PAL_PRIVATE palStatus_t pal_generateDrbgWithNoiseAttempt(palCtrDrbgCtxHandle_t drbgContext, uint8_t* outBuffer, bool partial, size_t numBytesToGenerate)
{
    uint16_t bitsRead = 0;
    int32_t buffer[PAL_NOISE_BUFFER_LEN] = { 0 };
    palStatus_t status = pal_noiseRead(buffer, partial, &bitsRead);
    if (PAL_SUCCESS == status)
    {
        status = pal_plat_CtrDRBGGenerateWithAdditional(drbgContext, (unsigned char*)outBuffer, numBytesToGenerate, (unsigned char*)buffer, (size_t)PAL_NOISE_BITS_TO_BYTES(bitsRead));
    }
    else
    {
        status = pal_CtrDRBGGenerate(drbgContext, (unsigned char*)outBuffer, numBytesToGenerate);
    }
    return status;
}

palStatus_t pal_osRandomBuffer(uint8_t *randomBuf, size_t bufSizeBytes)
{
    PAL_VALIDATE_ARGUMENTS (NULL == randomBuf);

    palStatus_t status = PAL_ERR_GENERIC_FAILURE;
    if (palRTOSInitialized == true)
    {
        if (NULLPTR == s_ctrDRBGCtx)
        {
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
                    PAL_LOG(ERR, "Invalid number of bytes read from sotp, bytes read=%" PRIu16, sotpBytesRead);
                    goto finish;
                }
                status = pal_CtrDRBGInit(&longCtrDRBGCtx, ptrSotpRead, PAL_INITIAL_RANDOM_SIZE); // initialize long term drbg with the seed that was read from sotp
                if (PAL_SUCCESS != status)
                {
                    PAL_LOG(ERR, "Failed to initialize long term drbg context, status=%" PRIx32 "\n", status);
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
                        tmpStatus = pal_noiseWriteBuffer((int32_t*)buf, (trngBytesRead * CHAR_BIT), &noiseBitsWrittern); // write whatever was collected from trng to the noise buffer
                        PAL_LOG(DBG, "Write trng to noise buffer, status=%" PRIx32 ", bits writtern=%" PRIu16 "\n", tmpStatus, noiseBitsWrittern);
                    }
                }
                else
                {
                    PAL_LOG(ERR, "Read from TRNG failed, status=%" PRIx32 "\n", status);
                }                
#endif // PAL_USE_HW_TRNG
                memset((void*)buf, 0, sizeof(buf));
                status = pal_generateDrbgWithNoiseAttempt(longCtrDRBGCtx, buf, true, (PAL_INITIAL_RANDOM_SIZE * 2)); // generate 96 bytes, the 1st 48 bytes will be used for short term drbg and the other 48 bytes will be used for long term drbg
                if (PAL_SUCCESS != status)
                {
                    PAL_LOG(ERR, "Failed to gererate drbg long term and short term seeds, status=%" PRIx32 "\n", status);
                    goto drbg_cleanup;
                }
                sotpCounter++; // increment counter before writting it back to sotp
                memcpy((void*)ptrSotpCounterWrite, (void*)&sotpCounter, sizeof(sotpCounter)); // copy the incremented counter to the last 4 bytes of the buffer
                sotpResult = sotp_set(SOTP_TYPE_RANDOM_SEED, sotpLenBytes, ptrSotpWrite); // write 48 long term drbg bytes + 4 counter bytes
                if (SOTP_SUCCESS != sotpResult)
                {
                    PAL_LOG(ERR, "Failed to write to sotp, sotp result=%d", sotpResult);
                    status = PAL_ERR_GENERIC_FAILURE;
                }                
drbg_cleanup:
                {
                    tmpStatus = pal_CtrDRBGFree(&longCtrDRBGCtx);
                    if (PAL_SUCCESS != tmpStatus)
                    {
                        PAL_LOG(ERR, "Failed to free long term drbg context, status=%" PRIx32 "\n", tmpStatus);
                    }
                    longCtrDRBGCtx = NULLPTR;                    
                    if (PAL_SUCCESS != status)
                    {
                        goto finish;
                    }
#if PAL_USE_HW_TRNG
                    status = pal_osThreadCreateWithAlloc(pal_trngNoiseThreadFunc, NULL, PAL_osPriorityReservedTRNG, PAL_NOISE_TRNG_THREAD_STACK_SIZE, NULL, &g_trngThreadID);
                    if (PAL_SUCCESS != status)
                    {
                        PAL_LOG(ERR, "Failed to create noise trng thread, status=%" PRIx32 "\n", tmpStatus);
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
#endif // PAL_USE_HW_TRNG
            }
            if (PAL_SUCCESS != status)
            {
                goto finish;
            }
            status = pal_CtrDRBGInit(&s_ctrDRBGCtx, (void*)buf, PAL_INITIAL_RANDOM_SIZE);
            if (PAL_SUCCESS != status)
            {
                PAL_LOG(ERR, "Failed to initialize short term drbg context, status=%" PRIx32 "\n", status);
                goto finish;
            }
        }
        status = pal_generateDrbgWithNoiseAttempt(s_ctrDRBGCtx, randomBuf, false, bufSizeBytes);
        if (PAL_SUCCESS != status)
        {
            PAL_LOG(ERR, "Failed to gererate random, status=%" PRIx32 "\n", status);
        }
    }
    else
    {
        return PAL_ERR_NOT_INITIALIZED;
    }
finish:
    return status;
}

palStatus_t pal_osRandom32bit(uint32_t *random)
{
    palStatus_t status = PAL_SUCCESS;

    PAL_VALIDATE_ARGUMENTS(NULL == random);
        
    status = pal_osRandomBuffer((uint8_t*)random, sizeof(uint32_t));
    return status;
}


PAL_PRIVATE palStatus_t pal_osGetRoT(uint8_t * key,size_t keyLenBytes)
{
    palStatus_t palStatus = PAL_SUCCESS;
#if (PAL_USE_HW_ROT)
    palStatus = pal_plat_osGetRoTFromHW(key, keyLenBytes);
#else
    sotp_result_e sotpStatus = SOTP_SUCCESS;
    uint16_t actual_size;
    sotpStatus = sotp_get(SOTP_TYPE_ROT, keyLenBytes, (uint32_t *)key, &actual_size);
    if (SOTP_NOT_FOUND == sotpStatus) 
    {
        palStatus = pal_osRandomBuffer(key , keyLenBytes);
        if (PAL_SUCCESS == palStatus) 
        {
            sotpStatus = sotp_set(SOTP_TYPE_ROT,keyLenBytes, (uint32_t *)key);
        }
    }
    if (SOTP_SUCCESS != sotpStatus)
    {
        palStatus = pal_osSotpErrorTranslation(sotpStatus);
    }
#endif
    return palStatus;
}

palStatus_t pal_osGetDeviceKey(palDevKeyType_t keyType, uint8_t *key, size_t keyLenBytes)
{
	palStatus_t status = PAL_SUCCESS;
    uint8_t rotBuffer[PAL_DEVICE_KEY_SIZE_IN_BYTES] __attribute__ ((aligned(4))) = {0};

    
	PAL_VALIDATE_CONDITION_WITH_ERROR(((keyLenBytes < PAL_DEVICE_KEY_SIZE_IN_BYTES) || ((palOsStorageHmacSha256 == keyType) && (keyLenBytes < PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES))),PAL_ERR_BUFFER_TOO_SMALL)

	PAL_VALIDATE_CONDITION_WITH_ERROR ((NULL == key),PAL_ERR_NULL_POINTER)

    status = pal_osGetRoT(rotBuffer, keyLenBytes);
	if (PAL_SUCCESS == status)
	{   // Logic of RoT according to key type using 128 bit strong Key Derivation Algorithm

#if (PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC == 1) //calculate the key derivation in an old way
        switch(keyType)
        {
            case palOsStorageEncryptionKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char*)PAL_STORAGE_ENCRYPTION_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageSignatureKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char *)PAL_STORAGE_SIGNATURE_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageHmacSha256:
            {
                size_t outputLenInBytes = 0;
                status = pal_mdHmacSha256((const unsigned char *)PAL_STORAGE_ENCRYPTION_256_BIT_KEY, PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES, (const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, key, &outputLenInBytes);
                break;
            }
            default:
                status = PAL_ERR_GET_DEV_KEY;
        } //switch end
#else //calculate the key derivation in a new way
        switch(keyType)
        {
            case palOsStorageEncryptionKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)PAL_STORAGE_ENCRYPTION_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);
                break;
            }
            case palOsStorageSignatureKey128Bit:
            {
                //USE strong KDF here!
                status = pal_cipherCMAC((const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BITS, (const unsigned char *)PAL_STORAGE_SIGNATURE_128_BIT_KEY, PAL_DEVICE_KEY_SIZE_IN_BYTES, key);                
                break;
            }
            case palOsStorageHmacSha256:
            {
                size_t outputLenInBytes = 0;
                status = pal_mdHmacSha256((const unsigned char*)rotBuffer, PAL_DEVICE_KEY_SIZE_IN_BYTES, (const unsigned char *)PAL_STORAGE_ENCRYPTION_256_BIT_KEY, PAL_SHA256_DEVICE_KEY_SIZE_IN_BYTES, key, &outputLenInBytes);                
                break;
            }
            default:
                status = PAL_ERR_GET_DEV_KEY;
        } //switch end
#endif        

	} // outer if
    else
    {
        status = PAL_ERR_GET_DEV_KEY;
    }

	return status;

}

palStatus_t pal_initTime(void)
{
    uint64_t rtcTime = 0;
    uint64_t sotpGetTime = 0, sotpLastTimeBack = 0;
    palStatus_t ret = PAL_SUCCESS;
    sotp_result_e status = SOTP_SUCCESS;
    uint16_t actualLenBytes = 0;

    status = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t*)&sotpGetTime, &actualLenBytes);
    if ((SOTP_SUCCESS != status) && (SOTP_NOT_FOUND != status))
    {
        ret = pal_osSotpErrorTranslation(status);
    }
    else if ((sizeof(uint64_t) != actualLenBytes) && (SOTP_NOT_FOUND != status))
    {
        ret = PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT;
    }

    status = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t*)&sotpLastTimeBack, &actualLenBytes);
    if ((SOTP_SUCCESS != status) && (SOTP_NOT_FOUND != status))
    {
        ret = pal_osSotpErrorTranslation(status);
    }
    else if ((sizeof(uint64_t) != actualLenBytes) && (SOTP_NOT_FOUND != status))
    {
        ret = PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT;
    }

    if (sotpLastTimeBack > sotpGetTime)
    {//Enter here only when reset occurs during set weak or strong time
        status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&sotpLastTimeBack);
        if (SOTP_SUCCESS != status)
        {
            ret = pal_osSotpErrorTranslation(status);
        }
        sotpGetTime = sotpLastTimeBack;
    }
    g_lastSavedTimeInSec = sotpGetTime;

#if (PAL_USE_HW_RTC)
    if (PAL_SUCCESS == ret)
    {
        ret = pal_plat_osGetRtcTime(&rtcTime);
    }
#endif

    if (PAL_SUCCESS == ret)
    {//set the max time as boot time of the device
       pal_osSetTime(PAL_MAX(rtcTime, sotpGetTime));
    }
    return ret;
}


palStatus_t pal_osSetStrongTime(uint64_t setNewTimeInSeconds)
{
    palStatus_t ret = PAL_SUCCESS;

    uint64_t getSotpTimeValue = 0;
    uint16_t actualLenBytes = 0;
    sotp_result_e status = SOTP_SUCCESS;
    
#if (PAL_USE_HW_RTC)
    //RTC Time Latency
    if (PAL_SUCCESS == ret)
    {
        uint64_t getRtcTimeValue = 0;
        ret = pal_plat_osGetRtcTime(&getRtcTimeValue);
        if (PAL_SUCCESS == ret)
        {
            if(llabs(setNewTimeInSeconds - getRtcTimeValue) > PAL_MINIMUM_RTC_LATENCY_SEC)
            {
                ret = pal_plat_osSetRtcTime(setNewTimeInSeconds);
            }
        }
    }
#endif

    status = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&getSotpTimeValue, &actualLenBytes);
    if ((SOTP_SUCCESS != status) && (SOTP_NOT_FOUND != status))
    {
        ret = pal_osSotpErrorTranslation(status);
    }
    else if ((sizeof(uint64_t) != actualLenBytes) && (SOTP_NOT_FOUND != status))
    {
        ret = PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT;
    }    
    else if (((setNewTimeInSeconds > getSotpTimeValue) && (setNewTimeInSeconds - getSotpTimeValue > PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC)) //Forward Time
            || ((setNewTimeInSeconds < getSotpTimeValue) && (getSotpTimeValue - setNewTimeInSeconds > PAL_MINIMUM_SOTP_BACKWARD_LATENCY_SEC))) //Backward Time
    {
        status = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&setNewTimeInSeconds);
        if (SOTP_SUCCESS != status)
        {
            ret = pal_osSotpErrorTranslation(status);
        }
        else
        {            
            status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setNewTimeInSeconds);
            if (SOTP_SUCCESS != status)
            {
                ret = pal_osSotpErrorTranslation(status);
            }
            g_lastSavedTimeInSec = setNewTimeInSeconds;
        }
    }

    if(PAL_SUCCESS == ret)
    {
       ret = pal_osSetTime(setNewTimeInSeconds); //Save new time to RAM
    }

    return ret;
}

PAL_PRIVATE palStatus_t pal_setWeakTimeForward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime)
{
    sotp_result_e status = SOTP_SUCCESS;
    palStatus_t ret = PAL_SUCCESS;

    ret = pal_osSetTime(setNewTimeInSeconds); //Save new time to RAM
#if (PAL_USE_HW_RTC)
    //RTC Time Forward
    if (PAL_SUCCESS == ret)
    {
        uint64_t getRtcTimeValue = 0;
        ret = pal_plat_osGetRtcTime(&getRtcTimeValue);
        if (PAL_SUCCESS == ret)
        {
            if((setNewTimeInSeconds > getRtcTimeValue) && (setNewTimeInSeconds - getRtcTimeValue > PAL_MINIMUM_RTC_LATENCY_SEC))
            {
                ret = pal_plat_osSetRtcTime(setNewTimeInSeconds);
            }
        }
    }
#endif// (PAL_USE_HW_RTC)

    if ((setNewTimeInSeconds - currentOsTime > PAL_MINIMUM_SOTP_FORWARD_LATENCY_SEC) && (PAL_SUCCESS == ret))
    {//SOTP time forward
        status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setNewTimeInSeconds);
        if (SOTP_SUCCESS != status)
        {
            ret = pal_osSotpErrorTranslation(status);
        }
        else
        {
            g_lastSavedTimeInSec = setNewTimeInSeconds;
        }
    }
    return ret;
}

PAL_PRIVATE palStatus_t pal_setWeakTimeBackward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime)
{
    uint64_t getSotpTimeValue = 0;
    uint16_t actualLenBytes = 0;
    sotp_result_e status = SOTP_SUCCESS;
    palStatus_t ret = PAL_SUCCESS;

    status = sotp_get(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&getSotpTimeValue, &actualLenBytes);
    if ((SOTP_SUCCESS != status) && (SOTP_NOT_FOUND != status))
    {
        ret = pal_osSotpErrorTranslation(status);
    }
    else if ((sizeof(uint64_t) != actualLenBytes) && (SOTP_NOT_FOUND != status))
    {
        ret = PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT;
    }
    else if (setNewTimeInSeconds > getSotpTimeValue)
    {
        if ((setNewTimeInSeconds - getSotpTimeValue) / PAL_RATIO_SECONDS_PER_DAY  > (currentOsTime - setNewTimeInSeconds))
        {
            status = sotp_set(SOTP_TYPE_LAST_TIME_BACK, sizeof(uint64_t), (uint32_t *)&setNewTimeInSeconds);
            if (SOTP_SUCCESS != status)
            {
                ret = pal_osSotpErrorTranslation(status);
            }
            else
            {               
                status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setNewTimeInSeconds);
                if (SOTP_SUCCESS != status)
                {
                    ret = pal_osSotpErrorTranslation(status);
                }
                else
                {
                    g_lastSavedTimeInSec = setNewTimeInSeconds;
                    ret = pal_osSetTime(setNewTimeInSeconds); //Save new time to RAM
                }
            }
        }
    }

    return ret;
}

palStatus_t pal_osSetWeakTime(uint64_t setNewTimeInSeconds)
{
    uint64_t getSotpTimeValue = 0;
    uint16_t actualLenBytes = 0;
    sotp_result_e status = SOTP_SUCCESS;
    palStatus_t ret = PAL_SUCCESS;
    uint64_t getOsTimeValue = 0;
    
    getOsTimeValue = pal_osGetTime(); //get current system time

    if (setNewTimeInSeconds > getOsTimeValue)
    {//Time Forward
        ret = pal_setWeakTimeForward(setNewTimeInSeconds, getOsTimeValue);
    }
    else if (getOsTimeValue > setNewTimeInSeconds)
    {//Time Backward
        ret = pal_setWeakTimeBackward(setNewTimeInSeconds, getOsTimeValue);
    }

    if(PAL_SUCCESS == ret)
    {
        getSotpTimeValue = 0;
        status = sotp_get(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&getSotpTimeValue, &actualLenBytes);
        if ((SOTP_SUCCESS != status) && (SOTP_NOT_FOUND != status))
        {
            ret = pal_osSotpErrorTranslation(status);
        }
        else if ((sizeof(uint64_t) != actualLenBytes) && (SOTP_NOT_FOUND != status))
        {
            ret = PAL_ERR_RTOS_RECEIVED_LENGTH_IS_TOO_SHORT;
        }
        else if ((setNewTimeInSeconds > getSotpTimeValue) && (setNewTimeInSeconds - getSotpTimeValue > PAL_MINIMUM_STORAGE_LATENCY_SEC))
        {
            status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&setNewTimeInSeconds);
            if (SOTP_SUCCESS != status)
            {
                ret = pal_osSotpErrorTranslation(status);
            }
            else
            {
                g_lastSavedTimeInSec = setNewTimeInSeconds;
            }
        }
    }
    return ret;
}

/*! Write a value (either all or specific bits) to the global noise buffer
*
* @param[in] data The value containing the bits to be written.
* @param[in] startBit The index of the first bit to be written, valid values are 0-31.
* @param[in] lenBits The number of bits that should be written (startBit+lenBits must be less than 32).
* @param[out] bitsWritten The number of bits that were actually written.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_noiseWriteValue(const int32_t* data, uint8_t startBit, uint8_t lenBits, uint8_t* bitsWritten)
{
    PAL_VALIDATE_ARGUMENTS((NULL == data) || (PAL_INT32_BITS - 1 < startBit) || (PAL_INT32_BITS < lenBits + startBit) || (NULL == bitsWritten));

    palStatus_t status = PAL_SUCCESS;
    uint16_t incrementedBitCount;
    uint8_t currentIndex, occupiedBitsInCurrentIndex, availableBitsInCurrentIndex;
    uint32_t mask, value;

    *bitsWritten = 0;
    if (PAL_NOISE_SIZE_BITS == g_noise.bitCountActual)
    {
        return PAL_ERR_RTOS_NOISE_BUFFER_FULL;
    }

    pal_osAtomicIncrement((int32_t*)(&g_noise.numWriters), 1); // increment number of writers
    if (g_noise.isReading) // if we're in read mode then discard & exit
    {
        status = PAL_ERR_RTOS_NOISE_BUFFER_IS_READING;
        goto finish;
    }

    incrementedBitCount = (uint16_t)pal_osAtomicIncrement((int32_t*)(&g_noise.bitCountAllocated), lenBits); // reserve space in the array
    if (PAL_NOISE_SIZE_BITS < incrementedBitCount) // we want to write more bits than are available in the (entire) buffer
    {
        lenBits -= incrementedBitCount - PAL_NOISE_SIZE_BITS; // max number of bits that are avialable for writing
        if ((int8_t)lenBits <= 0) // we don't have any available bits for writing
        {
            status = PAL_ERR_RTOS_NOISE_BUFFER_FULL;
            goto finish;
        }
        incrementedBitCount = PAL_NOISE_SIZE_BITS;
    }

    currentIndex = (incrementedBitCount - lenBits) / PAL_INT32_BITS; // the current index in the array
    occupiedBitsInCurrentIndex = (incrementedBitCount - lenBits) % PAL_INT32_BITS; // how many bits are already occupied (with either 0 or 1) in the current index
    availableBitsInCurrentIndex = PAL_INT32_BITS - occupiedBitsInCurrentIndex; // how many bits are available in the current index

    if (lenBits > availableBitsInCurrentIndex) // we want to write more bits than are available in the current index so we need to split the bits
    {
        mask = ((((int32_t)1) << availableBitsInCurrentIndex) - 1) << startBit; // mask to isolate the wanted bits
        value = *data & mask;
        if (((int8_t)(startBit - occupiedBitsInCurrentIndex)) > 0)
        {
            value = value >> (startBit - occupiedBitsInCurrentIndex);
        }
        else if (((int8_t)(startBit - occupiedBitsInCurrentIndex)) < 0)
        {
            value = value << (occupiedBitsInCurrentIndex - startBit);
        }
        pal_osAtomicIncrement(&g_noise.buffer[currentIndex], value); // write the 1st part of the splitted bits to the current index of the noise buffer
        *bitsWritten = availableBitsInCurrentIndex;
        lenBits -= availableBitsInCurrentIndex; // how many bits remain to be written
        startBit += availableBitsInCurrentIndex;
        mask = ((((int32_t)1) << lenBits) - 1) << startBit; // mask for the remaining bits that have not been written yet
        value = *data & mask;
        value = value >> startBit; // since we're writting to the next index we start at bit 0
        pal_osAtomicIncrement(&g_noise.buffer[currentIndex + 1], value); // write the 2nd part of the splitted bits to the next index of the noise buffer
        *bitsWritten += lenBits;
    }
    else // we have enough available bits for the current index (no need to split the bits)
    {
        mask = ((((int64_t)1) << lenBits) - 1) << startBit; // int64_t in case we want all the 32 bits
        value = *data & mask;
        if (((int8_t)(startBit - occupiedBitsInCurrentIndex)) > 0)
        {
            value = value >> (startBit - occupiedBitsInCurrentIndex);
        }
        else if (((int8_t)(startBit - occupiedBitsInCurrentIndex)) < 0)
        {
            value = value << (occupiedBitsInCurrentIndex - startBit);
        }
        pal_osAtomicIncrement(&g_noise.buffer[currentIndex], value); // write the bits to the current index of the noise buffer
        *bitsWritten = lenBits;
    }
    pal_osAtomicIncrement((int32_t*)(&g_noise.bitCountActual) , *bitsWritten); // increment how many bits were actually written    
finish:
    pal_osAtomicIncrement((int32_t*)(&g_noise.numWriters), -1); // decrement number of writers
    return status;
}

/*! Write values to the global noise buffer
*
* @param[in] buffer The buffer which contains the values to be written.
* @param[in] lenBits The number of bits that should be written.
* @param[out] bitsWritten The number of bits that were actually written.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten)
{
    PAL_VALIDATE_ARGUMENTS((NULL == buffer) || (PAL_NOISE_SIZE_BITS < lenBits) || (NULL == bitsWritten));

    palStatus_t status;
    uint8_t idx, bitsToWrite;
    uint16_t totalBitsWritten;

    idx = 0;
    totalBitsWritten = 0;
    do
    {
        bitsToWrite = (lenBits > PAL_INT32_BITS) ? PAL_INT32_BITS : lenBits; // we can write a max number of 32 bits at a time
        status = pal_noiseWriteValue(&buffer[idx], 0, bitsToWrite, (uint8_t*)bitsWritten);
        lenBits -= bitsToWrite;
        idx++;
        totalBitsWritten += *bitsWritten;
    } while ((PAL_SUCCESS == status) && (bitsToWrite == *bitsWritten) && lenBits); // exit if there was an error, or the noise buffer has no more space, or all bits were written

    *bitsWritten = totalBitsWritten;
    if (0 < totalBitsWritten)
    {
        status = PAL_SUCCESS;
    }
    return status;
}

/*! Read values from the global noise buffer
*
* @param[out] buffer The output buffer which will contain the noise data collected.
* @param[in] partial When true read what was collected so far, otherwise read only if the noise buffer is full.
* @param[out] bitsRead he number of bits that were actually read.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead)
{
    PAL_VALIDATE_ARGUMENTS((NULL == buffer) || (NULL == bitsRead));

    static uint32_t numOfNoiseReaders = 0; // allow only one reader at a time (no concurrent reads)
    palStatus_t status = PAL_SUCCESS;
    uint8_t numBytesToRead, numReadersLocal;
    uint16_t bitCountActual = (uint16_t)g_noise.bitCountActual;
    numReadersLocal = (uint8_t)pal_osAtomicIncrement((int32_t*)(&numOfNoiseReaders), 1); // increment number of readers
    *bitsRead = 0;
    if (1 != numReadersLocal) // single reader
    {
        PAL_LOG(DBG, "noise cannot read by multiple readers\n");
        status = PAL_ERR_RTOS_NOISE_BUFFER_EMPTY;
        goto finish;
    }
    
    if ((CHAR_BIT > bitCountActual) || (!partial && (PAL_NOISE_SIZE_BITS != bitCountActual))) // exit if less than 1 byte was written or if we want a full read and not all bits were written
    {
        status = (CHAR_BIT > bitCountActual) ? PAL_ERR_RTOS_NOISE_BUFFER_EMPTY : PAL_ERR_RTOS_NOISE_BUFFER_NOT_FULL;
        goto finish;
    }

    g_noise.isReading = true; // set mode to reading so that no more writes will be allowed
    while (g_noise.numWriters) // wait for currently executing writers to finish (relevant only for partial read)
    {
        pal_osDelay(PAL_NOISE_WAIT_FOR_WRITERS_DELAY_MILLI_SEC);
    }
    bitCountActual = (uint16_t)g_noise.bitCountActual; // this may occur if we waited for the writers to finish writing, meaning we might have a few more bits (relevant only for partial read)
    numBytesToRead = (uint8_t)PAL_NOISE_BITS_TO_BYTES(bitCountActual);    
    memcpy((void*)buffer, (void*)g_noise.buffer, numBytesToRead); // copy noise buffer to output buffer
    *bitsRead = (numBytesToRead * CHAR_BIT); // set out param of how many bits were actually read
    memset((void*)g_noise.buffer, 0, PAL_NOISE_SIZE_BYTES); // reset the noise buffer
    g_noise.bitCountActual = g_noise.bitCountAllocated = 0; // reset counters
    g_noise.isReading = false; // exit read mode so that writters will be able to continue writting
    PAL_LOG(DBG, "noise read %" PRIu8 " bits\n", *bitsRead);
finish:
    pal_osAtomicIncrement((int32_t*)(&numOfNoiseReaders), -1); // decrement number of readers
    return status;
}
