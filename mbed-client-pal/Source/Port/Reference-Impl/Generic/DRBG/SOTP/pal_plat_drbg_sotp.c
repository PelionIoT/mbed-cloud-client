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
#include "pal.h"
#include "pal_plat_drbg.h"
#include "pal_plat_entropy.h"
#include "sotp.h"

#include <stdlib.h>

#define TRACE_GROUP "PAL"


//! static variables for Random functionality.
//! CTR-DRBG context to be used for generating random numbers from given seed
static palCtrDrbgCtxHandle_t s_ctrDRBGCtx = NULLPTR;


PAL_PRIVATE bool g_palDRBGInitialized = false;


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

// XXX: these are not part of ANY public API, yet the test code accesses them.
palStatus_t pal_plat_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten); // forward declaration
palStatus_t pal_plat_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead); // forward declaration

#if PAL_USE_HW_TRNG
    PAL_PRIVATE palThreadID_t g_trngThreadID = NULLPTR;
#endif

PAL_PRIVATE palStatus_t pal_plat_generateDrbgWithNoiseAttempt(palCtrDrbgCtxHandle_t drbgContext, uint8_t* outBuffer, bool partial, size_t numBytesToGenerate);

extern palStatus_t pal_plat_CtrDRBGGenerateWithAdditional(palCtrDrbgCtxHandle_t ctx, unsigned char* out, size_t len, unsigned char* additional, size_t additionalLen);

palStatus_t pal_plat_DRBGInit(void)
{
    palStatus_t status = PAL_SUCCESS;
    if (g_palDRBGInitialized)
    {
        return status;
    }

    memset(g_noise.buffer, 0, PAL_NOISE_SIZE_BYTES);
    g_noise.bitCountActual = g_noise.bitCountAllocated = 0;
    g_noise.numWriters = 0;
    g_noise.isReading = false;
#if PAL_USE_HW_TRNG
    g_trngThreadID = NULLPTR;
#endif
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
    if (NULLPTR != g_trngThreadID)
    {
        if (PAL_SUCCESS != pal_osThreadTerminate(&g_trngThreadID))
        {
            PAL_LOG_ERR("pal_DRBGDestroy: failed to terminate trng noise thread\n");
        }
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
            status = pal_plat_noiseWriteBuffer((int32_t*)buf, (trngBytesRead * CHAR_BIT), &noiseBitsWritten);
            if (status != PAL_SUCCESS) {
                PAL_LOG_ERR("Write TRNG to noise buffer, status=%" PRIx32 ", bits writtern=%" PRIu16 "\n", status, noiseBitsWritten);
            }
        }
        pal_osDelay(PAL_NOISE_TRNG_THREAD_DELAY_MILLI_SEC);
    }
}
#endif // PAL_USE_HW_TRNG


// this function generates drbg with the possibility of adding noise as additional input to the drbg function.
PAL_PRIVATE palStatus_t pal_plat_generateDrbgWithNoiseAttempt(palCtrDrbgCtxHandle_t drbgContext, uint8_t* outBuffer, bool partial, size_t numBytesToGenerate)
{
    uint16_t bitsRead = 0;
    int32_t buffer[PAL_NOISE_BUFFER_LEN] = { 0 };
    palStatus_t status = pal_plat_noiseRead(buffer, partial, &bitsRead);
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

            palStatus_t entropyResult = pal_plat_get_nv_entropy(ptrSotpRead, sotpLenBytes, &sotpBytesRead); // read 48 drbg bytes + 4 counter bytes
            if (PAL_SUCCESS == entropyResult)
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
                entropyResult = pal_plat_set_nv_entropy(ptrSotpWrite, sotpLenBytes); // write 48 long term drbg bytes + 4 counter bytes
                if (PAL_SUCCESS != entropyResult)
                {
                    PAL_LOG_ERR("Failed to write to SOTP, sotp result=%" PRIx32, entropyResult);
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
                    status = pal_osThreadCreateWithAlloc(pal_trngNoiseThreadFunc, NULL, PAL_osPriorityReservedTRNG, PAL_NOISE_TRNG_THREAD_STACK_SIZE, NULL, &g_trngThreadID);
                    if (PAL_SUCCESS != status)
                    {
                        PAL_LOG_ERR("Failed to create noise TRNG thread, status=%" PRIx32 "\n", tmpStatus);
                    }
#endif // PAL_USE_HW_TRNG
                }
            }
            else if (PAL_ERR_ITEM_NOT_EXIST == entropyResult)
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


/*! Write a value (either all or specific bits) to the global noise buffer
*
* @param[in] data The value containing the bits to be written.
* @param[in] startBit The index of the first bit to be written, valid values are 0-31.
* @param[in] lenBits The number of bits that should be written (startBit+lenBits must be less than 32).
* @param[out] bitsWritten The number of bits that were actually written.
*
* \return PAL_SUCCESS(0) in case of success and a negative value indicating a specific error code in case of failure.
*/
palStatus_t pal_plat_noiseWriteValue(const int32_t* data, uint8_t startBit, uint8_t lenBits, uint8_t* bitsWritten)
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
palStatus_t pal_plat_noiseWriteBuffer(int32_t* buffer, uint16_t lenBits, uint16_t* bitsWritten)
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
        status = pal_plat_noiseWriteValue(&buffer[idx], 0, bitsToWrite, (uint8_t*)bitsWritten);
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
palStatus_t pal_plat_noiseRead(int32_t buffer[PAL_NOISE_BUFFER_LEN], bool partial, uint16_t* bitsRead)
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
        PAL_LOG_DBG("noise cannot read by multiple readers\n");
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
    PAL_LOG_DBG("noise read %" PRIu8 " bits\n", *bitsRead);
finish:
    pal_osAtomicIncrement((int32_t*)(&numOfNoiseReaders), -1); // decrement number of readers
    return status;
}
