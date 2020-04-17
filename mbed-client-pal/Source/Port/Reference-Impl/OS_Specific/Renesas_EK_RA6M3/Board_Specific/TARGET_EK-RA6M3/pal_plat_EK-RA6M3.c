/*******************************************************************************
 * Copyright 2020 ARM Ltd.
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
 
#include "pal_plat_rtos.h"
#include "FreeRTOS.h"

// This is the BPS starter header for Renesas RA system
#include "bsp_api.h"

/////////////////////////STATIC FUNCTION///////////////////////////
/*! disable all interrupts in system
*
* @param[in] Void
* \returns void
*
*/
PAL_PRIVATE PAL_INLINE void pal_plat_DisableIrq(void);
/*! Enable all interrupts in system
*
* @param[in] Void
* \returns void
*
*/
PAL_PRIVATE PAL_INLINE void pal_plat_EnableIrq(void);


/*! get one random byte
*
* @param[out] byte: pointer to one byte to hold the random number
*
* \returns void
*/
PAL_PRIVATE void getTRNGByte(unsigned char *byte);

/*! get random number in size of given bytes
*
* @param[out] output: pointer to buffer to hold the random number
* @param[in] length: size of the output buffer
* @param[out] output_length: actual size of the written data
*
* \returns void
*/
PAL_PRIVATE int getTRNGBytes(uint8_t *output, size_t length, size_t *output_length);

PAL_PRIVATE PAL_INLINE void pal_plat_DisableIrq(void)
{
	__asm volatile 	( " cpsid i " );
}

PAL_PRIVATE PAL_INLINE void pal_plat_EnableIrq(void)
{
	__asm volatile 	( " cpsie i " );
}
/////////////////////////END STATIC FUNCTION///////////////////////////

#if defined (__CC_ARM)          /* ARM Compiler */

#pragma push
#pragma O0

#if ((defined(__TARGET_ARCH_7_M) || defined(__TARGET_ARCH_7E_M)) && !defined(NO_EXCLUSIVE_ACCESS))
#define __USE_EXCLUSIVE_ACCESS
#else
#undef  __USE_EXCLUSIVE_ACCESS
#endif // ARMCC end

#elif defined (__GNUC__)        /* GNU Compiler */

#undef  __USE_EXCLUSIVE_ACCESS
#pragma GCC push_options
#pragma GCC optimize ("O0")

#if defined (__CORTEX_M0)
#define __TARGET_ARCH_6S_M
#endif

#if defined (__VFP_FP__) && !defined(__SOFTFP__)
#define __TARGET_FPU_VFP
#endif
#endif

int32_t pal_plat_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
#ifdef __USE_EXCLUSIVE_ACCESS
        int32_t res;
        res = __ldrex(valuePtr) + increment;
        do {
        } while (__strex(res, valuePtr));
        return (res);
#elif !defined (__CORTEX_M0)
    if (valuePtr != NULL)
    {
        asm volatile(
        "try:\n\t"
            "LDREX   R0, [%[valuePtr]]\n\t"
            "ADD     R0, %[increment]\n\t"
            "CMP     R0, R0\n\t"
            "ITT     EQ\n\t"
            "STREXEQ R1, R0, [%[valuePtr]]\n\t"
            "CMPEQ   R1, #0\n\t"
            "BNE     try\n\t"
            :[valuePtr]"+r"(valuePtr)
            :[increment]"r"(increment)
            );
        return *valuePtr;
    }
    else
    {
        return 0;
    }
#else
    int32_t res;
    pal_plat_DisableIrq();
     res = *valuePtr + increment;
    *valuePtr = res;
    pal_plat_EnableIrq();
    return (res);
#endif

}
#if defined (__CC_ARM)          /* ARM Compiler */

#pragma pop

#elif defined (__GNUC__)

#pragma GCC pop_options

#endif


void pal_plat_osReboot()
{
#define RESET_MASK_FOR_CORTEX_M_SERIES	0x5fa0004

    volatile unsigned int * AIRCR_REG = (volatile unsigned int *)(0xE000ED0C);  //This register address is true for the Cortex M family
    *AIRCR_REG = RESET_MASK_FOR_CORTEX_M_SERIES;
    while(1);                                                    /* wait until reset */
}

/*
 * Get one byte of entropy from the RNG, assuming it is up and running.
 * As recommended (34.1.1), get only one bit of each output.
 */
PAL_INLINE void getTRNGByte(unsigned char *byte)
{
    // TODO RA Later: Make this TRNG.
    // RA6M3 gets no TRNG rand() in 15 bits.
    uint32_t rV = rand();
    if (byte) *byte = rV;
}

PAL_PRIVATE int getTRNGBytes(uint8_t *output, size_t length, size_t *output_length)
{
    if (!output)
        return -1;

    size_t i;
    for (i = 0; i < length; i++)
    {
        getTRNGByte(output+i);
    }

    if (output_length)
        *output_length = length;

    return 0;
}

palStatus_t pal_plat_getRandomBufferFromHW(uint8_t *randomBuf, size_t bufSizeBytes, size_t* actualRandomSizeBytes)
{
    palStatus_t status = PAL_SUCCESS;
    int32_t platStatus = 0;
    size_t actualOutputLen = 0;
        
    platStatus = getTRNGBytes(randomBuf, bufSizeBytes, &actualOutputLen);
    if ((0 != platStatus) || (0 == actualOutputLen))
    {
        status = PAL_ERR_RTOS_TRNG_FAILED;
    }
    if (actualOutputLen != bufSizeBytes)
    {
        status = PAL_ERR_RTOS_TRNG_PARTIAL_DATA;
    }

    if (NULL != actualRandomSizeBytes)
    {
        *actualRandomSizeBytes = actualOutputLen;
    }
    return status;
}

#if (PAL_USE_HW_RTC)
palMutexID_t rtcMutex = NULLPTR;
palStatus_t pal_plat_osGetRtcTime(uint64_t *rtcGetTime)
{
    palStatus_t ret = PAL_SUCCESS;
    if(rtcGetTime != NULL)
    {
        *rtcGetTime = RTC->TSR;
    }
    else
    {
        ret = PAL_ERR_NULL_POINTER;
    }
    return ret;
}

palStatus_t pal_plat_osSetRtcTime(uint64_t rtcSetTime)
{
    palStatus_t ret = PAL_SUCCESS;
    if (rtcSetTime < (uint64_t)PAL_MIN_RTC_SET_TIME)
    {
        ret = PAL_ERR_INVALID_TIME;
    }
    else
    {
        ret = pal_osMutexWait(rtcMutex, 5 * PAL_MILLI_PER_SECOND * PAL_ONE_SEC);
        if(ret == PAL_SUCCESS)
        {
            RTC_StopTimer(RTC);
            RTC->TSR = rtcSetTime;
            RTC_StartTimer(RTC);
            ret = pal_osMutexRelease(rtcMutex);
        }
    }
    return ret;
}

palStatus_t pal_plat_rtcInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    if(NULLPTR == rtcMutex)
    {
        ret = pal_osMutexCreate(&rtcMutex);
    }
    return ret;
}

palStatus_t pal_plat_rtcDeInit(void)
{
    palStatus_t ret = PAL_SUCCESS;
    if(NULL != rtcMutex)
    {
        ret = pal_osMutexDelete(&rtcMutex);
        rtcMutex = NULLPTR;
    }
    return ret;
}
#endif //#if (PAL_USE_HW_RTC)
/* If configSUPPORT_STATIC_ALLOCATION is set to 1, the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
void vApplicationGetIdleTaskMemory( StaticTask_t ** ppxIdleTaskTCBBuffer,
                                    StackType_t ** ppxIdleTaskStackBuffer,
                                    uint32_t * pulIdleTaskStackSize )
{
    /* If the buffers to be provided to the Idle task are declared inside this
     * function then they must be declared static - otherwise they will be allocated on
     * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
    * Note that, as the array is necessarily of type StackType_t,
    * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}

/* If configSUPPORT_STATIC_ALLOCATION is set to 1, the application must provide an
 * implementation of vApplicationGetTimerTaskMemory() to provide the memory that is
 * used by the RTOS daemon/time task. */
void vApplicationGetTimerTaskMemory( StaticTask_t ** ppxTimerTaskTCBBuffer,
                                     StackType_t ** ppxTimerTaskStackBuffer,
                                     uint32_t * pulTimerTaskStackSize )
{
    /* If the buffers to be provided to the Timer task are declared inside this
     * function then they must be declared static - otherwise they will be allocated on
     * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
    * Note that, as the array is necessarily of type StackType_t,
    * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulTimerTaskStackSize = configMINIMAL_STACK_SIZE;
}
