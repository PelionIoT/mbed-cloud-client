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
#include "board.h"
#include "fsl_device_registers.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "FreeRTOS.h"
#include "task.h"
#include "fsl_rtc.h"

// TRNG Function for K64F device
#include "fsl_common.h"
#include "fsl_clock.h"

#include "pal_configuration.h"


#define APP_DEBUG_UART_BAUDRATE 115200                 /* Debug console baud rate.           */
#define APP_DEBUG_UART_CLKSRC_NAME kCLOCK_CoreSysClk /* System clock.       */

//This stack overflow hook can catch stack overflow errors in FreeRTOS.
//You must enable define of configCHECK_FOR_STACK_OVERFLOW in FreeRTOSConfig.h
void vApplicationStackOverflowHook( TaskHandle_t xTask,	signed char *pcTaskName )
{
	return;
}

//This MallocFailedHook can catch memory allocation errors in FreeRTOS.
//You must enable define of configUSE_MALLOC_FAILED_HOOK in FreeRTOSConfig.h
void vApplicationMallocFailedHook( void )
{
	return;
}


static void APP_InitPlatformTRNG()
{
    CLOCK_EnableClock(kCLOCK_Rnga0);
    CLOCK_DisableClock(kCLOCK_Rnga0);
    CLOCK_EnableClock(kCLOCK_Rnga0);
}

#if 0
static void APP_StopPlatformTRNG()
{
	CLOCK_DisableClock(kCLOCK_Rnga0);
}

void StopFreeRtosBoard()
{
	APP_StopPlatformTRNG();
}
#endif //0

void boardInit()
{
	MPU_Type *base = MPU;
	BOARD_InitPins();
	BOARD_BootClockRUN();
	BOARD_InitDebugConsole();

#if (PAL_USE_HW_RTC)
	rtc_config_t rtcConfig = {0, 0, 0, 0, 0};
    RTC_GetDefaultConfig(&rtcConfig);
    rtcConfig.supervisorAccess = true;
    RTC_Init(RTC, &rtcConfig);
    /* Enable the RTC 32KHz oscillator */
    RTC->CR |= RTC_CR_OSCE_MASK;
    RTC_StartTimer(RTC);
#endif

	APP_InitPlatformTRNG();
	/* Disable MPU. */
	base->CESR &= ~MPU_CESR_VLD_MASK;
}

