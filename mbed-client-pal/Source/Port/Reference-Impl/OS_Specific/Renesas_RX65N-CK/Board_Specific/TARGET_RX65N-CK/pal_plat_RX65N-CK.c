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
 
/***********************************************************************************************************************
Includes   <System Includes> , "Project Includes"
***********************************************************************************************************************/
#include "pal_plat_rtos.h"
/* Platform support. */
#include "platform.h"

/***********************************************************************************************************************
Macro definitions
***********************************************************************************************************************/
#define TRACE_GROUP "brd"

int32_t pal_plat_osAtomicIncrement(int32_t* valuePtr, int32_t increment)
{
    int32_t res;

    R_BSP_InterruptsDisable();

    res = *valuePtr + increment;
    *valuePtr = res;

    R_BSP_InterruptsEnable();
    return (res);
}

/**********************************************************************************************************************
 * Function Name: R_BSP_SoftwareReset
 ******************************************************************************************************************//**
 * @details Reset the MCU by Software Reset.
 */
void R_BSP_SoftwareReset(void)
{
    /* Protect off. */
    R_BSP_RegisterProtectDisable(BSP_REG_PROTECT_LPC_CGC_SWR);
    PAL_LOG_DBG("[Reboot] RegisterProtectDisable: OFF. \n ");

    /* Resets the MCU. */
    SYSTEM.SWRR = 0xA501;

    /* WAIT_LOOP */
    while(1)
    {
        //  R_BSP_NOP();
    }
} /* End of function R_BSP_SoftwareReset() */

void pal_plat_osReboot()
{
    PAL_LOG_DBG("[Reboot] entry: \n ");
    R_BSP_SoftwareReset();
}
