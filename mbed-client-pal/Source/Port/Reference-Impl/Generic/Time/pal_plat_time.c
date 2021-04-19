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

//! This module implements the Time platform API using the storage_rbp as storage backend
// and optionally setting the system RTC to match the "secure time". Generic idea
// is to prevent attack by setting clock backwards and to have some idea of current
// time across system power cycle, even if the system does not have a battery backed RTC.

#include "pal.h"
#include "pal_time.h"
#include "pal_plat_rtos.h"
#include "pal_plat_time.h"
#include "storage_kcm.h"
#include <stdlib.h>


#define TRACE_GROUP "PAL"

PAL_PRIVATE palStatus_t pal_plat_setWeakTimeForward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime);
PAL_PRIVATE palStatus_t pal_plat_setWeakTimeBackward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime);

static uint64_t g_palDeviceBootTimeInSec = 0;

palStatus_t pal_plat_initTime(void)
{
    uint64_t rtcTime = 0;
    uint64_t getTime = 0, lastTimeBack = 0;
    palStatus_t  ret = PAL_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    size_t actualLenBytes = 0;

    ret = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&getTime, sizeof(uint64_t), &actualLenBytes);
    //In case the weak time corrupted (could be due to power failure) :
    // 1. Set 0 getTime 
    // 2. Rewrite STORAGE_RBP_SAVED_TIME_NAME with 0, to avoid an error in pal_plat_osSetStrongTime later, when the function tries first to read the weak time.
    // 3. Avoid error status and continue.
    if ((ret != PAL_SUCCESS) && (ret != PAL_ERR_ITEM_NOT_EXIST))
    {
        getTime = 0;
        //Rewrite weak time to avoid error in pal_plat_osSetStrongTime
        ret = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&getTime, sizeof(uint64_t), false);
        pal_status = ret;
    }

    ret = storage_rbp_read(STORAGE_RBP_LAST_TIME_BACK_NAME, (uint8_t *)&lastTimeBack, sizeof(uint64_t),&actualLenBytes);
    //Strong time : avoid error, reset device time and continue
    //In case the strong time corrupted (could be due to power failure) : 
    //1. Set device time to 0,to enforce the device to update the time against trusted server later.
    //2. Set 0 lastTimeBack 
    //3. Rewrite STORAGE_RBP_LAST_TIME_BACK_NAME with 0, to avoid an error in pal_plat_osSetWeak later, when the functions could try first to read the strong time.
    //4. Set weak time value getTime to 0 , to avoid setting of the value to device time with pal_status = pal_osSetTime(PAL_MAX(rtcTime, getTime)) ,
    //   that called in this function later. In case of strong time corruption, we need to keep the device time value - 0.
    if ((ret != PAL_SUCCESS) && (ret != PAL_ERR_ITEM_NOT_EXIST))
    {
        pal_plat_osSetTime(0); //Set device time to 0
        lastTimeBack = 0;
        //Rewrite strong time to avoid error in pal_plat_osSetWeak functions
        ret = storage_rbp_write(STORAGE_RBP_LAST_TIME_BACK_NAME, (uint8_t *)&lastTimeBack, sizeof(uint64_t), false);
        pal_status = ret;
        getTime = 0; //to avoid setting of the value to device time with  pal_status = pal_osSetTime(PAL_MAX(rtcTime, getTime))
    }

    if (lastTimeBack > getTime)
    {//Enter here only when reset occurs during set weak or strong time
        ret = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&lastTimeBack, sizeof(uint64_t), false);
        if (PAL_SUCCESS != ret)
        {
            pal_status = ret;
        }
        getTime = lastTimeBack;
    }

#if (PAL_USE_HW_RTC)
    if (PAL_SUCCESS == pal_status)
    {
        pal_status = pal_plat_osGetRtcTime(&rtcTime);
    }
#endif

    if (PAL_SUCCESS == pal_status)
    {//set the max time as boot time of the device
        pal_status = pal_osSetTime(PAL_MAX(rtcTime, getTime));
    }
    
    return pal_status;
}

PAL_PRIVATE uint64_t pal_plat_sysTickTimeToSec()
{
    uint64_t sysTicksFromBoot = pal_osKernelSysTick();
    uint64_t secFromBoot = pal_osKernelSysMilliSecTick(sysTicksFromBoot) / PAL_MILLI_PER_SECOND;

    return secFromBoot;
}

uint64_t pal_plat_osGetTime(void)
{
    uint64_t curSysTimeInSec = 0;
    if (0 < g_palDeviceBootTimeInSec) //time was previously set
    {
        uint64_t secFromBoot = pal_plat_sysTickTimeToSec();
        curSysTimeInSec = g_palDeviceBootTimeInSec + secFromBoot; //boot time in sec + sec passed since boot
    }

    return curSysTimeInSec;
}

palStatus_t pal_plat_osSetTime(uint64_t seconds)
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
        uint64_t secFromBoot = pal_plat_sysTickTimeToSec();
        g_palDeviceBootTimeInSec = seconds - secFromBoot; //update device boot time
    }

    return status;
}

palStatus_t pal_plat_osSetStrongTime(uint64_t setNewTimeInSeconds)
{
    palStatus_t ret = PAL_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;

    uint64_t getTimeValue = 0;
    size_t actualLenBytes = 0;

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

    ret = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&getTimeValue, sizeof(uint64_t), &actualLenBytes);
    if ((PAL_SUCCESS != ret) && (PAL_ERR_ITEM_NOT_EXIST != ret))
    {
        pal_status =  ret;
    }
    
    else if (((setNewTimeInSeconds > getTimeValue) && (setNewTimeInSeconds - getTimeValue > PAL_MINIMUM_FORWARD_LATENCY_SEC)) //Forward Time
            || ((setNewTimeInSeconds < getTimeValue) && (getTimeValue - setNewTimeInSeconds > PAL_MINIMUM_BACKWARD_LATENCY_SEC))) //Backward Time
    {
        ret = storage_rbp_write(STORAGE_RBP_LAST_TIME_BACK_NAME,  (uint8_t *)&setNewTimeInSeconds, sizeof(uint64_t), false);
        if (PAL_SUCCESS != ret)
        {
            pal_status = ret;
        }
        else
        {
            pal_status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&setNewTimeInSeconds, sizeof(uint64_t), false);            
        }
    }

    if(PAL_SUCCESS == pal_status)
    {
       pal_status = pal_osSetTime(setNewTimeInSeconds); //Save new time to RAM
    }

    return pal_status;
}

PAL_PRIVATE palStatus_t pal_plat_setWeakTimeForward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime)
{
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

    if ((setNewTimeInSeconds - currentOsTime > PAL_MINIMUM_FORWARD_LATENCY_SEC) && (PAL_SUCCESS == ret))
    {  //time forward
        ret = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&setNewTimeInSeconds, sizeof(uint64_t), false);
    }
    
    return ret;
}

PAL_PRIVATE palStatus_t pal_plat_setWeakTimeBackward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime)
{
    uint64_t getTimeValue = 0;
    size_t actualLenBytes = 0;
    palStatus_t ret = PAL_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;

    ret = storage_rbp_read(STORAGE_RBP_LAST_TIME_BACK_NAME, (uint8_t *)&getTimeValue, sizeof(uint64_t), &actualLenBytes);
    if ((PAL_SUCCESS != ret) && (PAL_ERR_ITEM_NOT_EXIST != ret))
    {
        pal_status = ret;
    }
    
    else if (setNewTimeInSeconds > getTimeValue)
    {
        if ((setNewTimeInSeconds - getTimeValue) / PAL_RATIO_SECONDS_PER_DAY  > (currentOsTime - setNewTimeInSeconds))
        {
            ret = storage_rbp_write(STORAGE_RBP_LAST_TIME_BACK_NAME, (uint8_t *)&setNewTimeInSeconds, sizeof(uint64_t), false);
            if (PAL_SUCCESS != ret)
            {
                pal_status = ret;
            }
            else
            {
                ret = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&setNewTimeInSeconds, sizeof(uint64_t), false);
                if (PAL_SUCCESS == ret)
                {
                    pal_status = pal_osSetTime(setNewTimeInSeconds); //Save new time to RAM
                }
            }
        }
    }

    return pal_status;
}

palStatus_t pal_plat_osSetWeakTime(uint64_t setNewTimeInSeconds)
{
    uint64_t getTimeValue = 0;
    size_t actualLenBytes = 0;
    palStatus_t ret = PAL_SUCCESS;
    palStatus_t pal_status = PAL_SUCCESS;
    uint64_t getOsTimeValue = 0;

    getOsTimeValue = pal_osGetTime(); //get current system time

    if (setNewTimeInSeconds > getOsTimeValue)
    {//Time Forward
        ret = pal_plat_setWeakTimeForward(setNewTimeInSeconds, getOsTimeValue);
    }
    else if (getOsTimeValue > setNewTimeInSeconds)
    {//Time Backward
        ret = pal_plat_setWeakTimeBackward(setNewTimeInSeconds, getOsTimeValue);
    }

    if(PAL_SUCCESS == ret)
    {
        getTimeValue = 0;
        ret = storage_rbp_read(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&getTimeValue, sizeof(uint64_t), &actualLenBytes);
        if ((PAL_SUCCESS != ret) && (PAL_ERR_ITEM_NOT_EXIST != ret))
        {
            pal_status = ret;
        }
        else if ((setNewTimeInSeconds > getTimeValue) && (setNewTimeInSeconds - getTimeValue > PAL_MINIMUM_STORAGE_LATENCY_SEC))
        {
            pal_status = storage_rbp_write(STORAGE_RBP_SAVED_TIME_NAME, (uint8_t *)&setNewTimeInSeconds, sizeof(uint64_t), false);
        }
    }
    
    return pal_status;
}

