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

//! This module implements the Time platform API using the SOTP as storage backend
// and optionally setting the system RTC to match the "secure time". Generic idea
// is to prevent attack by setting clock backwards and to have some idea of current
// time across system power cycle, even if the system does not have a battery backed RTC.

#include "pal.h"
#include "pal_time.h"
#include "pal_plat_time.h"

// TODO: the #ifdef to make it possible to have this file and the really-platform specific pal_plat_time.c
// in the same build. That #if needs also get rid of the include to sotp.h.

#include "sotp.h"

#define TRACE_GROUP "PAL"

//! Store the last saved time in SOTP (ram) for quick access
PAL_PRIVATE uint64_t g_lastSavedTimeInSec = 0;

PAL_PRIVATE palStatus_t pal_plat_setWeakTimeForward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime);
PAL_PRIVATE palStatus_t pal_plat_setWeakTimeBackward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime);

static uint64_t g_palDeviceBootTimeInSec = 0;

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

palStatus_t pal_plat_initTime(void)
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

        if((curSysTimeInSec > g_lastSavedTimeInSec) && (curSysTimeInSec - g_lastSavedTimeInSec > PAL_LAST_SAVED_TIME_LATENCY_SEC))
        {
            sotp_result_e status = SOTP_SUCCESS;
            status = sotp_set(SOTP_TYPE_SAVED_TIME, sizeof(uint64_t), (uint32_t *)&curSysTimeInSec);
            if (SOTP_SUCCESS != status)
            {
                PAL_LOG_ERR("SOTP set time failed \n");
            }
            else
            {
                g_lastSavedTimeInSec = curSysTimeInSec;
            }
        }
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

PAL_PRIVATE palStatus_t pal_plat_setWeakTimeForward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime)
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

PAL_PRIVATE palStatus_t pal_plat_setWeakTimeBackward(uint64_t setNewTimeInSeconds, uint64_t currentOsTime)
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

palStatus_t pal_plat_osSetWeakTime(uint64_t setNewTimeInSeconds)
{
    uint64_t getSotpTimeValue = 0;
    uint16_t actualLenBytes = 0;
    sotp_result_e status = SOTP_SUCCESS;
    palStatus_t ret = PAL_SUCCESS;
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

