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

#ifndef _PAL_PLAT_TIME_H
#define _PAL_PLAT_TIME_H

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_plat_time.h
*  \brief PAL TIME - platform.
*   This file contains the real-time OS APIs that need to be implemented in the platform layer.
*   This file contains the secure time APIs and is a part of the PAL service API.
*   Unlike the "normal" timer and tick query APIs, which are left in RTOS, this
*   optional module provides access to clock, which is used mostly by the
*   PAL's own Crypto module.
*/


/*! \brief  Initialization the time module
*   After boot, the time in RAM will be initialized with the max value between RTC and SOTP SAVED_TIME. If no RTC is present, RTC time is zero.
*   After initialization the time module will start counting ticks.
*   The answer to get_time should be calculated by the sum of the initial value (RTC or SOTP) + the number of ticks converted into seconds.
*
* \return PAL_SUCCESS when initialization succeed. \n
*
* \note
*/
palStatus_t pal_plat_initTime(void);

/*! Get the system time.
* \return The system 64-bit counter indicating the current system time in seconds on success.
*         Zero value when the time is not set in the system.
* \note If the delta between secure time value previously set in the system and current system time is greater than PAL_LAST_SAVED_TIME_LATENCY_SEC
* then secure time value will be overridden with current system time
*/
uint64_t pal_plat_osGetTime(void);

/*! \brief Set the current system time by accepting seconds since January 1st 1970 UTC+0.
*
* @param[in] seconds Seconds from January 1st 1970 UTC+0.
*
* \return PAL_SUCCESS when the time was set successfully. \n
*         PAL_ERR_INVALID_TIME when there is a failure setting the system time.
*/
palStatus_t pal_plat_osSetTime(uint64_t seconds);

/*! \brief save weak time according to design
*   Time Forward (a)
*   set the time (in RAM) unconditionally. Save the new time in SOTP if the change (between new time and current time in RAM) is greater than 24 hours.
*   Set the time to RTC if the change is greater than 100 seconds. This limitation is to avoid multiple writes to the SOTP and RTC and not related to security.
*   Time Forward (b)
*   If (a) did not happen, save the time into SOTP if new time is greater from SAVED_TIME by a week (604800 seconds).
*   Time Backwards
*   set the device time on the device (RAM) and save the time in SOTP only if the change
*   (between new time and current time in RAM) is smaller than 3 minutes for each day lapsed from the last change
*   done via pal_osWeakSetTime. RTC is never set backwards by pal_osWeakSetTime().
*
* @param[in] uint64_t setTimeInSeconds  Seconds from January 1st 1970 UTC+0.
*
* \return PAL_SUCCESS when set weak  succeed. \n
*
* \note To implement this, when the new time is saved in SOTP by the function pal_osWeakSetTime two records with different types must be saved in SOTP:
* \note 1.- The new time (the same record as in factory setup)
* \note 2.- The time this action was performed, in order to enforce the 24 hours limitation. Record LAST_TIME_BACK.
*/
palStatus_t pal_plat_osSetWeakTime(uint64_t setTimeInSeconds);

/*! \brief save strong time according to design
*   Set the time (in RAM) unconditionally. Save in SOTP or/and RTC the new time under the following conditions:
•	Time forward – if time difference between current time in SOTP (not device time) and new time is greater than a day
•	Time backward – if time difference between current time and new time is greater than one minute.
*   If the time is saved in SOTP (forward or backwards), the record LAST_TIME_BACK must be saved.
*
** @param[in] uint64_t setTimeInSeconds - Seconds from January 1st 1970 UTC+0.
**
* \return PAL_SUCCESS when set strong succeed. \n
*
* \note   The limitations are aimed to reduce the number of write operations to the SOTP and not related to security.
*   This function will be called when receiving time from a server that is completely trusted.
*/
palStatus_t pal_plat_osSetStrongTime(uint64_t setTimeInSeconds);


#ifdef __cplusplus
}
#endif
#endif //_PAL_PLAT_TIME_H
