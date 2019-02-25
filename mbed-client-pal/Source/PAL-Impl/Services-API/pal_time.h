// ----------------------------------------------------------------------------
// Copyright 2016-2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef _PAL_TIME_H
#define _PAL_TIME_H

#ifndef _PAL_H
    #error "Please do not include this file directly, use pal.h instead"
#endif

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/*! \file pal_time.h
 *  \brief PAL time.
 *   This file contains the secure time APIs and is a part of the PAL service API.
 *
 *   Unlike the usual timer and tick query APIs, which are found in RTOS, this
 *   optional module provides access to the clock, which is used mostly by
 *   PAL's own Crypto module.
 */

/*! \brief  Initializes the time module.
 *
 *   After boot, the time in RAM will be initialized with the higher value of RTC and SOTP `SAVED_TIME`. If no RTC is present, RTC time is zero.
 *   After initialization, the time module will start counting ticks.
 *
 * \return PAL_SUCCESS when initialization succeeds.
 */
palStatus_t pal_initTime(void);

/*! \brief Get the system time.
 *
 *   The time is calculated by the sum of the initial value + the number of ticks passed, converted into seconds.
 *
 * \return A 64-bit counter indicating the current system time in seconds on success.
 * \return Zero value when the time is not set in the system.
 * \note If the delta between the secure time value previously set in the system and the current system time is greater than `PAL_LAST_SAVED_TIME_LATENCY_SEC`,
 *       then the secure time value will be overwritten with the current system time.
 */
uint64_t pal_osGetTime(void);

/*! \brief Set the current system time, defined as seconds since January 1st 1970 UTC+0.
 *
 * @param[in] seconds Seconds from January 1st 1970 UTC+0.
 *
 * \return PAL_SUCCESS when the time is set successfully.
 * \return PAL_ERR_INVALID_TIME when there is a failure in setting the system time.
 */
palStatus_t pal_osSetTime(uint64_t seconds);

/*! \brief Set the weak time.
 *
 *   Time Forward (a) \n
 *   set the time (in RAM) unconditionally. Save the new time in SOTP if the change (between new time and current time in RAM) is greater than 24 hours.
 *   Set the time to RTC if the change is greater than 100 seconds. This limitation is to avoid multiple writes to the SOTP and RTC and not related to security.
 *
 *   Time Forward (b) \n
 *   If (a) did not happen, save the time into SOTP if new time is greater from SAVED_TIME by a week (604800 seconds).
 *
 *   Time Backwards \n
 *   set the device time on the device (RAM) and save the time in SOTP only if the change
 *   (between new time and current time in RAM) is smaller than 3 minutes for each day lapsed from the last change
 *   done via `pal_osSetWeakTime`. RTC is never set backwards by `pal_osSetWeakTime`.
 *
 * @param[in] setTimeInSeconds  Seconds from January 1st 1970 UTC+0.
 *
 * \return PAL_SUCCESS when set weak time is successful.
 *
 * \note To implement this, when the new time is saved in SOTP by `pal_osSetWeakTime` two different records must be saved in SOTP:
 * \note 1. The new time (the same record as in factory setup)
 * \note 2. The time this action was performed, in order to enforce the 24 hours limitation. Record `LAST_TIME_BACK`.
 */
palStatus_t pal_osSetWeakTime(uint64_t setTimeInSeconds);

/*! \brief Set the strong time. This function will be called when receiving time from a server that is completely trusted.
 *
 *   Set the time in RAM unconditionally. Save the new time in SOTP or RTC under the following conditions:
 *
 *	 Time forward – if time difference between current time in SOTP (not device time) and new time is greater than a day.
 *
 *	 Time backward – if time difference between current time and new time is greater than one minute.
 *   If the time is saved in SOTP (forward or backwards), the record `LAST_TIME_BACK` must be saved.
 *
 * @param[in] setTimeInSeconds Seconds from January 1st 1970 UTC+0.
 *
 * \return PAL_SUCCESS when set strong succeed.
 *
 * \note The limitations are aimed to reduce the number of write operations to the SOTP and not related to security.
 */
palStatus_t pal_osSetStrongTime(uint64_t setTimeInSeconds);


#ifdef __cplusplus
}
#endif
#endif //_PAL_TIME_H
