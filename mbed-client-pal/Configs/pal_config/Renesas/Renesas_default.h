// ----------------------------------------------------------------------------
// Copyright 2016-2020 ARM Ltd.
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


#ifndef PAL_RENESAS_CONFIGURATION_H_
#define PAL_RENESAS_CONFIGURATION_H_

/*! \brief This file sets configuration for PAL porting on Renesas SDK.
    \note All configurations that are configured in this file overwrite their defaults values
    \note Default Values can be found at Sources/PAL-impl/Services-API/pal_configuration.h
    \note
  */

 //!< Max number of allowed timer
#ifndef PAL_MAX_NUM_OF_TIMERS
    #define PAL_MAX_NUM_OF_TIMERS 5
#endif

//!< Max given token for a semaphore
#ifndef PAL_SEMAPHORE_MAX_COUNT
    #define PAL_SEMAPHORE_MAX_COUNT 1024
#endif

#ifndef PAL_USE_HW_ROT
    #define PAL_USE_HW_ROT 0
#endif

#ifndef PAL_USE_HW_RTC
    #define PAL_USE_HW_RTC 0
#endif

#ifndef PAL_USE_HW_TRNG
    #define PAL_USE_HW_TRNG 1
#endif

#ifndef PAL_USE_INTERNAL_FLASH
    #define PAL_USE_INTERNAL_FLASH 0
#endif

#ifndef PAL_USE_SECURE_TIME
    #define PAL_USE_SECURE_TIME 1
#endif

#define SYS_CONF_SOTP   SYS_CONF_SOTP_DISABLED

#ifndef PAL_SUPPORT_IP_V6
    #define PAL_SUPPORT_IP_V6 0
#endif

#ifndef PAL_DEFAULT_RTT_ESTIMATE
    #define PAL_DEFAULT_RTT_ESTIMATE 5
#endif


#endif /* PAL_RENESAS_CONFIGURATION_H_ */
