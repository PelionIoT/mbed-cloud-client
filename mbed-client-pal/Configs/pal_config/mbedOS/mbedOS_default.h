// ----------------------------------------------------------------------------
// Copyright 2018-2019 ARM Ltd.
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

#ifndef PAL_MBEDOS_CONFIGURATION_H_
#define PAL_MBEDOS_CONFIGURATION_H_

#include "cmsis_os.h"
#include "mbed_version.h"

/*!
* \brief This file is for more specific definitions (per board or module if needed).
*        if this file is defined it will be included from pal_configuration.h
*        if not, the default file will be included - if needed
*/

#if (defined(MBED_DEBUG) && !defined(DEBUG))
    #define DEBUG
#endif

#ifndef PAL_RTOS_WAIT_FOREVER
    #define PAL_RTOS_WAIT_FOREVER osWaitForever
#endif

#if (PAL_NET_DNS_SUPPORT == true) && !(defined(PAL_DNS_API_VERSION))
#define PAL_DNS_API_VERSION 2 //!< asyncronous DNS API
#endif

//defines SST (KVstore) support flag.
//This flag should already be defined as this is client library flag.
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    #warning "External SST support has not been enabled."
	#define MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT 1
#endif

#ifndef PAL_NUMBER_OF_PARTITIONS
    #define PAL_NUMBER_OF_PARTITIONS 1
#endif

//mount fs to MBED_CONF_STORAGE_DEFAULT_KV mount point (same mount point as kvstore defines)
#ifndef PAL_FS_MOUNT_POINT_PRIMARY
    #define EXPANSION_STR(x) STR(x) //stringification of macro value
    #define STR(x) #x //stringification of the macro
    #define PAL_FS_MOUNT_POINT_PRIMARY "/" EXPANSION_STR(MBED_CONF_STORAGE_DEFAULT_KV)
#endif

//define secondary mount point to the same mount point as primary
#ifndef PAL_FS_MOUNT_POINT_SECONDARY
    #define PAL_FS_MOUNT_POINT_SECONDARY PAL_FS_MOUNT_POINT_PRIMARY
#endif


#ifndef PAL_NUM_OF_THREAD_INSTANCES
    #define PAL_NUM_OF_THREAD_INSTANCES 1
#endif

#ifndef PAL_MAX_SEMAPHORE_COUNT
    #define PAL_MAX_SEMAPHORE_COUNT 	1024
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

// SSL session resume requires Mbed TLS 2.18.0 or later
#ifndef PAL_USE_SSL_SESSION_RESUME
#define PAL_USE_SSL_SESSION_RESUME 1
#endif

//issue a warning if PAL_USE_INTERNAL_FLASH!=0 and or define PAL_USE_INTERNAL_FLASH=0
#if (PAL_USE_INTERNAL_FLASH == 1) //PAL_USE_INTERNAL_FLASH != 0
    #warning "Internal flash APIs should be disabled with KVStore"
#endif

#endif /* PAL_MBEDOS_SST_CONFIGURATION_H_ */
