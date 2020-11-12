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

#ifndef PAL_DEFAULT_LINUX_CONFIGURATION_H_
#define PAL_DEFAULT_LINUX_CONFIGURATION_H_
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT
    #include "trusted_storage/inc/config.h"
#endif //MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT

#ifndef PAL_BOARD_SPECIFIC_CONFIG
    // TARGET_X86_X64 is designed mainly for quick development and will use limited security features for storage.
    #if defined(TARGET_X86_X64)
        #ifndef PAL_SIMULATOR_TEST_ENABLE
            #define PAL_SIMULATOR_TEST_ENABLE 1
        #endif
    #endif
#endif

#ifndef PAL_NUMBER_OF_PARTITIONS
    #define PAL_NUMBER_OF_PARTITIONS 1
#endif
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT //for ESFS
#ifndef PAL_FS_MOUNT_POINT_PRIMARY
    #if (PAL_NUMBER_OF_PARTITIONS == 2)
        #define PAL_FS_MOUNT_POINT_PRIMARY    "./pal_pri"                                                       //!< User should change this for the his working folder
    #else
        #define PAL_FS_MOUNT_POINT_PRIMARY    "./pal"
    #endif
#endif

#ifndef PAL_FS_MOUNT_POINT_SECONDARY
    #if (PAL_NUMBER_OF_PARTITIONS == 2)
        #define PAL_FS_MOUNT_POINT_SECONDARY    "./pal_sec"
    #else
        #define PAL_FS_MOUNT_POINT_SECONDARY    "./pal"                                                    //!< User should change this for the his working folder
    #endif
#endif
#else  //support for Linux PSA
#ifndef PAL_FS_MOUNT_POINT_PRIMARY
    #define PAL_FS_MOUNT_POINT_PRIMARY    PSA_STORAGE_FILE_C_STORAGE_PREFIX
#endif
#ifndef PAL_FS_MOUNT_POINT_SECONDARY
    #define PAL_FS_MOUNT_POINT_SECONDARY  PSA_STORAGE_FILE_C_STORAGE_PREFIX
#endif
#endif

#ifndef PAL_NET_MAX_IF_NAME_LENGTH
    #define PAL_NET_MAX_IF_NAME_LENGTH   	16  //15 + '\0'
#endif

#ifndef PAL_NET_TEST_MAX_ASYNC_SOCKETS
    #define PAL_NET_TEST_MAX_ASYNC_SOCKETS 	5
#endif

// 16KB does not seem to be enough, some tests are failing with it
#ifndef PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE
    #define PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE (1024 * 24)
    #if (PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
        #undef PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE
        #define PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE PTHREAD_STACK_MIN
    #endif
#endif

#ifndef PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE
    #define PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE (1024 * 16)
    #if (PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
        #undef PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE
        #define PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE PTHREAD_STACK_MIN
    #endif
#endif

#ifndef PAL_FORMAT_CMD_MAX_LENGTH
    #define PAL_FORMAT_CMD_MAX_LENGTH 	256
#endif

#ifndef PAL_DEVICE_NAME_MAX_LENGTH
    #define PAL_DEVICE_NAME_MAX_LENGTH  128
#endif

#ifndef PAL_PARTITION_FORMAT_TYPE
    #define PAL_PARTITION_FORMAT_TYPE "ext4"
#endif

/*\brief  overwrite format command with remove all file and directory*/
#ifndef PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT
    #define PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT 0
#endif

#ifndef PAL_FS_FORMAT_COMMAND
    #define PAL_FS_FORMAT_COMMAND "mkfs -F -t %s %s"
#endif


#ifndef PARTITION_FORMAT_ADDITIONAL_PARAMS
    #define PARTITION_FORMAT_ADDITIONAL_PARAMS NULL
#endif

 /*\brief  Starting Address for section 1 Minimum requirement size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_1_ADDRESS
    #define PAL_INTERNAL_FLASH_SECTION_1_ADDRESS    0
#endif

/*\brief  Starting Address for section 2 Minimum requirement size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_ADDRESS
    #define PAL_INTERNAL_FLASH_SECTION_2_ADDRESS    0
#endif

/*\brief  Size for section 1*/
#ifndef PAL_INTERNAL_FLASH_SECTION_1_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_1_SIZE       0
#endif

/*\brief  Size for section 2*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_2_SIZE       0
#endif

//!< Stack size for thread created when calling pal_getAddressInfoAsync
#ifndef PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE
    #define PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE (1024 * 32)
    #if (PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
        #undef PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE
        #define PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE PTHREAD_STACK_MIN
    #endif
#endif

//! Stack size for TRNG noise collecting thread
#ifndef PAL_NOISE_TRNG_THREAD_STACK_SIZE
    #define PAL_NOISE_TRNG_THREAD_STACK_SIZE (1024 * 32)
    #if (PAL_NOISE_TRNG_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
        #undef PAL_NOISE_TRNG_THREAD_STACK_SIZE
        #define PAL_NOISE_TRNG_THREAD_STACK_SIZE PTHREAD_STACK_MIN
    #endif
#endif

#ifndef PAL_TIMER_SIGNAL
    // Signal number for timer completition signal, a RT signal is needed to get signal queueing
    #define PAL_TIMER_SIGNAL (SIGRTMIN+0)
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

#ifndef PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM
    #define PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM 0
#endif

#ifndef PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM
    // This also implies PAL_USE_INTERNAL_FLASH 1
    #define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM 1
#endif

#ifndef PAL_USE_SECURE_TIME
    #define PAL_USE_SECURE_TIME 1
#endif

// SSL session resume requires Mbed TLS 2.18.0 or later
#ifndef PAL_USE_SSL_SESSION_RESUME
#define PAL_USE_SSL_SESSION_RESUME 1
#endif

#ifndef PAL_DEFAULT_RTT_ESTIMATE
    #define PAL_DEFAULT_RTT_ESTIMATE 3
#endif

// Sanity check for defined stack sizes
#if (PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
#warning "PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE stack size is less than PTHREAD_STACK_MIN"
#endif

#if (PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
#warning "PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE stack size is less than PTHREAD_STACK_MIN"
#endif

#if (PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
#warning "PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE stack size is less than PTHREAD_STACK_MIN"
#endif

#if (PAL_NOISE_TRNG_THREAD_STACK_SIZE < PTHREAD_STACK_MIN)
#warning "PAL_NOISE_TRNG_THREAD_STACK_SIZE stack size is less than PTHREAD_STACK_MIN"
#endif

// Define this to use static memory buffer for mbedtls, instead of standard mbedtls memory system (default is using heap).
//#undef PAL_USE_STATIC_MEMBUF_FOR_MBEDTLS

// If PAL_USE_STATIC_MEMBUF_FOR_MBEDTLS is defined, you must also define the size of the static memory buffer for mbedtls
//#undef PAL_STATIC_MEMBUF_SIZE_FOR_MBEDTLS

// if PAL_USE_STATIC_MEMBUF_FOR_MBEDTLS is defined, you can also define the section name where the static buffer will be placed. Leave undefined for default.
//#undef PAL_STATIC_MEMBUF_SECTION_NAME

#endif /* PAL_DEFAULT_LINUX_CONFIGURATION_H_ */
