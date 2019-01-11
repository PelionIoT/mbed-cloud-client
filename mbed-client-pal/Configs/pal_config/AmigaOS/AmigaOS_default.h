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

#ifndef PAL_DEFAULT_AMIGAOS_CONFIGURATION_H_


#ifndef PAL_BOARD_SPECIFIC_CONFIG
    #if defined(TARGET_M68K)
        #include "m68k_default.h"
    #endif
#endif


#ifndef PAL_NUMBER_OF_PARTITIONS
    #define PAL_NUMBER_OF_PARTITIONS 1
#endif


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

#ifndef PAL_NET_MAX_IF_NAME_LENGTH
    #define PAL_NET_MAX_IF_NAME_LENGTH   16  //15 + '\0'
#endif

#ifndef PAL_NET_TEST_MAX_ASYNC_SOCKETS
    #define PAL_NET_TEST_MAX_ASYNC_SOCKETS 5
#endif

// 16KB does not seem to be enough, some tests are failing with it
#ifndef PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE
    #define PAL_NET_TEST_ASYNC_SOCKET_MANAGER_THREAD_STACK_SIZE (1024 * 24)
#endif


#ifndef PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE
    #define PAL_RTOS_HIGH_RES_TIMER_THREAD_STACK_SIZE (1024 * 16)
#endif

#ifndef PAL_FORMAT_CMD_MAX_LENGTH
    #define PAL_FORMAT_CMD_MAX_LENGTH 256
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
#endif

#ifndef PAL_USE_HW_TRNG
    #define PAL_USE_HW_TRNG    1
#endif // PAL_USE_HW_TRNG

#if PAL_USE_HW_TRNG
    //! Stack size for TRNG noise collecting thread
    #ifndef PAL_NOISE_TRNG_THREAD_STACK_SIZE
        #define PAL_NOISE_TRNG_THREAD_STACK_SIZE (1024 * 32)
    #endif
#endif

#endif /* PAL_DEFAULT_AMIGAOS_CONFIGURATION_H_ */
