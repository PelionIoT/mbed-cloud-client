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

#ifndef PAL_SXOS_CONFIGURATION_H_
/*! \brief This file sets configuration for PAL porting on SXOS.
    \note All configurations that are configured in this file overwrite their defaults values
    \note Default Values can be found at Sources/PAL-impl/Services-API/pal_configuration.h
    \note
  */

// __BYTE_ORDER not defined by the compiler
#ifndef PAL_COMPILATION_ENDIANITY
#define PAL_COMPILATION_ENDIANITY 0
#endif


//!< Number partitions on SD card used by PAL File System
#ifndef PAL_NUMBER_OF_PARTITIONS
#define PAL_NUMBER_OF_PARTITIONS 1
#endif

// On ChaN/FAT the mount point states the physical drive directly if multi-partition is not enabled.
// 2 equals to SDDISK and RAMDISK to 0.

//!< Mount point for primary file system partition
#ifndef PAL_FS_MOUNT_POINT_PRIMARY
    #if (PAL_NUMBER_OF_PARTITIONS == 1)
        #define PAL_FS_MOUNT_POINT_PRIMARY    "/mcc"
    #else
        #error "only single-partition mode supported"
    #endif
#endif

//!< Mount point for secondary file system partition
#ifndef PAL_FS_MOUNT_POINT_SECONDARY
    #if (PAL_NUMBER_OF_PARTITIONS == 1)
        #define PAL_FS_MOUNT_POINT_SECONDARY    "/mcc"
    #else
        #error "only single-partition mode supported"
    #endif
#endif

 //!< Max number of allowed timer
#ifndef PAL_MAX_NUM_OF_TIMERS
    #define PAL_MAX_NUM_OF_TIMERS 5
#endif

//!< Max given token for a semaphore
#ifndef PAL_SEMAPHORE_MAX_COUNT
    #define PAL_SEMAPHORE_MAX_COUNT 255
#endif

#ifndef PAL_INT_FLASH_NUM_SECTIONS
    #define PAL_INT_FLASH_NUM_SECTIONS 2
#endif

// This file is a copy of FreeRTOS_default.h and eg. flash addresses are not reflecting reality,
// but the sizes need to be there and match somewhat other platforms to have functional SOTP.


 /*\brief  Starting Address for section 1 Minimum requirement size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_1_ADDRESS
    #define PAL_INTERNAL_FLASH_SECTION_1_ADDRESS    0xFE000
#endif

/*\brief  Starting Address for section 2 Minimum requirement size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_ADDRESS
    #define PAL_INTERNAL_FLASH_SECTION_2_ADDRESS    0xFF000
#endif

/*\brief  Size for section 1*/
#ifndef PAL_INTERNAL_FLASH_SECTION_1_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_1_SIZE       0x1000
#endif

/*\brief  Size for section 2*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_2_SIZE       0x1000
#endif

#ifndef PAL_USE_INTERNAL_FLASH
    #define PAL_USE_INTERNAL_FLASH  1
#endif

#ifndef PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM
    #define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM 1
#endif

#ifndef PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT
    #define PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT 1
#endif

#ifndef PAL_USE_HW_ROT
    #define PAL_USE_HW_ROT     1
#endif

#ifndef PAL_USE_HW_RTC
    #define PAL_USE_HW_RTC    0
#endif

#ifndef PAL_USE_SECURE_TIME
    #define PAL_USE_SECURE_TIME 0
#endif

#ifndef PAL_USE_SOTP
    #define PAL_USE_SOTP    0
#endif

/* To relax some pal_init/pal_destroy tests when running unit tests from testapp.
 * Can be that unit test is not only instance that initializes pal. */
#ifndef PAL_INITIALIZED_BEFORE_TESTS
    #define PAL_INITIALIZED_BEFORE_TESTS 0
#endif

#endif /* PAL_SXOS_CONFIGURATION_H_ */
