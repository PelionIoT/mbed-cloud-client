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

#ifndef _PAL_COFIGURATION_H
#define _PAL_COFIGURATION_H
#include "limits.h"

#if 0
// This block is useful when building on new environment and one needs to find out,
// how to pass the "include-file.h" macro value via multiple layers of scripts
// and different reserved char escaping conventions.
#define XSTR(x) STR(x)
#define STR(x) #x

#pragma message "The value of PAL_USER_DEFINED_CONFIGURATION: " XSTR(PAL_USER_DEFINED_CONFIGURATION)
#endif

#ifdef PAL_USER_DEFINED_CONFIGURATION
    #include PAL_USER_DEFINED_CONFIGURATION
#endif

/*! \file pal_configuration.h
*   \brief PAL Configuration.
*   This file contains PAL configuration information.
*
*   Following are examples of configuration included:
*       1. The flags to enable or disable features.
*       2. The configuration of the number of objects provided by PAL (such as the number of threads supported) or their sizes.
*       3. The configuration of supported cipher suites.
*       4. The configuration for flash memory usage.
*       5. The configuration for the root of trust.
*/

/* If you need any board-specific configuration, please include this define
*/
#ifdef PAL_BOARD_SPECIFIC_CONFIG
    #include PAL_BOARD_SPECIFIC_CONFIG
#endif

/* Lets the user choose the platform configuration file.
    \note If the user does not specify a platform configuration file,
    \note PAL uses a default configuration set that can be found at Configs/pal_config folder
  */

#ifdef PAL_PLATFORM_DEFINED_CONFIGURATION
    #include PAL_PLATFORM_DEFINED_CONFIGURATION
#elif defined(__linux__) || defined(__LINUX__)
    #include "Linux_default.h"
#elif defined(__FREERTOS__)
    #include "FreeRTOS_default.h"
#elif defined(__NXP_FREERTOS__)
    #include "NXP_default.h"
#elif defined(__RENESAS_EK_RA6M3__)
    #include "Renesas/Renesas_default.h"
#elif defined(__MBED__)
    #include "mbedOS_default.h"
#elif defined(__SXOS__)
    #include "sxos_default.h"
#elif defined(__RTX)
    #include "RTX_MW_default.h"
#else
    #error "Please specify the platform PAL_PLATFORM_DEFINED_CONFIGURATION"
#endif

/**
 * \def PAL_USE_HW_ROT
 * Use hardware Root-of-trust.
 */
#ifndef PAL_USE_HW_ROT
    #define PAL_USE_HW_ROT     1
#endif

/**
 * \def PAL_USE_HW_RTC
 * Use hardware RTC.
 */
#ifndef PAL_USE_HW_RTC
    #define PAL_USE_HW_RTC    1
#endif

/**
 * \def PAL_USE_HW_TRNG
 * Use hardware TRNG. Disable for platforms which do not support TRNG.
 */
#ifndef PAL_USE_HW_TRNG
    #define PAL_USE_HW_TRNG    1
#endif

/**
 * \def PAL_USE_SECURE_TIME
 * Enables client-side verification for certificate time.
 */
#ifndef PAL_USE_SECURE_TIME
    #define PAL_USE_SECURE_TIME    1
#endif

#ifndef PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM
    #define PAL_SIMULATOR_FILE_SYSTEM_OVER_RAM 0
#endif

#ifndef PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM
    #define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM 0
#endif

#ifndef PAL_USE_INTERNAL_FLASH
    #define PAL_USE_INTERNAL_FLASH 0
#endif

/*
 * Network configuration
 */
// PAL configuration options
#ifndef PAL_NET_TCP_AND_TLS_SUPPORT
    #define PAL_NET_TCP_AND_TLS_SUPPORT         true //!< Add PAL support for TCP.
#endif

#ifndef PAL_NET_DNS_SUPPORT
    #define PAL_NET_DNS_SUPPORT                 true //!< Add PAL support for DNS lookup.
#endif

#if (PAL_NET_DNS_SUPPORT == true) && !(defined(PAL_DNS_API_VERSION))
#define PAL_DNS_API_VERSION 0 //!< syncronous DNS API
#endif

#ifndef PAL_NET_SERVER_SOCKET_API
    #define PAL_NET_SERVER_SOCKET_API                 true //!< Add PAL support for server socket.
#endif

#ifndef PAL_SUPPORT_IP_V4
    #define PAL_SUPPORT_IP_V4                 1 //!< support IPV4 as default
#endif
#ifndef PAL_SUPPORT_IP_V6
    #define PAL_SUPPORT_IP_V6                 1 //!< support IPV6 as default
#endif

//values for PAL_NET_DNS_IP_SUPPORT
#define PAL_NET_DNS_ANY          0    //!< if PAL_NET_DNS_IP_SUPPORT is set to PAL_NET_DNS_ANY pal_getAddressInfo will return the first available IPV4 or IPV6 address
#define PAL_NET_DNS_IPV4_ONLY    2    //!< if PAL_NET_DNS_IP_SUPPORT is set to PAL_NET_DNS_IPV4_ONLY pal_getAddressInfo will return the first available IPV4 address
#define PAL_NET_DNS_IPV6_ONLY    4    //!< if PAL_NET_DNS_IP_SUPPORT is set to PAL_NET_DNS_IPV6_ONLY pal_getAddressInfo will return the first available IPV6 address

#ifndef PAL_NET_DNS_IP_SUPPORT
#if (PAL_SUPPORT_IP_V6 == 1) && (PAL_SUPPORT_IP_V4 == 1)
    #define PAL_NET_DNS_IP_SUPPORT  0 //!< sets the type of IP addresses returned by  pal_getAddressInfo
#elif (PAL_SUPPORT_IP_V6 == 1)
    #define PAL_NET_DNS_IP_SUPPORT  4 //!< sets the type of IP addresses returned by  pal_getAddressInfo
#else
    #define PAL_NET_DNS_IP_SUPPORT  2 //!< sets the type of IP addresses returned by  pal_getAddressInfo
#endif
#endif

//! The maximum number of interfaces that can be supported at a time.
#ifndef PAL_MAX_SUPORTED_NET_INTERFACES
    #define PAL_MAX_SUPORTED_NET_INTERFACES 1
#endif

//! Stack size for thread created when calling pal_getAddressInfoAsync
#ifndef PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE
    #define PAL_NET_ASYNC_DNS_THREAD_STACK_SIZE (1024 * 2)
#endif

//! If you want PAL to not perform a rollback/cleanup when main PAL init fails, please set this flag to `false`
#ifndef PAL_CLEANUP_ON_INIT_FAILURE
    #define PAL_CLEANUP_ON_INIT_FAILURE true
#endif

/*
 * RTOS configuration
 */

/*! \brief Determines if PAL modules are thread safe.
 *
 *    1 - thread safety is enabled, \n
 *    0 - thread safety is disabled
 */
#ifndef PAL_THREAD_SAFETY
    #define PAL_THREAD_SAFETY 1
#endif

/*! Initial time (in milliseconds) until thread stack cleanup (mbedOS only).
 *
 * This is the amount of time to wait before checking that a thread has completed in order to free its stack.
 */
#ifndef PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC
    #define PAL_RTOS_THREAD_CLEANUP_TIMER_MILISEC 200
#endif

//! Determines the size of the initial random buffer (in bytes) held by PAL for random the algorithm.
#ifndef PAL_INITIAL_RANDOM_SIZE
    #define PAL_INITIAL_RANDOM_SIZE 48
#endif

#ifndef PAL_RTOS_WAIT_FOREVER
    #define PAL_RTOS_WAIT_FOREVER UINT_MAX
#endif

/*
 * TLS configuration
 */

//! The maximum number of supported cipher suites.
#ifndef PAL_MAX_ALLOWED_CIPHER_SUITES
    #define PAL_MAX_ALLOWED_CIPHER_SUITES 1
#endif

//! This value is in milliseconds.

/*
 * /def PAL_DTLS_PEER_MIN_TIMEOUT
 * /brief Define the DTLS peer minimum timeout value.
 */

#ifndef PAL_DTLS_PEER_MIN_TIMEOUT
    #define PAL_DTLS_PEER_MIN_TIMEOUT 10000
#endif

//! The debug threshold for TLS API.
#ifndef PAL_TLS_DEBUG_THRESHOLD
    #define PAL_TLS_DEBUG_THRESHOLD 5
#endif

//! 32 or 48 (depends on the curve) bytes for the X,Y coordinates and 1 for the normalized/non-normalized
#ifndef PAL_CERT_ID_SIZE
    #define PAL_CERT_ID_SIZE 33
#endif

#ifndef PAL_ENABLE_PSK
    #define PAL_ENABLE_PSK 0
#endif

#ifndef PAL_ENABLE_X509
    #define PAL_ENABLE_X509 1
#endif

// Defines the cipher suites for TLS. Only one cipher suite per device available.
#define PAL_TLS_PSK_WITH_AES_128_CCM_8_SUITE                    0x01
#define PAL_TLS_PSK_WITH_AES_256_CCM_8_SUITE                    0x02
#define PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_SUITE            0x04
#define PAL_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_SUITE       0x08
#define PAL_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_SUITE       0x10
#define PAL_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256_SUITE      0x20

//! Use the default cipher suite for TLS/DTLS operations
#if (PAL_ENABLE_X509 == 1)
    #ifndef PAL_TLS_CIPHER_SUITE
        #define PAL_TLS_CIPHER_SUITE PAL_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_SUITE
    #endif
#elif (PAL_ENABLE_PSK == 1)
    #ifndef PAL_TLS_CIPHER_SUITE
        #define PAL_TLS_CIPHER_SUITE PAL_TLS_PSK_WITH_AES_128_CCM_8_SUITE
    #endif
#endif

//! Enable the CMAC functionality \note This flag lets the bootloader be compiled without CMAC.
#ifndef PAL_CMAC_SUPPORT
    #define PAL_CMAC_SUPPORT 1
#endif //PAL_CMAC_SUPPORT

/*
 * UPDATE configuration
 */

#define PAL_UPDATE_USE_FLASH 1
#define PAL_UPDATE_USE_FS    2

#ifndef PAL_UPDATE_IMAGE_LOCATION
    #define PAL_UPDATE_IMAGE_LOCATION PAL_UPDATE_USE_FS     //!< Determines the storage option to use, file System or flash
#endif

//! Certificate date validation in Unix time format.
#ifndef PAL_CRYPTO_CERT_DATE_LENGTH
    #define PAL_CRYPTO_CERT_DATE_LENGTH sizeof(uint64_t)
#endif

/*
 * File system configuration
 */


/*! \brief Determines if filesystem is used by the underlying platform
 *
 * 1 - fileSystem is used
 * 0 - filesystem is not used
 */
#ifndef PAL_USE_FILESYSTEM
    #define PAL_USE_FILESYSTEM 1
#endif

/*! \brief The number of file system partitions
 *
 * 1 - There is a single partition in which the ARM client applications create and remove files (but not format it). This is the default. \n
 * 2 - There are two partitions in which ARM client applications may format or create and remove files,
 *     depending on PAL_PRIMARY_PARTITION_PRIVATE and PAL_SECONDARY_PARTITION_PRIVATE
 */
#ifndef PAL_NUMBER_OF_PARTITIONS
    #define PAL_NUMBER_OF_PARTITIONS 1 // Default partitions
#endif

#if (PAL_NUMBER_OF_PARTITIONS > 2)
    #error "PAL_NUMBER_OF_PARTITIONS cannot be more then 2"
#endif

/*! \brief Determines whether the primary partition is used only for the ARM client application.
 *
 * 1 - The primary partition is exclusively dedicated to the ARM client applications. \
 * 0 - The primary partition is used for storing other files as well.
 */
#ifndef PAL_PRIMARY_PARTITION_PRIVATE
    #define PAL_PRIMARY_PARTITION_PRIVATE 0
#endif

/*! \brief Determines whether the secondary partition is used only for the ARM client application.
 *
 *  1 - The secondary partition is exclusively dedicated to the ARM client applications.
 *  0 - The secondary partition is used for storing other files as well.
 */
#ifndef PAL_SECONDARY_PARTITION_PRIVATE
    #define PAL_SECONDARY_PARTITION_PRIVATE 0
#endif

//! The location of the primary mount point for the file system
#ifndef PAL_FS_MOUNT_POINT_PRIMARY
    #define PAL_FS_MOUNT_POINT_PRIMARY  ""
#endif

//! The location of the secondary mount point for the file system
#ifndef PAL_FS_MOUNT_POINT_SECONDARY
    #define PAL_FS_MOUNT_POINT_SECONDARY ""
#endif

// Update

#ifndef PAL_UPDATE_FIRMWARE_MOUNT_POINT
    #define PAL_UPDATE_FIRMWARE_MOUNT_POINT PAL_FS_MOUNT_POINT_PRIMARY
#endif

//! The location of the firmware update folder
#ifndef PAL_UPDATE_FIRMWARE_DIR
    #define PAL_UPDATE_FIRMWARE_DIR "/firmware"
#endif

#ifndef PAL_INT_FLASH_NUM_SECTIONS
    #define PAL_INT_FLASH_NUM_SECTIONS 0
#endif

#if PAL_USE_HW_TRNG
    //! Delay (in milliseconds) for TRNG noise collecting thread used between calls to TRNG
    #ifndef PAL_NOISE_TRNG_THREAD_DELAY_MILLI_SEC
        #define PAL_NOISE_TRNG_THREAD_DELAY_MILLI_SEC (1000 * 60) // one minute
    #endif
    //! Stack size for TRNG noise collecting thread
    #ifndef PAL_NOISE_TRNG_THREAD_STACK_SIZE
        #define PAL_NOISE_TRNG_THREAD_STACK_SIZE 1536 // 1.5K
    #endif
#endif

#ifndef PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC
    #define PAL_DEVICE_KEY_DERIVATION_BACKWARD_COMPATIBILITY_CALC 0
#endif

/*! \brief Starting Address for section 1
 *
 * Minimum required size is 1KB and section must be consecutive sectors
 */
#ifndef PAL_INTERNAL_FLASH_SECTION_1_ADDRESS
    #define PAL_INTERNAL_FLASH_SECTION_1_ADDRESS    0
#endif
/*! \brief Starting Address for section 2
 *
 * Minimum required size is 1KB and section must be consecutive sectors*/
#ifndef PAL_INTERNAL_FLASH_SECTION_2_ADDRESS
    #define PAL_INTERNAL_FLASH_SECTION_2_ADDRESS    0
#endif
//! Size for section 1
#ifndef PAL_INTERNAL_FLASH_SECTION_1_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_1_SIZE       0
#endif
//! Size for  section 2
#ifndef PAL_INTERNAL_FLASH_SECTION_2_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_2_SIZE       0
#endif

#ifndef PAL_SIMULATOR_TEST_ENABLE
    #define PAL_SIMULATOR_TEST_ENABLE    0
#endif

#if (PAL_SIMULATOR_TEST_ENABLE == 1)

    #undef PAL_SIMULATE_RTOS_REBOOT
    #define PAL_SIMULATE_RTOS_REBOOT 1

    #undef PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM
    #define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM    1

//! Overwrites the format command to remove all files and directories only for Linux*/
    #undef PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT
    #define PAL_SIMULATOR_FS_RM_INSTEAD_OF_FORMAT 1
#endif //PAL_SIMULATOR_TEST_ENABLE

#ifndef PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM
    #define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM    0
#endif

#if PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM

    #undef PAL_USE_INTERNAL_FLASH
    #define PAL_USE_INTERNAL_FLASH  1

    #undef PAL_INT_FLASH_NUM_SECTIONS
    #define PAL_INT_FLASH_NUM_SECTIONS 2

    #ifndef PAL_SIMULATOR_SOTP_AREA_SIZE
        #define PAL_SIMULATOR_SOTP_AREA_SIZE    4096 //!< must be power of two the can be divded to page size without reminder and must be a multiple of sector size
    #endif

    #ifndef SIMULATE_FLASH_SECTOR_SIZE
        #define SIMULATE_FLASH_SECTOR_SIZE      4096 //!<  Flash sector size
    #endif

    #ifndef SIMULATE_FLASH_DIR
        #define SIMULATE_FLASH_DIR              "" //!< Directory that holds the flash simulator file
    #endif

    #ifndef SIMULATE_FLASH_FILE_NAME
        #define SIMULATE_FLASH_FILE_NAME        SIMULATE_FLASH_DIR"/flashSim" //!< File name and path to the flash simulator file
    #endif

    #ifndef SIMULATE_FLASH_PAGE_SIZE
        #define SIMULATE_FLASH_PAGE_SIZE        8 //!< Minumum writing uint to flash (2, 4, 8, 16)
    #endif

    #if PAL_SIMULATOR_SOTP_AREA_SIZE < 4096
        #error Minimum Size of 4K
    #endif

    /* Note - In simulator mode all flash areas are overrided with the simulation sizes and address*/

/* \brief Size for section 1
 *
 * Minimum required size is 1KB and section must be consecutive sectors
 */
    #undef PAL_INTERNAL_FLASH_SECTION_1_SIZE
    #define PAL_INTERNAL_FLASH_SECTION_1_SIZE       PAL_SIMULATOR_SOTP_AREA_SIZE

    #undef PAL_INTERNAL_FLASH_SECTION_2_SIZE
/*! \brief Size for section 2
 *
 * Minimum requirement size is 1KB and section must be consecutive sectors
 */
    #define PAL_INTERNAL_FLASH_SECTION_2_SIZE       PAL_SIMULATOR_SOTP_AREA_SIZE

    #undef PAL_INTERNAL_FLASH_SECTION_1_ADDRESS
    //! Starting Address for section 1 */
    #define PAL_INTERNAL_FLASH_SECTION_1_ADDRESS    0

    #undef PAL_INTERNAL_FLASH_SECTION_2_ADDRESS
    //! Starting Address for section 2 */
    #define PAL_INTERNAL_FLASH_SECTION_2_ADDRESS    PAL_INTERNAL_FLASH_SECTION_1_SIZE

#endif //PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM

#define VALUE_TO_STRING(x) #x
#define VALUE(x) VALUE_TO_STRING(x)
#define VAR_NAME_VALUE(var) #var " = "  VALUE(var)

#if (((!PAL_USE_INTERNAL_FLASH && (!PAL_USE_HW_ROT || !PAL_USE_HW_RTC || !PAL_USE_HW_TRNG))  \
        || ((PAL_INT_FLASH_NUM_SECTIONS == 1) && PAL_USE_INTERNAL_FLASH && (!PAL_USE_HW_RTC || !PAL_USE_HW_TRNG)))  \
        && !defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT)
        #pragma message(VAR_NAME_VALUE(PAL_USE_INTERNAL_FLASH))
        #pragma message(VAR_NAME_VALUE(PAL_USE_HW_ROT))
        #pragma message(VAR_NAME_VALUE(PAL_USE_HW_RTC))
        #pragma message(VAR_NAME_VALUE(PAL_USE_HW_TRNG))
        #pragma message(VAR_NAME_VALUE(PAL_INT_FLASH_NUM_SECTIONS))
    #error Minimum configuration setting does not meet the requirements
#endif

#if (((PAL_ENABLE_PSK == 1) && (PAL_ENABLE_X509 == 1)) && !(defined(__linux__) || defined(__LINUX__)))
    #error "Please select only one option: PSK or X509"
#endif

#if ((PAL_ENABLE_PSK == 0) && (PAL_ENABLE_X509 == 0))
    #error "Please select one option: PSK or X509"
#endif

#if ((PAL_ENABLE_PSK == 1) && (PAL_USE_SECURE_TIME == 1))
    #error "PSK feature cannot be configured when using secure time"
#endif

//! Delay (in milliseconds) between calls to TRNG random buffer in case only partial data (PAL_ERR_RTOS_TRNG_PARTIAL_DATA) was generated for the function call
#ifndef PAL_TRNG_COLLECT_DELAY_MILLI_SEC
    #define PAL_TRNG_COLLECT_DELAY_MILLI_SEC 1000
#endif // PAL_TRNG_COLLECT_DELAY_MILLI_SEC

//! define the maximum number of images
#ifndef IMAGE_COUNT_MAX
    #define IMAGE_COUNT_MAX             1
#endif

#define PAL_NOISE_SIZE_BYTES 48 //!< Maximum number of bytes for noise
#define PAL_NOISE_SIZE_BITS (PAL_NOISE_SIZE_BYTES * CHAR_BIT) //!< Maximum number of bits for noise
#define PAL_NOISE_BUFFER_LEN (PAL_NOISE_SIZE_BYTES / sizeof(int32_t)) //!< Length of the noise buffer

// SSL session resume is enabled by default
#ifndef PAL_USE_SSL_SESSION_RESUME
    #define PAL_USE_SSL_SESSION_RESUME 1
#endif

// Sanity check for using static memory buffer with mbedtls.
#ifdef PAL_USE_STATIC_MEMBUF_FOR_MBEDTLS

#if !defined(PAL_STATIC_MEMBUF_SIZE_FOR_MBEDTLS)
    #error "When using PAL_USE_STATIC_MEMBUF_FOR_MBEDTLS, you must also define the size for the static memory buffer with PAL_STATIC_MEMBUF_SIZE_FOR_MBEDTLS."
#endif

#endif // #ifdef PAL_USE_STATIC_MEMBUF_FOR_MBEDTLS

#endif //_PAL_COFIGURATION_H
