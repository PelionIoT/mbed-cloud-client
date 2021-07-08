/* Copyright (c) 2021 Pelion
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
 */

#ifndef PAL_DEFAULT_ZEPHYR_CONFIGURATION_H_
#define PAL_DEFAULT_ZEPHYR_CONFIGURATION_H_


#ifndef PAL_SEMAPHORE_MAX_COUNT
    #define PAL_SEMAPHORE_MAX_COUNT UINT32_MAX
#endif

#ifndef PAL_USE_HW_ROT
    #define PAL_USE_HW_ROT 0
#endif

#ifndef PAL_USE_HW_RTC
    #define PAL_USE_HW_RTC 0
#endif

#ifndef PAL_USE_HW_TRNG
    #define PAL_USE_HW_TRNG 0
#endif

#ifndef PAL_USE_INTERNAL_FLASH
    #define PAL_USE_INTERNAL_FLASH 0
#endif

#ifndef PAL_INT_FLASH_NUM_SECTIONS
    #define PAL_INT_FLASH_NUM_SECTIONS 2
#endif

#ifndef PAL_USE_SECURE_TIME
	#define PAL_USE_SECURE_TIME 1
#endif

#ifndef PAL_USE_FILESYSTEM
    #define PAL_USE_FILESYSTEM 0
#endif

/*****************************************************************************/
/* Network                                                                   */
/*****************************************************************************/

#ifndef PAL_SOCKET_MAX
    #define PAL_SOCKET_MAX 1
#endif

#ifndef PAL_SOCKET_USE_LONG_POLLING
    #define PAL_SOCKET_USE_LONG_POLLING 1
#endif

#ifndef PAL_SOCKET_USE_LONG_POLLING_THREAD
    #define PAL_SOCKET_USE_LONG_POLLING_THREAD 0
#endif

#ifndef PAL_SOCKET_USE_K_WORK_POLL
    #define PAL_SOCKET_USE_K_WORK_POLL 0
#endif

#ifndef PAL_DEFAULT_RTT_ESTIMATE
    #define PAL_DEFAULT_RTT_ESTIMATE 1
#endif

#if !defined(PAL_SUPPORT_IP_V4) && defined(CONFIG_NET_IPV4)
	#define PAL_SUPPORT_IP_V4 1
#else
	#define PAL_SUPPORT_IP_V4 0
#endif

#if !defined(PAL_SUPPORT_IP_V6) && defined(CONFIG_NET_IPV6)
	#define PAL_SUPPORT_IP_V6 1
#else
	#define PAL_SUPPORT_IP_V6 0
#endif

#if !defined(PAL_SUPPORT_NAT64) && PAL_SUPPORT_IP_V6
    #define PAL_SUPPORT_NAT64 1
#endif

#ifndef PAL_DNS_API_VERSION
    #define PAL_DNS_API_VERSION 3
#endif

#ifndef PAL_DNS_CACHE_MAX
    #define PAL_DNS_CACHE_MAX 1
#endif

#ifndef PAL_DNS_TIMEOUT_MS
    #define PAL_DNS_TIMEOUT_MS (60*1000)
#endif

#ifndef PAL_USE_APPLICATION_NETWORK_CALLBACK
    #define PAL_USE_APPLICATION_NETWORK_CALLBACK 0
#endif

/*****************************************************************************/
/* RTOS                                                                      */
/*****************************************************************************/

#ifndef PAL_THREADS_MAX_COUNT
    #define PAL_THREADS_MAX_COUNT 1
#endif

#ifndef PAL_STACKS_MAX_SIZE
    #ifdef MBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE
        #define PAL_STACKS_MAX_SIZE MBED_CONF_NS_HAL_PAL_EVENT_LOOP_THREAD_STACK_SIZE
    #else
        #define PAL_STACKS_MAX_SIZE (8 * 1024)
    #endif
#endif

#ifndef PAL_USE_APPLICATION_REBOOT
    #define PAL_USE_APPLICATION_REBOOT 0
#endif

/*****************************************************************************/
/* TLS                                                                       */
/*****************************************************************************/

#ifndef PAL_USE_SSL_SESSION_RESUME
    #define PAL_USE_SSL_SESSION_RESUME 0
#endif

#endif /* PAL_DEFAULT_ZEPHYR_CONFIGURATION_H_ */
