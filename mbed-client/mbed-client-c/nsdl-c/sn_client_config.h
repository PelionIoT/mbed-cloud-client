/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SN_CLIENT_CONFIG_H
#define SN_CLIENT_CONFIG_H

#ifdef __DOXYGEN__

/**
* \brief Configuration options (set of defines and values)
*
*  This lists set of compile-time options that needs to be used to enable
*  or disable features selectively, and set the values for the mandatory
*  parameters.
*/

/**
 * \def DISABLE_RESOURCE_TYPE
 * \brief For Disabling Resource type
 *
 */
#define DISABLE_RESOURCE_TYPE

/**
 * \def DISABLE_INTERFACE_DESCRIPTION
 * \brief For Disabling Resource type
 *
 */
#define DISABLE_INTERFACE_DESCRIPTION

/**
 * \def MBED_CLIENT_PRINT_COAP_PAYLOAD
 * \brief If enabled this will print out the CoAP package payload.
 */
#define MBED_CLIENT_PRINT_COAP_PAYLOAD
#endif

// Include user defined configuration.
#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#ifdef MBED_CLIENT_USER_CONFIG_FILE
#include MBED_CLIENT_USER_CONFIG_FILE
#endif

#endif // SN_CONFIG_H
