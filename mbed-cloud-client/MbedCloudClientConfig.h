// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifndef MBED_CLOUD_CLIENT_CONFIG_H
#define MBED_CLOUD_CLIENT_CONFIG_H

#include <stdint.h>

/*! \file MbedCloudClientConfig.h
* \brief Configuration options (set of defines and values).
*
*  This lists a set of compile-time options that needs to be used to enable
*  or disable features selectively, and set the values for the mandatory
*  parameters.
*/

#if defined (__ICCARM__)
#define m2m_deprecated
#else
#define m2m_deprecated __attribute__ ((deprecated))
#endif

#ifdef __DOXYGEN__
// This __DOXYGEN__ block is for documentation purposes only and it does not affect application build.

/**
* \def MBED_CLOUD_CLIENT_ENDPOINT_TYPE
*
* \brief This is mandatory MACRO and MUST be enabled. You MUST define it like this #define MBED_CLOUD_CLIENT_ENDPOINT_TYPE "default".
*/
#define MBED_CLOUD_CLIENT_ENDPOINT_TYPE          /* "default" */

/**
* \def MBED_CLOUD_CLIENT_LIFETIME
*
* \brief This is mandatory MACRO and MUST be enabled. You MUST define it like this: #define MBED_CLOUD_CLIENT_LIFETIME 3600.
* This value denotes time in seconds.
*/
#define MBED_CLOUD_CLIENT_LIFETIME               /* 3600 */

/**
* \def MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP
*
* \brief Enable this MACRO if you want to enable UDP mode for the client.
*/
#define MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP

/**
* \def MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP
*
* \brief Enable this MACRO if you want to enable TCP mode for the client.
*/
#define MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP

/**
* \def MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE
*
* \brief Enable this MACRO if you want to enable UDP_QUEUE mode for the client.
*/
#define MBED_CLOUD_CLIENT_TRANSPORT_MODE_UDP_QUEUE

/**
* \def MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE
*
* \brief Enable this MACRO if you want to enable TCP_QUEUE mode for the client.
*/
#define MBED_CLOUD_CLIENT_TRANSPORT_MODE_TCP_QUEUE

#endif // __DOXYGEN__

/**
* \def MBED_CLOUD_CLIENT_LISTEN_PORT
*
* \brief This is mandatory MACRO and is set to 0 by default. This implies that the client picks a random port
 * for listening to the incoming connection.
*/
#define MBED_CLOUD_CLIENT_LISTEN_PORT           0

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#include "MbedCloudClientConfigCheck.h"

#endif // MBED_CLOUD_CLIENT_CONFIG_H
