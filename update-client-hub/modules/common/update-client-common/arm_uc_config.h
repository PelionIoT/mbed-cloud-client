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

#ifndef ARM_UPDATE_CONFIG_H
#define ARM_UPDATE_CONFIG_H

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#ifndef MAX_SOURCES
#define MAX_SOURCES 10
#endif

#ifndef ARM_UC_SOCKET_MAX_RETRY
#define ARM_UC_SOCKET_MAX_RETRY 3
#endif

/* Total memory allocated for download buffers.
   For HTTP sources, this number cannot be below 1 KiB.
*/
#ifdef MBED_CLOUD_CLIENT_UPDATE_BUFFER
#if MBED_CLOUD_CLIENT_UPDATE_BUFFER < 1024
#error MBED_CLOUD_CLIENT_UPDATE_BUFFER must be 1024 bytes or more
#else
#define ARM_UC_BUFFER_SIZE MBED_CLOUD_CLIENT_UPDATE_BUFFER
#endif
#endif

#ifndef ARM_UC_BUFFER_SIZE
#define ARM_UC_BUFFER_SIZE 1024
#endif

#ifndef ARM_UC_USE_KCM
#define ARM_UC_USE_KCM 1
#define ARM_UPDATE_USE_KCM 1
#endif

#ifndef ARM_UC_USE_PAL_CRYPTO
#define ARM_UC_USE_PAL_CRYPTO 1
#endif

#define MBED_CLOUD_CLIENT_UPDATE_CERTIFICATE_PREFIX "mbed.UpdateAuthCert."
#define MBED_CLOUD_CLIENT_UPDATE_CERTIFICATE_DEFAULT "mbed.UpdateAuthCert"
#define MBED_CLOUD_SHA256_BYTES (256/8)
#define MBED_CLOUD_BASE64_SIZE(X) (((X + 2)/3)*4)
#define MBED_CLOUD_CLIENT_UPDATE_CERTIFICATE_NAME_SIZE (MBED_CLOUD_BASE64_SIZE(MBED_CLOUD_SHA256_BYTES) + sizeof(MBED_CLOUD_CLIENT_UPDATE_CERTIFICATE_PREFIX))


// NOTE: The charset must be sorted except for the trailing character which is used as a padding character.
#define MBED_CLOUD_UPDATE_BASE64_CHARSET "0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"

#ifndef ARM_UC_SCHEDULER_STORAGE_POOL_SIZE
#define ARM_UC_SCHEDULER_STORAGE_POOL_SIZE 32
#endif

#endif // ARM_UPDATE_CONFIG_H
