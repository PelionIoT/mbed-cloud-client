// ----------------------------------------------------------------------------
// Copyright 2021 Pelion.
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

#ifndef MULTICAST_CONFIG_H
#define MULTICAST_CONFIG_H

// Include config
#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

// UCHub case is only valid when fota is not enabled
#if !defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
    #if defined(MBED_CLOUD_CLIENT_SUPPORT_MULTICAST_UPDATE)
        #if defined(MBED_CLOUD_CLIENT_SUPPORT_UPDATE)
            #define LIBOTA_ENABLED 1
            // Using UCHub
            #include "update-client-common/arm_uc_config.h"
            #define MULTICAST_UCHUB_INTEGRATION
            // Used to check that fragment size is multiple of this value when setting it dynamically
            #define LIBOTA_FRAGMENT_SIZE_DIVISOR MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
        #endif
    #endif
#else // !defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
    // fota is enabled
    #include "fota/fota_config.h"
    #if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT != FOTA_MULTICAST_UNSUPPORTED)

        #define LIBOTA_ENABLED 1
        // Using fota
        #define MULTICAST_FOTA_INTEGRATION

        // these are done in arm_uc_config in the UCHub side
        #if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
            #define ARM_UC_MULTICAST_BORDER_ROUTER_MODE
        #elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
            #define ARM_UC_MULTICAST_NODE_MODE
        #else
            // can do this error here as FOTA_MULTICAST_UNSUPPORTED is checked above
            #error "Configuration error: unknown value for MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT"
        #endif

        // TODO: can we get this definitely somehow?
        // Used to check that fragment size is multiple of this value when setting it dynamically
        #define LIBOTA_FRAGMENT_SIZE_DIVISOR 128

        // Sanity checking
        #include "fota_crypto_defs.h"
        #include "otaLIB.h"

        #if (OTA_WHOLE_FW_CHECKSUM_LENGTH != FOTA_CRYPTO_HASH_SIZE)
            #error "Configuration mismatch; OTA_WHOLE_FW_CHECKSUM_LENGTH != FOTA_CRYPTO_HASH_SIZE"
        #endif

    #endif // (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT != FOTA_MULTICAST_UNSUPPORTED)
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // #ifndef MULTICAST_CONFIG_H
