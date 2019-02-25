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

#ifndef PAL_MBEDOS_SST_CONFIGURATION_H_
#define PAL_MBEDOS_SST_CONFIGURATION_H_

/*!
* \brief This file is for more specific definitions (per board or module if needed).
*        if this file is defined it will be included from pal_configuration.h
*        if not, the default file will be included - if needed
*/

//define sst (kvstore) support flag
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
    #define MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT
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

//issue a warning if PAL_USE_INTERNAL_FLASH!=0 and or define PAL_USE_INTERNAL_FLASH=0
#if PAL_USE_INTERNAL_FLASH //PAL_USE_INTERNAL_FLASH != 0
    #warning "Internal flash APIs should be disabled with KVStore"
#else
    #define PAL_USE_INTERNAL_FLASH 0
#endif

#include "mbedOS_default.h"

#endif /* PAL_MBEDOS_SST_CONFIGURATION_H_ */
