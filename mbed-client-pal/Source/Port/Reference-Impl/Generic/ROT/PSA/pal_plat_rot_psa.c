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

/* for PSA Linux ROT  is not yet supported */

#if defined  MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT 
#include "pal.h"

#if (PAL_USE_HW_ROT == 0)

palStatus_t pal_plat_osGetRoT(uint8_t * key, size_t keyLenBytes)
{
    return PAL_ERR_ITEM_NOT_EXIST;
}

palStatus_t pal_plat_osSetRoT(uint8_t * key, size_t keyLenBytes)
{
    return PAL_ERR_ITEM_NOT_EXIST;
}

#endif // (PAL_USE_HW_ROT == 0)
#endif // defined MBED_CONF_MBED_CLOUD_CLIENT_PSA_SUPPORT && !defined MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_SST_SUPPORT