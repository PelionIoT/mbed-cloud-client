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

#ifndef __SXOS_SOTP_H__
#define __SXOS_SOTP_H__

#define PAL_ENABLE_X509                         1
#define PAL_USE_HW_ROT                          1
#define PAL_USE_HW_RTC                          1
#define PAL_USE_HW_TRNG                         0
#define PAL_SIMULATOR_FLASH_OVER_FILE_SYSTEM    1
#define PAL_USE_SECURE_TIME                     1

// Only cellular (NBIoT) interface is supported
#define PAL_MAX_SUPORTED_NET_INTERFACES         1

// Define security sector address for ROT key
#define ROT_MEM_ADDR  0x00001000

#endif // !__SXOS_SOTP_H__
