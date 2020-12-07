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

#ifndef _FCC_PAL_CRYPTO_COFIGURATION_H
#define _FCC_PAL_CRYPTO_COFIGURATION_H
#include "limits.h"

#ifdef PAL_USER_DEFINED_CONFIGURATION
#include PAL_USER_DEFINED_CONFIGURATION
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

//! Enable the CMAC functionality \note This flag lets the bootloader be compiled without CMAC.
#ifndef PAL_CMAC_SUPPORT
#define PAL_CMAC_SUPPORT 1
#endif //PAL_CMAC_SUPPORT

//! Certificate date validation in Unix time format.
#ifndef PAL_CRYPTO_CERT_DATE_LENGTH
#define PAL_CRYPTO_CERT_DATE_LENGTH sizeof(uint64_t)
#endif

#endif //_PAL_COFIGURATION_H