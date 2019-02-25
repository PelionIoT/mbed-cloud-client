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

#ifndef MANIFEST_MANAGER_COMMON_H
#define MANIFEST_MANAGER_COMMON_H

#include "update-client-manifest-manager/update-client-manifest-types.h"
#include "update-client-common/arm_uc_trace.h"
#include <string.h>
#include <stdio.h>

enum arm_uc_mmEvent {
    ARM_UC_MM_EVENT_INVALID = 0,
    ARM_UC_MM_EVENT_BEGIN,
};

#define ARRAY_SIZE(X)\
    (sizeof(X)/sizeof((X)[0]))

#define ARM_UC_MM_SET_BUFFER(BUF,ARRAY)\
    do {\
        (BUF).ptr = (ARRAY);\
        (BUF).size = 0;\
        (BUF).size_max = sizeof(ARRAY);\
    } while(0)

#define ARM_UC_MFST_SET_ERROR(VAR, ERROR)\
    do {\
    VAR.code = ERROR;\
    if (VAR.error != ERR_NONE) {\
        arm_uc_mmPersistentContext.errorFile = __FILE__;\
        arm_uc_mmPersistentContext.errorLine = __LINE__;\
    }\
    }while (0)

// Define htobe
#if defined(__ICCARM__)
#include <intrinsics.h>
#endif

#ifndef htobe
static inline uint32_t htobe(uint32_t x)
{
#if BYTE_ORDER == LITTLE_ENDIAN
#if defined(__ICCARM__)
    return __REV(x);
#else
    return __builtin_bswap32(x);
#endif
#else
    return x;
#endif
}
#endif

#endif //MANIFEST_MANAGER_COMMON_H
