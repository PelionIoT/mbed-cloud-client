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

#define ARM_UC_MM_DEBUG_LOG_LEVEL_NONE 0
#define ARM_UC_MM_DEBUG_LOG_LEVEL_VALS 9
#define ARM_UC_MM_DEBUG_LOG_LEVEL_STATES 10

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


#if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
extern volatile uint8_t arm_uc_mm_gDebugLevel;
#define ARM_UC_MM_DEBUG_LOG(LEVEL,...) \
    if(arm_uc_mm_gDebugLevel >= LEVEL) {printf(__VA_ARGS__);}
#else
#define ARM_UC_MM_DEBUG_LOG(LEVEL,...)
#endif

#endif //MANIFEST_MANAGER_COMMON_H
