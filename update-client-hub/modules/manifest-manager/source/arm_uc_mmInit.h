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

#ifndef ARM_UC_MM_INIT_H
#define ARM_UC_MM_INIT_H

#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"

#define ARM_UC_MM_INIT_STATE_LIST\
    ENUM_FIXED(ARM_UC_MM_INIT_UNINIT,0)\
    ENUM_AUTO(ARM_UC_MM_INIT_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_INIT_LATEST_MFST)\
    ENUM_AUTO(ARM_UC_MM_INIT_FINDING)\
    ENUM_AUTO(ARM_UC_MM_INIT_READING)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_HASH_VERIFY)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_PK_VERIFY)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_PK_VERIFYING)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_ROOT_DEPS_VERIFY_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_MANIFEST_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_GET_HASH)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_READING_DEPENDENCY)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_CHECK_HASH)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_DELETE)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECK)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_URI_CHECKING)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READ)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_SEEKING)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_READING)\
    ENUM_AUTO(ARM_UC_MM_INIT_STATE_DEPS_LOOP_DEPENDENCY_END)\


enum arm_uc_mm_init_state {
    #define ENUM_AUTO(name) name,
    #define ENUM_FIXED(name, val) name = val,
    ARM_UC_MM_INIT_STATE_LIST
    #undef ENUM_AUTO
    #undef ENUM_FIXED
};

arm_uc_error_t arm_uc_mmInitFSM(uint32_t event);

#endif // ARM_UC_MM_INIT_H
