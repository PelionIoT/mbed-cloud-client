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

#ifndef ARM_UC_MM_FSM_HELPER_H
#define ARM_UC_MM_FSM_HELPER_H

#define ARM_UC_MM_FSM_HELPER_START(CONTEXT, STATE_STR_FN)\
    uint32_t oldState;\
    ARM_UC_MM_DEBUG_LOG(ARM_UC_MM_DEBUG_LOG_LEVEL_STATES, "> %s (%u)\n", __PRETTY_FUNCTION__, (unsigned)event);\
    do {\
        oldState = (CONTEXT).state;\
        ARM_UC_MM_DEBUG_LOG(ARM_UC_MM_DEBUG_LOG_LEVEL_STATES, "+ %s state: %s(%u)\n", __PRETTY_FUNCTION__,\
            STATE_STR_FN((CONTEXT).state), (unsigned)(CONTEXT).state);\
        switch ((CONTEXT).state)

#define ARM_UC_MM_FSM_HELPER_FINISH(CONTEXT)\
    } while (err.code == MFST_ERR_NONE && oldState != (CONTEXT).state);\
    ARM_UC_MM_DEBUG_LOG(ARM_UC_MM_DEBUG_LOG_LEVEL_STATES, "< %s %c%c:%hu (%s)\n", __PRETTY_FUNCTION__,\
        err.modulecc[0], err.modulecc[1], err.error, ARM_UC_err2Str(err))

#endif // ARM_UC_MM_FSM_HELPER_H
