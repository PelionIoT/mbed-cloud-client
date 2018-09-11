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

#include "arm_uc_mmConfig.h"

#include "arm_uc_mmGetLatestTimestamp.h"
#include "update-client-manifest-manager/update-client-manifest-manager-context.h"
#if !MANIFEST_MANAGER_NO_STORAGE
#include "cfstore-fsm.h"
#endif

#include "update-client-common/arm_uc_error.h"
#include "update-client-common/arm_uc_types.h"

#define ARM_UC_MM_GET_LATEST_TS_STATE_LIST\
    ENUM_FIXED(ARM_UC_MM_GET_LATEST_TS_STATE_INVALID,0)\
    ENUM_AUTO(ARM_UC_MM_GET_LATEST_TS_STATE_BEGIN)\
    ENUM_AUTO(ARM_UC_MM_GET_LATEST_TS_STATE_FIND)\
    ENUM_AUTO(ARM_UC_MM_GET_LATEST_TS_STATE_READ)\
    ENUM_AUTO(ARM_UC_MM_GET_LATEST_TS_STATE_FETCH_NAME)\

enum arm_uc_mm_get_latest_ts_state {
#define ENUM_AUTO(name) name,
#define ENUM_FIXED(name, val) name = val,
    ARM_UC_MM_GET_LATEST_TS_STATE_LIST
#undef ENUM_AUTO
#undef ENUM_FIXED
};

const char *ARM_UC_mmGetLatestTsState2Str(uint32_t state)
{
    switch (state) {
#define ENUM_AUTO(name) case name: return #name;
#define ENUM_FIXED(name, val) ENUM_AUTO(name)
            ARM_UC_MM_GET_LATEST_TS_STATE_LIST
#undef ENUM_FIXED
#undef ENUM_AUTO
        default:
            return "Unknown State";
    }
}

/**
 * @brief Search the key/value store to find the latest timestamp.
 * @detail Searches for all *.ts entries in the manifest manager key/value store prefix. As each entry is found,
 * `getLatestManifestTimestampFSM()` updates ts with the largest timestamp encountered. If key is non-NULL, it is
 * populated with the path to the largest timestamp.
 *
 * @param[out] ts Pointer to a 64-bit unsigned integer. Contains the largest timestamp encountered when
 *                getLatestManifestTimestampFSM completes.
 * @param[out] key Pointer to a buffer; the location to store the key that contained the largest timestamp.
 * @retval MFST_ERR_NONE Always returns success.
 */
arm_uc_error_t getLatestManifestTimestamp(uint64_t *ts, arm_uc_buffer_t *key)
{
    *ts = 0;
    return (arm_uc_error_t) {MFST_ERR_NONE};
}

/**
 * @brief Run the getLatestManifestTimestampstate machine.
 * @details Processes through the getLatestManifestTimestamp state machine in response to received events
 *
 * @param[in] event The event which has caused this run through the state machine
 * @retval MFST_ERR_NONE    getLatestManifestTimestampFSM has completed
 * @retval MFST_ERR_PENDING getLatestManifestTimestampFSM is still on-going and waiting for an event
 * @return any other error code indicates an error has occurred
 */
arm_uc_error_t getLatestManifestTimestampFSM(uint32_t event)
{
    return (arm_uc_error_t) {MFST_ERR_NONE};
}
