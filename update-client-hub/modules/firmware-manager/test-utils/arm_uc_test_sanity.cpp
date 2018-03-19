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

#include "test-utils/arm_uc_test_sanity.h"

#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-paal/arm_uc_paal_update.h"

#include "pal.h"

#include "test-utils/arm_uc_test_alice.h"

#ifdef TARGET_LIKE_POSIX
#include <unistd.h>
#define __WFI() sleep(1)
#endif

using namespace utest::v1;

static uint8_t temp_nc[16];
static arm_uc_buffer_t keyBuffer  = { .size_max = 32, .size = 32, .ptr = (uint8_t*) key };
static arm_uc_buffer_t ivBuffer   = { .size_max = 16, .size = 16, .ptr = (uint8_t*) temp_nc };
static arm_uc_buffer_t hashBuffer = { .size_max = 32, .size = 32, .ptr = (uint8_t*) hash };

#define BUF_SIZE 1024
static uint8_t buf[BUF_SIZE] = {0};
static arm_uc_buffer_t fragment = {
    .size_max = BUF_SIZE,
    .size     = 0,
    .ptr      = buf
};

static bool FLAG_INITIALIZE_DONE = false;
static bool FLAG_PREPARE_DONE = false;
static bool FLAG_WRITE_DONE = false;
static bool FLAG_FINALIZE_DONE = false;
static bool FLAG_GET_FIRMWARE_DETAILS_DONE = false;

static void event_handler(uint32_t event)
{
    switch (event)
    {
        case UCFM_EVENT_INITIALIZE_DONE:
            printf("UCFM_EVENT_INITIALIZE_DONE\r\n");
            FLAG_INITIALIZE_DONE = true;
            break;

        case UCFM_EVENT_PREPARE_DONE:
            printf("UCFM_EVENT_PREPARE_DONE\r\n");
            FLAG_PREPARE_DONE = true;
            break;

        case UCFM_EVENT_WRITE_DONE:
            FLAG_WRITE_DONE = true;
            break;

        case UCFM_EVENT_FINALIZE_DONE:
            printf("UCFM_EVENT_FINALIZE_DONE\r\n");
            FLAG_FINALIZE_DONE = true;
            break;

        case UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE:
            printf("UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE\r\n");
            FLAG_GET_FIRMWARE_DETAILS_DONE = true;
            break;

        default:
            TEST_ASSERT_MESSAGE(false, "callback failed");
            break;
    }
}

control_t test_update_check_input_buffer()
{
    arm_uc_error_t result;
    result.code = ERR_NONE;

    /* Setup new firmware */
    memcpy(temp_nc, nc, sizeof(nc));
    ARM_UCFM_Setup_t setup;
    setup.mode = UCFM_MODE_AES_CTR_256_SHA_256;
    setup.key = &keyBuffer;
    setup.iv = &ivBuffer;
    setup.hash = &hashBuffer;
    setup.package_id = 0;
    setup.package_size = sizeof(ecila);

    FLAG_PREPARE_DONE = false;
    printf("Setup\r\n");

    /* temporary buffer */
    arm_uc_buffer_t buffer = {
        .size_max = BUF_SIZE,
        .size     = 0,
        .ptr      = buf
    };

    /* firmware details struct */
    arm_uc_firmware_details_t details = { 0 };

    memcpy(details.hash, hashBuffer.ptr, 32);
    details.version = 0;
    details.size = sizeof(ecila);

    result = ARM_UC_FirmwareManager.Initialize(event_handler);
    TEST_ASSERT_TRUE_MESSAGE(result.error == ERR_NONE, "initialize");
    while(!FLAG_INITIALIZE_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    result = ARM_UC_FirmwareManager.Prepare(&setup, &details, &buffer);
    TEST_ASSERT_TRUE_MESSAGE(result.error == ERR_NONE, "setup");
    while(!FLAG_PREPARE_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    fragment.size = fragment.size_max;
    result = ARM_UC_FirmwareManager.Write(&fragment);
    TEST_ASSERT_EQUAL_HEX(ERR_NONE, result.error);
    while(!UCFM_EVENT_WRITE_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    fragment.size = fragment.size_max + 1;
    result = ARM_UC_FirmwareManager.Write(&fragment);
    TEST_ASSERT_EQUAL_HEX(FIRM_ERR_INVALID_PARAMETER, result.code);

    fragment.size_max = 0;
    result = ARM_UC_FirmwareManager.Write(&fragment);
    TEST_ASSERT_EQUAL_HEX(FIRM_ERR_INVALID_PARAMETER, result.code);

    fragment.ptr = NULL;
    result = ARM_UC_FirmwareManager.Write(&fragment);
    TEST_ASSERT_EQUAL_HEX(FIRM_ERR_INVALID_PARAMETER, result.code);

    result = ARM_UC_FirmwareManager.Write(NULL);
    TEST_ASSERT_EQUAL_HEX(FIRM_ERR_INVALID_PARAMETER, result.code);

    return CaseNext;
}

