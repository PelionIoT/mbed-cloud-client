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

#include "test-utils/arm_uc_test_getactivehash.h"

#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-paal/arm_uc_paal_update.h"
#include "update-client-common/arm_uc_metadata_header_v2.h"

#include <mbedtls/sha256.h>

#if defined(TARGET_LIKE_POSIX)
#include <pal_plat_update.h>
#include <unistd.h>
#define __WFI() usleep(100)
#endif

using namespace utest::v1;

static bool FLAG_INITIALIZE_DONE = false;
static bool FLAG_GET_ACTIVE_FIRMWARE_DETAILS_DONE = false;

static void event_handler(uint32_t event)
{
    switch (event)
    {
        case UCFM_EVENT_INITIALIZE_DONE:
            printf("UCFM_EVENT_INITIALIZE_DONE\r\n");
            FLAG_INITIALIZE_DONE = true;
            break;

        case UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE:
            printf("UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE\r\n");
            FLAG_GET_ACTIVE_FIRMWARE_DETAILS_DONE = true;
            break;

        case UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR:
            TEST_ASSERT_MESSAGE(false, "UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_ERROR");
            break;

        default:
            TEST_ASSERT_MESSAGE(false, "callback failed");
            break;
    }
}

control_t test_get_active_hash()
{
    arm_uc_error_t result;

#if defined(TARGET_K64F)
    int32_t rc;

    FlashIAP flash;
    rc = flash.init();
    TEST_ASSERT_TRUE_MESSAGE(rc == 0, "main: FlashIAP::init failed");

    uint32_t sector_size = flash.get_sector_size(MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS);
    TEST_ASSERT_TRUE_MESSAGE(sector_size == 0x1000, "main: FlashIAP::get_sector_size failed");

    rc = flash.erase(MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS, sector_size);
    TEST_ASSERT_TRUE_MESSAGE(rc == 0, "main: FlashIAP::erase failed");

    uint8_t buffer[1024] = { 0 };
    arm_uc_firmware_details_t details = { 0 };
    arm_uc_buffer_t output = {
        .size_max   = 1024,
        .size       = 0,
        .ptr        = buffer
    };

    result = arm_uc_create_internal_header_v2(&details, &output);
    TEST_ASSERT_TRUE_MESSAGE(result.error == ERR_NONE, "main: arm_uc_create_internal_header_v2 failed");

    rc = flash.program(output.ptr, MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS, output.size);
    TEST_ASSERT_TRUE_MESSAGE(rc == 0, "main: FlashIAP::program failed");

#elif defined(TARGET_LIKE_POSIX)
#warning Active firmware details not implemented on Linux
#endif

    result = ARM_UC_FirmwareManager.Initialize(event_handler);
    TEST_ASSERT_TRUE_MESSAGE(result.error == ERR_NONE, "initialize");
    while(!FLAG_INITIALIZE_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    FLAG_GET_ACTIVE_FIRMWARE_DETAILS_DONE = false;

    printf("GetActiveHash\r\n");
    arm_uc_firmware_details_t readback = { 0 };
    result = ARM_UC_FirmwareManager.GetActiveFirmwareDetails(&readback);
    if (result.error != ERR_NONE)
    {
        printf("error: %s\r\n", ARM_UC_err2Str(result));
    }
    TEST_ASSERT_TRUE_MESSAGE(result.error == ERR_NONE, "GetActiveHash");
    while(!FLAG_GET_ACTIVE_FIRMWARE_DETAILS_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    return CaseNext;
}

