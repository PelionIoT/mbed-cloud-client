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

#include "test-utils/arm_uc_test_retval.h"

#include "update-client-firmware-manager/arm_uc_firmware_manager.h"
#include "update-client-paal/arm_uc_paal_update.h"

#include "pal.h"
#include "test-utils/arm_uc_test_alice.h"

#include <mbedtls/sha256.h>

#if defined(TARGET_LIKE_POSIX)
#include <unistd.h>
#define __WFI() usleep(100)
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

static uint8_t back_buf[BUF_SIZE] = {0};
static arm_uc_buffer_t back_buffer = {
    .size_max = BUF_SIZE,
    .size     = 0,
    .ptr      = back_buf
};

static arm_uc_firmware_details_t firmware_details = { 0 };

static bool FLAG_INIT_DONE = false;
static bool FLAG_PREPARE_DONE = false;
static bool FLAG_WRITE_DONE = false;
static bool FLAG_WRITE_ERROR = false;
static bool FLAG_FINALIZE_DONE = false;
static bool FLAG_GET_FIRMWARE_DETAILS_DONE = false;
static bool FLAG_GET_ACTIVE_FIRMWARE_DETAILS_DONE = false;
static bool FLAG_FINALIZE_ERROR = false;

static void event_handler(uint32_t event)
{
    switch (event)
    {
        case UCFM_EVENT_INITIALIZE_DONE:
            FLAG_INIT_DONE = true;
            printf("UCFM_EVENT_INITIALIZE_DONE\r\n");
            break;

        case UCFM_EVENT_PREPARE_DONE:
            printf("UCFM_EVENT_PREPARE_DONE\r\n");
            FLAG_PREPARE_DONE = true;
            break;

        case UCFM_EVENT_WRITE_DONE:
            FLAG_WRITE_DONE = true;
            break;

        case UCFM_EVENT_WRITE_ERROR:
            printf("UCFM_EVENT_WRITE_ERROR\r\n");
            FLAG_WRITE_ERROR = true;
            break;

        case UCFM_EVENT_FINALIZE_DONE:
            printf("UCFM_EVENT_FINALIZE_DONE\r\n");
            FLAG_FINALIZE_DONE = true;
            break;

        case UCFM_EVENT_FINALIZE_ERROR:
            printf("UCFM_EVENT_FINALIZE_ERROR\r\n");
            FLAG_FINALIZE_ERROR = true;
            break;

        case UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE:
            printf("UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE\r\n");
            FLAG_GET_FIRMWARE_DETAILS_DONE = true;
            break;

        case UCFM_EVENT_GET_ACTIVE_FIRMWARE_DETAILS_DONE:
            printf("UCFM_EVENT_GET_FIRMWARE_DETAILS_DONE\r\n");
            FLAG_GET_ACTIVE_FIRMWARE_DETAILS_DONE = true;
            break;

        default:
            TEST_ASSERT_MESSAGE(false, "callback failed");
            break;
    }
}

control_t test_retval_sanity_check()
{
    arm_uc_error_t result;

    /* Setup new firmware */
    memcpy(temp_nc, nc, sizeof(nc));
    ARM_UCFM_Setup_t setup;
    setup.mode = UCFM_MODE_AES_CTR_256_SHA_256;
    setup.key = &keyBuffer;
    setup.iv = &ivBuffer;
    setup.hash = &hashBuffer;
    setup.package_id = 0;
    setup.package_size = sizeof(ecila);

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

    printf("Initialize\r\n");
    result = ARM_UC_FirmwareManager.Initialize(NULL);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_INVALID_PARAMETER, result.code,
        "Initialize with null should return FIRM_ERR_INVALID_PARAMETER");

    result = ARM_UC_FirmwareManager.Prepare(&setup, &details, &buffer);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_UNINITIALIZED, result.code,
        "Calling setup before Initialize should return FIRM_ERR_UNINITIALIZED");

    fragment.size = 1;
    result = ARM_UC_FirmwareManager.Write(&fragment);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_UNINITIALIZED, result.code,
        "Calling Update before Initialize should return FIRM_ERR_UNINITIALIZED");

    fragment.size = 0;
    result = ARM_UC_FirmwareManager.GetActiveFirmwareDetails(&firmware_details);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_INVALID_PARAMETER, result.code,
        "Calling GetActiveHash before Initialize should return FIRM_ERR_INVALID_PARAMETER");

    result = ARM_UC_FirmwareManager.Finalize(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_UNINITIALIZED, result.code,
        "Calling Finish before Initialize should return FIRM_ERR_UNINITIALIZED");

    result = ARM_UC_FirmwareManager.Initialize(event_handler);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(ERR_NONE, result.error,
        "Initialize should succeed");
    while(!FLAG_INIT_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    result = ARM_UC_FirmwareManager.Prepare(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_INVALID_PARAMETER, result.code,
        "Calling setup with NULL should return FIRM_ERR_INVALID_PARAMETER");

    fragment.size = 1;
    result = ARM_UC_FirmwareManager.Write(&fragment);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_UNINITIALIZED, result.code,
        "Calling Update before Setup should return FIRM_ERR_UNINITIALIZED");

    result = ARM_UC_FirmwareManager.Finalize(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_UNINITIALIZED, result.code,
        "Calling Finalize before setup should return FIRM_ERR_UNINITIALIZED");

    printf("setup\r\n");
    FLAG_PREPARE_DONE = false;
    result = ARM_UC_FirmwareManager.Prepare(&setup, &details, &buffer);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(ERR_NONE, result.error,
        "setup should succeed");
    while(!FLAG_PREPARE_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    result = ARM_UC_FirmwareManager.Finalize(NULL, NULL);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(FIRM_ERR_INVALID_PARAMETER, result.code,
        "Calling Finalize without parameters should fail");

    printf("setup\r\n");
    FLAG_PREPARE_DONE = false;
    result = ARM_UC_FirmwareManager.Prepare(&setup, &details, &buffer);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(ERR_NONE, result.error,
        "setup should succeed");

    while(!FLAG_PREPARE_DONE)
    {
        ARM_UC_ProcessQueue();
        __WFI();
    }

    printf("write\r\n");
    uint32_t package_offset = 0;
    while(package_offset < setup.package_size)
    {
        uint32_t remaining = setup.package_size - package_offset;

        fragment.size = (remaining > fragment.size_max)? fragment.size_max:remaining;
        memcpy(fragment.ptr, ecila+package_offset, fragment.size);

        FLAG_WRITE_DONE = false;
        FLAG_WRITE_ERROR = false;
        result = ARM_UC_FirmwareManager.Write(&fragment);
        TEST_ASSERT_EQUAL_HEX_MESSAGE(ERR_NONE, result.error, "Update");
        while(!FLAG_WRITE_DONE)
        {
            ARM_UC_ProcessQueue();
            TEST_ASSERT_EQUAL_HEX_MESSAGE(false, FLAG_WRITE_ERROR, "Write");
            __WFI();
        }
        package_offset += fragment.size;
    }

    TEST_ASSERT_EQUAL(package_offset, setup.package_size);

    FLAG_FINALIZE_DONE = false;
    FLAG_FINALIZE_ERROR = false;
    result = ARM_UC_FirmwareManager.Finalize(&fragment, &back_buffer);
    TEST_ASSERT_EQUAL_HEX_MESSAGE(ERR_NONE, result.error, "Finish");
    while(!FLAG_FINALIZE_DONE)
    {
        ARM_UC_ProcessQueue();
        TEST_ASSERT_EQUAL_HEX_MESSAGE(false, FLAG_FINALIZE_ERROR, "Finish");
        __WFI();
    }

    return CaseNext;
}

