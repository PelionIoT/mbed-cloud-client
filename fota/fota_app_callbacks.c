// ----------------------------------------------------------------------------
// Copyright 2021 Pelion IoT Ltd.
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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_app_ifs.h"    // required for implementing custom install callback for Linux like targets
#include "fota/fota_platform_hooks.h"
#include "../config/edge_component_update_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define ACTIVATE_SCRIPT_LENGTH 512
#define CURR_SHA_FILE_NAME MBED_CLOUD_CLIENT_FOTA_LINUX_CONFIG_DIR "/fota_curr_sha"

int deploy_ostree_delta_update(const char *candidate_fs_name)
{
    int ret = FOTA_STATUS_SUCCESS;
    int rc;
    char command[ACTIVATE_SCRIPT_LENGTH] = {0};

    int length = snprintf(command,
                          ACTIVATE_SCRIPT_LENGTH,
                          "%s %s %s",
                          FOTA_SCRIPT_DIR "/" FOTA_COMPONENT_MAIN_COMPONENT_NAME "/" FOTA_INSTALL_MAIN_SCRIPT,  candidate_fs_name, MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME);
    FOTA_ASSERT(length < ACTIVATE_SCRIPT_LENGTH);

    /* execute script command */
    rc = system(command);
    if (rc) {
        ret = FOTA_STATUS_FW_INSTALLATION_FAILED;
        if (rc == -1) {
            FOTA_TRACE_ERROR("shell could not be run");
        } else {
            FOTA_TRACE_ERROR("Installation failed. Result of running command is %d", WEXITSTATUS(rc));
        }
    }
    return ret;
}


int verify_ostree_delta_update(const char *commit)
{
    int ret = FOTA_STATUS_SUCCESS;
    int rc;
    char command[ACTIVATE_SCRIPT_LENGTH] = {0};

    int length = snprintf(command,
                          ACTIVATE_SCRIPT_LENGTH,
                          "ostree admin status | head -1 | grep %s", commit);
    FOTA_ASSERT(length < ACTIVATE_SCRIPT_LENGTH);

    /* execute script command */
    rc = system(command);
    if (rc) {
        ret = FOTA_STATUS_FW_INSTALLATION_FAILED;
        if (rc == -1) {
            FOTA_TRACE_ERROR("shell could not be run");
        } else {
            FOTA_TRACE_ERROR("Verification failed. Expected commit was %s, result of running command is %d", commit, WEXITSTATUS(rc));
        }
    }
    return ret;
}

int fota_app_on_install_candidate(const char *candidate_fs_name, const manifest_firmware_info_t *firmware_info)
{
    return deploy_ostree_delta_update(candidate_fs_name);
}

#if FOTA_CUSTOM_PLATFORM

#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#include "fota/fota_sub_component.h"

int main_sub_component_install_handler(const char *comp_name, const char *sub_comp_name, const char *file_name, const uint8_t *vendor_data, size_t vendor_data_size)
{
    int rc = system("ostree admin status | head -1 | sed 's/\\\..*//' | sed 's/.* //g' > " CURR_SHA_FILE_NAME);
    if (rc) {
        FOTA_TRACE_ERROR("Unable to save current ostree sha");
        return FOTA_STATUS_FW_INSTALLATION_FAILED;
    }
    return deploy_ostree_delta_update(file_name);
}

int main_sub_component_verify_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size)
{
    return verify_ostree_delta_update((const char *) vendor_data);
}

int main_sub_component_rollback_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size)
{
    int rc = system("ostree admin deploy `cat " CURR_SHA_FILE_NAME "`");
    if (rc) {
        FOTA_TRACE_ERROR("Unable to rollback main sub component, result %d", WEXITSTATUS(rc));
        return FOTA_STATUS_FW_INSTALLATION_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

int main_sub_component_finalize_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, fota_status_e fota_status)
{
    remove(CURR_SHA_FILE_NAME);
    return FOTA_STATUS_SUCCESS;
}

int boot_sub_component_install_handler(const char *comp_name, const char *sub_comp_name, const char *file_name, const uint8_t *vendor_data, size_t vendor_data_size)
{
    int rc;
    char command[ACTIVATE_SCRIPT_LENGTH] = {0};
    rc = system("mkdir -p " BOOT_CAPSULE_UPDATE_DIR);
    if (rc) {
        FOTA_TRACE_ERROR("Unable to create capsule update directory");
        return FOTA_STATUS_FW_INSTALLATION_FAILED;
    }

    int length = snprintf(command,
                          ACTIVATE_SCRIPT_LENGTH,
                          "cp -f %s " BOOT_CAPSULE_UPDATE_DIR "/" BOOT_CAPSULE_UPDATE_FILENAME, file_name);
    FOTA_ASSERT(length < ACTIVATE_SCRIPT_LENGTH);

    rc = system(command);
    if (rc) {
        FOTA_TRACE_ERROR("Unable to copy capsule file to capsule directory");
        return FOTA_STATUS_FW_INSTALLATION_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

int boot_sub_component_verify_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size)
{
    // Currently only way to verify success of capsule update is to make sure that capsule update process removed the capsule file
    FILE *fp = fopen(BOOT_CAPSULE_UPDATE_DIR "/" BOOT_CAPSULE_UPDATE_FILENAME, "r");
    if (fp) {
        FOTA_TRACE_ERROR("Capsule update process failed");
        fclose(fp);
        return FOTA_STATUS_FW_INSTALLATION_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

int boot_sub_component_rollback_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size)
{
    // Nothing to do here
    return FOTA_STATUS_SUCCESS;
}

int boot_sub_component_finalize_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, fota_status_e fota_status)
{
    remove(BOOT_CAPSULE_UPDATE_DIR "/" BOOT_CAPSULE_UPDATE_FILENAME);
    return FOTA_STATUS_SUCCESS;
}

#endif

static fota_component_desc_info_t external_component_info;

static int edge_component_1_installer(const char *comp_name, const char *sub_comp_name, const char *file_name, const uint8_t *vendor_data, size_t vendor_data_size, void *app_ctx)
{
    int ret = FOTA_STATUS_SUCCESS;
    int rc;
    char command[ACTIVATE_SCRIPT_LENGTH] = {0};

    int length = snprintf(command,
                          ACTIVATE_SCRIPT_LENGTH,
                          "%s %s",
                          FOTA_SCRIPT_DIR "/" EDGE_COMPONENT_1_NAME "/" FOTA_INSTALL_SCRIPT,  file_name);
    FOTA_ASSERT(length < ACTIVATE_SCRIPT_LENGTH);

    /* execute script command */
    rc = system(command);
    if (rc) {
        ret = FOTA_STATUS_FW_INSTALLATION_FAILED;
        if (rc == -1) {
            FOTA_TRACE_ERROR("shell could not be run");
        } else {
            FOTA_TRACE_ERROR("Installation failed. Result of running command is %d", WEXITSTATUS(rc));
        }
    }
    return ret;
}

static int edge_component_1_verifier(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx)
{
    int ret = FOTA_STATUS_SUCCESS;
    int rc;
    char command[ACTIVATE_SCRIPT_LENGTH] = {0};

    int length = snprintf(command,
                          ACTIVATE_SCRIPT_LENGTH,
                          "%s",
                          FOTA_SCRIPT_DIR "/" EDGE_COMPONENT_1_NAME "/" FOTA_VERIFY_SCRIPT);
    FOTA_ASSERT(length < ACTIVATE_SCRIPT_LENGTH);

    /* execute script command */
    rc = system(command);
    if (rc) {
        ret = FOTA_STATUS_FW_INSTALLATION_FAILED;
        if (rc == -1) {
            FOTA_TRACE_ERROR("shell could not be run");
        } else {
            FOTA_TRACE_ERROR("Verification failed. Result of running command is %d", WEXITSTATUS(rc));
        }
    }
    return ret;
}


int fota_platform_init_hook(bool after_upgrade)
{
    int ret = 0;

    external_component_info.install_alignment = 1;
    external_component_info.support_delta = false;
    external_component_info.need_reboot = true;
    external_component_info.component_verify_install_cb = NULL;
    external_component_info.component_verify_cb = edge_component_1_verifier;

    external_component_info.component_install_cb = edge_component_1_installer;
    external_component_info.component_finalize_cb = NULL;

    external_component_info.curr_fw_read = 0; // only needed if support_delta = true
    external_component_info.curr_fw_get_digest = 0; // only needed if support_delta = true

    ret = fota_component_add(&external_component_info, EDGE_COMPONENT_1_NAME, EDGE_COMPONENT_1_VERSION);

#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    fota_sub_comp_info_t main_sub_component_desc = { 0 };
    main_sub_component_desc.finalize_cb = main_sub_component_finalize_handler;
    main_sub_component_desc.finalize_order = 1;
    main_sub_component_desc.install_cb = main_sub_component_install_handler;
    main_sub_component_desc.install_order = 1;
    main_sub_component_desc.rollback_cb = main_sub_component_rollback_handler;
    main_sub_component_desc.rollback_order = 2;
    main_sub_component_desc.verify_cb = main_sub_component_verify_handler;
    main_sub_component_desc.verify_order = 1;

    ret = fota_sub_component_add("MAIN", "main", &main_sub_component_desc);
    if (ret) {
        return ret;
    }

    fota_sub_comp_info_t boot_sub_component_desc = { 0 };
    boot_sub_component_desc.finalize_cb = boot_sub_component_finalize_handler;
    boot_sub_component_desc.finalize_order = 2;
    boot_sub_component_desc.install_cb = boot_sub_component_install_handler;
    boot_sub_component_desc.install_order = 2;
    boot_sub_component_desc.rollback_cb = boot_sub_component_rollback_handler;
    boot_sub_component_desc.rollback_order = 1;
    boot_sub_component_desc.verify_cb = boot_sub_component_verify_handler;
    boot_sub_component_desc.verify_order = 2;

    ret = fota_sub_component_add("MAIN", "boot", &boot_sub_component_desc);
#endif

    return ret;
}

int fota_platform_start_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_platform_finish_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_platform_abort_update_hook(const char *comp_name)
{
    return FOTA_STATUS_SUCCESS;
}

#endif // FOTA_CUSTOM_PLATFORM

#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE
