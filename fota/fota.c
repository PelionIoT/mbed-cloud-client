// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
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

#include "fota/fota.h"
#include "fota/fota_status.h"
#include "fota/fota_internal.h"
#include "fota/fota_manifest.h"
#include "fota/fota_source.h"
#include "fota/fota_delta.h"
#include "fota/fota_app_ifs.h"
#include "fota_platform_hooks.h"
#include "fota/fota_nvm.h"
#include "fota/fota_block_device.h"
#include "fota/fota_crypto.h"
#include "fota/fota_header_info.h"
#include "fota/fota_curr_fw.h"
#include "fota/fota_event_handler.h"
#include "fota/fota_candidate.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_fw_download.h"
#include "fota/fota_ext_downloader.h"
#include <stdlib.h>
#include <inttypes.h>

#ifdef __MBED__
#include "fota_device_key.h"
#include "mbed_power_mgmt.h"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#include "fota/fota_combined_package.h"
#include "fota/fota_sub_component.h"
#include "fota/fota_sub_component_internal.h"
#endif

#if MBED_CLOUD_CLIENT_FOTA_SUPPORT_PAL
#include "pal.h"
#define REBOOT_NOW() pal_osReboot()
#else
#include "platform/reboot.h"
#define REBOOT_NOW() mbed_client_default_reboot()
#endif

#if defined(TARGET_LIKE_LINUX)
#include "fota/platform/linux/fota_platform_linux.h"
#endif

#if defined (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE) && (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE > 0)
#include "m2mdynlog.h"
#endif

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME) && !FOTA_HEADER_HAS_CANDIDATE_READY
#error Full resume feature is not supported for legacy/external images
#endif

static fota_context_t *fota_ctx = NULL;
static fota_persistent_context_t fota_persistent_ctx;

static int handle_fw_fragment(uint8_t *buf, size_t size, bool last);
static int handle_manifest(uint8_t *manifest_buf, size_t manifest_size, bool is_resume, bool is_multicast);
static void on_reboot(void);
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE) && !defined (MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER)
static void on_reboot_in_ms(void *data, size_t size);
#endif
static int finalize_update(void);
static void fota_on_download_authorize();
static void fota_on_install_authorize(fota_install_state_e fota_install_type);

static bool initialized = false;
static size_t storage_available;

static bool fota_defer_by_user = false;
static bool erase_candidate_image = true;

bool fota_resume_download_after_user_auth = true; //indication if resume flow  executed after reboot, used also in test_fota_core.cpp.
fota_install_state_e fota_install_state = FOTA_INSTALL_STATE_IDLE; //FOTA installation state, used also in test_fota_core.cpp.
static int fota_verify_installation_after_upgrade();
static int fota_prepare_data_for_verify_installation(const fota_component_desc_t **comp_desc, unsigned int *comp_id, fota_header_info_t *header);
// Multicast related variables here should not be part of the FOTA context, as they live also outside of FOTA scope
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT != FOTA_MULTICAST_UNSUPPORTED)
static size_t mc_image_data_addr;
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
#if !(defined(TARGET_LIKE_LINUX))
static int multicast_br_candidate_install_handler(const char* comp_name, const char *sub_comp_name, fota_comp_candidate_iterate_callback_info *info, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx);
#endif
int multicast_br_post_install_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx);
#elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
#if MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER
static void ext_downloader_manifest_post_action_cb(int ret);
#endif
static bool mc_node_new_image = false;
static size_t mc_node_image_size = 0;
static size_t mc_node_frag_size = 0;
static void fota_multicast_node_on_fragment(void *data, size_t size);
#endif
#endif

static inline void clear_buffer_from_mem(void *buffer, size_t size)
{
#if !defined(FOTA_UNIT_TEST)
    // Clear buffer from memory due to security reasons
    // Skip it in unit tests, as buffer may still be needed for test logic
    memset(buffer, 0, size);
#endif
}

static int manifest_get(uint8_t *buffer, size_t size, size_t *bytes_read)
{
#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_UNSUPPORTED)
    return FOTA_STATUS_NOT_FOUND;
#else
    return fota_nvm_manifest_get(buffer, size, bytes_read);
#endif
}

static int manifest_set(const uint8_t *buffer, size_t size)
{
#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_UNSUPPORTED)
    return FOTA_STATUS_SUCCESS;
#else
    return fota_nvm_manifest_set(buffer, size);
#endif
}

int manifest_delete(void)
{
#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_UNSUPPORTED)
    return FOTA_STATUS_SUCCESS;
#else
    return fota_nvm_manifest_delete();
#endif

}

fota_context_t *fota_get_context(void)
{
    return fota_ctx;
}

static void free_context_buffers(void)
{
    if (!fota_ctx) {
        return;
    }
    free(fota_ctx->fw_info);
    fota_ctx->fw_info = NULL;
    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;

#if !defined(FOTA_DISABLE_DELTA)
    free(fota_ctx->delta_buf);
    fota_ctx->delta_buf = NULL;
    if (fota_ctx->delta_ctx) {
        fota_delta_finalize(&fota_ctx->delta_ctx);
    }
#endif  // !defined(FOTA_DISABLE_DELTA)

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_encrypt_finalize(&fota_ctx->enc_ctx);
#endif

    fota_hash_finish(&fota_ctx->payload_hash_ctx);
#if !defined(FOTA_DISABLE_DELTA)
    fota_hash_finish(&fota_ctx->installed_hash_ctx);
#endif
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    free(fota_ctx->mc_node_frag_buf);
    fota_ctx->mc_node_frag_buf = NULL;
#endif
}

static inline int handle_fota_app_on_complete(int32_t status)
{
#if FOTA_COMPONENT_SUPPORT
    // Not a real update - no need to notify application
    if (fota_component_is_internal_component(fota_ctx->comp_id)) {
        return FOTA_STATUS_SUCCESS;
    }
#endif

    int ret = fota_app_on_complete(status);
    if (ret) {
        FOTA_TRACE_ERROR("Application fota_app_on_complete failed %d", ret);
        fota_source_report_update_customer_result(ret);
    }
    return ret;
}

static inline void handle_fota_app_on_download_progress(size_t downloaded_size, size_t current_chunk_size, size_t total_size)
{
#if FOTA_COMPONENT_SUPPORT
    // Not a real update - no need to notify application
    if (fota_component_is_internal_component(fota_ctx->comp_id)) {
        return;
    }
#endif
    fota_app_on_download_progress(downloaded_size, current_chunk_size, total_size);
}

static void update_cleanup(void)
{
    if (fota_ctx) {
        fota_download_deinit(&fota_ctx->download_handle);
        free_context_buffers();
        free(fota_ctx);
        fota_ctx = NULL;
    }
    fota_source_enable_auto_observable_resources_reporting(true);
    report_state_random_delay(false);
}

static void do_abort_update(int ret, const char *msg)
{
    int upd_res;
    bool do_terminate_update = true;
    bool do_report_update_result = true;

    FOTA_TRACE_ERROR("Update aborted: (ret code %d) %s", ret, msg);

    if (ret == FOTA_STATUS_MULTICAST_UPDATE_ABORTED_INTERNAL) {
        do_report_update_result = false;
    }

    if (ret == FOTA_STATUS_FAIL_UPDATE_STATE ||
            ret == FOTA_STATUS_UPDATE_DEFERRED ||
            ret == FOTA_STATUS_TRANSIENT_FAILURE) {
        do_terminate_update = false;  // recoverable error, will trigger resume
    } else {
        upd_res = -1 * ret; // return to cloud
    }

    if (do_terminate_update) {
        if (upd_res > -1 * FOTA_STATUS_INTERNAL_ERR_BASE) {
            // map all internal errors to a generic internal error
            upd_res = -1 * FOTA_STATUS_INTERNAL_ERROR;
        }
        if (do_report_update_result) {
            fota_source_report_update_result(upd_res);
        }
        // used fota_source_report_state_in_ms with delay 0 becasuse this state even for multicast mode
        // should be sent without delay. We have manifest already and should set downloading state as well
        // but can't handle several fota eventOS_event at once.
        fota_source_report_state_in_ms(FOTA_SOURCE_STATE_IDLE, NULL, NULL, 0);
        manifest_delete();
        fota_nvm_fw_encryption_key_delete();
    } else {
        fota_source_report_state(FOTA_SOURCE_STATE_PROCESSING_MANIFEST, NULL, NULL);
    }

    const fota_component_desc_t *comp_desc;
    fota_component_get_desc(fota_persistent_ctx.comp_id, &comp_desc);
    fota_platform_abort_update_hook(comp_desc->name);
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
    if (fota_persistent_ctx.mc_br_update) {
        FOTA_DBG_ASSERT(fota_persistent_ctx.mc_br_post_action_callback);
        fota_persistent_ctx.mc_br_post_action_callback(ret);
    }
#elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    if (fota_persistent_ctx.mc_node_update && fota_persistent_ctx.mc_node_post_action_callback) {
        fota_persistent_ctx.mc_node_post_action_callback(ret);
    }
#endif

    int callback_ret = fota_app_on_complete(ret); //notify application
    if (callback_ret) {
        FOTA_TRACE_ERROR("Application fota_app_on_complete failed %d", callback_ret);
        fota_source_report_update_customer_result(callback_ret);
    }

    update_cleanup();
}

static void abort_update(int ret, const char *msg)
{
    FOTA_TRACE_DEBUG("abort_update");
    if (!fota_is_active_update()) {
        return;
    }

    //fill FOTA persistent context
    fota_persistent_ctx.comp_id = fota_ctx->comp_id;
    fota_persistent_ctx.state = fota_ctx->state;
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
    fota_persistent_ctx.mc_br_update = fota_ctx->mc_br_update;
    fota_persistent_ctx.mc_br_post_action_callback = fota_ctx->mc_br_post_action_callback;
#elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    fota_persistent_ctx.mc_node_update = fota_ctx->mc_node_update;
    fota_persistent_ctx.mc_node_post_action_callback = fota_ctx->mc_node_post_action_callback;
#endif

    do_abort_update(ret, msg);
}

static void on_state_set_failure(void)
{
    abort_update(FOTA_STATUS_FAIL_UPDATE_STATE, "Failed to deliver FOTA state");
}

static int fota_prepare_data_for_verify_installation(const fota_component_desc_t **comp_desc, unsigned int *comp_id, fota_header_info_t *header)
{
    int ret = FOTA_STATUS_SUCCESS;
    size_t bd_read_size;
    size_t bd_prog_size;
    size_t addr;
    fota_candidate_ready_header_t comp_header;

    ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_init failed %d.", ret);
        return ret;
    }

    ret = fota_bd_get_read_size(&bd_read_size);
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_get_read_size failed %d.", ret);
        return ret;
    }

    ret = fota_bd_get_program_size(&bd_prog_size);
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_get_program_size failed %d.", ret);
        return ret;
    }

    addr = fota_candidate_get_config()->storage_start_addr;

#if FOTA_HEADER_HAS_CANDIDATE_READY
    ret = fota_candidate_read_candidate_ready_header(&addr, bd_read_size, bd_prog_size, &comp_header);
    if (ret) {
        return ret;
    }

    ret = fota_component_name_to_id(comp_header.comp_name, comp_id);
    if (ret) {
        return ret;
    }
#else
    (void)comp_header;
    *comp_id = FOTA_COMPONENT_MAIN_COMP_NUM;
#endif //FOTA_HEADER_HAS_CANDIDATE_READY

    fota_component_get_desc(*comp_id, comp_desc);

    ret = fota_candidate_read_header(&addr, bd_read_size, bd_prog_size, header);
    if (ret) {
        FOTA_TRACE_ERROR("failed to read candidate header %d.", ret);
    }

    return ret;
}
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
static int fota_combined_verify_installation_after_upgrade(package_descriptor_t *descriptor_info)
{
    int ret = 0;
    const fota_component_desc_t *comp_desc;
    fota_header_info_t header;
    unsigned int comp_id;

    //Prepare component descriptor, id and candidate header
    ret = fota_prepare_data_for_verify_installation(&comp_desc, &comp_id, &header);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to prepare for validation");
        goto finalize;
    }

    ret = fota_sub_component_verify(comp_desc->name, descriptor_info);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to verify installation");
        goto finalize;
    }
    FOTA_TRACE_DEBUG("\n Combined validation finished");

    // Update current version
    fota_component_set_curr_version(comp_id, header.version);
    // Not saving version for the MAIN component
    if (comp_id != FOTA_COMPONENT_MAIN_COMP_NUM) {
        ret = fota_nvm_comp_version_set(comp_desc->name, header.version);
        if (ret) {
            FOTA_TRACE_ERROR("fota_nvm_comp_version_set ret %d", ret);
            goto finalize;
        }
    }

#if defined(TARGET_LIKE_LINUX)
    if (comp_id == FOTA_COMPONENT_MAIN_COMP_NUM) {
        // In Linux we don't have a bootloader that updates the current FW header in case of the main component,
        // So do it ourselves here - only after installation has been verified to succeed
        ret = fota_linux_update_curr_fw_header(&header);
        if (ret) {
            goto finalize;
        }
    }
#endif

finalize:
    if (ret) {
        // If result is not 0, perform rollback operation
        fota_sub_component_rollback(comp_desc->name, descriptor_info);
    }
    // Call to finalize operation
    fota_sub_component_finalize(comp_desc->name, descriptor_info, ret); //TODO: report finalize error



    return ret;
}

#endif

static void fota_after_upgrade()
{
    int ret = 0;
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    uint8_t *package_descriptor_buffer;
    size_t package_descriptor_buffer_size;
    package_descriptor_t descriptor_info;

#if defined(TARGET_LIKE_LINUX)
    ret = fota_linux_read_file(fota_linux_get_package_descriptor_file_name(), &package_descriptor_buffer, &package_descriptor_buffer_size);
#else
    ret = 0; // TODO : implement for embedded targets
#endif
    if (ret != 0 && ret != FOTA_STATUS_COMB_PACKAGE_DIR_NOT_FOUND) { // failed to read existing combined package descriptor
        fota_source_report_update_result(ret);
    } else if (ret == 0) { // valid combined package descriptor
        //Parse combined package data
        ret = fota_combined_package_parse(&descriptor_info, package_descriptor_buffer, package_descriptor_buffer_size);
        if (ret) {
            //Free package_descriptor_buffer allocated in fota_linux_read_file
            free(package_descriptor_buffer);
            fota_source_report_update_result(ret);
        } else {

            // Verify installed
            ret = fota_combined_verify_installation_after_upgrade(&descriptor_info);
            //Free package_descriptor_buffer allocated in fota_linux_read_file
            free(package_descriptor_buffer);
            //Clean image descriptors array allocated infota_combined_package_parse
            fota_combined_clean_image_descriptors_array(&descriptor_info);
            if (ret) {
                fota_candidate_erase();
                fota_nvm_fw_encryption_key_delete();
                fota_nvm_update_result_set(ret);
                REBOOT_NOW();
            }
        }
    } else
#endif // (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    {
        ret = fota_verify_installation_after_upgrade();
        if (ret) {
            fota_source_report_update_result(ret);
        }
    }

    ret = fota_candidate_erase();
    if (ret) {
        FOTA_TRACE_ERROR("fota_candidate_erase failed. ret = %d", ret);
        // Silently ignore failure here
    }

    fota_nvm_fw_encryption_key_delete();

}

bool fota_is_active_update(void)
{
    return (fota_ctx != NULL);
}

int fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state)
{
    size_t manifest_size;
    uint8_t *manifest = calloc(1, FOTA_MANIFEST_MAX_SIZE);
    if (!manifest) {
        FOTA_TRACE_ERROR("FOTA manifest - allocation failed");
        *fota_state = FOTA_STATE_INVALID;
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    int ret = manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (ret) {
        //  cannot find saved manifest - ready to start an update
        *fota_state = FOTA_STATE_IDLE;
        goto CLEANUP;
    }
    // manifest always saved with MAX size memcmp should be done on input size
    if ((size <= manifest_size) && (0 == memcmp(manifest, data, size))) {
        // notify FOTA already handles same manifest
        *fota_state = FOTA_STATE_DOWNLOADING;
        goto CLEANUP;
    }
    // fota is busy - different update is active
    *fota_state = FOTA_STATE_INVALID;

CLEANUP:
    free(manifest);
    return FOTA_STATUS_SUCCESS;
}

static inline void fota_dev_init(void)
{
    int ret;

    // Failure in below functions doesn't fail the process
    // The items can come from the default file of update_default_resources.c
    // When using this file, the capmaign will fail
#if defined(MBED_CLOUD_DEV_UPDATE_ID) && !defined(FOTA_USE_EXTERNAL_IDS)
    ret = fota_nvm_update_class_id_set();
    FOTA_TRACE_DEBUG("fota_nvm_update_class_id_set ret code %d", ret);

    ret = fota_nvm_update_vendor_id_set();
    FOTA_TRACE_DEBUG("fota_nvm_update_vendor_id_set ret code %d", ret);
#endif

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_X509_PUBLIC_KEY_FORMAT) && defined(MBED_CLOUD_DEV_UPDATE_CERT) && !defined(FOTA_USE_EXTERNAL_CERT)
    ret = fota_nvm_update_cert_set();
    FOTA_TRACE_DEBUG("fota_nvm_update_cert_set ret code %d", ret);
#endif

#if (MBED_CLOUD_CLIENT_FOTA_PUBLIC_KEY_FORMAT == FOTA_RAW_PUBLIC_KEY_FORMAT) && defined(MBED_CLOUD_DEV_UPDATE_RAW_PUBLIC_KEY) && !defined(FOTA_USE_EXTERNAL_UPDATE_RAW_PUBLIC_KEY)
    ret = fota_nvm_set_update_public_key();
    FOTA_TRACE_DEBUG("fota_nvm_set_update_public_key ret code %d", ret);
#endif

    (void)ret;  // fix unused variable warning in production
}

static int on_main_app_verify_install(const char *comp_name, const fota_header_info_t *expected_header_info)
{
#if FOTA_CUSTOM_MAIN_APP_VERIFY_INSTALL
    int ret  = fota_app_on_main_app_verify_install(expected_header_info);
    if (ret) {
        FOTA_TRACE_ERROR("Application fota_app_on_main_app_verify_install for %s failed %d", comp_name, ret);
        fota_source_report_update_customer_result(ret);
    }
    return ret;
#else
    FOTA_DBG_ASSERT(!strcmp(comp_name, FOTA_COMPONENT_MAIN_COMPONENT_NAME));
    size_t curr_fw_size;
    uint8_t *curr_digest;
    uint64_t curr_version;
    int ret;
    (void) curr_fw_size;
    (void) curr_digest;
    (void) curr_version;
    (void) ret;

#if defined(TARGET_LIKE_LINUX)
#if defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE)
    uint8_t calc_digest[FOTA_CRYPTO_HASH_SIZE];
    curr_digest = calc_digest;
    ret = fota_linux_get_curr_fw_size(&curr_fw_size);
    if (ret) {
        return ret;
    }

    ret = fota_linux_get_curr_fw_digest(curr_fw_size, curr_digest);
    if (ret) {
        return ret;
    }
    // We don't know the current version yet (we're about to update it)
    curr_version = expected_header_info->version;
#else // !MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE
    // Nothing to check here
    return FOTA_STATUS_SUCCESS;
#endif

#elif MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 1
    // Own supported current firmware
    fota_header_info_t curr_header_info;
    ret = fota_curr_fw_read_header(&curr_header_info);
    if (ret) {
        return ret;
    }
    curr_fw_size = curr_header_info.fw_size;
    curr_digest = curr_header_info.digest;
    curr_version = curr_header_info.version;

#else // Not Linux, not supported header
    // Nothing to do here
    return FOTA_STATUS_SUCCESS;
#endif

    if ((expected_header_info->fw_size != curr_fw_size) ||
            (expected_header_info->version != curr_version) ||
            (memcmp(expected_header_info->digest, curr_digest, FOTA_CRYPTO_HASH_SIZE))) {
        FOTA_TRACE_ERROR("Main app verify installation failed!");
        return FOTA_STATUS_FW_INSTALLATION_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
#endif // !FOTA_CUSTOM_MAIN_APP_VERIFY_INSTALL
}

static int comp_install_verify(const fota_component_desc_t *comp_desc, unsigned int comp_id, const fota_header_info_t *expected_header_info)
{
    int ret = FOTA_STATUS_SUCCESS;
    // TODO: Deprecated callback prototype. Remove once MAIN registration will be available to users
    if (comp_desc->desc_info.component_verify_install_cb) {
        FOTA_TRACE_DEBUG("Verifying installation of component %s", comp_desc->name);
        ret = comp_desc->desc_info.component_verify_install_cb(comp_desc->name, expected_header_info);
    } else {
        if(comp_desc->desc_info.component_verify_cb) {
            FOTA_TRACE_DEBUG("Verifying installation of component %s", comp_desc->name);
            ret = comp_desc->desc_info.component_verify_cb(comp_desc->name, NULL, expected_header_info->vendor_data, FOTA_MANIFEST_VENDOR_DATA_SIZE, NULL);
        }
    }
    if (ret) {
       FOTA_TRACE_ERROR("Failed to verify installation. ret %d", ret);
       return ret;
    }

    // Verification complete - update current version

    fota_component_set_curr_version(comp_id, expected_header_info->version);
    // Not saving version for the MAIN component
    if (comp_id != FOTA_COMPONENT_MAIN_COMP_NUM) {
        ret = fota_nvm_comp_version_set(comp_desc->name, expected_header_info->version);
        if (ret) {
            FOTA_TRACE_ERROR("fota_nvm_comp_version_set ret %d", ret);
        }
    }
    return ret;
}


static int fota_verify_installation_after_upgrade()
{
    int ret = FOTA_STATUS_SUCCESS;
    unsigned int comp_id;
    const fota_component_desc_t *comp_desc;
    fota_header_info_t header;

    ret = fota_prepare_data_for_verify_installation(&comp_desc, &comp_id, &header);
    if (ret) {
        FOTA_TRACE_ERROR("failed to prepare for verify %d.", ret);
        return ret;
    }

    ret = comp_install_verify(comp_desc, comp_id, &header);

#if defined(TARGET_LIKE_LINUX)
    // In Linux we don't have a bootloader that updates the current FW header in case of the main component,
    // So do it ourselves here - only after installation has been verified to succeed
    if (!ret && (comp_id == FOTA_COMPONENT_MAIN_COMP_NUM)) {
        ret = fota_linux_update_curr_fw_header(&header);
    }
#endif

    return ret;
}

static int calc_available_storage(void)
{
    size_t storage_start_addr, storage_end_addr, erase_size;
    storage_start_addr = fota_candidate_get_config()->storage_start_addr;
    storage_end_addr = storage_start_addr + fota_candidate_get_config()->storage_size;
    int ret = fota_bd_get_erase_size(storage_end_addr - 1, &erase_size);
    if (ret) {
        FOTA_TRACE_ERROR("Get erase size failed. ret %d", ret);
        return ret;
    }

    // Check for storage size misconfiguration
    FOTA_ASSERT(storage_end_addr == FOTA_ALIGN_UP(storage_end_addr, erase_size));
    storage_available = storage_end_addr - storage_start_addr;
    return FOTA_STATUS_SUCCESS;
}

int fota_init(void *m2m_interface, void *resource_list)
{
    uint8_t vendor_id[FOTA_GUID_SIZE];
    uint8_t class_id[FOTA_GUID_SIZE];
    size_t manifest_size = 0;
    fota_source_state_e source_state = FOTA_SOURCE_STATE_IDLE;
    fota_component_desc_info_t main_component_desc = {0};
    int ret;
    bool after_upgrade = false;
    uint8_t dummy;

    if (initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    fota_dev_init();

    FOTA_DBG_ASSERT(!fota_ctx);

    FOTA_DBG_ASSERT(m2m_interface);

    FOTA_TRACE_DEBUG("init start");

    ret = fota_nvm_get_vendor_id(vendor_id);
    FOTA_ASSERT(!ret);
    ret = fota_nvm_get_class_id(class_id);
    FOTA_ASSERT(!ret);

#if defined(TARGET_LIKE_LINUX)
    ret = fota_linux_init();
    FOTA_ASSERT(!ret);
#endif

    fota_header_info_t header_info;
    ret = fota_curr_fw_read_header(&header_info);
    FOTA_ASSERT(!ret);

    ret = fota_event_handler_init();  // Note: must be done before fota_source
    FOTA_ASSERT(!ret);

    // We just need to know whether manifest is present, so no need to allocate a full size manifest
    ret = manifest_get((uint8_t *)&dummy, sizeof(dummy), &manifest_size);
    if (ret != FOTA_STATUS_NOT_FOUND) {
        source_state = FOTA_SOURCE_STATE_PROCESSING_MANIFEST;
        FOTA_TRACE_DEBUG("manifest exists on fota_init()");
        fota_resume_download_after_user_auth = true; //fota_init() was called and manifest exists - we assume that resume flow will be initiated after reboot
    } else {
        uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE];
        ret = fota_nvm_fw_encryption_key_get(fw_key);
        fota_fi_memset(fw_key, 0, sizeof(fw_key));
        after_upgrade = !ret;
    }

    ret = fota_source_init(
              m2m_interface, resource_list,
              vendor_id, sizeof(vendor_id),
              class_id, sizeof(class_id),
              header_info.digest, sizeof(header_info.digest),
              header_info.version,
              source_state);
    FOTA_ASSERT(!ret);

#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    int update_result = 0;
    size_t read_size = 0;

    // Currently, this functionality is added for the combined image flow.
    // If installation validation fails during reboot after an upgrade, the flow must reboot again to activate rollback operations.
    // Before the reboot, the client saves FOTA_STATUS_FW_INSTALLATION_FAILED in non-volatile memory.
    // The device must report the saved result to the service to indicate that the combined package flow failed.

    //Check whether the FOTA update result was saved. Report update resource, delete update result and continue.
    ret = fota_nvm_update_result_get(&update_result, sizeof(update_result), &read_size);
    if (ret == FOTA_STATUS_SUCCESS && read_size == sizeof(update_result)) {
        fota_source_report_update_result(update_result);
        fota_nvm_update_result_delete();
    }
#endif

    fota_component_clean();
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
    fota_sub_component_clean();
#endif

#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)
    // If header v3, assume component version is always represent SemVer.
    header_info.version |= FOTA_COMPONENT_SEMVER_BIT;
#endif

    // register main component (should be done before platform init hook, which registers all other components).
    // "Factory" version here is what we read from main firmware header, as we don't save it to NVM.
    char factory_version[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE];
    fota_component_version_int_to_semver(header_info.version, factory_version);

    main_component_desc.need_reboot = true;
    // TODO: deprecated component_verify_install_cb callback. Replace with component_verify_cb once enabling MAIN registration for users
    main_component_desc.component_verify_install_cb = on_main_app_verify_install;
    main_component_desc.component_verify_cb = NULL;
    // In case of Linux, delta is supported on main component only in case of a single file
#if !defined(FOTA_DISABLE_DELTA) && !(defined(TARGET_LIKE_LINUX) && !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE))
    main_component_desc.support_delta = true;
    main_component_desc.curr_fw_read = fota_curr_fw_read;
#endif
// Get digest is used also for precursor calculation to be used by our bootloader, not only for delta
#if !(defined(TARGET_LIKE_LINUX) && !defined(MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE))
    main_component_desc.curr_fw_get_digest = fota_curr_fw_get_digest;
#endif

    ret = fota_component_add(&main_component_desc, FOTA_COMPONENT_MAIN_COMPONENT_NAME, factory_version);
    FOTA_DBG_ASSERT(!ret);
    fota_component_set_curr_version(FOTA_COMPONENT_MAIN_COMP_NUM, header_info.version);

    ret = fota_platform_init_hook(after_upgrade);
    FOTA_ASSERT(!ret);

    if (after_upgrade) {
        FOTA_TRACE_DEBUG("After upgrade, verifying installation");
        fota_after_upgrade();
    }// after_upgrade

#if (FOTA_COMPONENT_SUPPORT)
    // Now we should have all components registered, report them all
    unsigned int num_comps = fota_component_num_components();
    for (unsigned int i = 0; i < num_comps; i++) {
        const fota_component_desc_t *comp_desc;
        char semver[FOTA_COMPONENT_MAX_SEMVER_STR_SIZE] = {0};
        fota_component_version_t version;
        fota_component_get_desc(i, &comp_desc);
        ret = fota_nvm_comp_version_get(comp_desc->name, &version);

        // if not found, take factory version, set as current version.
        // Always true in main component case, which shouldn't be saved in NVM.
        if ((ret != FOTA_STATUS_SUCCESS) || (i == FOTA_COMPONENT_MAIN_COMP_NUM)) {
            fota_component_get_curr_version(i, &version);
        }
        ret = fota_component_version_int_to_semver(version, semver);
        FOTA_DBG_ASSERT(!ret);

        FOTA_TRACE_DEBUG("Registered %s component, version %s", comp_desc->name, semver);
        ret = fota_source_add_component(i, comp_desc->name, semver);
        FOTA_DBG_ASSERT(!ret);
        fota_component_set_curr_version(i, version);
    }
#else // !FOTA_COMPONENT_SUPPORT
    // Code saving - explicitly report main component only
    ret = fota_source_add_component(FOTA_COMPONENT_MAIN_COMP_NUM, FOTA_COMPONENT_MAIN_COMPONENT_NAME, factory_version);
    FOTA_DBG_ASSERT(!ret);
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION >= 3)
    // Don't show that in legacy case
    FOTA_TRACE_INFO("Registered %s component, version %s", FOTA_COMPONENT_MAIN_COMPONENT_NAME, factory_version);
#endif
#endif // !FOTA_COMPONENT_SUPPORT

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
    // Register internal component, which handles the Multicast BR installer
    fota_component_desc_info_t multicast_br_component_desc = {0};
    multicast_br_component_desc.need_reboot = false;
#if !(defined(TARGET_LIKE_LINUX))
    multicast_br_component_desc.candidate_iterate_cb = NULL;
#endif
    multicast_br_component_desc.component_verify_install_cb = NULL;
#if !(defined(TARGET_LIKE_LINUX))
    multicast_br_component_desc.component_install_cb = multicast_br_candidate_install_handler,
#endif
    multicast_br_component_desc.component_verify_cb = multicast_br_post_install_handler,
    multicast_br_component_desc.component_finalize_cb = NULL,

    ret = fota_component_add(&multicast_br_component_desc, FOTA_MULTICAST_BR_INT_COMP_NAME, "0.0.0");
    FOTA_DBG_ASSERT(!ret);
#endif

    initialized = true;
    FOTA_TRACE_DEBUG("init complete");

    return FOTA_STATUS_SUCCESS;
}

int fota_deinit(void)
{
    if (!initialized) {
        FOTA_TRACE_DEBUG("fota_deinit skipped");
        return FOTA_STATUS_SUCCESS;
    }

    FOTA_TRACE_DEBUG("fota_deinit");

#if !defined(FOTA_UNIT_TEST)
    FOTA_ASSERT(!fota_ctx);
#endif

    update_cleanup();
    fota_component_clean();
    fota_source_deinit();
    fota_random_deinit();
    fota_event_handler_deinit();
    fota_bd_deinit();
#if defined(TARGET_LIKE_LINUX)
    fota_linux_deinit();
#endif
    initialized = false;

    return FOTA_STATUS_SUCCESS;
}

static int init_encryption(manifest_firmware_info_t *fw_info)
{
    int ret = FOTA_STATUS_NOT_FOUND;

    uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE] = {0};

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_STARTED) {
        ret = fota_nvm_fw_encryption_key_get(fw_key);
        if (!ret) {
            FOTA_TRACE_DEBUG("Reloading saved FOTA key");
        } else {
            FOTA_TRACE_DEBUG("FOTA key not found, resetting resume state");
            // Can't continue with resume if FW key can't be reloaded
            fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
        }
    }
#endif

    if (ret) {
        for (;;) {
            uint8_t zero_key[FOTA_ENCRYPT_KEY_SIZE] = {0};
            volatile size_t loop_check;

#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_DEVICE_KEY)
            ret = fota_get_device_key_128bit(fw_key, FOTA_ENCRYPT_KEY_SIZE);
#elif (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)
            if (fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
                // copy the key from manifest_firmware_info_t
                // and clear it from the fota_ctx
                fota_fi_memcpy(fw_key, fota_ctx->encryption_key, sizeof(fw_key));
                fota_fi_memset(fota_ctx->encryption_key, 0, FOTA_ENCRYPT_KEY_SIZE);
                ret = FOTA_STATUS_SUCCESS;
            } else {
                ret = fota_gen_random(fw_key, sizeof(fw_key));
            }
#else
            // encryption support disabled
            ret = fota_gen_random(fw_key, sizeof(fw_key));
#endif
            if (ret) {
                FOTA_TRACE_ERROR("Unable to generate random FW key. ret %d", ret);
                return ret;
            }
            // safely check that key is non zero
            FOTA_FI_SAFE_COND((fota_fi_memcmp(fw_key, zero_key, FOTA_ENCRYPT_KEY_SIZE, &loop_check)
                               && (loop_check == FOTA_ENCRYPT_KEY_SIZE)), FOTA_STATUS_INTERNAL_ERROR,
                              "Zero encryption key - retry");

            ret = fota_nvm_fw_encryption_key_set(fw_key);
            if (ret) {
                FOTA_TRACE_ERROR("Unable to set FW key. ret %d", ret);
                return ret;
            }
            // non zero key
            break;

fail:
            // zero key
#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY)
            if (fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
                // don't retry since the fota_ctx->encryption_key will not changed
                return ret;
            }
#endif
            ;// retry here
        }

        FOTA_TRACE_DEBUG("New FOTA key saved");
    }


#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    ret = fota_encrypt_decrypt_start(&fota_ctx->enc_ctx, fw_key, sizeof(fw_key));
    fota_fi_memset(fw_key, 0, sizeof(fw_key));
    if (ret) {
        FOTA_TRACE_ERROR("Unable to start encryption engine. ret %d", ret);
        return ret;
    }
    FOTA_TRACE_DEBUG("FOTA encryption engine initialized");
#endif
    return FOTA_STATUS_SUCCESS;
}

static int init_header(size_t prog_size)
{
    fota_ctx->fw_header_bd_size = FOTA_ALIGN_UP(fota_get_header_size(), prog_size);

    // Reserve space for candidate ready header (if not legacy header version)
#if FOTA_HEADER_HAS_CANDIDATE_READY
    fota_ctx->candidate_header_size = FOTA_ALIGN_UP(sizeof(fota_candidate_ready_header_t), prog_size);
    // Special case - legacy header with candidate header enabled. This is in case we wish to have a legacy BL,
    // with component update enabled. In this case, disable the candidate ready header only for the main component.
#if (MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION < 3)
    if (fota_ctx->comp_id == FOTA_COMPONENT_MAIN_COMP_NUM) {
        fota_ctx->candidate_header_size = 0;
    }
#endif
#else
    fota_ctx->candidate_header_size = 0;
#endif

    fota_ctx->storage_addr += fota_ctx->candidate_header_size + fota_ctx->fw_header_bd_size;
    return FOTA_STATUS_SUCCESS;
}

void request_download_auth(void)
{
    FOTA_TRACE_DEBUG("Download Authorization requested");
    fota_component_version_t curr_ver;

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_ver);
    int ret = fota_app_on_download_authorization(
                  fota_ctx->fw_info,
                  curr_ver
              );
    if (ret) {
        fota_source_report_update_customer_result(ret);
        abort_update(FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED, "Failed delivering Downloading authorization request");
        return;
    }
}

static int handle_manifest_init(void)
{
    if (fota_ctx) {
        // Already called
        return FOTA_STATUS_SUCCESS;
    }

    fota_ctx = (fota_context_t *)calloc(1, sizeof(*fota_ctx));
    if (!fota_ctx) {
        FOTA_TRACE_ERROR("Unable to allocate FOTA context.");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    fota_ctx->fw_info = (manifest_firmware_info_t *) malloc(sizeof(manifest_firmware_info_t));
    if (!fota_ctx->fw_info) {
        FOTA_TRACE_ERROR("Unable to allocate FW info.");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    int ret = fota_random_init(NULL, 0);
    if (ret) {
        FOTA_TRACE_DEBUG("Unable to initialize random %d", ret);
        return ret;
    }
    return FOTA_STATUS_SUCCESS;
}

static int handle_manifest(uint8_t *manifest_buf, size_t manifest_size, bool is_resume, bool is_multicast)
{
    int ret;
    int manifest_save_ret = FOTA_STATUS_INTERNAL_ERROR;
    const fota_component_desc_t *comp_desc;
    fota_component_version_t curr_fw_version;
    uint8_t curr_fw_digest[FOTA_CRYPTO_HASH_SIZE] = {0};
    fota_source_state_e report_state = FOTA_SOURCE_STATE_AWAITING_DOWNLOAD_APPROVAL;
    report_sent_callback_t on_sent;

    ret = handle_manifest_init();
    if (ret) {
        goto fail;
    }

    FOTA_TRACE_INFO("Firmware update initiated.");

    if (is_multicast) {
        report_state = FOTA_SOURCE_STATE_DOWNLOADING;
    } else if (is_resume) {
        fota_ctx->resume_state = FOTA_RESUME_STATE_STARTED;
    } else {
        manifest_save_ret = manifest_set(manifest_buf, manifest_size);
        if (manifest_save_ret) {
            FOTA_TRACE_ERROR("failed to persist manifest %d", manifest_save_ret);
            // ignore the error as it is not essential for good path update
        }
        fota_source_send_manifest_received_ack(); // acknowledge manifest received
        // MUST be done ONLY after persisting the manifest
    }

    ret = fota_manifest_parse(
              manifest_buf, manifest_size,
              fota_ctx->fw_info);

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (!ret && (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED)) {
        ret = fota_encryption_key_parse(
                  manifest_buf, manifest_size,
                  fota_ctx->encryption_key);
    }
#endif

    // Reset manifest data, no need to keep it anymore
    clear_buffer_from_mem(manifest_buf, manifest_size);

    if (ret) {
        FOTA_TRACE_DEBUG("Pelion FOTA manifest rejected %d", ret);
        goto fail;
    }

    FOTA_TRACE_DEBUG("Pelion FOTA manifest is valid");

    ret = fota_component_name_to_id(fota_ctx->fw_info->component_name, &fota_ctx->comp_id);
    if (ret) {
        FOTA_TRACE_ERROR("Manifest addresses unknown component %s", fota_ctx->fw_info->component_name);
        ret = FOTA_STATUS_UNEXPECTED_COMPONENT;
        goto fail;
    }
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    if (comp_desc->desc_info.curr_fw_get_digest) {
        comp_desc->desc_info.curr_fw_get_digest(curr_fw_digest);
    }

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_fw_version);
    FOTA_FI_SAFE_COND(fota_ctx->fw_info->version > curr_fw_version,
                      FOTA_STATUS_MANIFEST_VERSION_REJECTED, "Manifest payload-version rejected - too old");

    FOTA_TRACE_DEBUG("Handle manifest: component %s, curr version %" PRIu64 ", new version %" PRIu64 "",
                     fota_ctx->fw_info->component_name, curr_fw_version, fota_ctx->fw_info->version);

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
#if defined(FOTA_DISABLE_DELTA)
        ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
        goto fail;
#else  // defined(FOTA_DISABLE_DELTA)
        if (!comp_desc->desc_info.support_delta) {
            ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
            FOTA_TRACE_ERROR("Delta payload unsupported.");
            goto fail;
        }

        FOTA_FI_SAFE_MEMCMP(curr_fw_digest, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE,
                            FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH,
                            "Precursor digest mismatch");
#endif  // defined(FOTA_DISABLE_DELTA)
    } else {
        // If we have the current fw digest, place it in precursor for the case the installer needs it
        memcpy(fota_ctx->fw_info->precursor_digest, curr_fw_digest, FOTA_CRYPTO_HASH_SIZE);
    }

    if ((is_resume == false) || (fota_resume_download_after_user_auth == true)) { //ask for authorization
        fota_ctx->state = FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION;
        FOTA_TRACE_DEBUG("Ask for user authorization");
        on_sent = request_download_auth;
    } else { // resume without asking authorization
        //skip asking authorization from user since he has already provided one
        FOTA_TRACE_DEBUG("Resuming download...");
        on_sent = fota_on_download_authorize;
    }

    fota_source_report_state(report_state, on_sent, on_state_set_failure);
    fota_resume_download_after_user_auth = false;
    return FOTA_STATUS_SUCCESS;

fail:
    if (manifest_save_ret == FOTA_STATUS_SUCCESS) {
        manifest_delete();
    }
    // Reset buffer received from network and failed authorization/verification
    clear_buffer_from_mem(manifest_buf, manifest_size);
    abort_update(ret, "on manifest event failed");
    return ret;
}

void fota_on_manifest(uint8_t *data, size_t size)
{
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
#if MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER
    // External downloader means that every received manifest is treated as a multicast one
    fota_multicast_node_on_manifest(data, size, ext_downloader_manifest_post_action_cb);
    return;
#endif
    if (fota_ctx && fota_ctx->mc_node_update) {
        if (fota_ctx->mc_node_update_activated) {
            FOTA_TRACE_DEBUG("Received manifest when multicast update is activated - ignored");
            return;
        }
        FOTA_TRACE_DEBUG("Overridden by unicast manifest, aborting previous multicast FOTA session");
        fota_event_cancel(EVENT_RANDOM_DELAY);
        // Not activated - unicast update should take precedence over multicast one. Abort multicast one.
        abort_update(FOTA_STATUS_MULTICAST_UPDATE_ABORTED_INTERNAL, "Overridden by unicast manifest");
    }
#endif

    // this should never happen as lwm2m on_manifest callback should verify that fota is idle
    FOTA_ASSERT(!fota_ctx);

    handle_manifest(data, size, /*is_resume*/ false, false);
}

void fota_on_reject(int32_t status)
{
    FOTA_ASSERT(initialized == true);

    FOTA_TRACE_ERROR("Application rejected update - reason %" PRId32, status);

    if (!fota_ctx) {
        // We just need to know whether manifest is present, so no need to allocate a full size manifest
        size_t manifest_size = 0;
        uint8_t dummy;

        if (manifest_get((uint8_t *)&dummy, sizeof(dummy), &manifest_size) != FOTA_STATUS_NOT_FOUND) {
            // these steps should be performed even if fota context does not exits, but manifest exists.
            // one possible scenario is if defer was called before reject, then the context is released (but manifest still exists).
            // when fota reject called, manifest should be removed and fota flow terminated.

            if (fota_persistent_ctx.state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) {
                do_abort_update(FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED, "Download Authorization not granted");
            } else {
                do_abort_update(FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED,  "Install Authorization not granted");
            }
        }
        return;
    } else if (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) {
        abort_update(FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED, "Download Authorization not granted");
    } else { //FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION
        abort_update(FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED, "Install Authorization not granted");
    }
}

void fota_on_defer(int32_t param)
{
    FOTA_ASSERT(initialized == true);

    if (!fota_ctx) {
        return;  // gracefully ignore this call if update is not running
    }

    if (fota_ctx->state == FOTA_STATE_INSTALLING) {
        return; //don't allow defer/postpone during install
    }

    FOTA_TRACE_DEBUG("fota_on_defer");
    /* mark call to defer only if FOTA is active */
    fota_defer_by_user = true; // for now we assume that defer called always by user app

    if (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        fota_on_install_authorize((fota_install_state_e) param);
        return;
    }

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_UNSUPPORTED)
    FOTA_TRACE_ERROR("Got update defer - resume not supported");
    abort_update(FOTA_STATUS_INTERNAL_ERROR, "Update aborted due to defer request");
#else
    abort_update(FOTA_STATUS_UPDATE_DEFERRED, "Update deferred by application");
#endif
}

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE) && !defined (MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER)
static void on_reboot_in_ms(void *data, size_t size)
{
    (void)data;
    (void)size;

    on_reboot();
}
#endif

static void on_reboot(void)
{
    FOTA_TRACE_INFO("Rebooting.");

    manifest_delete();

    const fota_component_desc_t *comp_desc;
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    // Reason this is here is that platform hook may cut communication with service,
    // so due to reliable report policy, this hook may not be reached.
    fota_platform_finish_update_hook(comp_desc->name);

    update_cleanup();

    REBOOT_NOW();
}

static int write_candidate_ready(const char *comp_name)
{
#if FOTA_HEADER_HAS_CANDIDATE_READY
    int ret;
    uint8_t *header_buf = calloc(1, fota_ctx->candidate_header_size);
    if (!header_buf) {
        FOTA_TRACE_ERROR("FOTA header_buf - allocation failed");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    fota_candidate_ready_header_t *header = (fota_candidate_ready_header_t *) header_buf;

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_ONGOING) {
        ret = fota_bd_read(header_buf, fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size);
        if (ret) {
            goto finish;
        }
        if (header->footer == FOTA_CANDIDATE_READY_MAGIC) {
            // Already programmed - no need to do anything. Return to normal state.
            fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
            goto finish;
        }
    }
#endif

    header->magic = FOTA_CANDIDATE_READY_MAGIC;
    header->footer = FOTA_CANDIDATE_READY_MAGIC;
    strncpy(header->comp_name, comp_name, FOTA_COMPONENT_MAX_NAME_SIZE - 1);

    ret = fota_bd_program(header_buf, fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size);
    if (ret) {
        FOTA_TRACE_ERROR("candidate_ready write to storage failed %d", ret);
        // Not really needed, just prevent warning if support resume is not configured
        goto finish;
    }

finish:

    free(header_buf);
    return ret;
#else // FOTA_HEADER_HAS_CANDIDATE_READY
    return FOTA_STATUS_SUCCESS;
#endif
}

static void install_single_component()
{
    unsigned int comp_id = fota_ctx->comp_id;
    const fota_component_desc_t *comp_desc;
    int ret = FOTA_STATUS_SUCCESS;
    (void) ret;

#if defined(__MBED__)
    // At this point we don't need our fota context buffers any more, for mbed
    // Free them before installer starts working (to flatten memory allocation curve).
    free_context_buffers();
#endif

    fota_component_get_desc(comp_id, &comp_desc);

    // Code saving - only relevant if we have additional components other than the main one
#if FOTA_COMPONENT_SUPPORT
    // Installer and successful finish actions apply to all components but the main one
    bool do_install;
    fota_comp_install_cb_t install_handler;
    fota_candidate_iterate_handler_t iterate_handler = NULL;
    size_t install_alignment;

#if defined(TARGET_LIKE_LINUX)
    // Linux platform: Always execute our own iterate handler, even for main component
    do_install = true;
    install_handler = fota_linux_candidate_iterate;
    install_alignment = 1;
#else
    // Embedded platform: Bootloader will run the installation on main component, rest are done here
    do_install = (comp_id == FOTA_COMPONENT_MAIN_COMP_NUM) ? false : true;
    // TODO: Deprecated iterate_handler used for backwards compatobility. Remove once we stop support it.
    iterate_handler = comp_desc->desc_info.candidate_iterate_cb;
    install_handler = comp_desc->desc_info.component_install_cb;
    install_alignment = comp_desc->desc_info.install_alignment;
#endif
    if (do_install) {
        FOTA_TRACE_INFO("Installing new version for component %s", comp_desc->name);

        // Run the installer using the candidate iterate service
        ret = fota_candidate_iterate_image(true, (bool) MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT,
                                           comp_desc->name, install_alignment,
                                           iterate_handler, install_handler);
        if (ret) {
            abort_update(ret, "Failed on component update");
            return;
        }

#if defined(TARGET_LIKE_LINUX)
        if (!fota_component_is_internal_component(comp_id)) {
            // comeback to change it later, as we would support main component registration
            // in case install_cb NULL or MAIN component - calling old API fota_app_on_install_candidate
            fota_comp_install_cb_t install_cb = comp_desc->desc_info.component_install_cb;
            if (install_cb == NULL || comp_id == FOTA_COMPONENT_MAIN_COMP_NUM) {
                ret = fota_app_on_install_candidate(fota_linux_get_candidate_file_name(), fota_ctx->fw_info);
            } else {
                ret = install_cb(comp_desc->name, NULL, fota_linux_get_candidate_file_name(), fota_ctx->fw_info->vendor_data, FOTA_MANIFEST_VENDOR_DATA_SIZE, NULL);
            }
            if (ret) {
                FOTA_TRACE_ERROR("Application candidate install callback for %s failed %d", comp_desc->name, ret);
                fota_source_report_update_customer_result(ret);
                abort_update(FOTA_STATUS_FW_INSTALLATION_FAILED, "Failed on component install");
                return;
            }
        }
#endif

        if (!comp_desc->desc_info.need_reboot) {
            size_t bd_read_size, bd_prog_size, offest = fota_ctx->fw_header_offset;
            fota_header_info_t header;
            ret = fota_bd_get_read_size(&bd_read_size);
            if (ret) {
                goto fail;
            }
            ret = fota_bd_get_program_size(&bd_prog_size);
            if (ret) {
                goto fail;
            }
            ret = fota_candidate_read_header(&offest, bd_read_size, bd_prog_size, &header);
            if (ret) {
                goto fail;
            }

            ret = comp_install_verify(comp_desc, comp_id, &header);
fail:
            fota_nvm_fw_encryption_key_delete();
            handle_fota_app_on_complete(ret); //notify application on after install, no reset
        }
    }

#endif // FOTA_COMPONENT_SUPPORT

    if ((comp_desc->desc_info.need_reboot) && (fota_install_state == FOTA_INSTALL_STATE_AUTHORIZE)) {
        fota_ctx->state = FOTA_STATE_IDLE;
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE) && !defined (MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER)
        if (fota_ctx->mc_node_update) {
            FOTA_DBG_ASSERT(fota_ctx->mc_node_post_action_callback);
            fota_ctx->mc_node_post_action_callback(FOTA_STATUS_SUCCESS);

            // delay activation by time requested by Multicast
            fota_event_handler_defer_with_data_in_ms(on_reboot_in_ms, NULL, 0, fota_ctx->activate_in_sec * 1000, 0);
            return;
        }
#endif
        fota_source_report_state(FOTA_SOURCE_STATE_REBOOTING, on_reboot, on_reboot);

        return;
    } else {
        // In case reboot is needed, the manifest is deleted in on_reboot_in_ms or in on_reboot CB
        // i.e. after the resource is being updated
        // In case the reboot isn't needed, delete the manifest now, after the installation is completed
        manifest_delete();
    }

    if (fota_install_state == FOTA_INSTALL_STATE_AUTHORIZE) {

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
        if (fota_ctx->mc_node_update) {
            FOTA_DBG_ASSERT(fota_ctx->mc_node_post_action_callback);
            fota_ctx->mc_node_post_action_callback(ret);
        }
#endif
        fota_platform_finish_update_hook(comp_desc->name);
        fota_source_report_update_result(FOTA_STATUS_FW_UPDATE_OK);
        fota_source_report_state(FOTA_SOURCE_STATE_IDLE, NULL, NULL);

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
        if (fota_ctx->mc_br_update) {
            // don't erase candidate image in case of node update by border router
            erase_candidate_image = false;
        }
#endif

        if (erase_candidate_image == true) {
            fota_candidate_erase();
        }
    }
    update_cleanup();

}
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)

static void install_combined_package()
{
    unsigned int comp_id = fota_ctx->comp_id;
    const fota_component_desc_t *comp_desc;
    package_descriptor_t descriptor_info;
    uint8_t *package_descriptor_buffer = NULL;
    size_t  package_descriptor_buffer_size;
    int ret = FOTA_STATUS_SUCCESS;
    (void) ret;

    fota_component_get_desc(comp_id, &comp_desc);

    FOTA_TRACE_INFO("Installing combined image");

    fota_comp_install_cb_t install_handler = fota_linux_candidate_iterate;
    fota_candidate_iterate_handler_t iterate_handler = NULL;
    size_t install_alignment = 1;

    //Get combined package from candidate
    ret = fota_candidate_iterate_image(true, (bool) MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT,
                                       comp_desc->name, install_alignment,
                                       iterate_handler, install_handler);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to extract combined package from the candidate");
        goto clean;
    }

    // Get package descriptor data
#if defined(TARGET_LIKE_LINUX)
    ret = fota_linux_extract_and_get_package_descriptor_data(&package_descriptor_buffer,
                                                             &package_descriptor_buffer_size);
#endif
    if (ret) {
        FOTA_TRACE_ERROR("Failed to read package descriptor");
        goto clean;
    }

    // Parse combined package data
    ret = fota_combined_package_parse(&descriptor_info, package_descriptor_buffer, package_descriptor_buffer_size);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to parse package descriptor");
        goto clean;
    }

    // validate parsed data
    ret = fota_sub_component_validate_package_images(comp_desc->name, &descriptor_info);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to validate package images");
        goto clean;
    }

    ret = fota_sub_component_install(comp_desc->name, &descriptor_info);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to install sub component");
        goto clean;
    }

    // remove manifest after candidate installation finished and before potential reboot.

    manifest_delete();

    fota_ctx->state = FOTA_STATE_IDLE;
    fota_source_report_state(FOTA_SOURCE_STATE_REBOOTING, on_reboot, on_reboot);

clean:
    // clean descriptor info memory
    fota_combined_clean_image_descriptors_array(&descriptor_info);

    if (package_descriptor_buffer) {
        free(package_descriptor_buffer);
    }

    if (ret != FOTA_STATUS_SUCCESS) {
        abort_update(ret, "Failed install_combined_package");
    }
    return;

}

#endif //#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)

static void install_component()
{
    int ret = FOTA_STATUS_SUCCESS;
    (void) ret;

    fota_ctx->state = FOTA_STATE_INSTALLING;

#if MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1

    // Check payload format
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_COMBINED ||
            fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
        // If payload is combined type call install_combined_package*/
        install_combined_package();
    } else
#endif
    {
        install_single_component();
    }
}

static int prepare_and_program_header(void)
{
    int ret;
    fota_header_info_t header_info = { 0 };
    size_t header_buf_actual_size = 0;
    uint8_t *header_buf = (uint8_t *) calloc(1, fota_ctx->fw_header_bd_size);
    if (!header_buf) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_ERROR("FOTA scratch buffer - allocation failed");
        goto fail;
    }

    fota_set_header_info_magic(&header_info);
    header_info.fw_size = fota_ctx->fw_info->installed_size;
    header_info.version = fota_ctx->fw_info->version;
    header_info.external_header_size = (uint16_t)(sizeof(fota_header_info_t) - offsetof(fota_header_info_t, internal_header_barrier));
    memcpy(header_info.digest, fota_ctx->fw_info->installed_digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(header_info.precursor, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(header_info.vendor_data, fota_ctx->fw_info->vendor_data, FOTA_MANIFEST_VENDOR_DATA_SIZE);
#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
    memcpy(header_info.signature, fota_ctx->fw_info->installed_signature, FOTA_IMAGE_RAW_SIGNATURE_SIZE);
#endif  // defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1) && \
    (MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE != FOTA_CLOUD_ENCRYPTION_BLOCK_SIZE)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
        header_info.block_size = FOTA_CLOUD_ENCRYPTION_BLOCK_SIZE;
    } else
#endif
    {
        header_info.block_size = MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE;
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    header_info.flags |= FOTA_HEADER_ENCRYPTED_FLAG;
#if (MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION == FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY) && !defined(TARGET_LIKE_LINUX)
    // encrypt fw_key buffer using device key and store it in the header
    uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE];
    ret = fota_nvm_fw_encryption_key_get(fw_key);
    if (ret) {
        FOTA_TRACE_DEBUG("Encryption key not found");
        goto fail;
    }
    ret = fota_encrypt_fw_key(fw_key,
                              header_info.encrypted_fw_key,
                              header_info.encrypted_fw_key_tag,
                              &header_info.encrypted_fw_key_iv);
    fota_fi_memset(fw_key, 0, sizeof(fw_key));
    if (ret) {
        FOTA_TRACE_ERROR("Failed to start encryption engine. ret %d", ret);
        goto fail;
    }
#endif // FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY
#endif

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    header_info.flags |= FOTA_HEADER_SUPPORT_RESUME_FLAG;
#endif

    ret = fota_serialize_header(&header_info, header_buf, fota_ctx->fw_header_bd_size, &header_buf_actual_size);
    if (ret) {
        FOTA_TRACE_ERROR("serialize header failed");
        goto fail;
    }

    FOTA_DBG_ASSERT(fota_ctx->fw_header_bd_size >= header_buf_actual_size);

    ret = fota_bd_program(header_buf, fota_ctx->fw_header_offset, fota_ctx->fw_header_bd_size);
    if (ret) {
        FOTA_TRACE_ERROR("header buf write to storage failed %d", ret);
    }

fail:
    free(header_buf);
    return ret;
}

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME

// Check whether a range is blank - should only be used by analyze_resume_state function
static int check_if_blank(size_t addr, size_t size, uint8_t erase_val, size_t *blank_start_offset)
{
    FOTA_DBG_ASSERT(fota_ctx->page_buf);
    FOTA_DBG_ASSERT(size <= fota_ctx->page_buf_size);
    FOTA_DBG_ASSERT(fota_ctx->resume_state != FOTA_RESUME_STATE_INACTIVE);

    int ret = fota_bd_read(fota_ctx->page_buf, addr, size);
    if (ret) {
        return ret;
    }

    for (*blank_start_offset = size; *blank_start_offset > 0; --(*blank_start_offset)) {
        if (fota_ctx->page_buf[*blank_start_offset - 1] != erase_val) {
            break;
        }
    }

    return ret;
}

static int analyze_resume_state(fota_state_e *next_fota_state)
{
    int ret = FOTA_STATUS_SUCCESS;
    int int_erase_val = 0;
    uint8_t erase_val;
    size_t blank_offs;
    uint32_t num_blocks_available, num_blocks_left;
    size_t save_storage_addr = fota_ctx->storage_addr;
    uint8_t fw_key[FOTA_ENCRYPT_KEY_SIZE];

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT != 1)
    fota_candidate_block_checksum_t checksum = 0;
#else
    fota_hash_context_t *payload_temp_hash_ctx = NULL;
#endif

    if (fota_ctx->resume_state == FOTA_RESUME_STATE_INACTIVE) {
        return FOTA_STATUS_SUCCESS;
    }

    // Resume functionality available for full update only
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        FOTA_TRACE_DEBUG("Delta update resume is not supported");
        goto no_resume;
    }

    fota_ctx->page_buf = malloc(fota_ctx->page_buf_size);
    if (!fota_ctx->page_buf) {
        FOTA_TRACE_ERROR("Not enough memory for page_buf");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto no_resume;
    }
    fota_ctx->effective_page_buf = fota_ctx->page_buf + fota_ctx->page_buf_size - fota_ctx->effective_page_buf_size;

    ret = fota_bd_get_erase_value(&int_erase_val);
    if (ret || (int_erase_val < 0)) {
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto no_resume;
    }
    erase_val = (uint8_t) int_erase_val;

    // Now start analyzing candidate storage to figure resume state out

    // Note for upcoming logic in candidate ready header and further cases:
    // After checking if blank, we should read the buffer to page_buf now in order to continue with data analysis.
    // However, check_if_blank function already does that, so need to read again.

    ret = check_if_blank(fota_candidate_get_config()->storage_start_addr, fota_ctx->candidate_header_size,
                         erase_val, &blank_offs);
    if (ret) {
        goto no_resume;
    } else if (blank_offs) {
        fota_candidate_ready_header_t *header = (fota_candidate_ready_header_t *) fota_ctx->page_buf;

        if ((header->magic != FOTA_CANDIDATE_READY_MAGIC) || (header->footer != FOTA_CANDIDATE_READY_MAGIC)) {
            // candidate header corrupt - no point resuming
            FOTA_TRACE_DEBUG("Candidate header corrupt");
            goto no_resume;
        }

        // Candidate header fully programmed - jump to install authorization
        FOTA_TRACE_DEBUG("Candidate header found. Resuming FOTA from install stage.");
        *next_fota_state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;
        // Mark resume state as ongoing, in order for later stage to know we can
        // move straight to download finish.
        fota_ctx->resume_state = FOTA_RESUME_STATE_ONGOING;
        goto finish;
    }

    // If header is blank or not fully written then no point resuming (as it's written on an early stage anyway)
    ret = check_if_blank(fota_ctx->fw_header_offset, fota_ctx->fw_header_bd_size,
                         erase_val, &blank_offs);
    if (ret || (blank_offs < fota_ctx->fw_header_bd_size)) {
        FOTA_TRACE_DEBUG("Header not programmed");
        goto no_resume;
    }

    // Now traverse candidate data

    ret = fota_nvm_fw_encryption_key_get(fw_key);
    if (ret) {
        FOTA_TRACE_DEBUG("Encryption key not found");
        goto no_resume;
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
        ret = fota_hash_start(&payload_temp_hash_ctx);
        if (ret) {
            goto no_resume;
        }
    }
#endif

    num_blocks_available = storage_available / fota_ctx->page_buf_size;
    num_blocks_left = FOTA_ALIGN_UP(fota_ctx->fw_info->payload_size, fota_ctx->effective_page_buf_size) /
                      fota_ctx->effective_page_buf_size;

    while (num_blocks_left) {

        if (num_blocks_left > num_blocks_available) {
            FOTA_TRACE_DEBUG("Not enough erased space left for resuming");
            goto no_resume;
        }

        size_t chunk = MIN(fota_ctx->fw_info->payload_size - fota_ctx->payload_offset, fota_ctx->effective_page_buf_size);

        ret = check_if_blank(fota_ctx->storage_addr, fota_ctx->page_buf_size, erase_val, &blank_offs);
        if (ret) {
            goto no_resume;
        }

        if (!blank_offs) {
            // If block is blank, this means we can converge to the regular downloading state.
            fota_ctx->resume_state = FOTA_RESUME_STATE_ONGOING;
            *next_fota_state = FOTA_STATE_DOWNLOADING;
            FOTA_TRACE_DEBUG("Resuming FOTA from download stage");
            goto finish;
        }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        size_t data_offset = 0;
        if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
            //  update data offset to skip the tag
            data_offset = FOTA_ENCRYPT_TAG_SIZE;
            // on an encrypted payload, update payload_temp_hash_ctx before decrypting
            // and copy it to payload_hash_ctx only if decrypt succeeds.
            ret = fota_hash_update(payload_temp_hash_ctx, fota_ctx->effective_page_buf, chunk);
            if (ret) {
                goto no_resume;
            }
        }
        // decrypt data with tag (at the beginning of page_buf)
        ret = fota_decrypt_data(fota_ctx->enc_ctx,
                                fota_ctx->effective_page_buf + data_offset,
                                chunk - data_offset,
                                fota_ctx->effective_page_buf + data_offset,
                                fota_ctx->page_buf);
        if (ret) {
            // Decryption failure - Skip the block
            FOTA_TRACE_DEBUG("Bad encrypted block skipped");
            goto next_block;
        }

#else
        checksum = 0;
        for (uint32_t i = 0; i < chunk; i++) {
            checksum += fota_ctx->effective_page_buf[i];
        }
        if (checksum != *(fota_candidate_block_checksum_t *) fota_ctx->page_buf) {
            // Bad checksum - Skip the block
            FOTA_TRACE_DEBUG("Bad checksum - block skipped");
            goto next_block;
        }
#endif

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
            // on encrypted payload, copy payload_temp_hash_ctx to payload_hash_ctx
            fota_hash_clone(fota_ctx->payload_hash_ctx, payload_temp_hash_ctx);
        } else
#endif
        {
            // update payload_hash_ctx after decryption
            ret = fota_hash_update(fota_ctx->payload_hash_ctx, fota_ctx->effective_page_buf, chunk);
            if (ret) {
                goto no_resume;
            }
        }

        // Block verified as OK - update num blocks left
        num_blocks_left--;
        fota_ctx->payload_offset += chunk;
        fota_ctx->fw_bytes_written += chunk;

next_block:
        num_blocks_available--;
        fota_ctx->storage_addr += fota_ctx->page_buf_size;
    }

#if !defined(FOTA_DISABLE_DELTA)
    // for a delta patch, copy payload_hash_ctx to installed_hash_ctx
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        fota_hash_clone(fota_ctx->installed_hash_ctx, fota_ctx->payload_hash_ctx);
    }
#endif

    // Got here means that the whole firmware has been written, but candidate ready header is blank.
    // This means we can converge to the regular install authorization flow.
    *next_fota_state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
    FOTA_TRACE_DEBUG("Resuming FOTA from install stage");
    goto finish;

no_resume:
    FOTA_TRACE_DEBUG("Full resume aborted, restarting FOTA");
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
    fota_ctx->storage_addr = save_storage_addr;
    fota_ctx->fw_bytes_written = 0;
    fota_ctx->payload_offset = 0;
    // reset payload_hash_ctx
    fota_hash_finish(&fota_ctx->payload_hash_ctx);
    fota_hash_start(&fota_ctx->payload_hash_ctx);
#if !defined(FOTA_DISABLE_DELTA)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        // reset installed_hash_ctx
        fota_hash_finish(&fota_ctx->installed_hash_ctx);
        fota_hash_start(&fota_ctx->installed_hash_ctx);
    }
#endif

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_encryption_stream_reset(fota_ctx->enc_ctx);
#endif

finish:
    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    fota_hash_finish(&payload_temp_hash_ctx);
#endif
    return ret;
}

#endif // MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME

static int calc_and_erase_needed_storage()
{
    int ret;
    size_t storage_needed = 0, erase_size, total_erase_size, end_addr;

    if (fota_ctx) {
        // Calculate needed space for FW data in storage:
        // This will align the non-encrypted image up to page buf size and recalculate the storage space
        // needed for interleaved data and tags in the encrypted case.
        storage_needed = fota_ctx->storage_addr - fota_candidate_get_config()->storage_start_addr +
                         FOTA_ALIGN_UP(fota_ctx->fw_info->installed_size, fota_ctx->effective_page_buf_size) /
                         fota_ctx->effective_page_buf_size * fota_ctx->page_buf_size;

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME && !defined(TARGET_LIKE_LINUX)
        // In case we support resume, erase twice as much as we need (capped by entire available storage),
        // covering bad blocks on the way (should be more than enough).
        storage_needed = MIN(2 * storage_needed, storage_available);
#endif
    }

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    if (!fota_ctx) {
        // Got here, this means we need to use candidate storage for non FOTA image.
        // Just take it from start, for as much size as Multicast module requires.
        mc_node_new_image = false;
        mc_image_data_addr = fota_candidate_get_config()->storage_start_addr;
        storage_needed = mc_node_image_size;
    } else if (fota_ctx->mc_node_update) {
        // Multicast FOTA case, need to tweak our needs
        mc_node_new_image = false;
        mc_node_image_size = fota_ctx->fw_info->payload_size;
        if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
            // Delta case - need to add space for delta image right after candidate image.
            // Multicast reading should be on the delta image.
            mc_image_data_addr = fota_candidate_get_config()->storage_start_addr + storage_needed;
            storage_needed += mc_node_image_size;
        } else {
            // Full image case - keep needed storage as is.
            // Multicast read should be on the data right after the headers (current storage address).
            mc_image_data_addr = fota_ctx->storage_addr;
        }
    }
#endif

    if (storage_needed > storage_available) {
        FOTA_TRACE_ERROR("Insufficient storage for image");
        return FOTA_STATUS_INSUFFICIENT_STORAGE;
    }

    end_addr = fota_candidate_get_config()->storage_start_addr + storage_needed;
    ret = fota_bd_get_erase_size(end_addr - 1, &erase_size);
    if (ret) {
        FOTA_TRACE_ERROR("Get erase size failed %d", ret);
        return ret;
    }

    // Align erase size to the end of last sector
    total_erase_size = end_addr % erase_size ? FOTA_ALIGN_DOWN(end_addr, erase_size) + erase_size - fota_candidate_get_config()->storage_start_addr :
                       storage_needed;
    FOTA_TRACE_DEBUG("Erasing storage at %zu, size %zu", fota_candidate_get_config()->storage_start_addr, total_erase_size);
    ret = fota_bd_erase(fota_candidate_get_config()->storage_start_addr, total_erase_size);
    if (ret) {
        FOTA_TRACE_ERROR("Erase storage failed %d", ret);
    }

    return ret;
}

static void on_downloading_state_delivered(void)
{
    int ret;

    ret = fota_download_init(&fota_ctx->download_handle);
    if (ret) {
        FOTA_TRACE_ERROR("init download failed %d", ret);
        goto fail;
    }

    ret = fota_download_start(fota_ctx->download_handle, fota_ctx->fw_info->uri, fota_ctx->payload_offset);
    if (ret) {
        FOTA_TRACE_ERROR("start firmware download failed %d", ret);
        goto fail;
    }

    return;

fail:
    FOTA_TRACE_DEBUG("Failed on download event. ret code %d", ret);
    abort_update(ret, "Failed on download authorization event");
}

static void fota_on_download_authorize()
{
    int ret;
    size_t prog_size;
    const fota_component_desc_t *comp_desc;
#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    int erase_val;
    fota_state_e next_fota_state = FOTA_STATE_DOWNLOADING;
#endif

    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    ret = fota_platform_start_update_hook(comp_desc->name);
    if (ret) {
        FOTA_TRACE_ERROR("Platform start update hook failed %d", ret);
        goto fail;
    }

    ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("Unable to initialize storage %d", ret);
        goto fail;
    }
    FOTA_TRACE_DEBUG("FOTA BlockDevice initialized");

#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
    ret = fota_bd_get_erase_value(&erase_val);
    if (ret || (erase_val < 0)) {
        FOTA_TRACE_ERROR("Full resume not supported for devices that have no erase");
        FOTA_ASSERT(0);
    }
#endif

    ret = fota_bd_get_program_size(&prog_size);
    if (ret) {
        FOTA_TRACE_ERROR("Get program size failed. ret %d", ret);
        goto fail;
    }

    fota_ctx->storage_addr = fota_candidate_get_config()->storage_start_addr;
    ret = init_header(prog_size);
    if (ret) {
        goto fail;
    }

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1) && \
    (MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE != FOTA_CLOUD_ENCRYPTION_BLOCK_SIZE)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW || fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
        fota_ctx->page_buf_size = FOTA_ALIGN_UP(FOTA_CLOUD_ENCRYPTION_BLOCK_SIZE, prog_size);
    } else
#endif
    {
        fota_ctx->page_buf_size = FOTA_ALIGN_UP(MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE, prog_size);
    }

    ret = init_encryption(fota_ctx->fw_info);
    if (ret) {
        goto fail;
    }

    fota_ctx->effective_page_buf_size = fota_ctx->page_buf_size;

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW && fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
        // on encrypted payload, skip reducing tag size
        fota_ctx->effective_page_buf_size -= FOTA_ENCRYPT_TAG_SIZE;
    }
#elif (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME)
    // Reduce checksum size
    fota_ctx->effective_page_buf_size -= sizeof(fota_candidate_block_checksum_t);
#endif

    ret = fota_hash_start(&fota_ctx->payload_hash_ctx);
    if (ret) {
        goto fail;
    }

#if !defined(FOTA_DISABLE_DELTA)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        ret = fota_hash_start(&fota_ctx->installed_hash_ctx);
        if (ret) {
            goto fail;
        }
    }
#endif

    fota_ctx->fw_header_offset = fota_ctx->storage_addr - fota_ctx->fw_header_bd_size;

    ret = calc_available_storage();
    if (ret) {
        goto fail;
    }

#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
    ret = analyze_resume_state(&next_fota_state);
    if (!ret && next_fota_state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        finalize_update();
        return;
    }
#else
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;
#endif

    // Erase storage (if we're resuming, this has already been done)
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_INACTIVE) {

        ret = calc_and_erase_needed_storage();
        if (ret) {
            goto fail;
        }

        // In non legacy headers we can and should program the FW header already here, to support full resume (as resume needs info from header).
        // This is OK, as the candidate ready header will be programmed at install phase.
        if (fota_ctx->candidate_header_size) {
            ret = prepare_and_program_header();
            if (ret) {
                goto fail;
            }
        }
    }

    // At this point, we have converged to regular state, even if we were resuming
    fota_ctx->resume_state = FOTA_RESUME_STATE_INACTIVE;

    fota_ctx->page_buf = malloc(fota_ctx->page_buf_size);
    if (!fota_ctx->page_buf) {
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        FOTA_TRACE_ERROR("FOTA scratch buffer - allocation failed");
        goto fail;
    }

    fota_ctx->effective_page_buf = fota_ctx->page_buf + fota_ctx->page_buf_size - fota_ctx->effective_page_buf_size;

#if !defined(FOTA_DISABLE_DELTA)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        fota_ctx->delta_buf = malloc(MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE);
        if (!fota_ctx->delta_buf) {
            FOTA_TRACE_ERROR("FOTA delta buffer - allocation failed");
            ret = FOTA_STATUS_OUT_OF_MEMORY;
            goto fail;
        }

        ret = fota_delta_start(&fota_ctx->delta_ctx, comp_desc->desc_info.curr_fw_read);
        if (ret) {
            goto fail;
        }
        FOTA_TRACE_DEBUG("FOTA delta engine initialized");
    }
#endif  // defined(FOTA_DISABLE_DELTA)

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    if (fota_ctx->mc_node_update) {
#if MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER
        // External downloader mode - supply fragment size ourselves
        // (use smallest possible size to allow maximal flexibility)
        fota_multicast_node_set_fragment_size(prog_size);
#endif
        // Notify Multicast module of manifest stage finish
        FOTA_DBG_ASSERT(fota_ctx->mc_node_post_action_callback);
        fota_ctx->mc_node_post_action_callback(FOTA_STATUS_SUCCESS);
        fota_ctx->mc_node_post_action_callback = NULL;
        return;
    }
#endif

    fota_ctx->state = FOTA_STATE_DOWNLOADING;
    fota_source_report_state(FOTA_SOURCE_STATE_DOWNLOADING, on_downloading_state_delivered, on_state_set_failure);

    return;

fail:
    FOTA_TRACE_DEBUG("Failed on download event. ret code %d", ret);
    abort_update(ret, "Failed on download authorization event");
}

static void fota_on_install_authorize(fota_install_state_e fota_install_type)
{
    int ret;
    const fota_component_desc_t *comp_desc;

    fota_install_state = fota_install_type;

    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    free(fota_ctx->page_buf);
    fota_ctx->page_buf = NULL;

    if (fota_install_state != FOTA_INSTALL_STATE_DEFER) {
        if (fota_ctx->candidate_header_size) {
            ret = write_candidate_ready(comp_desc->name);
        } else {
            ret = prepare_and_program_header();
        }
        if (ret) {
            FOTA_TRACE_ERROR("FOTA write final header - failed %d", ret);
            goto fail;
        }
    }

    if ((fota_install_state == FOTA_INSTALL_STATE_AUTHORIZE) || (fota_install_state == FOTA_INSTALL_STATE_POSTPONE_REBOOT))  {
        fota_source_report_state(FOTA_SOURCE_STATE_UPDATING, install_component, on_state_set_failure);
    } else { //FOTA_INSTALL_STATE_DEFER -  we skip the installation for now
#if MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
        FOTA_TRACE_INFO("FOTA install deferred until further user instruction");
#else
        abort_update(FOTA_STATUS_INTERNAL_ERROR,
                     "Component install defer requires resume support");
#endif
        update_cleanup();
    }

    return;

fail:
    FOTA_TRACE_DEBUG("Failed on install authorization event. ret code %d", ret);
    abort_update(ret, "Failed on install authorization event");
}

void fota_on_authorize(int32_t param)
{
    FOTA_ASSERT(fota_ctx);

    FOTA_ASSERT(
        (fota_ctx->state == FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION) ||
        (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION)
    );

    if (fota_ctx->state == FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION) {
        FOTA_ASSERT(param == FOTA_INSTALL_STATE_AUTHORIZE);
        FOTA_TRACE_INFO("Install authorization granted.");
        fota_on_install_authorize((fota_install_state_e)param);
        return;
    }

#if defined (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE) && (MBED_CLIENT_DYNAMIC_LOGGING_BUFFER_SIZE > 0)
    m2mdynlog_stop_capture(true);
#endif

    FOTA_TRACE_INFO("Download authorization granted.");
    fota_on_download_authorize();
}

static int program_to_storage(uint8_t *buf, size_t addr, uint32_t size)
{
    uint32_t data_size = size;
    uint32_t prog_size = size;
    uint8_t *src_buf = buf;
    uint8_t *prog_buf = buf;
    int ret;
    bool do_program = true;

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    // In case of a full multicast node update, image was already placed there by Multicast module.
    // Just skip programming (but keep all other calculations).
    if (fota_ctx && fota_ctx->mc_node_update &&
            (fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA)) {
        do_program = false;
    }
#endif

    if (fota_ctx->effective_page_buf_size < fota_ctx->page_buf_size) {
        data_size = MIN(fota_ctx->effective_page_buf_size, size);
        prog_size = fota_ctx->page_buf_size;
        prog_buf = fota_ctx->page_buf;
    }

    // simple while-loop instead of check + do-while would take tens of bytes more from ROM
    if (!size) {
        goto exit;
    }

    do {

#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
        if (fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW && fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED) {
            // on encrypted payload, data already encrypted
            uint8_t *tag = fota_ctx->page_buf;
            ret = fota_encrypt_data(fota_ctx->enc_ctx, src_buf, data_size, src_buf, tag);
            if (ret) {
                FOTA_TRACE_ERROR("encryption failed %d", ret);
                return ret;
            }
        }
#elif MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT == FOTA_RESUME_SUPPORT_RESUME
        fota_candidate_block_checksum_t *checksum = (fota_candidate_block_checksum_t *) fota_ctx->page_buf;
        *checksum = 0;
        for (uint32_t i = 0; i < data_size; i++) {
            *checksum += fota_ctx->effective_page_buf[i];
        }
#endif

        if (prog_size < fota_ctx->page_buf_size) {
            memset(fota_ctx->page_buf + prog_size, 0, fota_ctx->page_buf_size - prog_size);
            // We are on the very last page, align up to page buffer size
            prog_size = FOTA_ALIGN_UP(prog_size, fota_ctx->page_buf_size);
        }
        if (do_program) {
            ret = fota_bd_program(prog_buf, addr, prog_size);
            if (ret) {
                FOTA_TRACE_ERROR("Write to storage failed, address 0x%zx, size %" PRIu32 " %d",
                                 addr, size, ret);
                return ret;
            }
        }
        src_buf += data_size;
        addr += prog_size;
        size -= data_size;
        fota_ctx->fw_bytes_written += data_size;
        fota_ctx->storage_addr += prog_size;
    } while (size);

exit:
    return FOTA_STATUS_SUCCESS;
}

static int handle_fw_fragment(uint8_t *buf, size_t size, bool last)
{
    uint8_t *source_buf = buf, *prog_buf;
    uint32_t prog_size;
    uint32_t chunk;

    while (size) {
        // Two cases here:
        // 1. The "hard" one - If our fragment is not aligned to a whole page:
        //    In this case, just pull the remaining bytes into the page buf to complete the page.
        // 2. The "easy" one - fragment is aligned to a whole page:
        //    In this case, use source buffer directly and push as many pages as possible.
        if ((fota_ctx->effective_page_buf_size < fota_ctx->page_buf_size) ||
                fota_ctx->page_buf_offset || (size < fota_ctx->effective_page_buf_size)) {
            chunk = MIN(fota_ctx->effective_page_buf_size - fota_ctx->page_buf_offset, size);
            prog_size = fota_ctx->page_buf_offset + chunk;
            prog_buf = fota_ctx->effective_page_buf;
            memcpy(fota_ctx->effective_page_buf + fota_ctx->page_buf_offset, source_buf, chunk);
            fota_ctx->page_buf_offset = (fota_ctx->page_buf_offset + chunk) % fota_ctx->effective_page_buf_size;
        } else {
            chunk = FOTA_ALIGN_DOWN(size, fota_ctx->effective_page_buf_size);
            prog_size = chunk;
            prog_buf = source_buf;
        }
        source_buf += chunk;

        if ((prog_size >= fota_ctx->effective_page_buf_size) || last) {
            int ret = program_to_storage(prog_buf,
                                         fota_ctx->storage_addr,
                                         prog_size);
            if (ret) {
                FOTA_TRACE_ERROR("Failed writing to storage %d", ret);
                return ret;
            }
        }
        size -= chunk;
    }
    return FOTA_STATUS_SUCCESS;
}

static void on_approve_state_delivered(void)
{
    FOTA_TRACE_DEBUG("Install Authorization requested");
    int ret = fota_app_on_install_authorization();
    if (ret) {
        fota_source_report_update_customer_result(ret);
        abort_update(FOTA_STATUS_INSTALL_AUTH_NOT_GRANTED, "Failed to deliver install authorization");
    }
}

static int finalize_update(void)
{
    int ret;
    uint8_t calced_hash_buf[FOTA_CRYPTO_HASH_SIZE];
    fota_hash_context_t *calced_hash_ctx = fota_ctx->payload_hash_ctx;
    uint8_t *expected_digest = fota_ctx->fw_info->payload_digest;

#if !defined(FOTA_DISABLE_DELTA)
    // on delta, digest is calced on the install/unpatch data
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        calced_hash_ctx = fota_ctx->installed_hash_ctx;
        expected_digest = fota_ctx->fw_info->installed_digest;
    }
#endif

    // Ongoing resume state here means that all authentication has been done before.
    // Can jump straight to finish.
    if (fota_ctx->resume_state == FOTA_RESUME_STATE_ONGOING) {
        goto finished;
    }

    ret = fota_hash_result(calced_hash_ctx, calced_hash_buf);
    if (ret) {
        return ret;
    }

#if defined(MBED_CLOUD_CLIENT_FOTA_SIGNED_IMAGE_SUPPORT)
#if (MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT == 1)
    if (fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_RAW && fota_ctx->fw_info->payload_format != FOTA_MANIFEST_PAYLOAD_FORMAT_ENCRYPTED_COMBINED)
        // on encrypted payload, skip verifing signature as
        //  we can't calc the hash of the installed payload.
        //  It will be verified later by the bootloader.
#endif
    {
        ret = fota_verify_signature_prehashed(
                  calced_hash_buf,
                  fota_ctx->fw_info->installed_signature, FOTA_IMAGE_RAW_SIGNATURE_SIZE
              );
        FOTA_FI_SAFE_COND(
            (ret == FOTA_STATUS_SUCCESS),
            FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
            "Candidate image is not authentic"
        );
    }
#else
    // compare expected_digest against calced digest
    FOTA_FI_SAFE_MEMCMP(calced_hash_buf, expected_digest, FOTA_CRYPTO_HASH_SIZE,
                        FOTA_STATUS_MANIFEST_PAYLOAD_CORRUPTED,
                        "Downloaded FW hash does not match manifest hash");
#endif

finished:
#if !defined(FOTA_DISABLE_DELTA)
    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
        ret = fota_delta_finalize(&fota_ctx->delta_ctx);
        if (ret) {
            return ret;
        }
        fota_ctx->delta_ctx = 0;
    }
#endif

    FOTA_TRACE_INFO("Firmware download finished");

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)
    if (fota_ctx->mc_br_update) {
        // No need to authorize on BR mode, jump straight to installation
        fota_on_install_authorize(FOTA_INSTALL_STATE_AUTHORIZE);
        return FOTA_STATUS_SUCCESS;
    }
#endif

    fota_ctx->state = FOTA_STATE_AWAIT_INSTALL_AUTHORIZATION;

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    if (fota_ctx->mc_node_update) {
        // No need to report this state on node mode, as it was reported already. Jump straight to next state.
        on_approve_state_delivered();
        return FOTA_STATUS_SUCCESS;
    }
#endif

    fota_source_report_state(FOTA_SOURCE_STATE_AWAITING_APPLICATION_APPROVAL, on_approve_state_delivered, on_state_set_failure);

    return FOTA_STATUS_SUCCESS;

fail:
    abort_update(ret, "Failed on fragment event");
    return ret;

}

void fota_on_fragment_failure(int32_t status)
{
    FOTA_TRACE_ERROR("Failed to fetch fragment - %" PRId32, status);
    abort_update(FOTA_STATUS_DOWNLOAD_FRAGMENT_FAILED, "Failed to fetch fragment");
}

static inline int get_next_fragment()
{
#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)
    if (fota_ctx && fota_ctx->mc_node_update) {
        // In Multicast node mode, we already have the image fragments in storage.
        // Just call the function that reads them from there.
        // Do it in a deferred event, to avoid recursions and let the system breathe.
        fota_event_handler_defer_with_data(fota_multicast_node_on_fragment, NULL, 0);
        return FOTA_STATUS_SUCCESS;
    }
#endif

    return fota_download_request_next_fragment(fota_ctx->download_handle, fota_ctx->fw_info->uri, fota_ctx->payload_offset);
}

void fota_on_fragment(uint8_t *buf, size_t size)
{
    int ret = 0;
    bool last_fragment;

    // Silently ignore unexpected fragments (can be received prematurely as a result of retransmissions)
    // TODO: Check expected offset (requires API change here and in downloading engines)
    if (!fota_ctx || fota_ctx->state != FOTA_STATE_DOWNLOADING) {
        FOTA_TRACE_DEBUG("Unexpected fragment received - ignored");
        return;
    }

    uint32_t payload_bytes_left = fota_ctx->fw_info->payload_size - fota_ctx->payload_offset;

    //TODO: consider replacing with FOTA_DBG_ASSERT - as this should never happen
    if (size > payload_bytes_left) {
        abort_update(FOTA_STATUS_FW_SIZE_MISMATCH, "Got more bytes than expected");
        return;
    }

    handle_fota_app_on_download_progress(fota_ctx->payload_offset, size, fota_ctx->fw_info->payload_size);

    // update payload_hash_ctx with fragment
    ret = fota_hash_update(fota_ctx->payload_hash_ctx, buf, size);

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
#if !defined(FOTA_DISABLE_DELTA)
        bool finished = false;
        // This loop will have a single iteration in all cases except for the last payload fragment,
        // in which it'll have an additional iteration, where it will draw all firmware fragments
        // that come after the last delta payload fragment.
        do {
            uint32_t actual_frag_size;
            if (payload_bytes_left) {
                ret = fota_delta_new_payload_frag(fota_ctx->delta_ctx, buf, size);
                if (ret == FOTA_STATUS_FW_DELTA_REQUIRED_MORE_DATA) {
                    payload_bytes_left -= size;
                    break;
                }
            } else {
                ret = fota_delta_payload_finished(fota_ctx->delta_ctx);
                size = 0;
                finished = true;
            }
            if (ret) {
                goto fail;
            }
            do {
                ret = fota_delta_get_next_fw_frag(fota_ctx->delta_ctx,
                                                  fota_ctx->delta_buf,
                                                  MBED_CLOUD_CLIENT_FOTA_DELTA_BLOCK_SIZE,
                                                  &actual_frag_size);
                if (ret) {
                    goto fail;
                }
                if (actual_frag_size) {
                    last_fragment = ((fota_ctx->fw_bytes_written + fota_ctx->page_buf_offset + actual_frag_size) == fota_ctx->fw_info->installed_size);
                    // update installed_hash_ctx with delta_buf
                    ret = fota_hash_update(fota_ctx->installed_hash_ctx, fota_ctx->delta_buf, actual_frag_size);
                    if (ret) {
                        goto fail;
                    }
                    ret = handle_fw_fragment(fota_ctx->delta_buf, actual_frag_size, last_fragment);
                    if (ret) {
                        goto fail;
                    }
                }
            } while (actual_frag_size);
            payload_bytes_left -= size;
        } while (!payload_bytes_left && !finished);
#else
        // we should not get here. The error is reported from fota_on_manifest
        FOTA_ASSERT(0);
#endif  // #if !defined(FOTA_DISABLE_DELTA)
    } else {
        if (ret) {
            goto fail;
        }
        last_fragment = ((payload_bytes_left - size) == 0);
        ret = handle_fw_fragment(buf, size, last_fragment);
        if (ret) {
            goto fail;
        }
        payload_bytes_left -= size;
    }

    fota_ctx->payload_offset += size;

    clear_buffer_from_mem(buf, size);

    if (!payload_bytes_left) {
        ret = finalize_update();
        if (ret) {
            goto fail;
        }
        return;
    }

    ret = get_next_fragment();
    if (ret) {
        goto fail;
    }

    return;

fail:
    clear_buffer_from_mem(buf, size);
    abort_update(ret, "Failed on fragment event");
}


void fota_on_resume(fota_resume_reason_e resume_reason)
{
#if (MBED_CLOUD_CLIENT_FOTA_RESUME_SUPPORT != FOTA_RESUME_UNSUPPORTED)
    FOTA_TRACE_DEBUG("fota_on_resume");

    if (fota_ctx) {
        // We are in the middle of FOTA, defer wasn't called.
        // If we are here because of registration, it means there were
        // network errors.
        // The FOTA is aborted with TRANSIENT_FAILURE, i.e. the ctx is removed,
        // but the manifest isn't deleted.
        // The function continues to run and the FOTA resumes.
        if (resume_reason == FOTA_RESUME_REASON_REGISTRATION) {
            abort_update(FOTA_STATUS_TRANSIENT_FAILURE, "network errors during the FOTA");
        } else {
            FOTA_TRACE_DEBUG("FOTA already running");
            return;
        }
    }

    if (fota_install_state == FOTA_INSTALL_STATE_POSTPONE_REBOOT) {
        FOTA_TRACE_DEBUG("FOTA resume not supported after postpone");
        return;
    }

    FOTA_TRACE_INFO("fota_on_resume - resume reason %u", resume_reason);

    // If we got here, there is no FOTA context:
    // either defer was called or context was deleted because of internal error
    if ((fota_defer_by_user == true) && (resume_reason != FOTA_RESUME_REASON_USER_APP)) {
        /* fota was deferred by user app and resume was called from internal flow
         * ignore the resume  for now and wait for call from user app
         */
        FOTA_TRACE_INFO("Internal resume followed by user app defer - abort!");
        return; // don't resume now, wait for explicit user call for resume
    }

    size_t manifest_size;
    uint8_t *manifest = calloc(1, FOTA_MANIFEST_MAX_SIZE);

    if (!manifest) {
        FOTA_TRACE_ERROR("FOTA manifest - allocation failed");
        abort_update(FOTA_STATUS_OUT_OF_MEMORY, "fota_on_resume");
        return;
    }

    int ret = manifest_get(manifest, FOTA_MANIFEST_MAX_SIZE, &manifest_size);
    if (!ret) {
        FOTA_TRACE_INFO("Found manifest - resuming update");
        handle_manifest(manifest, manifest_size, /*is_resume*/ true, false);
    }

    free(manifest);

    if (ret == FOTA_STATUS_NOT_FOUND) {
        // silently ignore - no update to resume
        return;
    }
    if (ret) {
        FOTA_TRACE_ERROR("failed to load manifest from NVM (ret code %d) - update resume aborted.", ret);
    }
    fota_defer_by_user = false; //resume completed, remove the flag
#endif
}

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT != FOTA_MULTICAST_UNSUPPORTED)

// Local read from image API - support both Multicast node & BR modes
int fota_multicast_read_from_image(void *buffer, size_t offset, size_t size)
{
    int ret;
    size_t read_size, addr;

    ret = fota_bd_get_read_size(&read_size);
    if (ret) {
        return ret;
    }
    addr = mc_image_data_addr + offset;

    // Likely case - read is aligned in both start address and size (as read size is likely to be 1)
    if (!(addr % read_size) && !(size % read_size)) {
        return fota_bd_read(buffer, addr, size);
    }

    // Unlikely case, start or end not aligned to read size

    size_t chunk;
    uint8_t *buf = (uint8_t *) buffer;
    uint8_t *aligned_read_buf = (uint8_t *) malloc(read_size);
    if (!aligned_read_buf) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    // Handle unaligned start
    if (addr % read_size) {
        chunk = MIN(read_size - addr % read_size, size);
        ret = fota_bd_read(aligned_read_buf, FOTA_ALIGN_DOWN(addr, read_size), read_size);
        if (ret) {
            FOTA_TRACE_ERROR("Unable to get read size");
            goto end;
        }
        memcpy(buf, aligned_read_buf + addr % read_size, chunk);
        buf += chunk;
        addr += chunk;
        size -= chunk;
    }

    // Handle aligned portion
    chunk = FOTA_ALIGN_DOWN(size, read_size);
    if (chunk) {
        ret = fota_bd_read(buf, addr, chunk);
        if (ret) {
            goto end;
        }
        buf += chunk;
        addr += chunk;
        size -= chunk;
    }

    // Handle unaligned end
    if (size) {
        ret = fota_bd_read(aligned_read_buf, addr, read_size);
        if (ret) {
            goto end;
        }
        memcpy(buf, aligned_read_buf, size);
    }

end:
    free(aligned_read_buf);
    return ret;
}

#if (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_NODE_MODE)

static void fota_multicast_node_on_fragment(void *data, size_t size)
{
    (void)data; // unused param
    (void)size; // unused param

    int ret;
    FOTA_DBG_ASSERT(mc_node_frag_size);
    FOTA_DBG_ASSERT(fota_ctx);
    if (!fota_ctx->mc_node_frag_buf) {
        fota_ctx->mc_node_frag_buf = malloc(mc_node_frag_size);
        if (!fota_ctx->mc_node_frag_buf) {
            ret = FOTA_STATUS_OUT_OF_MEMORY;
            goto fail;
        }
    }
    size_t read_size = MIN(mc_node_frag_size, fota_ctx->fw_info->payload_size - fota_ctx->payload_offset);
    ret = fota_multicast_read_from_image(fota_ctx->mc_node_frag_buf, fota_ctx->payload_offset, read_size);
    if (ret) {
        FOTA_TRACE_ERROR("Unable to read from image");
        goto fail;
    }

    // Handle fragment with the one we read from storage
    fota_on_fragment(fota_ctx->mc_node_frag_buf, read_size);
    return;

fail:
    abort_update(ret, "Failed on multicast fragment event");
}

static int fota_multicast_node_check_update_status(bool require_mc_update)
{
    if (fota_ctx && !fota_ctx->mc_node_update) {
        FOTA_TRACE_DEBUG("FOTA multicast command ignored - Unicast update active");
        return FOTA_STATUS_RESOURCE_BUSY;
    }
    if (require_mc_update && !(fota_ctx && fota_ctx->mc_node_update)) {
        FOTA_TRACE_ERROR("FOTA multicast command ignored - Multicast update not active");
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_multicast_node_on_manifest(uint8_t *data, size_t size,
                                    fota_multicast_node_post_action_callback_t on_manifest_cb)
{
    FOTA_ASSERT(on_manifest_cb);
    FOTA_TRACE_DEBUG("Multicast manifest received");

    uint8_t manifest_hash[FOTA_CRYPTO_HASH_SIZE] = {0};
    int ret = fota_multicast_node_check_update_status(false);
    if (ret) {
        return ret;
    }

    fota_hash_context_t *manifest_hash_ctx;
    ret = fota_hash_start(&manifest_hash_ctx);
    if (ret) {
        return ret;
    }
    ret = fota_hash_update(manifest_hash_ctx, data, size);
    if (ret) {
        return ret;
    }
    ret = fota_hash_result(manifest_hash_ctx, manifest_hash);
    if (ret) {
        return ret;
    }
    fota_hash_finish(&manifest_hash_ctx);

    if (fota_ctx) {
        if (fota_ctx->mc_node_update_activated) {
            FOTA_TRACE_DEBUG("Current multicast update activated, can't override it");
            return FOTA_STATUS_MULTICAST_UPDATE_ACTIVATED;
        } else {
            if (memcmp(manifest_hash, fota_ctx->mc_node_manifest_hash, FOTA_CRYPTO_HASH_SIZE)) {
                FOTA_TRACE_DEBUG("Got a new multicast manifest, aborting previous FOTA session");
                fota_event_cancel(EVENT_RANDOM_DELAY);
                abort_update(FOTA_STATUS_MULTICAST_UPDATE_ABORTED_INTERNAL, "Multicast manifest overridden");
            } else {
                FOTA_TRACE_DEBUG("Same multicast manifest received, silently ignored");
                return FOTA_STATUS_SUCCESS;
            }
        }
    }
    ret = handle_manifest_init();
    if (ret) {
        return ret;
    }

    fota_ctx->mc_node_update = true;
    fota_ctx->mc_node_post_action_callback = on_manifest_cb;
    memcpy(fota_ctx->mc_node_manifest_hash, manifest_hash, FOTA_CRYPTO_HASH_SIZE);
#if !(MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER)
    report_state_random_delay(true);
#endif

    return handle_manifest(data, size, false, true);
}

int fota_multicast_node_on_image_ready(void)
{
    FOTA_TRACE_DEBUG("Multicast image ready");
    int ret = fota_multicast_node_check_update_status(false);
    if (ret) {
        return ret;
    }
    if (fota_ctx && fota_ctx->mc_node_update) {
        fota_ctx->state = FOTA_STATE_DOWNLOADING;
        // From service POV, image is already downloaded,so report application approval
        fota_source_report_state(FOTA_SOURCE_STATE_AWAITING_APPLICATION_APPROVAL, NULL, NULL);
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_multicast_node_on_activate(size_t activate_in_sec,
                                    fota_multicast_node_post_action_callback_t activate_finish_cb)
{
    FOTA_TRACE_DEBUG("Multicast activation in %ld seconds", activate_in_sec);
    int ret = fota_multicast_node_check_update_status(true);
    if (ret) {
        return ret;
    }
    if (fota_ctx && fota_ctx->mc_node_update_activated) {
        FOTA_TRACE_ERROR("Multicast FOTA already activated, activate command ignored");
        return FOTA_STATUS_MULTICAST_UPDATE_ACTIVATED;
    }

    fota_ctx->mc_node_update_activated = true;
    fota_ctx->mc_node_post_action_callback = activate_finish_cb;
    fota_ctx->activate_in_sec = activate_in_sec;

    fota_event_handler_defer_with_data(fota_multicast_node_on_fragment, NULL, 0);

    return FOTA_STATUS_SUCCESS;
}

int fota_multicast_node_on_abort(void)
{
    FOTA_TRACE_DEBUG("Multicast abort requested");
    int ret = fota_multicast_node_check_update_status(true);
    if (ret) {
        return ret;
    }
    if (fota_ctx) {
        if (fota_ctx->mc_node_update_activated) {
            FOTA_TRACE_DEBUG("Current multicast update activated, can't abort");
            return FOTA_STATUS_MULTICAST_UPDATE_ACTIVATED;
        } else {
            abort_update(FOTA_STATUS_MULTICAST_UPDATE_ABORTED, "Multicast abort requested");
        }
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_multicast_node_get_ready_for_image(size_t image_size)
{
    FOTA_TRACE_DEBUG("Multicast - get ready for a new image");
    int ret = fota_multicast_node_check_update_status(false);
    if (ret) {
        return ret;
    }

    // TODO: Is this logic correct?
    if (fota_ctx) {
        if (fota_ctx->mc_node_update_activated) {
            FOTA_TRACE_DEBUG("Current multicast update activated, can't override it");
            return FOTA_STATUS_MULTICAST_UPDATE_ACTIVATED;
        } else {
            if (mc_node_new_image) {
                FOTA_TRACE_INFO("Multicast - get ready for a new image again - silently ignored");
            }
        }
    }

    // Just mark image as new, but don't erase yet, as we don't know location and size yet
    mc_node_new_image = true;
    mc_node_image_size = image_size;

    return FOTA_STATUS_SUCCESS;
}

int fota_multicast_node_write_image_fragment(const void *buffer, size_t offset, size_t size)
{
    int ret = fota_multicast_node_check_update_status(false);
    if (ret) {
        return ret;
    }
    if (!mc_node_frag_size) {
        FOTA_TRACE_ERROR("FOTA multicast command ignored - fragment size not set");
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    if (offset % mc_node_frag_size) {
        FOTA_TRACE_ERROR("FOTA multicast node - attempted to write to storage with an invalid offset");
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    if (mc_node_new_image) {
        // Got here with new image flag still set. This means that no manifest was received,
        // so this is a non FOTA image. Erase storage now.
        ret = calc_and_erase_needed_storage();
        if (ret) {
            return ret;
        }
    }

    size_t prog_size, addr;

    ret = fota_bd_get_program_size(&prog_size);
    if (ret) {
        FOTA_TRACE_ERROR("Unable to get program size");
        return ret;
    }
    addr = mc_image_data_addr + offset;

    // Likely case - size is aligned to program size (true in all but last fragment perhaps)
    if (!(size % prog_size)) {
        return fota_bd_program(buffer, addr, size);
    }

    // Less likely case, end not aligned to program size (start must be)

    size_t chunk;
    uint8_t *buf = (uint8_t *) buffer;
    uint8_t *aligned_prog_buf = (uint8_t *) malloc(prog_size);
    if (!aligned_prog_buf) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    // Handle aligned portion
    chunk = FOTA_ALIGN_DOWN(size, prog_size);
    if (chunk) {
        ret = fota_bd_program(buf, addr, chunk);
        if (ret) {
            goto end;
        }
        buf += chunk;
        addr += chunk;
        size -= chunk;
    }

    // Handle unaligned end
    memcpy(aligned_prog_buf, buf, size);
    memset(aligned_prog_buf + size, 0, prog_size - size);
    ret = fota_bd_program(aligned_prog_buf, addr, prog_size);

end:
    free(aligned_prog_buf);
    return ret;
}

int fota_multicast_node_read_image_fragment(void *buffer, size_t offset, size_t size)
{
    int ret = fota_multicast_node_check_update_status(false);
    if (ret) {
        return ret;
    }
    return fota_multicast_read_from_image(buffer, offset, size);
}

int fota_multicast_node_set_fragment_size(size_t frag_size)
{
    size_t prog_size;
    FOTA_TRACE_DEBUG("Multicast - set fragment size to %ld", frag_size);

    int ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("Failed to initialize block device");
        return ret;
    }

    ret = fota_bd_get_program_size(&prog_size);
    if (ret) {
        FOTA_TRACE_ERROR("FOTA multicast set fragment size - unable to get BD program size");
        return ret;
    }
    if (frag_size % prog_size) {
        FOTA_TRACE_ERROR("FOTA multicast set fragment size - rejected");
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    ret = calc_available_storage();
    if (ret) {
        return ret;
    }

    mc_node_frag_size = frag_size;
    return FOTA_STATUS_SUCCESS;
}

#if MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER

// Those APIs are envelopes to the multicast node ones
static void ext_downloader_manifest_post_action_cb(int ret)
{
}

static void ext_downloader_activate_post_action_cb(int ret)
{
}

int fota_ext_downloader_write_image_fragment(const void *buffer, size_t offset, size_t size)
{
    return fota_multicast_node_write_image_fragment(buffer, offset, size);
}

int fota_ext_downloader_on_image_ready(void)
{
    int ret = fota_multicast_node_on_image_ready();
    if (ret) {
        return ret;
    }
    return fota_multicast_node_on_activate(0, ext_downloader_activate_post_action_cb);
}

#endif // MBED_CLOUD_CLIENT_FOTA_EXTERNAL_DOWNLOADER

#elif (MBED_CLOUD_CLIENT_FOTA_MULTICAST_SUPPORT == FOTA_MULTICAST_BR_MODE)

#if !(defined(TARGET_LIKE_LINUX))
static int multicast_br_candidate_install_handler(const char* comp_name, const char *sub_comp_name, fota_comp_candidate_iterate_callback_info *info, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx)
{
    // Nothing to do - candidate already here
    return FOTA_STATUS_SUCCESS;
}
#endif

int multicast_br_post_install_handler(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx)
{
    // Actual image data starts right after FW header
    mc_image_data_addr = fota_ctx->fw_header_bd_size + fota_ctx->fw_header_offset;
    FOTA_DBG_ASSERT(fota_ctx->mc_br_post_action_callback);
    fota_ctx->mc_br_post_action_callback(FOTA_STATUS_SUCCESS);
    return FOTA_STATUS_SUCCESS;
}

int fota_multicast_br_on_image_request(const fota_multicast_br_image_params *image_params,
                                       fota_multicast_br_post_action_callback_t image_ready_cb)
{
    int ret;
    FOTA_ASSERT(image_ready_cb);

    fota_header_info_t header_info;
    ret = fota_curr_fw_read_header(&header_info);
    FOTA_ASSERT(!ret);

    if (fota_ctx) {
        ret = FOTA_STATUS_RESOURCE_BUSY;
        goto fail;
    }

    ret = handle_manifest_init();
    if (ret) {
        goto fail;
    }

    // Masquerade this as a manifest now
    memset(fota_ctx->fw_info, 0, sizeof(manifest_firmware_info_t));
    fota_ctx->fw_info->payload_format = FOTA_MANIFEST_PAYLOAD_FORMAT_RAW;
    fota_ctx->fw_info->payload_size = image_params->payload_size;
    fota_ctx->fw_info->installed_size = image_params->payload_size;
    memcpy(fota_ctx->fw_info->payload_digest, image_params->payload_digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(fota_ctx->fw_info->installed_digest, image_params->payload_digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(fota_ctx->fw_info->precursor_digest, header_info.digest, FOTA_CRYPTO_HASH_SIZE);
    memcpy(fota_ctx->fw_info->uri, image_params->uri, FOTA_MANIFEST_URI_SIZE);
    strcpy(fota_ctx->fw_info->component_name, FOTA_MULTICAST_BR_INT_COMP_NAME);

    ret = fota_component_name_to_id(FOTA_MULTICAST_BR_INT_COMP_NAME, &fota_ctx->comp_id);
    FOTA_DBG_ASSERT(!ret);
    fota_ctx->mc_br_update = true;
    fota_ctx->mc_br_post_action_callback = image_ready_cb;

    // This is not a real update - don't report states to service
    fota_source_enable_auto_observable_resources_reporting(false);

    // Jump right to download authorize state (no need for download authorization)
    fota_on_download_authorize();

    return FOTA_STATUS_SUCCESS;

fail:
    abort_update(ret, "Multicast BR image request aborted");
    return ret;
}

int fota_multicast_br_read_from_image(void *buffer, size_t offset, size_t size)
{
    return fota_multicast_read_from_image(buffer, offset, size);
}

#endif // FOTA_MULTICAST_BR_MODE
#endif // != FOTA_MULTICAST_UNSUPPORTED

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
