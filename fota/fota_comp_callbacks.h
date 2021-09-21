// ----------------------------------------------------------------------------
// Copyright 2021 Pelion Ltd.
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

#ifndef __FOTA_COMP_CALLBACKS_H_
#define __FOTA_COMP_CALLBACKS_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_component_defs.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_header_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Candidate iterate status
 *
 * This status code is passed to user supplied fota_candidate_iterate_handler_t callback function.
 */
typedef enum {
    FOTA_CANDIDATE_ITERATE_START,  /**< sent once on candidate iteration start event */
    FOTA_CANDIDATE_ITERATE_FRAGMENT, /**< sent multiple times - once per extracted candidate fragment */
    FOTA_CANDIDATE_ITERATE_FINISH,  /**< sent once on candidate iteration finish event */
} fota_candidate_iterate_status;

/**
 * Component candidate iterate callback info
 *
 * @param status Iterate status.
 * @param frag_size Fragment size.
 * @param frag_pos Fragment position.
 * @param frag_buf Fragment buffer.
 * @param user_ctx User data, which lives between the calls to the callbacks.
 */
typedef struct {
    fota_candidate_iterate_status status;
    size_t frag_size;
    size_t frag_pos;
    uint8_t  *frag_buf;
    void *user_ctx;
} fota_comp_candidate_iterate_callback_info;

#if defined(TARGET_LIKE_LINUX)
/**
 *
 * Pelion FOTA install callback for components, to be implemented by the device application to install a component.
 * Invoked by Pelion FOTA after the device application authorizes installation.
 *
 * \param[in] comp_name Name of the component that refers to the current subcomponent. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
 * \param[in] sub_comp_name Name of the subcomponent to be installed. Max sub_comp_name size defined by ::FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE. The same name that was specified as an argument to ::fota_sub_component_add().
 * \param[in] file_name File name of the subcomponent to be installed.
 * \param[in] vendor_data Vendor data of the installed subcomponent.
 * \param[in] vendor_data_size Vendor data size of the installed subcomponent. Max data vendor size defined by ::FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE.
 * \param[in] app_ctx Application context, application info required in callback. Not in use yet.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
typedef int(*fota_comp_install_cb_t)(const char *comp_name, const char *sub_comp_name, const char *file_name, const uint8_t *vendor_data, size_t vendor_data_size, void *app_ctx);
#else
/**
 *
 * Pelion FOTA install callback for components, to be implemented by the device application to install a component.
 * Invoked by Pelion FOTA after the device application authorizes installation.
 *
 * \param[in] comp_name Name of the component that refers to the current subcomponent. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
 * \param[in] sub_comp_name Name of the subcomponent to be installed. Max sub_comp_name size defined by ::FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE. The same name that was specified as an argument to ::fota_sub_component_add().
 * \param[in] info Component iterate callback info.
 * \param[in] vendor_data Vendor data of the installed subcomponent.
 * \param[in] vendor_data_size Vendor data size of the installed subcomponent. Max data vendor size defined by ::FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE.
 * \param[in] app_ctx Application context, application info required in callback. Not in use yet.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
typedef int (*fota_comp_install_cb_t)(const char* comp_name, const char *sub_comp_name, fota_comp_candidate_iterate_callback_info *info, const uint8_t *vendor_data, size_t vendor_data_size, void* app_ctx);
#endif

/**
 * Deprecated callback. New customers should use `fota_comp_verify_cb_t`instead.
 * A callback function to verify component installation success.
 * Executed after component installation.
 *
 * \param[in] component_name Name of the installed component. The same name that was specified as an argument to ::fota_component_add().
 * \param[in] expected_header_info Header with expected values for installed components.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
fota_deprecated typedef int (*fota_component_verify_install_handler_t)(const char *comp_name, const fota_header_info_t *expected_header_info);

/**
 * Pelion FOTA verify callback for components, to be implemented by the device application to verify an installed comp onent.
 * Invoked by Pelion FOTA after component installation.
 *
 * \param[in] comp_name Name of the component that refers to the current subcomponent. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
 * \param[in] sub_comp_name Name of the subcomponent. Max sub_comp_name size defined by ::FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE. The same name that was specified as an argument to ::fota_sub_component_add().
 * \param[in] vendor_data Vendor data of the subcomponent.
 * \param[in] vendor_data_size Vendor data size of the subcomponent. Max data vendor size defined by ::FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE.
 * \param[in] app_ctx Application context, application info required in callback. Not in use yet.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
typedef int(*fota_comp_verify_cb_t)(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, void *app_ctx);

/**
 * Pelion FOTA finalize callback for component, to be implemented by the device application to finalize the installation of a component.
 * Invoked by Pelion FOTA to perform finalization actions after a combined update is finished.
 *
 * \param[in] comp_name Name of the component that refers to the current subcomponent. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
 * \param[in] sub_comp_name Name of the subcomponent. Max sub_comp_name size defined by ::FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE. The same name that was specified as an argument to ::fota_sub_component_add().
 * \param[in] vendor_data Vendor data of the subcomponent.
 * \param[in] vendor_data_size Vendor data size of the subcomponent. Max data vendor size defined by ::FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE.
 * \param[in] fota_status  Fota update status ::fota_status_e.
 * \param[in] app_ctx Application context, application info required in callback. Not in use yet.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
typedef int(*fota_comp_finalize_cb_t)(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, fota_status_e fota_status, void *app_ctx);

#ifdef __cplusplus
}
#endif

#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_COMP_CALLBACKS_H_
