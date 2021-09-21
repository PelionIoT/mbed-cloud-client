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

#ifndef __FOTA_SUB_COMPONENT_H_
#define __FOTA_SUB_COMPONENT_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)

#include "fota/fota_crypto_defs.h"
#include "fota/fota_component.h"
#include "fota/fota_combined_package.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
**
* Pelion FOTA rollback callback for subcomponents to be implemented by the device application to roll back an installed subcomponent.
* Invoked by Pelion FOTA after subcomponent installation or verification failure.
*
* \param[in] comp_name Name of the component that refers to the current subcomponent. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
* \param[in] sub_comp_name Name of the subcomponent. Max sub_comp_name size defined by ::FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE. The same name that was specified as an argument to ::fota_sub_component_add().
* \param[in] vendor_data Vendor data of the subcomponent.
* \param[in] vendor_data_size Vendor data size of the subcomponent. Max data vendor size defined by ::FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE.
* \param[in] app_ctx Application context, application info required in callback. Not avalible after reboot. Not in use yet.
*
* \return ::FOTA_STATUS_SUCCESS on success.
*/
typedef int(*fota_sub_comp_rollback_cb_t)(const char *comp_name, const char *sub_comp_name, const uint8_t *vendor_data, size_t vendor_data_size, void *app_ctx);

/**
* Subcomponent description information.
*
* @param install_cb An installation function for the subcomponent installation.
* @param rollback_cb A rollback function for the subcomponent rollback.
* @param verify_cb A verify function for the subcomponent install verification.
* @param finalize_cb A finalize function for the subcomponent finalization. The function is optional, can be NULL.
* @param install_order Installation order of the subcomponent. The order is relative to another subcomponents. The possible values are from 1 up to the number of subcomponents.
* @param rollback_order Rollback order of the subcomponent.
* @param verify_order Verify order of the subcomponent.
* @param finalize_order Finalize order of the subcomponent.
*/
typedef struct {
    fota_comp_install_cb_t install_cb;
    fota_sub_comp_rollback_cb_t rollback_cb;
    fota_comp_verify_cb_t verify_cb;
    fota_comp_finalize_cb_t finalize_cb;
    unsigned int install_order;
    unsigned int rollback_order;
    unsigned int verify_order;
    unsigned int finalize_order;
} fota_sub_comp_info_t;

/**
* Subcomponent registration.
* Adds the subcomponent and its component to the subcomponent database.
* Each subcomponent belongs to a specific component. A component can contain up to ::FOTA_MAX_NUM_OF_SUB_COMPONENTS subcomponents.
* The function should be called from the ::fota_platform_init_hook() function.
*
*
* \param[in] comp_name A string value representing the component name that refers to the current subcomponent. Maximum length is ::FOTA_COMPONENT_MAX_NAME_SIZE including NULL termination. Must not start with "%".
* \param[in] sub_comp_name A string value representing the subcomponent name to add. Maximum length is ::FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE including NULL termination. Must not start with "%".
* \param[in] info Subcomponent description with required information. This should reside in the stack to prevent unnecessary allocations and memory copies.
*
* \return ::FOTA_STATUS_SUCCESS on success.
*/
int fota_sub_component_add(const char *comp_name, const char *sub_comp_name, const fota_sub_comp_info_t *info);

#ifdef __cplusplus
}
#endif
#endif // (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_SUB_COMPONENT_H_
