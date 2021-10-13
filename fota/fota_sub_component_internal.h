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

#ifndef __FOTA_SUB_COMPONENT_INTERNAL_H_
#define __FOTA_SUB_COMPONENT_INTERNAL_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)

#include "fota/fota_sub_component.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *sub_comp_name; // sub_component_name
    void *cb_function;   // pointer to call back
} fota_cb_data_t;

typedef struct {
    char sub_comp_name[FOTA_MAX_NUM_OF_SUB_COMPONENTS][FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE];
    size_t num_of_sub_comps;
    fota_cb_data_t install_order[FOTA_MAX_NUM_OF_SUB_COMPONENTS];
    fota_cb_data_t verify_order[FOTA_MAX_NUM_OF_SUB_COMPONENTS];
    fota_cb_data_t rollback_order[FOTA_MAX_NUM_OF_SUB_COMPONENTS];
    fota_cb_data_t finalize_order[FOTA_MAX_NUM_OF_SUB_COMPONENTS];
} fota_sub_comp_table_t;


typedef struct {
    char comp_name[FOTA_COMPONENT_MAX_NAME_SIZE];
    fota_sub_comp_table_t sub_comp_table;
} fota_comp_table_t;

void fota_sub_component_clean(void);
int fota_sub_component_validate_package_images(const char *comp_name, const package_descriptor_t *descriptor_info);
int fota_sub_component_install(const char *comp_name, package_descriptor_t *descriptor_info);
int fota_sub_component_finalize(const char *comp_name, package_descriptor_t *descriptor_info, fota_status_e status);
int fota_sub_component_rollback(const char *comp_name, package_descriptor_t *descriptor_info);
int fota_sub_component_verify(const char *comp_name, package_descriptor_t *descriptor_info);
int fota_sub_component_get_table(fota_comp_table_t *comp_table, size_t comp_table_size);

#ifdef __cplusplus
}
#endif

#endif //(MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_SUB_COMPONENT_INTERNAL_H_
