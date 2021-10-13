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

#include "fota/fota_base.h"
#include "fota/fota_source.h"
#include <stdlib.h>

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#include "fota/fota_sub_component.h"
#include "fota/fota_sub_component_internal.h"

#if defined(TARGET_LIKE_LINUX)
#include "fota/platform/linux/fota_platform_linux.h"
#endif

static unsigned int g_num_components = 0;  // Component counter
static fota_comp_table_t g_comp_table[FOTA_NUM_COMPONENTS]; // Component table

static bool is_sub_comp_registered(fota_sub_comp_table_t *sub_comp_table, int num_of_sub_component, const char *sub_comp_name)
{
    int res = 0;

    for (int sub_comp_index = 0; sub_comp_index < num_of_sub_component; sub_comp_index++) {
        res = strcmp(sub_comp_name, sub_comp_table->sub_comp_name[sub_comp_index]);
        if (res == 0) {
            return true;
        }
    }
    return false;
}

int fota_sub_component_get_table(fota_comp_table_t *comp_table, size_t comp_table_size)
{
    int res = 0 ;

    if(comp_table_size < sizeof(g_comp_table)){
        return FOTA_STATUS_INVALID_ARGUMENT;
    }
    //Copy table
    memcpy( comp_table, g_comp_table, sizeof(g_comp_table));

    return FOTA_STATUS_SUCCESS; 
}

void fota_sub_component_clean(void)
{
    for (int comp_index = 0; comp_index < FOTA_NUM_COMPONENTS; comp_index++) {
        memset(&g_comp_table[comp_index], 0, sizeof(fota_comp_table_t));
    }
    g_num_components = 0;
}

static int set_sub_component_callback_table_data(fota_cb_data_t *callback_data,
                                                 const char *sub_comp_name,
                                                 void *callback_pointer)
{
    if (callback_data->cb_function != NULL) {
        FOTA_TRACE_ERROR("Installation ordering number assigned to the current callback is already in use");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }
    callback_data->cb_function = callback_pointer;
    callback_data->sub_comp_name = (char *)sub_comp_name; // Pointer of the subcomponent name from the subcomponent table

    return FOTA_STATUS_SUCCESS;
}

static int fota_sub_component_get_existing_comp_index(const char *comp_name, int *comp_table_index)
{
    int res = 0;
    int comp_index = 0;

    for (comp_index = 0; comp_index < g_num_components; comp_index++) {
        res = strcmp(g_comp_table[comp_index].comp_name, comp_name);
        if (!res) {
            *comp_table_index = comp_index;
            return FOTA_STATUS_SUCCESS;
        }
    }

    return FOTA_STATUS_INVALID_ARGUMENT;
}

static int fota_sub_component_get_next_comp_index(const char *comp_name, int *comp_table_index)
{
    int res = 0;
    int comp_index = 0;

    for (comp_index = 0; comp_index < g_num_components; comp_index++) {
        res = strcmp(g_comp_table[comp_index].comp_name, comp_name);
        if (!res) {
            *comp_table_index = comp_index;
            return FOTA_STATUS_SUCCESS;
        }
    }

    if (comp_index < FOTA_NUM_COMPONENTS) {
        *comp_table_index = comp_index;
        g_num_components++;
        return FOTA_STATUS_SUCCESS;
    } else {
        FOTA_TRACE_ERROR("Component table is full");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }
}

int fota_sub_component_add(const char *comp_name, const char *sub_comp_name, const fota_sub_comp_info_t *info)
{
    bool is_sub_comp_name_exists = false;
    int ret = 0;
    int comp_index = 0;
    fota_sub_comp_table_t *sub_comp_table = NULL;
    int sub_comp_index = 0;
    fota_cb_data_t *callback_data = NULL;

    FOTA_ASSERT(info);
    FOTA_ASSERT(sub_comp_name);
    FOTA_ASSERT(comp_name);

    // Check params
    // Check component name
    if (strnlen(comp_name, FOTA_COMPONENT_MAX_NAME_SIZE) > FOTA_COMPONENT_MAX_NAME_SIZE - 1) {
        FOTA_TRACE_ERROR("Component name too long");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // Check subcomponent name
    if (strnlen(sub_comp_name, FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE) > FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE - 1) {
        FOTA_TRACE_ERROR("Subcomponent name too long");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // Check info values
    if (info->install_order > FOTA_MAX_NUM_OF_SUB_COMPONENTS || info->install_order == 0 ||
            info->verify_order > FOTA_MAX_NUM_OF_SUB_COMPONENTS || info->verify_order == 0 ||
            info->finalize_order > FOTA_MAX_NUM_OF_SUB_COMPONENTS || info->finalize_order == 0 ||
            info->rollback_order > FOTA_MAX_NUM_OF_SUB_COMPONENTS || info->rollback_order == 0) {
        FOTA_TRACE_ERROR("Installation order of one of the callbacks is invalid (should be between 1 and %d)", FOTA_MAX_NUM_OF_SUB_COMPONENTS);
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // If component exists in the table, return its index; otherwise, return next free index
    ret = fota_sub_component_get_next_comp_index(comp_name, &comp_index);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to get component index");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // Set pointer of current subcomponent table
    sub_comp_table = &(g_comp_table[comp_index].sub_comp_table);

    // Set subcomponent number
    sub_comp_index = sub_comp_table->num_of_sub_comps;

    // Check number of existing subcomponents in current subcomponent table
    if (sub_comp_index == FOTA_MAX_NUM_OF_SUB_COMPONENTS) {
        FOTA_TRACE_ERROR("Number of subcomponents reached max value %d", FOTA_MAX_NUM_OF_SUB_COMPONENTS);
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // Check registration status of current subcomponent
    is_sub_comp_name_exists = is_sub_comp_registered(sub_comp_table, sub_comp_index, sub_comp_name);
    if (is_sub_comp_name_exists == true) {
        FOTA_TRACE_ERROR("Current subcomponent already registered");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // Set component name to the component table in the current component index
    strncpy(g_comp_table[comp_index].comp_name, comp_name, FOTA_COMPONENT_MAX_NAME_SIZE - 1);

    // Set subcomponent name to the subcomponent table  in the current subcomponent index
    strncpy(sub_comp_table->sub_comp_name[sub_comp_index], sub_comp_name, FOTA_COMPONENT_MAX_NAME_SIZE - 1);

    // Set callback order info
    // Set install callback order data
    FOTA_ASSERT(info->install_cb);
    callback_data = &(sub_comp_table->install_order[info->install_order - 1]);
    ret = set_sub_component_callback_table_data(callback_data, sub_comp_table->sub_comp_name[sub_comp_index], info->install_cb);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to set install data array");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    //Set verify callback order data
    FOTA_ASSERT(info->verify_cb);
    callback_data = &(sub_comp_table->verify_order[info->verify_order - 1]);
    ret = set_sub_component_callback_table_data(callback_data, sub_comp_table->sub_comp_name[sub_comp_index], info->verify_cb);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to set verify data array");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    //Set rollback callback order data
    FOTA_ASSERT(info->rollback_cb);
    callback_data = &(sub_comp_table->rollback_order[info->rollback_order - 1]);
    ret = set_sub_component_callback_table_data(callback_data, sub_comp_table->sub_comp_name[sub_comp_index], info->rollback_cb);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to set rollback data array");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    //Set finalize callback order data
    callback_data = &(sub_comp_table->finalize_order[info->finalize_order - 1]);
    ret = set_sub_component_callback_table_data(callback_data, sub_comp_table->sub_comp_name[sub_comp_index], info->finalize_cb);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to set finalize data array");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    //Update number of subcomponents for current component index
    sub_comp_table->num_of_sub_comps++;
    return FOTA_STATUS_SUCCESS;
}

int fota_sub_component_validate_package_images(const char *comp_name, const package_descriptor_t *descriptor_info)
{
    unsigned int desc_num_components = 0;
    char *descriptor_image_id;
    image_descriptor_t *img_descriptor = NULL;
    int comp_index = 0;
    fota_sub_comp_table_t *sub_comp_table = NULL;
    int ret = 0;

    FOTA_ASSERT(descriptor_info);
    desc_num_components = (unsigned int)descriptor_info->num_of_images;
    img_descriptor = descriptor_info->image_descriptors_array;

    ret = fota_sub_component_get_existing_comp_index(comp_name, &comp_index);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to get component info for %s ", comp_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    sub_comp_table = &(g_comp_table[comp_index].sub_comp_table);

    //Check number of subcomponents
    if (desc_num_components != sub_comp_table->num_of_sub_comps) {
        FOTA_TRACE_ERROR("Numbers of package images and registered subcomponents are different");
        return FOTA_STATUS_INVALID_ARGUMENT;
    }

    // During the subcomponent registration, we already checked that each name in the table is unique
    // Check that subcomponent names and descriptor info names correspond
    for (int index = 0; index < desc_num_components; index++) {
        descriptor_image_id = img_descriptor->image_id;
        if (!is_sub_comp_registered(sub_comp_table, sub_comp_table->num_of_sub_comps, (const char *)descriptor_image_id)) {
            FOTA_TRACE_ERROR("Names of descriptor package and subcomponents do not correspond");
            return FOTA_STATUS_INVALID_ARGUMENT;
        }
        img_descriptor++;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_sub_component_install(const char *comp_name, package_descriptor_t *descriptor_info)
{
    char *sub_component_name = NULL;
    fota_comp_install_cb_t install_cb;
    int ret = FOTA_STATUS_INTERNAL_ERROR;

    image_descriptor_t *image_descriptor = NULL;
    int comp_index = 0;
    fota_sub_comp_table_t *sub_comp_table = NULL;
    char *file_name = NULL;

    ret = fota_sub_component_get_existing_comp_index(comp_name, &comp_index);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to get component info for %s ", comp_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    sub_comp_table = &(g_comp_table[comp_index].sub_comp_table);

    // Go over subcomponent installer order array and call the installer for each image based on its order
    for (int sub_comp_index = 0; sub_comp_index < sub_comp_table->num_of_sub_comps; sub_comp_index++) {

        // Get the name of the subcomponent
        sub_component_name = sub_comp_table->install_order[sub_comp_index].sub_comp_name;

        // Get image descriptor of current subcomponent
        image_descriptor = fota_combined_package_get_descriptor(sub_component_name, descriptor_info);
        if (!image_descriptor) {
            FOTA_TRACE_ERROR("Failed to get subcomponent info for %s ", sub_component_name);
            goto end;
        }

        // Get installer callback pointer
        install_cb = sub_comp_table->install_order[sub_comp_index].cb_function;

        // Check install_cb
        if (!install_cb) {
            FOTA_TRACE_ERROR("Install callback is NULL");
            goto end;
        }

#if defined(TARGET_LIKE_LINUX)
        file_name = malloc(strlen(fota_linux_get_package_dir_name()) + strlen(sub_component_name) + 2);
        if (!file_name) {
            FOTA_TRACE_ERROR("Couldn't allocate file name");
            goto end;
        }
        sprintf(file_name, "%s/%s", fota_linux_get_package_dir_name(), sub_component_name);
#endif
        //Call installer callback
        ret = install_cb(comp_name, sub_component_name, file_name, image_descriptor->vendor_data, image_descriptor->vendor_data_size, NULL);
        if (ret) {
            FOTA_TRACE_ERROR("Failed to install current subcomponent %s ", sub_component_name);
            fota_source_report_update_customer_result(ret);
            ret = FOTA_STATUS_INTERNAL_ERROR;
            goto end;
        }
    }
    ret = FOTA_STATUS_SUCCESS;

end:
    free(file_name);
    if (ret) {
        fota_sub_component_rollback(comp_name, descriptor_info);
        fota_sub_component_finalize(comp_name, descriptor_info, FOTA_STATUS_FW_INSTALLATION_FAILED);// Finalize error ignored, the original error ret will be reported.
    }
    return ret;
}

int fota_sub_component_finalize(const char *comp_name, package_descriptor_t *descriptor_info, fota_status_e status)
{
    char *sub_component_name = NULL;
    fota_comp_finalize_cb_t finalize_cb;
    bool finished_with_errors = false;
    int ret = 0;
    image_descriptor_t *image_descriptor = NULL;
    int comp_index = 0;
    fota_sub_comp_table_t *sub_comp_table = NULL;


    ret = fota_sub_component_get_existing_comp_index(comp_name, &comp_index);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to get component info for %s ", comp_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    sub_comp_table = &(g_comp_table[comp_index].sub_comp_table);

    // Go over subcomponent finalize order array and call the installer for each image
    for (int sub_comp_index = 0; sub_comp_index < sub_comp_table->num_of_sub_comps; sub_comp_index++) {
        // Get the name of the subcomponent
        sub_component_name = sub_comp_table->finalize_order[sub_comp_index].sub_comp_name;

        // Get image descriptor of current subcomponent
        image_descriptor = fota_combined_package_get_descriptor(sub_component_name, descriptor_info);
        if (!image_descriptor) {
            FOTA_TRACE_ERROR("Failed to get subcomponent info for %s ", sub_component_name);
            finished_with_errors = true;
            continue;
        }

        // Get finalize callback pointer
        finalize_cb = sub_comp_table->finalize_order[sub_comp_index].cb_function;

        if (finalize_cb != NULL) {
            //Call finalize callback
            ret = finalize_cb(comp_name, sub_component_name, image_descriptor->vendor_data, image_descriptor->vendor_data_size, status, NULL);
            if (ret) {
                FOTA_TRACE_ERROR("Failed to finalize current subcomponent %s ", sub_component_name);
                fota_source_report_update_customer_result(ret);
                finished_with_errors = true;
            }
        }// finalize_cb != NULL
    }// for loop

    if (finished_with_errors) {
        return FOTA_STATUS_INTERNAL_ERROR;
    } else {
        return FOTA_STATUS_SUCCESS;
    }
}

int fota_sub_component_rollback(const char *comp_name, package_descriptor_t *descriptor_info)
{
    char *sub_component_name = NULL;
    fota_sub_comp_rollback_cb_t rollback_cb;
    int ret = 0;
    image_descriptor_t *image_descriptor = NULL;
    int comp_index = 0;
    fota_sub_comp_table_t *sub_comp_table = NULL;

    ret = fota_sub_component_get_existing_comp_index(comp_name, &comp_index);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to get component info for %s ", comp_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    sub_comp_table = &(g_comp_table[comp_index].sub_comp_table);

    // Go over subcomponent rollback order array and call the rollback for each image
    for (int sub_comp_index = 0; sub_comp_index < sub_comp_table->num_of_sub_comps; sub_comp_index++) {
        // Get the name of the subcomponent
        sub_component_name = sub_comp_table->rollback_order[sub_comp_index].sub_comp_name;

        // Get image descriptor of current subcomponent
        image_descriptor = fota_combined_package_get_descriptor(sub_component_name, descriptor_info);
        if (!image_descriptor) {
            FOTA_TRACE_ERROR("Failed to get subcomponent info for %s ", sub_component_name);
            return FOTA_STATUS_INTERNAL_ERROR;
        }

        // Get rollback callback pointer
        rollback_cb = sub_comp_table->rollback_order[sub_comp_index].cb_function;

        //Check rollback_cb
        if (!rollback_cb) {
            FOTA_TRACE_ERROR("Rollback callback is NULL");
            return FOTA_STATUS_INTERNAL_ERROR;
        };

        //Call rollback callback
        ret = rollback_cb(comp_name, sub_component_name, image_descriptor->vendor_data, image_descriptor->vendor_data_size, NULL);
        if (ret) {
            FOTA_TRACE_ERROR("Failed to roll back current subcomponent %s ", sub_component_name);
            fota_source_report_update_customer_result(ret);
            return FOTA_STATUS_INTERNAL_ERROR;
        }
    }

    return ret;
}

int fota_sub_component_verify(const char *comp_name, package_descriptor_t *descriptor_info)
{
    char *sub_component_name = NULL;
    fota_comp_verify_cb_t verify_cb;
    int ret = 0;
    image_descriptor_t *image_descriptor = NULL;
    int comp_index = 0;
    fota_sub_comp_table_t *sub_comp_table = NULL;


    ret = fota_sub_component_get_existing_comp_index(comp_name, &comp_index);
    if (ret) {
        FOTA_TRACE_ERROR("Failed to get component info for %s ", comp_name);
        return FOTA_STATUS_INTERNAL_ERROR;
    }
    sub_comp_table = &(g_comp_table[comp_index].sub_comp_table);


    // Go over subcomponent verify order array and call the verify callback for all images
    for (int sub_comp_index = 0; sub_comp_index < sub_comp_table->num_of_sub_comps; sub_comp_index++) {
        // Get the name of the subcomponent
        sub_component_name = sub_comp_table->verify_order[sub_comp_index].sub_comp_name;

        // Get image descriptor of current subcomponent
        image_descriptor = fota_combined_package_get_descriptor(sub_component_name, descriptor_info);
        if (!image_descriptor) {
            FOTA_TRACE_ERROR("Failed to get subcomponent info for %s ", sub_component_name);
            return FOTA_STATUS_INTERNAL_ERROR;
        }

        // Get verify callback pointer
        verify_cb = sub_comp_table->verify_order[sub_comp_index].cb_function;

        //Check verify_cb
        if (!verify_cb) {
            FOTA_TRACE_ERROR("Verify callback is NULL");
            return FOTA_STATUS_INTERNAL_ERROR;
        };

        //Call verify callback
        ret = verify_cb(comp_name, sub_component_name, image_descriptor->vendor_data, image_descriptor->vendor_data_size, NULL);
        if (ret) {
            FOTA_TRACE_ERROR("Failed to verify current subcomponent %s ", sub_component_name);
            fota_source_report_update_customer_result(ret);
            return FOTA_STATUS_INTERNAL_ERROR;
        }
    }
    return FOTA_STATUS_SUCCESS;
}

#endif //MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
