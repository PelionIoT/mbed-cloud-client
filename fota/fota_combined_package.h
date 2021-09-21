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

#ifndef __FOTA_COMBINED_PACKAGE_H_
#define __FOTA_COMBINED_PACKAGE_H_

#include "fota/fota_base.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#include "fota/fota_crypto_defs.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE 9

typedef struct {
    char       image_id[FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE];  /*< Component name */
    uint8_t*   vendor_data;                                    /*< Vendor custom data. */ //[FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE]
    size_t     vendor_data_size;                               /*< Vendor data size */
    uint32_t   image_size;                                     /*< Image size */
} image_descriptor_t;

typedef struct {
    uint8_t              num_of_images;    /*< Number of images in combined package */
    image_descriptor_t*  image_descriptors_array;      /*< Array of image descriptors */
} package_descriptor_t;

int fota_combined_package_parse(package_descriptor_t *descriptor_info, uint8_t *package_descriptor_buffer, size_t package_descriptor_buffer_size);
void fota_combined_clean_image_descriptors_array(package_descriptor_t *descriptor_info);
image_descriptor_t* fota_combined_package_get_descriptor(const char *sub_comp_name, const package_descriptor_t *descriptor_info);

#if defined(TARGET_LIKE_LINUX)
#define FOTA_COMBINED_IMAGE_DESCRIPTOR_FILENAME  "_desc_"
#endif

#ifdef FOTA_PACKAGE_DEBUG
#define FOTA_PACKAGE_TRACE_DEBUG FOTA_TRACE_DEBUG
#else
#define FOTA_PACKAGE_TRACE_DEBUG(fmt, ...)
#endif

#ifdef __cplusplus
}
#endif
#endif // (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#endif // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)
#endif // __FOTA_COMBINED_PACKAGE_H_
