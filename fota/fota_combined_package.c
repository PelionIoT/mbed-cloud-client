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

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE
#if (MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1)
#define TRACE_GROUP "FOTA"
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
#include "fota/fota_combined_package.h"
#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"
#include "fota/fota_crypto.h"
#include "fota/fota_crypto_asn_extra.h"
#include "fota/fota_base.h"
#include "fota/fota_internal.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#if defined(TARGET_LIKE_LINUX)
#include "fota/platform/linux/fota_platform_linux.h"
#endif


// Allocate internal package descriptor structure
static int init_image_descriptors_array(package_descriptor_t *descriptor_info)
{

    // Allocate image descriptors array
    descriptor_info->image_descriptors_array = malloc(descriptor_info->num_of_images * sizeof(image_descriptor_t));
    if (!descriptor_info->image_descriptors_array) {
        FOTA_TRACE_ERROR("Failed to allocate memory");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    memset(descriptor_info->image_descriptors_array, 0, descriptor_info->num_of_images * sizeof(image_descriptor_t));

    return 0;
}

void fota_combined_clean_image_descriptors_array(package_descriptor_t *descriptor_info)
{
    package_descriptor_t *temp_descriptor_info = NULL;


    if (!descriptor_info->image_descriptors_array) {
        temp_descriptor_info = descriptor_info;
        // Release for each array member allocated vendor data memory
        for (int index = 0; index < temp_descriptor_info->num_of_images; index++) {
            if (temp_descriptor_info->image_descriptors_array->vendor_data != NULL) {
                free(temp_descriptor_info->image_descriptors_array->vendor_data);
                temp_descriptor_info->image_descriptors_array->vendor_data = NULL;
            }
            temp_descriptor_info->image_descriptors_array++;
        }
        // Release allocated image descriptors array memory
        free(descriptor_info->image_descriptors_array);
        descriptor_info->image_descriptors_array = NULL;
    }
    return;
}

/*
* Assuming following ASN1 schema
* --Image descriptor
* ImgDescriptor :: = SEQUENCE
* {
*      id                  UTF8String,
*      vendor-data         OctetString,
*      vendor-data-size    Integer,
*      image-size          Integer
*}
*/
static int parse_descriptors_array(const uint8_t *descriptor_array_data,
                                   size_t descriptor_array_size,
                                   package_descriptor_t *descriptor_info)
{
    int res = 0;
    size_t len = descriptor_array_size;
    unsigned char *p = (unsigned char *)descriptor_array_data;
    unsigned char *desc_arrary_end = p + len;
    int tmp_status;  // reusable status
    size_t num_of_img_descriptors = descriptor_info->num_of_images;
    image_descriptor_t *img_desc_array = NULL;
    uint8_t *vendor_data = NULL;
    size_t vendor_data_size = 0;
    size_t len_of_image_descriptor = 0;
    unsigned char *start_of_image_descriptor = NULL;

    // Initialize package descriptor internal structure (image descriptors array)
    res = init_image_descriptors_array(descriptor_info);
    if (res != 0) {
        return res;
    }

    img_desc_array = descriptor_info->image_descriptors_array;

    // Read descriptors for all images
    for (int image_index = 0; image_index < num_of_img_descriptors; image_index++) {

        FOTA_PACKAGE_TRACE_DEBUG("Parse ImgDescriptor ");
        tmp_status = mbedtls_asn1_get_tag(
                         &p, desc_arrary_end, &len,
                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (tmp_status != 0) {
            FOTA_TRACE_ERROR("Error package descriptor array tag %d", tmp_status);
            res = FOTA_STATUS_COMB_PACKAGE_MALFORMED;
            goto cleanup;
        }
        start_of_image_descriptor = p;
        len_of_image_descriptor = len;

        FOTA_PACKAGE_TRACE_DEBUG("Parse ImgDescriptor:image_id");
        // Parse image id data
        tmp_status = mbedtls_asn1_get_tag(
                         &p, desc_arrary_end, &len, MBEDTLS_ASN1_UTF8_STRING);
        if (tmp_status != 0) {
            FOTA_TRACE_ERROR("Error reading ImgDescriptor:image_id %d", tmp_status);
            res = FOTA_STATUS_COMB_PACKAGE_MALFORMED;
            goto cleanup;
        }

        if (len >= FOTA_PACKAGE_IMAGE_ID_MAX_NAME_SIZE) {
            FOTA_TRACE_ERROR("image id-name too long %zu", len);
            res = FOTA_STATUS_COMB_PACKAGE_IMAGE_ID_NAME_TOO_LONG;
            goto cleanup;
        }

        // Set image id data
        memcpy(img_desc_array->image_id, p, len);
        FOTA_PACKAGE_TRACE_DEBUG("image id %s", img_desc_array->image_id);
        p += len;

        FOTA_PACKAGE_TRACE_DEBUG("Parse ImgDescriptor:vendor_data");
        tmp_status = mbedtls_asn1_get_tag(
                         &p, desc_arrary_end, &len,
                         MBEDTLS_ASN1_OCTET_STRING);
        if (tmp_status != 0) {
            FOTA_TRACE_ERROR("Error reading ImgDescriptor:vendor_data %d", tmp_status);
            res = FOTA_STATUS_COMB_PACKAGE_MALFORMED;
            goto cleanup;
        }

        if (len > FOTA_COMBINED_IMAGE_VENDOR_MAX_DATA_SIZE) {
            FOTA_TRACE_ERROR("Vendor data too long %zu", len);
            res = FOTA_STATUS_COMB_PACKAGE_VENDOR_DATA_TOO_LONG;
            goto cleanup;
        }
        // Set vendor_data pointer and size
        vendor_data = p;
        vendor_data_size = len;

        p += len;

        FOTA_PACKAGE_TRACE_DEBUG("Parse ImgDescriptor:vendor_data_size");
        // Parse vendor data size
        tmp_status = mbedtls_asn1_get_int(&p, desc_arrary_end, (int *) & (img_desc_array->vendor_data_size));
        if (tmp_status != 0) {
            FOTA_TRACE_ERROR("Error reading ImgDescriptor:vendor_data_size %d", tmp_status);
            res = FOTA_STATUS_COMB_PACKAGE_MALFORMED;
            goto cleanup;
        }

        // Validate vendor data size
        if (vendor_data_size != img_desc_array->vendor_data_size) {
            FOTA_TRACE_ERROR("Vendor data size is wrong %zu", img_desc_array->vendor_data_size);
            return FOTA_STATUS_COMB_PACKAGE_MALFORMED;
        }
        // Allocate vendor data buffer according to the size
        // We add 1 for null terminator, in case it's a (non null terminated) string. This is harmless.
        img_desc_array->vendor_data = malloc(vendor_data_size + 1);
        if (!img_desc_array->vendor_data) {
            FOTA_TRACE_ERROR("Failed to allocate memory");
            res = FOTA_STATUS_OUT_OF_MEMORY;
            goto cleanup;
        }
        // Copy vendor data to the allocated buffer
        memcpy(img_desc_array->vendor_data, vendor_data, vendor_data_size);
        // Null terminate the string, in case it's not yet null terminated
        img_desc_array->vendor_data[vendor_data_size] = '\0';
        FOTA_PACKAGE_TRACE_DEBUG("Vendor data %s", vendor_data);

        FOTA_PACKAGE_TRACE_DEBUG("Parse ImgDescriptor:image_size");
        // Parse image size
        tmp_status = mbedtls_asn1_get_int(&p, desc_arrary_end, (int *)&img_desc_array->image_size);
        if (tmp_status != 0) {
            FOTA_TRACE_ERROR("Error reading ImgDescriptor:image_size %d", tmp_status);
            res = FOTA_STATUS_COMB_PACKAGE_MALFORMED;
            goto cleanup;
        }

        // Do not delete !!!
        p = start_of_image_descriptor + len_of_image_descriptor; // For backward compatibility - the parser should ignore unknown fields
        img_desc_array++;
    }// for

    return 0;

cleanup:
    // Release all allocated resources
    fota_combined_clean_image_descriptors_array(descriptor_info);
    return res;
}

/*
* Assuming following ASN1 schema
* Descriptor ::= SEQUENCE
* {
*  num-of-images Integer (0..255),
*  descriptors-array SEQUENCE OF ImgDescriptor
* }
*/
int fota_combined_package_parse(package_descriptor_t *descriptor_info, uint8_t *package_descriptor_buffer, size_t package_descriptor_buffer_size)
{
    size_t len = package_descriptor_buffer_size;
    unsigned char *p = (unsigned char *)package_descriptor_buffer;
    unsigned char *desc_data_end = p + len;
    int tmp_status;  // reusable status

    FOTA_DBG_ASSERT(package_descriptor_buffer_size != 0);

    // Reset descriptor info structure memory
    memset(descriptor_info, 0, sizeof(*descriptor_info));

    tmp_status = mbedtls_asn1_get_tag(
                     &p, desc_data_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error package descriptor tag %d", tmp_status);
        return FOTA_STATUS_COMB_PACKAGE_MALFORMED;
    }

    // Check length of the asn1 buffer against actual data buffer size
    if (p + len > desc_data_end) {
        FOTA_TRACE_ERROR("Truncated package descriptor");
        return FOTA_STATUS_COMB_PACKAGE_MALFORMED;
    }

    // Get number of images inside the descriptor
    tmp_status = mbedtls_asn1_get_int(&p, desc_data_end, (int *) & (descriptor_info->num_of_images));
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading Descriptor:num_of_images %d", tmp_status);
        return FOTA_STATUS_COMB_PACKAGE_MALFORMED;
    }

    if (FOTA_MAX_NUM_OF_SUB_COMPONENTS != descriptor_info->num_of_images) {
        FOTA_TRACE_ERROR("Wrong number of combined images");
        return FOTA_STATUS_COMB_PACKAGE_WRONG_IMAGE_NUM;
    }

    // Get size of the descriptors array section
    tmp_status = mbedtls_asn1_get_tag(
                     &p, desc_data_end, &len,
                     MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("Error reading Descriptor:descriptors-array %d", tmp_status);
        return FOTA_STATUS_COMB_PACKAGE_MALFORMED;
    }
    // Set pointer and size of descriptors array
    uint8_t *desc_array_ptr = p;
    size_t desc_array_size = len;

    //Parse descriptors array
    tmp_status = parse_descriptors_array(
                     desc_array_ptr,
                     desc_array_size,
                     descriptor_info);
    if (tmp_status != 0) {
        FOTA_TRACE_ERROR("parse_descriptors_array failed %d", tmp_status);
        return tmp_status;
    }

    // For For backward compatibility - ignore unkown fields and do not check end of the buffer.
    return 0;
}

image_descriptor_t *fota_combined_package_get_descriptor(const char *sub_comp_name, const package_descriptor_t *descriptor_info)
{
    int res = 0;
    image_descriptor_t *p_image_descriptor = NULL;//todo p
    bool img_is_found = false;

    FOTA_ASSERT(descriptor_info);
    FOTA_ASSERT(sub_comp_name);
    p_image_descriptor = descriptor_info->image_descriptors_array;

    //Find sub component name in image descriptors array
    for (int img_index = 0; img_index < descriptor_info->num_of_images; img_index++) {
        res = strcmp(sub_comp_name, p_image_descriptor->image_id);
        if (res == 0) {
            img_is_found = true;
            break;
        }
        p_image_descriptor++;
    }
    if (img_is_found == false) {
        FOTA_TRACE_ERROR("Subcomponent name not found in the descriptor info");
        return NULL;
    }

    return p_image_descriptor;

}
#endif  //MBED_CLOUD_CLIENT_FOTA_SUB_COMPONENT_SUPPORT == 1
#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
