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

#include "arm_uc_pal_filesystem_utils.h"
#include "update-client-common/arm_uc_utilities.h"

#include "pal.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "UCPI"

#include <stdio.h>

/**
 * @brief Get the path of the specified item (header or file) for a firmware image
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param location Index of the firmware image in storage.
 * @param what 'FIRMWARE_IMAGE_ITEM_HEADER' to return the path to the image
 *        header, or 'FIRMWARE_IMAGE_ITEM_DATA' to return the path to the
 *        actual image data.
 * @param dest Where to write the path.
 * @param dest_size Size of the 'dest' array above. It should be at least
 *        PAL_MAX_FILE_AND_FOLDER_LENGTH.
 * @return ERR_INVALID_PARAMETER if an error occured, ERR_NONE otherwise.
 */
arm_uc_error_t arm_uc_pal_filesystem_get_path(uint32_t location,
                                              firmwareImageItemType what,
                                              char *dest,
                                              uint32_t dest_size)
{
    arm_uc_error_t result = { .code = ERR_INVALID_PARAMETER };

    if (dest && dest_size > 0)
    {
        /* copy the base directory of firmware into dest */
        int length = snprintf(dest, dest_size, "%s", pal_imageGetFolder());

        /* add missing slash at end if needed */
        if ((length < dest_size) && (dest[length - 1] != '/'))
        {
            dest[length] = '/';
            length++;
        }

        /* start snprintf after the mount point name and add length */
        length += snprintf(&dest[length],
                           dest_size - length,
                           "%s_%" PRIu32 ".bin",
                           what == FIRMWARE_IMAGE_ITEM_HEADER ? "header" : "image",
                           location);

        /* check that file path didn't overrun */
        if (length < dest_size)
        {
            result.code = ERR_NONE;
        }
    }

    return result;
}
