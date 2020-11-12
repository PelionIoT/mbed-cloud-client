// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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
#include <stdlib.h>

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_component.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_status.h"

#if defined(TARGET_LIKE_LINUX)
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#endif // defined(TARGET_LIKE_LINUX)

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

static unsigned int num_components = 0;
static fota_component_desc_t comp_table[FOTA_NUM_COMPONENTS];

#define MAJOR_NUM_BITS 24
#define MINOR_NUM_BITS 24
#define SPLIT_NUM_BITS 16
#define MAX_VER 999

//num is between 0 and 999 (MAX_VER)
static char *append_number_to_string(char *str, uint_fast16_t num, char trail) {
    if (num > 100) {
        char p = '0' + num/100;
        *str++ = p;
    }
    if (num > 10) {
        *str++ = '0' + (num%100)/10;
    }
    *str++ = '0' + (num%10);
    *str++ = trail;
    return str;
}

void fota_component_clean(void)
{
    num_components = 0;
    memset(comp_table, 0, sizeof(comp_table));
}

int fota_component_add(const fota_component_desc_info_t *comp_desc_info, const char *comp_name, const char *comp_semver)
{
    FOTA_ASSERT(num_components < FOTA_NUM_COMPONENTS);
    FOTA_ASSERT(!(comp_desc_info->support_delta && (!comp_desc_info->curr_fw_get_digest || !comp_desc_info->curr_fw_read)));

    memcpy(&comp_table[num_components].desc_info, comp_desc_info, sizeof(*comp_desc_info));
    strncpy(comp_table[num_components].name, comp_name, FOTA_COMPONENT_MAX_NAME_SIZE - 1);
    fota_component_version_semver_to_int(comp_semver, &comp_table[num_components].version);

    num_components++;
    return FOTA_STATUS_SUCCESS;
}

unsigned int fota_component_num_components(void)
{
    return num_components;
}

void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc)
{
    FOTA_ASSERT(comp_id < num_components)
    *comp_desc = &comp_table[comp_id];
}

void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version)
{
    FOTA_ASSERT(comp_id < num_components)
    *version = comp_table[comp_id].version;
}

void fota_component_set_curr_version(unsigned int comp_id, fota_component_version_t version)
{
    FOTA_ASSERT(comp_id < num_components)
    comp_table[comp_id].version = version;
}

int fota_component_name_to_id(const char *name, unsigned int *comp_id)
{
    int i = num_components;

    // One or more components
    do {
        if (!strncmp(name, comp_table[num_components - i].name, FOTA_COMPONENT_MAX_NAME_SIZE)) {
            *comp_id = num_components - i;
            return FOTA_STATUS_SUCCESS;
        }
    } while (--i);

    return FOTA_STATUS_NOT_FOUND;
}

int fota_component_version_int_to_semver(fota_component_version_t version, char *sem_ver)
{
#if MAJOR_NUM_BITS > 32 || MINOR_NUM_BITS > 32 || SPLIT_NUM_BITS > 32
#error "Assuming 32-bit version components"
#endif
    uint32_t major, minor, split;
    uint64_t full_mask = 0xFFFFFFFFFFFFFFFFULL;
    int ret = FOTA_STATUS_SUCCESS;
    char *tmp = sem_ver;

    split = version & ~(full_mask << SPLIT_NUM_BITS);
    minor = (version & ~(full_mask << (SPLIT_NUM_BITS + MINOR_NUM_BITS))) >> SPLIT_NUM_BITS;
    major = version >> (SPLIT_NUM_BITS + MINOR_NUM_BITS);

    if ((major > MAX_VER) || (minor > MAX_VER) || (split > MAX_VER)) {
        ret = FOTA_STATUS_INVALID_ARGUMENT;
    }
    //These are only needed if above check fails (unittests only)
    split = MIN(split, MAX_VER);
    minor = MIN(minor, MAX_VER);
    major = MIN(major, MAX_VER);

    //ouput is "major.minor.split\0"
    tmp = append_number_to_string(tmp, major, '.');
    tmp = append_number_to_string(tmp, minor, '.');
    tmp = append_number_to_string(tmp, split, '\0');
    return ret;
}

int fota_component_version_semver_to_int(const char *sem_ver, fota_component_version_t *version)
{
    // This better use signed strtol() instead of strtoul() as it is already used by other code
    // and there is no need to add more dependencies here. That change saves ~120B.
    long major, minor, split;
    char *endptr;
    int ret = FOTA_STATUS_SUCCESS;

    major = strtol(sem_ver, &endptr, 10);
    minor = strtol(endptr + 1, &endptr, 10);
    split = strtol(endptr + 1, &endptr, 10);
    FOTA_DBG_ASSERT((endptr - sem_ver) <= FOTA_COMPONENT_MAX_SEMVER_STR_SIZE);

    if ((major < 0) || (major > MAX_VER) ||
            (minor < 0) || (minor > MAX_VER) ||
            (split < 0) || (split > MAX_VER)) {
        ret = FOTA_STATUS_INVALID_ARGUMENT;

        // Unfortunately not all call sites of this handle the error, so this might as well
        // give stable output on error path too.
        *version = 0;
    } else {

        split = MIN(split, MAX_VER);
        minor = MIN(minor, MAX_VER);
        major = MIN(major, MAX_VER);

        *version = ((uint64_t) split) | ((uint64_t) minor << SPLIT_NUM_BITS) | ((uint64_t) major << (SPLIT_NUM_BITS + MINOR_NUM_BITS));
    }
    return ret;
}

#if defined(TARGET_LIKE_LINUX)

extern char *program_invocation_name;

int fota_component_install_main(const char *candidate_file_name)
{
    unsigned int file_mode = ALLPERMS;
    struct stat statbuf;

    FOTA_TRACE_INFO("Installing MAIN component");
    
    // get current file permissions
    if (stat(program_invocation_name, &statbuf) == 0) {
        file_mode = statbuf.st_mode & 0x1FF;
    }

    // unlink current file
    if (unlink(program_invocation_name) != 0) {
        FOTA_TRACE_ERROR("Failed to unlink file %s: %s", program_invocation_name, strerror(errno));
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    // change file permission to same as previously
    chmod(candidate_file_name, file_mode);

    if (rename(candidate_file_name, program_invocation_name) != 0) {
        FOTA_TRACE_ERROR("Failed to rename file %s: %s", candidate_file_name, strerror(errno));
        return FOTA_STATUS_INTERNAL_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}
#endif  //defined(TARGET_LIKE_LINUX)

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
