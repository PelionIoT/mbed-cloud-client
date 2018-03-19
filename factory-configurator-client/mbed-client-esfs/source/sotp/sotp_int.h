/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __SOTP_INT_H
#define __SOTP_INT_H

#include <stdint.h>
#include "mbed-trace/mbed_trace.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRACE_GROUP                     "sotp"

#ifdef ESFS_INTERACTIVE_TEST
#define STATIC
#define PR_ERR printf
#define PR_INFO printf
#define PR_DEBUG printf
#else
#define STATIC static
#define PR_ERR tr_err
#define PR_INFO tr_info
#define PR_DEBUG tr_debug
#endif


typedef struct {
    uint16_t type_and_flags;
    uint16_t length;
    uint32_t mac;
} record_header_t __attribute__((aligned(4)));

#define FLASH_MINIMAL_PROG_UNIT 8

#define DELETE_ITEM_FLAG        0x8000
#define HEADER_FLAG_MASK        0xF000
#define SOTP_MASTER_RECORD_TYPE 0x0FFE
#define SOTP_NO_TYPE            0x0FFF

#define MASTER_RECORD_BLANK_FIELD_SIZE FLASH_MINIMAL_PROG_UNIT


typedef struct {
    uint16_t version;
    uint16_t format_rev;
    uint32_t reserved;
} master_record_data_t __attribute__((aligned(4)));

#define MASTER_RECORD_SIZE sizeof(master_record_data_t)

palStatus_t sotp_flash_read_area(uint8_t area, uint32_t offset, uint32_t len_bytes, uint32_t *buf);
palStatus_t sotp_flash_write_area(uint8_t area, uint32_t offset, uint32_t len_bytes, const uint32_t *buf);
palStatus_t sotp_flash_erase_area(uint8_t area);

#ifdef __cplusplus
}
#endif

#endif
