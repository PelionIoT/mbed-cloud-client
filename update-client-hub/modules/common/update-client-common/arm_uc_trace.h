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

#ifndef ARM_UPDATE_TRACE_H
#define ARM_UPDATE_TRACE_H

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

/*
    Available update client trace flags:
    ARM_UC_ALL_TRACE_ENABLE
    ARM_UC_HUB_TRACE_ENABLE
    ARM_UC_COMMON_TRACE_ENABLE
    ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE
    ARM_UC_CONTROL_CENTER_TRACE_ENABLE
    ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
    ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
    ARM_UC_PAAL_TRACE_ENABLE
*/

/* if the global trace flag is enabled, enable trace for all hub modules */
#if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1
#include "mbed-trace/mbed_trace.h"
#undef ARM_UC_ALL_TRACE_ENABLE
#define ARM_UC_ALL_TRACE_ENABLE 1
#endif // if MBED_CONF_MBED_TRACE_ENABLE

#if defined(ARM_UC_ALL_TRACE_ENABLE) && ARM_UC_ALL_TRACE_ENABLE == 1
#undef ARM_UC_HUB_TRACE_ENABLE
#define ARM_UC_HUB_TRACE_ENABLE 1
#undef ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE
#define ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE 1
#undef ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
#define ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE 1
#undef ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
#define ARM_UC_SOURCE_MANAGER_TRACE_ENABLE 1
#undef ARM_UC_CONTROL_CENTER_TRACE_ENABLE
#define ARM_UC_CONTROL_CENTER_TRACE_ENABLE 1
#undef ARM_UC_COMMON_TRACE_ENABLE
#define ARM_UC_COMMON_TRACE_ENABLE 1
#undef ARM_UC_PAAL_TRACE_ENABLE
#define ARM_UC_PAAL_TRACE_ENABLE 1
#endif // if ARM_UC_ALL_TRACE_ENABLE

#if ARM_UC_HUB_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_HUB_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "HUB ", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_HUB_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "HUB ", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_HUB_TRACE(fmt, ...) printf("[TRACE][HUB]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_HUB_ERR_MSG(fmt, ...) printf("[ERROR][HUB]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_HUB_TRACE(...)
#define UC_HUB_ERR_MSG(...)
#endif // if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE

#if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_FIRM_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "FIRM", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_FIRM_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "FIRM", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_FIRM_TRACE(fmt, ...) printf("[TRACE][FIRM]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_FIRM_ERR_MSG(fmt, ...) printf("[ERROR][FIRM]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_FIRM_TRACE(fmt, ...)
#define UC_FIRM_ERR_MSG(fmt, ...)
#endif // if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE

#if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_MMGR_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "MMGR", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_MMGR_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "MMGR", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_MMGR_TRACE(fmt, ...) printf("[TRACE][MMGR]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_MMGR_ERR_MSG(fmt, ...) printf("[ERROR][MMGR]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_MMGR_TRACE(fmt, ...)
#define UC_MMGR_ERR_MSG(fmt, ...)
#endif // if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE

#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_SRCE_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "SRCE", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_SRCE_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "SRCE", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_SRCE_TRACE(fmt, ...) printf("[TRACE][SRCE]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_SRCE_ERR_MSG(fmt, ...) printf("[ERROR][SRCE]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_SRCE_TRACE(fmt, ...)
#define UC_SRCE_ERR_MSG(fmt, ...)
#endif // if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE

#if ARM_UC_CONTROL_CENTER_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_CONT_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "CTRL", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_CONT_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "CTRL", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_CONT_TRACE(fmt, ...) printf("[TRACE][CTRL]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_CONT_ERR_MSG(fmt, ...) printf("[ERROR][CTRL]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_CONT_TRACE(fmt, ...)
#define UC_CONT_ERR_MSG(fmt, ...)
#endif // if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE

#if ARM_UC_COMMON_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_COMM_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "COMM", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_COMM_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "COMM", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_COMM_TRACE(fmt, ...) printf("[TRACE][COMM]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_COMM_ERR_MSG(fmt, ...) printf("[ERROR][COMM]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_COMM_TRACE(fmt, ...)
#define UC_COMM_ERR_MSG(fmt, ...)
#endif // if ARM_UC_COMMON_TRACE_ENABLE

#if ARM_UC_PAAL_TRACE_ENABLE
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if MBED_CONF_MBED_TRACE_ENABLE
#define UC_PAAL_TRACE(fmt, ...) mbed_tracef(TRACE_LEVEL_DEBUG, "PAAL", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_PAAL_ERR_MSG(fmt, ...) mbed_tracef(TRACE_LEVEL_ERROR, "PAAL", "%s:%d: " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define UC_PAAL_TRACE(fmt, ...) printf("[TRACE][PAAL]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#define UC_PAAL_ERR_MSG(fmt, ...) printf("[ERROR][PAAL]" "%s:%d: " fmt "\r\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif // if MBED_CONF_MBED_TRACE_ENABLE
#else
#define UC_PAAL_TRACE(fmt, ...)
#define UC_PAAL_ERR_MSG(fmt, ...)
#endif // if ARM_UC_COMMON_TRACE_ENABLE

#endif // ARM_UPDATE_TRACE_H
