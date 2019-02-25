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

#include <inttypes.h>
#include <string.h>

/*
    Available update client trace flags:
    ARM_UC_ALL_TRACE_ENABLE
    ARM_UC_HUB_TRACE_ENABLE
    ARM_UC_ERROR_TRACE_ENABLE
    ARM_UC_COMMON_TRACE_ENABLE
    ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE
    ARM_UC_CONTROL_CENTER_TRACE_ENABLE
    ARM_UC_RESUME_TRACE_ENABLE
    ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
    ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
    ARM_UC_PAAL_TRACE_ENABLE
    ARM_UC_QA_TRACE_ENABLE
    ARM_UC_SDLR_TRACE_ENABLE
*/

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/* if the global trace flag is enabled, enable trace for all hub modules */
#if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1

#include "mbed-trace/mbed_trace.h"
#ifndef TRACE_GROUP
#define TRACE_GROUP  "UC"
#endif

#define ARM_UC_TRACE_DEBUG_PRINTF(module, fmt, ...) tr_debug("[%-4s] %s:%d: " fmt, module, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define ARM_UC_TRACE_ERROR_PRINTF(module, fmt, ...) tr_error("[%-4s] %s:%d: " fmt, module, __FILENAME__, __LINE__, ##__VA_ARGS__)

#undef ARM_UC_ALL_TRACE_ENABLE
#define ARM_UC_ALL_TRACE_ENABLE 1

#else // if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1

#include <stdio.h>

#define ARM_UC_TRACE_DEBUG_PRINTF(module, fmt, ...) printf("[TRACE][%-4s] %s:%d: " fmt "\r\n", module, __FILENAME__, __LINE__, ##__VA_ARGS__)
#define ARM_UC_TRACE_ERROR_PRINTF(module, fmt, ...) printf("[ERROR][%-4s] %s:%d: " fmt "\r\n", module, __FILENAME__, __LINE__, ##__VA_ARGS__)

#endif // if defined(MBED_CONF_MBED_TRACE_ENABLE) && MBED_CONF_MBED_TRACE_ENABLE == 1

#if defined(ARM_UC_ALL_TRACE_ENABLE) && ARM_UC_ALL_TRACE_ENABLE == 1
#undef ARM_UC_ERROR_TRACE_ENABLE
#define ARM_UC_ERROR_TRACE_ENABLE 1
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
#undef ARM_UC_QA_TRACE_ENABLE
#define ARM_UC_QA_TRACE_ENABLE 1
#ifndef ARM_UC_SDLR_TRACE_ENABLE
#define ARM_UC_SDLR_TRACE_ENABLE 0
#endif
#ifndef ARM_UC_RESUME_TRACE_ENABLE
#define ARM_UC_RESUME_TRACE_ENABLE 1
#endif
#endif // if ARM_UC_ALL_TRACE_ENABLE

#if ARM_UC_ERROR_TRACE_ENABLE
#define UC_ERROR_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("ERR", fmt, ##__VA_ARGS__)
#define UC_ERROR_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("ERR", fmt, ##__VA_ARGS__)
#else
#define UC_ERROR_TRACE(fmt, ...)
#define UC_ERROR_ERR_MSG(fmt, ...)
#endif // if ARM_UC_ERROR_TRACE_ENABLE

#if ARM_UC_HUB_TRACE_ENABLE
#define UC_HUB_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("HUB", fmt, ##__VA_ARGS__)
#define UC_HUB_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("HUB", fmt, ##__VA_ARGS__)
#else
#define UC_HUB_TRACE(...)
#define UC_HUB_ERR_MSG(...)
#endif // if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE

#if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE
#define UC_FIRM_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("FIRM", fmt, ##__VA_ARGS__)
#define UC_FIRM_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("FIRM", fmt, ##__VA_ARGS__)
#else
#define UC_FIRM_TRACE(fmt, ...)
#define UC_FIRM_ERR_MSG(fmt, ...)
#endif // if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE

#if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE
#define UC_MMGR_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("MMGR", fmt, ##__VA_ARGS__)
#define UC_MMGR_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("MMGR", fmt, ##__VA_ARGS__)
#else
#define UC_MMGR_TRACE(fmt, ...)
#define UC_MMGR_ERR_MSG(fmt, ...)
#endif // if ARM_UC_MANIFEST_MANAGER_TRACE_ENABLE

#if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE
#define UC_SRCE_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("SRCE", fmt, ##__VA_ARGS__)
#define UC_SRCE_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("SRCE", fmt, ##__VA_ARGS__)
#else
#define UC_SRCE_TRACE(fmt, ...)
#define UC_SRCE_ERR_MSG(fmt, ...)
#endif // if ARM_UC_SOURCE_MANAGER_TRACE_ENABLE

#if ARM_UC_CONTROL_CENTER_TRACE_ENABLE
#define UC_CONT_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("CTRL", fmt, ##__VA_ARGS__)
#define UC_CONT_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("CTRL", fmt, ##__VA_ARGS__)
#else
#define UC_CONT_TRACE(fmt, ...)
#define UC_CONT_ERR_MSG(fmt, ...)
#endif // if ARM_UC_FIRMWARE_MANAGER_TRACE_ENABLE

#if ARM_UC_RESUME_TRACE_ENABLE
#define UC_RESUME_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("RESM", fmt, ##__VA_ARGS__)
#define UC_RESUME_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("RESM", fmt, ##__VA_ARGS__)
#else
#define UC_RESUME_TRACE(fmt, ...)
#define UC_RESUME_ERR_MSG(fmt, ...)
#endif // if ARM_UC_RESUME_TRACE_ENABLE

#if ARM_UC_COMMON_TRACE_ENABLE
#define UC_COMM_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("COMM", fmt, ##__VA_ARGS__)
#define UC_COMM_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("COMM", fmt, ##__VA_ARGS__)
#else
#define UC_COMM_TRACE(fmt, ...)
#define UC_COMM_ERR_MSG(fmt, ...)
#endif // if ARM_UC_COMMON_TRACE_ENABLE

#if ARM_UC_PAAL_TRACE_ENABLE
#define UC_PAAL_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("PAAL", fmt, ##__VA_ARGS__)
#define UC_PAAL_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("PAAL", fmt, ##__VA_ARGS__)
#else
#define UC_PAAL_TRACE(fmt, ...)
#define UC_PAAL_ERR_MSG(fmt, ...)
#endif // if ARM_UC_COMMON_TRACE_ENABLE

#if ARM_UC_QA_TRACE_ENABLE
#define UC_QA_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("QA", fmt, ##__VA_ARGS__)
#define UC_QA_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("QA", fmt, ##__VA_ARGS__)
#else
#define UC_QA_TRACE(fmt, ...)
#define UC_QA_ERR_MSG(fmt, ...)
#endif // if ARM_UC_COMMON_TRACE_ENABLE

#if ARM_UC_SDLR_TRACE_ENABLE
#define UC_SDLR_TRACE(fmt, ...)   ARM_UC_TRACE_DEBUG_PRINTF("SDLR", fmt, ##__VA_ARGS__)
#define UC_SDLR_ERR_MSG(fmt, ...) ARM_UC_TRACE_ERROR_PRINTF("SDLR", fmt, ##__VA_ARGS__)
#else
#define UC_SDLR_TRACE(fmt, ...)
#define UC_SDLR_ERR_MSG(fmt, ...)
#endif // if ARM_UC_SDLR_TRACE_ENABLE

#endif // ARM_UPDATE_TRACE_H
